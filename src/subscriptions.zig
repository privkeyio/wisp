const std = @import("std");
const Connection = @import("connection.zig").Connection;
const nostr = @import("nostr.zig");
const metrics = @import("relay_metrics.zig");

pub const Subscriptions = struct {
    allocator: std.mem.Allocator,
    connections: std.AutoHashMap(u64, *Connection),
    rwlock: std.Io.RwLock,
    kind_index: std.AutoHashMap(i32, std.ArrayListUnmanaged(u64)),

    pub fn init(allocator: std.mem.Allocator) Subscriptions {
        return .{
            .allocator = allocator,
            .connections = std.AutoHashMap(u64, *Connection).init(allocator),
            .rwlock = .init,
            .kind_index = std.AutoHashMap(i32, std.ArrayListUnmanaged(u64)).init(allocator),
        };
    }

    pub fn deinit(self: *Subscriptions) void {
        self.connections.deinit();

        var iter = self.kind_index.valueIterator();
        while (iter.next()) |list| {
            list.deinit(self.allocator);
        }
        self.kind_index.deinit();
    }

    pub fn addConnection(self: *Subscriptions, conn: *Connection) !void {
        const io = nostr.io.io();
        self.rwlock.lockUncancelable(io);
        defer self.rwlock.unlock(io);
        try self.connections.put(conn.id, conn);
    }

    pub fn tryAddConnection(self: *Subscriptions, conn: *Connection, max_connections: usize) !void {
        const io = nostr.io.io();
        self.rwlock.lockUncancelable(io);
        defer self.rwlock.unlock(io);
        if (self.connections.count() >= max_connections) return error.TooManyConnections;
        try self.connections.put(conn.id, conn);
    }

    pub fn removeConnection(self: *Subscriptions, conn_id: u64) void {
        const io = nostr.io.io();
        self.rwlock.lockUncancelable(io);
        defer self.rwlock.unlock(io);

        var kind_iter = self.kind_index.valueIterator();
        while (kind_iter.next()) |list| {
            for (list.items, 0..) |id, i| {
                if (id == conn_id) {
                    _ = list.swapRemove(i);
                    break;
                }
            }
        }

        _ = self.connections.remove(conn_id);
    }

    pub fn closeIdleConnection(self: *Subscriptions, conn_id: u64) bool {
        const io = nostr.io.io();
        self.rwlock.lockSharedUncancelable(io);
        const conn = self.connections.get(conn_id);
        if (conn) |c| _ = c.write_guard.fetchAdd(1, .acquire);
        self.rwlock.unlockShared(io);

        const c = conn orelse return false;
        // No courtesy NOTICE here: the reaper runs on the single cleanup thread,
        // and a synchronous write to a non-reading idle client would stall it for
        // up to the send timeout (per client), starving the other periodic jobs.
        // closeWs() shuts down the read half so the worker still runs its normal
        // cleanup and frees the slot/bucket. The write_guard keeps the connection
        // alive until closeWs completes.
        defer _ = c.write_guard.fetchSub(1, .release);
        c.closeWs();
        return true;
    }

    // Write a message to one connection by id, bumping its write_guard under the
    // registry lock so the connection cannot be freed mid-write. Used by the
    // writer thread to deliver OK replies after a batch commits.
    pub fn sendTo(self: *Subscriptions, conn_id: u64, data: []const u8) void {
        const io = nostr.io.io();
        self.rwlock.lockSharedUncancelable(io);
        const conn = self.connections.get(conn_id);
        if (conn) |c| _ = c.write_guard.fetchAdd(1, .acquire);
        self.rwlock.unlockShared(io);

        const c = conn orelse return;
        defer _ = c.write_guard.fetchSub(1, .release);
        c.write(data) catch {};
    }

    pub fn connectionCount(self: *Subscriptions) usize {
        const io = nostr.io.io();
        self.rwlock.lockSharedUncancelable(io);
        defer self.rwlock.unlockShared(io);
        return self.connections.count();
    }

    pub fn subscribe(
        self: *Subscriptions,
        conn: *Connection,
        sub_id: []const u8,
        filters: []const nostr.Filter,
        max_subs: u32,
    ) !void {
        const io = nostr.io.io();
        self.rwlock.lockUncancelable(io);
        defer self.rwlock.unlock(io);

        try conn.addSubscription(sub_id, filters, max_subs);

        for (filters) |f| {
            if (f.kinds()) |kinds| {
                for (kinds) |kind| {
                    const gop = try self.kind_index.getOrPut(kind);
                    if (!gop.found_existing) gop.value_ptr.* = .empty;

                    const found = for (gop.value_ptr.items) |id| {
                        if (id == conn.id) break true;
                    } else false;

                    if (!found) try gop.value_ptr.append(self.allocator, conn.id);
                }
            }
        }
    }

    pub fn unsubscribe(self: *Subscriptions, conn: *Connection, sub_id: []const u8) void {
        const io = nostr.io.io();
        self.rwlock.lockUncancelable(io);
        defer self.rwlock.unlock(io);
        conn.removeSubscription(sub_id);
    }

    fn connHasWildcard(conn: *Connection) bool {
        var sub_iter = conn.subscriptions.valueIterator();
        while (sub_iter.next()) |sub| {
            for (sub.filters) |f| {
                if (f.kinds() == null) return true;
            }
        }
        return false;
    }

    const PendingWrite = struct {
        conn: *Connection,
        sub_id: []const u8,
    };

    // Reused per-broadcast scratch. forEachMatching runs on the single writer
    // thread in durable sync modes but on multiple worker threads concurrently
    // in sync=none, so the scratch is threadlocal (no shared-mutable state) and
    // cleared per call rather than reallocated, avoiding per-event glibc arena
    // churn in the fan-out hot path. Reusing one buffer per thread makes
    // forEachMatching non-reentrant on a thread: callees (the post-unlock socket
    // writes) must never re-enter it, or the inner clear would corrupt the outer
    // drain and unbalance write_guard.
    //
    // These are struct-scoped threadlocals shared across every Subscriptions
    // instance on a thread, and tl_seen is bound to whichever instance's
    // allocator first initializes it. That is correct ONLY because there is
    // exactly one Subscriptions instance, backed by one process-global allocator;
    // a second instance with a different allocator would alias this state.
    //
    // The buffers are never freed or shrunk: each thread retains its peak
    // fan-out capacity for the process lifetime. This is bounded and intentional,
    // and it assumes the worker-pool threads live for the whole process. A
    // respawned pool thread would orphan (leak) its buffers.
    threadlocal var tl_pending: std.ArrayListUnmanaged(PendingWrite) = .empty;
    threadlocal var tl_seen: ?std.AutoHashMap(u64, void) = null;

    pub fn forEachMatching(
        self: *Subscriptions,
        event: *const nostr.Event,
        msg_buf: *[65536]u8,
    ) void {
        const io = nostr.io.io();

        // Snapshot matching targets under the lock, then write after releasing
        // it. Blocking socket writes must never run while holding subs.rwlock: a
        // single non-reading client would stall every lock waiter for up to the
        // send timeout. Each snapshotted connection has its write_guard bumped
        // while still in the registry; removeConnection plus close() drain the
        // guard before freeing, so writing post-unlock is use-after-free safe.
        const pending = &tl_pending;
        pending.clearRetainingCapacity();

        if (tl_seen == null) tl_seen = std.AutoHashMap(u64, void).init(self.allocator);
        const seen = &tl_seen.?;
        seen.clearRetainingCapacity();

        {
            self.rwlock.lockSharedUncancelable(io);
            defer self.rwlock.unlockShared(io);

            // Kind-indexed candidates: only connections subscribed to this kind.
            if (self.kind_index.get(event.kind())) |conn_ids| {
                for (conn_ids.items) |conn_id| {
                    if (seen.contains(conn_id)) continue;
                    seen.put(conn_id, {}) catch continue;
                    const conn = self.connections.get(conn_id) orelse continue;
                    snapshotMatch(self, pending, conn, event);
                }
            }

            // Wildcard candidates: connections with a kindless filter are not in
            // the kind index but can still match any event.
            var conn_iter = self.connections.valueIterator();
            while (conn_iter.next()) |conn_ptr| {
                const conn = conn_ptr.*;
                if (seen.contains(conn.id)) continue;
                if (!connHasWildcard(conn)) continue;
                seen.put(conn.id, {}) catch continue;
                snapshotMatch(self, pending, conn, event);
            }
        }

        var delivered: u64 = 0;
        for (pending.items) |item| {
            defer _ = item.conn.write_guard.fetchSub(1, .release);
            const msg = nostr.RelayMsg.event(item.sub_id, event, msg_buf) catch continue;
            item.conn.write(msg) catch {};
            _ = item.conn.events_sent.fetchAdd(1, .monotonic);
            delivered += 1;
        }
        metrics.eventBroadcast(delivered);
    }

    fn snapshotMatch(
        self: *Subscriptions,
        pending: *std.ArrayListUnmanaged(PendingWrite),
        conn: *Connection,
        event: *const nostr.Event,
    ) void {
        const sub_id = conn.matchesEvent(event) orelse return;
        _ = conn.write_guard.fetchAdd(1, .acquire);
        pending.append(self.allocator, .{ .conn = conn, .sub_id = sub_id }) catch {
            _ = conn.write_guard.fetchSub(1, .release);
        };
    }

    pub fn getIdleConnections(self: *Subscriptions, idle_seconds: u32) []u64 {
        const io = nostr.io.io();
        self.rwlock.lockSharedUncancelable(io);
        defer self.rwlock.unlockShared(io);

        const now = nostr.io.timestamp();
        const threshold = now - @as(i64, @intCast(idle_seconds));

        var result: std.ArrayListUnmanaged(u64) = .empty;
        var conn_iter = self.connections.valueIterator();
        while (conn_iter.next()) |conn| {
            if (conn.*.last_activity.load(.monotonic) < threshold) {
                result.append(self.allocator, conn.*.id) catch continue;
            }
        }
        return result.toOwnedSlice(self.allocator) catch blk: {
            result.deinit(self.allocator);
            break :blk &[_]u64{};
        };
    }
};

const testing = std.testing;

// 64- and 128-hex-char fields so Event.parse accepts the structure.
const HID = "0" ** 63 ++ "1";
const HPK = "0" ** 63 ++ "2";
const HSIG = "0" ** 127 ++ "3";

fn eventJson(comptime kind: []const u8) []const u8 {
    return "[\"EVENT\",{\"id\":\"" ++ HID ++ "\",\"pubkey\":\"" ++ HPK ++
        "\",\"created_at\":1700000000,\"kind\":" ++ kind ++
        ",\"tags\":[],\"content\":\"hi\",\"sig\":\"" ++ HSIG ++ "\"}]";
}

test "forEachMatching reuses threadlocal scratch cleanly across calls" {
    // The Subscriptions instance owns the threadlocal scratch (tl_pending/tl_seen)
    // which is intentionally never freed for the process lifetime, so back it with
    // a non-leak-checking allocator. Connections use testing.allocator and are
    // deinitialized normally.
    var subs = Subscriptions.init(std.heap.page_allocator);
    defer subs.deinit();

    var conn1: Connection = undefined;
    conn1.init(testing.allocator, 1);
    defer conn1.deinit();
    var conn7: Connection = undefined;
    conn7.init(testing.allocator, 7);
    defer conn7.deinit();

    try subs.addConnection(&conn1);
    try subs.addConnection(&conn7);

    var req1 = try nostr.ClientMsg.parse("[\"REQ\",\"k1\",{\"kinds\":[1]}]");
    defer req1.deinit();
    try subs.subscribe(&conn1, "k1", try req1.getFilters(conn1.allocator()), 5);

    var req7 = try nostr.ClientMsg.parse("[\"REQ\",\"k7\",{\"kinds\":[7]}]");
    defer req7.deinit();
    try subs.subscribe(&conn7, "k7", try req7.getFilters(conn7.allocator()), 5);

    const msg_buf = try testing.allocator.create([65536]u8);
    defer testing.allocator.destroy(msg_buf);

    // First broadcast: a kind-1 event reaches only conn1.
    var ev1 = try nostr.ClientMsg.parse(eventJson("1"));
    defer ev1.deinit();
    const event1 = try ev1.getEvent();
    subs.forEachMatching(&event1, msg_buf);

    try testing.expectEqual(@as(u64, 1), conn1.events_sent.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), conn7.events_sent.load(.monotonic));
    // The post-unlock drain balances every guard it took.
    try testing.expectEqual(@as(u32, 0), conn1.write_guard.load(.acquire));
    try testing.expectEqual(@as(u32, 0), conn7.write_guard.load(.acquire));

    // Second broadcast on the same thread: a kind-7 event reaches only conn7. If
    // the threadlocal scratch carried stale entries from call 1, conn1 would be
    // written again or its guard would leak.
    var ev7 = try nostr.ClientMsg.parse(eventJson("7"));
    defer ev7.deinit();
    const event7 = try ev7.getEvent();
    subs.forEachMatching(&event7, msg_buf);

    try testing.expectEqual(@as(u64, 1), conn1.events_sent.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), conn7.events_sent.load(.monotonic));
    try testing.expectEqual(@as(u32, 0), conn1.write_guard.load(.acquire));
    try testing.expectEqual(@as(u32, 0), conn7.write_guard.load(.acquire));
}
