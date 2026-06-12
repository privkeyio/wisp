const std = @import("std");
const Connection = @import("connection.zig").Connection;
const nostr = @import("nostr.zig");

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

    pub fn getConnection(self: *Subscriptions, conn_id: u64) ?*Connection {
        const io = nostr.io.io();
        self.rwlock.lockSharedUncancelable(io);
        defer self.rwlock.unlockShared(io);
        return self.connections.get(conn_id);
    }

    pub fn withConnection(self: *Subscriptions, conn_id: u64, comptime func: fn (*Connection) void) void {
        const io = nostr.io.io();
        self.rwlock.lockSharedUncancelable(io);
        defer self.rwlock.unlockShared(io);
        if (self.connections.get(conn_id)) |conn| {
            func(conn);
        }
    }

    pub fn closeIdleConnection(self: *Subscriptions, conn_id: u64, notice: []const u8) bool {
        const io = nostr.io.io();
        self.rwlock.lockSharedUncancelable(io);
        const conn = self.connections.get(conn_id);
        if (conn) |c| _ = c.write_guard.fetchAdd(1, .acquire);
        self.rwlock.unlockShared(io);

        const c = conn orelse return false;
        // Write the notice outside the lock: a non-reading idle client would
        // otherwise stall every lock waiter for up to the send timeout. The
        // write_guard keeps the connection alive until the write completes.
        defer _ = c.write_guard.fetchSub(1, .release);
        c.write(notice) catch {};
        c.closeWs();
        return true;
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
                    var list = self.kind_index.getPtr(kind);
                    if (list == null) {
                        try self.kind_index.put(kind, .empty);
                        list = self.kind_index.getPtr(kind);
                    }

                    const found = for (list.?.items) |id| {
                        if (id == conn.id) break true;
                    } else false;

                    if (!found) {
                        try list.?.append(self.allocator, conn.id);
                    }
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
        var pending: std.ArrayListUnmanaged(PendingWrite) = .empty;
        defer pending.deinit(self.allocator);

        {
            self.rwlock.lockSharedUncancelable(io);
            defer self.rwlock.unlockShared(io);

            var seen = std.AutoHashMap(u64, void).init(self.allocator);
            defer seen.deinit();

            // Kind-indexed candidates: only connections subscribed to this kind.
            if (self.kind_index.get(event.kind())) |conn_ids| {
                for (conn_ids.items) |conn_id| {
                    if (seen.contains(conn_id)) continue;
                    seen.put(conn_id, {}) catch continue;
                    const conn = self.connections.get(conn_id) orelse continue;
                    snapshotMatch(self, &pending, conn, event);
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
                snapshotMatch(self, &pending, conn, event);
            }
        }

        for (pending.items) |item| {
            defer _ = item.conn.write_guard.fetchSub(1, .release);
            const msg = nostr.RelayMsg.event(item.sub_id, event, msg_buf) catch continue;
            item.conn.write(msg) catch {};
            _ = item.conn.events_sent.fetchAdd(1, .monotonic);
        }
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
