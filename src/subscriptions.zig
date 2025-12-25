const std = @import("std");
const Connection = @import("connection.zig").Connection;
const nostr = @import("nostr.zig");

pub const Subscriptions = struct {
    allocator: std.mem.Allocator,
    connections: std.AutoHashMap(u64, *Connection),
    rwlock: std.Thread.RwLock,
    kind_index: std.AutoHashMap(i32, std.ArrayListUnmanaged(u64)),

    pub fn init(allocator: std.mem.Allocator) Subscriptions {
        return .{
            .allocator = allocator,
            .connections = std.AutoHashMap(u64, *Connection).init(allocator),
            .rwlock = .{},
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
        self.rwlock.lock();
        defer self.rwlock.unlock();
        try self.connections.put(conn.id, conn);
    }

    pub fn tryAddConnection(self: *Subscriptions, conn: *Connection, max_connections: usize) !void {
        self.rwlock.lock();
        defer self.rwlock.unlock();
        if (self.connections.count() >= max_connections) return error.TooManyConnections;
        try self.connections.put(conn.id, conn);
    }

    pub fn removeConnection(self: *Subscriptions, conn_id: u64) void {
        self.rwlock.lock();
        defer self.rwlock.unlock();

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
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        return self.connections.get(conn_id);
    }

    pub fn withConnection(self: *Subscriptions, conn_id: u64, comptime func: fn (*Connection) void) void {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        if (self.connections.get(conn_id)) |conn| {
            func(conn);
        }
    }

    pub fn sendToConnection(self: *Subscriptions, conn_id: u64, data: []const u8) bool {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        if (self.connections.get(conn_id)) |conn| {
            return conn.send(data);
        }
        return false;
    }

    pub fn closeIdleConnection(self: *Subscriptions, conn_id: u64, notice: []const u8) bool {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        if (self.connections.get(conn_id)) |conn| {
            conn.sendDirect(notice);
            conn.stopWriteQueue();
            conn.clearDirectWriter();
            conn.shutdown();
            return true;
        }
        return false;
    }

    pub fn connectionCount(self: *Subscriptions) usize {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        return self.connections.count();
    }

    pub fn subscribe(
        self: *Subscriptions,
        conn: *Connection,
        sub_id: []const u8,
        filters: []const nostr.Filter,
        max_subs: u32,
    ) !void {
        self.rwlock.lock();
        defer self.rwlock.unlock();

        try conn.addSubscription(sub_id, filters, max_subs);

        for (filters) |f| {
            if (f.kinds()) |kinds| {
                for (kinds) |kind| {
                    var list = self.kind_index.getPtr(kind);
                    if (list == null) {
                        try self.kind_index.put(kind, .{});
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
        self.rwlock.lock();
        defer self.rwlock.unlock();
        conn.removeSubscription(sub_id);
    }

    pub fn getCandidates(self: *Subscriptions, event: *const nostr.Event) ![]*Connection {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();

        var result = std.ArrayListUnmanaged(*Connection){};
        var seen = std.AutoHashMap(u64, void).init(self.allocator);
        defer seen.deinit();

        if (self.kind_index.get(event.kind())) |conn_ids| {
            for (conn_ids.items) |conn_id| {
                if (!seen.contains(conn_id)) {
                    if (self.connections.get(conn_id)) |conn| {
                        try result.append(self.allocator, conn);
                        try seen.put(conn_id, {});
                    }
                }
            }
        }

        var conn_iter = self.connections.valueIterator();
        while (conn_iter.next()) |conn| {
            if (seen.contains(conn.*.id)) continue;

            var sub_iter = conn.*.subscriptions.valueIterator();
            while (sub_iter.next()) |sub| {
                var has_wildcard = false;
                for (sub.filters) |f| {
                    if (f.kinds() == null) {
                        has_wildcard = true;
                        break;
                    }
                }
                if (has_wildcard) {
                    try result.append(self.allocator, conn.*);
                    break;
                }
            }
        }

        return result.toOwnedSlice(self.allocator);
    }

    pub fn forEachMatching(
        self: *Subscriptions,
        event: *const nostr.Event,
        msg_buf: *[65536]u8,
    ) void {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();

        var conn_iter = self.connections.valueIterator();
        while (conn_iter.next()) |conn| {
            if (conn.*.matchesEvent(event)) |sub_id| {
                const msg = nostr.RelayMsg.event(sub_id, event, msg_buf) catch continue;
                _ = conn.*.send(msg);
                conn.*.events_sent += 1;
            }
        }
    }

    pub fn getIdleConnections(self: *Subscriptions, idle_seconds: u32) []u64 {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();

        const now = std.time.timestamp();
        const threshold = now - @as(i64, @intCast(idle_seconds));

        var result = std.ArrayListUnmanaged(u64){};
        var conn_iter = self.connections.valueIterator();
        while (conn_iter.next()) |conn| {
            if (conn.*.last_activity < threshold) {
                result.append(self.allocator, conn.*.id) catch continue;
            }
        }
        return result.toOwnedSlice(self.allocator) catch &[_]u64{};
    }
};
