const std = @import("std");
const Connection = @import("connection.zig").Connection;
const nostr = @import("nostr.zig");

pub const Subscriptions = struct {
    allocator: std.mem.Allocator,
    connections: std.AutoHashMap(u64, *Connection),
    mutex: std.Thread.Mutex,
    kind_index: std.AutoHashMap(i32, std.ArrayListUnmanaged(u64)),

    pub fn init(allocator: std.mem.Allocator) Subscriptions {
        return .{
            .allocator = allocator,
            .connections = std.AutoHashMap(u64, *Connection).init(allocator),
            .mutex = .{},
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
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.connections.put(conn.id, conn);
    }

    pub fn removeConnection(self: *Subscriptions, conn_id: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

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
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.connections.get(conn_id);
    }

    pub fn connectionCount(self: *Subscriptions) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.connections.count();
    }

    pub fn subscribe(
        self: *Subscriptions,
        conn: *Connection,
        sub_id: []const u8,
        filters: []const nostr.Filter,
        max_subs: u32,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

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
        self.mutex.lock();
        defer self.mutex.unlock();
        conn.removeSubscription(sub_id);
    }

    pub fn getCandidates(self: *Subscriptions, event: *const nostr.Event) ![]*Connection {
        self.mutex.lock();
        defer self.mutex.unlock();

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
};
