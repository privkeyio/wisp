const std = @import("std");
const nostr = @import("nostr.zig");

pub const Connection = struct {
    id: u64,
    arena: std.heap.ArenaAllocator,
    subscriptions: std.StringHashMap(Subscription),
    created_at: i64,
    last_activity: i64,
    ws_conn: ?*anyopaque = null,
    ws_write_fn: ?*const fn (*anyopaque, []const u8) anyerror!void = null,

    events_received: u64 = 0,
    events_sent: u64 = 0,

    pub fn init(self: *Connection, backing_allocator: std.mem.Allocator, id: u64) void {
        const now = std.time.timestamp();
        self.id = id;
        self.arena = std.heap.ArenaAllocator.init(backing_allocator);
        self.subscriptions = std.StringHashMap(Subscription).init(self.arena.allocator());
        self.created_at = now;
        self.last_activity = now;
        self.events_received = 0;
        self.events_sent = 0;
        self.ws_conn = null;
        self.ws_write_fn = null;
    }

    pub fn send(self: *Connection, data: []const u8) void {
        if (self.ws_conn != null and self.ws_write_fn != null) {
            self.ws_write_fn.?(self.ws_conn.?, data) catch {};
        }
    }

    pub fn deinit(self: *Connection) void {
        self.arena.deinit();
    }

    pub fn allocator(self: *Connection) std.mem.Allocator {
        return self.arena.allocator();
    }

    pub fn addSubscription(self: *Connection, sub_id: []const u8, filters: []const nostr.Filter, max_subs: u32) !void {
        if (self.subscriptions.count() >= max_subs) {
            return error.TooManySubscriptions;
        }

        const alloc = self.allocator();

        self.removeSubscription(sub_id);

        const sub_id_copy = try alloc.dupe(u8, sub_id);
        const filters_copy = try alloc.alloc(nostr.Filter, filters.len);
        for (filters, 0..) |f, i| {
            filters_copy[i] = try f.clone(alloc);
        }

        try self.subscriptions.put(sub_id_copy, .{
            .id = sub_id_copy,
            .filters = filters_copy,
            .created_at = std.time.timestamp(),
        });
    }

    pub fn removeSubscription(self: *Connection, sub_id: []const u8) void {
        _ = self.subscriptions.remove(sub_id);
    }

    pub fn matchesEvent(self: *Connection, event: *const nostr.Event) ?[]const u8 {
        var iter = self.subscriptions.iterator();
        while (iter.next()) |entry| {
            const sub = entry.value_ptr;
            if (nostr.filtersMatch(sub.filters, event)) {
                return sub.id;
            }
        }
        return null;
    }

    pub fn touch(self: *Connection) void {
        self.last_activity = std.time.timestamp();
    }
};

pub const Subscription = struct {
    id: []const u8,
    filters: []const nostr.Filter,
    created_at: i64,
};
