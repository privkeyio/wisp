const std = @import("std");
const nostr = @import("nostr.zig");
const httpz = @import("httpz");
const websocket = httpz.websocket;

pub const Connection = struct {
    id: u64,
    arena: std.heap.ArenaAllocator,
    subscriptions: std.StringHashMap(Subscription),
    created_at: i64,
    last_activity: i64,
    ws_conn: ?*websocket.Conn = null,

    events_received: u64 = 0,
    events_sent: u64 = 0,

    events_this_minute: u32 = 0,
    minute_start: i64 = 0,

    client_ip: [64]u8 = undefined,
    client_ip_len: u8 = 0,
    auth_challenge: [32]u8 = undefined,
    authenticated_pubkeys: std.AutoHashMap([32]u8, void) = undefined,
    challenge_sent: bool = false,

    pub fn init(self: *Connection, backing_allocator: std.mem.Allocator, id: u64) void {
        const now = std.time.timestamp();
        self.id = id;
        self.arena = std.heap.ArenaAllocator.init(backing_allocator);
        self.subscriptions = std.StringHashMap(Subscription).init(self.arena.allocator());
        self.created_at = now;
        self.last_activity = now;
        self.events_received = 0;
        self.events_sent = 0;
        self.events_this_minute = 0;
        self.minute_start = now;
        self.client_ip = undefined;
        self.client_ip_len = 0;
        self.ws_conn = null;
        std.crypto.random.bytes(&self.auth_challenge);
        self.authenticated_pubkeys = std.AutoHashMap([32]u8, void).init(self.arena.allocator());
        self.challenge_sent = false;
    }

    pub fn setClientIp(self: *Connection, ip: []const u8) void {
        const len = @min(ip.len, self.client_ip.len);
        @memcpy(self.client_ip[0..len], ip[0..len]);
        self.client_ip_len = @intCast(len);
    }

    pub fn getClientIp(self: *const Connection) []const u8 {
        return self.client_ip[0..self.client_ip_len];
    }

    pub fn isAuthenticated(self: *const Connection) bool {
        return self.authenticated_pubkeys.count() > 0;
    }

    pub fn isPubkeyAuthenticated(self: *const Connection, pubkey: *const [32]u8) bool {
        return self.authenticated_pubkeys.contains(pubkey.*);
    }

    pub fn addAuthenticatedPubkey(self: *Connection, pubkey: *const [32]u8) !void {
        try self.authenticated_pubkeys.put(pubkey.*, {});
    }

    pub fn send(self: *Connection, data: []const u8) void {
        if (self.ws_conn) |conn| {
            conn.write(data) catch {};
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

    pub fn checkRateLimit(self: *Connection, limit: u32) bool {
        const now = std.time.timestamp();
        if (now - self.minute_start >= 60) {
            self.minute_start = now;
            self.events_this_minute = 0;
        }
        return self.events_this_minute < limit;
    }

    pub fn recordEvent(self: *Connection) void {
        self.events_this_minute += 1;
    }
};

pub const Subscription = struct {
    id: []const u8,
    filters: []const nostr.Filter,
    created_at: i64,
};
