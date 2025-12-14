const std = @import("std");
const nostr = @import("nostr.zig");
const httpz = @import("httpz");
const websocket = httpz.websocket;
const WriteQueue = @import("write_queue.zig").WriteQueue;

pub const NegSession = struct {
    storage: nostr.negentropy.VectorStorage,
    sealed: bool = false,

    pub fn init(allocator: std.mem.Allocator) NegSession {
        return .{ .storage = nostr.negentropy.VectorStorage.init(allocator) };
    }

    pub fn deinit(self: *NegSession) void {
        self.storage.deinit();
    }
};

pub const Connection = struct {
    id: u64,
    arena: std.heap.ArenaAllocator,
    subscriptions: std.StringHashMap(Subscription),
    neg_sessions: std.StringHashMap(NegSession),
    created_at: i64,
    last_activity: i64,
    ws_conn: ?*websocket.Conn = null,

    events_received: u64 = 0,
    events_sent: u64 = 0,
    event_timestamps: [256]i64 = undefined,
    event_ts_head: u8 = 0,
    event_ts_count: u8 = 0,

    client_ip: [64]u8 = undefined,
    client_ip_len: u8 = 0,
    auth_challenge: [32]u8 = undefined,
    authenticated_pubkeys: std.AutoHashMap([32]u8, void) = undefined,
    challenge_sent: bool = false,

    write_queue: WriteQueue,
    backing_allocator: std.mem.Allocator,

    pub fn init(self: *Connection, backing_allocator: std.mem.Allocator, id: u64) void {
        const now = std.time.timestamp();
        self.id = id;
        self.backing_allocator = backing_allocator;
        self.arena = std.heap.ArenaAllocator.init(backing_allocator);
        self.subscriptions = std.StringHashMap(Subscription).init(self.arena.allocator());
        self.neg_sessions = std.StringHashMap(NegSession).init(self.arena.allocator());
        self.created_at = now;
        self.last_activity = now;
        self.events_received = 0;
        self.events_sent = 0;
        self.client_ip = undefined;
        self.client_ip_len = 0;
        self.ws_conn = null;
        std.crypto.random.bytes(&self.auth_challenge);
        self.authenticated_pubkeys = std.AutoHashMap([32]u8, void).init(self.arena.allocator());
        self.challenge_sent = false;
        self.write_queue = WriteQueue.init(backing_allocator);
    }

    pub fn startWriteQueue(self: *Connection, ws_conn: *websocket.Conn) void {
        self.write_queue.start(ws_conn);
    }

    pub fn stopWriteQueue(self: *Connection) void {
        self.write_queue.stop();
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

    pub fn send(self: *Connection, data: []const u8) bool {
        return self.write_queue.enqueue(data);
    }

    pub fn sendDirect(self: *Connection, data: []const u8) void {
        if (self.ws_conn) |conn| {
            conn.write(data) catch {};
        }
    }

    pub fn deinit(self: *Connection) void {
        var neg_iter = self.neg_sessions.valueIterator();
        while (neg_iter.next()) |session| {
            session.deinit();
        }
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

    pub fn addNegSession(self: *Connection, sub_id: []const u8) !*NegSession {
        const alloc = self.allocator();
        if (self.neg_sessions.getPtr(sub_id)) |existing| {
            existing.deinit();
            _ = self.neg_sessions.remove(sub_id);
        }
        const sub_id_copy = try alloc.dupe(u8, sub_id);
        try self.neg_sessions.put(sub_id_copy, NegSession.init(self.backing_allocator));
        return self.neg_sessions.getPtr(sub_id_copy).?;
    }

    pub fn getNegSession(self: *Connection, sub_id: []const u8) ?*NegSession {
        return self.neg_sessions.getPtr(sub_id);
    }

    pub fn removeNegSession(self: *Connection, sub_id: []const u8) void {
        if (self.neg_sessions.getPtr(sub_id)) |session| {
            session.deinit();
        }
        _ = self.neg_sessions.remove(sub_id);
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

    pub fn checkEventRateLimit(self: *Connection, max_events_per_minute: u32) bool {
        if (max_events_per_minute == 0) return true;
        const now = std.time.timestamp();
        const window_start = now - 60;
        var count: u32 = 0;
        var i: u8 = 0;
        while (i < self.event_ts_count) : (i += 1) {
            const idx = self.event_ts_head -% i -% 1;
            if (self.event_timestamps[idx] >= window_start) {
                count += 1;
            }
        }
        return count < max_events_per_minute;
    }

    pub fn recordEvent(self: *Connection) void {
        const now = std.time.timestamp();
        self.event_timestamps[self.event_ts_head] = now;
        self.event_ts_head +%= 1;
        if (self.event_ts_count < 255) {
            self.event_ts_count += 1;
        }
        self.events_received += 1;
    }
};

pub const Subscription = struct {
    id: []const u8,
    filters: []const nostr.Filter,
    created_at: i64,
};
