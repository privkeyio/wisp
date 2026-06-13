const std = @import("std");
const nostr = @import("nostr.zig");
const websocket = @import("httpz").websocket;

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
    last_activity: std.atomic.Value(i64),
    // Thread-safe writer provided by websocket.zig; serializes per-connection
    // writes internally, so both REQ streaming and broadcast use it directly.
    ws_conn: ?*websocket.Conn = null,

    events_sent: std.atomic.Value(u64) = .init(0),

    client_ip: [64]u8 = undefined,
    client_ip_len: u8 = 0,
    auth_challenge: [32]u8 = undefined,
    authenticated_pubkeys: std.AutoHashMap([32]u8, void) = undefined,
    challenge_sent: bool = false,

    backing_allocator: std.mem.Allocator,
    deinitialized: bool = false,

    // Counts broadcasts/idle-closes that have snapshotted this connection under
    // the shared subs lock and may write to it after releasing the lock. close()
    // drains this to zero before freeing, preventing use-after-free.
    write_guard: std.atomic.Value(u32) = .init(0),

    pub fn init(self: *Connection, backing_allocator: std.mem.Allocator, id: u64) void {
        const now = nostr.io.timestamp();
        self.id = id;
        self.backing_allocator = backing_allocator;
        self.arena = std.heap.ArenaAllocator.init(backing_allocator);
        self.subscriptions = std.StringHashMap(Subscription).init(self.arena.allocator());
        self.neg_sessions = std.StringHashMap(NegSession).init(self.arena.allocator());
        self.created_at = now;
        self.last_activity = .init(now);
        self.events_sent = .init(0);
        self.write_guard = .init(0);
        self.client_ip = undefined;
        self.client_ip_len = 0;
        self.ws_conn = null;
        nostr.io.randomBytes(&self.auth_challenge);
        self.authenticated_pubkeys = std.AutoHashMap([32]u8, void).init(self.arena.allocator());
        self.challenge_sent = false;
        self.deinitialized = false;
    }

    pub fn setWsConn(self: *Connection, conn: *websocket.Conn) void {
        self.ws_conn = conn;
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

    /// Thread-safe write of a complete relay message (text frame). Used by both
    /// synchronous REQ streaming and concurrent broadcast; websocket.zig
    /// serializes per-connection writes. Returns an error if the peer is gone or
    /// the write times out, which callers use to stop streaming.
    pub fn write(self: *Connection, data: []const u8) !void {
        const conn = self.ws_conn orelse return error.NotConnected;
        return conn.write(data);
    }

    /// Request the connection be closed (e.g. idle timeout). Safe to call from
    /// another thread.
    pub fn closeWs(self: *Connection) void {
        if (self.ws_conn) |conn| {
            conn.close(.{}) catch {};
        }
    }

    pub fn deinit(self: *Connection) void {
        if (self.deinitialized) return;
        self.deinitialized = true;
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
        // Drop any existing subscription with this id first so replacing one at
        // capacity is allowed; only genuinely new ids are subject to the limit.
        self.removeSubscription(sub_id);

        if (self.subscriptions.count() >= max_subs) {
            return error.TooManySubscriptions;
        }

        const alloc = self.allocator();

        const sub_id_copy = try alloc.dupe(u8, sub_id);
        const filters_copy = try alloc.alloc(nostr.Filter, filters.len);
        for (filters, 0..) |f, i| {
            filters_copy[i] = try f.clone(alloc);
        }

        try self.subscriptions.put(sub_id_copy, .{
            .id = sub_id_copy,
            .filters = filters_copy,
            .created_at = nostr.io.timestamp(),
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
        self.last_activity.store(nostr.io.timestamp(), .monotonic);
    }

    /// Block until no broadcaster/idle-close still holds a write reference to this
    /// connection. Must be called after the connection is removed from the subs
    /// registry (so no new references can be taken) and before deinit/destroy.
    pub fn waitForPendingWrites(self: *Connection) void {
        while (self.write_guard.load(.acquire) != 0) {
            std.Io.sleep(nostr.io.io(), .{ .nanoseconds = std.time.ns_per_ms }, .awake) catch {};
        }
    }

};

pub const Subscription = struct {
    id: []const u8,
    filters: []const nostr.Filter,
    created_at: i64,
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

test "addSubscription enforces max_subs" {
    var conn: Connection = undefined;
    conn.init(testing.allocator, 1);
    defer conn.deinit();

    var req = try nostr.ClientMsg.parse("[\"REQ\",\"s\",{\"kinds\":[1]}]");
    defer req.deinit();
    const filters = try req.getFilters(conn.allocator());

    try conn.addSubscription("a", filters, 2);
    try conn.addSubscription("b", filters, 2);
    try testing.expectError(error.TooManySubscriptions, conn.addSubscription("c", filters, 2));
    try testing.expectEqual(@as(usize, 2), conn.subscriptions.count());
}

test "addSubscription replaces an existing id in place" {
    var conn: Connection = undefined;
    conn.init(testing.allocator, 1);
    defer conn.deinit();

    var req = try nostr.ClientMsg.parse("[\"REQ\",\"s\",{\"kinds\":[1]}]");
    defer req.deinit();
    const filters = try req.getFilters(conn.allocator());

    try conn.addSubscription("a", filters, 5);
    try conn.addSubscription("a", filters, 5);
    try testing.expectEqual(@as(usize, 1), conn.subscriptions.count());

    // Replacing an existing id is allowed even at capacity; only new ids are
    // rejected once max_subs is reached.
    try conn.addSubscription("b", filters, 2);
    try testing.expectEqual(@as(usize, 2), conn.subscriptions.count());
    try conn.addSubscription("a", filters, 2);
    try testing.expectEqual(@as(usize, 2), conn.subscriptions.count());
    try testing.expect(conn.subscriptions.contains("a"));
    try testing.expectError(error.TooManySubscriptions, conn.addSubscription("c", filters, 2));
}

test "matchesEvent returns the matching sub id or null" {
    var conn: Connection = undefined;
    conn.init(testing.allocator, 1);
    defer conn.deinit();

    var req = try nostr.ClientMsg.parse("[\"REQ\",\"kind1\",{\"kinds\":[1]}]");
    defer req.deinit();
    const filters = try req.getFilters(conn.allocator());
    try conn.addSubscription("kind1", filters, 5);

    var ev1 = try nostr.ClientMsg.parse(eventJson("1"));
    defer ev1.deinit();
    const event1 = try ev1.getEvent();
    try testing.expectEqualStrings("kind1", conn.matchesEvent(&event1).?);

    var ev7 = try nostr.ClientMsg.parse(eventJson("7"));
    defer ev7.deinit();
    const event7 = try ev7.getEvent();
    try testing.expect(conn.matchesEvent(&event7) == null);
}
