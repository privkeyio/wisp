const std = @import("std");
const nostr = @import("nostr.zig");
const Store = @import("store.zig").Store;
const Broadcaster = @import("broadcaster.zig").Broadcaster;
const Config = @import("config.zig").Config;
const websocket = @import("websocket");

const log = std.log.scoped(.spider);

const BATCH_SIZE: usize = 20;
const BATCH_CREATION_DELAY_MS: u64 = 500;
const RECONNECT_DELAY_MS: u64 = 10_000;
const MAX_RECONNECT_DELAY_MS: u64 = 3600_000;
const BLACKOUT_MS: u64 = 24 * 3600_000;
const REFRESH_INTERVAL_MS: u64 = 300_000;
const QUICK_DISCONNECT_MS: i64 = 120_000;

pub const Spider = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    store: *Store,
    broadcaster: *Broadcaster,
    running: std.atomic.Value(bool),
    relays: std.StringArrayHashMap(RelayConn),
    follow_pubkeys: std.ArrayListUnmanaged([32]u8),
    follow_mutex: std.Thread.Mutex,
    threads: std.ArrayListUnmanaged(std.Thread),
    ca_bundle: std.crypto.Certificate.Bundle,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const Config,
        store: *Store,
        broadcaster: *Broadcaster,
    ) !Spider {
        var spider = Spider{
            .allocator = allocator,
            .config = config,
            .store = store,
            .broadcaster = broadcaster,
            .running = std.atomic.Value(bool).init(false),
            .relays = std.StringArrayHashMap(RelayConn).init(allocator),
            .follow_pubkeys = .{},
            .follow_mutex = .{},
            .threads = .{},
            .ca_bundle = .{},
        };

        try spider.ca_bundle.rescan(allocator);

        var relay_iter = std.mem.splitScalar(u8, config.spider_relays, ',');
        while (relay_iter.next()) |relay_url| {
            const trimmed = std.mem.trim(u8, relay_url, " \t");
            if (trimmed.len == 0) continue;

            const url_copy = try allocator.dupe(u8, trimmed);
            try spider.relays.put(url_copy, RelayConn.init(url_copy));
        }

        return spider;
    }

    pub fn deinit(self: *Spider) void {
        self.ca_bundle.deinit(self.allocator);
        for (self.relays.keys()) |key| {
            self.allocator.free(key);
        }
        self.relays.deinit();
        self.follow_pubkeys.deinit(self.allocator);
        self.threads.deinit(self.allocator);
    }

    pub fn start(self: *Spider) !void {
        if (self.relays.count() == 0) {
            log.warn("Spider enabled but no relays configured", .{});
            return;
        }

        self.running.store(true, .release);
        self.refreshFollowList();

        if (self.follow_pubkeys.items.len == 0) {
            log.warn("Spider enabled but no pubkeys to follow", .{});
        }

        log.info("Spider starting with {d} relays, {d} pubkeys", .{
            self.relays.count(),
            self.follow_pubkeys.items.len,
        });

        for (self.relays.keys()) |relay_url| {
            const thread = try std.Thread.spawn(.{}, relayLoop, .{ self, relay_url });
            try self.threads.append(self.allocator, thread);
        }

        const refresh_thread = try std.Thread.spawn(.{}, refreshLoop, .{self});
        try self.threads.append(self.allocator, refresh_thread);
    }

    pub fn stop(self: *Spider) void {
        log.info("Spider stopping...", .{});
        self.running.store(false, .release);

        for (self.threads.items) |thread| {
            thread.join();
        }
        self.threads.clearRetainingCapacity();

        log.info("Spider stopped", .{});
    }

    fn refreshFollowList(self: *Spider) void {
        self.follow_mutex.lock();
        defer self.follow_mutex.unlock();

        self.follow_pubkeys.clearRetainingCapacity();

        if (self.config.spider_admin.len == 64) {
            if (self.loadKind3FollowList()) {
                log.info("Loaded {d} pubkeys from kind 3 contact list", .{self.follow_pubkeys.items.len});
                return;
            }
            log.info("No local kind 3 found, bootstrapping from remote relay...", .{});
            self.follow_mutex.unlock();
            self.bootstrapKind3();
            self.follow_mutex.lock();
            if (self.loadKind3FollowList()) {
                log.info("Loaded {d} pubkeys from bootstrapped kind 3 contact list", .{self.follow_pubkeys.items.len});
                return;
            }
        }

        self.loadConfigPubkeys();
        log.info("Loaded {d} pubkeys from config", .{self.follow_pubkeys.items.len});
    }

    fn bootstrapKind3(self: *Spider) void {
        if (self.config.spider_admin.len != 64) return;

        var owner_pubkey: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&owner_pubkey, self.config.spider_admin) catch return;

        // Try each configured relay
        for (self.relays.keys()) |relay_url| {
            log.info("Bootstrapping kind 3 from {s}...", .{relay_url});

            const parsed = parseRelayUrl(relay_url) orelse continue;

            var client = websocket.Client.init(self.allocator, .{
                .host = parsed.host,
                .port = parsed.port,
                .tls = parsed.use_tls,
                .ca_bundle = self.ca_bundle,
                .max_size = 1024 * 1024,
            }) catch continue;
            defer client.deinit();

            var host_header_buf: [256]u8 = undefined;
            const host_header = std.fmt.bufPrint(&host_header_buf, "Host: {s}\r\n", .{parsed.host}) catch continue;

            client.handshake(parsed.path, .{ .headers = host_header }) catch continue;

            var req_buf: [512]u8 = undefined;
            const req_msg = std.fmt.bufPrint(&req_buf, "[\"REQ\",\"bootstrap\",{{\"kinds\":[3],\"authors\":[\"{s}\"],\"limit\":1}}]", .{self.config.spider_admin}) catch continue;

            client.writeText(@constCast(req_msg)) catch continue;

            var msg_count: usize = 0;
            while (msg_count < 10) : (msg_count += 1) {
                const message = client.read() catch break;
                if (message) |msg| {
                    defer client.done(msg);
                    if (msg.data.len > 0) {
                        if (std.mem.startsWith(u8, msg.data, "[\"EVENT\"")) {
                            var dummy: u64 = 0;
                            self.handleRelayMessage(msg.data, relay_url, &dummy);
                            log.info("Bootstrapped kind 3 from {s}", .{relay_url});
                            return;
                        }
                        if (std.mem.startsWith(u8, msg.data, "[\"EOSE\"")) {
                            break;
                        }
                    }
                }
            }
        }
        log.warn("Failed to bootstrap kind 3 from any relay", .{});
    }

    fn loadKind3FollowList(self: *Spider) bool {
        var owner_pubkey: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&owner_pubkey, self.config.spider_admin) catch return false;

        var authors_array = [1][32]u8{owner_pubkey};
        const filters = [_]nostr.Filter{.{
            .kinds_slice = &[_]i32{3},
            .authors_bytes = &authors_array,
            .limit_val = 1,
        }};

        var iter = self.store.query(&filters, 1) catch return false;
        defer iter.deinit();

        const json = (iter.next() catch return false) orelse return false;

        var event = nostr.Event.parse(json) catch return false;
        defer event.deinit();

        if (event.tags.get('p')) |p_tags| {
            for (p_tags) |tag| {
                switch (tag) {
                    .binary => |bytes| {
                        self.follow_pubkeys.append(self.allocator, bytes) catch continue;
                    },
                    .string => {},
                }
            }
        }

        return self.follow_pubkeys.items.len > 0;
    }

    fn loadConfigPubkeys(self: *Spider) void {
        var pubkey_iter = std.mem.splitScalar(u8, self.config.spider_pubkeys, ',');
        while (pubkey_iter.next()) |pubkey_str| {
            const trimmed = std.mem.trim(u8, pubkey_str, " \t");
            if (trimmed.len != 64) continue;

            var pubkey: [32]u8 = undefined;
            if (std.fmt.hexToBytes(&pubkey, trimmed)) |_| {
                self.follow_pubkeys.append(self.allocator, pubkey) catch continue;
            } else |_| {}
        }
    }

    fn refreshLoop(self: *Spider) void {
        while (self.running.load(.acquire)) {
            std.Thread.sleep(REFRESH_INTERVAL_MS * std.time.ns_per_ms);

            if (!self.running.load(.acquire)) break;

            const old_count = blk: {
                self.follow_mutex.lock();
                defer self.follow_mutex.unlock();
                break :blk self.follow_pubkeys.items.len;
            };

            self.refreshFollowList();

            const new_count = blk: {
                self.follow_mutex.lock();
                defer self.follow_mutex.unlock();
                break :blk self.follow_pubkeys.items.len;
            };

            if (old_count != new_count) {
                log.info("Follow list updated: {d} -> {d} pubkeys", .{ old_count, new_count });
            }
        }
    }

    fn relayLoop(self: *Spider, relay_url: []const u8) void {
        log.info("Starting relay loop for {s}", .{relay_url});

        var conn = self.relays.getPtr(relay_url) orelse return;

        while (self.running.load(.acquire)) {
            if (conn.blackout_until > 0) {
                const now = std.time.milliTimestamp();
                if (now < conn.blackout_until) {
                    const wait_ms: u64 = @intCast(conn.blackout_until - now);
                    log.info("{s}: In blackout for {d}ms more", .{ relay_url, wait_ms });
                    std.Thread.sleep(@as(u64, @min(wait_ms, 60_000)) * std.time.ns_per_ms);
                    continue;
                }
                conn.blackout_until = 0;
                conn.reconnect_delay_ms = RECONNECT_DELAY_MS;
            }

            log.info("{s}: Connecting...", .{relay_url});
            const connect_start = std.time.milliTimestamp();
            const success = self.connectAndSubscribe(conn, relay_url);
            const connection_duration = std.time.milliTimestamp() - connect_start;

            if (success) {
                if (connection_duration < QUICK_DISCONNECT_MS) {
                    log.warn("{s}: Quick disconnect after {d}ms", .{ relay_url, connection_duration });
                    conn.reconnect_delay_ms = @min(conn.reconnect_delay_ms * 2, MAX_RECONNECT_DELAY_MS);
                } else {
                    log.info("{s}: Disconnected after {d}ms uptime", .{ relay_url, connection_duration });
                    if (conn.reconnect_delay_ms > RECONNECT_DELAY_MS * 8) {
                        conn.reconnect_delay_ms = conn.reconnect_delay_ms / 2;
                    } else {
                        conn.reconnect_delay_ms = RECONNECT_DELAY_MS;
                    }
                }
                std.Thread.sleep(5 * std.time.ns_per_s);
            } else {
                log.warn("{s}: Connection failed, waiting {d}ms", .{ relay_url, conn.reconnect_delay_ms });
                std.Thread.sleep(conn.reconnect_delay_ms * std.time.ns_per_ms);
                conn.reconnect_delay_ms = @min(conn.reconnect_delay_ms * 2, MAX_RECONNECT_DELAY_MS);
            }

            if (conn.reconnect_delay_ms >= MAX_RECONNECT_DELAY_MS) {
                conn.blackout_until = std.time.milliTimestamp() + @as(i64, @intCast(BLACKOUT_MS));
                conn.reconnect_delay_ms = RECONNECT_DELAY_MS;
                log.warn("{s}: Entering 24h blackout", .{relay_url});
            }
        }

        log.info("Exiting relay loop for {s}", .{relay_url});
    }

    fn connectAndSubscribe(self: *Spider, conn: *RelayConn, relay_url: []const u8) bool {
        const parsed = parseRelayUrl(relay_url) orelse {
            log.err("{s}: Invalid URL", .{relay_url});
            return false;
        };

        var client = websocket.Client.init(self.allocator, .{
            .host = parsed.host,
            .port = parsed.port,
            .tls = parsed.use_tls,
            .ca_bundle = self.ca_bundle,
            .max_size = 1024 * 1024,
        }) catch |err| {
            log.err("{s}: Failed to connect: {}", .{ relay_url, err });
            return false;
        };
        defer client.deinit();

        var host_header_buf: [256]u8 = undefined;
        const host_header = std.fmt.bufPrint(&host_header_buf, "Host: {s}\r\n", .{parsed.host}) catch {
            log.err("{s}: Host too long", .{relay_url});
            return false;
        };

        client.handshake(parsed.path, .{
            .headers = host_header,
        }) catch |err| {
            log.err("{s}: WebSocket handshake failed: {}", .{ relay_url, err });
            return false;
        };

        log.info("{s}: Connected{s}", .{ relay_url, if (parsed.use_tls) " (TLS)" else "" });
        conn.state = .connected;
        conn.last_connect = std.time.milliTimestamp();

        self.sendSubscriptions(&client, relay_url) catch |err| {
            log.err("{s}: Failed to send subscriptions: {}", .{ relay_url, err });
            return false;
        };

        self.readLoop(&client, relay_url);

        conn.state = .disconnected;
        return true;
    }

    fn sendSubscriptions(self: *Spider, client: *websocket.Client, relay_url: []const u8) !void {
        self.follow_mutex.lock();
        defer self.follow_mutex.unlock();

        if (self.follow_pubkeys.items.len == 0) {
            log.warn("{s}: No pubkeys to subscribe to", .{relay_url});
            return;
        }

        var batch_idx: usize = 0;
        var i: usize = 0;

        while (i < self.follow_pubkeys.items.len) {
            const end = @min(i + BATCH_SIZE, self.follow_pubkeys.items.len);
            const batch = self.follow_pubkeys.items[i..end];

            var msg_buf: [65536]u8 = undefined;
            const msg = buildReqMessage(&msg_buf, batch_idx, batch) catch |err| {
                log.err("{s}: Failed to build REQ: {}", .{ relay_url, err });
                return err;
            };

            client.writeText(@constCast(msg)) catch |err| {
                log.err("{s}: Failed to send REQ: {}", .{ relay_url, err });
                return err;
            };

            log.debug("{s}: Sent subscription batch-{d} with {d} pubkeys", .{ relay_url, batch_idx, batch.len });

            batch_idx += 1;
            i = end;

            if (i < self.follow_pubkeys.items.len) {
                std.Thread.sleep(BATCH_CREATION_DELAY_MS * std.time.ns_per_ms);
            }
        }

        log.info("{s}: Sent {d} subscription batches", .{ relay_url, batch_idx });
    }

    fn readLoop(self: *Spider, client: *websocket.Client, relay_url: []const u8) void {
        var events_received: u64 = 0;

        while (self.running.load(.acquire)) {
            const message = client.read() catch |err| {
                if (err == error.Closed or err == error.ConnectionResetByPeer) {
                    log.info("{s}: Connection closed", .{relay_url});
                } else {
                    log.err("{s}: Read error: {}", .{ relay_url, err });
                }
                return;
            };

            if (message) |msg| {
                defer client.done(msg);
                if (msg.data.len > 0) {
                    self.handleRelayMessage(msg.data, relay_url, &events_received);
                }
            }
        }

        log.info("{s}: Read loop exiting, received {d} events", .{ relay_url, events_received });
    }

    fn handleRelayMessage(self: *Spider, data: []const u8, relay_url: []const u8, events_received: *u64) void {
        if (data.len < 10 or !std.mem.startsWith(u8, data, "[\"EVENT\"")) return;

        var depth: i32 = 0;
        var in_string = false;
        var escape = false;
        var comma_count: u32 = 0;
        var event_start: ?usize = null;

        for (data, 0..) |c, idx| {
            if (escape) {
                escape = false;
                continue;
            }
            if (c == '\\' and in_string) {
                escape = true;
                continue;
            }
            if (c == '"') {
                in_string = !in_string;
                continue;
            }
            if (in_string) continue;

            if (c == '[' or c == '{') depth += 1;
            if (c == ']' or c == '}') depth -= 1;
            if (c == ',' and depth == 1) {
                comma_count += 1;
                if (comma_count == 2) {
                    event_start = idx + 1;
                    break;
                }
            }
        }

        const evt_start = event_start orelse return;
        var actual_start = evt_start;
        while (actual_start < data.len and (data[actual_start] == ' ' or data[actual_start] == '\t')) {
            actual_start += 1;
        }

        if (actual_start >= data.len or data[actual_start] != '{') return;

        const event_json = blk: {
            var d: i32 = 0;
            var in_str = false;
            var esc = false;
            for (data[actual_start..], actual_start..) |c, idx| {
                if (esc) {
                    esc = false;
                    continue;
                }
                if (c == '\\' and in_str) {
                    esc = true;
                    continue;
                }
                if (c == '"') {
                    in_str = !in_str;
                    continue;
                }
                if (in_str) continue;
                if (c == '{') d += 1;
                if (c == '}') {
                    d -= 1;
                    if (d == 0) {
                        break :blk data[actual_start .. idx + 1];
                    }
                }
            }
            return;
        };

        var event = nostr.Event.parseWithAllocator(event_json, self.allocator) catch return;
        defer event.deinit();

        event.validate() catch return;

        const result = self.store.store(&event, event_json) catch return;

        if (result.stored) {
            events_received.* += 1;
            self.broadcaster.broadcast(&event);

            if (events_received.* % 100 == 0) {
                log.info("{s}: Stored {d} events", .{ relay_url, events_received.* });
            }
        }
    }
};

const RelayConn = struct {
    url: []const u8,
    state: State = .disconnected,
    reconnect_delay_ms: u64 = RECONNECT_DELAY_MS,
    blackout_until: i64 = 0,
    last_connect: i64 = 0,

    const State = enum { disconnected, connecting, connected };

    fn init(url: []const u8) RelayConn {
        return .{ .url = url };
    }
};

const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
    use_tls: bool,
};

fn parseRelayUrl(url: []const u8) ?ParsedUrl {
    var use_tls = false;
    var rest = url;

    if (std.mem.startsWith(u8, url, "wss://")) {
        use_tls = true;
        rest = url[6..];
    } else if (std.mem.startsWith(u8, url, "ws://")) {
        rest = url[5..];
    } else {
        return null;
    }

    var path: []const u8 = "/";
    const path_start = std.mem.indexOf(u8, rest, "/");
    var host_port = rest;
    if (path_start) |idx| {
        path = rest[idx..];
        host_port = rest[0..idx];
    }

    var port: u16 = if (use_tls) 443 else 80;
    var host = host_port;
    if (std.mem.indexOf(u8, host_port, ":")) |colon| {
        host = host_port[0..colon];
        port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch return null;
    }

    return .{
        .host = host,
        .port = port,
        .path = path,
        .use_tls = use_tls,
    };
}

fn buildReqMessage(buf: []u8, batch_idx: usize, pubkeys: [][32]u8) ![]u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const writer = fbs.writer();

    try writer.print("[\"REQ\",\"spider-batch-{d}\",", .{batch_idx});

    try writer.writeAll("{\"authors\":[");
    for (pubkeys, 0..) |pk, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.print("\"{x}\"", .{pk});
    }
    try writer.writeAll("]},");

    try writer.writeAll("{\"#p\":[");
    for (pubkeys, 0..) |pk, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.print("\"{x}\"", .{pk});
    }
    try writer.writeAll("]}]");

    return fbs.getWritten();
}
