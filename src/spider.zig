const std = @import("std");
const nostr = @import("nostr.zig");
const Store = @import("store.zig").Store;
const Broadcaster = @import("broadcaster.zig").Broadcaster;
const Config = @import("config.zig").Config;
const websocket = @import("websocket");

const log = std.log.scoped(.spider);
const negentropy = nostr.negentropy;

const BATCH_SIZE: usize = 20;
const BATCH_CREATION_DELAY_MS: u64 = 500;
const RECONNECT_DELAY_MS: u64 = 10_000;
const MAX_RECONNECT_DELAY_MS: u64 = 3600_000;
const BLACKOUT_MS: u64 = 24 * 3600_000;
const QUICK_DISCONNECT_MS: i64 = 120_000;
const RATE_LIMIT_BACKOFF_MS: u64 = 60_000;
const MAX_RATE_LIMIT_BACKOFF_MS: u64 = 1800_000;
const CATCHUP_WINDOW_MS: i64 = 1800_000;

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

        for (self.relays.keys()) |relay_url| {
            log.info("Bootstrapping admin events from {s}...", .{relay_url});

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
            const req_msg = std.fmt.bufPrint(&req_buf, "[\"REQ\",\"bootstrap\",{{\"kinds\":[0,3,10002],\"authors\":[\"{s}\"]}}]", .{self.config.spider_admin}) catch continue;

            client.writeText(@constCast(req_msg)) catch continue;

            var events_received: u64 = 0;
            var got_kind3 = false;
            var msg_count: usize = 0;
            while (msg_count < 20) : (msg_count += 1) {
                const message = client.read() catch break;
                if (message) |msg| {
                    defer client.done(msg);
                    if (msg.data.len > 0) {
                        if (std.mem.startsWith(u8, msg.data, "[\"EVENT\"")) {
                            self.handleRelayMessage(msg.data, relay_url, &events_received);
                            if (std.mem.indexOf(u8, msg.data, "\"kind\":3")) |_| {
                                got_kind3 = true;
                            }
                        }
                        if (std.mem.startsWith(u8, msg.data, "[\"EOSE\"")) {
                            break;
                        }
                    }
                }
            }

            if (events_received > 0) {
                log.info("Bootstrapped {d} admin events from {s}", .{ events_received, relay_url });
                if (got_kind3) return;
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
        const interval_s: u64 = @max(1, @as(u64, self.config.spider_sync_interval));
        const interval_ms: u64 = interval_s * 1000;
        while (self.running.load(.acquire)) {
            std.Thread.sleep(interval_ms * std.time.ns_per_ms);

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
        if (conn.isRateLimited()) {
            const wait_ms: u64 = @intCast(@max(0, conn.rate_limit_until - std.time.milliTimestamp()));
            log.info("{s}: Rate limited, waiting {d}ms", .{ relay_url, wait_ms });
            std.Thread.sleep(wait_ms * std.time.ns_per_ms);
        }

        const parsed = parseRelayUrl(relay_url) orelse {
            log.err("{s}: Invalid URL", .{relay_url});
            return false;
        };

        var client = websocket.Client.init(self.allocator, .{
            .host = parsed.host,
            .port = parsed.port,
            .tls = parsed.use_tls,
            .ca_bundle = self.ca_bundle,
            .max_size = 10 * 1024 * 1024,
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
        const now = std.time.milliTimestamp();

        if (conn.last_connect == 0) {
            self.performNegentropySync(&client, relay_url);
        } else if (conn.last_disconnect > 0) {
            self.performCatchup(&client, conn, relay_url);
        }

        conn.last_connect = now;
        conn.clearRateLimit();

        self.sendSubscriptions(&client, relay_url) catch |err| {
            log.err("{s}: Failed to send subscriptions: {}", .{ relay_url, err });
            return false;
        };

        self.readLoop(&client, relay_url);

        conn.last_disconnect = std.time.milliTimestamp();
        conn.state = .disconnected;
        return true;
    }

    fn performCatchup(self: *Spider, client: *websocket.Client, conn: *RelayConn, relay_url: []const u8) void {
        const since_ts = conn.last_disconnect - CATCHUP_WINDOW_MS;
        const until_ts = std.time.milliTimestamp() + CATCHUP_WINDOW_MS;
        const since_unix = @divFloor(since_ts, 1000);
        const until_unix = @divFloor(until_ts, 1000);

        log.info("{s}: Performing catch-up from {d} to {d}", .{ relay_url, since_unix, until_unix });

        self.follow_mutex.lock();
        defer self.follow_mutex.unlock();

        if (self.follow_pubkeys.items.len == 0) return;

        var msg_buf: [65536]u8 = undefined;
        const msg = buildCatchupReqMessage(&msg_buf, self.follow_pubkeys.items, since_unix, until_unix) catch |err| {
            log.err("{s}: Failed to build catch-up REQ: {}", .{ relay_url, err });
            return;
        };

        client.writeText(@constCast(msg)) catch |err| {
            log.err("{s}: Failed to send catch-up REQ: {}", .{ relay_url, err });
            return;
        };

        var catchup_events: u64 = 0;
        const catchup_start = std.time.milliTimestamp();
        const catchup_timeout_ms: i64 = 30_000;

        while (std.time.milliTimestamp() - catchup_start < catchup_timeout_ms) {
            const message = client.read() catch break;
            if (message) |msg_data| {
                defer client.done(msg_data);
                if (msg_data.data.len > 0) {
                    if (std.mem.startsWith(u8, msg_data.data, "[\"EOSE\"")) {
                        log.info("{s}: Catch-up complete, received {d} events", .{ relay_url, catchup_events });
                        break;
                    }
                    if (std.mem.startsWith(u8, msg_data.data, "[\"EVENT\"")) {
                        self.handleRelayMessage(msg_data.data, relay_url, &catchup_events);
                    }
                    if (std.mem.startsWith(u8, msg_data.data, "[\"NOTICE\"")) {
                        self.handleNotice(msg_data.data, relay_url);
                        if (conn.isRateLimited()) {
                            log.warn("{s}: Rate limited during catch-up, aborting", .{relay_url});
                            break;
                        }
                    }
                }
            }
        }

        var close_buf: [64]u8 = undefined;
        const close_msg = std.fmt.bufPrint(&close_buf, "[\"CLOSE\",\"catchup\"]", .{}) catch return;
        client.writeText(@constCast(close_msg)) catch {};

        log.info("{s}: Catch-up finished with {d} events", .{ relay_url, catchup_events });
    }

    fn performNegentropySync(self: *Spider, client: *websocket.Client, relay_url: []const u8) void {
        self.follow_mutex.lock();
        const pubkeys = self.allocator.dupe([32]u8, self.follow_pubkeys.items) catch {
            self.follow_mutex.unlock();
            return;
        };
        self.follow_mutex.unlock();
        defer self.allocator.free(pubkeys);

        if (pubkeys.len == 0) return;

        var local_storage = negentropy.VectorStorage.init(self.allocator);
        defer local_storage.deinit();

        const filters = [_]nostr.Filter{
            .{ .authors_bytes = pubkeys },
        };

        var iter = self.store.query(&filters, 100000) catch {
            log.err("{s}: Failed to query local events for negentropy", .{relay_url});
            return;
        };
        defer iter.deinit();

        var local_count: usize = 0;
        while (iter.next() catch null) |json| {
            var event = nostr.Event.parse(json) catch continue;
            defer event.deinit();
            local_storage.insert(@intCast(event.createdAt()), event.id()) catch continue;
            local_count += 1;
        }
        local_storage.seal();

        log.info("{s}: Negentropy sync starting with {d} local events", .{ relay_url, local_count });

        var filter_buf: [32768]u8 = undefined;
        const filter_json = buildNegentropyFilter(&filter_buf, pubkeys) catch {
            log.err("{s}: Failed to build negentropy filter", .{relay_url});
            return;
        };

        var neg = negentropy.Negentropy.init(local_storage.storage(), 0);
        var init_buf: [65536]u8 = undefined;
        const init_msg = neg.initiate(&init_buf) catch {
            log.err("{s}: Failed to initiate negentropy", .{relay_url});
            return;
        };

        var neg_open_buf: [131072]u8 = undefined;
        var fbs_neg = std.io.fixedBufferStream(&neg_open_buf);
        const neg_writer = fbs_neg.writer();
        neg_writer.print("[\"NEG-OPEN\",\"neg-sync\",{s},\"", .{filter_json}) catch {
            log.err("{s}: NEG-OPEN message too large", .{relay_url});
            return;
        };
        for (init_msg) |b| neg_writer.print("{x:0>2}", .{b}) catch return;
        neg_writer.writeAll("\"]") catch return;
        const neg_open = fbs_neg.getWritten();

        client.writeText(@constCast(neg_open)) catch |err| {
            log.err("{s}: Failed to send NEG-OPEN: {}", .{ relay_url, err });
            return;
        };

        var have_ids: std.ArrayListUnmanaged([32]u8) = .{};
        defer have_ids.deinit(self.allocator);
        var need_ids: std.ArrayListUnmanaged([32]u8) = .{};
        defer need_ids.deinit(self.allocator);

        const sync_start = std.time.milliTimestamp();
        const initial_timeout_ms: i64 = 5_000;
        const sync_timeout_ms: i64 = 60_000;
        var rounds: usize = 0;
        var got_response = false;

        while (std.time.milliTimestamp() - sync_start < sync_timeout_ms) {
            if (!got_response and std.time.milliTimestamp() - sync_start > initial_timeout_ms) {
                log.warn("{s}: No negentropy response, relay may not support NIP-77", .{relay_url});
                return;
            }
            const message = client.read() catch break;
            if (message) |msg| {
                defer client.done(msg);
                if (msg.data.len == 0) continue;

                if (std.mem.startsWith(u8, msg.data, "[\"NEG-ERR\"")) {
                    log.warn("{s}: Negentropy not supported, falling back to REQ", .{relay_url});
                    var close_buf: [64]u8 = undefined;
                    const close_msg = std.fmt.bufPrint(&close_buf, "[\"NEG-CLOSE\",\"neg-sync\"]", .{}) catch break;
                    client.writeText(@constCast(close_msg)) catch {};
                    return;
                }

                if (std.mem.startsWith(u8, msg.data, "[\"NEG-MSG\"")) {
                    got_response = true;
                    rounds += 1;
                    const payload = extractNegPayload(msg.data) orelse continue;
                    const decoded = decodeHexPayload(payload, self.allocator) catch continue;
                    defer self.allocator.free(decoded);

                    var out_buf: [65536]u8 = undefined;
                    var result = neg.reconcile(decoded, &out_buf, self.allocator) catch continue;

                    for (result.have_ids.items) |id| have_ids.append(self.allocator, id) catch {};
                    for (result.need_ids.items) |id| need_ids.append(self.allocator, id) catch {};

                    const output_len = result.output.len;
                    const have_count = result.have_ids.items.len;
                    const need_count = result.need_ids.items.len;

                    if (output_len == 0 or (have_count == 0 and need_count == 0 and rounds > 1)) {
                        result.deinit();
                        log.info("{s}: Negentropy sync complete after {d} rounds", .{ relay_url, rounds });
                        break;
                    }

                    var neg_msg_buf: [131072]u8 = undefined;
                    var fbs_msg = std.io.fixedBufferStream(&neg_msg_buf);
                    const msg_writer = fbs_msg.writer();
                    msg_writer.writeAll("[\"NEG-MSG\",\"neg-sync\",\"") catch {
                        result.deinit();
                        continue;
                    };
                    for (result.output) |b| msg_writer.print("{x:0>2}", .{b}) catch {
                        result.deinit();
                        continue;
                    };
                    msg_writer.writeAll("\"]") catch {
                        result.deinit();
                        continue;
                    };
                    result.deinit();

                    client.writeText(@constCast(fbs_msg.getWritten())) catch break;
                }
            }
        }

        var close_buf: [64]u8 = undefined;
        const close_msg = std.fmt.bufPrint(&close_buf, "[\"NEG-CLOSE\",\"neg-sync\"]", .{}) catch return;
        client.writeText(@constCast(close_msg)) catch {};

        log.info("{s}: Need {d} events, have {d} events to skip", .{ relay_url, need_ids.items.len, have_ids.items.len });

        if (need_ids.items.len > 0) {
            self.fetchEventsByIds(client, relay_url, need_ids.items);
        }
    }

    fn fetchEventsByIds(self: *Spider, client: *websocket.Client, relay_url: []const u8, ids: [][32]u8) void {
        const batch_size: usize = 100;
        var fetched: u64 = 0;
        var i: usize = 0;

        while (i < ids.len) {
            const end = @min(i + batch_size, ids.len);
            const batch = ids[i..end];

            var msg_buf: [65536]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&msg_buf);
            const writer = fbs.writer();

            const req_msg = build_req: {
                writer.writeAll("[\"REQ\",\"fetch\",{\"ids\":[") catch break :build_req null;
                for (batch, 0..) |id, j| {
                    if (j > 0) writer.writeAll(",") catch break :build_req null;
                    writer.writeAll("\"") catch break :build_req null;
                    for (id) |b| writer.print("{x:0>2}", .{b}) catch break :build_req null;
                    writer.writeAll("\"") catch break :build_req null;
                }
                writer.writeAll("]}]") catch break :build_req null;
                break :build_req fbs.getWritten();
            };

            if (req_msg) |msg| {
                client.writeText(@constCast(msg)) catch break;
            } else {
                i = end;
                continue;
            }

            const fetch_start = std.time.milliTimestamp();
            while (std.time.milliTimestamp() - fetch_start < 30_000) {
                const message = client.read() catch break;
                if (message) |msg| {
                    defer client.done(msg);
                    if (std.mem.startsWith(u8, msg.data, "[\"EOSE\"")) break;
                    if (std.mem.startsWith(u8, msg.data, "[\"EVENT\"")) {
                        self.handleRelayMessage(msg.data, relay_url, &fetched);
                    }
                }
            }

            var close_buf: [64]u8 = undefined;
            const close_msg = std.fmt.bufPrint(&close_buf, "[\"CLOSE\",\"fetch\"]", .{}) catch break;
            client.writeText(@constCast(close_msg)) catch {};

            i = end;
        }

        log.info("{s}: Fetched {d} events via negentropy sync", .{ relay_url, fetched });
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
        if (data.len > 10 and std.mem.startsWith(u8, data, "[\"NOTICE\"")) {
            self.handleNotice(data, relay_url);
            return;
        }

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

    fn handleNotice(self: *Spider, data: []const u8, relay_url: []const u8) void {
        const notice_start = std.mem.indexOf(u8, data, ",") orelse return;
        if (notice_start + 2 >= data.len) return;

        var msg_start: usize = notice_start + 1;
        while (msg_start < data.len and data[msg_start] != '"') : (msg_start += 1) {}
        if (msg_start >= data.len) return;
        msg_start += 1;

        var msg_end = msg_start;
        while (msg_end < data.len and data[msg_end] != '"') : (msg_end += 1) {}
        if (msg_end >= data.len) return;

        const notice_msg = data[msg_start..msg_end];
        log.info("{s}: NOTICE: {s}", .{ relay_url, notice_msg });

        if (std.mem.indexOf(u8, notice_msg, "rate") != null or
            std.mem.indexOf(u8, notice_msg, "too many") != null or
            std.mem.indexOf(u8, notice_msg, "slow down") != null or
            std.mem.indexOf(u8, notice_msg, "REQ") != null)
        {
            if (self.relays.getPtr(relay_url)) |conn| {
                conn.applyRateLimit();
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
    last_disconnect: i64 = 0,
    rate_limit_until: i64 = 0,
    rate_limit_backoff_ms: u64 = RATE_LIMIT_BACKOFF_MS,

    const State = enum { disconnected, connecting, connected };

    fn init(url: []const u8) RelayConn {
        return .{ .url = url };
    }

    fn applyRateLimit(self: *RelayConn) void {
        const now = std.time.milliTimestamp();
        self.rate_limit_until = now + @as(i64, @intCast(self.rate_limit_backoff_ms));
        log.warn("{s}: Rate limited, backing off for {d}ms", .{ self.url, self.rate_limit_backoff_ms });
        self.rate_limit_backoff_ms = @min(self.rate_limit_backoff_ms * 2, MAX_RATE_LIMIT_BACKOFF_MS);
    }

    fn isRateLimited(self: *const RelayConn) bool {
        return std.time.milliTimestamp() < self.rate_limit_until;
    }

    fn clearRateLimit(self: *RelayConn) void {
        self.rate_limit_backoff_ms = RATE_LIMIT_BACKOFF_MS;
        self.rate_limit_until = 0;
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

fn buildCatchupReqMessage(buf: []u8, pubkeys: [][32]u8, since: i64, until: i64) ![]u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const writer = fbs.writer();

    try writer.writeAll("[\"REQ\",\"catchup\",");
    try writer.writeAll("{\"authors\":[");
    for (pubkeys, 0..) |pk, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.print("\"{x}\"", .{pk});
    }
    try writer.print("],\"since\":{d},\"until\":{d}}},", .{ since, until });
    try writer.writeAll("{\"#p\":[");
    for (pubkeys, 0..) |pk, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.print("\"{x}\"", .{pk});
    }
    try writer.print("],\"since\":{d},\"until\":{d}}}]", .{ since, until });

    return fbs.getWritten();
}

fn buildNegentropyFilter(buf: []u8, pubkeys: [][32]u8) ![]u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const writer = fbs.writer();

    try writer.writeAll("{\"authors\":[");
    for (pubkeys, 0..) |pk, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.print("\"{x}\"", .{pk});
    }
    try writer.writeAll("]}");

    return fbs.getWritten();
}

fn extractNegPayload(data: []const u8) ?[]const u8 {
    var comma_count: usize = 0;
    var in_string = false;
    var escape = false;
    var payload_start: ?usize = null;

    for (data, 0..) |c, i| {
        if (escape) {
            escape = false;
            continue;
        }
        if (c == '\\' and in_string) {
            escape = true;
            continue;
        }
        if (c == '"') {
            if (!in_string and comma_count == 2) {
                payload_start = i + 1;
            } else if (in_string and payload_start != null) {
                return data[payload_start.?..i];
            }
            in_string = !in_string;
            continue;
        }
        if (!in_string and c == ',') {
            comma_count += 1;
        }
    }
    return null;
}

fn decodeHexPayload(hex: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = std.fmt.hexToBytes(out, hex) catch {
        allocator.free(out);
        return error.InvalidHex;
    };
    return out;
}
