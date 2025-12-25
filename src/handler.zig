const std = @import("std");
const Config = @import("config.zig").Config;
const Store = @import("store.zig").Store;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const Broadcaster = @import("broadcaster.zig").Broadcaster;
const connection = @import("connection.zig");
const Connection = connection.Connection;
const NegSession = connection.NegSession;
const nostr = @import("nostr.zig");
const rate_limiter = @import("rate_limiter.zig");

fn isMultiKindOnly(f: *const nostr.Filter) bool {
    const kinds = f.kinds() orelse return false;
    if (kinds.len < 2) return false;
    if (f.authors() != null) return false;
    if (f.ids() != null) return false;
    if (f.hasTagFilters()) return false;
    return true;
}

fn isKindOnlyQuery(f: *const nostr.Filter) bool {
    const kinds = f.kinds() orelse return false;
    if (kinds.len == 0) return false;
    if (f.authors() != null) return false;
    if (f.ids() != null) return false;
    if (f.hasTagFilters()) return false;
    return true;
}

fn countLeadingZeroBits(id: *const [32]u8) u8 {
    var count: u8 = 0;
    for (id) |byte| {
        if (byte == 0) {
            count +|= 8;
        } else {
            count +|= @clz(byte);
            break;
        }
    }
    return count;
}

fn getCommittedDifficulty(raw_json: []const u8) ?u8 {
    const tags_start = std.mem.indexOf(u8, raw_json, "\"tags\"") orelse return null;
    var pos = tags_start + 6;

    while (pos < raw_json.len and raw_json[pos] != '[') : (pos += 1) {}
    if (pos >= raw_json.len) return null;
    pos += 1;

    var depth: i32 = 0;
    var in_string = false;
    var escape = false;
    var tag_start: ?usize = null;

    while (pos < raw_json.len) {
        const c = raw_json[pos];

        if (escape) {
            escape = false;
            pos += 1;
            continue;
        }
        if (c == '\\' and in_string) {
            escape = true;
            pos += 1;
            continue;
        }
        if (c == '"') {
            in_string = !in_string;
            pos += 1;
            continue;
        }

        if (!in_string) {
            if (c == '[') {
                if (depth == 0) {
                    tag_start = pos;
                }
                depth += 1;
            } else if (c == ']') {
                depth -= 1;
                if (depth == 0 and tag_start != null) {
                    const tag_json = raw_json[tag_start.? .. pos + 1];
                    if (extractNonceTarget(tag_json)) |target| {
                        return target;
                    }
                    tag_start = null;
                }
                if (depth < 0) break;
            }
        }

        pos += 1;
    }

    return null;
}

fn extractNonceTarget(tag_json: []const u8) ?u8 {
    var values: [3]?[]const u8 = .{ null, null, null };
    var value_idx: usize = 0;
    var pos: usize = 0;
    var in_string = false;
    var string_start: usize = 0;
    var escape = false;

    while (pos < tag_json.len and value_idx < 3) {
        const c = tag_json[pos];

        if (escape) {
            escape = false;
            pos += 1;
            continue;
        }
        if (c == '\\' and in_string) {
            escape = true;
            pos += 1;
            continue;
        }

        if (c == '"') {
            if (in_string) {
                values[value_idx] = tag_json[string_start..pos];
                value_idx += 1;
            } else {
                string_start = pos + 1;
            }
            in_string = !in_string;
        }

        pos += 1;
    }

    if (values[0] != null and values[2] != null) {
        if (std.mem.eql(u8, values[0].?, "nonce")) {
            return std.fmt.parseInt(u8, values[2].?, 10) catch null;
        }
    }
    return null;
}

pub const Handler = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    store: *Store,
    subs: *Subscriptions,
    broadcaster: *Broadcaster,
    send_fn: *const fn (conn_id: u64, data: []const u8) void,
    event_limiter: *rate_limiter.EventRateLimiter,
    shutdown: *std.atomic.Value(bool),

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const Config,
        store: *Store,
        subs: *Subscriptions,
        broadcaster: *Broadcaster,
        send_fn: *const fn (conn_id: u64, data: []const u8) void,
        event_limiter: *rate_limiter.EventRateLimiter,
        shutdown: *std.atomic.Value(bool),
    ) Handler {
        return .{
            .allocator = allocator,
            .config = config,
            .store = store,
            .subs = subs,
            .broadcaster = broadcaster,
            .send_fn = send_fn,
            .event_limiter = event_limiter,
            .shutdown = shutdown,
        };
    }

    pub fn handle(self: *Handler, conn: *Connection, message: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        conn.touch();

        if (!validateMessageStructure(message)) {
            self.sendNotice(conn, "error: invalid message structure");
            return;
        }

        var msg = nostr.ClientMsg.parse(message) catch {
            self.sendNotice(conn, "error: invalid message");
            return;
        };
        defer msg.deinit();

        switch (msg.msgType()) {
            .event => self.handleEvent(conn, &msg),
            .req => self.handleReq(conn, &msg),
            .close => self.handleClose(conn, &msg),
            .auth => self.handleAuth(conn, &msg),
            .count => self.handleCount(conn, &msg),
            .neg_open => self.handleNegOpen(conn, &msg),
            .neg_msg => self.handleNegMsg(conn, &msg),
            .neg_close => self.handleNegClose(conn, &msg),
        }
    }

    fn validateMessageStructure(message: []const u8) bool {
        const trimmed = std.mem.trimRight(u8, message, " \t\r\n");
        if (trimmed.len < 5) return false;
        if (trimmed[0] != '[') return false;
        if (trimmed[trimmed.len - 1] != ']') return false;

        for (message) |c| {
            if (c < 0x20 and c != '\t' and c != '\n' and c != '\r') {
                return false;
            }
        }

        return true;
    }

    fn handleEvent(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        var event = msg.getEvent() catch |err| {
            self.sendNotice(conn, nostr.errorMessage(err));
            return;
        };

        const id = event.id();

        if (self.config.auth_required or self.config.auth_to_write) {
            if (!conn.isAuthenticated()) {
                self.sendOk(conn, id, false, "auth-required: authentication required to publish events");
                return;
            }
        }

        if (!self.event_limiter.checkAndRecord(conn.getClientIp())) {
            self.sendOk(conn, id, false, "rate-limited: too many events");
            return;
        }

        const now = std.time.timestamp();
        const created = event.createdAt();

        if (created > now + self.config.max_future_seconds) {
            self.sendOk(conn, id, false, "invalid: event too far in future");
            return;
        }

        if (created < now - self.config.max_event_age) {
            self.sendOk(conn, id, false, "invalid: event too old");
            return;
        }

        if (event.content().len > self.config.max_content_length) {
            self.sendOk(conn, id, false, "invalid: content too long");
            return;
        }

        if (event.tagCount() > self.config.max_event_tags) {
            self.sendOk(conn, id, false, "invalid: too many tags");
            return;
        }

        event.validate() catch |err| {
            self.sendOk(conn, id, false, nostr.errorMessage(err));
            return;
        };

        if (self.config.min_pow_difficulty > 0) {
            const pow_difficulty = countLeadingZeroBits(id);
            const committed = getCommittedDifficulty(event.raw_json);
            if (committed) |target| {
                if (target < self.config.min_pow_difficulty) {
                    self.sendOk(conn, id, false, "pow: committed target difficulty too low");
                    return;
                }
                if (pow_difficulty < target) {
                    self.sendOk(conn, id, false, "pow: actual difficulty below committed target");
                    return;
                }
            }
            if (pow_difficulty < self.config.min_pow_difficulty) {
                self.sendOk(conn, id, false, "pow: difficulty too low");
                return;
            }
        }

        if (event.kind() == 22242) {
            self.sendOk(conn, id, false, "invalid: AUTH events cannot be published");
            return;
        }

        if (nostr.isProtected(&event)) {
            if (!conn.isPubkeyAuthenticated(event.pubkey())) {
                self.sendAuthChallenge(conn);
                self.sendOk(conn, id, false, "auth-required: this event may only be published by its author");
                return;
            }
        }

        if (nostr.isExpired(&event)) {
            self.sendOk(conn, id, false, "invalid: event expired");
            return;
        }

        if (nostr.isDeletion(&event)) {
            self.handleDeletion(conn, &event);
            return;
        }

        const json = if (event.raw_json.len > 0)
            event.raw_json
        else blk: {
            var json_buf: [65536]u8 = undefined;
            break :blk event.serialize(&json_buf) catch {
                self.sendOk(conn, id, false, "error: serialization failed");
                return;
            };
        };

        const result = self.store.store(&event, json) catch {
            self.sendOk(conn, id, false, "error: storage failed");
            return;
        };

        if (!result.stored) {
            const success = std.mem.startsWith(u8, result.message, "duplicate");
            self.sendOk(conn, id, success, result.message);
            return;
        }

        self.sendOk(conn, id, true, "");
        conn.recordEvent();

        self.broadcaster.broadcast(&event);
    }

    fn handleDeletion(self: *Handler, conn: *Connection, event: *const nostr.Event) void {
        const id = event.id();
        const pubkey = event.pubkey();

        const ids_to_delete = nostr.getDeletionIds(self.allocator, event) catch {
            self.sendOk(conn, id, false, "error: failed to parse deletion");
            return;
        };
        defer self.allocator.free(ids_to_delete);

        for (ids_to_delete) |target_id| {
            _ = self.store.delete(&target_id, pubkey) catch {};
        }

        var json_buf: [65536]u8 = undefined;
        const json = event.serialize(&json_buf) catch {
            self.sendOk(conn, id, false, "error: serialization failed");
            return;
        };

        _ = self.store.store(event, json) catch {};

        self.sendOk(conn, id, true, "");

        self.broadcaster.broadcast(event);
    }

    fn validateSearchFilters(filters: []const nostr.Filter) ?[]const u8 {
        for (filters) |filter| {
            if (filter.search()) |search_query| {
                if (search_query.len > 256) {
                    return "error: search query too long (max 256 chars)";
                }
                const kinds = filter.kinds();
                if (kinds == null or kinds.?.len == 0) {
                    return "error: search requires kinds filter";
                }
            }
        }
        return null;
    }

    fn handleReq(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        const sub_id_raw = msg.subscriptionId();

        if (sub_id_raw.len == 0 or sub_id_raw.len > 64) {
            self.sendClosed(conn, sub_id_raw, "error: invalid subscription ID");
            return;
        }

        var sub_id_buf: [64]u8 = undefined;
        @memcpy(sub_id_buf[0..sub_id_raw.len], sub_id_raw);
        const sub_id = sub_id_buf[0..sub_id_raw.len];

        if (self.config.auth_required) {
            if (!conn.isAuthenticated()) {
                self.sendClosed(conn, sub_id, "auth-required: authentication required to subscribe");
                return;
            }
        }

        const filters = msg.getFilters(conn.allocator()) catch {
            self.sendClosed(conn, sub_id, "error: failed to parse filters");
            return;
        };

        if (filters.len > self.config.max_filters) {
            self.sendClosed(conn, sub_id, "error: too many filters");
            conn.allocator().free(filters);
            return;
        }

        if (validateSearchFilters(filters)) |err_msg| {
            self.sendClosed(conn, sub_id, err_msg);
            conn.allocator().free(filters);
            return;
        }

        self.subs.subscribe(conn, sub_id, filters, self.config.max_subscriptions) catch |err| {
            const error_msg = switch (err) {
                error.TooManySubscriptions => "error: too many subscriptions",
                else => "error: subscription failed",
            };
            self.sendClosed(conn, sub_id, error_msg);
            conn.allocator().free(filters);
            return;
        };

        var limit = self.config.query_limit_default;
        if (filters.len > 0 and filters[0].limit() > 0) {
            limit = @min(@as(u32, @intCast(filters[0].limit())), self.config.query_limit_max);
        }

        if (filters.len == 1 and isKindOnlyQuery(&filters[0])) {
            const kinds = filters[0].kinds().?;
            if (kinds.len == 1) {
                if (self.shutdown.load(.acquire)) return;
                var iter = self.store.query(filters, limit) catch {
                    self.sendClosed(conn, sub_id, "error: query failed");
                    return;
                };
                defer iter.deinit();

                while (iter.next() catch null) |json| {
                    var buf: [65536]u8 = undefined;
                    const event_msg = nostr.RelayMsg.eventRaw(sub_id, json, &buf) catch continue;
                    _ = conn.send(event_msg);
                    conn.events_sent += 1;
                }
            } else {
                if (self.shutdown.load(.acquire)) return;
                var mk_iter = self.store.queryMultiKind(kinds, limit) catch {
                    self.sendClosed(conn, sub_id, "error: query failed");
                    return;
                };
                defer mk_iter.deinit();

                while (mk_iter.next() catch null) |json| {
                    var buf: [65536]u8 = undefined;
                    const event_msg = nostr.RelayMsg.eventRaw(sub_id, json, &buf) catch continue;
                    _ = conn.send(event_msg);
                    conn.events_sent += 1;
                }
            }
        } else {
            if (self.shutdown.load(.acquire)) return;
            var iter = self.store.query(filters, limit) catch {
                self.sendClosed(conn, sub_id, "error: query failed");
                return;
            };
            defer iter.deinit();

            while (iter.next() catch null) |json| {
                var buf: [65536]u8 = undefined;
                const event_msg = nostr.RelayMsg.eventRaw(sub_id, json, &buf) catch continue;
                _ = conn.send(event_msg);
                conn.events_sent += 1;
            }
        }

        self.sendEose(conn, sub_id);
    }

    fn handleClose(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        const sub_id = msg.subscriptionId();
        self.subs.unsubscribe(conn, sub_id);
        self.sendClosed(conn, sub_id, "");
    }

    fn handleCount(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        const sub_id = msg.subscriptionId();

        if (sub_id.len == 0 or sub_id.len > 64) {
            self.sendClosed(conn, sub_id, "error: invalid subscription ID");
            return;
        }

        if (self.config.auth_required) {
            if (!conn.isAuthenticated()) {
                self.sendClosed(conn, sub_id, "auth-required: authentication required");
                return;
            }
        }

        const filters = msg.getFilters(conn.allocator()) catch {
            self.sendClosed(conn, sub_id, "error: failed to parse filters");
            return;
        };
        defer {
            for (filters) |*f| {
                var filter = f.*;
                filter.deinit();
            }
            conn.allocator().free(filters);
        }

        if (filters.len > self.config.max_filters) {
            self.sendClosed(conn, sub_id, "error: too many filters");
            return;
        }

        if (validateSearchFilters(filters)) |err_msg| {
            self.sendClosed(conn, sub_id, err_msg);
            return;
        }

        var total_count: u64 = 0;
        for (filters) |filter| {
            var iter = self.store.query(&[_]nostr.Filter{filter}, self.config.query_limit_max) catch {
                self.sendClosed(conn, sub_id, "error: query failed");
                return;
            };
            defer iter.deinit();

            while (iter.next() catch null) |_| {
                total_count += 1;
            }
        }

        self.sendCount(conn, sub_id, total_count);
    }

    fn handleAuth(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        var event = msg.getEvent() catch |err| {
            self.sendNotice(conn, nostr.errorMessage(err));
            return;
        };
        const id = event.id();

        if (event.kind() != 22242) {
            self.sendOk(conn, id, false, "invalid: AUTH event must be kind 22242");
            return;
        }

        const now = std.time.timestamp();
        const created = event.createdAt();
        const time_diff = if (now > created) now - created else created - now;
        if (time_diff > 600) {
            self.sendOk(conn, id, false, "invalid: AUTH event timestamp too far from current time");
            return;
        }

        const auth_tags = nostr.Auth.extractTags(event.raw_json);

        var expected_challenge: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&expected_challenge, "{x}", .{conn.auth_challenge}) catch {
            self.sendOk(conn, id, false, "error: internal error");
            return;
        };

        if (auth_tags.challenge == null or !std.mem.eql(u8, auth_tags.challenge.?, &expected_challenge)) {
            self.sendOk(conn, id, false, "invalid: challenge mismatch");
            return;
        }

        if (self.config.relay_url.len > 0) {
            if (auth_tags.relay == null or !nostr.Auth.domainsMatch(self.config.relay_url, auth_tags.relay.?)) {
                self.sendOk(conn, id, false, "invalid: relay URL mismatch");
                return;
            }
        }

        event.validate() catch |err| {
            self.sendOk(conn, id, false, nostr.errorMessage(err));
            return;
        };

        conn.addAuthenticatedPubkey(event.pubkey()) catch {
            self.sendOk(conn, id, false, "error: failed to record authentication");
            return;
        };

        self.sendOk(conn, id, true, "");
    }

    fn handleNegOpen(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        const sub_id = msg.subscriptionId();

        if (!self.config.negentropy_enabled) {
            self.sendNegErr(conn, sub_id, "blocked: negentropy not supported");
            return;
        }

        if (sub_id.len == 0 or sub_id.len > 64) {
            self.sendNegErr(conn, sub_id, "error: invalid subscription ID");
            return;
        }

        var filter = msg.getNegFilter(conn.allocator()) catch {
            self.sendNegErr(conn, sub_id, "error: invalid filter");
            return;
        } orelse {
            self.sendNegErr(conn, sub_id, "error: missing filter");
            return;
        };
        defer filter.deinit();

        var payload_buf: [65536]u8 = undefined;
        const payload = msg.getNegPayload(&payload_buf) catch {
            self.sendNegErr(conn, sub_id, "error: invalid negentropy payload");
            return;
        };

        const session = conn.addNegSession(sub_id) catch {
            self.sendNegErr(conn, sub_id, "error: failed to create session");
            return;
        };

        if (self.shutdown.load(.acquire)) return;
        var iter = self.store.query(&[_]nostr.Filter{filter}, self.config.negentropy_max_sync_events) catch {
            conn.removeNegSession(sub_id);
            self.sendNegErr(conn, sub_id, "error: query failed");
            return;
        };
        defer iter.deinit();

        var count: u32 = 0;
        while (iter.next() catch null) |json| {
            var event = nostr.Event.parse(json) catch continue;
            defer event.deinit();
            session.storage.insert(@intCast(event.createdAt()), event.id()) catch continue;
            count += 1;
            if (count >= self.config.negentropy_max_sync_events) {
                conn.removeNegSession(sub_id);
                self.sendNegErr(conn, sub_id, "blocked: too many events");
                return;
            }
        }

        session.storage.seal();
        session.sealed = true;

        self.reconcileAndSend(conn, sub_id, session, payload);
    }

    fn handleNegMsg(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        const sub_id = msg.subscriptionId();

        if (!self.config.negentropy_enabled) {
            self.sendNegErr(conn, sub_id, "blocked: negentropy not supported");
            return;
        }

        const session = conn.getNegSession(sub_id) orelse {
            self.sendNegErr(conn, sub_id, "closed: unknown subscription");
            return;
        };

        if (!session.sealed) {
            self.sendNegErr(conn, sub_id, "error: session not ready");
            return;
        }

        var payload_buf: [65536]u8 = undefined;
        const payload = msg.getNegPayload(&payload_buf) catch {
            self.sendNegErr(conn, sub_id, "error: invalid negentropy payload");
            return;
        };

        self.reconcileAndSend(conn, sub_id, session, payload);
    }

    fn handleNegClose(_: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        conn.removeNegSession(msg.subscriptionId());
    }

    fn reconcileAndSend(self: *Handler, conn: *Connection, sub_id: []const u8, session: *NegSession, query: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        var out_buf: [65536]u8 = undefined;
        var neg = nostr.negentropy.Negentropy.init(session.storage.storage(), 0);

        var result = neg.reconcile(query, &out_buf, conn.allocator()) catch {
            if (self.shutdown.load(.acquire)) return;
            var err_buf: [512]u8 = undefined;
            const err_msg = nostr.RelayMsg.negErr(sub_id, "error: reconciliation failed", &err_buf) catch return;
            conn.sendDirect(err_msg);
            return;
        };
        defer result.deinit();

        if (self.shutdown.load(.acquire)) return;
        var msg_buf: [131072]u8 = undefined;
        const neg_msg = nostr.RelayMsg.negMsg(sub_id, result.output, &msg_buf) catch return;
        conn.sendDirect(neg_msg);
    }

    fn sendNegErr(self: *Handler, conn: *Connection, sub_id: []const u8, reason: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.negErr(sub_id, reason, &buf) catch return;
        conn.sendDirect(msg);
    }

    fn sendOk(self: *Handler, conn: *Connection, event_id: *const [32]u8, success: bool, message: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.ok(event_id, success, message, &buf) catch return;
        conn.sendDirect(msg);
    }

    fn sendEose(self: *Handler, conn: *Connection, sub_id: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [256]u8 = undefined;
        const msg = nostr.RelayMsg.eose(sub_id, &buf) catch return;
        conn.sendDirect(msg);
    }

    fn sendClosed(self: *Handler, conn: *Connection, sub_id: []const u8, message: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.closed(sub_id, message, &buf) catch return;
        conn.sendDirect(msg);
    }

    fn sendCount(self: *Handler, conn: *Connection, sub_id: []const u8, count_val: u64) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [256]u8 = undefined;
        const msg = nostr.RelayMsg.count(sub_id, count_val, &buf) catch return;
        conn.sendDirect(msg);
    }

    fn sendNotice(self: *Handler, conn: *Connection, message: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.notice(message, &buf) catch return;
        conn.sendDirect(msg);
    }

    fn sendAuthChallenge(self: *Handler, conn: *Connection) void {
        if (self.shutdown.load(.acquire)) return;
        if (conn.challenge_sent) return;
        var buf: [256]u8 = undefined;
        const auth_msg = nostr.RelayMsg.auth(&conn.auth_challenge, &buf) catch return;
        conn.sendDirect(auth_msg);
        conn.challenge_sent = true;
    }
};
