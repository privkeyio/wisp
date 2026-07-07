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
const ManagementStore = @import("management_store.zig").ManagementStore;
const Writer = @import("writer.zig").Writer;
const metrics = @import("relay_metrics.zig");

fn isKindOnlyQuery(f: *const nostr.Filter) bool {
    const kinds = f.kinds() orelse return false;
    if (kinds.len == 0) return false;
    if (f.authors() != null) return false;
    if (f.ids() != null) return false;
    if (f.hasTagFilters()) return false;
    if (f.search() != null) return false;
    return true;
}

fn streamQueryResults(conn: *Connection, sub_id: []const u8, iter: anytype) void {
    while (iter.next() catch null) |json| {
        var buf: [65536]u8 = undefined;
        const event_msg = nostr.RelayMsg.eventRaw(sub_id, json, &buf) catch continue;
        // A write error (peer gone / send timeout on a slow client) stops the
        // stream so the LMDB read txn is released promptly.
        conn.write(event_msg) catch break;
        _ = conn.events_sent.fetchAdd(1, .monotonic);
    }
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
    event_limiter: *rate_limiter.EventRateLimiter,
    query_limiter: *rate_limiter.EventRateLimiter,
    shutdown: *std.atomic.Value(bool),
    mgmt_store: *ManagementStore,
    // Group-commit writer, present only for durable sync modes (meta/full). When
    // null (the default, non-durable `none` mode) events are stored synchronously
    // on the worker thread, which is faster when there is no fsync to amortize.
    writer: ?*Writer,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const Config,
        store: *Store,
        subs: *Subscriptions,
        broadcaster: *Broadcaster,
        event_limiter: *rate_limiter.EventRateLimiter,
        query_limiter: *rate_limiter.EventRateLimiter,
        shutdown: *std.atomic.Value(bool),
        mgmt_store: *ManagementStore,
        writer: ?*Writer,
    ) Handler {
        return .{
            .allocator = allocator,
            .config = config,
            .store = store,
            .subs = subs,
            .broadcaster = broadcaster,
            .event_limiter = event_limiter,
            .query_limiter = query_limiter,
            .shutdown = shutdown,
            .mgmt_store = mgmt_store,
            .writer = writer,
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
        const trimmed = std.mem.trimEnd(u8, message, " \t\r\n");
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

        if (self.mgmt_store.isPubkeyBanned(event.pubkey())) {
            self.sendOk(conn, id, false, "blocked: pubkey is banned");
            return;
        }

        if (self.mgmt_store.hasAllowedPubkeys()) {
            if (!self.mgmt_store.isPubkeyAllowed(event.pubkey())) {
                self.sendOk(conn, id, false, "blocked: pubkey not in allowlist");
                return;
            }
        }

        if (!self.mgmt_store.isKindAllowed(event.kind())) {
            self.sendOk(conn, id, false, "blocked: event kind not allowed");
            return;
        }

        if (self.mgmt_store.isEventBanned(id)) {
            self.sendOk(conn, id, false, "blocked: event is banned");
            return;
        }

        if (!self.event_limiter.checkAndRecord(conn.getClientIp())) {
            metrics.rateLimited();
            self.sendOk(conn, id, false, "rate-limited: too many events");
            return;
        }

        const now = nostr.io.timestamp();
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

        // Durable modes: hand off to the group-commit writer, which stores the
        // event in a batched transaction and sends OK + broadcasts only after the
        // commit, so an acknowledged write is on disk. Validation stays synchronous.
        if (self.writer) |writer| {
            if (!writer.submit(.event, conn.id, json)) {
                self.sendOk(conn, id, false, "error: relay overloaded");
            }
            return;
        }

        const result = self.store.store(&event, json) catch {
            self.sendOk(conn, id, false, "error: storage failed");
            return;
        };

        if (!result.stored and !result.ephemeral) {
            const success = std.mem.startsWith(u8, result.message, "duplicate");
            if (!success) metrics.eventRejected();
            self.replyOk(conn, id, success, result.message);
            return;
        }

        // Stored, OR ephemeral (relayed but not persisted, NIP-16): ack and broadcast to subscribers.
        // Ephemeral acks use replyOk so they are not miscounted as stored (sendOk records the stored
        // metric); only genuinely persisted events go through sendOk.
        if (result.ephemeral) self.replyOk(conn, id, true, "") else self.sendOk(conn, id, true, "");
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

        const json = if (event.raw_json.len > 0)
            event.raw_json
        else blk: {
            var json_buf: [65536]u8 = undefined;
            break :blk event.serialize(&json_buf) catch {
                self.sendOk(conn, id, false, "error: serialization failed");
                return;
            };
        };

        // Durable modes: the writer applies the deletions and stores the deletion
        // event in the same batched, ordered transaction as regular events, which
        // preserves same-connection publish/delete ordering.
        if (self.writer) |writer| {
            if (!writer.submit(.deletion, conn.id, json)) {
                self.sendOk(conn, id, false, "error: relay overloaded");
            }
            return;
        }

        for (ids_to_delete) |target_id| {
            _ = self.store.delete(&target_id, pubkey) catch {};
        }

        const stored = if (self.store.store(event, json)) |r| r.stored else |_| false;

        self.replyOk(conn, id, true, "");
        if (stored) metrics.eventStored();

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
        metrics.reqReceived();
        const sub_id_raw = msg.subscriptionId();

        if (sub_id_raw.len == 0 or sub_id_raw.len > 64) {
            self.sendClosed(conn, sub_id_raw, "error: invalid subscription ID");
            return;
        }

        var sub_id_buf: [64]u8 = undefined;
        @memcpy(sub_id_buf[0..sub_id_raw.len], sub_id_raw);
        const sub_id = sub_id_buf[0..sub_id_raw.len];

        if (!self.query_limiter.checkAndRecord(conn.getClientIp())) {
            metrics.queryRateLimited();
            self.sendClosed(conn, sub_id, "rate-limited: too many queries");
            return;
        }

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

                streamQueryResults(conn, sub_id, &iter);
            } else {
                if (self.shutdown.load(.acquire)) return;
                var mk_iter = self.store.queryMultiKind(kinds, limit) catch {
                    self.sendClosed(conn, sub_id, "error: query failed");
                    return;
                };
                defer mk_iter.deinit();

                streamQueryResults(conn, sub_id, &mk_iter);
            }
        } else {
            if (self.shutdown.load(.acquire)) return;
            var iter = self.store.query(filters, limit) catch {
                self.sendClosed(conn, sub_id, "error: query failed");
                return;
            };
            defer iter.deinit();

            streamQueryResults(conn, sub_id, &iter);
        }

        self.sendEose(conn, sub_id);
    }

    fn handleClose(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        const sub_id = msg.subscriptionId();
        self.subs.unsubscribe(conn, sub_id);
        // Per NIP-01, CLOSED is only sent when the relay ends a subscription on
        // its own initiative; a client CLOSE is acknowledged by silently
        // dropping the subscription.
    }

    fn handleCount(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        const sub_id = msg.subscriptionId();

        if (sub_id.len == 0 or sub_id.len > 64) {
            self.sendClosed(conn, sub_id, "error: invalid subscription ID");
            return;
        }

        if (!self.query_limiter.checkAndRecord(conn.getClientIp())) {
            metrics.queryRateLimited();
            self.sendClosed(conn, sub_id, "rate-limited: too many queries");
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
            self.replyOk(conn, id, false, "invalid: AUTH event must be kind 22242");
            return;
        }

        const now = nostr.io.timestamp();
        const created = event.createdAt();
        const time_diff = if (now > created) now - created else created - now;
        if (time_diff > 600) {
            self.replyOk(conn, id, false, "invalid: AUTH event timestamp too far from current time");
            return;
        }

        const auth_tags = nostr.Auth.extractTags(event.raw_json);

        var expected_challenge: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&expected_challenge, "{x}", .{conn.auth_challenge}) catch {
            self.replyOk(conn, id, false, "error: internal error");
            return;
        };

        if (auth_tags.challenge == null or !std.mem.eql(u8, auth_tags.challenge.?, &expected_challenge)) {
            self.replyOk(conn, id, false, "invalid: challenge mismatch");
            return;
        }

        if (self.config.relay_url.len > 0) {
            if (auth_tags.relay == null or !nostr.Auth.domainsMatch(self.config.relay_url, auth_tags.relay.?)) {
                self.replyOk(conn, id, false, "invalid: relay URL mismatch");
                return;
            }
        }

        event.validate() catch |err| {
            self.replyOk(conn, id, false, nostr.errorMessage(err));
            return;
        };

        conn.addAuthenticatedPubkey(event.pubkey()) catch {
            self.replyOk(conn, id, false, "error: failed to record authentication");
            return;
        };

        self.replyOk(conn, id, true, "");
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

        if (!self.query_limiter.checkAndRecord(conn.getClientIp())) {
            metrics.queryRateLimited();
            self.sendNegErr(conn, sub_id, "rate-limited: too many queries");
            return;
        }

        // Reconciliation reveals which event IDs the relay holds, so it must
        // honor the same auth gate as REQ/COUNT.
        if (self.config.auth_required and !conn.isAuthenticated()) {
            self.sendNegErr(conn, sub_id, "auth-required: authentication required");
            return;
        }

        // Each session buffers up to negentropy_max_sync_events in memory; cap the
        // number of concurrent sessions so a connection cannot exhaust memory by
        // opening many distinct sub_ids. Re-opening an existing sub_id is allowed.
        if (conn.getNegSession(sub_id) == null and
            conn.neg_sessions.count() >= self.config.max_neg_sessions)
        {
            self.sendNegErr(conn, sub_id, "blocked: too many negentropy sessions");
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
            conn.write(err_msg) catch {};
            return;
        };
        defer result.deinit();

        if (self.shutdown.load(.acquire)) return;
        var msg_buf: [131072]u8 = undefined;
        const neg_msg = nostr.RelayMsg.negMsg(sub_id, result.output, &msg_buf) catch return;
        conn.write(neg_msg) catch {};
    }

    fn sendNegErr(self: *Handler, conn: *Connection, sub_id: []const u8, reason: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.negErr(sub_id, reason, &buf) catch return;
        conn.write(msg) catch {};
    }

    fn replyOk(self: *Handler, conn: *Connection, event_id: *const [32]u8, success: bool, message: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.ok(event_id, success, message, &buf) catch return;
        conn.write(msg) catch {};
    }

    /// OK responder for EVENT submissions: records the store/reject metric, then
    /// replies. AUTH and duplicate acks use `replyOk` directly so they are not
    /// miscounted as stored or rejected events.
    fn sendOk(self: *Handler, conn: *Connection, event_id: *const [32]u8, success: bool, message: []const u8) void {
        if (success) metrics.eventStored() else metrics.eventRejected();
        self.replyOk(conn, event_id, success, message);
    }

    fn sendEose(self: *Handler, conn: *Connection, sub_id: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [256]u8 = undefined;
        const msg = nostr.RelayMsg.eose(sub_id, &buf) catch return;
        conn.write(msg) catch {};
    }

    fn sendClosed(self: *Handler, conn: *Connection, sub_id: []const u8, message: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.closed(sub_id, message, &buf) catch return;
        conn.write(msg) catch {};
    }

    fn sendCount(self: *Handler, conn: *Connection, sub_id: []const u8, count_val: u64) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [256]u8 = undefined;
        const msg = nostr.RelayMsg.count(sub_id, count_val, &buf) catch return;
        conn.write(msg) catch {};
    }

    fn sendNotice(self: *Handler, conn: *Connection, message: []const u8) void {
        if (self.shutdown.load(.acquire)) return;
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.notice(message, &buf) catch return;
        conn.write(msg) catch {};
    }

    fn sendAuthChallenge(self: *Handler, conn: *Connection) void {
        if (self.shutdown.load(.acquire)) return;
        if (conn.challenge_sent) return;
        var buf: [256]u8 = undefined;
        const auth_msg = nostr.RelayMsg.auth(&conn.auth_challenge, &buf) catch return;
        // Only mark the challenge as sent if the write succeeded; a failed write
        // (timeout/disconnect) must not permanently suppress future AUTH attempts.
        conn.write(auth_msg) catch return;
        conn.challenge_sent = true;
    }
};

const testing = std.testing;

test countLeadingZeroBits {
    var id = [_]u8{0} ** 32;
    try testing.expectEqual(@as(u8, 255), countLeadingZeroBits(&id));

    id[0] = 0xff;
    try testing.expectEqual(@as(u8, 0), countLeadingZeroBits(&id));

    id[0] = 0x01;
    try testing.expectEqual(@as(u8, 7), countLeadingZeroBits(&id));

    id = [_]u8{0} ** 32;
    id[1] = 0x0f;
    try testing.expectEqual(@as(u8, 12), countLeadingZeroBits(&id));
}

test extractNonceTarget {
    try testing.expectEqual(@as(?u8, 21), extractNonceTarget("[\"nonce\",\"12345\",\"21\"]"));
    try testing.expectEqual(@as(?u8, null), extractNonceTarget("[\"p\",\"abc\"]"));
    try testing.expectEqual(@as(?u8, null), extractNonceTarget("[\"nonce\",\"12345\"]"));
    // Target overflowing u8 must parse-fail to null, never wrap.
    try testing.expectEqual(@as(?u8, null), extractNonceTarget("[\"nonce\",\"1\",\"999\"]"));
    try testing.expectEqual(@as(?u8, null), extractNonceTarget(""));
}

test getCommittedDifficulty {
    try testing.expectEqual(@as(?u8, 16), getCommittedDifficulty(
        "{\"tags\":[[\"nonce\",\"9999\",\"16\"]],\"content\":\"x\"}",
    ));
    try testing.expectEqual(@as(?u8, null), getCommittedDifficulty(
        "{\"tags\":[[\"p\",\"abc\"]]}",
    ));
    try testing.expectEqual(@as(?u8, null), getCommittedDifficulty("{\"tags\":[]}"));
    try testing.expectEqual(@as(?u8, null), getCommittedDifficulty("{\"content\":\"x\"}"));
    // Truncated tags array must not over-read.
    try testing.expectEqual(@as(?u8, null), getCommittedDifficulty("{\"tags\":[[\"nonce\""));
    // A nonce string inside content must not be mistaken for a tag.
    try testing.expectEqual(@as(?u8, null), getCommittedDifficulty("{\"content\":\"nonce\"}"));
}

test "validateMessageStructure" {
    try testing.expect(Handler.validateMessageStructure("[\"REQ\",\"s\",{}]"));
    try testing.expect(Handler.validateMessageStructure("[\"REQ\"]\n  "));
    try testing.expect(!Handler.validateMessageStructure("[]"));
    try testing.expect(!Handler.validateMessageStructure("not json"));
    try testing.expect(!Handler.validateMessageStructure("{\"a\":1}"));
    // Starts with '[' but is not closed: the trailing-']' check must reject it.
    try testing.expect(!Handler.validateMessageStructure("[\"REQ\""));
    // Embedded control byte is rejected.
    try testing.expect(!Handler.validateMessageStructure("[\"a\x01\"]"));
}

fn fuzzGetCommittedDifficulty(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [2048]u8 = undefined;
    const n = smith.slice(&buf);
    _ = getCommittedDifficulty(buf[0..n]);
}

test "fuzz getCommittedDifficulty" {
    try std.testing.fuzz({}, fuzzGetCommittedDifficulty, .{});
}

fn fuzzExtractNonceTarget(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [512]u8 = undefined;
    const n = smith.slice(&buf);
    _ = extractNonceTarget(buf[0..n]);
}

test "fuzz extractNonceTarget" {
    try std.testing.fuzz({}, fuzzExtractNonceTarget, .{});
}

fn fuzzValidateMessageStructure(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [2048]u8 = undefined;
    const n = smith.slice(&buf);
    _ = Handler.validateMessageStructure(buf[0..n]);
}

test "fuzz validateMessageStructure" {
    try std.testing.fuzz({}, fuzzValidateMessageStructure, .{});
}

// Deterministic randomized stress over the hand-rolled scanners. `zig build
// test --fuzz` is the real fuzzer, but Zig 0.16.0's test runner mis-types the
// fuzz error path (writeStackTrace), so it can't build in fuzz mode. This pumps
// random and JSON-mutated inputs through the scanners under a normal test run,
// relying on Debug safety checks to catch any out-of-bounds read or overflow.
test "scanner stress" {
    var prng = std.Random.DefaultPrng.init(0x515c0); // fixed seed: reproducible
    const rand = prng.random();

    const seeds = [_][]const u8{
        "{\"tags\":[[\"nonce\",\"9999\",\"16\"]],\"content\":\"hi\"}",
        "{\"tags\":[[\"p\",\"abc\"],[\"nonce\",\"1\",\"8\"]]}",
        "[\"REQ\",\"s\",{\"kinds\":[1]}]",
        "[\"nonce\",\"123\",\"20\"]",
        "{\"tags\":[]}",
    };

    var buf: [256]u8 = undefined;
    var i: usize = 0;
    while (i < 100_000) : (i += 1) {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        const input = buf[0..len];

        if (rand.boolean()) {
            rand.bytes(input);
        } else {
            const seed = seeds[rand.intRangeLessThan(usize, 0, seeds.len)];
            const copy_len = @min(seed.len, len);
            @memcpy(buf[0..copy_len], seed[0..copy_len]);
            // Corrupt a handful of bytes to reach malformed-JSON states.
            const muts = rand.intRangeAtMost(usize, 0, 4);
            var m: usize = 0;
            while (m < muts and copy_len > 0) : (m += 1) {
                buf[rand.intRangeLessThan(usize, 0, copy_len)] = rand.int(u8);
            }
        }

        _ = getCommittedDifficulty(input);
        _ = extractNonceTarget(input);
        _ = Handler.validateMessageStructure(input);
    }
}
