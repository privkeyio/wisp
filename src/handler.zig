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

pub const Handler = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    store: *Store,
    subs: *Subscriptions,
    broadcaster: *Broadcaster,
    send_fn: *const fn (conn_id: u64, data: []const u8) void,
    event_limiter: *rate_limiter.EventRateLimiter,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const Config,
        store: *Store,
        subs: *Subscriptions,
        broadcaster: *Broadcaster,
        send_fn: *const fn (conn_id: u64, data: []const u8) void,
        event_limiter: *rate_limiter.EventRateLimiter,
    ) Handler {
        return .{
            .allocator = allocator,
            .config = config,
            .store = store,
            .subs = subs,
            .broadcaster = broadcaster,
            .send_fn = send_fn,
            .event_limiter = event_limiter,
        };
    }

    pub fn handle(self: *Handler, conn: *Connection, message: []const u8) void {
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
        if (message.len < 5) return false;
        if (message[0] != '[') return false;
        if (message[message.len - 1] != ']') return false;

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

        if (event.kind() == 22242) {
            self.sendOk(conn, id, false, "invalid: AUTH events cannot be published");
            return;
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

    fn handleReq(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        const sub_id = msg.subscriptionId();

        if (sub_id.len == 0 or sub_id.len > 64) {
            self.sendClosed(conn, sub_id, "error: invalid subscription ID");
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

        self.subs.subscribe(conn, sub_id, filters, self.config.max_subscriptions) catch |err| {
            const error_msg = switch (err) {
                error.TooManySubscriptions => "error: too many subscriptions",
                else => "error: subscription failed",
            };
            self.sendClosed(conn, sub_id, error_msg);
            conn.allocator().free(filters);
            return;
        };

        // NIP-50: Validate search filters
        for (filters) |filter| {
            if (filter.search()) |search_query| {
                // Reject search queries over 256 characters
                if (search_query.len > 256) {
                    self.sendClosed(conn, sub_id, "error: search query too long (max 256 chars)");
                    return;
                }
                // Require kinds filter with search to prevent full table scan
                if (filter.kinds() == null) {
                    self.sendClosed(conn, sub_id, "error: search requires kinds filter");
                    return;
                }
            }
        }

        var limit = self.config.query_limit_default;
        if (filters.len > 0 and filters[0].limit() > 0) {
            limit = @min(@as(u32, @intCast(filters[0].limit())), self.config.query_limit_max);
        }

        if (filters.len == 1 and isKindOnlyQuery(&filters[0])) {
            const kinds = filters[0].kinds().?;
            if (kinds.len == 1) {
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

    fn reconcileAndSend(_: *Handler, conn: *Connection, sub_id: []const u8, session: *NegSession, query: []const u8) void {
        var out_buf: [65536]u8 = undefined;
        var neg = nostr.negentropy.Negentropy.init(session.storage.storage(), 0);

        var result = neg.reconcile(query, &out_buf, conn.allocator()) catch {
            var err_buf: [512]u8 = undefined;
            const err_msg = nostr.RelayMsg.negErr(sub_id, "error: reconciliation failed", &err_buf) catch return;
            conn.sendDirect(err_msg);
            return;
        };
        defer result.deinit();

        var msg_buf: [131072]u8 = undefined;
        const neg_msg = nostr.RelayMsg.negMsg(sub_id, result.output, &msg_buf) catch return;
        conn.sendDirect(neg_msg);
    }

    fn sendNegErr(_: *Handler, conn: *Connection, sub_id: []const u8, reason: []const u8) void {
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.negErr(sub_id, reason, &buf) catch return;
        conn.sendDirect(msg);
    }

    fn sendOk(_: *Handler, conn: *Connection, event_id: *const [32]u8, success: bool, message: []const u8) void {
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.ok(event_id, success, message, &buf) catch return;
        conn.sendDirect(msg);
    }

    fn sendEose(_: *Handler, conn: *Connection, sub_id: []const u8) void {
        var buf: [256]u8 = undefined;
        const msg = nostr.RelayMsg.eose(sub_id, &buf) catch return;
        conn.sendDirect(msg);
    }

    fn sendClosed(_: *Handler, conn: *Connection, sub_id: []const u8, message: []const u8) void {
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.closed(sub_id, message, &buf) catch return;
        conn.sendDirect(msg);
    }

    fn sendCount(_: *Handler, conn: *Connection, sub_id: []const u8, count_val: u64) void {
        var buf: [256]u8 = undefined;
        const msg = nostr.RelayMsg.count(sub_id, count_val, &buf) catch return;
        conn.sendDirect(msg);
    }

    fn sendNotice(_: *Handler, conn: *Connection, message: []const u8) void {
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.notice(message, &buf) catch return;
        conn.sendDirect(msg);
    }
};
