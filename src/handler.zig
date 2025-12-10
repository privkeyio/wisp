const std = @import("std");
const Config = @import("config.zig").Config;
const Store = @import("store.zig").Store;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const Broadcaster = @import("broadcaster.zig").Broadcaster;
const Connection = @import("connection.zig").Connection;
const nostr = @import("nostr.zig");

pub const Handler = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    store: *Store,
    subs: *Subscriptions,
    broadcaster: *Broadcaster,
    send_fn: *const fn (conn_id: u64, data: []const u8) void,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const Config,
        store: *Store,
        subs: *Subscriptions,
        broadcaster: *Broadcaster,
        send_fn: *const fn (conn_id: u64, data: []const u8) void,
    ) Handler {
        return .{
            .allocator = allocator,
            .config = config,
            .store = store,
            .subs = subs,
            .broadcaster = broadcaster,
            .send_fn = send_fn,
        };
    }

    pub fn handle(self: *Handler, conn: *Connection, message: []const u8) void {
        conn.touch();

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
        }
    }

    fn handleEvent(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        var event = msg.getEvent();

        const id = event.id();

        // NIP-42: Check if auth is required for writes
        if (self.config.auth_required or self.config.auth_to_write) {
            if (!conn.isAuthenticated()) {
                self.sendOk(conn, id, false, "auth-required: authentication required to publish events");
                return;
            }
        }

        event.validate() catch |err| {
            self.sendOk(conn, id, false, nostr.errorMessage(err));
            return;
        };

        // NIP-42: Reject kind 22242 AUTH events submitted as regular events
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

        var json_buf: [65536]u8 = undefined;
        const json = event.serialize(&json_buf) catch {
            self.sendOk(conn, id, false, "error: serialization failed");
            return;
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
        conn.events_received += 1;

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

        // NIP-42: Check if auth is required for all operations
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

        var limit = self.config.query_limit_default;
        if (filters.len > 0 and filters[0].limit() > 0) {
            limit = @min(@as(u32, @intCast(filters[0].limit())), self.config.query_limit_max);
        }

        var iter = self.store.query(filters, limit) catch {
            self.sendClosed(conn, sub_id, "error: query failed");
            return;
        };
        defer iter.deinit();

        while (iter.next() catch null) |json| {
            var event = nostr.Event.parse(json) catch continue;
            defer event.deinit();

            var buf: [65536]u8 = undefined;
            const event_msg = nostr.RelayMsg.event(sub_id, &event, &buf) catch continue;
            self.send_fn(conn.id, event_msg);
            conn.events_sent += 1;
        }

        self.sendEose(conn, sub_id);
    }

    fn handleClose(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        const sub_id = msg.subscriptionId();
        self.subs.unsubscribe(conn, sub_id);
        self.sendClosed(conn, sub_id, "");
    }

    fn handleAuth(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        var event = msg.getEvent();
        const id = event.id();

        // NIP-42: kind must be 22242
        if (event.kind() != 22242) {
            self.sendOk(conn, id, false, "invalid: AUTH event must be kind 22242");
            return;
        }

        // Verify created_at is within 10 minutes
        const now = std.time.timestamp();
        const created = event.createdAt();
        const time_diff = if (now > created) now - created else created - now;
        if (time_diff > 600) {
            self.sendOk(conn, id, false, "invalid: AUTH event timestamp too far from current time");
            return;
        }

        // Parse and verify the event has proper tags
        const auth_tags = self.parseAuthTags(event.raw_json);

        // Verify challenge tag matches
        var expected_challenge: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&expected_challenge, "{x}", .{conn.auth_challenge}) catch {
            self.sendOk(conn, id, false, "error: internal error");
            return;
        };

        if (auth_tags.challenge == null or !std.mem.eql(u8, auth_tags.challenge.?, &expected_challenge)) {
            self.sendOk(conn, id, false, "invalid: challenge mismatch");
            return;
        }

        // Verify relay tag (domain matching)
        if (self.config.relay_url.len > 0) {
            if (auth_tags.relay == null or !self.verifyRelayUrl(auth_tags.relay.?)) {
                self.sendOk(conn, id, false, "invalid: relay URL mismatch");
                return;
            }
        }

        // Verify the event signature (validates id and sig)
        event.validate() catch |err| {
            self.sendOk(conn, id, false, nostr.errorMessage(err));
            return;
        };

        // Authentication successful - add pubkey to authenticated set
        conn.addAuthenticatedPubkey(event.pubkey()) catch {
            self.sendOk(conn, id, false, "error: failed to record authentication");
            return;
        };

        self.sendOk(conn, id, true, "");
    }

    const AuthTags = struct {
        relay: ?[]const u8 = null,
        challenge: ?[]const u8 = null,
    };

    fn parseAuthTags(_: *Handler, json: []const u8) AuthTags {
        var result = AuthTags{};

        // Find "tags" array in the JSON
        const tags_start = std.mem.indexOf(u8, json, "\"tags\"") orelse return result;
        var pos = tags_start + 6;

        // Skip to opening bracket
        while (pos < json.len and json[pos] != '[') : (pos += 1) {}
        if (pos >= json.len) return result;
        pos += 1;

        // Parse each tag
        var depth: i32 = 0;
        var in_string = false;
        var escape = false;
        var tag_start: ?usize = null;

        while (pos < json.len) {
            const c = json[pos];

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
                        const tag_json = json[tag_start.? .. pos + 1];
                        extractAuthTag(tag_json, &result);
                        tag_start = null;
                    }
                    if (depth < 0) break;
                }
            }

            pos += 1;
        }

        return result;
    }

    fn extractAuthTag(tag_json: []const u8, result: *AuthTags) void {
        // Extract first two string values from tag array
        var values: [2]?[]const u8 = .{ null, null };
        var value_idx: usize = 0;
        var pos: usize = 0;
        var in_string = false;
        var string_start: usize = 0;
        var escape = false;

        while (pos < tag_json.len and value_idx < 2) {
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

        if (values[0] != null and values[1] != null) {
            if (std.mem.eql(u8, values[0].?, "relay")) {
                result.relay = values[1].?;
            } else if (std.mem.eql(u8, values[0].?, "challenge")) {
                result.challenge = values[1].?;
            }
        }
    }

    fn verifyRelayUrl(self: *Handler, provided: []const u8) bool {
        // Extract domain from config relay_url and provided URL
        const config_domain = extractDomain(self.config.relay_url);
        const provided_domain = extractDomain(provided);

        if (config_domain == null or provided_domain == null) return false;

        return std.ascii.eqlIgnoreCase(config_domain.?, provided_domain.?);
    }

    fn extractDomain(url: []const u8) ?[]const u8 {
        // Skip protocol
        var start: usize = 0;
        if (std.mem.startsWith(u8, url, "wss://")) {
            start = 6;
        } else if (std.mem.startsWith(u8, url, "ws://")) {
            start = 5;
        } else if (std.mem.startsWith(u8, url, "https://")) {
            start = 8;
        } else if (std.mem.startsWith(u8, url, "http://")) {
            start = 7;
        }

        if (start >= url.len) return null;

        // Find end of domain (port, path, or end of string)
        var end = start;
        while (end < url.len) {
            if (url[end] == ':' or url[end] == '/' or url[end] == '?') break;
            end += 1;
        }

        if (end <= start) return null;
        return url[start..end];
    }

    fn sendOk(self: *Handler, conn: *Connection, event_id: *const [32]u8, success: bool, message: []const u8) void {
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.ok(event_id, success, message, &buf) catch return;
        self.send_fn(conn.id, msg);
    }

    fn sendEose(self: *Handler, conn: *Connection, sub_id: []const u8) void {
        var buf: [256]u8 = undefined;
        const msg = nostr.RelayMsg.eose(sub_id, &buf) catch return;
        self.send_fn(conn.id, msg);
    }

    fn sendClosed(self: *Handler, conn: *Connection, sub_id: []const u8, message: []const u8) void {
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.closed(sub_id, message, &buf) catch return;
        self.send_fn(conn.id, msg);
    }

    fn sendNotice(self: *Handler, conn: *Connection, message: []const u8) void {
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.notice(message, &buf) catch return;
        self.send_fn(conn.id, msg);
    }
};
