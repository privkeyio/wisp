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
            .auth => {},
        }
    }

    fn handleEvent(self: *Handler, conn: *Connection, msg: *nostr.ClientMsg) void {
        var event = msg.getEvent();

        const id = event.id();

        event.validate() catch |err| {
            self.sendOk(conn, id, false, nostr.errorMessage(err));
            return;
        };

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
