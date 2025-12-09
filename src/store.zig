const std = @import("std");
const Lmdb = @import("lmdb.zig").Lmdb;
const Txn = @import("lmdb.zig").Txn;
const Dbi = @import("lmdb.zig").Dbi;
const Cursor = @import("lmdb.zig").Cursor;
const nostr = @import("nostr.zig");

pub const Store = struct {
    lmdb: *Lmdb,
    allocator: std.mem.Allocator,

    events: Dbi,
    idx_created: Dbi,
    idx_pubkey: Dbi,
    idx_kind: Dbi,
    idx_tag: Dbi,
    replaceable: Dbi,
    deleted: Dbi,

    pub const StoreResult = struct {
        stored: bool,
        message: []const u8 = "",
        replaced_id: ?[32]u8 = null,
    };

    pub fn init(allocator: std.mem.Allocator, lmdb: *Lmdb) !Store {
        var txn = try lmdb.beginTxn(false);
        errdefer txn.abort();

        const events = try lmdb.openDbi(&txn, "events");
        const idx_created = try lmdb.openDbi(&txn, "idx:created");
        const idx_pubkey = try lmdb.openDbi(&txn, "idx:pubkey");
        const idx_kind = try lmdb.openDbi(&txn, "idx:kind");
        const idx_tag = try lmdb.openDbi(&txn, "idx:tag");
        const replaceable = try lmdb.openDbi(&txn, "replaceable");
        const deleted = try lmdb.openDbi(&txn, "deleted");

        try txn.commit();

        return .{
            .lmdb = lmdb,
            .allocator = allocator,
            .events = events,
            .idx_created = idx_created,
            .idx_pubkey = idx_pubkey,
            .idx_kind = idx_kind,
            .idx_tag = idx_tag,
            .replaceable = replaceable,
            .deleted = deleted,
        };
    }

    pub fn deinit(self: *Store) void {
        _ = self;
    }

    pub fn store(self: *Store, event: *const nostr.Event, json: []const u8) !StoreResult {
        const kind_type = nostr.kindType(event.kind());

        if (kind_type == .ephemeral) {
            return .{ .stored = false, .message = "ephemeral: not stored" };
        }

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();

        const id = event.id();

        if (try txn.get(self.events, id) != null) {
            txn.abort();
            return .{ .stored = false, .message = "duplicate: already have this event" };
        }

        if (try txn.get(self.deleted, id) != null) {
            txn.abort();
            return .{ .stored = false, .message = "deleted: event was deleted" };
        }

        var replaced_id: ?[32]u8 = null;

        if (kind_type == .replaceable or kind_type == .addressable) {
            replaced_id = try self.handleReplaceable(&txn, event, kind_type);
        }

        try txn.put(self.events, id, json);
        try self.indexEvent(&txn, event);
        try txn.commit();

        return .{ .stored = true, .replaced_id = replaced_id };
    }

    fn handleReplaceable(self: *Store, txn: *Txn, event: *const nostr.Event, kind_type: nostr.KindType) !?[32]u8 {
        var key_buf: [128]u8 = undefined;
        var key_len: usize = 0;

        @memcpy(key_buf[0..32], event.pubkey());
        key_len = 32;

        const kind_be = @byteSwap(@as(u32, @bitCast(event.kind())));
        @memcpy(key_buf[key_len..][0..4], std.mem.asBytes(&kind_be));
        key_len += 4;

        if (kind_type == .addressable) {
            if (event.dTag()) |d| {
                const copy_len = @min(d.len, key_buf.len - key_len);
                @memcpy(key_buf[key_len..][0..copy_len], d[0..copy_len]);
                key_len += copy_len;
            }
        }

        const key = key_buf[0..key_len];

        if (try txn.get(self.replaceable, key)) |existing_id_slice| {
            if (try txn.get(self.events, existing_id_slice)) |existing_json| {
                var existing = try nostr.Event.parse(existing_json);
                defer existing.deinit();

                if (existing.createdAt() >= event.createdAt()) {
                    return null;
                }

                var replaced: [32]u8 = undefined;
                @memcpy(&replaced, existing_id_slice[0..32]);

                try self.deleteEventInternal(txn, &existing);
                try txn.put(self.replaceable, key, event.id());

                return replaced;
            }
        }

        try txn.put(self.replaceable, key, event.id());
        return null;
    }

    fn indexEvent(self: *Store, txn: *Txn, event: *const nostr.Event) !void {
        const id = event.id();
        const created_at_be = @byteSwap(@as(u64, @bitCast(event.createdAt())));
        const empty: []const u8 = "";

        var created_key: [40]u8 = undefined;
        @memcpy(created_key[0..8], std.mem.asBytes(&created_at_be));
        @memcpy(created_key[8..40], id);
        try txn.put(self.idx_created, &created_key, empty);

        var pubkey_key: [72]u8 = undefined;
        @memcpy(pubkey_key[0..32], event.pubkey());
        @memcpy(pubkey_key[32..40], std.mem.asBytes(&created_at_be));
        @memcpy(pubkey_key[40..72], id);
        try txn.put(self.idx_pubkey, &pubkey_key, empty);

        var kind_key: [44]u8 = undefined;
        const kind_be = @byteSwap(@as(u32, @bitCast(event.kind())));
        @memcpy(kind_key[0..4], std.mem.asBytes(&kind_be));
        @memcpy(kind_key[4..12], std.mem.asBytes(&created_at_be));
        @memcpy(kind_key[12..44], id);
        try txn.put(self.idx_kind, &kind_key, empty);
    }

    fn deleteEventInternal(self: *Store, txn: *Txn, event: *const nostr.Event) !void {
        const id = event.id();
        const created_at_be = @byteSwap(@as(u64, @bitCast(event.createdAt())));

        var created_key: [40]u8 = undefined;
        @memcpy(created_key[0..8], std.mem.asBytes(&created_at_be));
        @memcpy(created_key[8..40], id);
        txn.delete(self.idx_created, &created_key) catch {};

        var pubkey_key: [72]u8 = undefined;
        @memcpy(pubkey_key[0..32], event.pubkey());
        @memcpy(pubkey_key[32..40], std.mem.asBytes(&created_at_be));
        @memcpy(pubkey_key[40..72], id);
        txn.delete(self.idx_pubkey, &pubkey_key) catch {};

        var kind_key: [44]u8 = undefined;
        const kind_be = @byteSwap(@as(u32, @bitCast(event.kind())));
        @memcpy(kind_key[0..4], std.mem.asBytes(&kind_be));
        @memcpy(kind_key[4..12], std.mem.asBytes(&created_at_be));
        @memcpy(kind_key[12..44], id);
        txn.delete(self.idx_kind, &kind_key) catch {};

        txn.delete(self.events, id) catch {};
    }

    pub fn delete(self: *Store, event_id: *const [32]u8, requester_pubkey: *const [32]u8) !bool {
        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();

        const json = try txn.get(self.events, event_id) orelse {
            txn.abort();
            return false;
        };

        var event = try nostr.Event.parse(json);
        defer event.deinit();

        if (!std.mem.eql(u8, event.pubkey(), requester_pubkey)) {
            txn.abort();
            return false;
        }

        try self.deleteEventInternal(&txn, &event);
        try txn.put(self.deleted, event_id, "");
        try txn.commit();
        return true;
    }

    pub fn get(self: *Store, event_id: *const [32]u8) !?[]const u8 {
        var txn = try self.lmdb.beginTxn(true);
        defer txn.abort();
        return try txn.get(self.events, event_id);
    }

    pub fn query(self: *Store, filters: []const nostr.Filter, limit: u32) !QueryIterator {
        return QueryIterator.init(self, filters, limit);
    }
};

pub const QueryIterator = struct {
    store: *Store,
    filters: []const nostr.Filter,
    limit: u32,
    returned: u32 = 0,
    txn: ?Txn = null,
    cursor: ?Cursor = null,
    started: bool = false,

    pub fn init(store: *Store, filters: []const nostr.Filter, limit: u32) QueryIterator {
        return .{
            .store = store,
            .filters = filters,
            .limit = limit,
        };
    }

    pub fn next(self: *QueryIterator) !?[]const u8 {
        if (self.returned >= self.limit) return null;

        if (self.txn == null) {
            self.txn = try self.store.lmdb.beginTxn(true);
            self.cursor = try self.txn.?.cursor(self.store.idx_created);
        }

        if (!self.started) {
            self.started = true;
            const first_entry = try self.cursor.?.get(.last) orelse return null;
            if (first_entry.key.len >= 40) {
                const event_id = first_entry.key[8..40];
                if (try self.txn.?.get(self.store.events, event_id)) |json| {
                    var event = nostr.Event.parse(json) catch return try self.next();
                    defer event.deinit();
                    if (!nostr.isExpired(&event)) {
                        if (self.filters.len == 0 or nostr.filtersMatch(self.filters, &event)) {
                            self.returned += 1;
                            return json;
                        }
                    }
                }
            }
        }

        while (true) {
            const entry = try self.cursor.?.get(.prev) orelse return null;

            if (entry.key.len < 40) continue;
            const event_id = entry.key[8..40];

            const json = try self.txn.?.get(self.store.events, event_id) orelse continue;

            var event = nostr.Event.parse(json) catch continue;
            defer event.deinit();

            if (nostr.isExpired(&event)) continue;

            if (self.filters.len == 0 or nostr.filtersMatch(self.filters, &event)) {
                self.returned += 1;
                return json;
            }
        }
    }

    pub fn deinit(self: *QueryIterator) void {
        if (self.cursor) |*cur| cur.close();
        if (self.txn) |*t| t.abort();
    }
};
