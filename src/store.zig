const std = @import("std");
const Lmdb = @import("lmdb.zig").Lmdb;
const Txn = @import("lmdb.zig").Txn;
const Dbi = @import("lmdb.zig").Dbi;
const Cursor = @import("lmdb.zig").Cursor;
const nostr = @import("nostr.zig");
const QueryCache = @import("query_cache.zig").QueryCache;

pub const Store = struct {
    lmdb: *Lmdb,
    allocator: std.mem.Allocator,
    query_cache: QueryCache,

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
            .query_cache = QueryCache.init(allocator),
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
        self.query_cache.deinit();
    }

    pub fn store(self: *Store, event: *const nostr.Event, json: []const u8) !StoreResult {
        const kind_type = nostr.kindType(event.kind());

        if (kind_type == .ephemeral) {
            return .{ .stored = false, .message = "ephemeral: not stored" };
        }

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();

        const id = event.id();

        if (try txn.get(self.deleted, id) != null) {
            txn.abort();
            return .{ .stored = false, .message = "deleted: event was deleted" };
        }

        var replaced_id: ?[32]u8 = null;

        if (kind_type == .replaceable or kind_type == .addressable) {
            const result = try self.handleReplaceable(&txn, event, kind_type);
            switch (result) {
                .rejected => {
                    txn.abort();
                    return .{ .stored = false, .message = "replaced: have newer event" };
                },
                .replaced => |rid| {
                    replaced_id = rid;
                },
                .new_entry => {},
            }
        }

        txn.putNoOverwrite(self.events, id, json) catch |err| {
            if (err == error.KeyExists) {
                txn.abort();
                return .{ .stored = false, .message = "duplicate: already have this event" };
            }
            return err;
        };

        try self.indexEvent(&txn, event);
        try txn.commit();

        self.query_cache.invalidate();

        return .{ .stored = true, .replaced_id = replaced_id };
    }

    pub const ReplaceableResult = union(enum) {
        replaced: [32]u8,
        new_entry: void,
        rejected: void,
    };

    fn handleReplaceable(self: *Store, txn: *Txn, event: *const nostr.Event, kind_type: nostr.KindType) !ReplaceableResult {
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

                if (existing.createdAt() > event.createdAt()) {
                    return .rejected;
                }

                if (existing.createdAt() == event.createdAt()) {
                    const existing_id = existing.id();
                    const new_id = event.id();
                    if (std.mem.order(u8, existing_id, new_id) == .lt) {
                        return .rejected;
                    }
                }

                var replaced: [32]u8 = undefined;
                @memcpy(&replaced, existing_id_slice[0..32]);

                try self.deleteEventInternal(txn, &existing);
                try txn.put(self.replaceable, key, event.id());

                return .{ .replaced = replaced };
            }
        }

        try txn.put(self.replaceable, key, event.id());
        return .new_entry;
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

        var kind_key: [42]u8 = undefined;
        const kind_u16: u16 = @truncate(@as(u32, @bitCast(event.kind())));
        const kind_be = @byteSwap(kind_u16);
        @memcpy(kind_key[0..2], std.mem.asBytes(&kind_be));
        @memcpy(kind_key[2..10], std.mem.asBytes(&created_at_be));
        @memcpy(kind_key[10..42], id);
        try txn.put(self.idx_kind, &kind_key, empty);

        try self.indexTags(txn, event, id, std.mem.asBytes(&created_at_be));
    }

    fn indexTags(self: *Store, txn: *Txn, event: *const nostr.Event, id: *const [32]u8, created_at_be: *const [8]u8) !void {
        const empty: []const u8 = "";
        var iter = event.tags.iterator();

        while (iter.next()) |entry| {
            switch (entry.value) {
                .binary => |bytes| {
                    var tag_key: [73]u8 = undefined;
                    tag_key[0] = entry.letter;
                    @memcpy(tag_key[1..33], &bytes);
                    @memcpy(tag_key[33..41], created_at_be);
                    @memcpy(tag_key[41..73], id);
                    try txn.put(self.idx_tag, &tag_key, empty);
                },
                .string => |str| {
                    if (str.len > 256) continue;
                    var tag_key_buf: [297]u8 = undefined;
                    tag_key_buf[0] = entry.letter;
                    @memcpy(tag_key_buf[1..][0..str.len], str);
                    @memcpy(tag_key_buf[1 + str.len ..][0..8], created_at_be);
                    @memcpy(tag_key_buf[1 + str.len + 8 ..][0..32], id);
                    const key_len = 1 + str.len + 8 + 32;
                    try txn.put(self.idx_tag, tag_key_buf[0..key_len], empty);
                },
            }
        }
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

        var kind_key: [42]u8 = undefined;
        const kind_u16: u16 = @truncate(@as(u32, @bitCast(event.kind())));
        const kind_be = @byteSwap(kind_u16);
        @memcpy(kind_key[0..2], std.mem.asBytes(&kind_be));
        @memcpy(kind_key[2..10], std.mem.asBytes(&created_at_be));
        @memcpy(kind_key[10..42], id);
        txn.delete(self.idx_kind, &kind_key) catch {};
        self.deleteTags(txn, event, id, std.mem.asBytes(&created_at_be));

        txn.delete(self.events, id) catch {};
    }

    fn deleteTags(self: *Store, txn: *Txn, event: *const nostr.Event, id: *const [32]u8, created_at_be: *const [8]u8) void {
        var iter = event.tags.iterator();

        while (iter.next()) |entry| {
            switch (entry.value) {
                .binary => |bytes| {
                    var tag_key: [73]u8 = undefined;
                    tag_key[0] = entry.letter;
                    @memcpy(tag_key[1..33], &bytes);
                    @memcpy(tag_key[33..41], created_at_be);
                    @memcpy(tag_key[41..73], id);
                    txn.delete(self.idx_tag, &tag_key) catch {};
                },
                .string => |str| {
                    if (str.len > 256) continue;
                    var tag_key_buf: [297]u8 = undefined;
                    tag_key_buf[0] = entry.letter;
                    @memcpy(tag_key_buf[1..][0..str.len], str);
                    @memcpy(tag_key_buf[1 + str.len ..][0..8], created_at_be);
                    @memcpy(tag_key_buf[1 + str.len + 8 ..][0..32], id);
                    const key_len = 1 + str.len + 8 + 32;
                    txn.delete(self.idx_tag, tag_key_buf[0..key_len]) catch {};
                },
            }
        }
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
        const now = std.time.timestamp();
        const now_bytes = std.mem.asBytes(&now);
        try txn.put(self.deleted, event_id, now_bytes);
        try txn.commit();
        return true;
    }

    pub fn cleanupDeletedEntries(self: *Store, max_age_seconds: i64) !u64 {
        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();

        var cursor = try txn.cursor(self.deleted);
        defer cursor.close();

        const now = std.time.timestamp();
        const cutoff = now - max_age_seconds;
        var deleted_count: u64 = 0;

        var entry = try cursor.get(.first);
        while (entry != null) {
            const e = entry.?;
            if (e.value.len >= 8) {
                const ts_ptr: *const i64 = @ptrCast(@alignCast(e.value[0..8]));
                if (ts_ptr.* < cutoff) {
                    try cursor.del();
                    deleted_count += 1;
                }
            } else if (e.value.len == 0) {
                try cursor.del();
                deleted_count += 1;
            }
            entry = try cursor.get(.next);
        }

        try txn.commit();
        if (deleted_count > 0) {
            std.log.info("Cleaned up {d} old deleted event entries", .{deleted_count});
        }
        return deleted_count;
    }

    pub fn get(self: *Store, event_id: *const [32]u8) !?[]const u8 {
        var txn = try self.lmdb.beginTxn(true);
        defer txn.abort();
        return try txn.get(self.events, event_id);
    }

    pub fn query(self: *Store, filters: []const nostr.Filter, limit: u32) !QueryIterator {
        return QueryIterator.init(self, filters, limit);
    }

    pub fn queryMultiKind(self: *Store, kinds: []const i32, limit: u32) !MultiKindResult {
        var txn = try self.lmdb.beginTxn(true);
        errdefer txn.abort();

        var results: std.ArrayListUnmanaged(EventRef) = .empty;
        errdefer results.deinit(self.allocator);

        var kind_set: [256]bool = .{false} ** 256;
        var has_large_kind = false;
        for (kinds) |kind| {
            if (kind >= 0 and kind < 256) {
                kind_set[@intCast(kind)] = true;
            } else {
                has_large_kind = true;
            }
        }

        var cursor = try txn.cursor(self.idx_created);
        defer cursor.close();

        var entry = try cursor.get(.last);
        var collected: u32 = 0;
        var scanned: u32 = 0;
        const max_scan: u32 = limit * 20;

        while (entry != null and collected < limit and scanned < max_scan) : (entry = try cursor.get(.prev)) {
            const e = entry.?;
            scanned += 1;

            if (e.key.len < 40) continue;

            const event_id: *const [32]u8 = @ptrCast(e.key[8..40]);
            const ts_bytes: *const [8]u8 = @ptrCast(e.key[0..8]);
            const timestamp = @byteSwap(@as(u64, @bitCast(ts_bytes.*)));

            const json = try txn.get(self.events, event_id) orelse continue;
            const kind_opt = extractKindFromJson(json);
            if (kind_opt) |kind| {
                const matches = if (kind >= 0 and kind < 256)
                    kind_set[@intCast(kind)]
                else if (has_large_kind)
                    blk: {
                        for (kinds) |k| {
                            if (k == kind) break :blk true;
                        }
                        break :blk false;
                    }
                else
                    false;

                if (matches) {
                    try results.append(self.allocator, .{
                        .id = event_id.*,
                        .timestamp = timestamp,
                    });
                    collected += 1;
                }
            }
        }

        return MultiKindResult{
            .store = self,
            .txn = txn,
            .results = results,
            .index = 0,
            .limit = results.items.len,
        };
    }

    fn extractKindFromJson(json: []const u8) ?i32 {
        const pattern = "\"kind\":";
        if (std.mem.indexOf(u8, json, pattern)) |idx| {
            var pos = idx + pattern.len;
            while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t')) {
                pos += 1;
            }
            if (pos >= json.len) return null;

            var num: i32 = 0;
            var found_digit = false;
            while (pos < json.len) {
                const c = json[pos];
                if (c >= '0' and c <= '9') {
                    num = num * 10 + @as(i32, @intCast(c - '0'));
                    found_digit = true;
                } else {
                    break;
                }
                pos += 1;
            }
            if (found_digit) return num;
        }
        return null;
    }
};

const EventRef = struct {
    id: [32]u8,
    timestamp: u64,
};

pub const MultiKindResult = struct {
    store: *Store,
    txn: Txn,
    results: std.ArrayListUnmanaged(EventRef),
    index: usize,
    limit: usize,

    pub fn next(self: *MultiKindResult) !?[]const u8 {
        while (self.index < self.limit) {
            const ref = self.results.items[self.index];
            self.index += 1;

            if (try self.txn.get(self.store.events, &ref.id)) |json| {
                return json;
            }
        }
        return null;
    }

    pub fn deinit(self: *MultiKindResult) void {
        self.results.deinit(self.store.allocator);
        self.txn.abort();
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
    index_type: IndexType = .created,
    prefix: [44]u8 = undefined,
    prefix_len: usize = 0,
    skip_filter: bool = false,

    const IndexType = enum { created, kind, pubkey, tag };

    pub fn init(store: *Store, filters: []const nostr.Filter, limit: u32) QueryIterator {
        var iter = QueryIterator{
            .store = store,
            .filters = filters,
            .limit = limit,
        };

        if (filters.len > 0) {
            const f = filters[0];

            if (f.authors()) |authors| {
                if (authors.len == 1) {
                    iter.index_type = .pubkey;
                    @memcpy(iter.prefix[0..32], &authors[0]);
                    iter.prefix_len = 32;
                    iter.skip_filter = (f.kinds() == null and f.ids() == null and !f.hasTagFilters());
                    return iter;
                }
            }

            if (f.kinds()) |kinds| {
                if (f.authors() == null and f.ids() == null and !f.hasTagFilters()) {
                    if (kinds.len == 1) {
                        iter.index_type = .kind;
                        const kind_u16: u16 = @truncate(@as(u32, @bitCast(kinds[0])));
                        const kind_be = @byteSwap(kind_u16);
                        @memcpy(iter.prefix[0..2], std.mem.asBytes(&kind_be));
                        iter.prefix_len = 2;
                        iter.skip_filter = true;
                        return iter;
                    }
                }
            }

            if (f.tag_filters) |tag_filters| {
                if (tag_filters.len > 0) {
                    const tag_filter = tag_filters[0];
                    if (tag_filter.values.len == 1) {
                        const val = tag_filter.values[0];
                        switch (val) {
                            .binary => |bytes| {
                                iter.index_type = .tag;
                                iter.prefix[0] = tag_filter.letter;
                                @memcpy(iter.prefix[1..33], &bytes);
                                iter.prefix_len = 33;
                                iter.skip_filter = (f.kinds() == null and f.authors() == null and f.ids() == null);
                            },
                            .string => {},
                        }
                    }
                }
            }
        }

        return iter;
    }

    pub fn next(self: *QueryIterator) !?[]const u8 {
        if (self.returned >= self.limit) return null;

        if (self.txn == null) {
            self.txn = try self.store.lmdb.beginTxn(true);
            const dbi = switch (self.index_type) {
                .kind => self.store.idx_kind,
                .pubkey => self.store.idx_pubkey,
                .tag => self.store.idx_tag,
                .created => self.store.idx_created,
            };
            self.cursor = try self.txn.?.cursor(dbi);
        }

        if (!self.started) {
            self.started = true;

            const first_entry = switch (self.index_type) {
                .kind, .pubkey => blk: {
                    var seek_key: [72]u8 = undefined;
                    @memcpy(seek_key[0..self.prefix_len], self.prefix[0..self.prefix_len]);
                    @memset(seek_key[self.prefix_len..][0..8], 0xFF);
                    @memset(seek_key[self.prefix_len + 8 ..][0..32], 0xFF);
                    const key_len = self.prefix_len + 40;

                    if (try self.cursor.?.seek(seek_key[0..key_len])) |_| {
                        break :blk try self.cursor.?.get(.prev);
                    } else {
                        break :blk try self.cursor.?.get(.last);
                    }
                },
                else => try self.cursor.?.get(.last),
            };

            if (first_entry) |entry| {
                if (try self.processEntry(entry)) |json| {
                    return json;
                }
            } else {
                return null;
            }
        }

        while (true) {
            const entry = try self.cursor.?.get(.prev) orelse return null;

            if (self.prefix_len > 0) {
                if (entry.key.len < self.prefix_len or
                    !std.mem.eql(u8, entry.key[0..self.prefix_len], self.prefix[0..self.prefix_len]))
                {
                    return null;
                }
            }

            if (try self.processEntry(entry)) |json| {
                return json;
            }
        }
    }

    const Entry = @import("lmdb.zig").Entry;
    fn processEntry(self: *QueryIterator, entry: Entry) !?[]const u8 {
        const event_id = switch (self.index_type) {
            .kind => blk: {
                if (entry.key.len < 42) return null;
                break :blk entry.key[10..42];
            },
            .pubkey => blk: {
                if (entry.key.len < 72) return null;
                break :blk entry.key[40..72];
            },
            .tag => blk: {
                if (entry.key.len < 41) return null;
                break :blk entry.key[entry.key.len - 32 ..];
            },
            .created => blk: {
                if (entry.key.len < 40) return null;
                break :blk entry.key[8..40];
            },
        };

        const json = try self.txn.?.get(self.store.events, event_id) orelse return null;

        if (self.skip_filter) {
            self.returned += 1;
            return json;
        }

        var event = nostr.Event.parse(json) catch return null;
        defer event.deinit();

        if (nostr.isExpired(&event)) return null;

        if (self.filters.len == 0 or nostr.filtersMatch(self.filters, &event)) {
            self.returned += 1;
            return json;
        }

        return null;
    }

    pub fn deinit(self: *QueryIterator) void {
        if (self.cursor) |*cur| cur.close();
        if (self.txn) |*t| t.abort();
    }
};
