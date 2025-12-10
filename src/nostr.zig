const std = @import("std");
pub const crypto = @import("crypto.zig");

pub const Error = error{
    InvalidJson,
    MissingField,
    InvalidId,
    InvalidPubkey,
    InvalidSig,
    InvalidCreatedAt,
    InvalidKind,
    InvalidTags,
    InvalidContent,
    IdMismatch,
    SigMismatch,
    FutureEvent,
    ExpiredEvent,
    InvalidSubscriptionId,
    TooManyFilters,
    BufferTooSmall,
    AllocFailed,
    Unknown,
};

pub fn errorMessage(err: Error) []const u8 {
    return switch (err) {
        error.InvalidJson => "invalid: malformed JSON",
        error.MissingField => "invalid: missing required field",
        error.InvalidId => "invalid: bad event ID",
        error.InvalidPubkey => "invalid: bad pubkey",
        error.InvalidSig => "invalid: bad signature",
        error.InvalidCreatedAt => "invalid: bad created_at",
        error.InvalidKind => "invalid: bad kind",
        error.InvalidTags => "invalid: bad tags",
        error.InvalidContent => "invalid: bad content",
        error.IdMismatch => "invalid: ID doesn't match content",
        error.SigMismatch => "invalid: signature verification failed",
        error.FutureEvent => "invalid: created_at too far in future",
        error.ExpiredEvent => "invalid: event expired",
        error.InvalidSubscriptionId => "invalid: bad subscription ID",
        error.TooManyFilters => "invalid: too many filters",
        error.BufferTooSmall => "error: buffer too small",
        error.AllocFailed => "error: allocation failed",
        error.Unknown => "error: unknown error",
    };
}

pub const TagValue = union(enum) {
    binary: [32]u8,
    string: []const u8,

    pub fn eql(self: TagValue, other: TagValue) bool {
        return switch (self) {
            .binary => |b| switch (other) {
                .binary => |ob| std.mem.eql(u8, &b, &ob),
                .string => false,
            },
            .string => |s| switch (other) {
                .binary => false,
                .string => |os| std.mem.eql(u8, s, os),
            },
        };
    }
};

pub const TagIndex = struct {
    entries: [26]std.ArrayListUnmanaged(TagValue),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) TagIndex {
        var entries: [26]std.ArrayListUnmanaged(TagValue) = undefined;
        for (&entries) |*e| {
            e.* = .{};
        }
        return .{ .entries = entries, .allocator = allocator };
    }

    pub fn deinit(self: *TagIndex) void {
        for (&self.entries) |*list| {
            for (list.items) |val| {
                switch (val) {
                    .string => |s| self.allocator.free(s),
                    .binary => {},
                }
            }
            list.deinit(self.allocator);
        }
    }

    fn letterIndex(letter: u8) ?usize {
        if (letter >= 'a' and letter <= 'z') return letter - 'a';
        if (letter >= 'A' and letter <= 'Z') return letter - 'A';
        return null;
    }

    pub fn append(self: *TagIndex, tag_letter: u8, value: TagValue) !void {
        const idx = letterIndex(tag_letter) orelse return;
        try self.entries[idx].append(self.allocator, value);
    }

    pub fn get(self: *const TagIndex, tag_letter: u8) ?[]const TagValue {
        const idx = letterIndex(tag_letter) orelse return null;
        if (self.entries[idx].items.len == 0) return null;
        return self.entries[idx].items;
    }

    pub fn iterator(self: *const TagIndex) TagIterator {
        return TagIterator.init(self);
    }
};

pub const TagIterator = struct {
    index: *const TagIndex,
    letter_idx: usize = 0,
    value_idx: usize = 0,

    pub fn init(index: *const TagIndex) TagIterator {
        return .{ .index = index };
    }

    pub const Entry = struct {
        letter: u8,
        value: TagValue,
    };

    pub fn next(self: *TagIterator) ?Entry {
        while (self.letter_idx < 26) {
            const list = &self.index.entries[self.letter_idx];
            if (self.value_idx < list.items.len) {
                const entry = Entry{
                    .letter = @intCast(self.letter_idx + 'a'),
                    .value = list.items[self.value_idx],
                };
                self.value_idx += 1;
                return entry;
            }
            self.letter_idx += 1;
            self.value_idx = 0;
        }
        return null;
    }
};

pub const Event = struct {
    id_bytes: [32]u8,
    pubkey_bytes: [32]u8,
    sig_bytes: [64]u8,
    created_at_val: i64,
    kind_val: i32,
    raw_json: []const u8,

    d_tag_val: ?[]const u8 = null,
    expiration_val: ?i64 = null,
    e_tags: std.ArrayListUnmanaged([32]u8),
    tags: TagIndex,
    tag_count: u32 = 0,
    allocator: std.mem.Allocator,

    pub fn parse(json: []const u8) Error!Event {
        return parseWithAllocator(json, std.heap.page_allocator);
    }

    pub fn parseWithAllocator(json: []const u8, allocator: std.mem.Allocator) Error!Event {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();

        const root = parsed.value.object;

        const id_hex = (root.get("id") orelse return error.MissingField).string;
        const pubkey_hex = (root.get("pubkey") orelse return error.MissingField).string;
        const sig_hex = (root.get("sig") orelse return error.MissingField).string;
        const created_at_val = root.get("created_at") orelse return error.MissingField;
        const kind_val = root.get("kind") orelse return error.MissingField;
        _ = (root.get("content") orelse return error.MissingField).string;

        const created_at: i64 = switch (created_at_val) {
            .integer => |i| i,
            else => return error.InvalidCreatedAt,
        };

        const kind_num: i32 = switch (kind_val) {
            .integer => |i| @intCast(i),
            else => return error.InvalidKind,
        };

        var id_bytes: [32]u8 = undefined;
        var pubkey_bytes: [32]u8 = undefined;
        var sig_bytes: [64]u8 = undefined;

        if (id_hex.len != 64) return error.InvalidId;
        if (pubkey_hex.len != 64) return error.InvalidPubkey;
        if (sig_hex.len != 128) return error.InvalidSig;

        _ = std.fmt.hexToBytes(&id_bytes, id_hex) catch return error.InvalidId;
        _ = std.fmt.hexToBytes(&pubkey_bytes, pubkey_hex) catch return error.InvalidPubkey;
        _ = std.fmt.hexToBytes(&sig_bytes, sig_hex) catch return error.InvalidSig;

        var event = Event{
            .id_bytes = id_bytes,
            .pubkey_bytes = pubkey_bytes,
            .sig_bytes = sig_bytes,
            .created_at_val = created_at,
            .kind_val = kind_num,
            .raw_json = json,
            .allocator = allocator,
            .e_tags = .{},
            .tags = TagIndex.init(allocator),
        };

        if (root.get("tags")) |tags_val| {
            if (tags_val == .array) {
                event.tag_count = @intCast(tags_val.array.items.len);
                for (tags_val.array.items) |tag| {
                    if (tag != .array or tag.array.items.len < 2) continue;

                    const tag_name = if (tag.array.items[0] == .string) tag.array.items[0].string else continue;
                    const tag_value_str = if (tag.array.items[1] == .string) tag.array.items[1].string else continue;

                    if (std.mem.eql(u8, tag_name, "d")) {
                        event.d_tag_val = findStringInJson(json, tag_value_str);
                    } else if (std.mem.eql(u8, tag_name, "expiration")) {
                        event.expiration_val = std.fmt.parseInt(i64, tag_value_str, 10) catch null;
                    }

                    if (tag_name.len == 1) {
                        const letter = tag_name[0];

                        if (letter == 'e' or letter == 'p') {
                            if (tag_value_str.len == 64) {
                                var bytes: [32]u8 = undefined;
                                if (std.fmt.hexToBytes(&bytes, tag_value_str)) |_| {
                                    event.tags.append(letter, .{ .binary = bytes }) catch {};
                                    if (letter == 'e') {
                                        event.e_tags.append(allocator, bytes) catch {};
                                    }
                                } else |_| {}
                            }
                        } else {
                            if (tag_value_str.len > 0 and tag_value_str.len <= 256) {
                                const duped = allocator.dupe(u8, tag_value_str) catch continue;
                                event.tags.append(letter, .{ .string = duped }) catch {
                                    allocator.free(duped);
                                };
                            }
                        }
                    }
                }
            }
        }

        return event;
    }

    pub fn validate(self: *const Event) Error!void {
        const now = std.time.timestamp();
        if (self.created_at_val > now + 900) return error.FutureEvent;

        const computed_id = self.computeId() catch return error.IdMismatch;
        if (!std.mem.eql(u8, &computed_id, &self.id_bytes)) return error.IdMismatch;

        crypto.verifySignature(&self.pubkey_bytes, &computed_id, &self.sig_bytes) catch return error.SigMismatch;
    }

    fn computeId(self: *const Event) ![32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("[0,\"");

        var pubkey_hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&pubkey_hex, "{x}", .{self.pubkey_bytes}) catch unreachable;
        hasher.update(&pubkey_hex);

        hasher.update("\",");

        var created_buf: [20]u8 = undefined;
        const created_str = std.fmt.bufPrint(&created_buf, "{d}", .{self.created_at_val}) catch unreachable;
        hasher.update(created_str);

        hasher.update(",");

        var kind_buf: [11]u8 = undefined;
        const kind_str = std.fmt.bufPrint(&kind_buf, "{d}", .{self.kind_val}) catch unreachable;
        hasher.update(kind_str);

        hasher.update(",");

        if (findJsonValue(self.raw_json, "tags")) |tags_slice| {
            hasher.update(tags_slice);
        } else {
            hasher.update("[]");
        }

        hasher.update(",\"");
        for (self.content()) |c| {
            switch (c) {
                '"' => hasher.update("\\\""),
                '\\' => hasher.update("\\\\"),
                '\n' => hasher.update("\\n"),
                '\r' => hasher.update("\\r"),
                '\t' => hasher.update("\\t"),
                else => {
                    if (c < 0x20) {
                        var buf: [6]u8 = undefined;
                        const s = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch continue;
                        hasher.update(s);
                    } else {
                        hasher.update(&[_]u8{c});
                    }
                },
            }
        }
        hasher.update("\"");

        hasher.update("]");

        return hasher.finalResult();
    }

    pub fn serialize(self: *const Event, buf: []u8) ![]u8 {
        if (self.raw_json.len > 0 and self.raw_json.len <= buf.len) {
            @memcpy(buf[0..self.raw_json.len], self.raw_json);
            return buf[0..self.raw_json.len];
        }
        return error.BufferTooSmall;
    }

    pub fn id(self: *const Event) *const [32]u8 {
        return &self.id_bytes;
    }

    pub fn pubkey(self: *const Event) *const [32]u8 {
        return &self.pubkey_bytes;
    }

    pub fn idHex(self: *const Event, buf: *[65]u8) void {
        _ = std.fmt.bufPrint(buf[0..64], "{x}", .{self.id_bytes}) catch {};
        buf[64] = 0;
    }

    pub fn pubkeyHex(self: *const Event, buf: *[65]u8) void {
        _ = std.fmt.bufPrint(buf[0..64], "{x}", .{self.pubkey_bytes}) catch {};
        buf[64] = 0;
    }

    pub fn kind(self: *const Event) i32 {
        return self.kind_val;
    }

    pub fn createdAt(self: *const Event) i64 {
        return self.created_at_val;
    }

    pub fn content(self: *const Event) []const u8 {
        return extractJsonString(self.raw_json, "content") orelse "";
    }

    pub fn dTag(self: *const Event) ?[]const u8 {
        return self.d_tag_val;
    }

    pub fn tagCount(self: *const Event) u32 {
        return self.tag_count;
    }

    pub fn deinit(self: *Event) void {
        self.e_tags.deinit(self.allocator);
        self.tags.deinit();
    }
};

pub const KindType = enum {
    regular,
    replaceable,
    ephemeral,
    addressable,
};

pub fn kindType(kind_num: i32) KindType {
    if (kind_num == 0 or kind_num == 3) return .replaceable;
    if (kind_num >= 10000 and kind_num < 20000) return .replaceable;
    if (kind_num >= 20000 and kind_num < 30000) return .ephemeral;
    if (kind_num >= 30000 and kind_num < 40000) return .addressable;
    return .regular;
}

pub fn isExpired(event: *const Event) bool {
    if (event.expiration_val) |exp| {
        return std.time.timestamp() > exp;
    }
    return false;
}

pub fn isDeletion(event: *const Event) bool {
    return event.kind() == 5;
}

pub fn getDeletionIds(allocator: std.mem.Allocator, event: *const Event) ![]const [32]u8 {
    if (event.e_tags.items.len > 0) {
        return allocator.dupe([32]u8, event.e_tags.items);
    }
    return &[_][32]u8{};
}

pub const FilterTagEntry = struct {
    letter: u8,
    values: []const TagValue,
};

pub const Filter = struct {
    kinds_slice: ?[]const i32 = null,
    ids_bytes: ?[][32]u8 = null,
    authors_bytes: ?[][32]u8 = null,
    since_val: i64 = 0,
    until_val: i64 = 0,
    limit_val: i32 = 0,
    tag_filters: ?[]FilterTagEntry = null,
    allocator: ?std.mem.Allocator = null,

    pub fn clone(self: *const Filter, allocator: std.mem.Allocator) !Filter {
        var new_filter = self.*;
        new_filter.allocator = allocator;

        if (self.kinds_slice) |k| {
            new_filter.kinds_slice = try allocator.dupe(i32, k);
        }
        if (self.ids_bytes) |id_list| {
            new_filter.ids_bytes = try allocator.dupe([32]u8, id_list);
        }
        if (self.authors_bytes) |author_list| {
            new_filter.authors_bytes = try allocator.dupe([32]u8, author_list);
        }
        if (self.tag_filters) |tags| {
            var new_tags = try allocator.alloc(FilterTagEntry, tags.len);
            for (tags, 0..) |entry, i| {
                new_tags[i] = .{
                    .letter = entry.letter,
                    .values = try allocator.dupe(TagValue, entry.values),
                };
            }
            new_filter.tag_filters = new_tags;
        }

        return new_filter;
    }

    pub fn matches(self: *const Filter, event: *const Event) bool {
        if (self.ids_bytes) |id_list| {
            var found = false;
            for (id_list) |id| {
                if (std.mem.eql(u8, &id, &event.id_bytes)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        if (self.authors_bytes) |author_list| {
            var found = false;
            for (author_list) |author| {
                if (std.mem.eql(u8, &author, &event.pubkey_bytes)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        if (self.kinds_slice) |k_slice| {
            var found = false;
            for (k_slice) |k| {
                if (k == event.kind()) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        if (self.since_val > 0 and event.createdAt() < self.since_val) {
            return false;
        }

        if (self.until_val > 0 and event.createdAt() > self.until_val) {
            return false;
        }

        if (self.tag_filters) |tag_entries| {
            for (tag_entries) |filter_entry| {
                const event_tag_values = event.tags.get(filter_entry.letter) orelse return false;
                var tag_found = false;
                outer: for (filter_entry.values) |filter_val| {
                    for (event_tag_values) |event_val| {
                        if (filter_val.eql(event_val)) {
                            tag_found = true;
                            break :outer;
                        }
                    }
                }
                if (!tag_found) return false;
            }
        }

        return true;
    }

    pub fn kinds(self: *const Filter) ?[]const i32 {
        return self.kinds_slice;
    }

    pub fn ids(self: *const Filter) ?[][32]u8 {
        return self.ids_bytes;
    }

    pub fn authors(self: *const Filter) ?[][32]u8 {
        return self.authors_bytes;
    }

    pub fn since(self: *const Filter) i64 {
        return self.since_val;
    }

    pub fn until(self: *const Filter) i64 {
        return self.until_val;
    }

    pub fn limit(self: *const Filter) i32 {
        return self.limit_val;
    }

    pub fn deinit(self: *Filter) void {
        if (self.allocator) |alloc| {
            if (self.kinds_slice) |k| alloc.free(k);
            if (self.ids_bytes) |id_list| alloc.free(id_list);
            if (self.authors_bytes) |author_list| alloc.free(author_list);
            if (self.tag_filters) |tags| {
                for (tags) |entry| {
                    for (entry.values) |val| {
                        switch (val) {
                            .string => |s| alloc.free(s),
                            .binary => {},
                        }
                    }
                    alloc.free(entry.values);
                }
                alloc.free(tags);
            }
        }
        self.* = .{};
    }
};

pub fn filtersMatch(filters: []const Filter, event: *const Event) bool {
    for (filters) |f| {
        if (f.matches(event)) return true;
    }
    return false;
}

pub const ClientMsgType = enum {
    event,
    req,
    close,
    auth,
};

pub const ClientMsg = struct {
    msg_type: ClientMsgType,
    raw_json: []const u8,
    subscription_id_slice: []const u8 = "",
    event_obj: ?Event = null,
    allocator: std.mem.Allocator,

    pub fn parse(json: []const u8) Error!ClientMsg {
        return parseWithAllocator(json, std.heap.page_allocator);
    }

    pub fn parseWithAllocator(json: []const u8, allocator: std.mem.Allocator) Error!ClientMsg {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();

        if (parsed.value != .array or parsed.value.array.items.len < 1) {
            return error.InvalidJson;
        }

        const arr = parsed.value.array.items;
        const type_str = if (arr[0] == .string) arr[0].string else return error.InvalidJson;

        var msg = ClientMsg{
            .msg_type = .event,
            .raw_json = json,
            .allocator = allocator,
        };

        if (std.mem.eql(u8, type_str, "EVENT")) {
            msg.msg_type = .event;
        } else if (std.mem.eql(u8, type_str, "REQ")) {
            msg.msg_type = .req;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "CLOSE")) {
            msg.msg_type = .close;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "AUTH")) {
            msg.msg_type = .auth;
        } else {
            return error.InvalidJson;
        }

        return msg;
    }

    pub fn msgType(self: *const ClientMsg) ClientMsgType {
        return self.msg_type;
    }

    pub fn getEvent(self: *ClientMsg) Event {
        if (self.event_obj) |ev| {
            return ev;
        }

        if (findArrayElement(self.raw_json, 1)) |event_json| {
            self.event_obj = Event.parseWithAllocator(event_json, self.allocator) catch return undefined;
            return self.event_obj.?;
        }

        return undefined;
    }

    pub fn subscriptionId(self: *const ClientMsg) []const u8 {
        return self.subscription_id_slice;
    }

    pub fn getFilters(self: *const ClientMsg, allocator: std.mem.Allocator) ![]Filter {
        if (self.msg_type != .req) return &[_]Filter{};

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, self.raw_json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();

        if (parsed.value != .array) return &[_]Filter{};

        const arr = parsed.value.array.items;
        if (arr.len < 3) return &[_]Filter{};

        var filters: std.ArrayListUnmanaged(Filter) = .{};
        errdefer filters.deinit(allocator);

        for (arr[2..]) |filter_val| {
            if (filter_val != .object) continue;

            var filter = Filter{ .allocator = allocator };
            const filter_obj = filter_val.object;

            if (filter_obj.get("ids")) |ids_val| {
                if (ids_val == .array) {
                    var ids_list: std.ArrayListUnmanaged([32]u8) = .{};
                    for (ids_val.array.items) |id_val| {
                        if (id_val == .string and id_val.string.len == 64) {
                            var id_bytes: [32]u8 = undefined;
                            if (std.fmt.hexToBytes(&id_bytes, id_val.string)) |_| {
                                try ids_list.append(allocator, id_bytes);
                            } else |_| {}
                        }
                    }
                    if (ids_list.items.len > 0) {
                        filter.ids_bytes = try ids_list.toOwnedSlice(allocator);
                    } else {
                        ids_list.deinit(allocator);
                    }
                }
            }

            if (filter_obj.get("authors")) |authors_val| {
                if (authors_val == .array) {
                    var authors_list: std.ArrayListUnmanaged([32]u8) = .{};
                    for (authors_val.array.items) |author_val| {
                        if (author_val == .string and author_val.string.len == 64) {
                            var author_bytes: [32]u8 = undefined;
                            if (std.fmt.hexToBytes(&author_bytes, author_val.string)) |_| {
                                try authors_list.append(allocator, author_bytes);
                            } else |_| {}
                        }
                    }
                    if (authors_list.items.len > 0) {
                        filter.authors_bytes = try authors_list.toOwnedSlice(allocator);
                    } else {
                        authors_list.deinit(allocator);
                    }
                }
            }

            if (filter_obj.get("kinds")) |kinds_val| {
                if (kinds_val == .array) {
                    var kinds_list: std.ArrayListUnmanaged(i32) = .{};
                    for (kinds_val.array.items) |k| {
                        if (k == .integer) {
                            try kinds_list.append(allocator, @intCast(k.integer));
                        }
                    }
                    if (kinds_list.items.len > 0) {
                        filter.kinds_slice = try kinds_list.toOwnedSlice(allocator);
                    } else {
                        kinds_list.deinit(allocator);
                    }
                }
            }

            if (filter_obj.get("limit")) |v| {
                if (v == .integer) {
                    filter.limit_val = @intCast(v.integer);
                }
            }

            if (filter_obj.get("since")) |v| {
                if (v == .integer) {
                    filter.since_val = v.integer;
                }
            }
            if (filter_obj.get("until")) |v| {
                if (v == .integer) {
                    filter.until_val = v.integer;
                }
            }

            var tag_entries: std.ArrayListUnmanaged(FilterTagEntry) = .{};
            errdefer {
                for (tag_entries.items) |entry| {
                    for (entry.values) |val| {
                        switch (val) {
                            .string => |s| allocator.free(s),
                            .binary => {},
                        }
                    }
                    allocator.free(entry.values);
                }
                tag_entries.deinit(allocator);
            }

            var filter_iter = filter_obj.iterator();
            while (filter_iter.next()) |kv| {
                const key = kv.key_ptr.*;
                if (key.len == 2 and key[0] == '#') {
                    const letter = key[1];
                    if ((letter >= 'a' and letter <= 'z') or (letter >= 'A' and letter <= 'Z')) {
                        const tag_val = kv.value_ptr.*;
                        if (tag_val == .array) {
                            var values_list: std.ArrayListUnmanaged(TagValue) = .{};
                            errdefer values_list.deinit(allocator);

                            for (tag_val.array.items) |item| {
                                if (item == .string) {
                                    const str = item.string;
                                    if ((letter == 'e' or letter == 'p' or letter == 'E' or letter == 'P') and str.len == 64) {
                                        var bytes: [32]u8 = undefined;
                                        if (std.fmt.hexToBytes(&bytes, str)) |_| {
                                            try values_list.append(allocator, .{ .binary = bytes });
                                        } else |_| {
                                            const duped = try allocator.dupe(u8, str);
                                            try values_list.append(allocator, .{ .string = duped });
                                        }
                                    } else {
                                        if (str.len > 0 and str.len <= 256) {
                                            const duped = try allocator.dupe(u8, str);
                                            try values_list.append(allocator, .{ .string = duped });
                                        }
                                    }
                                }
                            }

                            if (values_list.items.len > 0) {
                                try tag_entries.append(allocator, .{
                                    .letter = if (letter >= 'A' and letter <= 'Z') letter + 32 else letter,
                                    .values = try values_list.toOwnedSlice(allocator),
                                });
                            } else {
                                values_list.deinit(allocator);
                            }
                        }
                    }
                }
            }

            if (tag_entries.items.len > 0) {
                filter.tag_filters = try tag_entries.toOwnedSlice(allocator);
            } else {
                tag_entries.deinit(allocator);
            }

            try filters.append(allocator, filter);
        }

        return filters.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *ClientMsg) void {
        if (self.event_obj) |*ev| {
            ev.deinit();
        }
    }
};

pub const RelayMsg = struct {
    pub fn event(sub_id: []const u8, ev: *const Event, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"EVENT\",\"");
        try writer.writeAll(sub_id);
        try writer.writeAll("\",");
        try writer.writeAll(ev.raw_json);
        try writer.writeAll("]");

        return fbs.getWritten();
    }

    pub fn ok(event_id: *const [32]u8, success: bool, message: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"OK\",\"");

        var id_hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&id_hex, "{x}", .{event_id.*}) catch unreachable;
        try writer.writeAll(&id_hex);

        try writer.writeAll("\",");
        try writer.writeAll(if (success) "true" else "false");
        try writer.writeAll(",\"");

        for (message) |c| {
            switch (c) {
                '"' => try writer.writeAll("\\\""),
                '\\' => try writer.writeAll("\\\\"),
                '\n' => try writer.writeAll("\\n"),
                else => try writer.writeByte(c),
            }
        }

        try writer.writeAll("\"]");

        return fbs.getWritten();
    }

    pub fn eose(sub_id: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"EOSE\",\"");
        try writer.writeAll(sub_id);
        try writer.writeAll("\"]");

        return fbs.getWritten();
    }

    pub fn closed(sub_id: []const u8, message: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"CLOSED\",\"");
        try writer.writeAll(sub_id);
        try writer.writeAll("\",\"");

        for (message) |c| {
            switch (c) {
                '"' => try writer.writeAll("\\\""),
                '\\' => try writer.writeAll("\\\\"),
                '\n' => try writer.writeAll("\\n"),
                else => try writer.writeByte(c),
            }
        }

        try writer.writeAll("\"]");

        return fbs.getWritten();
    }

    pub fn notice(message: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"NOTICE\",\"");

        for (message) |c| {
            switch (c) {
                '"' => try writer.writeAll("\\\""),
                '\\' => try writer.writeAll("\\\\"),
                '\n' => try writer.writeAll("\\n"),
                else => try writer.writeByte(c),
            }
        }

        try writer.writeAll("\"]");

        return fbs.getWritten();
    }

    pub fn auth(challenge: *const [32]u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"AUTH\",\"");

        var challenge_hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&challenge_hex, "{x}", .{challenge.*}) catch unreachable;
        try writer.writeAll(&challenge_hex);

        try writer.writeAll("\"]");

        return fbs.getWritten();
    }
};

fn findJsonValue(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [68]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;

    if (std.mem.indexOf(u8, json, search)) |pos| {
        var start = pos + search.len;

        while (start < json.len and (json[start] == ' ' or json[start] == '\t' or json[start] == '\n' or json[start] == '\r')) {
            start += 1;
        }

        if (start >= json.len) return null;

        const first = json[start];

        if (first == '[' or first == '{') {
            const close_char: u8 = if (first == '[') ']' else '}';
            var depth: i32 = 0;
            var end = start;
            var in_string = false;
            var escape = false;

            for (json[start..], 0..) |c, i| {
                if (escape) {
                    escape = false;
                    continue;
                }
                if (c == '\\' and in_string) {
                    escape = true;
                    continue;
                }
                if (c == '"' and !escape) {
                    in_string = !in_string;
                    continue;
                }
                if (!in_string) {
                    if (c == first) depth += 1;
                    if (c == close_char) {
                        depth -= 1;
                        if (depth == 0) {
                            end = start + i + 1;
                            break;
                        }
                    }
                }
            }
            return json[start..end];
        }
    }
    return null;
}

fn findArrayElement(json: []const u8, index: usize) ?[]const u8 {
    var pos: usize = 0;
    while (pos < json.len and json[pos] != '[') : (pos += 1) {}
    if (pos >= json.len) return null;
    pos += 1;

    var current_index: usize = 0;
    var depth: i32 = 0;
    var in_string = false;
    var escape = false;
    var element_start: usize = pos;

    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t' or json[pos] == '\n' or json[pos] == '\r')) : (pos += 1) {}
    element_start = pos;

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
            if (c == '[' or c == '{') {
                depth += 1;
            } else if (c == ']' or c == '}') {
                if (depth == 0 and c == ']') {
                    if (current_index == index) {
                        return json[element_start..pos];
                    }
                    return null;
                }
                depth -= 1;
            } else if (c == ',' and depth == 0) {
                if (current_index == index) {
                    return json[element_start..pos];
                }
                current_index += 1;
                pos += 1;
                while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t' or json[pos] == '\n' or json[pos] == '\r')) : (pos += 1) {}
                element_start = pos;
                continue;
            }
        }

        pos += 1;
    }

    return null;
}

fn extractJsonString(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [68]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, json, search) orelse return null;
    var pos = key_pos + search.len;

    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t' or json[pos] == '\n' or json[pos] == '\r')) : (pos += 1) {}

    if (pos >= json.len or json[pos] != '"') return null;
    pos += 1;

    const start = pos;
    var escape = false;

    while (pos < json.len) {
        const c = json[pos];
        if (escape) {
            escape = false;
        } else if (c == '\\') {
            escape = true;
        } else if (c == '"') {
            return json[start..pos];
        }
        pos += 1;
    }
    return null;
}

fn findStringInJson(json: []const u8, needle: []const u8) ?[]const u8 {
    var search_buf: [256]u8 = undefined;
    if (needle.len > 250) return null;

    const search = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{needle}) catch return null;
    const pos = std.mem.indexOf(u8, json, search) orelse return null;

    return json[pos + 1 .. pos + 1 + needle.len];
}

pub fn init() !void {
    try crypto.init();
}

pub fn cleanup() void {
    crypto.cleanup();
}
