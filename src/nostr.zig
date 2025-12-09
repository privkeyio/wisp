const std = @import("std");

const c = @cImport({
    @cInclude("nostr.h");
    @cInclude("nostr_relay_protocol.h");
});

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

fn mapError(code: anytype) Error {
    return switch (code) {
        c.NOSTR_RELAY_ERR_INVALID_JSON => error.InvalidJson,
        c.NOSTR_RELAY_ERR_MISSING_FIELD => error.MissingField,
        c.NOSTR_RELAY_ERR_INVALID_ID => error.InvalidId,
        c.NOSTR_RELAY_ERR_INVALID_PUBKEY => error.InvalidPubkey,
        c.NOSTR_RELAY_ERR_INVALID_SIG => error.InvalidSig,
        c.NOSTR_RELAY_ERR_INVALID_CREATED_AT => error.InvalidCreatedAt,
        c.NOSTR_RELAY_ERR_INVALID_KIND => error.InvalidKind,
        c.NOSTR_RELAY_ERR_INVALID_TAGS => error.InvalidTags,
        c.NOSTR_RELAY_ERR_INVALID_CONTENT => error.InvalidContent,
        c.NOSTR_RELAY_ERR_ID_MISMATCH => error.IdMismatch,
        c.NOSTR_RELAY_ERR_SIG_MISMATCH => error.SigMismatch,
        c.NOSTR_RELAY_ERR_FUTURE_EVENT => error.FutureEvent,
        c.NOSTR_RELAY_ERR_EXPIRED_EVENT => error.ExpiredEvent,
        c.NOSTR_RELAY_ERR_INVALID_SUBSCRIPTION_ID => error.InvalidSubscriptionId,
        c.NOSTR_RELAY_ERR_TOO_MANY_FILTERS => error.TooManyFilters,
        c.NOSTR_RELAY_ERR_BUFFER_TOO_SMALL => error.BufferTooSmall,
        c.NOSTR_RELAY_ERR_MEMORY => error.AllocFailed,
        else => error.Unknown,
    };
}

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

pub const Event = struct {
    inner: *c.nostr_event,
    owned: bool,

    pub fn parse(json: []const u8) !Event {
        var event: ?*c.nostr_event = null;
        const result = c.nostr_event_parse(json.ptr, json.len, &event);
        if (result != c.NOSTR_RELAY_OK) {
            return mapError(result);
        }
        return .{ .inner = event.?, .owned = true };
    }

    pub fn borrow(inner: *c.nostr_event) Event {
        return .{ .inner = inner, .owned = false };
    }

    pub fn validate(self: *const Event) !void {
        var validation_result: c.nostr_validation_result_t = undefined;
        const result = c.nostr_event_validate_full(self.inner, 900, &validation_result);
        if (result != c.NOSTR_RELAY_OK) {
            return mapError(result);
        }
        if (!validation_result.valid) {
            return mapError(validation_result.error_code);
        }
    }

    pub fn serialize(self: *const Event, buf: []u8) ![]u8 {
        var len: usize = undefined;
        const result = c.nostr_event_serialize(self.inner, buf.ptr, buf.len, &len);
        if (result != c.NOSTR_RELAY_OK) {
            return mapError(result);
        }
        return buf[0..len];
    }

    pub fn id(self: *const Event) *const [32]u8 {
        return @ptrCast(c.nostr_event_get_id(self.inner));
    }

    pub fn pubkey(self: *const Event) *const [32]u8 {
        return @ptrCast(c.nostr_event_get_pubkey(self.inner));
    }

    pub fn idHex(self: *const Event, buf: *[65]u8) void {
        c.nostr_event_get_id_hex(self.inner, buf);
    }

    pub fn pubkeyHex(self: *const Event, buf: *[65]u8) void {
        c.nostr_event_get_pubkey_hex(self.inner, buf);
    }

    pub fn kind(self: *const Event) i32 {
        return @intCast(self.inner.kind);
    }

    pub fn createdAt(self: *const Event) i64 {
        return self.inner.created_at;
    }

    pub fn content(self: *const Event) []const u8 {
        if (self.inner.content) |ptr| {
            return std.mem.sliceTo(ptr, 0);
        }
        return "";
    }

    pub fn dTag(self: *const Event) ?[]const u8 {
        const ptr = c.nostr_event_get_d_tag(self.inner);
        if (ptr) |p| {
            return std.mem.sliceTo(p, 0);
        }
        return null;
    }

    pub fn tagCount(self: *const Event) usize {
        return c.nostr_event_get_tag_count(self.inner);
    }

    pub fn deinit(self: *Event) void {
        if (self.owned) {
            c.nostr_event_destroy(self.inner);
        }
    }
};

pub const KindType = enum {
    regular,
    replaceable,
    ephemeral,
    addressable,
};

pub fn kindType(kind_num: i32) KindType {
    const result = c.nostr_kind_get_type(kind_num);
    return switch (result) {
        c.NOSTR_KIND_REGULAR => .regular,
        c.NOSTR_KIND_REPLACEABLE => .replaceable,
        c.NOSTR_KIND_EPHEMERAL => .ephemeral,
        c.NOSTR_KIND_ADDRESSABLE => .addressable,
        else => .regular,
    };
}

pub fn isExpired(event: *const Event) bool {
    return c.nostr_event_is_expired_now(event.inner);
}

pub fn isDeletion(event: *const Event) bool {
    return event.kind() == 5;
}

pub fn getDeletionIds(allocator: std.mem.Allocator, event: *const Event) ![]const [32]u8 {
    var count: usize = 0;
    const ids = c.nostr_event_get_e_tags_binary(event.inner, &count);
    if (ids == null or count == 0) {
        return &[_][32]u8{};
    }
    defer c.nostr_free(ids);

    const result = try allocator.alloc([32]u8, count);
    for (0..count) |i| {
        @memcpy(&result[i], @as(*const [32]u8, @ptrCast(&ids[i])));
    }
    return result;
}

pub const Filter = struct {
    inner: *const c.nostr_filter_t,
    owned: bool,

    pub fn parse(json: []const u8, out: *c.nostr_filter_t) !Filter {
        const result = c.nostr_filter_parse(json.ptr, json.len, out);
        if (result != c.NOSTR_RELAY_OK) {
            return mapError(result);
        }
        return .{ .inner = out, .owned = true };
    }

    pub fn borrow(inner: *const c.nostr_filter_t) Filter {
        return .{ .inner = inner, .owned = false };
    }

    pub fn matches(self: *const Filter, event: *const Event) bool {
        return c.nostr_filter_matches(self.inner, event.inner);
    }

    pub fn ids(self: *const Filter) ?[]const [32]u8 {
        _ = self;
        return null;
    }

    pub fn authors(self: *const Filter) ?[]const [32]u8 {
        _ = self;
        return null;
    }

    pub fn kinds(self: *const Filter) ?[]const i32 {
        var count: usize = undefined;
        const ptr = c.nostr_filter_get_kinds(self.inner, &count);
        if (ptr == null or count == 0) return null;
        return @as([*]const i32, @ptrCast(ptr))[0..count];
    }

    pub fn since(self: *const Filter) i64 {
        return c.nostr_filter_get_since(self.inner);
    }

    pub fn until(self: *const Filter) i64 {
        return c.nostr_filter_get_until(self.inner);
    }

    pub fn limit(self: *const Filter) i32 {
        return c.nostr_filter_get_limit(self.inner);
    }

    pub fn deinit(self: *Filter) void {
        if (self.owned) {
            c.nostr_filter_free(@constCast(self.inner));
        }
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
    inner: c.nostr_client_msg_t,

    pub fn parse(json: []const u8) !ClientMsg {
        var msg: c.nostr_client_msg_t = undefined;
        const result = c.nostr_client_msg_parse(json.ptr, json.len, &msg);
        if (result != c.NOSTR_RELAY_OK) {
            return mapError(result);
        }
        return .{ .inner = msg };
    }

    pub fn msgType(self: *const ClientMsg) ClientMsgType {
        return switch (c.nostr_client_msg_get_type(&self.inner)) {
            c.NOSTR_CLIENT_MSG_EVENT => .event,
            c.NOSTR_CLIENT_MSG_REQ => .req,
            c.NOSTR_CLIENT_MSG_CLOSE => .close,
            c.NOSTR_CLIENT_MSG_AUTH => .auth,
            else => .event,
        };
    }

    pub fn getEvent(self: *const ClientMsg) Event {
        const ptr = c.nostr_client_msg_get_event(&self.inner);
        return Event.borrow(@constCast(ptr));
    }

    pub fn subscriptionId(self: *const ClientMsg) []const u8 {
        const ptr = c.nostr_client_msg_get_subscription_id(&self.inner);
        if (ptr) |p| {
            return std.mem.sliceTo(p, 0);
        }
        return "";
    }

    pub fn getFilters(self: *const ClientMsg, allocator: std.mem.Allocator) ![]Filter {
        var count: usize = undefined;
        const ptr = c.nostr_client_msg_get_filters(&self.inner, &count);
        if (ptr == null or count == 0) {
            return &[_]Filter{};
        }

        const filters = try allocator.alloc(Filter, count);
        const safe_ptr: [*]const c.nostr_filter_t = @ptrCast(ptr);
        for (0..count) |i| {
            filters[i] = Filter.borrow(&safe_ptr[i]);
        }
        return filters;
    }

    pub fn deinit(self: *ClientMsg) void {
        c.nostr_client_msg_free(&self.inner);
    }
};

pub const RelayMsg = struct {
    pub fn event(sub_id: []const u8, ev: *const Event, buf: []u8) ![]u8 {
        var msg: c.nostr_relay_msg_t = undefined;
        c.nostr_relay_msg_event(&msg, sub_id.ptr, ev.inner);

        var len: usize = undefined;
        const result = c.nostr_relay_msg_serialize(&msg, buf.ptr, buf.len, &len);
        if (result != c.NOSTR_RELAY_OK) {
            return mapError(result);
        }
        return buf[0..len];
    }

    pub fn ok(event_id: *const [32]u8, success: bool, message: []const u8, buf: []u8) ![]u8 {
        var msg: c.nostr_relay_msg_t = undefined;
        var id_hex: [65]u8 = undefined;
        c.nostr_bytes_to_hex(event_id, 32, &id_hex);
        c.nostr_relay_msg_ok(&msg, &id_hex, success, message.ptr);

        var len: usize = undefined;
        const result = c.nostr_relay_msg_serialize(&msg, buf.ptr, buf.len, &len);
        if (result != c.NOSTR_RELAY_OK) {
            return mapError(result);
        }
        return buf[0..len];
    }

    pub fn eose(sub_id: []const u8, buf: []u8) ![]u8 {
        var msg: c.nostr_relay_msg_t = undefined;
        c.nostr_relay_msg_eose(&msg, sub_id.ptr);

        var len: usize = undefined;
        const result = c.nostr_relay_msg_serialize(&msg, buf.ptr, buf.len, &len);
        if (result != c.NOSTR_RELAY_OK) {
            return mapError(result);
        }
        return buf[0..len];
    }

    pub fn closed(sub_id: []const u8, message: []const u8, buf: []u8) ![]u8 {
        var msg: c.nostr_relay_msg_t = undefined;
        c.nostr_relay_msg_closed(&msg, sub_id.ptr, message.ptr);

        var len: usize = undefined;
        const result = c.nostr_relay_msg_serialize(&msg, buf.ptr, buf.len, &len);
        if (result != c.NOSTR_RELAY_OK) {
            return mapError(result);
        }
        return buf[0..len];
    }

    pub fn notice(message: []const u8, buf: []u8) ![]u8 {
        var msg: c.nostr_relay_msg_t = undefined;
        c.nostr_relay_msg_notice(&msg, message.ptr);

        var len: usize = undefined;
        const result = c.nostr_relay_msg_serialize(&msg, buf.ptr, buf.len, &len);
        if (result != c.NOSTR_RELAY_OK) {
            return mapError(result);
        }
        return buf[0..len];
    }
};

pub fn init() !void {
    const result = c.nostr_init();
    if (result != c.NOSTR_OK) {
        return error.Unknown;
    }
}

pub fn cleanup() void {
    c.nostr_cleanup();
}
