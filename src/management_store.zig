const std = @import("std");
const Lmdb = @import("lmdb.zig").Lmdb;
const Txn = @import("lmdb.zig").Txn;
const Dbi = @import("lmdb.zig").Dbi;
const Cursor = @import("lmdb.zig").Cursor;
const nostr = @import("nostr.zig");

pub const ManagementStore = struct {
    lmdb: *Lmdb,
    allocator: std.mem.Allocator,

    banned_pubkeys: Dbi,
    allowed_pubkeys: Dbi,
    banned_events: Dbi,
    allowed_events: Dbi,
    allowed_kinds: Dbi,
    disallowed_kinds: Dbi,
    blocked_ips: Dbi,
    relay_settings: Dbi,

    mutex: std.Io.Mutex,

    pub fn init(allocator: std.mem.Allocator, lmdb: *Lmdb) !ManagementStore {
        var txn = try lmdb.beginTxn(false);
        errdefer txn.abort();

        const banned_pubkeys = try lmdb.openDbi(&txn, "mgmt:banned_pubkeys");
        const allowed_pubkeys = try lmdb.openDbi(&txn, "mgmt:allowed_pubkeys");
        const banned_events = try lmdb.openDbi(&txn, "mgmt:banned_events");
        const allowed_events = try lmdb.openDbi(&txn, "mgmt:allowed_events");
        const allowed_kinds = try lmdb.openDbi(&txn, "mgmt:allowed_kinds");
        const disallowed_kinds = try lmdb.openDbi(&txn, "mgmt:disallowed_kinds");
        const blocked_ips = try lmdb.openDbi(&txn, "mgmt:blocked_ips");
        const relay_settings = try lmdb.openDbi(&txn, "mgmt:relay_settings");

        try txn.commit();

        return .{
            .lmdb = lmdb,
            .allocator = allocator,
            .banned_pubkeys = banned_pubkeys,
            .allowed_pubkeys = allowed_pubkeys,
            .banned_events = banned_events,
            .allowed_events = allowed_events,
            .allowed_kinds = allowed_kinds,
            .disallowed_kinds = disallowed_kinds,
            .blocked_ips = blocked_ips,
            .relay_settings = relay_settings,
            .mutex = .init,
        };
    }

    /// Writes `key` to `put_dbi` and removes it from `clear_dbi` in one
    /// transaction. NIP-86 ban and allow lists are mutually exclusive.
    fn putExclusive(self: *ManagementStore, put_dbi: Dbi, clear_dbi: Dbi, key: []const u8, value: []const u8) !void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        try txn.put(put_dbi, key, value);
        txn.delete(clear_dbi, key) catch {};
        try txn.commit();
    }

    fn remove(self: *ManagementStore, dbi: Dbi, key: []const u8) !void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        txn.delete(dbi, key) catch {};
        try txn.commit();
    }

    fn contains(self: *ManagementStore, dbi: Dbi, key: []const u8) bool {
        var txn = self.lmdb.beginTxn(true) catch return false;
        defer txn.abort();
        return txn.get(dbi, key) catch null != null;
    }

    /// Why the relay's NIP-86 policy refuses `event`, or null if it admits it.
    /// A NIP-86 `allowevent` approves that one event past the pubkey and kind
    /// allowlists; a pubkey ban still applies.
    pub fn rejection(self: *ManagementStore, event: *const nostr.Event) ?[]const u8 {
        if (self.isPubkeyBanned(event.pubkey())) return "blocked: pubkey is banned";
        const approved = self.isEventAllowed(event.id());
        if (!approved and self.hasAllowedPubkeys() and !self.isPubkeyAllowed(event.pubkey())) return "blocked: pubkey not in allowlist";
        if (!approved and !self.isKindAllowed(event.kind())) return "blocked: event kind not allowed";
        if (self.isEventBanned(event.id())) return "blocked: event is banned";
        return null;
    }

    pub fn banPubkey(self: *ManagementStore, pubkey: *const [32]u8, reason: []const u8) !void {
        try self.putExclusive(self.banned_pubkeys, self.allowed_pubkeys, pubkey, reason);
    }

    pub fn unbanPubkey(self: *ManagementStore, pubkey: *const [32]u8) !void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        txn.delete(self.banned_pubkeys, pubkey) catch {};
        try txn.commit();
    }

    pub fn isPubkeyBanned(self: *ManagementStore, pubkey: *const [32]u8) bool {
        var txn = self.lmdb.beginTxn(true) catch return false;
        defer txn.abort();
        return txn.get(self.banned_pubkeys, pubkey) catch null != null;
    }

    pub fn listBannedPubkeys(self: *ManagementStore, allocator: std.mem.Allocator) ![]PubkeyEntry {
        var txn = try self.lmdb.beginTxn(true);
        defer txn.abort();

        var cursor = try txn.cursor(self.banned_pubkeys);
        defer cursor.close();

        var list: std.ArrayListUnmanaged(PubkeyEntry) = .empty;
        errdefer {
            for (list.items) |*e| e.deinit(allocator);
            list.deinit(allocator);
        }

        var entry = try cursor.get(.first);
        while (entry != null) {
            const e = entry.?;
            if (e.key.len == 32) {
                var pk: [32]u8 = undefined;
                @memcpy(&pk, e.key[0..32]);
                const reason = if (e.value.len > 0)
                    try allocator.dupe(u8, e.value)
                else
                    try allocator.dupe(u8, "");
                try list.append(allocator, .{ .pubkey = pk, .reason = reason });
            }
            entry = try cursor.get(.next);
        }

        return try list.toOwnedSlice(allocator);
    }

    pub fn allowPubkey(self: *ManagementStore, pubkey: *const [32]u8, reason: []const u8) !void {
        try self.putExclusive(self.allowed_pubkeys, self.banned_pubkeys, pubkey, reason);
    }

    pub fn disallowPubkey(self: *ManagementStore, pubkey: *const [32]u8) !void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        txn.delete(self.allowed_pubkeys, pubkey) catch {};
        try txn.commit();
    }

    pub fn isPubkeyAllowed(self: *ManagementStore, pubkey: *const [32]u8) bool {
        var txn = self.lmdb.beginTxn(true) catch return false;
        defer txn.abort();
        return txn.get(self.allowed_pubkeys, pubkey) catch null != null;
    }

    pub fn hasAllowedPubkeys(self: *ManagementStore) bool {
        var txn = self.lmdb.beginTxn(true) catch return false;
        defer txn.abort();
        var cursor = txn.cursor(self.allowed_pubkeys) catch return false;
        defer cursor.close();
        return (cursor.get(.first) catch null) != null;
    }

    pub fn listAllowedPubkeys(self: *ManagementStore, allocator: std.mem.Allocator) ![]PubkeyEntry {
        var txn = try self.lmdb.beginTxn(true);
        defer txn.abort();

        var cursor = try txn.cursor(self.allowed_pubkeys);
        defer cursor.close();

        var list: std.ArrayListUnmanaged(PubkeyEntry) = .empty;
        errdefer {
            for (list.items) |*e| e.deinit(allocator);
            list.deinit(allocator);
        }

        var entry = try cursor.get(.first);
        while (entry != null) {
            const e = entry.?;
            if (e.key.len == 32) {
                var pk: [32]u8 = undefined;
                @memcpy(&pk, e.key[0..32]);
                const reason = if (e.value.len > 0)
                    try allocator.dupe(u8, e.value)
                else
                    try allocator.dupe(u8, "");
                try list.append(allocator, .{ .pubkey = pk, .reason = reason });
            }
            entry = try cursor.get(.next);
        }

        return try list.toOwnedSlice(allocator);
    }

    pub fn banEvent(self: *ManagementStore, event_id: *const [32]u8, reason: []const u8) !void {
        try self.putExclusive(self.banned_events, self.allowed_events, event_id, reason);
    }

    pub fn allowEvent(self: *ManagementStore, event_id: *const [32]u8, reason: []const u8) !void {
        try self.putExclusive(self.allowed_events, self.banned_events, event_id, reason);
    }

    pub fn disallowEvent(self: *ManagementStore, event_id: *const [32]u8) !void {
        try self.remove(self.allowed_events, event_id);
    }

    pub fn isEventAllowed(self: *ManagementStore, event_id: *const [32]u8) bool {
        return self.contains(self.allowed_events, event_id);
    }

    pub fn unbanEvent(self: *ManagementStore, event_id: *const [32]u8) !void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        txn.delete(self.banned_events, event_id) catch {};
        try txn.commit();
    }

    pub fn isEventBanned(self: *ManagementStore, event_id: *const [32]u8) bool {
        var txn = self.lmdb.beginTxn(true) catch return false;
        defer txn.abort();
        return txn.get(self.banned_events, event_id) catch null != null;
    }

    pub fn listBannedEvents(self: *ManagementStore, allocator: std.mem.Allocator) ![]EventEntry {
        return self.listEvents(self.banned_events, allocator);
    }

    pub fn listAllowedEvents(self: *ManagementStore, allocator: std.mem.Allocator) ![]EventEntry {
        return self.listEvents(self.allowed_events, allocator);
    }

    fn listEvents(self: *ManagementStore, dbi: Dbi, allocator: std.mem.Allocator) ![]EventEntry {
        var txn = try self.lmdb.beginTxn(true);
        defer txn.abort();

        var cursor = try txn.cursor(dbi);
        defer cursor.close();

        var list: std.ArrayListUnmanaged(EventEntry) = .empty;
        errdefer {
            for (list.items) |*e| e.deinit(allocator);
            list.deinit(allocator);
        }

        var entry = try cursor.get(.first);
        while (entry != null) {
            const e = entry.?;
            if (e.key.len == 32) {
                var id: [32]u8 = undefined;
                @memcpy(&id, e.key[0..32]);
                const reason = if (e.value.len > 0)
                    try allocator.dupe(u8, e.value)
                else
                    try allocator.dupe(u8, "");
                try list.append(allocator, .{ .id = id, .reason = reason });
            }
            entry = try cursor.get(.next);
        }

        return try list.toOwnedSlice(allocator);
    }

    pub fn allowKind(self: *ManagementStore, kind: i32) !void {
        try self.putExclusive(self.allowed_kinds, self.disallowed_kinds, std.mem.asBytes(&kind), "");
    }

    /// Denies the kind outright. The allowlist is left alone: removing the kind
    /// from it could empty it, which would admit every kind.
    pub fn disallowKind(self: *ManagementStore, kind: i32) !void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        try txn.put(self.disallowed_kinds, std.mem.asBytes(&kind), "");
        try txn.commit();
    }

    pub fn isKindAllowed(self: *ManagementStore, kind: i32) bool {
        if (self.contains(self.disallowed_kinds, std.mem.asBytes(&kind))) return false;
        if (!self.hasAllowedKinds()) return true;
        return self.contains(self.allowed_kinds, std.mem.asBytes(&kind));
    }

    pub fn hasAllowedKinds(self: *ManagementStore) bool {
        var txn = self.lmdb.beginTxn(true) catch return false;
        defer txn.abort();
        var cursor = txn.cursor(self.allowed_kinds) catch return false;
        defer cursor.close();
        return (cursor.get(.first) catch null) != null;
    }

    pub fn listAllowedKinds(self: *ManagementStore, allocator: std.mem.Allocator) ![]i32 {
        return self.listKinds(self.allowed_kinds, allocator);
    }

    pub fn listDisallowedKinds(self: *ManagementStore, allocator: std.mem.Allocator) ![]i32 {
        return self.listKinds(self.disallowed_kinds, allocator);
    }

    fn listKinds(self: *ManagementStore, dbi: Dbi, allocator: std.mem.Allocator) ![]i32 {
        var txn = try self.lmdb.beginTxn(true);
        defer txn.abort();

        var cursor = try txn.cursor(dbi);
        defer cursor.close();

        var list: std.ArrayListUnmanaged(i32) = .empty;
        errdefer list.deinit(allocator);

        var entry = try cursor.get(.first);
        while (entry != null) {
            const e = entry.?;
            if (e.key.len == 4) {
                const kind: i32 = @bitCast(e.key[0..4].*);
                try list.append(allocator, kind);
            }
            entry = try cursor.get(.next);
        }

        return list.toOwnedSlice(allocator);
    }

    pub fn blockIp(self: *ManagementStore, ip: []const u8, reason: []const u8) !void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        try txn.put(self.blocked_ips, ip, reason);
        try txn.commit();
    }

    pub fn unblockIp(self: *ManagementStore, ip: []const u8) !void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        txn.delete(self.blocked_ips, ip) catch {};
        try txn.commit();
    }

    pub fn isIpBlocked(self: *ManagementStore, ip: []const u8) bool {
        var txn = self.lmdb.beginTxn(true) catch return false;
        defer txn.abort();

        if ((txn.get(self.blocked_ips, ip) catch null) != null) return true;

        var pos: usize = 0;
        while (std.mem.indexOfScalarPos(u8, ip, pos, '.')) |dot| {
            if ((txn.get(self.blocked_ips, ip[0..dot]) catch null) != null) return true;
            pos = dot + 1;
        }

        return false;
    }

    pub fn listBlockedIps(self: *ManagementStore, allocator: std.mem.Allocator) ![]IpEntry {
        var txn = try self.lmdb.beginTxn(true);
        defer txn.abort();

        var cursor = try txn.cursor(self.blocked_ips);
        defer cursor.close();

        var list: std.ArrayListUnmanaged(IpEntry) = .empty;
        errdefer {
            for (list.items) |*e| e.deinit(allocator);
            list.deinit(allocator);
        }

        var entry = try cursor.get(.first);
        while (entry != null) {
            const e = entry.?;
            const ip = try allocator.dupe(u8, e.key);
            errdefer allocator.free(ip);
            const reason = if (e.value.len > 0)
                try allocator.dupe(u8, e.value)
            else
                try allocator.dupe(u8, "");
            try list.append(allocator, .{ .ip = ip, .reason = reason });
            entry = try cursor.get(.next);
        }

        return try list.toOwnedSlice(allocator);
    }

    pub fn setRelaySetting(self: *ManagementStore, key: []const u8, value: []const u8) !void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        try txn.put(self.relay_settings, key, value);
        try txn.commit();
    }

    pub fn getRelaySetting(self: *ManagementStore, key: []const u8, allocator: std.mem.Allocator) !?[]const u8 {
        var txn = try self.lmdb.beginTxn(true);
        defer txn.abort();
        if (try txn.get(self.relay_settings, key)) |value| {
            return try allocator.dupe(u8, value);
        }
        return null;
    }

    pub const PubkeyEntry = struct {
        pubkey: [32]u8,
        reason: []const u8,

        pub fn deinit(self: *PubkeyEntry, allocator: std.mem.Allocator) void {
            allocator.free(self.reason);
        }
    };

    pub const EventEntry = struct {
        id: [32]u8,
        reason: []const u8,

        pub fn deinit(self: *EventEntry, allocator: std.mem.Allocator) void {
            allocator.free(self.reason);
        }
    };

    pub const IpEntry = struct {
        ip: []const u8,
        reason: []const u8,

        pub fn deinit(self: *IpEntry, allocator: std.mem.Allocator) void {
            allocator.free(self.ip);
            allocator.free(self.reason);
        }
    };

    pub fn freePubkeyEntries(entries: []PubkeyEntry, allocator: std.mem.Allocator) void {
        for (entries) |*e| e.deinit(allocator);
        allocator.free(entries);
    }

    pub fn freeEventEntries(entries: []EventEntry, allocator: std.mem.Allocator) void {
        for (entries) |*e| e.deinit(allocator);
        allocator.free(entries);
    }

    pub fn freeIpEntries(entries: []IpEntry, allocator: std.mem.Allocator) void {
        for (entries) |*e| e.deinit(allocator);
        allocator.free(entries);
    }
};
