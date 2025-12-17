const std = @import("std");
const Lmdb = @import("lmdb.zig").Lmdb;
const Txn = @import("lmdb.zig").Txn;
const Dbi = @import("lmdb.zig").Dbi;
const Cursor = @import("lmdb.zig").Cursor;

pub const ManagementStore = struct {
    lmdb: *Lmdb,
    allocator: std.mem.Allocator,

    banned_pubkeys: Dbi,
    allowed_pubkeys: Dbi,
    banned_events: Dbi,
    allowed_kinds: Dbi,
    blocked_ips: Dbi,
    relay_settings: Dbi,

    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, lmdb: *Lmdb) !ManagementStore {
        var txn = try lmdb.beginTxn(false);
        errdefer txn.abort();

        const banned_pubkeys = try lmdb.openDbi(&txn, "mgmt:banned_pubkeys");
        const allowed_pubkeys = try lmdb.openDbi(&txn, "mgmt:allowed_pubkeys");
        const banned_events = try lmdb.openDbi(&txn, "mgmt:banned_events");
        const allowed_kinds = try lmdb.openDbi(&txn, "mgmt:allowed_kinds");
        const blocked_ips = try lmdb.openDbi(&txn, "mgmt:blocked_ips");
        const relay_settings = try lmdb.openDbi(&txn, "mgmt:relay_settings");

        try txn.commit();

        return .{
            .lmdb = lmdb,
            .allocator = allocator,
            .banned_pubkeys = banned_pubkeys,
            .allowed_pubkeys = allowed_pubkeys,
            .banned_events = banned_events,
            .allowed_kinds = allowed_kinds,
            .blocked_ips = blocked_ips,
            .relay_settings = relay_settings,
            .mutex = .{},
        };
    }

    pub fn banPubkey(self: *ManagementStore, pubkey: *const [32]u8, reason: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        try txn.put(self.banned_pubkeys, pubkey, reason);
        try txn.commit();
    }

    pub fn unbanPubkey(self: *ManagementStore, pubkey: *const [32]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

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

        var list: std.ArrayListUnmanaged(PubkeyEntry) = .{};
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
        self.mutex.lock();
        defer self.mutex.unlock();

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        try txn.put(self.allowed_pubkeys, pubkey, reason);
        try txn.commit();
    }

    pub fn disallowPubkey(self: *ManagementStore, pubkey: *const [32]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

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

        var list: std.ArrayListUnmanaged(PubkeyEntry) = .{};
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
        self.mutex.lock();
        defer self.mutex.unlock();

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        try txn.put(self.banned_events, event_id, reason);
        try txn.commit();
    }

    pub fn unbanEvent(self: *ManagementStore, event_id: *const [32]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

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
        var txn = try self.lmdb.beginTxn(true);
        defer txn.abort();

        var cursor = try txn.cursor(self.banned_events);
        defer cursor.close();

        var list: std.ArrayListUnmanaged(EventEntry) = .{};
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
        self.mutex.lock();
        defer self.mutex.unlock();

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        const key = std.mem.asBytes(&kind);
        try txn.put(self.allowed_kinds, key, "");
        try txn.commit();
    }

    pub fn disallowKind(self: *ManagementStore, kind: i32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        const key = std.mem.asBytes(&kind);
        txn.delete(self.allowed_kinds, key) catch {};
        try txn.commit();
    }

    pub fn isKindAllowed(self: *ManagementStore, kind: i32) bool {
        if (!self.hasAllowedKinds()) return true;
        var txn = self.lmdb.beginTxn(true) catch return true;
        defer txn.abort();
        const key = std.mem.asBytes(&kind);
        return txn.get(self.allowed_kinds, key) catch null != null;
    }

    pub fn hasAllowedKinds(self: *ManagementStore) bool {
        var txn = self.lmdb.beginTxn(true) catch return false;
        defer txn.abort();
        var cursor = txn.cursor(self.allowed_kinds) catch return false;
        defer cursor.close();
        return (cursor.get(.first) catch null) != null;
    }

    pub fn listAllowedKinds(self: *ManagementStore, allocator: std.mem.Allocator) ![]i32 {
        var txn = try self.lmdb.beginTxn(true);
        defer txn.abort();

        var cursor = try txn.cursor(self.allowed_kinds);
        defer cursor.close();

        var list: std.ArrayListUnmanaged(i32) = .{};
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
        self.mutex.lock();
        defer self.mutex.unlock();

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        try txn.put(self.blocked_ips, ip, reason);
        try txn.commit();
    }

    pub fn unblockIp(self: *ManagementStore, ip: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var txn = try self.lmdb.beginTxn(false);
        errdefer txn.abort();
        txn.delete(self.blocked_ips, ip) catch {};
        try txn.commit();
    }

    pub fn isIpBlocked(self: *ManagementStore, ip: []const u8) bool {
        var txn = self.lmdb.beginTxn(true) catch return false;
        defer txn.abort();

        if ((txn.get(self.blocked_ips, ip) catch null) != null) return true;

        var cursor = txn.cursor(self.blocked_ips) catch return false;
        defer cursor.close();

        var entry = cursor.get(.first) catch null;
        while (entry != null) {
            const e = entry.?;
            if (std.mem.startsWith(u8, ip, e.key)) {
                return true;
            }
            entry = cursor.get(.next) catch null;
        }

        return false;
    }

    pub fn listBlockedIps(self: *ManagementStore, allocator: std.mem.Allocator) ![]IpEntry {
        var txn = try self.lmdb.beginTxn(true);
        defer txn.abort();

        var cursor = try txn.cursor(self.blocked_ips);
        defer cursor.close();

        var list: std.ArrayListUnmanaged(IpEntry) = .{};
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
        self.mutex.lock();
        defer self.mutex.unlock();

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
