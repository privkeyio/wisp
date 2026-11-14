const std = @import("std");
const Lmdb = @import("lmdb.zig").Lmdb;
const Txn = @import("lmdb.zig").Txn;
const Dbi = @import("lmdb.zig").Dbi;
const Cursor = @import("lmdb.zig").Cursor;
const nostr = @import("nostr.zig");
const ip_match = @import("ip_match.zig");

const log = std.log.scoped(.management_store);

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

    /// Parsed copy of `blocked_ips`, rebuilt on every change so the
    /// per-connection check never touches LMDB or parses a rule.
    ip_rules: std.ArrayListUnmanaged(ip_match.Rule),
    ip_rules_mutex: std.Io.Mutex,

    pub fn init(allocator: std.mem.Allocator, lmdb: *Lmdb) !ManagementStore {
        var self = try open(allocator, lmdb);
        try self.reloadIpRules();
        return self;
    }

    fn open(allocator: std.mem.Allocator, lmdb: *Lmdb) !ManagementStore {
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
            .ip_rules = .empty,
            .ip_rules_mutex = .init,
        };
    }

    pub fn deinit(self: *ManagementStore) void {
        self.ip_rules.deinit(self.allocator);
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
    /// allowlists; a pubkey ban still applies. Reads one snapshot, and refuses
    /// the event if the policy cannot be read rather than admitting it.
    pub fn rejection(self: *ManagementStore, event: *const nostr.Event) ?[]const u8 {
        const unreadable = "error: relay policy unavailable";
        var txn = self.lmdb.beginTxn(true) catch return unreadable;
        defer txn.abort();
        const kind = std.mem.asBytes(&event.kind());

        if (has(&txn, self.banned_pubkeys, event.pubkey()) catch return unreadable) return "blocked: pubkey is banned";
        const approved = has(&txn, self.allowed_events, event.id()) catch return unreadable;
        if (!approved) {
            const allowlist = hasAny(&txn, self.allowed_pubkeys) catch return unreadable;
            if (allowlist and !(has(&txn, self.allowed_pubkeys, event.pubkey()) catch return unreadable)) return "blocked: pubkey not in allowlist";
            if (has(&txn, self.disallowed_kinds, kind) catch return unreadable) return "blocked: event kind not allowed";
            const kind_allowlist = hasAny(&txn, self.allowed_kinds) catch return unreadable;
            if (kind_allowlist and !(has(&txn, self.allowed_kinds, kind) catch return unreadable)) return "blocked: event kind not allowed";
        }
        if (has(&txn, self.banned_events, event.id()) catch return unreadable) return "blocked: event is banned";
        return null;
    }

    fn has(txn: *Txn, dbi: Dbi, key: []const u8) !bool {
        return (try txn.get(dbi, key)) != null;
    }

    fn hasAny(txn: *Txn, dbi: Dbi) !bool {
        var cursor = try txn.cursor(dbi);
        defer cursor.close();
        return (try cursor.get(.first)) != null;
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

    /// `ip` is an address, a CIDR range, or a legacy prefix ("10.0.0." or the
    /// older dotless "10.0.0"); see ip_match.zig. The key is stored as given so
    /// unblockip with the same text removes it.
    pub fn blockIp(self: *ManagementStore, ip: []const u8, reason: []const u8) !void {
        if (ip_match.parseRule(ip, .allow_dotless_prefix) == null) return error.InvalidIpRule;

        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        {
            var txn = try self.lmdb.beginTxn(false);
            errdefer txn.abort();
            try txn.put(self.blocked_ips, ip, reason);
            try txn.commit();
        }
        try self.reloadIpRules();
    }

    pub fn unblockIp(self: *ManagementStore, ip: []const u8) !void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        {
            var txn = try self.lmdb.beginTxn(false);
            errdefer txn.abort();
            txn.delete(self.blocked_ips, ip) catch {};
            try txn.commit();
        }
        try self.reloadIpRules();
    }

    pub fn isIpBlocked(self: *ManagementStore, ip: []const u8) bool {
        const addr = ip_match.parseAddr(ip) orelse return false;
        const io = nostr.io.io();
        self.ip_rules_mutex.lockUncancelable(io);
        defer self.ip_rules_mutex.unlock(io);
        return ip_match.anyMatch(self.ip_rules.items, addr);
    }

    /// Rebuild `ip_rules` from LMDB. Keys that do not parse (stored before
    /// blockip validated its input) are skipped with a warning.
    fn reloadIpRules(self: *ManagementStore) !void {
        var rules: std.ArrayListUnmanaged(ip_match.Rule) = .empty;
        errdefer rules.deinit(self.allocator);
        {
            var txn = try self.lmdb.beginTxn(true);
            defer txn.abort();
            var cursor = try txn.cursor(self.blocked_ips);
            defer cursor.close();

            var entry = try cursor.get(.first);
            while (entry) |e| : (entry = try cursor.get(.next)) {
                const rule = ip_match.parseRule(e.key, .allow_dotless_prefix) orelse {
                    var buf: [64]u8 = undefined;
                    log.warn("blocked IP entry \"{s}\" is not a valid address, CIDR range or prefix and is ignored; remove it with unblockip", .{ip_match.safeEntry(e.key, &buf)});
                    continue;
                };
                try rules.append(self.allocator, rule);
            }
        }

        const io = nostr.io.io();
        self.ip_rules_mutex.lockUncancelable(io);
        defer self.ip_rules_mutex.unlock(io);
        self.ip_rules.deinit(self.allocator);
        self.ip_rules = rules;
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

test "blocked IPs: CIDR, IPv6 subnets, legacy keys and malformed input" {
    const testing = std.testing;
    const io = nostr.io.io();
    const cwd = std.Io.Dir.cwd();
    const db_path = "./test_mgmt_blocked_ips_db";
    defer {
        cwd.deleteFile(io, db_path) catch {};
        cwd.deleteFile(io, db_path ++ "-lock") catch {};
    }

    var lmdb = try Lmdb.init(testing.allocator, db_path, 10, .none);
    defer lmdb.deinit();

    // Keys written before CIDR support: the dotless prefix form blockip used to
    // match on, and junk that was stored unvalidated.
    {
        var setup = try ManagementStore.init(testing.allocator, &lmdb);
        defer setup.deinit();
        var txn = try lmdb.beginTxn(false);
        errdefer txn.abort();
        try txn.put(setup.blocked_ips, "45.9.148", "legacy dotless");
        try txn.put(setup.blocked_ips, "not-an-ip", "junk");
        try txn.commit();
    }

    var mgmt = try ManagementStore.init(testing.allocator, &lmdb);
    defer mgmt.deinit();

    // Legacy dotless key is a /24; junk is skipped rather than failing init.
    try testing.expectEqual(@as(usize, 1), mgmt.ip_rules.items.len);
    try testing.expect(mgmt.isIpBlocked("45.9.148.7"));
    try testing.expect(!mgmt.isIpBlocked("45.9.149.7"));

    try mgmt.blockIp("185.220.100.0/22", "tor exits");
    try mgmt.blockIp("2001:db8::/32", "");
    try mgmt.blockIp("10.0.0.", "legacy trailing dot");
    try mgmt.blockIp("1.2.3.4", "");

    try testing.expect(mgmt.isIpBlocked("185.220.103.255"));
    try testing.expect(!mgmt.isIpBlocked("185.220.104.0"));
    try testing.expect(mgmt.isIpBlocked("::ffff:185.220.101.1"));
    try testing.expect(mgmt.isIpBlocked("2001:db8:abcd::1"));
    try testing.expect(!mgmt.isIpBlocked("2001:db9::1"));
    try testing.expect(mgmt.isIpBlocked("10.0.0.200"));
    try testing.expect(mgmt.isIpBlocked("1.2.3.4"));
    try testing.expect(!mgmt.isIpBlocked("1.2.3.40"));
    try testing.expect(!mgmt.isIpBlocked("unknown"));

    try testing.expectError(error.InvalidIpRule, mgmt.blockIp("10.0.0.0/33", ""));
    try testing.expectError(error.InvalidIpRule, mgmt.blockIp("192.168.*", ""));
    try testing.expectError(error.InvalidIpRule, mgmt.blockIp("", ""));

    // Re-blocking an entry does not duplicate its rule; unblocking removes it.
    try mgmt.blockIp("1.2.3.4", "again");
    try testing.expectEqual(@as(usize, 5), mgmt.ip_rules.items.len);
    try mgmt.unblockIp("185.220.100.0/22");
    try testing.expect(!mgmt.isIpBlocked("185.220.101.1"));
    // Junk keys can still be removed.
    try mgmt.unblockIp("not-an-ip");
    const entries = try mgmt.listBlockedIps(testing.allocator);
    defer ManagementStore.freeIpEntries(entries, testing.allocator);
    try testing.expectEqual(@as(usize, 4), entries.len);

    // Rules are rebuilt from LMDB on startup.
    var reopened = try ManagementStore.init(testing.allocator, &lmdb);
    defer reopened.deinit();
    try testing.expect(reopened.isIpBlocked("2001:db8::5"));
    try testing.expect(!reopened.isIpBlocked("185.220.101.1"));
}
