const std = @import("std");
const Config = @import("config.zig").Config;
const ManagementStore = @import("management_store.zig").ManagementStore;
const nostr = @import("nostr.zig");
const nip86 = nostr.nip86;
const hex = nostr.hex;
const log = std.log.scoped(.nip86);

pub const Nip86Handler = struct {
    config: *const Config,
    mgmt_store: *ManagementStore,
    allocator: std.mem.Allocator,

    relay_name: ?[]const u8 = null,
    relay_description: ?[]const u8 = null,
    relay_icon: ?[]const u8 = null,
    // admin_pubkeys decoded once; entries that are neither 64-char hex (any
    // case) nor an npub are logged and left out.
    admins: std.ArrayListUnmanaged([32]u8) = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const Config,
        mgmt_store: *ManagementStore,
    ) Nip86Handler {
        var handler: Nip86Handler = .{
            .allocator = allocator,
            .config = config,
            .mgmt_store = mgmt_store,
        };
        var iter = std.mem.splitScalar(u8, config.admin_pubkeys, ',');
        while (iter.next()) |entry| {
            const trimmed = std.mem.trim(u8, entry, " \t");
            if (trimmed.len == 0) continue;
            const key = parseAdminKey(trimmed) orelse {
                log.warn("admin_pubkeys entry \"{s}\" is not a 64-character hex key or an npub; it grants no access", .{trimmed});
                continue;
            };
            handler.admins.append(allocator, key) catch log.err("out of memory loading admin_pubkeys", .{});
        }
        return handler;
    }

    fn parseAdminKey(entry: []const u8) ?[32]u8 {
        if (entry.len == 64) {
            var key: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&key, entry) catch return null;
            return key;
        }
        if (entry.len != 63 or !std.mem.startsWith(u8, entry, "npub1")) return null;
        var hrp: [8]u8 = undefined;
        var data: [40]u8 = undefined;
        const decoded = nostr.bech32.decode(entry, &hrp, &data) catch return null;
        if (!std.mem.eql(u8, hrp[0..decoded.hrp_len], "npub") or decoded.data_len != 32) return null;
        return data[0..32].*;
    }

    pub fn deinit(self: *Nip86Handler) void {
        self.freeRelaySettings();
        self.admins.deinit(self.allocator);
    }

    fn freeRelaySettings(self: *Nip86Handler) void {
        if (self.relay_name) |name| {
            self.allocator.free(name);
            self.relay_name = null;
        }
        if (self.relay_description) |desc| {
            self.allocator.free(desc);
            self.relay_description = null;
        }
        if (self.relay_icon) |icon| {
            self.allocator.free(icon);
            self.relay_icon = null;
        }
    }

    pub fn loadRelaySettings(self: *Nip86Handler) void {
        self.freeRelaySettings();
        self.relay_name = self.mgmt_store.getRelaySetting("name", self.allocator) catch null;
        self.relay_description = self.mgmt_store.getRelaySetting("description", self.allocator) catch null;
        self.relay_icon = self.mgmt_store.getRelaySetting("icon", self.allocator) catch null;
    }

    pub fn getRelayName(self: *const Nip86Handler) []const u8 {
        return self.relay_name orelse self.config.name;
    }

    pub fn getRelayDescription(self: *const Nip86Handler) []const u8 {
        return self.relay_description orelse self.config.description;
    }

    pub fn getRelayIcon(self: *const Nip86Handler) ?[]const u8 {
        return self.relay_icon;
    }

    pub fn handle(self: *Nip86Handler, body: []const u8, auth_header: ?[]const u8, request_url: []const u8) nip86.Response {
        const auth_result = nip86.validateNip98Auth(auth_header, body, request_url);
        if (auth_result.err) |err| {
            return nip86.Response.unauthorized(err);
        }
        const admin_pubkey = auth_result.pubkey orelse {
            return nip86.Response.unauthorized("{\"error\":\"authorization required\"}");
        };

        if (!self.isAdmin(&admin_pubkey)) {
            return nip86.Response.forbidden("{\"error\":\"forbidden: not an admin\"}");
        }

        const request = nip86.Request.parse(body) orelse {
            return nip86.Response.badRequest("{\"error\":\"invalid request\"}");
        };

        return self.dispatch(request.method, request.params);
    }

    fn dispatch(self: *Nip86Handler, method: []const u8, params: []const u8) nip86.Response {
        const m = nip86.Method.fromString(method) orelse {
            return nip86.Response.badRequest("{\"error\":\"unknown method\"}");
        };

        return switch (m) {
            .supportedmethods => nip86.Response.ok(
                \\{"result":["supportedmethods","banpubkey","unbanpubkey","listbannedpubkeys","allowpubkey","unallowpubkey","listallowedpubkeys","listeventsneedingmoderation","allowevent","unallowevent","listallowedevents","banevent","unbanevent","listbannedevents","changerelayname","changerelaydescription","changerelayicon","allowkind","disallowkind","listallowedkinds","listdisallowedkinds","blockip","unblockip","listblockedips"]}
            ),
            .banpubkey => self.banPubkey(params),
            .unbanpubkey => self.unbanPubkey(params),
            .listbannedpubkeys => self.listBannedPubkeys(),
            .allowpubkey => self.allowPubkey(params),
            .unallowpubkey => self.unallowPubkey(params),
            .listallowedpubkeys => self.listAllowedPubkeys(),
            .banevent => self.banEvent(params),
            .unbanevent => self.unbanEvent(params),
            .allowevent => self.allowEvent(params),
            .unallowevent => self.unallowEvent(params),
            .listbannedevents => self.listEvents(.banned),
            .listallowedevents => self.listEvents(.allowed),
            .listeventsneedingmoderation => nip86.Response.ok("{\"result\":[]}"),
            .changerelayname => self.changeRelayName(params),
            .changerelaydescription => self.changeRelayDescription(params),
            .changerelayicon => self.changeRelayIcon(params),
            .allowkind => self.allowKind(params),
            .disallowkind => self.disallowKind(params),
            .listallowedkinds => self.listKinds(.allowed),
            .listdisallowedkinds => self.listKinds(.disallowed),
            .blockip => self.blockIp(params),
            .unblockip => self.unblockIp(params),
            .listblockedips => self.listBlockedIps(),
        };
    }

    fn banPubkey(self: *Nip86Handler, params: []const u8) nip86.Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, self.allocator);
        defer parsed.deinit();
        var pubkey: [32]u8 = undefined;
        if (!parsed.parsePubkey(&pubkey)) {
            return nip86.Response.badRequest("{\"error\":\"missing or invalid pubkey parameter\"}");
        }
        self.mgmt_store.banPubkey(&pubkey, parsed.values[1] orelse "") catch {
            return nip86.Response.internalError();
        };
        return nip86.Response.ok("{\"result\":true}");
    }

    fn listBannedPubkeys(self: *Nip86Handler) nip86.Response {
        const entries = self.mgmt_store.listBannedPubkeys(self.allocator) catch return nip86.Response.internalError();
        defer ManagementStore.freePubkeyEntries(entries, self.allocator);
        return self.formatPubkeyList(entries);
    }

    fn allowPubkey(self: *Nip86Handler, params: []const u8) nip86.Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, self.allocator);
        defer parsed.deinit();
        var pubkey: [32]u8 = undefined;
        if (!parsed.parsePubkey(&pubkey)) {
            return nip86.Response.badRequest("{\"error\":\"missing or invalid pubkey parameter\"}");
        }
        self.mgmt_store.allowPubkey(&pubkey, parsed.values[1] orelse "") catch {
            return nip86.Response.internalError();
        };
        return nip86.Response.ok("{\"result\":true}");
    }

    fn listAllowedPubkeys(self: *Nip86Handler) nip86.Response {
        const entries = self.mgmt_store.listAllowedPubkeys(self.allocator) catch return nip86.Response.internalError();
        defer ManagementStore.freePubkeyEntries(entries, self.allocator);
        return self.formatPubkeyList(entries);
    }

    fn banEvent(self: *Nip86Handler, params: []const u8) nip86.Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, self.allocator);
        defer parsed.deinit();
        var event_id: [32]u8 = undefined;
        if (!parsed.parseEventId(&event_id)) {
            return nip86.Response.badRequest("{\"error\":\"missing or invalid event_id parameter\"}");
        }
        self.mgmt_store.banEvent(&event_id, parsed.values[1] orelse "") catch {
            return nip86.Response.internalError();
        };
        return nip86.Response.ok("{\"result\":true}");
    }

    fn allowEvent(self: *Nip86Handler, params: []const u8) nip86.Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, self.allocator);
        defer parsed.deinit();
        var event_id: [32]u8 = undefined;
        if (!parsed.parseEventId(&event_id)) {
            return nip86.Response.badRequest("{\"error\":\"missing or invalid event_id parameter\"}");
        }
        self.mgmt_store.allowEvent(&event_id, parsed.values[1] orelse "") catch return nip86.Response.internalError();
        return nip86.Response.ok("{\"result\":true}");
    }

    fn unbanEvent(self: *Nip86Handler, params: []const u8) nip86.Response {
        const event_id = parseEventIdParam(params, self.allocator) orelse return badEventId();
        self.mgmt_store.unbanEvent(&event_id) catch return nip86.Response.internalError();
        return nip86.Response.ok("{\"result\":true}");
    }

    fn unallowEvent(self: *Nip86Handler, params: []const u8) nip86.Response {
        const event_id = parseEventIdParam(params, self.allocator) orelse return badEventId();
        self.mgmt_store.disallowEvent(&event_id) catch return nip86.Response.internalError();
        return nip86.Response.ok("{\"result\":true}");
    }

    fn unbanPubkey(self: *Nip86Handler, params: []const u8) nip86.Response {
        const pubkey = parsePubkeyParam(params, self.allocator) orelse return badPubkey();
        self.mgmt_store.unbanPubkey(&pubkey) catch return nip86.Response.internalError();
        return nip86.Response.ok("{\"result\":true}");
    }

    fn unallowPubkey(self: *Nip86Handler, params: []const u8) nip86.Response {
        const pubkey = parsePubkeyParam(params, self.allocator) orelse return badPubkey();
        self.mgmt_store.disallowPubkey(&pubkey) catch return nip86.Response.internalError();
        return nip86.Response.ok("{\"result\":true}");
    }

    fn parsePubkeyParam(params: []const u8, allocator: std.mem.Allocator) ?[32]u8 {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, allocator);
        defer parsed.deinit();
        var pubkey: [32]u8 = undefined;
        return if (parsed.parsePubkey(&pubkey)) pubkey else null;
    }

    fn parseEventIdParam(params: []const u8, allocator: std.mem.Allocator) ?[32]u8 {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, allocator);
        defer parsed.deinit();
        var event_id: [32]u8 = undefined;
        return if (parsed.parseEventId(&event_id)) event_id else null;
    }

    fn badPubkey() nip86.Response {
        return nip86.Response.badRequest("{\"error\":\"missing or invalid pubkey parameter\"}");
    }

    fn badEventId() nip86.Response {
        return nip86.Response.badRequest("{\"error\":\"missing or invalid event_id parameter\"}");
    }

    const List = enum { banned, allowed };

    fn listEvents(self: *Nip86Handler, which: List) nip86.Response {
        const entries = switch (which) {
            .banned => self.mgmt_store.listBannedEvents(self.allocator),
            .allowed => self.mgmt_store.listAllowedEvents(self.allocator),
        } catch return nip86.Response.internalError();
        defer ManagementStore.freeEventEntries(entries, self.allocator);

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(self.allocator);

        buf.appendSlice(self.allocator, "{\"result\":[") catch return nip86.Response.internalError();
        for (entries, 0..) |entry, i| {
            if (i > 0) buf.append(self.allocator, ',') catch return nip86.Response.internalError();
            buf.appendSlice(self.allocator, "{\"id\":\"") catch return nip86.Response.internalError();
            var hex_buf: [64]u8 = undefined;
            hex.encode(&entry.id, &hex_buf);
            buf.appendSlice(self.allocator, &hex_buf) catch return nip86.Response.internalError();
            buf.appendSlice(self.allocator, "\",\"reason\":") catch return nip86.Response.internalError();
            nip86.writeJsonString(&buf, self.allocator, entry.reason) catch return nip86.Response.internalError();
            buf.append(self.allocator, '}') catch return nip86.Response.internalError();
        }
        buf.appendSlice(self.allocator, "]}") catch return nip86.Response.internalError();

        const result = self.allocator.dupe(u8, buf.items) catch return nip86.Response.internalError();
        return nip86.Response.ownedOk(result);
    }

    fn changeRelayName(self: *Nip86Handler, params: []const u8) nip86.Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 1, self.allocator);
        defer parsed.deinit();
        const name = parsed.values[0] orelse return nip86.Response.badRequest("{\"error\":\"missing name parameter\"}");
        self.mgmt_store.setRelaySetting("name", name) catch return nip86.Response.internalError();
        if (self.relay_name) |old| self.allocator.free(old);
        self.relay_name = self.allocator.dupe(u8, name) catch null;
        return nip86.Response.ok("{\"result\":true}");
    }

    fn changeRelayDescription(self: *Nip86Handler, params: []const u8) nip86.Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 1, self.allocator);
        defer parsed.deinit();
        const desc = parsed.values[0] orelse return nip86.Response.badRequest("{\"error\":\"missing description parameter\"}");
        self.mgmt_store.setRelaySetting("description", desc) catch return nip86.Response.internalError();
        if (self.relay_description) |old| self.allocator.free(old);
        self.relay_description = self.allocator.dupe(u8, desc) catch null;
        return nip86.Response.ok("{\"result\":true}");
    }

    fn changeRelayIcon(self: *Nip86Handler, params: []const u8) nip86.Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 1, self.allocator);
        defer parsed.deinit();
        const icon = parsed.values[0] orelse return nip86.Response.badRequest("{\"error\":\"missing icon url parameter\"}");
        self.mgmt_store.setRelaySetting("icon", icon) catch return nip86.Response.internalError();
        if (self.relay_icon) |old| self.allocator.free(old);
        self.relay_icon = self.allocator.dupe(u8, icon) catch null;
        return nip86.Response.ok("{\"result\":true}");
    }

    fn allowKind(self: *Nip86Handler, params: []const u8) nip86.Response {
        const kind = nip86.ParsedParams.parseKind(params) orelse {
            return nip86.Response.badRequest("{\"error\":\"invalid kind parameter\"}");
        };
        self.mgmt_store.allowKind(kind) catch return nip86.Response.internalError();
        return nip86.Response.ok("{\"result\":true}");
    }

    fn disallowKind(self: *Nip86Handler, params: []const u8) nip86.Response {
        const kind = nip86.ParsedParams.parseKind(params) orelse {
            return nip86.Response.badRequest("{\"error\":\"invalid kind parameter\"}");
        };
        self.mgmt_store.disallowKind(kind) catch return nip86.Response.internalError();
        return nip86.Response.ok("{\"result\":true}");
    }

    fn listKinds(self: *Nip86Handler, which: enum { allowed, disallowed }) nip86.Response {
        const kinds = switch (which) {
            .allowed => self.mgmt_store.listAllowedKinds(self.allocator),
            .disallowed => self.mgmt_store.listDisallowedKinds(self.allocator),
        } catch return nip86.Response.internalError();
        defer self.allocator.free(kinds);

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(self.allocator);

        buf.appendSlice(self.allocator, "{\"result\":[") catch return nip86.Response.internalError();
        for (kinds, 0..) |kind, i| {
            if (i > 0) buf.append(self.allocator, ',') catch return nip86.Response.internalError();
            var num_buf: [16]u8 = undefined;
            const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{kind}) catch return nip86.Response.internalError();
            buf.appendSlice(self.allocator, num_str) catch return nip86.Response.internalError();
        }
        buf.appendSlice(self.allocator, "]}") catch return nip86.Response.internalError();

        const result = self.allocator.dupe(u8, buf.items) catch return nip86.Response.internalError();
        return nip86.Response.ownedOk(result);
    }

    fn blockIp(self: *Nip86Handler, params: []const u8) nip86.Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, self.allocator);
        defer parsed.deinit();
        const ip = parsed.values[0] orelse return nip86.Response.badRequest("{\"error\":\"missing ip parameter\"}");
        self.mgmt_store.blockIp(ip, parsed.values[1] orelse "") catch return nip86.Response.internalError();
        return nip86.Response.ok("{\"result\":true}");
    }

    fn unblockIp(self: *Nip86Handler, params: []const u8) nip86.Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 1, self.allocator);
        defer parsed.deinit();
        const ip = parsed.values[0] orelse return nip86.Response.badRequest("{\"error\":\"missing ip parameter\"}");
        self.mgmt_store.unblockIp(ip) catch return nip86.Response.internalError();
        return nip86.Response.ok("{\"result\":true}");
    }

    fn listBlockedIps(self: *Nip86Handler) nip86.Response {
        const entries = self.mgmt_store.listBlockedIps(self.allocator) catch return nip86.Response.internalError();
        defer ManagementStore.freeIpEntries(entries, self.allocator);

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(self.allocator);

        buf.appendSlice(self.allocator, "{\"result\":[") catch return nip86.Response.internalError();
        for (entries, 0..) |entry, i| {
            if (i > 0) buf.append(self.allocator, ',') catch return nip86.Response.internalError();
            buf.appendSlice(self.allocator, "{\"ip\":") catch return nip86.Response.internalError();
            nip86.writeJsonString(&buf, self.allocator, entry.ip) catch return nip86.Response.internalError();
            buf.appendSlice(self.allocator, ",\"reason\":") catch return nip86.Response.internalError();
            nip86.writeJsonString(&buf, self.allocator, entry.reason) catch return nip86.Response.internalError();
            buf.append(self.allocator, '}') catch return nip86.Response.internalError();
        }
        buf.appendSlice(self.allocator, "]}") catch return nip86.Response.internalError();

        const result = self.allocator.dupe(u8, buf.items) catch return nip86.Response.internalError();
        return nip86.Response.ownedOk(result);
    }

    fn formatPubkeyList(self: *Nip86Handler, entries: []const ManagementStore.PubkeyEntry) nip86.Response {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(self.allocator);

        buf.appendSlice(self.allocator, "{\"result\":[") catch return nip86.Response.internalError();
        for (entries, 0..) |entry, i| {
            if (i > 0) buf.append(self.allocator, ',') catch return nip86.Response.internalError();
            buf.appendSlice(self.allocator, "{\"pubkey\":\"") catch return nip86.Response.internalError();
            var hex_buf: [64]u8 = undefined;
            hex.encode(&entry.pubkey, &hex_buf);
            buf.appendSlice(self.allocator, &hex_buf) catch return nip86.Response.internalError();
            buf.appendSlice(self.allocator, "\",\"reason\":") catch return nip86.Response.internalError();
            nip86.writeJsonString(&buf, self.allocator, entry.reason) catch return nip86.Response.internalError();
            buf.append(self.allocator, '}') catch return nip86.Response.internalError();
        }
        buf.appendSlice(self.allocator, "]}") catch return nip86.Response.internalError();

        const result = self.allocator.dupe(u8, buf.items) catch return nip86.Response.internalError();
        return nip86.Response.ownedOk(result);
    }

    fn isAdmin(self: *Nip86Handler, pubkey: *const [32]u8) bool {
        for (self.admins.items) |admin| if (std.mem.eql(u8, &admin, pubkey)) return true;
        return false;
    }
};

const testing = std.testing;

test "isAdmin matches the configured pubkey list" {
    var config = Config.defaults();
    config.admin_pubkeys = "00000000000000000000000000000000000000000000000000000000000000aa, 00000000000000000000000000000000000000000000000000000000000000BB, npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqrwse98m4x, not-a-key, npub1bad";

    var mgmt: ManagementStore = undefined;
    var handler = Nip86Handler.init(testing.allocator, &config, &mgmt);
    defer handler.deinit();

    // Lowercase hex, uppercase hex and npub entries all grant access.
    for ([_][]const u8{ "aa", "bb", "dd" }) |last| {
        var admin: [32]u8 = @splat(0);
        _ = try std.fmt.hexToBytes(admin[31..], last);
        try testing.expect(handler.isAdmin(&admin));
    }
    try testing.expectEqual(@as(usize, 3), handler.admins.items.len);

    var stranger: [32]u8 = @splat(0);
    stranger[31] = 0xcc;
    try testing.expect(!handler.isAdmin(&stranger));

    // An empty admin list denies everyone.
    config.admin_pubkeys = "";
    var empty = Nip86Handler.init(testing.allocator, &config, &mgmt);
    defer empty.deinit();
    var admin: [32]u8 = @splat(0);
    admin[31] = 0xaa;
    try testing.expect(!empty.isAdmin(&admin));
}

test "nip86 dispatch routing, param guards, and store round-trip" {
    const Lmdb = @import("lmdb.zig").Lmdb;
    const io = nostr.io.io();
    const cwd = std.Io.Dir.cwd();
    const db_path = "./test_nip86_db";
    defer {
        cwd.deleteFile(io, db_path) catch {};
        cwd.deleteFile(io, db_path ++ "-lock") catch {};
    }

    var lmdb = try Lmdb.init(testing.allocator, db_path, 10, .none);
    defer lmdb.deinit();
    var mgmt = try ManagementStore.init(testing.allocator, &lmdb);

    var config = Config.defaults();
    var handler = Nip86Handler.init(testing.allocator, &config, &mgmt);
    defer handler.deinit();

    // handle() gates every request behind NIP-98 auth before dispatch. A
    // missing header and an invalid scheme are both rejected with 401, so the
    // store is never reached without authentication.
    const ban_req = "{\"method\":\"banpubkey\",\"params\":[\"00000000000000000000000000000000000000000000000000000000000000bb\"]}";
    try testing.expectEqual(@as(u16, 401), handler.handle(ban_req, null, "https://relay/").status);
    try testing.expectEqual(@as(u16, 401), handler.handle(ban_req, "Bearer xyz", "https://relay/").status);

    // The static method list responds 200.
    try testing.expectEqual(@as(u16, 200), handler.dispatch("supportedmethods", "[]").status);

    // An unknown method is rejected.
    try testing.expectEqual(@as(u16, 400), handler.dispatch("bogus", "[]").status);

    // A malformed pubkey is rejected before the store is touched.
    try testing.expectEqual(@as(u16, 400), handler.dispatch("banpubkey", "[\"notahexpubkey\"]").status);

    // A valid pubkey bans successfully and the store reflects it.
    const pk_hex = "00000000000000000000000000000000000000000000000000000000000000bb";
    const r = handler.dispatch("banpubkey", "[\"" ++ pk_hex ++ "\"]");
    defer if (r.owned) testing.allocator.free(r.body);
    try testing.expectEqual(@as(u16, 200), r.status);

    var pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk, pk_hex);
    try testing.expect(mgmt.isPubkeyBanned(&pk));
}

test "nip86 ban and allow lists are exclusive and disallowkind is a deny list" {
    const Lmdb = @import("lmdb.zig").Lmdb;
    const io = nostr.io.io();
    const cwd = std.Io.Dir.cwd();
    const db_path = "./test_nip86_lists_db";
    defer {
        cwd.deleteFile(io, db_path) catch {};
        cwd.deleteFile(io, db_path ++ "-lock") catch {};
    }

    var lmdb = try Lmdb.init(testing.allocator, db_path, 10, .none);
    defer lmdb.deinit();
    var mgmt = try ManagementStore.init(testing.allocator, &lmdb);

    var config = Config.defaults();
    var handler = Nip86Handler.init(testing.allocator, &config, &mgmt);
    defer handler.deinit();

    const pk_hex = "00000000000000000000000000000000000000000000000000000000000000bb";
    var pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk, pk_hex);
    const id_hex = "00000000000000000000000000000000000000000000000000000000000000ee";
    var id: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&id, id_hex);

    try testing.expectEqual(@as(u16, 200), handler.dispatch("banpubkey", "[\"" ++ pk_hex ++ "\"]").status);
    try testing.expectEqual(@as(u16, 200), handler.dispatch("allowpubkey", "[\"" ++ pk_hex ++ "\"]").status);
    try testing.expect(!mgmt.isPubkeyBanned(&pk));
    try testing.expect(mgmt.isPubkeyAllowed(&pk));
    try testing.expectEqual(@as(u16, 200), handler.dispatch("unallowpubkey", "[\"" ++ pk_hex ++ "\"]").status);
    try testing.expect(!mgmt.hasAllowedPubkeys());
    try testing.expectEqual(@as(u16, 200), handler.dispatch("banpubkey", "[\"" ++ pk_hex ++ "\"]").status);
    try testing.expectEqual(@as(u16, 200), handler.dispatch("unbanpubkey", "[\"" ++ pk_hex ++ "\"]").status);
    try testing.expect(!mgmt.isPubkeyBanned(&pk));

    try testing.expectEqual(@as(u16, 200), handler.dispatch("banevent", "[\"" ++ id_hex ++ "\"]").status);
    try testing.expectEqual(@as(u16, 200), handler.dispatch("allowevent", "[\"" ++ id_hex ++ "\"]").status);
    try testing.expect(!mgmt.isEventBanned(&id));
    try testing.expect(mgmt.isEventAllowed(&id));
    try testing.expectEqual(@as(u16, 200), handler.dispatch("unallowevent", "[\"" ++ id_hex ++ "\"]").status);
    try testing.expect(!mgmt.isEventAllowed(&id));
    try testing.expectEqual(@as(u16, 400), handler.dispatch("unbanevent", "[\"nothex\"]").status);

    try testing.expect(mgmt.isKindAllowed(7));
    try testing.expectEqual(@as(u16, 200), handler.dispatch("disallowkind", "[7]").status);
    try testing.expect(!mgmt.isKindAllowed(7));
    try testing.expect(mgmt.isKindAllowed(1));
    const denied = handler.dispatch("listdisallowedkinds", "[]");
    defer if (denied.owned) testing.allocator.free(denied.body);
    try testing.expectEqualStrings("{\"result\":[7]}", denied.body);
    try testing.expectEqual(@as(u16, 200), handler.dispatch("allowkind", "[7]").status);
    try testing.expect(mgmt.isKindAllowed(7));
    try testing.expect(!mgmt.isKindAllowed(1));

    // Denying the only allowlisted kind must not open the relay to every kind.
    try testing.expectEqual(@as(u16, 200), handler.dispatch("disallowkind", "[7]").status);
    try testing.expect(!mgmt.isKindAllowed(7));
    try testing.expect(!mgmt.isKindAllowed(1));

    // rejection() is the one policy check shared by published and synced events.
    // A kind on the allowlist is admitted, which pins the kind key encoding.
    var kind7 = try nostr.Event.parseWithAllocator(
        \\{"id":"00000000000000000000000000000000000000000000000000000000000000e7","pubkey":"00000000000000000000000000000000000000000000000000000000000000bb","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","kind":7,"created_at":1700000000,"content":"","tags":[]}
    , testing.allocator);
    defer kind7.deinit();
    try testing.expectEqualStrings("blocked: event kind not allowed", mgmt.rejection(&kind7).?);
    try testing.expectEqual(@as(u16, 200), handler.dispatch("allowkind", "[7]").status);
    try testing.expectEqual(@as(?[]const u8, null), mgmt.rejection(&kind7));
    try testing.expectEqual(@as(u16, 200), handler.dispatch("allowpubkey", "[\"00000000000000000000000000000000000000000000000000000000000000cc\"]").status);
    try testing.expectEqualStrings("blocked: pubkey not in allowlist", mgmt.rejection(&kind7).?);
    try testing.expectEqual(@as(u16, 200), handler.dispatch("unallowpubkey", "[\"00000000000000000000000000000000000000000000000000000000000000cc\"]").status);

    var event = try nostr.Event.parseWithAllocator(
        \\{"id":"00000000000000000000000000000000000000000000000000000000000000ee","pubkey":"00000000000000000000000000000000000000000000000000000000000000bb","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","kind":1,"created_at":1700000000,"content":"","tags":[]}
    , testing.allocator);
    defer event.deinit();
    try testing.expectEqualStrings("blocked: event kind not allowed", mgmt.rejection(&event).?);
    try testing.expectEqual(@as(u16, 200), handler.dispatch("allowevent", "[\"" ++ id_hex ++ "\"]").status);
    try testing.expectEqual(@as(?[]const u8, null), mgmt.rejection(&event));
    try testing.expectEqual(@as(u16, 200), handler.dispatch("banpubkey", "[\"" ++ pk_hex ++ "\"]").status);
    try testing.expectEqualStrings("blocked: pubkey is banned", mgmt.rejection(&event).?);
    try testing.expectEqual(@as(u16, 200), handler.dispatch("unbanpubkey", "[\"" ++ pk_hex ++ "\"]").status);

    // An event ban applies even where kinds and pubkeys would admit the event.
    try testing.expectEqual(@as(u16, 200), handler.dispatch("allowkind", "[1]").status);
    try testing.expectEqual(@as(?[]const u8, null), mgmt.rejection(&event));
    try testing.expectEqual(@as(u16, 200), handler.dispatch("banevent", "[\"" ++ id_hex ++ "\"]").status);
    try testing.expectEqualStrings("blocked: event is banned", mgmt.rejection(&event).?);
}

test "rejection refuses an event when the policy cannot be read" {
    const Lmdb = @import("lmdb.zig").Lmdb;
    const Store = @import("store.zig").Store;
    const io = nostr.io.io();
    const cwd = std.Io.Dir.cwd();
    const db_path = "./test_nip86_policy_db";
    defer {
        cwd.deleteFile(io, db_path) catch {};
        cwd.deleteFile(io, db_path ++ "-lock") catch {};
    }

    var lmdb = try Lmdb.init(testing.allocator, db_path, 10, .none);
    defer lmdb.deinit();
    var store = try Store.init(testing.allocator, &lmdb);
    defer store.deinit();
    var mgmt = try ManagementStore.init(testing.allocator, &lmdb);

    var event = try nostr.Event.parseWithAllocator(
        \\{"id":"00000000000000000000000000000000000000000000000000000000000000ee","pubkey":"00000000000000000000000000000000000000000000000000000000000000bb","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","kind":1,"created_at":1700000000,"content":"","tags":[]}
    , testing.allocator);
    defer event.deinit();
    try testing.expectEqual(@as(?[]const u8, null), mgmt.rejection(&event));

    // LMDB allows one transaction per thread, so while a store read is open on
    // this thread the policy cannot be read and the event must be refused.
    const filters = [_]nostr.Filter{.{}};
    {
        var iter = try store.queryFull(&filters, 10);
        defer iter.deinit();
        _ = try iter.next();
        try testing.expectEqualStrings("error: relay policy unavailable", mgmt.rejection(&event).?);
    }
    try testing.expectEqual(@as(?[]const u8, null), mgmt.rejection(&event));
}
