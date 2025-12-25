const std = @import("std");
const Config = @import("config.zig").Config;
const ManagementStore = @import("management_store.zig").ManagementStore;
const nostr = @import("nostr.zig");
const nip86 = nostr.nip86;
const hex = nostr.hex;

pub const Nip86Handler = struct {
    config: *const Config,
    mgmt_store: *ManagementStore,
    allocator: std.mem.Allocator,

    relay_name: ?[]const u8 = null,
    relay_description: ?[]const u8 = null,
    relay_icon: ?[]const u8 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const Config,
        mgmt_store: *ManagementStore,
    ) Nip86Handler {
        return .{
            .allocator = allocator,
            .config = config,
            .mgmt_store = mgmt_store,
        };
    }

    pub fn deinit(self: *Nip86Handler) void {
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
        self.deinit();
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
                \\{"result":["supportedmethods","banpubkey","listbannedpubkeys","allowpubkey","listallowedpubkeys","listeventsneedingmoderation","allowevent","banevent","listbannedevents","changerelayname","changerelaydescription","changerelayicon","allowkind","disallowkind","listallowedkinds","blockip","unblockip","listblockedips"]}
            ),
            .banpubkey => self.banPubkey(params),
            .listbannedpubkeys => self.listBannedPubkeys(),
            .allowpubkey => self.allowPubkey(params),
            .listallowedpubkeys => self.listAllowedPubkeys(),
            .banevent => self.banEvent(params),
            .allowevent => self.allowEvent(params),
            .listbannedevents => self.listBannedEvents(),
            .listeventsneedingmoderation => nip86.Response.ok("{\"result\":[]}"),
            .changerelayname => self.changeRelayName(params),
            .changerelaydescription => self.changeRelayDescription(params),
            .changerelayicon => self.changeRelayIcon(params),
            .allowkind => self.allowKind(params),
            .disallowkind => self.disallowKind(params),
            .listallowedkinds => self.listAllowedKinds(),
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
        self.mgmt_store.unbanEvent(&event_id) catch return nip86.Response.internalError();
        return nip86.Response.ok("{\"result\":true}");
    }

    fn listBannedEvents(self: *Nip86Handler) nip86.Response {
        const entries = self.mgmt_store.listBannedEvents(self.allocator) catch return nip86.Response.internalError();
        defer ManagementStore.freeEventEntries(entries, self.allocator);

        var buf: std.ArrayListUnmanaged(u8) = .{};
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

    fn listAllowedKinds(self: *Nip86Handler) nip86.Response {
        const kinds = self.mgmt_store.listAllowedKinds(self.allocator) catch return nip86.Response.internalError();
        defer self.allocator.free(kinds);

        var buf: std.ArrayListUnmanaged(u8) = .{};
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

        var buf: std.ArrayListUnmanaged(u8) = .{};
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
        var buf: std.ArrayListUnmanaged(u8) = .{};
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
        if (self.config.admin_pubkeys.len == 0) return false;

        var hex_buf: [64]u8 = undefined;
        hex.encode(pubkey, &hex_buf);

        var iter = std.mem.splitScalar(u8, self.config.admin_pubkeys, ',');
        while (iter.next()) |admin| {
            const trimmed = std.mem.trim(u8, admin, " \t");
            if (trimmed.len == 64 and std.mem.eql(u8, trimmed, &hex_buf)) {
                return true;
            }
        }
        return false;
    }
};
