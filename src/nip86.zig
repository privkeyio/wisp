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

    pub fn handle(
        self: *Nip86Handler,
        body: []const u8,
        auth_header: ?[]const u8,
        request_url: []const u8,
    ) Response {
        const auth_result = self.validateAuth(auth_header, body, request_url);
        if (auth_result.err) |err| {
            return Response{ .status = 401, .body = err };
        }
        const admin_pubkey = auth_result.pubkey orelse {
            return Response{ .status = 401, .body = "{\"error\":\"authorization required\"}" };
        };

        if (!self.isAdmin(&admin_pubkey)) {
            return Response{ .status = 403, .body = "{\"error\":\"forbidden: not an admin\"}" };
        }

        const request = nip86.Request.parse(body) orelse {
            return Response{ .status = 400, .body = "{\"error\":\"invalid request\"}" };
        };

        return self.dispatch(request.method, request.params);
    }

    fn dispatch(self: *Nip86Handler, method: []const u8, params: []const u8) Response {
        const m = nip86.Method.fromString(method) orelse {
            return Response{ .status = 400, .body = "{\"error\":\"unknown method\"}" };
        };

        return switch (m) {
            .supportedmethods => self.supportedMethods(),
            .banpubkey => self.banPubkey(params),
            .listbannedpubkeys => self.listBannedPubkeys(),
            .allowpubkey => self.allowPubkey(params),
            .listallowedpubkeys => self.listAllowedPubkeys(),
            .banevent => self.banEvent(params),
            .allowevent => self.allowEvent(params),
            .listbannedevents => self.listBannedEvents(),
            .listeventsneedingmoderation => self.listEventsNeedingModeration(),
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

    fn supportedMethods(self: *Nip86Handler) Response {
        _ = self;
        return Response{
            .status = 200,
            .body =
            \\{"result":["supportedmethods","banpubkey","listbannedpubkeys","allowpubkey","listallowedpubkeys","listeventsneedingmoderation","allowevent","banevent","listbannedevents","changerelayname","changerelaydescription","changerelayicon","allowkind","disallowkind","listallowedkinds","blockip","unblockip","listblockedips"]}
            ,
        };
    }

    fn banPubkey(self: *Nip86Handler, params: []const u8) Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, self.allocator);
        defer parsed.deinit();
        var pubkey: [32]u8 = undefined;
        if (!parsed.parsePubkey(&pubkey)) {
            return Response{ .status = 400, .body = "{\"error\":\"missing or invalid pubkey parameter\"}" };
        }
        const reason = parsed.values[1] orelse "";
        self.mgmt_store.banPubkey(&pubkey, reason) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn listBannedPubkeys(self: *Nip86Handler) Response {
        const entries = self.mgmt_store.listBannedPubkeys(self.allocator) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        defer ManagementStore.freePubkeyEntries(entries, self.allocator);

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(self.allocator);

        buf.appendSlice(self.allocator, "{\"result\":[") catch return errorResponse();
        for (entries, 0..) |entry, i| {
            if (i > 0) buf.append(self.allocator, ',') catch return errorResponse();
            buf.appendSlice(self.allocator, "{\"pubkey\":\"") catch return errorResponse();
            var hex_buf: [64]u8 = undefined;
            hex.encode(&entry.pubkey, &hex_buf);
            buf.appendSlice(self.allocator, &hex_buf) catch return errorResponse();
            buf.appendSlice(self.allocator, "\",\"reason\":") catch return errorResponse();
            nip86.writeJsonString(&buf, self.allocator, entry.reason) catch return errorResponse();
            buf.append(self.allocator, '}') catch return errorResponse();
        }
        buf.appendSlice(self.allocator, "]}") catch return errorResponse();

        const result = self.allocator.dupe(u8, buf.items) catch return errorResponse();
        return Response{ .status = 200, .body = result, .owned = true };
    }

    fn allowPubkey(self: *Nip86Handler, params: []const u8) Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, self.allocator);
        defer parsed.deinit();
        var pubkey: [32]u8 = undefined;
        if (!parsed.parsePubkey(&pubkey)) {
            return Response{ .status = 400, .body = "{\"error\":\"missing or invalid pubkey parameter\"}" };
        }
        const reason = parsed.values[1] orelse "";
        self.mgmt_store.allowPubkey(&pubkey, reason) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn listAllowedPubkeys(self: *Nip86Handler) Response {
        const entries = self.mgmt_store.listAllowedPubkeys(self.allocator) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        defer ManagementStore.freePubkeyEntries(entries, self.allocator);

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(self.allocator);

        buf.appendSlice(self.allocator, "{\"result\":[") catch return errorResponse();
        for (entries, 0..) |entry, i| {
            if (i > 0) buf.append(self.allocator, ',') catch return errorResponse();
            buf.appendSlice(self.allocator, "{\"pubkey\":\"") catch return errorResponse();
            var hex_buf: [64]u8 = undefined;
            hex.encode(&entry.pubkey, &hex_buf);
            buf.appendSlice(self.allocator, &hex_buf) catch return errorResponse();
            buf.appendSlice(self.allocator, "\",\"reason\":") catch return errorResponse();
            nip86.writeJsonString(&buf, self.allocator, entry.reason) catch return errorResponse();
            buf.append(self.allocator, '}') catch return errorResponse();
        }
        buf.appendSlice(self.allocator, "]}") catch return errorResponse();

        const result = self.allocator.dupe(u8, buf.items) catch return errorResponse();
        return Response{ .status = 200, .body = result, .owned = true };
    }

    fn banEvent(self: *Nip86Handler, params: []const u8) Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, self.allocator);
        defer parsed.deinit();
        var event_id: [32]u8 = undefined;
        if (!parsed.parseEventId(&event_id)) {
            return Response{ .status = 400, .body = "{\"error\":\"missing or invalid event_id parameter\"}" };
        }
        const reason = parsed.values[1] orelse "";
        self.mgmt_store.banEvent(&event_id, reason) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn allowEvent(self: *Nip86Handler, params: []const u8) Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, self.allocator);
        defer parsed.deinit();
        var event_id: [32]u8 = undefined;
        if (!parsed.parseEventId(&event_id)) {
            return Response{ .status = 400, .body = "{\"error\":\"missing or invalid event_id parameter\"}" };
        }
        self.mgmt_store.unbanEvent(&event_id) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn listEventsNeedingModeration(_: *Nip86Handler) Response {
        return Response{ .status = 200, .body = "{\"result\":[]}" };
    }

    fn listBannedEvents(self: *Nip86Handler) Response {
        const entries = self.mgmt_store.listBannedEvents(self.allocator) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        defer ManagementStore.freeEventEntries(entries, self.allocator);

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(self.allocator);

        buf.appendSlice(self.allocator, "{\"result\":[") catch return errorResponse();
        for (entries, 0..) |entry, i| {
            if (i > 0) buf.append(self.allocator, ',') catch return errorResponse();
            buf.appendSlice(self.allocator, "{\"id\":\"") catch return errorResponse();
            var hex_buf: [64]u8 = undefined;
            hex.encode(&entry.id, &hex_buf);
            buf.appendSlice(self.allocator, &hex_buf) catch return errorResponse();
            buf.appendSlice(self.allocator, "\",\"reason\":") catch return errorResponse();
            nip86.writeJsonString(&buf, self.allocator, entry.reason) catch return errorResponse();
            buf.append(self.allocator, '}') catch return errorResponse();
        }
        buf.appendSlice(self.allocator, "]}") catch return errorResponse();

        const result = self.allocator.dupe(u8, buf.items) catch return errorResponse();
        return Response{ .status = 200, .body = result, .owned = true };
    }

    fn changeRelayName(self: *Nip86Handler, params: []const u8) Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 1, self.allocator);
        defer parsed.deinit();
        const name = parsed.values[0] orelse {
            return Response{ .status = 400, .body = "{\"error\":\"missing name parameter\"}" };
        };
        self.mgmt_store.setRelaySetting("name", name) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        if (self.relay_name) |old| self.allocator.free(old);
        self.relay_name = self.allocator.dupe(u8, name) catch null;
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn changeRelayDescription(self: *Nip86Handler, params: []const u8) Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 1, self.allocator);
        defer parsed.deinit();
        const desc = parsed.values[0] orelse {
            return Response{ .status = 400, .body = "{\"error\":\"missing description parameter\"}" };
        };
        self.mgmt_store.setRelaySetting("description", desc) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        if (self.relay_description) |old| self.allocator.free(old);
        self.relay_description = self.allocator.dupe(u8, desc) catch null;
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn changeRelayIcon(self: *Nip86Handler, params: []const u8) Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 1, self.allocator);
        defer parsed.deinit();
        const icon = parsed.values[0] orelse {
            return Response{ .status = 400, .body = "{\"error\":\"missing icon url parameter\"}" };
        };
        self.mgmt_store.setRelaySetting("icon", icon) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        if (self.relay_icon) |old| self.allocator.free(old);
        self.relay_icon = self.allocator.dupe(u8, icon) catch null;
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn allowKind(self: *Nip86Handler, params: []const u8) Response {
        const kind = nip86.ParsedParams.parseKind(params) orelse {
            return Response{ .status = 400, .body = "{\"error\":\"invalid kind parameter\"}" };
        };
        self.mgmt_store.allowKind(kind) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn disallowKind(self: *Nip86Handler, params: []const u8) Response {
        const kind = nip86.ParsedParams.parseKind(params) orelse {
            return Response{ .status = 400, .body = "{\"error\":\"invalid kind parameter\"}" };
        };
        self.mgmt_store.disallowKind(kind) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn listAllowedKinds(self: *Nip86Handler) Response {
        const kinds = self.mgmt_store.listAllowedKinds(self.allocator) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        defer self.allocator.free(kinds);

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(self.allocator);

        buf.appendSlice(self.allocator, "{\"result\":[") catch return errorResponse();
        for (kinds, 0..) |kind, i| {
            if (i > 0) buf.append(self.allocator, ',') catch return errorResponse();
            var num_buf: [16]u8 = undefined;
            const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{kind}) catch return errorResponse();
            buf.appendSlice(self.allocator, num_str) catch return errorResponse();
        }
        buf.appendSlice(self.allocator, "]}") catch return errorResponse();

        const result = self.allocator.dupe(u8, buf.items) catch return errorResponse();
        return Response{ .status = 200, .body = result, .owned = true };
    }

    fn blockIp(self: *Nip86Handler, params: []const u8) Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 2, self.allocator);
        defer parsed.deinit();
        const ip = parsed.values[0] orelse {
            return Response{ .status = 400, .body = "{\"error\":\"missing ip parameter\"}" };
        };
        const reason = parsed.values[1] orelse "";
        self.mgmt_store.blockIp(ip, reason) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn unblockIp(self: *Nip86Handler, params: []const u8) Response {
        var parsed = nip86.ParsedParams.parseStrings(params, 1, self.allocator);
        defer parsed.deinit();
        const ip = parsed.values[0] orelse {
            return Response{ .status = 400, .body = "{\"error\":\"missing ip parameter\"}" };
        };
        self.mgmt_store.unblockIp(ip) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn listBlockedIps(self: *Nip86Handler) Response {
        const entries = self.mgmt_store.listBlockedIps(self.allocator) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        defer ManagementStore.freeIpEntries(entries, self.allocator);

        var buf: std.ArrayListUnmanaged(u8) = .{};
        defer buf.deinit(self.allocator);

        buf.appendSlice(self.allocator, "{\"result\":[") catch return errorResponse();
        for (entries, 0..) |entry, i| {
            if (i > 0) buf.append(self.allocator, ',') catch return errorResponse();
            buf.appendSlice(self.allocator, "{\"ip\":") catch return errorResponse();
            nip86.writeJsonString(&buf, self.allocator, entry.ip) catch return errorResponse();
            buf.appendSlice(self.allocator, ",\"reason\":") catch return errorResponse();
            nip86.writeJsonString(&buf, self.allocator, entry.reason) catch return errorResponse();
            buf.append(self.allocator, '}') catch return errorResponse();
        }
        buf.appendSlice(self.allocator, "]}") catch return errorResponse();

        const result = self.allocator.dupe(u8, buf.items) catch return errorResponse();
        return Response{ .status = 200, .body = result, .owned = true };
    }

    const AuthResult = struct {
        pubkey: ?[32]u8 = null,
        err: ?[]const u8 = null,
    };

    fn validateAuth(_: *Nip86Handler, auth_header: ?[]const u8, body: []const u8, request_url: []const u8) AuthResult {
        const header = auth_header orelse return AuthResult{ .err = "{\"error\":\"missing authorization header\"}" };

        if (!std.ascii.startsWithIgnoreCase(header, "nostr ")) {
            return AuthResult{ .err = "{\"error\":\"invalid authorization scheme\"}" };
        }

        const b64_event = std.mem.trim(u8, header[6..], " ");
        var decode_buf: [4096]u8 = undefined;
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64_event) catch {
            return AuthResult{ .err = "{\"error\":\"invalid base64 in authorization\"}" };
        };
        if (decoded_len > decode_buf.len) {
            return AuthResult{ .err = "{\"error\":\"authorization event too large\"}" };
        }
        std.base64.standard.Decoder.decode(&decode_buf, b64_event) catch {
            return AuthResult{ .err = "{\"error\":\"invalid base64 in authorization\"}" };
        };
        const decoded = decode_buf[0..decoded_len];

        var event = nostr.Event.parse(decoded) catch {
            return AuthResult{ .err = "{\"error\":\"invalid event in authorization\"}" };
        };
        defer event.deinit();

        if (event.kind() != 27235) {
            return AuthResult{ .err = "{\"error\":\"authorization event must be kind 27235\"}" };
        }

        const now = std.time.timestamp();
        const created = event.createdAt();
        const time_diff = if (now > created) now - created else created - now;
        if (time_diff > 60) {
            return AuthResult{ .err = "{\"error\":\"authorization event timestamp too old\"}" };
        }

        event.validate() catch {
            return AuthResult{ .err = "{\"error\":\"invalid event signature\"}" };
        };

        const tags = nip86.Nip98Tags.extract(decoded);

        if (tags.url == null) {
            return AuthResult{ .err = "{\"error\":\"missing u tag in authorization\"}" };
        }
        if (!nostr.Auth.domainsMatch(request_url, tags.url.?)) {
            return AuthResult{ .err = "{\"error\":\"url mismatch in authorization\"}" };
        }

        if (tags.method == null or !std.ascii.eqlIgnoreCase(tags.method.?, "POST")) {
            return AuthResult{ .err = "{\"error\":\"method must be POST\"}" };
        }

        if (tags.payload) |expected_hash| {
            var actual_hash: [64]u8 = undefined;
            var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
            sha256.update(body);
            const digest = sha256.finalResult();
            hex.encode(&digest, &actual_hash);
            if (!std.mem.eql(u8, expected_hash, &actual_hash)) {
                return AuthResult{ .err = "{\"error\":\"payload hash mismatch\"}" };
            }
        } else {
            return AuthResult{ .err = "{\"error\":\"missing payload tag in authorization\"}" };
        }

        var pubkey: [32]u8 = undefined;
        @memcpy(&pubkey, event.pubkey());
        return AuthResult{ .pubkey = pubkey };
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

    pub const Response = struct {
        status: u16,
        body: []const u8,
        owned: bool = false,
    };
};

fn errorResponse() Nip86Handler.Response {
    return Nip86Handler.Response{ .status = 500, .body = "{\"error\":\"internal error\"}" };
}
