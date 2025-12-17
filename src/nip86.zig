const std = @import("std");
const Config = @import("config.zig").Config;
const ManagementStore = @import("management_store.zig").ManagementStore;
const nostr = @import("nostr.zig");

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

    pub fn loadRelaySettings(self: *Nip86Handler) void {
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

        const request = parseRequest(body) orelse {
            return Response{ .status = 400, .body = "{\"error\":\"invalid request\"}" };
        };

        return self.dispatch(request.method, request.params);
    }

    fn dispatch(self: *Nip86Handler, method: []const u8, params: []const u8) Response {
        if (std.mem.eql(u8, method, "supportedmethods")) {
            return self.supportedMethods();
        } else if (std.mem.eql(u8, method, "banpubkey")) {
            return self.banPubkey(params);
        } else if (std.mem.eql(u8, method, "listbannedpubkeys")) {
            return self.listBannedPubkeys();
        } else if (std.mem.eql(u8, method, "allowpubkey")) {
            return self.allowPubkey(params);
        } else if (std.mem.eql(u8, method, "listallowedpubkeys")) {
            return self.listAllowedPubkeys();
        } else if (std.mem.eql(u8, method, "banevent")) {
            return self.banEvent(params);
        } else if (std.mem.eql(u8, method, "allowevent")) {
            return self.allowEvent(params);
        } else if (std.mem.eql(u8, method, "listbannedevents")) {
            return self.listBannedEvents();
        } else if (std.mem.eql(u8, method, "listeventsneedingmoderation")) {
            return self.listEventsNeedingModeration();
        } else if (std.mem.eql(u8, method, "changerelayname")) {
            return self.changeRelayName(params);
        } else if (std.mem.eql(u8, method, "changerelaydescription")) {
            return self.changeRelayDescription(params);
        } else if (std.mem.eql(u8, method, "changerelayicon")) {
            return self.changeRelayIcon(params);
        } else if (std.mem.eql(u8, method, "allowkind")) {
            return self.allowKind(params);
        } else if (std.mem.eql(u8, method, "disallowkind")) {
            return self.disallowKind(params);
        } else if (std.mem.eql(u8, method, "listallowedkinds")) {
            return self.listAllowedKinds();
        } else if (std.mem.eql(u8, method, "blockip")) {
            return self.blockIp(params);
        } else if (std.mem.eql(u8, method, "unblockip")) {
            return self.unblockIp(params);
        } else if (std.mem.eql(u8, method, "listblockedips")) {
            return self.listBlockedIps();
        } else {
            return Response{ .status = 400, .body = "{\"error\":\"unknown method\"}" };
        }
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
        const parsed = parseStringParams(params, 2);
        if (parsed.values[0] == null) {
            return Response{ .status = 400, .body = "{\"error\":\"missing pubkey parameter\"}" };
        }
        var pubkey: [32]u8 = undefined;
        if (!hexToBytes(parsed.values[0].?, &pubkey)) {
            return Response{ .status = 400, .body = "{\"error\":\"invalid pubkey hex\"}" };
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
            _ = bytesToHex(&entry.pubkey, &hex_buf);
            buf.appendSlice(self.allocator, &hex_buf) catch return errorResponse();
            buf.appendSlice(self.allocator, "\",\"reason\":") catch return errorResponse();
            writeJsonStringUnmanaged(&buf, self.allocator, entry.reason) catch return errorResponse();
            buf.append(self.allocator, '}') catch return errorResponse();
        }
        buf.appendSlice(self.allocator, "]}") catch return errorResponse();

        const result = self.allocator.dupe(u8, buf.items) catch return errorResponse();
        return Response{ .status = 200, .body = result, .owned = true };
    }

    fn allowPubkey(self: *Nip86Handler, params: []const u8) Response {
        const parsed = parseStringParams(params, 2);
        if (parsed.values[0] == null) {
            return Response{ .status = 400, .body = "{\"error\":\"missing pubkey parameter\"}" };
        }
        var pubkey: [32]u8 = undefined;
        if (!hexToBytes(parsed.values[0].?, &pubkey)) {
            return Response{ .status = 400, .body = "{\"error\":\"invalid pubkey hex\"}" };
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
            _ = bytesToHex(&entry.pubkey, &hex_buf);
            buf.appendSlice(self.allocator, &hex_buf) catch return errorResponse();
            buf.appendSlice(self.allocator, "\",\"reason\":") catch return errorResponse();
            writeJsonStringUnmanaged(&buf, self.allocator, entry.reason) catch return errorResponse();
            buf.append(self.allocator, '}') catch return errorResponse();
        }
        buf.appendSlice(self.allocator, "]}") catch return errorResponse();

        const result = self.allocator.dupe(u8, buf.items) catch return errorResponse();
        return Response{ .status = 200, .body = result, .owned = true };
    }

    fn banEvent(self: *Nip86Handler, params: []const u8) Response {
        const parsed = parseStringParams(params, 2);
        if (parsed.values[0] == null) {
            return Response{ .status = 400, .body = "{\"error\":\"missing event_id parameter\"}" };
        }
        var event_id: [32]u8 = undefined;
        if (!hexToBytes(parsed.values[0].?, &event_id)) {
            return Response{ .status = 400, .body = "{\"error\":\"invalid event_id hex\"}" };
        }
        const reason = parsed.values[1] orelse "";
        self.mgmt_store.banEvent(&event_id, reason) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn allowEvent(self: *Nip86Handler, params: []const u8) Response {
        const parsed = parseStringParams(params, 2);
        if (parsed.values[0] == null) {
            return Response{ .status = 400, .body = "{\"error\":\"missing event_id parameter\"}" };
        }
        var event_id: [32]u8 = undefined;
        if (!hexToBytes(parsed.values[0].?, &event_id)) {
            return Response{ .status = 400, .body = "{\"error\":\"invalid event_id hex\"}" };
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
            _ = bytesToHex(&entry.id, &hex_buf);
            buf.appendSlice(self.allocator, &hex_buf) catch return errorResponse();
            buf.appendSlice(self.allocator, "\",\"reason\":") catch return errorResponse();
            writeJsonStringUnmanaged(&buf, self.allocator, entry.reason) catch return errorResponse();
            buf.append(self.allocator, '}') catch return errorResponse();
        }
        buf.appendSlice(self.allocator, "]}") catch return errorResponse();

        const result = self.allocator.dupe(u8, buf.items) catch return errorResponse();
        return Response{ .status = 200, .body = result, .owned = true };
    }

    fn changeRelayName(self: *Nip86Handler, params: []const u8) Response {
        const parsed = parseStringParams(params, 1);
        if (parsed.values[0] == null) {
            return Response{ .status = 400, .body = "{\"error\":\"missing name parameter\"}" };
        }
        self.mgmt_store.setRelaySetting("name", parsed.values[0].?) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        if (self.relay_name) |old| self.allocator.free(old);
        self.relay_name = self.allocator.dupe(u8, parsed.values[0].?) catch null;
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn changeRelayDescription(self: *Nip86Handler, params: []const u8) Response {
        const parsed = parseStringParams(params, 1);
        if (parsed.values[0] == null) {
            return Response{ .status = 400, .body = "{\"error\":\"missing description parameter\"}" };
        }
        self.mgmt_store.setRelaySetting("description", parsed.values[0].?) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        if (self.relay_description) |old| self.allocator.free(old);
        self.relay_description = self.allocator.dupe(u8, parsed.values[0].?) catch null;
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn changeRelayIcon(self: *Nip86Handler, params: []const u8) Response {
        const parsed = parseStringParams(params, 1);
        if (parsed.values[0] == null) {
            return Response{ .status = 400, .body = "{\"error\":\"missing icon url parameter\"}" };
        }
        self.mgmt_store.setRelaySetting("icon", parsed.values[0].?) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        if (self.relay_icon) |old| self.allocator.free(old);
        self.relay_icon = self.allocator.dupe(u8, parsed.values[0].?) catch null;
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn allowKind(self: *Nip86Handler, params: []const u8) Response {
        const kind = parseKindParam(params) orelse {
            return Response{ .status = 400, .body = "{\"error\":\"invalid kind parameter\"}" };
        };
        self.mgmt_store.allowKind(kind) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn disallowKind(self: *Nip86Handler, params: []const u8) Response {
        const kind = parseKindParam(params) orelse {
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
        const parsed = parseStringParams(params, 2);
        if (parsed.values[0] == null) {
            return Response{ .status = 400, .body = "{\"error\":\"missing ip parameter\"}" };
        }
        const reason = parsed.values[1] orelse "";
        self.mgmt_store.blockIp(parsed.values[0].?, reason) catch {
            return Response{ .status = 500, .body = "{\"error\":\"storage error\"}" };
        };
        return Response{ .status = 200, .body = "{\"result\":true}" };
    }

    fn unblockIp(self: *Nip86Handler, params: []const u8) Response {
        const parsed = parseStringParams(params, 1);
        if (parsed.values[0] == null) {
            return Response{ .status = 400, .body = "{\"error\":\"missing ip parameter\"}" };
        }
        self.mgmt_store.unblockIp(parsed.values[0].?) catch {
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
            writeJsonStringUnmanaged(&buf, self.allocator, entry.ip) catch return errorResponse();
            buf.appendSlice(self.allocator, ",\"reason\":") catch return errorResponse();
            writeJsonStringUnmanaged(&buf, self.allocator, entry.reason) catch return errorResponse();
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

        const tags = Nip98Tags.extract(decoded);

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
            _ = bytesToHex(&digest, &actual_hash);
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
        _ = bytesToHex(pubkey, &hex_buf);

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

const Request = struct {
    method: []const u8,
    params: []const u8,
};

fn parseRequest(body: []const u8) ?Request {
    const method_key = "\"method\"";
    const method_idx = std.mem.indexOf(u8, body, method_key) orelse return null;
    var pos = method_idx + method_key.len;

    while (pos < body.len and (body[pos] == ':' or body[pos] == ' ' or body[pos] == '\t')) pos += 1;
    if (pos >= body.len or body[pos] != '"') return null;
    pos += 1;

    const method_start = pos;
    while (pos < body.len and body[pos] != '"') pos += 1;
    if (pos >= body.len) return null;
    const method = body[method_start..pos];

    const params_key = "\"params\"";
    const params_idx = std.mem.indexOf(u8, body, params_key) orelse return Request{ .method = method, .params = "[]" };
    pos = params_idx + params_key.len;

    while (pos < body.len and (body[pos] == ':' or body[pos] == ' ' or body[pos] == '\t')) pos += 1;
    if (pos >= body.len or body[pos] != '[') return Request{ .method = method, .params = "[]" };

    const params_start = pos;
    var depth: i32 = 0;
    while (pos < body.len) {
        if (body[pos] == '[') depth += 1;
        if (body[pos] == ']') {
            depth -= 1;
            if (depth == 0) {
                pos += 1;
                break;
            }
        }
        pos += 1;
    }

    return Request{ .method = method, .params = body[params_start..pos] };
}

const ParsedParams = struct {
    values: [4]?[]const u8,
};

fn parseStringParams(params: []const u8, comptime max_count: usize) ParsedParams {
    var result = ParsedParams{ .values = .{ null, null, null, null } };
    var count: usize = 0;
    var pos: usize = 0;
    var in_string = false;
    var string_start: usize = 0;
    var escape = false;

    while (pos < params.len and count < max_count) {
        const c = params[pos];

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
            if (in_string) {
                result.values[count] = params[string_start..pos];
                count += 1;
            } else {
                string_start = pos + 1;
            }
            in_string = !in_string;
        }

        pos += 1;
    }

    return result;
}

fn parseKindParam(params: []const u8) ?i32 {
    var pos: usize = 0;
    while (pos < params.len and (params[pos] == '[' or params[pos] == ' ' or params[pos] == '\t')) pos += 1;

    var num: i32 = 0;
    var found_digit = false;
    while (pos < params.len) {
        const c = params[pos];
        if (c >= '0' and c <= '9') {
            num = num * 10 + @as(i32, @intCast(c - '0'));
            found_digit = true;
        } else if (found_digit) {
            break;
        }
        pos += 1;
    }

    if (found_digit) return num;
    return null;
}

fn hexToBytes(hex: []const u8, out: *[32]u8) bool {
    if (hex.len != 64) return false;
    for (0..32) |i| {
        const high = hexDigit(hex[i * 2]) orelse return false;
        const low = hexDigit(hex[i * 2 + 1]) orelse return false;
        out[i] = (high << 4) | low;
    }
    return true;
}

fn hexDigit(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return null;
}

fn writeJsonStringUnmanaged(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try buf.append(allocator, '"');
    for (value) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
                var escape_buf: [6]u8 = undefined;
                const escape = std.fmt.bufPrint(&escape_buf, "\\u{x:0>4}", .{c}) catch continue;
                try buf.appendSlice(allocator, escape);
            },
            else => try buf.append(allocator, c),
        }
    }
    try buf.append(allocator, '"');
}

fn errorResponse() Nip86Handler.Response {
    return Nip86Handler.Response{ .status = 500, .body = "{\"error\":\"internal error\"}" };
}

fn bytesToHex(bytes: []const u8, out: []u8) []u8 {
    const hex_chars = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return out[0 .. bytes.len * 2];
}

const Nip98Tags = struct {
    url: ?[]const u8 = null,
    method: ?[]const u8 = null,
    payload: ?[]const u8 = null,

    pub fn extract(json: []const u8) Nip98Tags {
        var result = Nip98Tags{};

        const tags_start = std.mem.indexOf(u8, json, "\"tags\"") orelse return result;
        var pos = tags_start + 6;

        while (pos < json.len and json[pos] != '[') : (pos += 1) {}
        if (pos >= json.len) return result;
        pos += 1;

        var depth: i32 = 0;
        var in_string = false;
        var escape = false;
        var tag_start: ?usize = null;

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
                if (c == '[') {
                    if (depth == 0) {
                        tag_start = pos;
                    }
                    depth += 1;
                } else if (c == ']') {
                    depth -= 1;
                    if (depth == 0 and tag_start != null) {
                        const tag_json = json[tag_start.? .. pos + 1];
                        extractNip98TagValue(tag_json, &result);
                        tag_start = null;
                    }
                    if (depth < 0) break;
                }
            }

            pos += 1;
        }

        return result;
    }
};

fn extractNip98TagValue(tag_json: []const u8, result: *Nip98Tags) void {
    var values: [2]?[]const u8 = .{ null, null };
    var value_idx: usize = 0;
    var pos: usize = 0;
    var in_string = false;
    var string_start: usize = 0;
    var escape = false;

    while (pos < tag_json.len and value_idx < 2) {
        const c = tag_json[pos];

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
            if (in_string) {
                values[value_idx] = tag_json[string_start..pos];
                value_idx += 1;
            } else {
                string_start = pos + 1;
            }
            in_string = !in_string;
        }

        pos += 1;
    }

    if (values[0] != null and values[1] != null) {
        if (std.mem.eql(u8, values[0].?, "u")) {
            result.url = values[1].?;
        } else if (std.mem.eql(u8, values[0].?, "method")) {
            result.method = values[1].?;
        } else if (std.mem.eql(u8, values[0].?, "payload")) {
            result.payload = values[1].?;
        }
    }
}
