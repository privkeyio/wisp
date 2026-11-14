//! IP address and CIDR rule matching shared by the config IP lists
//! (ip_whitelist, ip_blacklist, trusted_proxies) and the NIP-86 blocked-IP store.
//!
//! Rule syntax:
//!   - a bare address: "10.0.0.5" (/32), "2001:db8::1" (/128)
//!   - CIDR: "185.220.100.0/22", "2001:db8::/32". Host bits past the prefix are
//!     ignored, so "10.1.2.3/8" is 10.0.0.0/8.
//!   - legacy prefix (kept so existing configs keep working), converted to CIDR:
//!     "10." -> /8, "10.0." -> /16, "10.0.0." -> /24, and IPv6 "2001:db8:" ->
//!     one /16 per group, so 2001:db8::/32.
//!
//! IPv4-mapped IPv6 ("::ffff:1.2.3.4") is folded to IPv4 on both sides, so an
//! IPv4 rule matches a client that a dual-stack socket reports as mapped. Other
//! IPv6 rules only match IPv6 clients: "::/0" covers all of IPv6, not IPv4.

const std = @import("std");
const net = std.Io.net;

pub const Family = enum { v4, v6 };

/// A parsed client address. IPv4 lives in the low 32 bits.
pub const Addr = struct {
    family: Family,
    bits: u128,
};

pub const Rule = struct {
    family: Family,
    net: u128,
    mask: u128,

    pub fn matches(self: Rule, addr: Addr) bool {
        return self.family == addr.family and (addr.bits & self.mask) == self.net;
    }
};

pub const Syntax = enum {
    /// Address, CIDR, or legacy prefix ending in '.' or ':'.
    standard,
    /// Also accepts a dotless IPv4 prefix ("185.220" -> /16), which is how the
    /// NIP-86 blocked-IP store matched keys before CIDR support.
    allow_dotless_prefix,
};

/// Linear scan; rule lists are operator-written and small.
pub fn anyMatch(rules: []const Rule, addr: Addr) bool {
    for (rules) |r| {
        if (r.matches(addr)) return true;
    }
    return false;
}

/// Parse a client address. A zone id ("fe80::1%eth0") is ignored.
pub fn parseAddr(text: []const u8) ?Addr {
    if (std.mem.indexOfScalar(u8, text, ':') != null) {
        const host = if (std.mem.indexOfScalar(u8, text, '%')) |pct| text[0..pct] else text;
        const a = net.Ip6Address.parse(host, 0) catch return null;
        return fromIp6Bytes(a.bytes);
    }
    const a = net.Ip4Address.parse(text, 0) catch return null;
    return .{ .family = .v4, .bits = std.mem.readInt(u32, &a.bytes, .big) };
}

/// Parse a rule, or null if `text` is not a valid address, CIDR or prefix.
pub fn parseRule(text: []const u8, syntax: Syntax) ?Rule {
    if (text.len == 0) return null;

    if (std.mem.indexOfScalar(u8, text, '/')) |slash| {
        const len = parsePrefixLen(text[slash + 1 ..]) orelse return null;
        const addr = parseRuleAddr(text[0..slash]) orelse return null;
        return makeRule(addr, len);
    }

    if (parseRuleAddr(text)) |addr| {
        return makeRule(addr, if (addr.family == .v4) 32 else 128);
    }

    const last = text[text.len - 1];
    if (last == '.') return parseLegacyIp4(text);
    if (last == ':') return parseLegacyIp6(text);
    if (syntax == .allow_dotless_prefix and std.mem.count(u8, text, ".") < 3) {
        var buf: [16]u8 = undefined;
        if (text.len >= buf.len) return null;
        @memcpy(buf[0..text.len], text);
        buf[text.len] = '.';
        return parseLegacyIp4(buf[0 .. text.len + 1]);
    }
    return null;
}

const RuleAddr = struct { family: Family, bits: u128, mapped: bool };

/// Like `parseAddr`, but rejects zone ids: a rule naming an interface scope
/// would silently match regardless of interface.
fn parseRuleAddr(text: []const u8) ?RuleAddr {
    if (std.mem.indexOfScalar(u8, text, '%') != null) return null;
    if (std.mem.indexOfScalar(u8, text, ':') != null) {
        const a = net.Ip6Address.parse(text, 0) catch return null;
        return .{ .family = .v6, .bits = std.mem.readInt(u128, &a.bytes, .big), .mapped = isMapped(a.bytes) };
    }
    const a = net.Ip4Address.parse(text, 0) catch return null;
    return .{ .family = .v4, .bits = std.mem.readInt(u32, &a.bytes, .big), .mapped = false };
}

fn makeRule(addr: RuleAddr, len: u8) ?Rule {
    switch (addr.family) {
        .v4 => {
            if (len > 32) return null;
            return v4Rule(@truncate(addr.bits), len);
        },
        .v6 => {
            if (len > 128) return null;
            // ::ffff:a.b.c.d/96+n is the IPv4 rule a.b.c.d/n, so it matches the
            // folded IPv4 client.
            if (addr.mapped and len >= 96) return v4Rule(@truncate(addr.bits), len - 96);
            const mask: u128 = if (len == 0) 0 else ~@as(u128, 0) << @intCast(128 - @as(u16, len));
            return .{ .family = .v6, .net = addr.bits & mask, .mask = mask };
        },
    }
}

fn v4Rule(bits: u32, len: u8) Rule {
    const mask: u32 = if (len == 0) 0 else ~@as(u32, 0) << @intCast(32 - @as(u16, len));
    return .{ .family = .v4, .net = bits & mask, .mask = mask };
}

fn parsePrefixLen(text: []const u8) ?u8 {
    if (text.len == 0 or text.len > 3) return null;
    if (text.len > 1 and text[0] == '0') return null;
    var n: u16 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
        n = n * 10 + (c - '0');
    }
    return if (n > 128) null else @intCast(n);
}

/// "a." / "a.b." / "a.b.c." -> /8, /16, /24.
fn parseLegacyIp4(text: []const u8) ?Rule {
    if (std.mem.indexOfScalar(u8, text, ':') != null) return null;
    const octets = std.mem.count(u8, text, ".");
    if (octets < 1 or octets > 3) return null;
    var buf: [16]u8 = undefined;
    const full = std.fmt.bufPrint(&buf, "{s}{s}", .{ text, ("0.0.0")[2 * (octets - 1) ..] }) catch return null;
    const a = net.Ip4Address.parse(full, 0) catch return null;
    return v4Rule(std.mem.readInt(u32, &a.bytes, .big), @intCast(8 * octets));
}

/// "x:" / "x:y:" ... -> one /16 per group. A "::" makes the group count
/// ambiguous, so such an entry is only valid as a complete address; every
/// group must be non-empty.
fn parseLegacyIp6(text: []const u8) ?Rule {
    if (text[0] == ':' or std.mem.indexOf(u8, text, "::") != null) return null;
    const groups = std.mem.count(u8, text, ":");
    if (groups < 1 or groups > 7) return null;
    var buf: [48]u8 = undefined;
    const full = std.fmt.bufPrint(&buf, "{s}:", .{text}) catch return null;
    const a = net.Ip6Address.parse(full, 0) catch return null;
    return makeRule(.{ .family = Family.v6, .bits = std.mem.readInt(u128, &a.bytes, .big), .mapped = false }, @intCast(16 * groups));
}

/// `entry` truncated to 64 bytes with non-printable bytes replaced, for logging
/// operator- or client-supplied text without terminal-escape injection.
pub fn safeEntry(entry: []const u8, buf: *[64]u8) []const u8 {
    const len = @min(entry.len, buf.len);
    for (entry[0..len], buf[0..len]) |c, *out| {
        out.* = if (std.ascii.isPrint(c)) c else '?';
    }
    return buf[0..len];
}

fn isMapped(b: [16]u8) bool {
    return std.mem.allEqual(u8, b[0..10], 0) and b[10] == 0xff and b[11] == 0xff;
}

fn fromIp6Bytes(b: [16]u8) Addr {
    if (isMapped(b)) return .{ .family = .v4, .bits = std.mem.readInt(u32, b[12..16], .big) };
    return .{ .family = .v6, .bits = std.mem.readInt(u128, &b, .big) };
}

const testing = std.testing;

fn ruleMatches(rule_text: []const u8, ip: []const u8) bool {
    const rule = parseRule(rule_text, .standard) orelse @panic("test rule did not parse");
    const addr = parseAddr(ip) orelse return false;
    return rule.matches(addr);
}

test "parseAddr" {
    try testing.expectEqual(Addr{ .family = .v4, .bits = 0x0a000005 }, parseAddr("10.0.0.5").?);
    try testing.expectEqual(Addr{ .family = .v6, .bits = 1 }, parseAddr("::1").?);
    try testing.expectEqual(Addr{ .family = .v6, .bits = 0xfe80 << 112 | 1 }, parseAddr("fe80::1%eth0").?);
    // IPv4-mapped IPv6 folds to IPv4, in dotted and uncompressed hex form.
    try testing.expectEqual(Addr{ .family = .v4, .bits = 0x01020304 }, parseAddr("::ffff:1.2.3.4").?);
    try testing.expectEqual(Addr{ .family = .v4, .bits = 0x01020304 }, parseAddr("0:0:0:0:0:ffff:102:304").?);
    try testing.expect(parseAddr("") == null);
    try testing.expect(parseAddr("unknown") == null);
    try testing.expect(parseAddr("10.0.0.256") == null);
    try testing.expect(parseAddr("10.0.0") == null);
    try testing.expect(parseAddr("1:2:3:4:5:6:7:8:9") == null);
}

test "IPv4 CIDR boundaries" {
    // The incident range: 185.220.100.0/22 is 185.220.100.0 - 185.220.103.255.
    try testing.expect(!ruleMatches("185.220.100.0/22", "185.220.99.255"));
    try testing.expect(ruleMatches("185.220.100.0/22", "185.220.100.0"));
    try testing.expect(ruleMatches("185.220.100.0/22", "185.220.101.7"));
    try testing.expect(ruleMatches("185.220.100.0/22", "185.220.103.255"));
    try testing.expect(!ruleMatches("185.220.100.0/22", "185.220.104.0"));

    try testing.expect(ruleMatches("10.0.0.0/8", "10.255.255.255"));
    try testing.expect(!ruleMatches("10.0.0.0/8", "11.0.0.0"));
    try testing.expect(ruleMatches("10.0.0.128/25", "10.0.0.128"));
    try testing.expect(!ruleMatches("10.0.0.128/25", "10.0.0.127"));

    // Host bits past the prefix are masked off.
    try testing.expect(ruleMatches("10.1.2.3/8", "10.200.0.1"));

    // /32 is a single address, /0 is all of IPv4 but not IPv6.
    try testing.expect(ruleMatches("1.2.3.4/32", "1.2.3.4"));
    try testing.expect(!ruleMatches("1.2.3.4/32", "1.2.3.5"));
    try testing.expect(ruleMatches("0.0.0.0/0", "0.0.0.0"));
    try testing.expect(ruleMatches("0.0.0.0/0", "255.255.255.255"));
    try testing.expect(!ruleMatches("0.0.0.0/0", "2001:db8::1"));
}

test "IPv6 CIDR boundaries" {
    try testing.expect(ruleMatches("2001:db8::/32", "2001:db8::"));
    try testing.expect(ruleMatches("2001:db8::/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"));
    try testing.expect(!ruleMatches("2001:db8::/32", "2001:db9::"));
    try testing.expect(!ruleMatches("2001:db8::/32", "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff"));

    try testing.expect(ruleMatches("2001:db8:0:1::/64", "2001:db8:0:1:abcd::1"));
    try testing.expect(!ruleMatches("2001:db8:0:1::/64", "2001:db8:0:2::1"));

    // An odd length splits a group.
    try testing.expect(ruleMatches("2001:db8::/31", "2001:db9::1"));
    try testing.expect(!ruleMatches("2001:db8::/31", "2001:dba::1"));

    try testing.expect(ruleMatches("2001:db8::1/128", "2001:db8::1"));
    try testing.expect(!ruleMatches("2001:db8::1/128", "2001:db8::2"));
    try testing.expect(ruleMatches("::1", "::1"));

    // ::/0 is all of IPv6, but not IPv4 (including mapped IPv4).
    try testing.expect(ruleMatches("::/0", "::"));
    try testing.expect(ruleMatches("::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    try testing.expect(!ruleMatches("::/0", "1.2.3.4"));
    try testing.expect(!ruleMatches("::/0", "::ffff:1.2.3.4"));
}

test "IPv4-mapped IPv6 matches IPv4 rules" {
    try testing.expect(ruleMatches("1.2.3.4", "::ffff:1.2.3.4"));
    try testing.expect(ruleMatches("185.220.100.0/22", "::ffff:185.220.102.9"));
    try testing.expect(!ruleMatches("185.220.100.0/22", "::ffff:185.220.104.9"));
    try testing.expect(ruleMatches("10.0.0.", "::ffff:10.0.0.9"));

    // A mapped rule is the IPv4 rule it embeds.
    try testing.expect(ruleMatches("::ffff:1.2.3.4", "1.2.3.4"));
    try testing.expect(ruleMatches("::ffff:10.0.0.0/104", "10.9.9.9"));
    try testing.expect(!ruleMatches("::ffff:10.0.0.0/104", "11.0.0.0"));
    try testing.expect(ruleMatches("::ffff:0.0.0.0/96", "8.8.8.8"));
}

test "legacy prefixes convert to CIDR" {
    const cases = [_]struct { legacy: []const u8, cidr: []const u8 }{
        .{ .legacy = "10.", .cidr = "10.0.0.0/8" },
        .{ .legacy = "192.168.", .cidr = "192.168.0.0/16" },
        .{ .legacy = "185.220.101.", .cidr = "185.220.101.0/24" },
        .{ .legacy = "2001:", .cidr = "2001::/16" },
        .{ .legacy = "2001:db8:", .cidr = "2001:db8::/32" },
        .{ .legacy = "1:2:3:4:5:6:7:", .cidr = "1:2:3:4:5:6:7::/112" },
    };
    for (cases) |c| {
        try testing.expectEqual(parseRule(c.cidr, .standard).?, parseRule(c.legacy, .standard).?);
    }

    try testing.expect(ruleMatches("185.220.101.", "185.220.101.0"));
    try testing.expect(ruleMatches("185.220.101.", "185.220.101.255"));
    try testing.expect(!ruleMatches("185.220.101.", "185.220.102.1"));
    // A prefix ends at an octet boundary: "1.2.3." does not cover 1.2.30.x.
    try testing.expect(!ruleMatches("1.2.3.", "1.2.30.1"));

    // A complete address ending in "::" is an exact address, not a prefix.
    try testing.expectEqual(parseRule("2001:db8::/128", .standard).?, parseRule("2001:db8::", .standard).?);
    try testing.expect(!ruleMatches("2001:db8::", "2001:db8::1"));

    // Dotless prefixes are only accepted for the NIP-86 store.
    try testing.expect(parseRule("185.220", .standard) == null);
    try testing.expectEqual(parseRule("185.220.0.0/16", .standard).?, parseRule("185.220", .allow_dotless_prefix).?);
    try testing.expectEqual(parseRule("185.0.0.0/8", .standard).?, parseRule("185", .allow_dotless_prefix).?);
    try testing.expectEqual(parseRule("1.2.3.4/32", .standard).?, parseRule("1.2.3.4", .allow_dotless_prefix).?);
}

test "malformed rules are rejected" {
    const bad = [_][]const u8{
        "",               ".",                ":",            "/",
        "/8",             "10.0.0.0/",        "10.0.0.0/33",  "10.0.0.0/-1",
        "10.0.0.0/+8",    "10.0.0.0/08",      "10.0.0.0/8/8", "10.0.0.0/ 8",
        "2001:db8::/129", "2001:db8::/1000",  "10.0.0.256",   "10.0.0",
        "10.0.0.0.",      "256.",             "10..",         "010.",
        "192.168.*",      "example.com",      "::ffff:1.2.",  "2001::db8:",
        "12345:",         "1:2:3:4:5:6:7:8:", "fe80::1%eth0", "fe80::%eth0/64",
        "10.0.0.0/8 ",    " 10.0.0.0/8",      "x::/16",
    };
    for (bad) |text| {
        if (parseRule(text, .standard) != null) {
            std.debug.print("accepted malformed rule \"{s}\"\n", .{text});
            return error.TestUnexpectedResult;
        }
    }
    try testing.expect(parseRule("1.2.3.4.5", .allow_dotless_prefix) == null);
    try testing.expect(parseRule("abc", .allow_dotless_prefix) == null);
    try testing.expect(parseRule("1.2.3.4/33", .allow_dotless_prefix) == null);
}

test anyMatch {
    const rules = [_]Rule{
        parseRule("10.0.0.0/8", .standard).?,
        parseRule("2001:db8::/32", .standard).?,
    };
    try testing.expect(anyMatch(&rules, parseAddr("10.1.1.1").?));
    try testing.expect(anyMatch(&rules, parseAddr("2001:db8::5").?));
    try testing.expect(!anyMatch(&rules, parseAddr("11.1.1.1").?));
    try testing.expect(!anyMatch(&[_]Rule{}, parseAddr("10.1.1.1").?));
}
