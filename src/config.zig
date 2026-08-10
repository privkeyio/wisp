const std = @import("std");
const nostr = @import("nostr.zig");

const log = std.log.scoped(.config);

fn getenv(name: [*:0]const u8) ?[]const u8 {
    const v = std.c.getenv(name) orelse return null;
    return std.mem.sliceTo(v, 0);
}

/// Accepted spellings of a boolean, case-insensitive. Returns null for anything
/// else so callers can decide between failing and warning, rather than silently
/// reading an unrecognized value as false.
fn parseBool(value: []const u8) ?bool {
    const truthy = [_][]const u8{ "true", "1", "yes", "on" };
    const falsy = [_][]const u8{ "false", "0", "no", "off" };
    for (truthy) |t| if (std.ascii.eqlIgnoreCase(value, t)) return true;
    for (falsy) |f| if (std.ascii.eqlIgnoreCase(value, f)) return false;
    return null;
}

// A malformed environment variable keeps the current value rather than aborting:
// these usually come from an orchestrator, where refusing to boot turns a typo
// into a crash loop. It must never pass silently though, since the knobs being
// set here are limits and a self-termination switch, and an operator who
// mistypes one would otherwise believe a cap is in force when it is not. The
// config file is stricter: a bad value there fails the load.
fn envInt(comptime T: type, name: []const u8, value: []const u8, current: T) T {
    return std.fmt.parseInt(T, value, 10) catch {
        log.warn("{s}=\"{s}\" is not a valid {s}; keeping {d}", .{ name, value, @typeName(T), current });
        return current;
    };
}

fn envBool(name: []const u8, value: []const u8, current: bool) bool {
    return parseBool(value) orelse {
        log.warn("{s}=\"{s}\" is not a valid boolean; keeping {}", .{ name, value, current });
        return current;
    };
}

pub const Config = struct {
    host: []const u8,
    port: u16,
    name: []const u8,
    description: []const u8,
    pubkey: ?[]const u8,
    contact: ?[]const u8,
    max_connections: u32,
    // Epoll worker threads. 0 means auto (scale with CPU, capped at 4). Lower it
    // (e.g. 1) on a personal or memory-constrained relay: each worker carries its
    // own buffer pools and thread subset, so fewer workers means a smaller footprint.
    workers: u16,
    // Per-worker live-connection cap handed to httpz (workers.max_conn). At the cap
    // the worker pauses accept. 0 keeps httpz's default (8192). Setting it makes an
    // accept stall (see wisp-ci1's slot leak) trip the watchdog sooner.
    max_conn: u16,
    max_subscriptions: u32,
    max_filters: u32,
    max_message_size: u32,
    max_event_tags: u32,
    max_content_length: u32,
    query_limit_default: u32,
    query_limit_max: u32,
    // Bounds the entries a single query may scan to `limit * query_scan_multiplier`
    // before stopping, so a selective filter (few matches) cannot page-fault the
    // entire event DB looking for `limit` results. 0 disables the cap.
    query_scan_multiplier: u32,
    max_event_age: i64,
    max_future_seconds: i64,
    storage_path: []const u8,
    storage_map_size_mb: u32,
    // LMDB durability: "none" (MDB_NOSYNC, fastest, can lose recent writes and
    // corrupt the db on crash), "meta" (default; flush data each commit, defer
    // metapage fsync), or "full" (durable fsync each commit).
    storage_sync: []const u8,
    idle_seconds: u32,
    events_per_minute: u32,
    // Per-IP limit on expensive query messages (REQ/COUNT/NEG_OPEN). 0 disables.
    queries_per_minute: u32,
    deleted_retention_days: u32,

    auth_required: bool,
    auth_to_write: bool,
    relay_url: []const u8,

    trust_proxy: bool,
    // Comma-separated IPs/prefixes of reverse proxies whose forwarded headers are
    // honored. Empty with trust_proxy=true honors headers from any peer.
    trusted_proxies: []const u8,
    max_connections_per_ip: u32,
    ip_whitelist: []const u8,
    ip_blacklist: []const u8,

    // Spider configuration
    spider_enabled: bool,
    spider_relays: []const u8,
    spider_admin: []const u8,
    spider_pubkeys: []const u8,
    spider_sync_interval: u32,

    // Negentropy (NIP-77) configuration
    negentropy_enabled: bool,
    negentropy_max_sync_events: u32,
    // Concurrent negentropy sessions per connection. Each buffers up to
    // negentropy_max_sync_events IDs, so this is kept small independent of
    // max_subscriptions.
    max_neg_sessions: u32,

    min_pow_difficulty: u8,

    admin_pubkeys: []const u8,

    // Self-watchdog: a background thread periodically opens a loopback TCP
    // connection to our own listener and expects an HTTP reply. If the accept
    // loop wedges (kernel completes handshakes but wisp never services them), the
    // probe gets no bytes back; after `watchdog_failures` consecutive misses the
    // process exits so the supervisor restarts it. On by default.
    watchdog_enabled: bool,
    watchdog_interval_seconds: u32,
    watchdog_timeout_ms: u32,
    watchdog_failures: u32,

    _allocated: std.ArrayListUnmanaged([]const u8),
    _allocator: ?std.mem.Allocator,

    pub fn defaults() Config {
        return .{
            .host = "127.0.0.1",
            .port = 7777,
            .name = "Wisp",
            .description = "A lightweight Nostr relay",
            .pubkey = null,
            .contact = null,
            .max_connections = 1000,
            .workers = 0,
            .max_conn = 0,
            .max_subscriptions = 20,
            .max_filters = 10,
            .max_message_size = 65536,
            .max_event_tags = 2000,
            .max_content_length = 102400,
            .query_limit_default = 500,
            .query_limit_max = 5000,
            .query_scan_multiplier = 20,
            .max_event_age = 94608000,
            .max_future_seconds = 900,
            .storage_path = "./data",
            .storage_map_size_mb = 10240,
            .storage_sync = "meta",
            .idle_seconds = 300,
            .events_per_minute = 120,
            .queries_per_minute = 300,
            .deleted_retention_days = 90,
            .auth_required = false,
            .auth_to_write = false,
            .relay_url = "",
            .trust_proxy = false,
            .trusted_proxies = "",
            .max_connections_per_ip = 10,
            .ip_whitelist = "",
            .ip_blacklist = "",
            .spider_enabled = false,
            .spider_relays = "",
            .spider_admin = "",
            .spider_pubkeys = "",
            .spider_sync_interval = 300,
            .negentropy_enabled = true,
            .negentropy_max_sync_events = 1000000,
            .max_neg_sessions = 4,
            .min_pow_difficulty = 0,
            .admin_pubkeys = "",
            .watchdog_enabled = true,
            .watchdog_interval_seconds = 10,
            .watchdog_timeout_ms = 2000,
            .watchdog_failures = 3,
            ._allocated = undefined,
            ._allocator = null,
        };
    }

    pub fn load(allocator: std.mem.Allocator, path: []const u8) !Config {
        var config = defaults();
        config._allocator = allocator;
        config._allocated = .empty;

        const io = nostr.io.io();
        const content = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
        defer allocator.free(content);

        var section: []const u8 = "";
        var lines = std.mem.splitScalar(u8, content, '\n');
        var line_no: usize = 0;

        while (lines.next()) |line| {
            line_no += 1;
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']') {
                section = trimmed[1 .. trimmed.len - 1];
                continue;
            }

            const eq_pos = std.mem.indexOf(u8, trimmed, "=") orelse continue;
            const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            var value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            if (value.len > 0 and value[0] == '"') {
                if (std.mem.indexOfScalarPos(u8, value, 1, '"')) |close_quote| {
                    value = value[0 .. close_quote + 1];
                }
            } else if (std.mem.indexOf(u8, value, "#")) |hash_pos| {
                value = std.mem.trim(u8, value[0..hash_pos], " \t");
            }

            if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                value = value[1 .. value.len - 1];
            }

            // A bad value in the file aborts the load, but say which one: the bare
            // error.InvalidCharacter this used to surface gave an operator nothing
            // to go on in a file with dozens of keys.
            config.setValue(section, key, value) catch |err| {
                log.err("{s}:{d}: [{s}] {s} = \"{s}\": {t}", .{ path, line_no, section, key, value, err });
                return err;
            };
        }

        return config;
    }

    fn setValue(self: *Config, section: []const u8, key: []const u8, value: []const u8) !void {
        if (std.mem.eql(u8, section, "server")) {
            if (std.mem.eql(u8, key, "host")) {
                self.host = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "port")) {
                self.port = try std.fmt.parseInt(u16, value, 10);
            }
        } else if (std.mem.eql(u8, section, "relay")) {
            if (std.mem.eql(u8, key, "name")) {
                self.name = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "description")) {
                self.description = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "pubkey")) {
                self.pubkey = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "contact")) {
                self.contact = try self.allocString(value);
            }
        } else if (std.mem.eql(u8, section, "limits")) {
            if (std.mem.eql(u8, key, "max_connections")) {
                self.max_connections = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "workers")) {
                self.workers = try std.fmt.parseInt(u16, value, 10);
            } else if (std.mem.eql(u8, key, "max_conn")) {
                self.max_conn = try std.fmt.parseInt(u16, value, 10);
            } else if (std.mem.eql(u8, key, "max_subscriptions")) {
                self.max_subscriptions = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "max_filters")) {
                self.max_filters = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "max_message_size")) {
                self.max_message_size = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "max_event_tags")) {
                self.max_event_tags = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "max_content_length")) {
                self.max_content_length = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "query_limit_default")) {
                self.query_limit_default = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "query_limit_max")) {
                self.query_limit_max = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "query_scan_multiplier")) {
                self.query_scan_multiplier = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "max_event_age")) {
                self.max_event_age = try std.fmt.parseInt(i64, value, 10);
            } else if (std.mem.eql(u8, key, "max_future_seconds")) {
                self.max_future_seconds = try std.fmt.parseInt(i64, value, 10);
            } else if (std.mem.eql(u8, key, "min_pow_difficulty")) {
                self.min_pow_difficulty = try std.fmt.parseInt(u8, value, 10);
            }
        } else if (std.mem.eql(u8, section, "storage")) {
            if (std.mem.eql(u8, key, "path")) {
                self.storage_path = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "map_size_mb")) {
                self.storage_map_size_mb = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "sync")) {
                self.storage_sync = try self.allocString(value);
            }
        } else if (std.mem.eql(u8, section, "timeouts")) {
            if (std.mem.eql(u8, key, "idle_seconds")) {
                self.idle_seconds = try std.fmt.parseInt(u32, value, 10);
            }
        } else if (std.mem.eql(u8, section, "rate_limits")) {
            if (std.mem.eql(u8, key, "events_per_minute")) {
                self.events_per_minute = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "queries_per_minute")) {
                self.queries_per_minute = try std.fmt.parseInt(u32, value, 10);
            }
        } else if (std.mem.eql(u8, section, "auth")) {
            if (std.mem.eql(u8, key, "required")) {
                self.auth_required = parseBool(value) orelse return error.InvalidBoolean;
            } else if (std.mem.eql(u8, key, "to_write")) {
                self.auth_to_write = parseBool(value) orelse return error.InvalidBoolean;
            } else if (std.mem.eql(u8, key, "relay_url")) {
                self.relay_url = try self.allocString(value);
            }
        } else if (std.mem.eql(u8, section, "security")) {
            if (std.mem.eql(u8, key, "trust_proxy")) {
                self.trust_proxy = parseBool(value) orelse return error.InvalidBoolean;
            } else if (std.mem.eql(u8, key, "trusted_proxies")) {
                self.trusted_proxies = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "max_connections_per_ip")) {
                self.max_connections_per_ip = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "ip_whitelist")) {
                self.ip_whitelist = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "ip_blacklist")) {
                self.ip_blacklist = try self.allocString(value);
            }
        } else if (std.mem.eql(u8, section, "spider")) {
            if (std.mem.eql(u8, key, "enabled")) {
                self.spider_enabled = parseBool(value) orelse return error.InvalidBoolean;
            } else if (std.mem.eql(u8, key, "relays")) {
                self.spider_relays = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "admin")) {
                self.spider_admin = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "pubkeys")) {
                self.spider_pubkeys = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "sync_interval")) {
                self.spider_sync_interval = try std.fmt.parseInt(u32, value, 10);
            }
        } else if (std.mem.eql(u8, section, "negentropy")) {
            if (std.mem.eql(u8, key, "enabled")) {
                self.negentropy_enabled = parseBool(value) orelse return error.InvalidBoolean;
            } else if (std.mem.eql(u8, key, "max_sync_events")) {
                self.negentropy_max_sync_events = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "max_sessions")) {
                self.max_neg_sessions = try std.fmt.parseInt(u32, value, 10);
            }
        } else if (std.mem.eql(u8, section, "management")) {
            if (std.mem.eql(u8, key, "admin_pubkeys")) {
                self.admin_pubkeys = try self.allocString(value);
            }
        } else if (std.mem.eql(u8, section, "watchdog")) {
            if (std.mem.eql(u8, key, "enabled")) {
                self.watchdog_enabled = parseBool(value) orelse return error.InvalidBoolean;
            } else if (std.mem.eql(u8, key, "interval_seconds")) {
                self.watchdog_interval_seconds = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "timeout_ms")) {
                self.watchdog_timeout_ms = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "failures")) {
                self.watchdog_failures = try std.fmt.parseInt(u32, value, 10);
            }
        }
    }

    fn allocString(self: *Config, value: []const u8) ![]const u8 {
        if (self._allocator) |alloc| {
            const copy = try alloc.dupe(u8, value);
            try self._allocated.append(alloc, copy);
            return copy;
        }
        return value;
    }

    pub fn loadEnv(self: *Config) void {
        if (getenv("WISP_HOST")) |v| self.host = v;
        if (getenv("WISP_PORT")) |v| self.port = envInt(u16, "WISP_PORT", v, self.port);
        if (getenv("WISP_RELAY_NAME")) |v| self.name = v;
        if (getenv("WISP_STORAGE_PATH")) |v| self.storage_path = v;
        if (getenv("WISP_STORAGE_SYNC")) |v| self.storage_sync = v;
        if (getenv("WISP_MAX_CONNECTIONS")) |v| self.max_connections = envInt(u32, "WISP_MAX_CONNECTIONS", v, self.max_connections);
        if (getenv("WISP_AUTH_REQUIRED")) |v| self.auth_required = envBool("WISP_AUTH_REQUIRED", v, self.auth_required);
        if (getenv("WISP_AUTH_TO_WRITE")) |v| self.auth_to_write = envBool("WISP_AUTH_TO_WRITE", v, self.auth_to_write);
        if (getenv("WISP_RELAY_URL")) |v| self.relay_url = v;
        if (getenv("WISP_TRUST_PROXY")) |v| self.trust_proxy = envBool("WISP_TRUST_PROXY", v, self.trust_proxy);
        if (getenv("WISP_TRUSTED_PROXIES")) |v| self.trusted_proxies = v;
        if (getenv("WISP_MAX_CONNECTIONS_PER_IP")) |v| self.max_connections_per_ip = envInt(u32, "WISP_MAX_CONNECTIONS_PER_IP", v, self.max_connections_per_ip);
        if (getenv("WISP_WORKERS")) |v| self.workers = envInt(u16, "WISP_WORKERS", v, self.workers);
        if (getenv("WISP_MAX_CONN")) |v| self.max_conn = envInt(u16, "WISP_MAX_CONN", v, self.max_conn);
        if (getenv("WISP_EVENTS_PER_MINUTE")) |v| self.events_per_minute = envInt(u32, "WISP_EVENTS_PER_MINUTE", v, self.events_per_minute);
        if (getenv("WISP_QUERIES_PER_MINUTE")) |v| self.queries_per_minute = envInt(u32, "WISP_QUERIES_PER_MINUTE", v, self.queries_per_minute);
        if (getenv("WISP_QUERY_SCAN_MULTIPLIER")) |v| self.query_scan_multiplier = envInt(u32, "WISP_QUERY_SCAN_MULTIPLIER", v, self.query_scan_multiplier);
        if (getenv("WISP_IDLE_SECONDS")) |v| self.idle_seconds = envInt(u32, "WISP_IDLE_SECONDS", v, self.idle_seconds);
        if (getenv("WISP_IP_WHITELIST")) |v| self.ip_whitelist = v;
        if (getenv("WISP_IP_BLACKLIST")) |v| self.ip_blacklist = v;
        if (getenv("WISP_SPIDER_ENABLED")) |v| self.spider_enabled = envBool("WISP_SPIDER_ENABLED", v, self.spider_enabled);
        if (getenv("WISP_SPIDER_RELAYS")) |v| self.spider_relays = v;
        if (getenv("WISP_SPIDER_ADMIN")) |v| self.spider_admin = v;
        if (getenv("WISP_SPIDER_PUBKEYS")) |v| self.spider_pubkeys = v;
        if (getenv("WISP_SPIDER_SYNC_INTERVAL")) |v| self.spider_sync_interval = envInt(u32, "WISP_SPIDER_SYNC_INTERVAL", v, self.spider_sync_interval);
        if (getenv("WISP_NEGENTROPY_ENABLED")) |v| self.negentropy_enabled = envBool("WISP_NEGENTROPY_ENABLED", v, self.negentropy_enabled);
        if (getenv("WISP_NEGENTROPY_MAX_SYNC_EVENTS")) |v| self.negentropy_max_sync_events = envInt(u32, "WISP_NEGENTROPY_MAX_SYNC_EVENTS", v, self.negentropy_max_sync_events);
        if (getenv("WISP_NEGENTROPY_MAX_SESSIONS")) |v| self.max_neg_sessions = envInt(u32, "WISP_NEGENTROPY_MAX_SESSIONS", v, self.max_neg_sessions);
        if (getenv("WISP_MIN_POW_DIFFICULTY")) |v| self.min_pow_difficulty = envInt(u8, "WISP_MIN_POW_DIFFICULTY", v, self.min_pow_difficulty);
        if (getenv("WISP_ADMIN_PUBKEYS")) |v| self.admin_pubkeys = v;
        if (getenv("WISP_WATCHDOG_ENABLED")) |v| self.watchdog_enabled = envBool("WISP_WATCHDOG_ENABLED", v, self.watchdog_enabled);
        if (getenv("WISP_WATCHDOG_INTERVAL_SECONDS")) |v| self.watchdog_interval_seconds = envInt(u32, "WISP_WATCHDOG_INTERVAL_SECONDS", v, self.watchdog_interval_seconds);
        if (getenv("WISP_WATCHDOG_TIMEOUT_MS")) |v| self.watchdog_timeout_ms = envInt(u32, "WISP_WATCHDOG_TIMEOUT_MS", v, self.watchdog_timeout_ms);
        if (getenv("WISP_WATCHDOG_FAILURES")) |v| self.watchdog_failures = envInt(u32, "WISP_WATCHDOG_FAILURES", v, self.watchdog_failures);
    }

    pub fn deinit(self: *Config) void {
        if (self._allocator) |alloc| {
            for (self._allocated.items) |s| {
                alloc.free(s);
            }
            self._allocated.deinit(alloc);
        }
    }
};

test parseBool {
    for ([_][]const u8{ "true", "TRUE", "True", "1", "yes", "YES", "on", "ON" }) |v| {
        try std.testing.expectEqual(true, parseBool(v).?);
    }
    for ([_][]const u8{ "false", "FALSE", "False", "0", "no", "NO", "off", "OFF" }) |v| {
        try std.testing.expectEqual(false, parseBool(v).?);
    }
    // Unrecognized values are rejected rather than read as false. The old
    // `eql("true") or eql("1")` form silently turned `TRUE` into false, which for
    // watchdog.enabled meant quietly disabling a self-termination switch the
    // operator believed they had turned on.
    for ([_][]const u8{ "", "maybe", "tru", "2", "-1", "t", "y", "enabled" }) |v| {
        try std.testing.expectEqual(@as(?bool, null), parseBool(v));
    }
}

test "envInt: a malformed value keeps the current one" {
    // Out of range for the target type, which is the wisp-qj3 case:
    // WISP_MAX_CONN=70000 does not fit u16.
    try std.testing.expectEqual(@as(u16, 4096), envInt(u16, "WISP_MAX_CONN", "70000", 4096));
    // Units accidentally included, the other common operator slip.
    try std.testing.expectEqual(@as(u32, 2000), envInt(u32, "WISP_WATCHDOG_TIMEOUT_MS", "2000ms", 2000));
    try std.testing.expectEqual(@as(u32, 7), envInt(u32, "X", "", 7));
    // A valid value is still applied.
    try std.testing.expectEqual(@as(u16, 12), envInt(u16, "WISP_MAX_CONN", "12", 4096));
}

test "envBool: a malformed value keeps the current one" {
    try std.testing.expectEqual(true, envBool("WISP_WATCHDOG_ENABLED", "maybe", true));
    try std.testing.expectEqual(false, envBool("WISP_WATCHDOG_ENABLED", "", false));
    // Case no longer silently flips a knob off.
    try std.testing.expectEqual(true, envBool("WISP_WATCHDOG_ENABLED", "TRUE", false));
    try std.testing.expectEqual(false, envBool("WISP_WATCHDOG_ENABLED", "Off", true));
}

test "setValue: a malformed boolean in the config file fails the load" {
    var config = Config.defaults();
    // The file path is strict, unlike the environment: it is authored
    // deliberately, so a value that cannot be read is an error rather than a
    // silently ignored line.
    try std.testing.expectError(error.InvalidBoolean, config.setValue("watchdog", "enabled", "maybe"));
    try std.testing.expectError(error.InvalidCharacter, config.setValue("watchdog", "timeout_ms", "2000ms"));

    // Valid spellings still load, including ones the old form rejected.
    try config.setValue("watchdog", "enabled", "OFF");
    try std.testing.expectEqual(false, config.watchdog_enabled);
    try config.setValue("watchdog", "enabled", "yes");
    try std.testing.expectEqual(true, config.watchdog_enabled);
}
