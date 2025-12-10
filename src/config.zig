const std = @import("std");

pub const Config = struct {
    host: []const u8,
    port: u16,
    name: []const u8,
    description: []const u8,
    pubkey: ?[]const u8,
    contact: ?[]const u8,
    max_connections: u32,
    max_subscriptions: u32,
    max_filters: u32,
    max_message_size: u32,
    max_event_tags: u32,
    max_content_length: u32,
    query_limit_default: u32,
    query_limit_max: u32,
    events_per_minute: u32,
    max_event_age: i64,
    max_future_seconds: i64,
    storage_path: []const u8,
    storage_map_size_mb: u32,
    idle_seconds: u32,

    auth_required: bool,
    auth_to_write: bool,
    relay_url: []const u8,

    trust_proxy: bool,
    events_per_minute_per_ip: u32,
    global_events_per_minute: u64,
    max_connections_per_ip: u32,
    ip_whitelist: []const u8,
    ip_blacklist: []const u8,

    // Spider configuration
    spider_enabled: bool,
    spider_relays: []const u8,
    spider_owner_pubkey: []const u8,
    spider_pubkeys: []const u8,

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
            .max_subscriptions = 20,
            .max_filters = 10,
            .max_message_size = 65536,
            .max_event_tags = 2000,
            .max_content_length = 102400,
            .query_limit_default = 500,
            .query_limit_max = 5000,
            .events_per_minute = 60,
            .max_event_age = 94608000,
            .max_future_seconds = 900,
            .storage_path = "./data",
            .storage_map_size_mb = 10240,
            .idle_seconds = 300,
            .auth_required = false,
            .auth_to_write = false,
            .relay_url = "",
            .trust_proxy = false,
            .events_per_minute_per_ip = 120,
            .global_events_per_minute = 10000,
            .max_connections_per_ip = 10,
            .ip_whitelist = "",
            .ip_blacklist = "",
            .spider_enabled = false,
            .spider_relays = "",
            .spider_owner_pubkey = "",
            .spider_pubkeys = "",
            ._allocated = undefined,
            ._allocator = null,
        };
    }

    pub fn load(allocator: std.mem.Allocator, path: []const u8) !Config {
        var config = defaults();
        config._allocator = allocator;
        config._allocated = .{};

        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(content);

        var section: []const u8 = "";
        var lines = std.mem.splitScalar(u8, content, '\n');

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']') {
                section = trimmed[1 .. trimmed.len - 1];
                continue;
            }

            const eq_pos = std.mem.indexOf(u8, trimmed, "=") orelse continue;
            const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            var value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                value = value[1 .. value.len - 1];
            }

            try config.setValue(section, key, value);
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
            } else if (std.mem.eql(u8, key, "events_per_minute")) {
                self.events_per_minute = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "max_event_age")) {
                self.max_event_age = try std.fmt.parseInt(i64, value, 10);
            } else if (std.mem.eql(u8, key, "max_future_seconds")) {
                self.max_future_seconds = try std.fmt.parseInt(i64, value, 10);
            }
        } else if (std.mem.eql(u8, section, "storage")) {
            if (std.mem.eql(u8, key, "path")) {
                self.storage_path = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "map_size_mb")) {
                self.storage_map_size_mb = try std.fmt.parseInt(u32, value, 10);
            }
        } else if (std.mem.eql(u8, section, "timeouts")) {
            if (std.mem.eql(u8, key, "idle_seconds")) {
                self.idle_seconds = try std.fmt.parseInt(u32, value, 10);
            }
        } else if (std.mem.eql(u8, section, "auth")) {
            if (std.mem.eql(u8, key, "required")) {
                self.auth_required = std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1");
            } else if (std.mem.eql(u8, key, "to_write")) {
                self.auth_to_write = std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1");
            } else if (std.mem.eql(u8, key, "relay_url")) {
                self.relay_url = try self.allocString(value);
            }
        } else if (std.mem.eql(u8, section, "security")) {
            if (std.mem.eql(u8, key, "trust_proxy")) {
                self.trust_proxy = std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1");
            } else if (std.mem.eql(u8, key, "events_per_minute_per_ip")) {
                self.events_per_minute_per_ip = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "global_events_per_minute")) {
                self.global_events_per_minute = try std.fmt.parseInt(u64, value, 10);
            } else if (std.mem.eql(u8, key, "max_connections_per_ip")) {
                self.max_connections_per_ip = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "ip_whitelist")) {
                self.ip_whitelist = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "ip_blacklist")) {
                self.ip_blacklist = try self.allocString(value);
            }
        } else if (std.mem.eql(u8, section, "spider")) {
            if (std.mem.eql(u8, key, "enabled")) {
                self.spider_enabled = std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1");
            } else if (std.mem.eql(u8, key, "relays")) {
                self.spider_relays = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "owner_pubkey")) {
                self.spider_owner_pubkey = try self.allocString(value);
            } else if (std.mem.eql(u8, key, "pubkeys")) {
                self.spider_pubkeys = try self.allocString(value);
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
        if (std.posix.getenv("WISP_HOST")) |v| self.host = v;
        if (std.posix.getenv("WISP_PORT")) |v| {
            self.port = std.fmt.parseInt(u16, v, 10) catch self.port;
        }
        if (std.posix.getenv("WISP_RELAY_NAME")) |v| self.name = v;
        if (std.posix.getenv("WISP_STORAGE_PATH")) |v| self.storage_path = v;
        if (std.posix.getenv("WISP_MAX_CONNECTIONS")) |v| {
            self.max_connections = std.fmt.parseInt(u32, v, 10) catch self.max_connections;
        }
        if (std.posix.getenv("WISP_AUTH_REQUIRED")) |v| {
            self.auth_required = std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "1");
        }
        if (std.posix.getenv("WISP_AUTH_TO_WRITE")) |v| {
            self.auth_to_write = std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "1");
        }
        if (std.posix.getenv("WISP_RELAY_URL")) |v| self.relay_url = v;
        if (std.posix.getenv("WISP_EVENTS_PER_MINUTE")) |v| {
            self.events_per_minute = std.fmt.parseInt(u32, v, 10) catch self.events_per_minute;
        }
        if (std.posix.getenv("WISP_TRUST_PROXY")) |v| {
            self.trust_proxy = std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "1");
        }
        if (std.posix.getenv("WISP_EVENTS_PER_MINUTE_PER_IP")) |v| {
            self.events_per_minute_per_ip = std.fmt.parseInt(u32, v, 10) catch self.events_per_minute_per_ip;
        }
        if (std.posix.getenv("WISP_GLOBAL_EVENTS_PER_MINUTE")) |v| {
            self.global_events_per_minute = std.fmt.parseInt(u64, v, 10) catch self.global_events_per_minute;
        }
        if (std.posix.getenv("WISP_MAX_CONNECTIONS_PER_IP")) |v| {
            self.max_connections_per_ip = std.fmt.parseInt(u32, v, 10) catch self.max_connections_per_ip;
        }
        if (std.posix.getenv("WISP_IP_WHITELIST")) |v| self.ip_whitelist = v;
        if (std.posix.getenv("WISP_IP_BLACKLIST")) |v| self.ip_blacklist = v;
        if (std.posix.getenv("WISP_SPIDER_ENABLED")) |v| {
            self.spider_enabled = std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "1");
        }
        if (std.posix.getenv("WISP_SPIDER_RELAYS")) |v| self.spider_relays = v;
        if (std.posix.getenv("WISP_SPIDER_OWNER_PUBKEY")) |v| self.spider_owner_pubkey = v;
        if (std.posix.getenv("WISP_SPIDER_PUBKEYS")) |v| self.spider_pubkeys = v;
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
