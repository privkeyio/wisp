const std = @import("std");

pub const ConnectionLimiter = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,
    ip_buckets: std.StringHashMap(IpBucket),
    max_connections_per_ip: u32,
    cleanup_interval_seconds: i64,

    const IpBucket = struct {
        connection_count: u32,
        last_activity: i64,
    };

    pub fn init(allocator: std.mem.Allocator, max_connections_per_ip: u32) ConnectionLimiter {
        return .{
            .allocator = allocator,
            .mutex = .{},
            .ip_buckets = std.StringHashMap(IpBucket).init(allocator),
            .max_connections_per_ip = max_connections_per_ip,
            .cleanup_interval_seconds = 300,
        };
    }

    pub fn deinit(self: *ConnectionLimiter) void {
        var iter = self.ip_buckets.keyIterator();
        while (iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.ip_buckets.deinit();
    }

    pub fn canConnect(self: *ConnectionLimiter, ip: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.ip_buckets.get(ip)) |bucket| {
            return bucket.connection_count < self.max_connections_per_ip;
        }
        return true;
    }

    pub fn addConnection(self: *ConnectionLimiter, ip: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();

        if (self.ip_buckets.getPtr(ip)) |bucket| {
            bucket.connection_count += 1;
            bucket.last_activity = now;
        } else {
            const ip_copy = self.allocator.dupe(u8, ip) catch return;
            self.ip_buckets.put(ip_copy, .{
                .connection_count = 1,
                .last_activity = now,
            }) catch {
                self.allocator.free(ip_copy);
            };
        }
    }

    pub fn removeConnection(self: *ConnectionLimiter, ip: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.ip_buckets.getPtr(ip)) |bucket| {
            if (bucket.connection_count > 0) {
                bucket.connection_count -= 1;
            }
        }
    }

    pub fn cleanup(self: *ConnectionLimiter) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();
        var to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();

        var iter = self.ip_buckets.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.connection_count == 0 and
                now - entry.value_ptr.last_activity > self.cleanup_interval_seconds)
            {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            _ = self.ip_buckets.remove(key);
            self.allocator.free(key);
        }
    }

    pub fn getStats(self: *ConnectionLimiter) Stats {
        self.mutex.lock();
        defer self.mutex.unlock();

        return .{
            .tracked_ips = self.ip_buckets.count(),
        };
    }

    pub const Stats = struct {
        tracked_ips: usize,
    };
};

pub const IpFilter = struct {
    allocator: std.mem.Allocator,
    whitelist: std.StringHashMap(void),
    blacklist: std.StringHashMap(void),
    whitelist_enabled: bool,
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) IpFilter {
        return .{
            .allocator = allocator,
            .whitelist = std.StringHashMap(void).init(allocator),
            .blacklist = std.StringHashMap(void).init(allocator),
            .whitelist_enabled = false,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *IpFilter) void {
        var wl_iter = self.whitelist.keyIterator();
        while (wl_iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.whitelist.deinit();

        var bl_iter = self.blacklist.keyIterator();
        while (bl_iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.blacklist.deinit();
    }

    pub fn loadWhitelist(self: *IpFilter, list: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (list.len == 0) return;

        self.whitelist_enabled = true;
        var iter = std.mem.splitScalar(u8, list, ',');
        while (iter.next()) |entry| {
            const trimmed = std.mem.trim(u8, entry, " \t");
            if (trimmed.len > 0) {
                const copy = try self.allocator.dupe(u8, trimmed);
                try self.whitelist.put(copy, {});
            }
        }
    }

    pub fn loadBlacklist(self: *IpFilter, list: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (list.len == 0) return;

        var iter = std.mem.splitScalar(u8, list, ',');
        while (iter.next()) |entry| {
            const trimmed = std.mem.trim(u8, entry, " \t");
            if (trimmed.len > 0) {
                const copy = try self.allocator.dupe(u8, trimmed);
                try self.blacklist.put(copy, {});
            }
        }
    }

    pub fn isAllowed(self: *IpFilter, ip: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.matchesPrefix(&self.blacklist, ip)) {
            return false;
        }

        if (self.whitelist_enabled) {
            return self.matchesPrefix(&self.whitelist, ip);
        }

        return true;
    }

    fn matchesPrefix(self: *IpFilter, map: *std.StringHashMap(void), ip: []const u8) bool {
        _ = self;
        if (map.contains(ip)) return true;

        var iter = map.keyIterator();
        while (iter.next()) |prefix| {
            if (std.mem.startsWith(u8, ip, prefix.*)) {
                return true;
            }
        }
        return false;
    }
};

pub fn extractClientIp(
    forwarded_for: ?[]const u8,
    real_ip: ?[]const u8,
    remote_addr: []const u8,
    trust_proxy: bool,
) []const u8 {
    if (trust_proxy) {
        if (real_ip) |ip| {
            if (ip.len > 0) {
                return normalizeIp(ip);
            }
        }

        if (forwarded_for) |xff| {
            if (xff.len > 0) {
                if (std.mem.indexOf(u8, xff, ",")) |comma| {
                    return normalizeIp(std.mem.trim(u8, xff[0..comma], " "));
                }
                return normalizeIp(xff);
            }
        }
    }

    return normalizeIp(remote_addr);
}

fn normalizeIp(ip: []const u8) []const u8 {
    var result = ip;

    if (result.len > 2 and result[0] == '[') {
        if (std.mem.indexOf(u8, result, "]")) |end| {
            result = result[1..end];
        }
    }

    if (std.mem.lastIndexOf(u8, result, ":")) |colon| {
        const colon_count = std.mem.count(u8, result, ":");
        if (colon_count <= 1) {
            result = result[0..colon];
        }
    }

    return result;
}

test "extractClientIp" {
    try std.testing.expectEqualStrings("192.168.1.1", extractClientIp(null, null, "192.168.1.1:8080", false));
    try std.testing.expectEqualStrings("10.0.0.1", extractClientIp("1.2.3.4", null, "10.0.0.1:8080", false));
    try std.testing.expectEqualStrings("1.2.3.4", extractClientIp("1.2.3.4, 10.0.0.1", null, "127.0.0.1:8080", true));
    try std.testing.expectEqualStrings("5.6.7.8", extractClientIp("1.2.3.4", "5.6.7.8", "127.0.0.1:8080", true));
}

test "normalizeIp" {
    try std.testing.expectEqualStrings("192.168.1.1", normalizeIp("192.168.1.1:8080"));
    try std.testing.expectEqualStrings("::1", normalizeIp("[::1]:8080"));
    try std.testing.expectEqualStrings("192.168.1.1", normalizeIp("192.168.1.1"));
}
