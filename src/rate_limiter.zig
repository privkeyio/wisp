const std = @import("std");
const nostr = @import("nostr.zig");

pub const ConnectionLimiter = struct {
    allocator: std.mem.Allocator,
    mutex: std.Io.Mutex,
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
            .mutex = .init,
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
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        if (self.ip_buckets.get(ip)) |bucket| {
            return bucket.connection_count < self.max_connections_per_ip;
        }
        return true;
    }

    /// Atomically check the per-IP limit and increment in one locked section.
    /// Returns false (without incrementing) if the IP is already at the limit,
    /// closing the canConnect/addConnection check-then-act race.
    pub fn tryAcquireConnection(self: *ConnectionLimiter, ip: []const u8) bool {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const now = nostr.io.timestamp();

        if (self.ip_buckets.getPtr(ip)) |bucket| {
            if (bucket.connection_count >= self.max_connections_per_ip) return false;
            bucket.connection_count += 1;
            bucket.last_activity = now;
            return true;
        }

        const ip_copy = self.allocator.dupe(u8, ip) catch return false;
        self.ip_buckets.put(ip_copy, .{
            .connection_count = 1,
            .last_activity = now,
        }) catch {
            self.allocator.free(ip_copy);
            return false;
        };
        return true;
    }

    pub fn removeConnection(self: *ConnectionLimiter, ip: []const u8) void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        if (self.ip_buckets.getPtr(ip)) |bucket| {
            if (bucket.connection_count > 0) {
                bucket.connection_count -= 1;
            }
        }
    }

    pub fn cleanup(self: *ConnectionLimiter) void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const now = nostr.io.timestamp();
        var to_remove: std.ArrayListUnmanaged([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var iter = self.ip_buckets.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.connection_count == 0 and
                now - entry.value_ptr.last_activity > self.cleanup_interval_seconds)
            {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            _ = self.ip_buckets.remove(key);
            self.allocator.free(key);
        }
    }

    pub fn getStats(self: *ConnectionLimiter) Stats {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

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
    mutex: std.Io.Mutex,

    pub fn init(allocator: std.mem.Allocator) IpFilter {
        return .{
            .allocator = allocator,
            .whitelist = std.StringHashMap(void).init(allocator),
            .blacklist = std.StringHashMap(void).init(allocator),
            .whitelist_enabled = false,
            .mutex = .init,
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
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

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
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

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
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

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
                if (std.mem.lastIndexOf(u8, xff, ",")) |comma| {
                    return normalizeIp(std.mem.trim(u8, xff[comma + 1 ..], " "));
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
    try std.testing.expectEqualStrings("10.0.0.1", extractClientIp("1.2.3.4, 10.0.0.1", null, "127.0.0.1:8080", true));
    try std.testing.expectEqualStrings("5.6.7.8", extractClientIp("1.2.3.4", "5.6.7.8", "127.0.0.1:8080", true));
}

test "normalizeIp" {
    try std.testing.expectEqualStrings("192.168.1.1", normalizeIp("192.168.1.1:8080"));
    try std.testing.expectEqualStrings("::1", normalizeIp("[::1]:8080"));
    try std.testing.expectEqualStrings("192.168.1.1", normalizeIp("192.168.1.1"));
}

pub const EventRateLimiter = struct {
    allocator: std.mem.Allocator,
    mutex: std.Io.Mutex,
    ip_buckets: std.StringHashMap(EventBucket),
    events_per_minute: u32,

    // Idle buckets are reclaimed after this many seconds; a bucket idle for a
    // full window has refilled to capacity, so dropping it is indistinguishable
    // from a fresh IP.
    const IDLE_SECONDS: i64 = 60;

    // Token bucket per IP: capacity is events_per_minute, refilled at
    // events_per_minute/60 tokens per second. O(1) state, so any configured
    // limit is enforced (the previous 256-slot ring silently capped at 255).
    const EventBucket = struct {
        tokens: f64,
        last_refill: i64,
    };

    pub fn init(allocator: std.mem.Allocator, events_per_minute: u32) EventRateLimiter {
        return .{
            .allocator = allocator,
            .mutex = .init,
            .ip_buckets = std.StringHashMap(EventBucket).init(allocator),
            .events_per_minute = events_per_minute,
        };
    }

    pub fn deinit(self: *EventRateLimiter) void {
        var iter = self.ip_buckets.keyIterator();
        while (iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.ip_buckets.deinit();
    }

    pub fn checkAndRecord(self: *EventRateLimiter, ip: []const u8) bool {
        if (self.events_per_minute == 0) return true;
        return self.checkAndRecordAt(ip, nostr.io.timestamp());
    }

    fn checkAndRecordAt(self: *EventRateLimiter, ip: []const u8, now: i64) bool {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const capacity: f64 = @floatFromInt(self.events_per_minute);
        const refill_per_sec: f64 = capacity / 60.0;

        if (self.ip_buckets.getPtr(ip)) |bucket| {
            const elapsed: f64 = @floatFromInt(@max(@as(i64, 0), now - bucket.last_refill));
            bucket.tokens = @min(capacity, bucket.tokens + elapsed * refill_per_sec);
            bucket.last_refill = now;
            if (bucket.tokens >= 1.0) {
                bucket.tokens -= 1.0;
                return true;
            }
            return false;
        }

        // First event from this IP: start with a full bucket, then consume one.
        const ip_copy = self.allocator.dupe(u8, ip) catch return false;
        self.ip_buckets.put(ip_copy, .{
            .tokens = capacity - 1.0,
            .last_refill = now,
        }) catch {
            self.allocator.free(ip_copy);
            return false;
        };
        return true;
    }

    pub fn cleanup(self: *EventRateLimiter) void {
        self.cleanupAt(nostr.io.timestamp());
    }

    fn cleanupAt(self: *EventRateLimiter, now: i64) void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var to_remove: std.ArrayListUnmanaged([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var iter = self.ip_buckets.iterator();
        while (iter.next()) |entry| {
            if (now - entry.value_ptr.last_refill >= IDLE_SECONDS) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            _ = self.ip_buckets.remove(key);
            self.allocator.free(key);
        }
    }
};

test "EventRateLimiter enforces a limit above 255" {
    var limiter = EventRateLimiter.init(std.testing.allocator, 300);
    defer limiter.deinit();

    // The bucket holds a full minute's capacity, so a burst within the same
    // second allows up to 300 events and throttles the rest. The old 256-slot
    // ring capped its count at 255, so a 300/min limit never tripped and all
    // 400 would have passed.
    var allowed: u32 = 0;
    var i: u32 = 0;
    while (i < 400) : (i += 1) {
        if (limiter.checkAndRecord("1.2.3.4")) allowed += 1;
    }
    try std.testing.expect(allowed >= 300); // limit honored, not over-throttled
    try std.testing.expect(allowed < 400); // and actually throttled
}

test "EventRateLimiter is disabled when the limit is zero" {
    var limiter = EventRateLimiter.init(std.testing.allocator, 0);
    defer limiter.deinit();
    var i: u32 = 0;
    while (i < 500) : (i += 1) {
        try std.testing.expect(limiter.checkAndRecord("9.9.9.9"));
    }
}

test "EventRateLimiter refills tokens over time" {
    var limiter = EventRateLimiter.init(std.testing.allocator, 60); // 1 token/sec
    defer limiter.deinit();

    // Drain the full bucket within the same second.
    var allowed: u32 = 0;
    var i: u32 = 0;
    while (i < 60) : (i += 1) {
        if (limiter.checkAndRecordAt("1.2.3.4", 1000)) allowed += 1;
    }
    try std.testing.expectEqual(@as(u32, 60), allowed);
    try std.testing.expect(!limiter.checkAndRecordAt("1.2.3.4", 1000)); // empty now

    // After 10 seconds, ~10 tokens have refilled.
    allowed = 0;
    i = 0;
    while (i < 20) : (i += 1) {
        if (limiter.checkAndRecordAt("1.2.3.4", 1010)) allowed += 1;
    }
    try std.testing.expectEqual(@as(u32, 10), allowed);
}

test "EventRateLimiter tracks IPs independently" {
    var limiter = EventRateLimiter.init(std.testing.allocator, 5);
    defer limiter.deinit();

    // Drain the first IP completely.
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        try std.testing.expect(limiter.checkAndRecordAt("1.1.1.1", 1000));
    }
    try std.testing.expect(!limiter.checkAndRecordAt("1.1.1.1", 1000));

    // A different IP is unaffected and gets its own full bucket.
    i = 0;
    while (i < 5) : (i += 1) {
        try std.testing.expect(limiter.checkAndRecordAt("2.2.2.2", 1000));
    }
    try std.testing.expect(!limiter.checkAndRecordAt("2.2.2.2", 1000));
}

test "EventRateLimiter cleanup reclaims only idle buckets" {
    var limiter = EventRateLimiter.init(std.testing.allocator, 10);
    defer limiter.deinit();

    try std.testing.expect(limiter.checkAndRecordAt("1.1.1.1", 1000));
    try std.testing.expect(limiter.checkAndRecordAt("2.2.2.2", 1050));

    // At t=1059, the first bucket is idle for 59s (<60), so nothing is reclaimed.
    limiter.cleanupAt(1059);
    try std.testing.expectEqual(@as(u32, 2), limiter.ip_buckets.count());

    // At t=1060, the first bucket hits IDLE_SECONDS and is removed; the second
    // (idle 10s) is retained.
    limiter.cleanupAt(1060);
    try std.testing.expectEqual(@as(u32, 1), limiter.ip_buckets.count());
    try std.testing.expect(limiter.ip_buckets.contains("2.2.2.2"));
}
