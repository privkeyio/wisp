const std = @import("std");
const nostr = @import("nostr.zig");
const ip_match = @import("ip_match.zig");

const log = std.log.scoped(.ip_filter);

// Per-IP limiter state is sharded across independent mutex+map buckets so
// worker threads keying on different IPs do not serialize on one process-global
// lock on every event/query/connection. The shard is chosen by hashing the
// final bucket key, so a given IP always maps to the same shard and per-IP
// semantics are preserved exactly.
const SHARD_COUNT = 16;

// The hash is seeded with a per-process random value chosen at init. The seed is
// public-input-independent, so an attacker who controls the bucket key (e.g. via
// a spoofable X-Forwarded-For under trust_proxy) cannot craft keys that all fall
// on one shard and collapse the 16-way split back to a single mutex. The seed
// only needs to be stable for the process lifetime (per-IP -> same shard), not
// across restarts.
fn shardIndex(seed: u64, key: []const u8) usize {
    return std.hash.Wyhash.hash(seed, key) % SHARD_COUNT;
}

fn randomSeed() u64 {
    var buf: [8]u8 = undefined;
    nostr.io.randomBytes(&buf);
    return std.mem.readInt(u64, &buf, .little);
}

pub const SubnetLimit = struct {
    /// Concurrent connections per subnet; 0 disables the subnet cap.
    max_connections: u32 = 0,
    prefix_v4: u8 = 24,
    prefix_v6: u8 = 48,
};

pub const ConnectionLimiter = struct {
    allocator: std.mem.Allocator,
    shards: [SHARD_COUNT]Shard,
    shard_seed: u64,
    max_connections_per_ip: u32,
    subnet: SubnetLimit,
    cleanup_interval_seconds: i64,

    const IpBucket = struct {
        connection_count: u32,
        last_activity: i64,
    };

    // Every client that does not parse as an address shares one `unparsed`
    // subnet bucket. Socket peers always parse, so this only holds malformed or
    // forged forwarded headers, and it keeps a stream of distinct garbage
    // strings (each its own per-IP bucket) from bypassing the subnet cap.
    // The network bits are bytes rather than a u128 so the key is 17 bytes
    // instead of padding to 32.
    const SubnetKey = struct {
        family: enum(u8) { v4, v6, unparsed },
        bits: [16]u8,
    };

    comptime {
        std.debug.assert(@sizeOf(SubnetKey) == 17);
    }

    // cleanup() rebuilds a shard's map once fewer than 1/8 of its slots are
    // live, so a burst of distinct addresses does not pin its peak capacity.
    const shrink_min_capacity = 64;

    const Shard = struct {
        mutex: std.Io.Mutex,
        ip_buckets: std.StringHashMap(IpBucket),
        subnet_buckets: std.AutoHashMapUnmanaged(SubnetKey, IpBucket),
    };

    pub const Admission = enum { admitted, per_ip_limit, per_subnet_limit };

    pub fn init(allocator: std.mem.Allocator, max_connections_per_ip: u32, subnet: SubnetLimit) ConnectionLimiter {
        var effective = subnet;
        // A single address may always use its full per-IP allowance. Otherwise a
        // relay that raised max_connections_per_ip because every client arrives
        // from one proxy address would silently be capped at the subnet limit.
        if (effective.max_connections != 0) {
            effective.max_connections = @max(effective.max_connections, max_connections_per_ip);
        }
        var self: ConnectionLimiter = .{
            .allocator = allocator,
            .shards = undefined,
            .shard_seed = randomSeed(),
            .max_connections_per_ip = max_connections_per_ip,
            .subnet = effective,
            .cleanup_interval_seconds = 300,
        };
        for (&self.shards) |*shard| {
            shard.* = .{
                .mutex = .init,
                .ip_buckets = std.StringHashMap(IpBucket).init(allocator),
                .subnet_buckets = .empty,
            };
        }
        return self;
    }

    pub fn deinit(self: *ConnectionLimiter) void {
        for (&self.shards) |*shard| {
            var iter = shard.ip_buckets.keyIterator();
            while (iter.next()) |key| {
                self.allocator.free(key.*);
            }
            shard.ip_buckets.deinit();
            shard.subnet_buckets.deinit(self.allocator);
        }
    }

    pub fn canConnect(self: *ConnectionLimiter, raw_ip: []const u8) bool {
        const io = nostr.io.io();
        var key_buf: [19]u8 = undefined;
        const ip = bucketKey(raw_ip, &key_buf);
        const shard = &self.shards[shardIndex(self.shard_seed, ip)];

        shard.mutex.lockUncancelable(io);
        defer shard.mutex.unlock(io);

        if (shard.ip_buckets.get(ip)) |bucket| {
            return bucket.connection_count < self.max_connections_per_ip;
        }
        return self.max_connections_per_ip > 0;
    }

    /// Bool form of `acquire`.
    pub fn tryAcquireConnection(self: *ConnectionLimiter, raw_ip: []const u8) bool {
        return self.acquire(raw_ip) == .admitted;
    }

    /// Take a slot in both the per-IP and the subnet bucket, or in neither.
    /// Each bucket is checked and incremented in one locked section, closing the
    /// check-then-act race. If the subnet is full the per-IP slot is given back;
    /// in that window a concurrent acquire from the same IP may be refused, but
    /// nothing is ever admitted over a cap. Release with `removeConnection`.
    pub fn acquire(self: *ConnectionLimiter, raw_ip: []const u8) Admission {
        if (!self.acquireIp(raw_ip)) return .per_ip_limit;
        if (self.subnet.max_connections != 0 and !self.acquireSubnet(self.subnetKey(raw_ip))) {
            _ = self.releaseIp(raw_ip);
            return .per_subnet_limit;
        }
        return .admitted;
    }

    /// Give back both slots taken by a successful `acquire`. The subnet slot is
    /// released only when a per-IP slot was, so an unmatched call cannot free a
    /// slot held by another address in the subnet.
    pub fn removeConnection(self: *ConnectionLimiter, raw_ip: []const u8) void {
        if (!self.releaseIp(raw_ip)) return;
        if (self.subnet.max_connections != 0) self.releaseSubnet(self.subnetKey(raw_ip));
    }

    fn acquireIp(self: *ConnectionLimiter, raw_ip: []const u8) bool {
        const io = nostr.io.io();
        var key_buf: [19]u8 = undefined;
        const ip = bucketKey(raw_ip, &key_buf);
        const shard = &self.shards[shardIndex(self.shard_seed, ip)];

        shard.mutex.lockUncancelable(io);
        defer shard.mutex.unlock(io);

        const now = nostr.io.timestamp();

        // A cap of 0 admits no one, a new address included.
        if (self.max_connections_per_ip == 0) return false;

        if (shard.ip_buckets.getPtr(ip)) |bucket| {
            if (bucket.connection_count >= self.max_connections_per_ip) return false;
            bucket.connection_count += 1;
            bucket.last_activity = now;
            return true;
        }

        const ip_copy = self.allocator.dupe(u8, ip) catch return false;
        shard.ip_buckets.put(ip_copy, .{
            .connection_count = 1,
            .last_activity = now,
        }) catch {
            self.allocator.free(ip_copy);
            return false;
        };
        return true;
    }

    /// Whether a slot was held and given back.
    fn releaseIp(self: *ConnectionLimiter, raw_ip: []const u8) bool {
        const io = nostr.io.io();
        var key_buf: [19]u8 = undefined;
        const ip = bucketKey(raw_ip, &key_buf);
        const shard = &self.shards[shardIndex(self.shard_seed, ip)];

        shard.mutex.lockUncancelable(io);
        defer shard.mutex.unlock(io);

        const bucket = shard.ip_buckets.getPtr(ip) orelse return false;
        if (bucket.connection_count == 0) return false;
        bucket.connection_count -= 1;
        return true;
    }

    fn subnetKey(self: *const ConnectionLimiter, raw_ip: []const u8) SubnetKey {
        const addr = ip_match.parseAddr(raw_ip) orelse return .{ .family = .unparsed, .bits = @splat(0) };
        return switch (addr.family) {
            .v4 => .{ .family = .v4, .bits = @bitCast(addr.prefix(self.subnet.prefix_v4).bits) },
            .v6 => .{ .family = .v6, .bits = @bitCast(addr.prefix(self.subnet.prefix_v6).bits) },
        };
    }

    fn subnetShard(self: *ConnectionLimiter, key: SubnetKey) *Shard {
        var h = std.hash.Wyhash.init(self.shard_seed);
        h.update(&.{@backingInt(key.family)});
        h.update(&key.bits);
        return &self.shards[h.final() % SHARD_COUNT];
    }

    fn acquireSubnet(self: *ConnectionLimiter, key: SubnetKey) bool {
        const io = nostr.io.io();
        const shard = self.subnetShard(key);

        shard.mutex.lockUncancelable(io);
        defer shard.mutex.unlock(io);

        const gop = shard.subnet_buckets.getOrPut(self.allocator, key) catch return false;
        if (gop.found_existing) {
            if (gop.value_ptr.connection_count >= self.subnet.max_connections) return false;
        } else {
            gop.value_ptr.* = .{ .connection_count = 0, .last_activity = 0 };
        }
        gop.value_ptr.connection_count += 1;
        gop.value_ptr.last_activity = nostr.io.timestamp();
        return true;
    }

    fn releaseSubnet(self: *ConnectionLimiter, key: SubnetKey) void {
        const io = nostr.io.io();
        const shard = self.subnetShard(key);

        shard.mutex.lockUncancelable(io);
        defer shard.mutex.unlock(io);

        if (shard.subnet_buckets.getPtr(key)) |bucket| {
            if (bucket.connection_count > 0) {
                bucket.connection_count -= 1;
            }
        }
    }

    pub fn cleanup(self: *ConnectionLimiter) void {
        const io = nostr.io.io();
        const now = nostr.io.timestamp();

        for (&self.shards) |*shard| {
            shard.mutex.lockUncancelable(io);
            defer shard.mutex.unlock(io);

            var to_remove: std.ArrayListUnmanaged([]const u8) = .empty;
            defer to_remove.deinit(self.allocator);

            var iter = shard.ip_buckets.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.connection_count == 0 and
                    now - entry.value_ptr.last_activity > self.cleanup_interval_seconds)
                {
                    to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
                }
            }

            for (to_remove.items) |key| {
                _ = shard.ip_buckets.remove(key);
                self.allocator.free(key);
            }

            var subnet_remove: std.ArrayListUnmanaged(SubnetKey) = .empty;
            defer subnet_remove.deinit(self.allocator);

            var subnet_iter = shard.subnet_buckets.iterator();
            while (subnet_iter.next()) |entry| {
                if (entry.value_ptr.connection_count == 0 and
                    now - entry.value_ptr.last_activity > self.cleanup_interval_seconds)
                {
                    subnet_remove.append(self.allocator, entry.key_ptr.*) catch continue;
                }
            }

            for (subnet_remove.items) |key| {
                _ = shard.subnet_buckets.remove(key);
            }

            shrinkIfSparse(self.allocator, &shard.ip_buckets.unmanaged);
            shrinkIfSparse(self.allocator, &shard.subnet_buckets);
        }
    }

    /// Release a map's storage once it is mostly empty: free it outright when
    /// no entries are left, otherwise move the entries into a map sized to them.
    /// Keys and values move as they are, so owned keys stay owned. On allocation
    /// failure the map is left as it was. Caller holds the shard lock.
    fn shrinkIfSparse(allocator: std.mem.Allocator, map: anytype) void {
        const cap = map.capacity();
        const live = map.count();
        if (cap <= shrink_min_capacity or live >= cap / 8) return;
        if (live == 0) {
            map.clearAndFree(allocator);
            return;
        }
        var fresh: @TypeOf(map.*) = .empty;
        fresh.ensureTotalCapacity(allocator, live) catch return;
        var iter = map.iterator();
        while (iter.next()) |entry| fresh.putAssumeCapacityNoClobber(entry.key_ptr.*, entry.value_ptr.*);
        map.deinit(allocator);
        map.* = fresh;
    }

    pub fn getStats(self: *ConnectionLimiter) Stats {
        const io = nostr.io.io();
        var tracked: usize = 0;
        var subnets: usize = 0;
        for (&self.shards) |*shard| {
            shard.mutex.lockUncancelable(io);
            defer shard.mutex.unlock(io);
            tracked += shard.ip_buckets.count();
            subnets += shard.subnet_buckets.count();
        }
        return .{ .tracked_ips = tracked, .tracked_subnets = subnets };
    }

    pub const Stats = struct {
        tracked_ips: usize,
        tracked_subnets: usize,
    };

    // Locate the bucket for an IP so a test can backdate last_activity. Mirrors
    // EventRateLimiter.tracks: test-only, no lock (single-threaded tests).
    fn bucketPtrForTest(self: *ConnectionLimiter, raw_ip: []const u8) ?*IpBucket {
        var key_buf: [19]u8 = undefined;
        const ip = bucketKey(raw_ip, &key_buf);
        return self.shards[shardIndex(self.shard_seed, ip)].ip_buckets.getPtr(ip);
    }

    fn subnetCountForTest(self: *ConnectionLimiter, raw_ip: []const u8) u32 {
        const key = self.subnetKey(raw_ip);
        const bucket = self.subnetShard(key).subnet_buckets.get(key) orelse return 0;
        return bucket.connection_count;
    }
};

test "ConnectionLimiter cleanup reclaims only idle buckets across shards" {
    var limiter = ConnectionLimiter.init(std.testing.allocator, 5, .{});
    defer limiter.deinit();

    // Track four IPs. With a per-process seed they spread across shards, and
    // cleanup() sweeps every shard, so the assertion holds regardless of layout.
    try std.testing.expect(limiter.tryAcquireConnection("1.1.1.1"));
    try std.testing.expect(limiter.tryAcquireConnection("2.2.2.2"));
    try std.testing.expect(limiter.tryAcquireConnection("3.3.3.3"));
    try std.testing.expect(limiter.tryAcquireConnection("4.4.4.4"));
    try std.testing.expectEqual(@as(usize, 4), limiter.getStats().tracked_ips);

    const now = nostr.io.timestamp();

    // Two IPs go idle (count 0) and stale (last_activity older than the 300s
    // cleanup interval): these must be reclaimed.
    limiter.removeConnection("1.1.1.1");
    limiter.removeConnection("2.2.2.2");
    limiter.bucketPtrForTest("1.1.1.1").?.last_activity = now - 400;
    limiter.bucketPtrForTest("2.2.2.2").?.last_activity = now - 400;

    // 3.3.3.3 stays active (count > 0). 4.4.4.4 is idle but recent. Both remain.
    limiter.removeConnection("4.4.4.4");
    limiter.bucketPtrForTest("4.4.4.4").?.last_activity = now;

    limiter.cleanup();

    try std.testing.expectEqual(@as(usize, 2), limiter.getStats().tracked_ips);

    // A fresh limiter tracks nothing.
    var empty = ConnectionLimiter.init(std.testing.allocator, 5, .{});
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.getStats().tracked_ips);
}

test "ConnectionLimiter subnet cap bounds a /24 while other /24s still connect" {
    var limiter = ConnectionLimiter.init(std.testing.allocator, 2, .{ .max_connections = 5 });
    defer limiter.deinit();

    // Five distinct addresses in 185.220.100.0/24, each under its per-IP cap of 2.
    var buf: [32]u8 = undefined;
    for (1..6) |i| {
        const ip = try std.fmt.bufPrint(&buf, "185.220.100.{d}", .{i});
        try std.testing.expectEqual(ConnectionLimiter.Admission.admitted, limiter.acquire(ip));
    }
    // A sixth address in the same /24 is refused by the subnet cap, and the
    // per-IP slot it briefly took is given back.
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_subnet_limit, limiter.acquire("185.220.100.200"));
    try std.testing.expectEqual(@as(u32, 0), limiter.bucketPtrForTest("185.220.100.200").?.connection_count);
    try std.testing.expectEqual(@as(u32, 5), limiter.subnetCountForTest("185.220.100.0"));

    // The neighbouring /24 is a separate subnet.
    try std.testing.expectEqual(ConnectionLimiter.Admission.admitted, limiter.acquire("185.220.101.1"));

    // Releasing one connection frees a subnet slot.
    limiter.removeConnection("185.220.100.3");
    try std.testing.expectEqual(ConnectionLimiter.Admission.admitted, limiter.acquire("185.220.100.200"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_subnet_limit, limiter.acquire("185.220.100.201"));
}

test "ConnectionLimiter per-IP cap still applies under the subnet cap" {
    var limiter = ConnectionLimiter.init(std.testing.allocator, 2, .{ .max_connections = 50 });
    defer limiter.deinit();

    try std.testing.expect(limiter.tryAcquireConnection("10.0.0.1"));
    try std.testing.expect(limiter.tryAcquireConnection("10.0.0.1"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_ip_limit, limiter.acquire("10.0.0.1"));
    // A per-IP rejection takes no subnet slot.
    try std.testing.expectEqual(@as(u32, 2), limiter.subnetCountForTest("10.0.0.1"));
    try std.testing.expect(limiter.tryAcquireConnection("10.0.0.2"));

    // Every release gives back both slots, so after a full drain the /24 is empty.
    limiter.removeConnection("10.0.0.1");
    limiter.removeConnection("10.0.0.1");
    limiter.removeConnection("10.0.0.2");
    try std.testing.expectEqual(@as(u32, 0), limiter.subnetCountForTest("10.0.0.1"));
    try std.testing.expect(limiter.canConnect("10.0.0.1"));
}

test "ConnectionLimiter subnet cap is never below the per-IP cap" {
    // All clients behind one proxy address: the per-IP cap still governs.
    var limiter = ConnectionLimiter.init(std.testing.allocator, 8, .{ .max_connections = 3 });
    defer limiter.deinit();
    for (0..8) |_| try std.testing.expect(limiter.tryAcquireConnection("127.0.0.1"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_ip_limit, limiter.acquire("127.0.0.1"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_subnet_limit, limiter.acquire("127.0.0.2"));
}

test "ConnectionLimiter counts IPv4-mapped clients in the IPv4 subnet" {
    var limiter = ConnectionLimiter.init(std.testing.allocator, 1, .{ .max_connections = 2 });
    defer limiter.deinit();

    try std.testing.expect(limiter.tryAcquireConnection("192.42.116.1"));
    try std.testing.expect(limiter.tryAcquireConnection("::ffff:192.42.116.2"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_subnet_limit, limiter.acquire("192.42.116.3"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_subnet_limit, limiter.acquire("::ffff:c02a:7404"));

    limiter.removeConnection("::ffff:192.42.116.2");
    try std.testing.expect(limiter.tryAcquireConnection("192.42.116.3"));
}

test "ConnectionLimiter groups IPv6 clients by the configured prefix" {
    var limiter = ConnectionLimiter.init(std.testing.allocator, 1, .{ .max_connections = 2 });
    defer limiter.deinit();

    // Different /64s, so distinct per-IP buckets, but one /48.
    try std.testing.expect(limiter.tryAcquireConnection("2001:db8:1:1::1"));
    try std.testing.expect(limiter.tryAcquireConnection("2001:db8:1:2::1"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_subnet_limit, limiter.acquire("2001:db8:1:3::1"));
    try std.testing.expect(limiter.tryAcquireConnection("2001:db8:2::1"));
    // IPv6 and IPv4 subnets never share a bucket, even with equal low bits.
    try std.testing.expect(limiter.tryAcquireConnection("0.0.0.1"));
    try std.testing.expect(limiter.tryAcquireConnection("::1"));
}

test "ConnectionLimiter pools unparseable client IPs into one subnet" {
    var limiter = ConnectionLimiter.init(std.testing.allocator, 1, .{ .max_connections = 2 });
    defer limiter.deinit();

    try std.testing.expect(limiter.tryAcquireConnection("garbage-1"));
    try std.testing.expect(limiter.tryAcquireConnection("unknown"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_subnet_limit, limiter.acquire("garbage-2"));
    limiter.removeConnection("unknown");
    try std.testing.expect(limiter.tryAcquireConnection("garbage-2"));
}

test "ConnectionLimiter subnet cap of 0 is disabled" {
    var limiter = ConnectionLimiter.init(std.testing.allocator, 1, .{ .max_connections = 0 });
    defer limiter.deinit();
    var buf: [32]u8 = undefined;
    for (0..200) |i| {
        const ip = try std.fmt.bufPrint(&buf, "45.66.35.{d}", .{i});
        try std.testing.expect(limiter.tryAcquireConnection(ip));
    }
    try std.testing.expectEqual(@as(usize, 0), limiter.getStats().tracked_subnets);
}

test "ConnectionLimiter cleanup reclaims idle subnet buckets" {
    var limiter = ConnectionLimiter.init(std.testing.allocator, 5, .{ .max_connections = 50 });
    defer limiter.deinit();

    try std.testing.expect(limiter.tryAcquireConnection("1.1.1.1"));
    try std.testing.expect(limiter.tryAcquireConnection("2.2.2.2"));
    try std.testing.expectEqual(@as(usize, 2), limiter.getStats().tracked_subnets);

    limiter.removeConnection("1.1.1.1");
    const key = limiter.subnetKey("1.1.1.1");
    limiter.subnetShard(key).subnet_buckets.getPtr(key).?.last_activity = nostr.io.timestamp() - 400;
    limiter.cleanup();

    // 2.2.2.0/24 still holds a connection and stays.
    try std.testing.expectEqual(@as(usize, 1), limiter.getStats().tracked_subnets);
    try std.testing.expectEqual(@as(u32, 1), limiter.subnetCountForTest("2.2.2.2"));
}

test "ConnectionLimiter unmatched removeConnection frees no other address's subnet slot" {
    var limiter = ConnectionLimiter.init(std.testing.allocator, 1, .{ .max_connections = 4 });
    defer limiter.deinit();

    try std.testing.expect(limiter.tryAcquireConnection("10.0.0.1"));
    try std.testing.expect(limiter.tryAcquireConnection("10.0.0.2"));
    limiter.removeConnection("10.0.0.1");
    // A second, unmatched release, and one for an address never seen.
    limiter.removeConnection("10.0.0.1");
    limiter.removeConnection("10.0.0.99");
    try std.testing.expectEqual(@as(u32, 1), limiter.subnetCountForTest("10.0.0.2"));

    // 10.0.0.2 still holds one of the four slots, so only three more fit.
    try std.testing.expect(limiter.tryAcquireConnection("10.0.0.3"));
    try std.testing.expect(limiter.tryAcquireConnection("10.0.0.4"));
    try std.testing.expect(limiter.tryAcquireConnection("10.0.0.5"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_subnet_limit, limiter.acquire("10.0.0.6"));
}

test "ConnectionLimiter per-IP cap of 0 admits no one" {
    var limiter = ConnectionLimiter.init(std.testing.allocator, 0, .{ .max_connections = 50 });
    defer limiter.deinit();

    try std.testing.expect(!limiter.canConnect("10.0.0.1"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_ip_limit, limiter.acquire("10.0.0.1"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_ip_limit, limiter.acquire("10.0.0.1"));
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_ip_limit, limiter.acquire("2001:db8::1"));
    const stats = limiter.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats.tracked_ips);
    try std.testing.expectEqual(@as(usize, 0), stats.tracked_subnets);
}

test "ConnectionLimiter cleanup shrinks maps left sparse by a burst" {
    var limiter = ConnectionLimiter.init(std.testing.allocator, 1, .{ .max_connections = 1, .prefix_v4 = 32 });
    defer limiter.deinit();
    // Every idle bucket is stale.
    limiter.cleanup_interval_seconds = -1;

    var buf: [32]u8 = undefined;
    for (0..4096) |i| {
        const ip = try std.fmt.bufPrint(&buf, "10.{d}.{d}.1", .{ i / 256, i % 256 });
        try std.testing.expect(limiter.tryAcquireConnection(ip));
    }
    for (2..4096) |i| {
        const ip = try std.fmt.bufPrint(&buf, "10.{d}.{d}.1", .{ i / 256, i % 256 });
        limiter.removeConnection(ip);
    }

    var cap_before: usize = 0;
    for (&limiter.shards) |*shard| cap_before += shard.ip_buckets.capacity() + shard.subnet_buckets.capacity();
    limiter.cleanup();
    var cap_after: usize = 0;
    for (&limiter.shards) |*shard| cap_after += shard.ip_buckets.capacity() + shard.subnet_buckets.capacity();
    try std.testing.expect(cap_after * 8 < cap_before);

    // The two live connections survive the rebuild with their counts.
    const stats = limiter.getStats();
    try std.testing.expectEqual(@as(usize, 2), stats.tracked_ips);
    try std.testing.expectEqual(@as(usize, 2), stats.tracked_subnets);
    try std.testing.expectEqual(ConnectionLimiter.Admission.per_ip_limit, limiter.acquire("10.0.0.1"));
    try std.testing.expectEqual(@as(u32, 1), limiter.subnetCountForTest("10.0.1.1"));

    limiter.removeConnection("10.0.0.1");
    limiter.removeConnection("10.0.1.1");

    // A fully drained burst frees each map outright.
    for (0..4096) |i| {
        const ip = try std.fmt.bufPrint(&buf, "10.{d}.{d}.1", .{ i / 256, i % 256 });
        try std.testing.expect(limiter.tryAcquireConnection(ip));
        limiter.removeConnection(ip);
    }
    limiter.cleanup();
    for (&limiter.shards) |*shard| {
        try std.testing.expectEqual(@as(u32, 0), shard.ip_buckets.capacity());
        try std.testing.expectEqual(@as(u32, 0), shard.subnet_buckets.capacity());
    }
}

/// Allow/deny lists of addresses and CIDR ranges; see ip_match.zig for the
/// entry syntax. Entries are parsed once at load.
pub const IpFilter = struct {
    allocator: std.mem.Allocator,
    whitelist: std.ArrayListUnmanaged(ip_match.Rule),
    blacklist: std.ArrayListUnmanaged(ip_match.Rule),
    whitelist_enabled: bool,
    mutex: std.Io.Mutex,

    pub fn init(allocator: std.mem.Allocator) IpFilter {
        return .{
            .allocator = allocator,
            .whitelist = .empty,
            .blacklist = .empty,
            .whitelist_enabled = false,
            .mutex = .init,
        };
    }

    pub fn deinit(self: *IpFilter) void {
        self.whitelist.deinit(self.allocator);
        self.blacklist.deinit(self.allocator);
    }

    pub fn loadWhitelist(self: *IpFilter, list: []const u8) !void {
        return self.loadInto(&self.whitelist, list, "allow list", true);
    }

    pub fn loadBlacklist(self: *IpFilter, list: []const u8) !void {
        return self.loadInto(&self.blacklist, list, "deny list", false);
    }

    fn loadInto(
        self: *IpFilter,
        rules: *std.ArrayListUnmanaged(ip_match.Rule),
        list: []const u8,
        name: []const u8,
        enables_whitelist: bool,
    ) !void {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        if (list.len == 0) return;

        if (enables_whitelist) self.whitelist_enabled = true;
        var iter = std.mem.splitScalar(u8, list, ',');
        while (iter.next()) |entry| {
            const trimmed = std.mem.trim(u8, entry, " \t");
            if (trimmed.len == 0) continue;
            // Refusing the entry and saying so beats storing one that quietly
            // never matches: the operator can act on a log line, not on silence.
            const rule = ip_match.parseRule(trimmed, .standard) orelse {
                var buf: [64]u8 = undefined;
                log.warn("{s} entry \"{s}\" is not a valid address, CIDR range or prefix ending in '.' or ':' and was ignored; '*' wildcards are not supported", .{ name, ip_match.safeEntry(trimmed, &buf) });
                continue;
            };
            try rules.append(self.allocator, rule);
        }
    }

    pub fn isAllowed(self: *IpFilter, ip: []const u8) bool {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const addr = ip_match.parseAddr(ip);
        if (addr) |a| {
            if (ip_match.anyMatch(self.blacklist.items, a)) return false;
        }

        if (self.whitelist_enabled) {
            const a = addr orelse return false;
            return ip_match.anyMatch(self.whitelist.items, a);
        }

        return true;
    }

    pub fn isTrustedProxy(self: *IpFilter, ip: []const u8) bool {
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        // An empty trusted-proxy set trusts every peer; otherwise only configured
        // addresses/ranges are honored.
        if (!self.whitelist_enabled) return true;
        const addr = ip_match.parseAddr(ip) orelse return false;
        return ip_match.anyMatch(self.whitelist.items, addr);
    }
};

pub fn extractClientIp(
    forwarded_for: ?[]const u8,
    real_ip: ?[]const u8,
    remote_addr: []const u8,
    trust_proxy: bool,
) []const u8 {
    if (trust_proxy) {
        // Prefer X-Forwarded-For: the trusted proxy appends the address it
        // actually received from, so the rightmost entry is proxy-controlled.
        // X-Real-IP is only a fallback because a client can set it when the proxy
        // does not, which would let it spoof the key used for every per-IP control.
        if (forwarded_for) |xff| {
            if (xff.len > 0) {
                const segment = if (std.mem.lastIndexOf(u8, xff, ",")) |comma|
                    xff[comma + 1 ..]
                else
                    xff;
                const entry = std.mem.trim(u8, segment, " \t");
                // A trailing comma or whitespace-only segment trims to empty; fall
                // back to X-Real-IP, then remote_addr, instead of one shared key.
                if (entry.len > 0) return normalizeIp(entry);
            }
        }

        if (real_ip) |ip| {
            if (ip.len > 0) {
                return normalizeIp(ip);
            }
        }
    }

    return normalizeIp(remote_addr);
}

// Derive the per-IP rate-limit bucket key. IPv6 clients are keyed on their /64
// prefix so a client rotating addresses within a single /64 allocation cannot get
// fresh allowance per address or bloat the bucket map. IPv4 and non-address
// strings pass through unchanged. `buf` backs the returned slice for the IPv6 case.
fn bucketKey(ip: []const u8, buf: *[19]u8) []const u8 {
    if (std.mem.count(u8, ip, ":") < 2) return ip;
    const addr = std.Io.net.Ip6Address.parse(ip, 0) catch return ip;
    const b = addr.bytes;

    // IPv4-mapped (::ffff:a.b.c.d): key on the embedded IPv4 so a dual-stack
    // listener does not collapse every IPv4 client into one /64 bucket.
    var zero_prefix = true;
    for (b[0..10]) |x| {
        if (x != 0) {
            zero_prefix = false;
            break;
        }
    }
    if (zero_prefix and b[10] == 0xff and b[11] == 0xff) {
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ b[12], b[13], b[14], b[15] }) catch ip;
    }

    const hex = std.fmt.bytesToHex(b[0..8].*, .lower);
    return std.fmt.bufPrint(buf, "{s}/64", .{hex}) catch ip;
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
    // Proxy headers ignored unless trust_proxy is set.
    try std.testing.expectEqualStrings("192.168.1.1", extractClientIp(null, null, "192.168.1.1:8080", false));
    try std.testing.expectEqualStrings("10.0.0.1", extractClientIp("1.2.3.4", null, "10.0.0.1:8080", false));
    // Trusted: rightmost X-Forwarded-For entry (the hop the proxy appended).
    try std.testing.expectEqualStrings("10.0.0.1", extractClientIp("1.2.3.4, 10.0.0.1", null, "127.0.0.1:8080", true));
    // X-Forwarded-For is preferred over client-settable X-Real-IP.
    try std.testing.expectEqualStrings("1.2.3.4", extractClientIp("1.2.3.4", "5.6.7.8", "127.0.0.1:8080", true));
    // X-Real-IP is used only when no X-Forwarded-For is present.
    try std.testing.expectEqualStrings("5.6.7.8", extractClientIp(null, "5.6.7.8", "127.0.0.1:8080", true));
}

test "IpFilter full address matches exactly, not as a prefix" {
    var f = IpFilter.init(std.testing.allocator);
    defer f.deinit();
    try f.loadWhitelist("10.0.0.5");
    try std.testing.expect(f.isAllowed("10.0.0.5"));
    // The bug: "10.0.0.5" must not admit "10.0.0.50"/"10.0.0.55".
    try std.testing.expect(!f.isAllowed("10.0.0.50"));
    try std.testing.expect(!f.isAllowed("10.0.0.55"));
}

test "IpFilter trailing-dot entry is an explicit subnet prefix" {
    var f = IpFilter.init(std.testing.allocator);
    defer f.deinit();
    try f.loadWhitelist("10.0.0.");
    try std.testing.expect(f.isAllowed("10.0.0.5"));
    try std.testing.expect(f.isAllowed("10.0.0.50"));
    try std.testing.expect(!f.isAllowed("10.0.1.5"));
}

test "IpFilter blacklist does not over-block on shared prefix" {
    var f = IpFilter.init(std.testing.allocator);
    defer f.deinit();
    try f.loadBlacklist("1.2.3.4");
    try std.testing.expect(!f.isAllowed("1.2.3.4"));
    try std.testing.expect(f.isAllowed("1.2.3.40"));
}

test "normalizeIp" {
    try std.testing.expectEqualStrings("192.168.1.1", normalizeIp("192.168.1.1:8080"));
    try std.testing.expectEqualStrings("::1", normalizeIp("[::1]:8080"));
    try std.testing.expectEqualStrings("192.168.1.1", normalizeIp("192.168.1.1"));
}

pub const EventRateLimiter = struct {
    allocator: std.mem.Allocator,
    shards: [SHARD_COUNT]Shard,
    shard_seed: u64,
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

    const Shard = struct {
        mutex: std.Io.Mutex,
        ip_buckets: std.StringHashMap(EventBucket),
    };

    pub fn init(allocator: std.mem.Allocator, events_per_minute: u32) EventRateLimiter {
        var self: EventRateLimiter = .{
            .allocator = allocator,
            .shards = undefined,
            .shard_seed = randomSeed(),
            .events_per_minute = events_per_minute,
        };
        for (&self.shards) |*shard| {
            shard.* = .{ .mutex = .init, .ip_buckets = std.StringHashMap(EventBucket).init(allocator) };
        }
        return self;
    }

    pub fn deinit(self: *EventRateLimiter) void {
        for (&self.shards) |*shard| {
            var iter = shard.ip_buckets.keyIterator();
            while (iter.next()) |key| {
                self.allocator.free(key.*);
            }
            shard.ip_buckets.deinit();
        }
    }

    pub fn checkAndRecord(self: *EventRateLimiter, ip: []const u8) bool {
        if (self.events_per_minute == 0) return true;
        var buf: [19]u8 = undefined;
        return self.checkAndRecordAt(bucketKey(ip, &buf), nostr.io.timestamp());
    }

    fn checkAndRecordAt(self: *EventRateLimiter, ip: []const u8, now: i64) bool {
        const io = nostr.io.io();
        const shard = &self.shards[shardIndex(self.shard_seed, ip)];
        shard.mutex.lockUncancelable(io);
        defer shard.mutex.unlock(io);

        const capacity: f64 = @floatFromInt(self.events_per_minute);
        const refill_per_sec: f64 = capacity / 60.0;

        if (shard.ip_buckets.getPtr(ip)) |bucket| {
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
        shard.ip_buckets.put(ip_copy, .{
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

        for (&self.shards) |*shard| {
            shard.mutex.lockUncancelable(io);
            defer shard.mutex.unlock(io);

            var to_remove: std.ArrayListUnmanaged([]const u8) = .empty;
            defer to_remove.deinit(self.allocator);

            var iter = shard.ip_buckets.iterator();
            while (iter.next()) |entry| {
                if (now - entry.value_ptr.last_refill >= IDLE_SECONDS) {
                    to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
                }
            }

            for (to_remove.items) |key| {
                _ = shard.ip_buckets.remove(key);
                self.allocator.free(key);
            }
        }
    }

    // Total tracked IPs across all shards. Test-only helper; the sharded map has
    // no single count() to assert against.
    fn trackedCount(self: *EventRateLimiter) usize {
        var total: usize = 0;
        for (&self.shards) |*shard| total += shard.ip_buckets.count();
        return total;
    }

    fn tracks(self: *EventRateLimiter, ip: []const u8) bool {
        return self.shards[shardIndex(self.shard_seed, ip)].ip_buckets.contains(ip);
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
    try std.testing.expectEqual(@as(usize, 2), limiter.trackedCount());

    // At t=1060, the first bucket hits IDLE_SECONDS and is removed; the second
    // (idle 10s) is retained.
    limiter.cleanupAt(1060);
    try std.testing.expectEqual(@as(usize, 1), limiter.trackedCount());
    try std.testing.expect(limiter.tracks("2.2.2.2"));
}

test "IpFilter blacklist accepts CIDR alongside legacy prefixes and addresses" {
    var f = IpFilter.init(std.testing.allocator);
    defer f.deinit();

    // The incident list as one CIDR, next to an existing legacy-prefix config.
    try f.loadBlacklist("185.220.100.0/22, 45.9.148., 1.2.3.4, 2001:db8::/32, fe80:");
    try std.testing.expect(!f.isAllowed("185.220.100.1"));
    try std.testing.expect(!f.isAllowed("185.220.103.254"));
    try std.testing.expect(f.isAllowed("185.220.104.1"));
    try std.testing.expect(!f.isAllowed("45.9.148.200"));
    try std.testing.expect(f.isAllowed("45.9.149.1"));
    try std.testing.expect(!f.isAllowed("1.2.3.4"));
    try std.testing.expect(f.isAllowed("1.2.3.40"));
    // IPv6 subnets can be blocked, and mapped IPv4 hits the IPv4 rules.
    try std.testing.expect(!f.isAllowed("2001:db8:1::1"));
    try std.testing.expect(f.isAllowed("2001:db9::1"));
    try std.testing.expect(!f.isAllowed("fe80::1"));
    try std.testing.expect(!f.isAllowed("::ffff:185.220.101.9"));
}

test "IpFilter whitelist with CIDR" {
    var f = IpFilter.init(std.testing.allocator);
    defer f.deinit();
    try f.loadWhitelist("10.0.0.0/8, ::1");
    try std.testing.expect(f.isAllowed("10.200.3.4"));
    try std.testing.expect(f.isAllowed("::ffff:10.0.0.1"));
    try std.testing.expect(f.isAllowed("::1"));
    try std.testing.expect(!f.isAllowed("11.0.0.1"));
    try std.testing.expect(!f.isAllowed("::2"));
    // A client address that does not parse cannot be on an allow list.
    try std.testing.expect(!f.isAllowed("unknown"));
}

test "IpFilter trusted proxies with CIDR" {
    var f = IpFilter.init(std.testing.allocator);
    defer f.deinit();
    try std.testing.expect(f.isTrustedProxy("8.8.8.8"));
    try f.loadWhitelist("172.16.0.0/12");
    try std.testing.expect(f.isTrustedProxy("172.31.255.255"));
    try std.testing.expect(!f.isTrustedProxy("172.32.0.0"));
    try std.testing.expect(!f.isTrustedProxy("unknown"));
}

test "IpFilter malformed entries are ignored, not stored" {
    var f = IpFilter.init(std.testing.allocator);
    defer f.deinit();

    // Globs and bad CIDR are dropped with a warning; the usable entry still works.
    try f.loadBlacklist("192.168.*, 10.0.0.0/33, example.com, 1.2.3.4");
    try std.testing.expectEqual(@as(usize, 1), f.blacklist.items.len);
    try std.testing.expect(!f.isAllowed("1.2.3.4"));
    try std.testing.expect(f.isAllowed("192.168.1.1"));
    try std.testing.expect(f.isAllowed("10.1.2.3"));

    // An allow list whose every entry is malformed still enables the allow list,
    // so it fails closed rather than admitting everyone.
    var g = IpFilter.init(std.testing.allocator);
    defer g.deinit();
    try g.loadWhitelist("192.168.*");
    try std.testing.expect(!g.isAllowed("192.168.1.1"));
}
