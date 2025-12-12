const std = @import("std");

pub const QueryCache = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMap(CacheKey, CacheEntry),
    access_order: std.ArrayListUnmanaged(CacheKey),
    max_entries: usize,
    mutex: std.Thread.Mutex,
    hits: u64 = 0,
    misses: u64 = 0,
    generation: u64 = 0,

    const CacheKey = struct {
        kind: i32,
        limit: u32,
    };

    const CacheEntry = struct {
        results: [][]const u8,
        generation: u64,
        timestamp: i64,
    };

    const TTL_SECONDS: i64 = 5;
    const MAX_ENTRIES: usize = 64;

    pub fn init(allocator: std.mem.Allocator) QueryCache {
        return .{
            .allocator = allocator,
            .entries = std.AutoHashMap(CacheKey, CacheEntry).init(allocator),
            .access_order = .{},
            .max_entries = MAX_ENTRIES,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *QueryCache) void {
        var iter = self.entries.valueIterator();
        while (iter.next()) |entry| {
            for (entry.results) |result| {
                self.allocator.free(result);
            }
            self.allocator.free(entry.results);
        }
        self.entries.deinit();
        self.access_order.deinit(self.allocator);
    }

    pub fn get(self: *QueryCache, kind: i32, limit: u32) ?[]const []const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = CacheKey{ .kind = kind, .limit = limit };
        if (self.entries.get(key)) |entry| {
            const now = std.time.timestamp();
            if (now - entry.timestamp <= TTL_SECONDS and entry.generation == self.generation) {
                self.hits += 1;
                return entry.results;
            }
            self.removeEntry(key);
        }
        self.misses += 1;
        return null;
    }

    pub fn put(self: *QueryCache, kind: i32, limit: u32, results: []const []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = CacheKey{ .kind = kind, .limit = limit };

        if (self.entries.count() >= self.max_entries) {
            self.evictOldest();
        }

        const results_copy = self.allocator.alloc([]const u8, results.len) catch return;
        for (results, 0..) |result, i| {
            results_copy[i] = self.allocator.dupe(u8, result) catch {
                for (0..i) |j| {
                    self.allocator.free(results_copy[j]);
                }
                self.allocator.free(results_copy);
                return;
            };
        }

        self.removeEntry(key);

        self.entries.put(key, .{
            .results = results_copy,
            .generation = self.generation,
            .timestamp = std.time.timestamp(),
        }) catch return;

        self.access_order.append(self.allocator, key) catch {};
    }

    pub fn invalidate(self: *QueryCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.generation +%= 1;
    }

    fn removeEntry(self: *QueryCache, key: CacheKey) void {
        if (self.entries.fetchRemove(key)) |kv| {
            for (kv.value.results) |result| {
                self.allocator.free(result);
            }
            self.allocator.free(kv.value.results);
        }

        for (self.access_order.items, 0..) |k, i| {
            if (k.kind == key.kind and k.limit == key.limit) {
                _ = self.access_order.orderedRemove(i);
                break;
            }
        }
    }

    fn evictOldest(self: *QueryCache) void {
        if (self.access_order.items.len == 0) return;
        const oldest_key = self.access_order.orderedRemove(0);
        if (self.entries.fetchRemove(oldest_key)) |kv| {
            for (kv.value.results) |result| {
                self.allocator.free(result);
            }
            self.allocator.free(kv.value.results);
        }
    }

    pub fn stats(self: *QueryCache) struct { hits: u64, misses: u64, entries: usize } {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .hits = self.hits,
            .misses = self.misses,
            .entries = self.entries.count(),
        };
    }
};
