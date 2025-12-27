const std = @import("std");

pub const WriteFn = *const fn (ctx: *anyopaque, data: []const u8) void;

const QueuedMessage = struct {
    data: []const u8,
    allocator: std.mem.Allocator,

    fn deinit(self: *QueuedMessage) void {
        self.allocator.free(self.data);
    }
};

pub const WriteQueue = struct {
    messages: std.ArrayListUnmanaged(QueuedMessage),
    mutex: std.Thread.Mutex,
    not_empty: std.Thread.Condition,
    closed: std.atomic.Value(bool),
    stopped: std.atomic.Value(bool),
    write_thread: ?std.Thread,
    write_fn: ?WriteFn,
    write_ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    dropped_count: std.atomic.Value(u64),
    max_queue_size: usize,

    pub fn init(allocator: std.mem.Allocator) WriteQueue {
        return .{
            .messages = .{},
            .mutex = .{},
            .not_empty = .{},
            .closed = std.atomic.Value(bool).init(false),
            .stopped = std.atomic.Value(bool).init(true),
            .write_thread = null,
            .write_fn = null,
            .write_ctx = null,
            .allocator = allocator,
            .dropped_count = std.atomic.Value(u64).init(0),
            .max_queue_size = 1024,
        };
    }

    pub fn start(self: *WriteQueue, write_fn: WriteFn, write_ctx: *anyopaque) void {
        // Guard against double-start: if already running, return early
        if (!self.stopped.load(.acquire)) {
            return;
        }

        self.write_fn = write_fn;
        self.write_ctx = write_ctx;
        self.closed.store(false, .release);
        // Note: stopped remains true until spawn succeeds
        self.write_thread = std.Thread.spawn(.{}, writeLoop, .{self}) catch |err| {
            std.log.err("WriteQueue: failed to spawn write thread: {}", .{err});
            // Restore state so enqueue is blocked
            self.closed.store(true, .release);
            self.stopped.store(true, .release);
            self.write_thread = null;
            return;
        };
        // Only mark as running after spawn succeeds
        self.stopped.store(false, .release);
    }

    pub fn stop(self: *WriteQueue) void {
        if (self.stopped.swap(true, .acq_rel)) {
            return;
        }

        self.closed.store(true, .release);

        self.mutex.lock();
        self.not_empty.signal();
        self.mutex.unlock();

        if (self.write_thread) |t| {
            t.join();
            self.write_thread = null;
        }

        self.mutex.lock();
        for (self.messages.items) |*msg| {
            msg.deinit();
        }
        self.messages.clearAndFree(self.allocator);
        self.mutex.unlock();

        self.write_fn = null;
        self.write_ctx = null;
    }

    pub fn enqueue(self: *WriteQueue, data: []const u8) bool {
        if (self.closed.load(.acquire)) {
            _ = self.dropped_count.fetchAdd(1, .monotonic);
            return false;
        }

        const copy = self.allocator.dupe(u8, data) catch {
            _ = self.dropped_count.fetchAdd(1, .monotonic);
            return false;
        };

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed.load(.acquire)) {
            self.allocator.free(copy);
            _ = self.dropped_count.fetchAdd(1, .monotonic);
            return false;
        }

        if (self.messages.items.len >= self.max_queue_size) {
            self.allocator.free(copy);
            _ = self.dropped_count.fetchAdd(1, .monotonic);
            return false;
        }

        self.messages.append(self.allocator, .{
            .data = copy,
            .allocator = self.allocator,
        }) catch {
            self.allocator.free(copy);
            _ = self.dropped_count.fetchAdd(1, .monotonic);
            return false;
        };

        self.not_empty.signal();
        return true;
    }

    fn writeLoop(self: *WriteQueue) void {
        while (true) {
            var batch: []QueuedMessage = &.{};

            {
                self.mutex.lock();
                defer self.mutex.unlock();

                while (self.messages.items.len == 0 and !self.closed.load(.acquire)) {
                    self.not_empty.wait(&self.mutex);
                }

                if (self.closed.load(.acquire) and self.messages.items.len == 0) {
                    return;
                }

                batch = self.messages.toOwnedSlice(self.allocator) catch return;
            }

            const write_fn = self.write_fn orelse {
                for (batch) |*msg| msg.deinit();
                self.allocator.free(batch);
                continue;
            };
            const ctx = self.write_ctx orelse {
                for (batch) |*msg| msg.deinit();
                self.allocator.free(batch);
                continue;
            };

            for (batch) |*msg| {
                write_fn(ctx, msg.data);
                msg.deinit();
            }
            self.allocator.free(batch);
        }
    }

    pub fn droppedCount(self: *WriteQueue) u64 {
        return self.dropped_count.load(.monotonic);
    }

    pub fn queueDepth(self: *WriteQueue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.messages.items.len;
    }
};

const TestContext = struct {
    received: std.ArrayListUnmanaged([]const u8),
    mutex: std.Thread.Mutex,
    allocator: std.mem.Allocator,

    fn write(ctx: *anyopaque, data: []const u8) void {
        const self: *TestContext = @ptrCast(@alignCast(ctx));
        self.mutex.lock();
        defer self.mutex.unlock();
        const copy = self.allocator.dupe(u8, data) catch return;
        self.received.append(self.allocator, copy) catch {
            self.allocator.free(copy);
        };
    }

    fn deinit(self: *TestContext) void {
        for (self.received.items) |item| self.allocator.free(item);
        self.received.deinit(self.allocator);
    }
};

test "WriteQueue basic functionality" {
    const allocator = std.testing.allocator;
    var queue = WriteQueue.init(allocator);

    var ctx = TestContext{
        .received = .{},
        .mutex = .{},
        .allocator = allocator,
    };
    defer ctx.deinit();

    queue.start(TestContext.write, @ptrCast(&ctx));
    defer queue.stop();

    try std.testing.expect(queue.enqueue("hello"));
    try std.testing.expect(queue.enqueue("world"));

    std.Thread.sleep(50 * std.time.ns_per_ms);

    ctx.mutex.lock();
    defer ctx.mutex.unlock();
    try std.testing.expectEqual(@as(usize, 2), ctx.received.items.len);
    try std.testing.expectEqualStrings("hello", ctx.received.items[0]);
    try std.testing.expectEqualStrings("world", ctx.received.items[1]);
}

test "WriteQueue drops messages when closed" {
    const allocator = std.testing.allocator;
    var queue = WriteQueue.init(allocator);

    const TestWriter = struct {
        fn write(_: *anyopaque, _: []const u8) void {}
    };

    queue.start(TestWriter.write, @ptrCast(&queue));
    queue.stop();

    try std.testing.expect(!queue.enqueue("should fail"));
    try std.testing.expectEqual(@as(u64, 1), queue.droppedCount());
}

const BlockingWriter = struct {
    started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    release: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn write(ctx: *anyopaque, _: []const u8) void {
        const self: *BlockingWriter = @ptrCast(@alignCast(ctx));
        self.started.store(true, .release);
        while (!self.release.load(.acquire)) {
            std.Thread.sleep(1 * std.time.ns_per_ms);
        }
    }
};

test "WriteQueue respects max queue size" {
    const allocator = std.testing.allocator;
    var queue = WriteQueue.init(allocator);
    queue.max_queue_size = 3;

    var blocker = BlockingWriter{};

    queue.start(BlockingWriter.write, @ptrCast(&blocker));
    defer {
        blocker.release.store(true, .release);
        queue.stop();
    }

    try std.testing.expect(queue.enqueue("1"));

    while (!blocker.started.load(.acquire)) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    try std.testing.expect(queue.enqueue("2"));
    try std.testing.expect(queue.enqueue("3"));
    try std.testing.expect(queue.enqueue("4"));
    try std.testing.expect(!queue.enqueue("5"));
    try std.testing.expect(queue.droppedCount() >= 1);
}

test "WriteQueue concurrent stop is safe" {
    const allocator = std.testing.allocator;
    var queue = WriteQueue.init(allocator);

    const NoopWriter = struct {
        fn write(_: *anyopaque, _: []const u8) void {}
    };

    queue.start(NoopWriter.write, @ptrCast(&queue));

    var threads: [4]?std.Thread = .{ null, null, null, null };
    for (&threads) |*t| {
        t.* = std.Thread.spawn(.{}, struct {
            fn run(q: *WriteQueue) void {
                q.stop();
            }
        }.run, .{&queue}) catch null;
    }

    for (threads) |t| {
        if (t) |thread| thread.join();
    }

    try std.testing.expect(queue.stopped.load(.acquire));
}
