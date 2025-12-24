const std = @import("std");
const net = std.net;

pub const WriteFn = *const fn (ctx: *anyopaque, data: []const u8) void;

pub const WriteQueue = struct {
    write_fn: ?WriteFn,
    write_ctx: ?*anyopaque,
    dropped_count: std.atomic.Value(u64),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) WriteQueue {
        return .{
            .write_fn = null,
            .write_ctx = null,
            .dropped_count = std.atomic.Value(u64).init(0),
            .allocator = allocator,
        };
    }

    pub fn start(self: *WriteQueue, write_fn: WriteFn, write_ctx: *anyopaque) void {
        self.write_fn = write_fn;
        self.write_ctx = write_ctx;
    }

    pub fn stop(self: *WriteQueue) void {
        self.write_fn = null;
        self.write_ctx = null;
    }

    pub fn enqueue(self: *WriteQueue, data: []const u8) bool {
        const write_fn = self.write_fn orelse {
            _ = self.dropped_count.fetchAdd(1, .monotonic);
            return false;
        };
        const ctx = self.write_ctx orelse {
            _ = self.dropped_count.fetchAdd(1, .monotonic);
            return false;
        };
        write_fn(ctx, data);
        return true;
    }

    pub fn droppedCount(self: *WriteQueue) u64 {
        return self.dropped_count.load(.monotonic);
    }

    pub fn queueDepth(_: *WriteQueue) usize {
        return 0;
    }
};
