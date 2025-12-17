const std = @import("std");
const httpz = @import("httpz");
const websocket = httpz.websocket;

pub const WriteQueue = struct {
    ws_conn: std.atomic.Value(?*websocket.Conn),
    dropped_count: std.atomic.Value(u64),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) WriteQueue {
        return .{
            .ws_conn = std.atomic.Value(?*websocket.Conn).init(null),
            .dropped_count = std.atomic.Value(u64).init(0),
            .allocator = allocator,
        };
    }

    pub fn start(self: *WriteQueue, ws_conn: *websocket.Conn) void {
        self.ws_conn.store(ws_conn, .release);
    }

    pub fn stop(self: *WriteQueue) void {
        self.ws_conn.store(null, .release);
    }

    pub fn enqueue(self: *WriteQueue, data: []const u8) bool {
        const conn = self.ws_conn.load(.acquire) orelse {
            _ = self.dropped_count.fetchAdd(1, .monotonic);
            return false;
        };
        conn.write(data) catch {
            _ = self.dropped_count.fetchAdd(1, .monotonic);
            return false;
        };
        return true;
    }

    pub fn droppedCount(self: *WriteQueue) u64 {
        return self.dropped_count.load(.monotonic);
    }

    pub fn queueDepth(_: *WriteQueue) usize {
        return 0; // No queue
    }
};
