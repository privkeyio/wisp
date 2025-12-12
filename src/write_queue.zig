const std = @import("std");
const httpz = @import("httpz");
const websocket = httpz.websocket;

pub const WriteQueue = struct {
    ws_conn: ?*websocket.Conn,
    dropped_count: std.atomic.Value(u64),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) WriteQueue {
        return .{
            .ws_conn = null,
            .dropped_count = std.atomic.Value(u64).init(0),
            .allocator = allocator,
        };
    }

    pub fn start(self: *WriteQueue, ws_conn: *websocket.Conn) void {
        self.ws_conn = ws_conn;
    }

    pub fn stop(self: *WriteQueue) void {
        self.ws_conn = null;
    }

    pub fn enqueue(self: *WriteQueue, data: []const u8) bool {
        if (self.ws_conn) |conn| {
            conn.write(data) catch {
                _ = self.dropped_count.fetchAdd(1, .monotonic);
                return false;
            };
            return true;
        }
        _ = self.dropped_count.fetchAdd(1, .monotonic);
        return false;
    }

    pub fn droppedCount(self: *WriteQueue) u64 {
        return self.dropped_count.load(.monotonic);
    }

    pub fn queueDepth(_: *WriteQueue) usize {
        return 0; // No queue
    }
};
