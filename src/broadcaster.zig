const std = @import("std");
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const nostr = @import("nostr.zig");

pub const Broadcaster = struct {
    subs: *Subscriptions,

    pub fn init(
        _: std.mem.Allocator,
        subs: *Subscriptions,
        _: *const fn (conn_id: u64, data: []const u8) void,
    ) Broadcaster {
        return .{
            .subs = subs,
        };
    }

    pub fn broadcast(self: *Broadcaster, event: *const nostr.Event) void {
        var msg_buf: [65536]u8 = undefined;
        self.subs.forEachMatching(event, &msg_buf);
    }
};
