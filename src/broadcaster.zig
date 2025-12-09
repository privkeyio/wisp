const std = @import("std");
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const nostr = @import("nostr.zig");

pub const Broadcaster = struct {
    allocator: std.mem.Allocator,
    subs: *Subscriptions,
    send_fn: *const fn (conn_id: u64, data: []const u8) void,

    pub fn init(
        allocator: std.mem.Allocator,
        subs: *Subscriptions,
        send_fn: *const fn (conn_id: u64, data: []const u8) void,
    ) Broadcaster {
        return .{
            .allocator = allocator,
            .subs = subs,
            .send_fn = send_fn,
        };
    }

    pub fn broadcast(self: *Broadcaster, event: *const nostr.Event) void {
        const candidates = self.subs.getCandidates(event) catch return;
        defer self.allocator.free(candidates);

        for (candidates) |conn| {
            if (conn.matchesEvent(event)) |sub_id| {
                var buf: [65536]u8 = undefined;
                const msg = nostr.RelayMsg.event(sub_id, event, &buf) catch continue;

                self.send_fn(conn.id, msg);
                conn.events_sent += 1;
            }
        }
    }
};
