//! Lightweight, lock-free operational metrics exposed in Prometheus text format
//! at GET /metrics. Counters are process-global atomics so any worker thread can
//! update them without coordination; the active-connections gauge is read live
//! from the subscription registry at scrape time.

const std = @import("std");

var connections_total = std.atomic.Value(u64).init(0);
var events_stored = std.atomic.Value(u64).init(0);
var events_rejected = std.atomic.Value(u64).init(0);
var events_broadcast = std.atomic.Value(u64).init(0);
var reqs_total = std.atomic.Value(u64).init(0);
var rate_limited = std.atomic.Value(u64).init(0);

pub fn connectionOpened() void {
    _ = connections_total.fetchAdd(1, .monotonic);
}

pub fn eventStored() void {
    _ = events_stored.fetchAdd(1, .monotonic);
}

pub fn eventRejected() void {
    _ = events_rejected.fetchAdd(1, .monotonic);
}

pub fn eventBroadcast(count: u64) void {
    if (count != 0) _ = events_broadcast.fetchAdd(count, .monotonic);
}

pub fn reqReceived() void {
    _ = reqs_total.fetchAdd(1, .monotonic);
}

pub fn rateLimited() void {
    _ = rate_limited.fetchAdd(1, .monotonic);
}

fn metric(w: anytype, name: []const u8, help: []const u8, kind: []const u8, value: u64) !void {
    try w.print("# HELP {s} {s}\n# TYPE {s} {s}\n{s} {d}\n", .{ name, help, name, kind, name, value });
}

/// Write all metrics in Prometheus exposition format. `active_connections` is the
/// live connection count, read from the registry by the caller at scrape time.
pub fn write(w: anytype, active_connections: u64) !void {
    try metric(w, "wisp_connections_total", "Total WebSocket connections accepted", "counter", connections_total.load(.monotonic));
    try metric(w, "wisp_connections_active", "Currently open WebSocket connections", "gauge", active_connections);
    try metric(w, "wisp_events_stored_total", "Events accepted and stored", "counter", events_stored.load(.monotonic));
    try metric(w, "wisp_events_rejected_total", "Events rejected (validation, auth, limits, PoW, ...)", "counter", events_rejected.load(.monotonic));
    try metric(w, "wisp_events_broadcast_total", "Events delivered to matching subscriptions", "counter", events_broadcast.load(.monotonic));
    try metric(w, "wisp_req_total", "REQ subscription messages received", "counter", reqs_total.load(.monotonic));
    try metric(w, "wisp_rate_limited_total", "Connections/events rejected by rate or connection limits", "counter", rate_limited.load(.monotonic));
}

test write {
    const conn_before = connections_total.load(.monotonic);
    const bcast_before = events_broadcast.load(.monotonic);

    connectionOpened();
    eventBroadcast(3);
    eventBroadcast(0); // no-op: a zero-recipient broadcast must not move the counter

    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, 7);
    const out = w.buffered();

    // Each metric emits HELP, TYPE, and a value line.
    try std.testing.expect(std.mem.indexOf(u8, out, "# HELP wisp_connections_total Total WebSocket connections accepted\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "# TYPE wisp_connections_total counter\n") != null);
    // The active-connections gauge reflects the caller-supplied live count.
    try std.testing.expect(std.mem.indexOf(u8, out, "# TYPE wisp_connections_active gauge\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "wisp_connections_active 7\n") != null);
    // Counters are process-global atomics shared across the test binary, so assert
    // the delta from this test's own calls rather than hard-coded absolute totals.
    var line_buf: [128]u8 = undefined;
    const conn_line = try std.fmt.bufPrint(&line_buf, "wisp_connections_total {d}\n", .{conn_before + 1});
    try std.testing.expect(std.mem.indexOf(u8, out, conn_line) != null);
    const bcast_line = try std.fmt.bufPrint(&line_buf, "wisp_events_broadcast_total {d}\n", .{bcast_before + 3});
    try std.testing.expect(std.mem.indexOf(u8, out, bcast_line) != null);
}
