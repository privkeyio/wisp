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
