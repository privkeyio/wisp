const std = @import("std");
const posix = std.posix;
const net = std.Io.net;
const Config = @import("config.zig").Config;
const nostr = @import("nostr.zig");

const log = std.log.scoped(.watchdog);

// A wedged accept loop (kernel completes the TCP handshake but wisp never
// accept()s or services the request) leaves the process alive at ~0 CPU while
// every connection returns 0 bytes. No in-process counter reliably detects this
// (the stall lives in the httpz worker's epoll loop), so we detect it the same
// way an external monitor would: open a loopback TCP connection to our own
// listener and send a minimal HTTP request with a tight timeout. A healthy relay
// answers in well under a millisecond; a wedged one accepts the connection but
// never replies. After `failures` consecutive misses we log loudly and exit, so
// the StartOS Daemon supervisor restarts the process (it restarts on exit, not on
// health-check failure). Any HTTP response — including 403/429/503 — counts as
// alive; only "no bytes back" is treated as a stall.
pub fn run(config: *const Config, shutdown: *std.atomic.Value(bool)) void {
    if (!config.watchdog_enabled) return;

    const host = probeHost(config.host);
    const address = net.IpAddress.parse(host, config.port) catch |err| {
        log.err("watchdog disabled: cannot parse probe address {s}:{d}: {}", .{ host, config.port, err });
        return;
    };

    const interval: u32 = @max(config.watchdog_interval_seconds, 1);
    const fail_threshold: u32 = @max(config.watchdog_failures, 1);
    var consecutive_failures: u32 = 0;
    var elapsed: u32 = 0;

    while (!shutdown.load(.acquire)) {
        // Sleep in 1s steps so a shutdown is noticed promptly rather than after a
        // whole probe interval (the main thread joins this thread on exit).
        std.Io.sleep(nostr.io.io(), .{ .nanoseconds = std.time.ns_per_s }, .awake) catch {};
        if (shutdown.load(.acquire)) return;
        elapsed += 1;
        if (elapsed < interval) continue;
        elapsed = 0;

        if (probe(address, config.watchdog_timeout_ms)) {
            consecutive_failures = 0;
            continue;
        }

        consecutive_failures += 1;
        log.warn("self-probe to {s}:{d} failed ({d}/{d})", .{ host, config.port, consecutive_failures, fail_threshold });
        if (consecutive_failures >= fail_threshold) {
            log.err("accept loop appears wedged: {d} consecutive self-probes to {s}:{d} failed; exiting for supervisor restart", .{ consecutive_failures, host, config.port });
            std.process.exit(1);
        }
    }
}

fn probeHost(host: []const u8) []const u8 {
    if (std.mem.eql(u8, host, "0.0.0.0")) return "127.0.0.1";
    if (std.mem.eql(u8, host, "::") or std.mem.eql(u8, host, "[::]")) return "::1";
    return host;
}

// Returns true if the listener accepted the connection and sent back any bytes
// within the timeout. All error paths return false (treated as a probe miss); a
// single miss never exits — only `failures` consecutive misses do.
fn probe(address: net.IpAddress, timeout_ms: u32) bool {
    const io = nostr.io.io();
    const stream = net.IpAddress.connect(&address, io, .{ .mode = .stream }) catch return false;
    const sock = stream.socket.handle;
    defer stream.close(io);

    // The connected socket is blocking, so a receive/send timeout bounds our wait
    // when a wedged relay accepts the socket but never replies.
    const tv = posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(tv)) catch return false;
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, &std.mem.toBytes(tv)) catch return false;

    const request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    var written: usize = 0;
    while (written < request.len) {
        const rc = posix.system.write(sock, request.ptr + written, request.len - written);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return false;
                written += n;
            },
            .INTR => continue,
            else => return false,
        }
    }

    var buf: [64]u8 = undefined;
    const n = posix.read(sock, &buf) catch return false;
    return n > 0;
}

test probeHost {
    try std.testing.expectEqualStrings("127.0.0.1", probeHost("0.0.0.0"));
    try std.testing.expectEqualStrings("::1", probeHost("::"));
    try std.testing.expectEqualStrings("::1", probeHost("[::]"));
    try std.testing.expectEqualStrings("192.168.1.5", probeHost("192.168.1.5"));
    try std.testing.expectEqualStrings("127.0.0.1", probeHost("127.0.0.1"));
}
