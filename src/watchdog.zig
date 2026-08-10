const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const net = std.Io.net;
const Config = @import("config.zig").Config;
const nostr = @import("nostr.zig");
const httpz = @import("httpz");
const server = @import("server.zig");

const log = std.log.scoped(.watchdog);

// A probe deadline is also the worst case a shutdown waits on a probe that is
// already in flight, since main() joins this thread. Keep it inside a range that
// is long enough to be meaningful and short enough not to stall an operator's
// stop.
const min_timeout_ms: u32 = 100;
const max_timeout_ms: u32 = 5_000;

/// What a single self-probe observed.
pub const Outcome = enum {
    /// Connected and the relay wrote bytes back. Definitively alive. Any HTTP
    /// status counts, including an error page: the question is whether the
    /// accept loop answers at all, not what it answers.
    alive,
    /// We reached the listen queue but nothing ever came back within the
    /// deadline. This is the signature of a wedged accept loop, and the only
    /// outcome that counts toward the exit threshold.
    stalled,
    /// No connection at all: refused because the listener is not up, or our own
    /// descriptor limits. A restart fixes neither, so this never counts.
    no_connection,
};

// A worker that has hit its connection cap pauses accept, which from outside is
// indistinguishable from a wedged accept loop: both accept the handshake into
// the backlog and then answer nothing. The difference is that capacity pressure
// clears itself once the relay reaps the stalled connections. So the watchdog
// must never be able to fire before that has had time to happen, whatever the
// operator configured, or anyone who can open sockets can force a restart.
fn minFailures(interval_seconds: u32, configured: u32) u32 {
    // The observation window is measured from the first stalled probe, and the
    // threshold is reached on the Nth stall, so N probes only span (N-1)
    // intervals. Without the +1 a threshold of 1 exits on the very first stall
    // no matter how long the interval is, which is exactly the behavior this
    // guard exists to prevent.
    const spans = std.math.divCeil(u32, server.self_heal_seconds, @max(interval_seconds, 1)) catch
        return @max(configured, 2);
    return @max(configured, spans + 1);
}

/// Decision for one probe, kept separate from the I/O so the three-strike logic
/// is testable without spawning a relay.
const Decision = enum { healthy, ignore, count, exit_now };

const State = struct {
    fail_threshold: u32,
    consecutive_failures: u32 = 0,
    // Exit stays disarmed until one probe has succeeded. Before that, a failing
    // probe means the listener is still binding, or that loopback probing does
    // not work here at all, and exiting would just restart forever.
    ever_succeeded: bool = false,

    fn step(self: *State, outcome: Outcome, accepts_progressed: bool) Decision {
        switch (outcome) {
            .alive => {
                self.ever_succeeded = true;
                self.consecutive_failures = 0;
                return .healthy;
            },
            .no_connection => return .ignore,
            .stalled => {},
        }

        // An accept completed since the previous probe proves the accept loop is
        // running, so the probe was starved (slow handler, saturated thread
        // pool) rather than wedged. Corroboration only ever clears failures, it
        // never adds any, so it can only make the watchdog less trigger-happy.
        //
        // Note this covers the probe's own connection: httpz counts an accept
        // before any handler runs, so a probe that gets accepted and then goes
        // unanswered vetoes itself. That is deliberate. It makes this strictly
        // an accept-loop watchdog: a relay whose handlers are slow or whose
        // thread pool is saturated is degraded, not wedged, and restarting it
        // would turn a slowdown into an outage. Only a relay that never accepts
        // the probe at all can reach the exit path.
        if (accepts_progressed) {
            self.consecutive_failures = 0;
            return .healthy;
        }

        if (!self.ever_succeeded) return .ignore;

        self.consecutive_failures += 1;
        return if (self.consecutive_failures >= self.fail_threshold) .exit_now else .count;
    }
};

pub fn run(config: *const Config, shutdown: *std.atomic.Value(bool)) void {
    if (!config.watchdog_enabled) return;

    const host = probeHost(config.host);
    const address = net.IpAddress.parse(host, config.port) catch |err| {
        log.err("watchdog disabled: cannot parse probe address {s}:{d}: {}", .{ host, config.port, err });
        return;
    };

    const interval: u32 = @max(config.watchdog_interval_seconds, 1);
    const timeout_ms: u32 = std.math.clamp(config.watchdog_timeout_ms, min_timeout_ms, max_timeout_ms);

    const configured_failures = @max(config.watchdog_failures, 1);
    const fail_threshold = minFailures(interval, configured_failures);
    if (fail_threshold != configured_failures) {
        log.warn("watchdog.failures raised {d} -> {d}: at a {d}s interval a lower value could fire before the relay reaps stalled connections ({d}s), turning ordinary connection pressure into a restart", .{ configured_failures, fail_threshold, interval, server.self_heal_seconds });
    }
    var state: State = .{ .fail_threshold = fail_threshold };
    var last_accepts = httpz.connectionCount();
    const interval_ms: u64 = @as(u64, interval) * std.time.ms_per_s;
    var next_probe_at: u64 = (monotonicMs() orelse 0) + interval_ms;

    while (!shutdown.load(.acquire)) {
        // Sleep in 1s steps so a shutdown is noticed promptly rather than after a
        // whole probe interval (the main thread joins this thread on exit).
        std.Io.sleep(nostr.io.io(), .{ .nanoseconds = std.time.ns_per_s }, .awake) catch {};
        if (shutdown.load(.acquire)) return;

        // Gate on the clock rather than on a count of sleeps: if sleep fails and
        // returns immediately, counting iterations would spin and fire probes
        // back to back, collapsing the whole minFailures time budget into
        // milliseconds.
        const now = monotonicMs() orelse continue;
        if (now < next_probe_at) continue;
        next_probe_at = now + interval_ms;

        const outcome = probe(address, timeout_ms);

        const accepts = httpz.connectionCount();
        const progressed = accepts != last_accepts;
        last_accepts = accepts;

        switch (state.step(outcome, progressed)) {
            .healthy => {},
            .ignore => log.warn("self-probe to {s}:{d}: {s}; not counted as a stall", .{ host, config.port, @tagName(outcome) }),
            .count => log.warn("self-probe to {s}:{d} stalled ({d}/{d})", .{ host, config.port, state.consecutive_failures, state.fail_threshold }),
            .exit_now => {
                // A graceful shutdown closes the listener while this probe is in
                // flight, which stalls it legitimately. Do not turn an operator's
                // stop into a failure exit.
                if (shutdown.load(.acquire)) return;
                log.err("accept loop appears wedged: {d} consecutive self-probes to {s}:{d} stalled; exiting for supervisor restart", .{ state.consecutive_failures, host, config.port });
                hardExit(1);
            },
        }
    }
}

// std.process.exit() runs libc atexit handlers and stdio teardown on this thread
// while the httpz workers, the LMDB writer and the spider are all still live.
// Terminate immediately instead: LMDB's commit is atomic across process death,
// and anything still queued in the writer has not been acked to a client.
fn hardExit(code: u8) noreturn {
    if (builtin.link_libc) std.c._exit(code);
    std.process.exit(code);
}

fn probeHost(host: []const u8) []const u8 {
    if (std.mem.eql(u8, host, "0.0.0.0")) return "127.0.0.1";
    if (std.mem.eql(u8, host, "::") or std.mem.eql(u8, host, "[::]")) return "::1";
    return host;
}

fn probe(address: net.IpAddress, timeout_ms: u32) Outcome {
    switch (address) {
        .ip4 => |a| {
            var sa: posix.sockaddr.in = .{
                .port = std.mem.nativeToBig(u16, a.port),
                .addr = @bitCast(a.bytes),
            };
            return probeAddr(posix.AF.INET, @ptrCast(&sa), @sizeOf(posix.sockaddr.in), timeout_ms);
        },
        .ip6 => |a| {
            var sa: posix.sockaddr.in6 = .{
                .port = std.mem.nativeToBig(u16, a.port),
                .flowinfo = a.flow,
                .addr = a.bytes,
                .scope_id = a.interface.index,
            };
            return probeAddr(posix.AF.INET6, @ptrCast(&sa), @sizeOf(posix.sockaddr.in6), timeout_ms);
        },
    }
}

// Drives the socket by hand, non-blocking throughout, with every wait bounded by
// one shared deadline. std's connect cannot be used here: it is blocking with no
// timeout (Io.Threaded outright panics if a timeout is requested), and a full
// accept backlog -- exactly what a wedged accept loop eventually produces --
// makes the kernel drop our SYN, parking the caller for the whole SYN-retry
// schedule (~130s by default), long past a shutdown request.
fn probeAddr(family: u32, sa: *const posix.sockaddr, sa_len: posix.socklen_t, timeout_ms: u32) Outcome {
    const deadline = (monotonicMs() orelse return .no_connection) + timeout_ms;

    const srv = posix.system.socket(family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    if (posix.errno(srv) != .SUCCESS) return .no_connection;
    const sock: posix.fd_t = @intCast(srv);
    defer closeSocket(sock);

    switch (posix.errno(posix.system.connect(sock, sa, sa_len))) {
        .SUCCESS => {},
        .INPROGRESS, .INTR, .ALREADY => {
            switch (wait(sock, posix.POLL.OUT, deadline)) {
                .ready => {},
                // Nothing completed the handshake in time. On loopback that means
                // the accept queue is full, i.e. the relay is not draining it.
                .timed_out => return .stalled,
                .failed => return .no_connection,
            }
            var so_err: i32 = 0;
            var so_len: posix.socklen_t = @sizeOf(i32);
            const grc = posix.system.getsockopt(sock, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&so_err), &so_len);
            if (posix.errno(grc) != .SUCCESS or so_err != 0) return .no_connection;
        },
        else => return .no_connection,
    }

    const request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    var written: usize = 0;
    while (written < request.len) {
        const wrc = posix.system.write(sock, request.ptr + written, request.len - written);
        switch (posix.errno(wrc)) {
            .SUCCESS => {
                const n: usize = @intCast(wrc);
                if (n == 0) return .no_connection;
                written += n;
            },
            .INTR => {},
            .AGAIN => switch (wait(sock, posix.POLL.OUT, deadline)) {
                .ready => {},
                .timed_out => return .stalled,
                .failed => return .no_connection,
            },
            else => return .no_connection,
        }
    }

    var buf: [64]u8 = undefined;
    while (true) {
        const rrc = posix.system.read(sock, &buf, buf.len);
        switch (posix.errno(rrc)) {
            // A clean EOF with no bytes means something accepted the connection
            // and closed it, which is evidence the accept loop ran. Not a reply,
            // so not `.alive`, but definitely not the silence of a wedge either.
            .SUCCESS => return if (rrc > 0) .alive else .no_connection,
            .INTR => {},
            .AGAIN => switch (wait(sock, posix.POLL.IN, deadline)) {
                .ready => {},
                .timed_out => return .stalled,
                .failed => return .no_connection,
            },
            else => return .no_connection,
        }
    }
}

fn closeSocket(fd: posix.fd_t) void {
    _ = posix.system.close(fd);
}

const Wait = enum { ready, timed_out, failed };

fn wait(sock: posix.fd_t, events: i16, deadline: u64) Wait {
    // Losing the clock mid-probe is reported as `.failed`, which maps to
    // `.no_connection` and is never counted toward the exit threshold.
    const now = monotonicMs() orelse return .failed;
    if (now >= deadline) return .timed_out;
    const timeout_ms = std.math.cast(i32, deadline - now) orelse std.math.maxInt(i32);
    var fds = [_]posix.pollfd{.{ .fd = sock, .events = events, .revents = 0 }};
    const n = posix.poll(&fds, timeout_ms) catch return .failed;
    return if (n == 0) .timed_out else .ready;
}

// Null rather than a sentinel: a 0 here would silently disable the probe
// deadline, and depending on which call failed that means either every probe
// instantly reading as stalled or none of them ever timing out.
fn monotonicMs() ?u64 {
    var ts: posix.timespec = undefined;
    if (posix.errno(posix.system.clock_gettime(posix.CLOCK.MONOTONIC, &ts)) != .SUCCESS) return null;
    return @as(u64, @intCast(ts.sec)) * std.time.ms_per_s + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

test probeHost {
    try std.testing.expectEqualStrings("127.0.0.1", probeHost("0.0.0.0"));
    try std.testing.expectEqualStrings("::1", probeHost("::"));
    try std.testing.expectEqualStrings("::1", probeHost("[::]"));
    try std.testing.expectEqualStrings("192.168.1.5", probeHost("192.168.1.5"));
    try std.testing.expectEqualStrings("127.0.0.1", probeHost("127.0.0.1"));
}

test "minFailures: the watchdog can never fire before the relay self-heals" {
    // Whatever the operator sets, interval * failures must cover the window in
    // which stalled connections are reaped, or a burst of idle connections is
    // enough to restart the relay.
    // Intervals at and above self_heal_seconds are included deliberately: there
    // divCeil is 1, and without the +1 the threshold stays at the configured 1,
    // so a single stalled probe would exit.
    for ([_]u32{ 1, 2, 3, 5, 10, 24, 25, 26, 30, 60, 3600 }) |interval| {
        for ([_]u32{ 1, 2, 3, 10 }) |configured| {
            const got = minFailures(interval, configured);
            try std.testing.expect(got >= configured);
            try std.testing.expect(got >= 2);
            // The window runs from the first stall to the Nth, which is N-1
            // intervals, not N.
            try std.testing.expect((got - 1) * interval >= server.self_heal_seconds);
        }
    }
}

test "minFailures: a single stalled probe can never trigger an exit" {
    // Regression: divCeil(25, 25) == 1 previously left `failures = 1` untouched,
    // restoring the one-burst restart this guard is meant to remove.
    for ([_]u32{ 25, 26, 100, 4000 }) |interval| {
        try std.testing.expect(minFailures(interval, 1) >= 2);
    }
}

test "minFailures: an interval of zero cannot divide by zero" {
    try std.testing.expect(minFailures(0, 1) >= 2);
}

test "step: a live relay clears the failure count and arms the exit" {
    var s: State = .{ .fail_threshold = 3 };
    try std.testing.expectEqual(Decision.healthy, s.step(.alive, false));
    try std.testing.expect(s.ever_succeeded);
    try std.testing.expectEqual(@as(u32, 0), s.consecutive_failures);
}

test "step: stalls never exit until one probe has succeeded" {
    var s: State = .{ .fail_threshold = 2 };
    // A relay that has never answered is starting up, or is unreachable by
    // design. Restarting it would loop forever, so this must never exit.
    for (0..50) |_| {
        try std.testing.expectEqual(Decision.ignore, s.step(.stalled, false));
    }
    try std.testing.expectEqual(@as(u32, 0), s.consecutive_failures);
}

test "step: consecutive stalls after a success reach the threshold exactly once" {
    var s: State = .{ .fail_threshold = 3 };
    try std.testing.expectEqual(Decision.healthy, s.step(.alive, false));
    try std.testing.expectEqual(Decision.count, s.step(.stalled, false));
    try std.testing.expectEqual(Decision.count, s.step(.stalled, false));
    try std.testing.expectEqual(Decision.exit_now, s.step(.stalled, false));
}

test "step: a single good probe resets a partial failure streak" {
    var s: State = .{ .fail_threshold = 3 };
    _ = s.step(.alive, false);
    _ = s.step(.stalled, false);
    _ = s.step(.stalled, false);
    try std.testing.expectEqual(Decision.healthy, s.step(.alive, false));
    try std.testing.expectEqual(@as(u32, 0), s.consecutive_failures);
    // The streak restarts from zero rather than resuming at 2.
    try std.testing.expectEqual(Decision.count, s.step(.stalled, false));
}

test "step: accepted connections veto a stall" {
    var s: State = .{ .fail_threshold = 2 };
    _ = s.step(.alive, false);
    // The probe was starved, but the relay accepted a connection meanwhile, so
    // the accept loop is demonstrably running.
    try std.testing.expectEqual(Decision.healthy, s.step(.stalled, true));
    try std.testing.expectEqual(@as(u32, 0), s.consecutive_failures);
}

test "step: a refused connection never counts toward the exit threshold" {
    var s: State = .{ .fail_threshold = 1 };
    _ = s.step(.alive, false);
    for (0..50) |_| {
        try std.testing.expectEqual(Decision.ignore, s.step(.no_connection, false));
    }
    try std.testing.expectEqual(@as(u32, 0), s.consecutive_failures);
}

// Test listeners driven with raw syscalls: these tests must not depend on the
// relay, or on an Io instance, to exercise the probe.
fn testListener(backlog: u32) !struct { fd: posix.fd_t, port: u16 } {
    const rc = posix.system.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: posix.fd_t = @intCast(rc);
    errdefer closeSocket(fd);

    var sa: posix.sockaddr.in = .{ .port = 0, .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
    if (posix.errno(posix.system.bind(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in))) != .SUCCESS) return error.BindFailed;
    if (posix.errno(posix.system.listen(fd, backlog)) != .SUCCESS) return error.ListenFailed;

    var bound: posix.sockaddr.in = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    if (posix.errno(posix.system.getsockname(fd, @ptrCast(&bound), &len)) != .SUCCESS) return error.GetSockNameFailed;

    return .{ .fd = fd, .port = std.mem.bigToNative(u16, bound.port) };
}

test "probe: a listener that replies is alive" {
    const l = try testListener(8);
    defer closeSocket(l.fd);

    const t = try std.Thread.spawn(.{}, struct {
        fn accept(fd: posix.fd_t) void {
            // Bounded: a blocking accept() here would hang the test binary
            // forever if the probe never connects, instead of failing.
            var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
            const ready = posix.poll(&fds, 5000) catch return;
            if (ready == 0) return;
            const c = posix.system.accept(fd, null, null);
            if (posix.errno(c) != .SUCCESS) return;
            const conn: posix.fd_t = @intCast(c);
            defer closeSocket(conn);
            const reply = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            _ = posix.system.write(conn, reply.ptr, reply.len);
        }
    }.accept, .{l.fd});

    const addr = try net.IpAddress.parse("127.0.0.1", l.port);
    // Join before asserting: a failed assert would otherwise skip the join and
    // leave the thread running against a listener the defer is about to close.
    const outcome = probe(addr, 5000);
    t.join();
    try std.testing.expectEqual(Outcome.alive, outcome);
}

// The wedge this watchdog exists to catch: the kernel completes the handshake
// into the backlog, but the application never accepts or answers.
test "probe: a listener that never accepts is a stall, not a connection failure" {
    const l = try testListener(8);
    defer closeSocket(l.fd);

    const addr = try net.IpAddress.parse("127.0.0.1", l.port);
    const started = monotonicMs().?;
    try std.testing.expectEqual(Outcome.stalled, probe(addr, 300));
    // The deadline is honored rather than blocking indefinitely.
    try std.testing.expect(monotonicMs().? - started < 5 * std.time.ms_per_s);
}

test "probe: a closed port is a connection failure, not a stall" {
    const l = try testListener(8);
    const port = l.port;
    closeSocket(l.fd);

    const addr = try net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectEqual(Outcome.no_connection, probe(addr, 1000));
}

test "probe: a zero timeout still terminates" {
    const l = try testListener(8);
    defer closeSocket(l.fd);

    // run() clamps to min_timeout_ms, but probe() itself must never block
    // forever even when handed 0 directly.
    const addr = try net.IpAddress.parse("127.0.0.1", l.port);
    const started = monotonicMs().?;
    _ = probe(addr, 0);
    try std.testing.expect(monotonicMs().? - started < 5 * std.time.ms_per_s);
}
