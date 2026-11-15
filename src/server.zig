const std = @import("std");
const builtin = @import("builtin");
const httpz = @import("httpz");
const websocket = httpz.websocket;
const nostr = @import("nostr.zig");

const Config = @import("config.zig").Config;
const MsgHandler = @import("handler.zig").Handler;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const Connection = @import("connection.zig").Connection;
const nip11 = @import("nip11.zig");
const rate_limiter = @import("rate_limiter.zig");
const ip_match = @import("ip_match.zig");
const Nip86Handler = @import("nip86.zig").Nip86Handler;
const metrics = @import("relay_metrics.zig");

const log = std.log.scoped(.server);

const CORS_OPTIONS = "Access-Control-Allow-Origin: *";

/// Shared services. Held by value in httpz (it is just pointers, cheap to copy)
/// and reachable from both the HTTP actions and the WebSocket handlers.
pub const App = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    msg_handler: *MsgHandler,
    subs: *Subscriptions,
    shutdown: *std.atomic.Value(bool),
    nip86_handler: *Nip86Handler,
    conn_limiter: *rate_limiter.ConnectionLimiter,
    ip_filter: *rate_limiter.IpFilter,
    trusted_proxies: *rate_limiter.IpFilter,
    reserved_ips: *rate_limiter.IpFilter,
    next_id: *std.atomic.Value(u64),

    // httpz requires this declaration to enable WebSocket upgrades.
    pub const WebsocketHandler = WsConn;

    /// GET / — WebSocket upgrade, or NIP-11 relay info, or a default page.
    pub fn getRoot(app: App, req: *httpz.Request, res: *httpz.Response) !void {
        // Determine client IP (socket peer, or proxy headers when trusted).
        var ip_buf: [64]u8 = undefined;
        const client_ip = app.clientIp(req, res, &ip_buf);

        if (app.ipDenied(client_ip)) {
            res.status = 403;
            return;
        }

        // WebSocket upgrade?
        if (req.header("upgrade")) |_| {
            var ctx = WsContext{
                .app = app,
                .client_ip_len = 0,
                .client_ip = undefined,
                .may_be_reserved = app.mayBeReserved(req, res),
            };
            ctx.setIp(client_ip);
            // WsConn.init runs inside the upgrade handshake, before any 101 reply is
            // written, so a connection-limit rejection surfaces here as an error.
            // Reply with a proper status (and log the source IP) instead of letting
            // httpz treat it as an unhandled exception and return 500.
            var log_ip_buf: [64]u8 = undefined;
            const upgraded = httpz.upgradeWebsocket(WsConn, req, res, &ctx) catch |err| switch (err) {
                error.TooManyConnectionsPerIp => {
                    res.status = 429;
                    res.content_type = .TEXT;
                    res.body = "too many connections from your address";
                    log.warn("connection rejected (per-IP limit): {s}", .{safeIp(client_ip, &log_ip_buf)});
                    return;
                },
                error.TooManyConnectionsPerSubnet => {
                    res.status = 429;
                    res.content_type = .TEXT;
                    res.body = "too many connections from your network";
                    log.warn("connection rejected (per-subnet limit): {s}", .{safeIp(client_ip, &log_ip_buf)});
                    return;
                },
                error.TooManyConnections => {
                    res.status = 503;
                    res.content_type = .TEXT;
                    res.body = "server connection limit reached";
                    log.warn("connection rejected (global limit): {s}", .{safeIp(client_ip, &log_ip_buf)});
                    return;
                },
                error.WriteFailed => return, // client disconnected during the upgrade handshake; nothing to send
                else => return err,
            };
            if (upgraded == false) {
                res.status = 400;
                res.content_type = .TEXT;
                res.body = "invalid websocket upgrade";
            }
            return;
        }

        // NIP-11 relay information document.
        if (req.header("accept")) |accept| {
            if (std.mem.indexOf(u8, accept, "application/nostr+json") != null) {
                res.header("Access-Control-Allow-Origin", "*");
                res.header("Content-Type", "application/nostr+json");
                const w = res.writer();
                // The writer buffers in memory (httpz flushes to the socket after
                // this returns), so the only failure here is allocation failure
                // while serializing the document. Reset the partial body and
                // return 500 instead of serving a truncated 200 or letting it
                // surface as an httpz "unhandled exception".
                nip11.write(app.config, app.nip86_handler, w) catch |err| switch (err) {
                    error.WriteFailed => {
                        res.clearWriter();
                        res.status = 500;
                    },
                };
                return;
            }
        }

        res.content_type = .HTML;
        res.body = "<!DOCTYPE html><p>wisp nostr relay. Connect over WebSocket.</p>";
    }

    /// POST / — NIP-86 relay management (NIP-98 authenticated).
    pub fn postRoot(app: App, req: *httpz.Request, res: *httpz.Response) !void {
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
        res.header("Access-Control-Allow-Methods", "POST, OPTIONS");

        // Same network policy as getRoot: this management endpoint shares the port.
        var ip_buf: [64]u8 = undefined;
        const client_ip = app.clientIp(req, res, &ip_buf);
        if (app.ipDenied(client_ip)) {
            res.status = 403;
            return;
        }

        if (app.nip86_handler.admins.items.len == 0) {
            res.status = 404;
            res.content_type = .JSON;
            res.body = "{\"error\":\"management API not enabled\"}";
            return;
        }

        const body = req.body() orelse {
            res.status = 400;
            res.content_type = .JSON;
            res.body = "{\"error\":\"missing request body\"}";
            return;
        };

        const auth_header = req.header("authorization");

        var url_buf: [512]u8 = undefined;
        const request_url = if (app.config.relay_url.len > 0)
            app.config.relay_url
        else
            std.fmt.bufPrint(&url_buf, "http://{s}:{d}", .{ app.config.host, app.config.port }) catch "";

        const result = app.nip86_handler.handle(body, auth_header, request_url);
        defer if (result.owned) app.allocator.free(result.body);

        res.status = result.status;
        res.content_type = .JSON;
        // Copy into the response arena so the (possibly owned) body outlives the defer.
        res.body = try res.arena.dupe(u8, result.body);
    }

    /// GET /metrics — Prometheus operational metrics. Unless metrics_public is
    /// set, only direct requests from a loopback socket peer are served; anything
    /// relayed by a proxy is refused regardless of trust_proxy. Always subject to
    /// the relay's IP policy.
    pub fn getMetrics(app: App, req: *httpz.Request, res: *httpz.Response) !void {
        var ip_buf: [64]u8 = undefined;
        const client_ip = app.clientIp(req, res, &ip_buf);
        var peer_buf: [64]u8 = undefined;
        const peer_ip = formatPeerIp(res.conn.address, &peer_buf);
        const forwarded = isForwarded(
            req.header("x-forwarded-for"),
            req.header("x-real-ip"),
            req.headers.len >= req.headers.keys.len,
        );
        if (app.ipDenied(client_ip) or !metricsAllowed(app.config.metrics_public, peer_ip, forwarded)) {
            res.status = 403;
            return;
        }
        res.header("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
        const w = res.writer();
        try metrics.write(w, app.subs.connectionCount());
        // httpz's own counters, chiefly httpz_connections. That one counts
        // accepts, incremented before any handler runs, so comparing it against
        // wisp_connections_total (completed WebSocket upgrades) is what tells an
        // operator whether the accept loop is running but work is backing up, as
        // opposed to the accept loop being stuck. It is the same signal the
        // watchdog uses to decide a stalled probe is not a wedge.
        try httpz.writeMetrics(w);
    }

    /// OPTIONS / — CORS preflight.
    pub fn optionsRoot(_: App, _: *httpz.Request, res: *httpz.Response) !void {
        res.status = 204;
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
        res.header("Access-Control-Allow-Methods", "POST, OPTIONS");
        res.header("Access-Control-Max-Age", "86400");
    }

    fn ipDenied(app: App, client_ip: []const u8) bool {
        return !app.ip_filter.isAllowed(client_ip) or app.nip86_handler.mgmt_store.isIpBlocked(client_ip);
    }

    /// May use the reserved_connections headroom and is never evicted. Only
    /// reserved_ips grants this; ip_whitelist only gates who may connect.
    fn isReservedIp(app: App, client_ip: []const u8) bool {
        return app.reserved_ips.matchesWhitelist(client_ip);
    }

    /// False when the request was relayed by a proxy whose forwarding headers
    /// are not honored: the client IP is then the proxy's own address, which
    /// would make every proxied client reserved (the /metrics rule).
    fn mayBeReserved(app: App, req: *httpz.Request, res: *httpz.Response) bool {
        const forwarded = isForwarded(
            req.header("x-forwarded-for"),
            req.header("x-real-ip"),
            req.headers.len >= req.headers.keys.len,
        );
        if (!forwarded) return true;
        var peer_buf: [64]u8 = undefined;
        const peer_ip = formatPeerIp(res.conn.address, &peer_buf);
        return reservedAllowed(app.config.trust_proxy and app.trusted_proxies.isTrustedProxy(peer_ip), forwarded);
    }

    fn clientIp(app: App, req: *httpz.Request, res: *httpz.Response, buf: *[64]u8) []const u8 {
        const socket_ip = formatPeerIp(res.conn.address, buf);
        if (!app.config.trust_proxy) return socket_ip;
        // Only honor forwarded headers when the socket peer is a configured trusted
        // proxy; otherwise an attacker hitting the backend directly could forge them
        // to spoof any client IP. An empty trusted_proxies set trusts any peer.
        if (!app.trusted_proxies.isTrustedProxy(socket_ip)) return socket_ip;
        const xff = req.header("x-forwarded-for");
        const xrip = req.header("x-real-ip");
        return rate_limiter.extractClientIp(xff, xrip, socket_ip, true);
    }

    // Forwarded-header IPs are never validated as addresses (they key per-IP
    // limits, not parsing), so scrub anything outside the IP character set before
    // logging to avoid terminal-escape injection from a forged X-Forwarded-For.
    fn safeIp(ip: []const u8, buf: *[64]u8) []const u8 {
        const len = @min(ip.len, buf.len);
        for (ip[0..len], buf[0..len]) |c, *out| {
            out.* = switch (c) {
                '0'...'9', 'a'...'f', 'A'...'F', '.', ':' => c,
                else => '?',
            };
        }
        return buf[0..len];
    }
};

/// Context handed to WsConn.init via httpz.upgradeWebsocket.
const WsContext = struct {
    app: App,
    client_ip: [64]u8,
    client_ip_len: u8,
    // See App.mayBeReserved: false for a relayed request whose client IP is
    // the proxy's own address.
    may_be_reserved: bool,

    fn setIp(self: *WsContext, addr: []const u8) void {
        const len = @min(addr.len, self.client_ip.len);
        @memcpy(self.client_ip[0..len], addr[0..len]);
        self.client_ip_len = @intCast(len);
    }

    fn ip(self: *const WsContext) []const u8 {
        return self.client_ip[0..self.client_ip_len];
    }
};

/// Per-connection WebSocket handler. websocket.zig creates one per connection on
/// a bounded epoll worker pool — no thread-per-connection.
pub const WsConn = struct {
    app: App,
    connection: *Connection,
    client_ip: [64]u8,
    client_ip_len: u8,

    pub fn init(conn: *websocket.Conn, ctx: *const WsContext) !WsConn {
        const app = ctx.app;
        const ip = ctx.ip();

        // Atomic per-IP and per-subnet connection limits. On rejection neither
        // slot is held; on success both are, and every later error path and
        // close() gives both back through removeConnection.
        switch (app.conn_limiter.acquire(ip)) {
            .admitted => {},
            .per_ip_limit => {
                metrics.rateLimited();
                return error.TooManyConnectionsPerIp;
            },
            .per_subnet_limit => {
                metrics.rateLimited();
                metrics.connectionRejectedSubnet();
                return error.TooManyConnectionsPerSubnet;
            },
        }
        errdefer app.conn_limiter.removeConnection(ip);

        const connection = try app.allocator.create(Connection);
        errdefer app.allocator.destroy(connection);
        const id = app.next_id.fetchAdd(1, .monotonic);
        connection.init(app.allocator, id);
        connection.setWsConn(conn);
        connection.setClientIp(ip);
        connection.reserved = ctx.may_be_reserved and app.isReservedIp(ip);

        // Restore the accept-time socket tuning the worker-pool migration dropped.
        const fd = conn.stream.socket.handle;
        const TCP_NODELAY = 1;
        std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, TCP_NODELAY, &std.mem.toBytes(@as(i32, 1))) catch {};

        // This send timeout does NOT bound writes in the build we ship, and the
        // comment here used to claim that it did. httpz accepts with O_NONBLOCK
        // and restores that flag when it hands a connection over to the WebSocket
        // layer, and Linux ignores SO_SNDTIMEO on a non-blocking socket. Measured
        // on a live upgrade: F_GETFL reports 2050, i.e. O_NONBLOCK is set.
        //
        // What actually stops a write to a stalled peer is that websocket.zig's
        // writeAllIOVec does a bare `try posix.writev`, so a full send buffer
        // surfaces as error.WouldBlock immediately rather than blocking. This is
        // kept because it costs nothing and does apply if httpz is ever built in
        // blocking mode (httpz_blocking), where an unbounded write would
        // otherwise be possible.
        const send_timeout = std.posix.timeval{ .sec = 10, .usec = 0 };
        std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, &std.mem.toBytes(send_timeout)) catch {};
        // Kernel-level backstop for dead/half-open peers. In the production topology
        // every client shares one internal IP behind the tunnel/reverse proxy, so
        // per-IP limits can't shed a stuck peer; keepalive lets the kernel reap it
        // independently of the app-level idle reaper. SO_KEEPALIVE is portable; the
        // TCP_KEEP* idle/interval/count tuning uses Linux socket option numbers that
        // mean other things on macOS (option 4 is TCP_NOPUSH), so gate it to Linux.
        std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, &std.mem.toBytes(@as(i32, 1))) catch {};
        if (builtin.os.tag == .linux) {
            // ~2min to detect: 60s idle, then 4 probes 15s apart. These aren't in
            // std.posix, so define them locally like TCP_NODELAY above.
            const TCP_KEEPIDLE = 4;
            const TCP_KEEPINTVL = 5;
            const TCP_KEEPCNT = 6;
            std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, TCP_KEEPIDLE, &std.mem.toBytes(@as(i32, 60))) catch {};
            std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, TCP_KEEPINTVL, &std.mem.toBytes(@as(i32, 15))) catch {};
            std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, TCP_KEEPCNT, &std.mem.toBytes(@as(i32, 4))) catch {};
        }
        errdefer connection.deinit();

        // Global connection limit + registry. This runs only after the per-IP
        // and per-subnet caps above admitted the newcomer, so a source cannot
        // evict anyone with connections it was not allowed to hold.
        const evicted = app.subs.tryAddConnection(connection, .{
            .max_connections = app.config.max_connections,
            .reserved_connections = app.config.reserved_connections,
            .reserved = connection.reserved,
            .evict_idle_seconds = app.config.evict_idle_seconds,
        }) catch |err| {
            metrics.rateLimited();
            return err;
        };
        if (evicted) {
            metrics.connectionEvicted();
            eviction_log.record();
        }
        metrics.connectionOpened();

        var self = WsConn{
            .app = app,
            .connection = connection,
            .client_ip = undefined,
            .client_ip_len = 0,
        };
        const len = @min(ip.len, self.client_ip.len);
        @memcpy(self.client_ip[0..len], ip[0..len]);
        self.client_ip_len = @intCast(len);
        return self;
    }

    pub fn afterInit(self: *WsConn) !void {
        const config = self.app.config;
        if (config.auth_required or config.auth_to_write) {
            var auth_buf: [256]u8 = undefined;
            const auth_msg = nostr.RelayMsg.auth(&self.connection.auth_challenge, &auth_buf) catch return;
            self.connection.write(auth_msg) catch return;
            self.connection.challenge_sent = true;
        }
    }

    pub fn clientMessage(self: *WsConn, data: []const u8) !void {
        self.app.msg_handler.handle(self.connection, data);
    }

    pub fn close(self: *WsConn) void {
        // removeConnection drops the registry entry under the exclusive lock, so
        // no broadcaster/idle-close can take a new write reference afterward.
        // Drain any in-flight references before freeing to avoid use-after-free.
        self.app.subs.removeConnection(self.connection.id);
        self.app.conn_limiter.removeConnection(self.client_ip[0..self.client_ip_len]);
        self.connection.waitForPendingWrites();
        self.connection.deinit();
        self.app.allocator.destroy(self.connection);
    }
};

/// Evictions are logged at most once per interval, as a count, so a flood that
/// churns the pool cannot flood the log with one line per upgrade.
/// A count still pending when the evictions stop is flushed by the cleanup
/// thread's once-a-second tick (flushEvictionLog), so a burst followed by quiet
/// still reaches the log within one interval.
const EvictionLog = struct {
    const interval_s: i64 = 60;

    pending: std.atomic.Value(u64) = .init(0),
    last_logged: std.atomic.Value(i64) = .init(0),

    fn record(self: *EvictionLog) void {
        _ = self.pending.fetchAdd(1, .monotonic);
        if (self.take(nostr.io.timestamp())) |n| logEvictions(n);
    }

    /// The count to log now, or null if none is pending or the last line was
    /// less than an interval ago. At most one caller per interval gets it.
    fn take(self: *EvictionLog, now: i64) ?u64 {
        if (self.pending.load(.monotonic) == 0) return null;
        const last = self.last_logged.load(.monotonic);
        if (now - last < interval_s) return null;
        if (self.last_logged.cmpxchgStrong(last, now, .monotonic, .monotonic) != null) return null;
        const n = self.pending.swap(0, .monotonic);
        return if (n == 0) null else n;
    }
};

fn logEvictions(n: u64) void {
    log.warn("connection pool full: evicted {d} idle connection(s) to admit new clients", .{n});
}

var eviction_log: EvictionLog = .{};

/// Called from the cleanup thread's periodic tick.
pub fn flushEvictionLog() void {
    if (eviction_log.take(nostr.io.timestamp())) |n| logEvictions(n);
}

fn formatPeerIp(address: anytype, buf: *[64]u8) []const u8 {
    const formatted = std.fmt.bufPrint(buf, "{f}", .{address}) catch return "unknown";
    // IPv6 is "[addr]:port"; return the bracketed address.
    if (formatted.len > 0 and formatted[0] == '[') {
        if (std.mem.indexOfScalar(u8, formatted, ']')) |end| return formatted[1..end];
    }
    if (std.mem.lastIndexOf(u8, formatted, ":")) |colon| return formatted[0..colon];
    return formatted;
}

/// 127.0.0.0/8, ::1, or IPv4-mapped ::ffff:127.0.0.0/104. Anything that does
/// not parse as an address (e.g. "unknown") is not loopback.
fn isLoopback(ip: []const u8) bool {
    if (std.Io.net.Ip4Address.parse(ip, 0)) |a| return a.bytes[0] == 127 else |_| {}
    const b = (std.Io.net.Ip6Address.parse(ip, 0) catch return false).bytes;
    const v4_mapped = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    if (std.mem.eql(u8, b[0..12], &v4_mapped)) return b[12] == 127;
    return std.mem.allEqual(u8, b[0..15], 0) and b[15] == 1;
}

/// /metrics policy: open when metrics_public, otherwise only for a loopback
/// socket peer that is not relaying for someone else. Forwarding headers are
/// checked for presence, not trusted, so a same-host proxy never passes.
fn metricsAllowed(metrics_public: bool, peer_ip: []const u8, has_forwarded_header: bool) bool {
    if (metrics_public) return true;
    return isLoopback(peer_ip) and !has_forwarded_header;
}

/// True if any reserved_ips entry overlaps loopback or a private, link-local
/// or CGNAT range, i.e. an address a reverse proxy or tunnel would connect from.
/// Entries that do not parse are skipped; IpFilter already warns about them.
fn coversProxyRange(list: []const u8) bool {
    const internal = [_][]const u8{
        "127.0.0.0/8",    "10.0.0.0/8",    "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "100.64.0.0/10", "::1/128",       "fc00::/7",
        "fe80::/10",
    };
    var iter = std.mem.splitScalar(u8, list, ',');
    while (iter.next()) |entry| {
        const rule = ip_match.parseRule(std.mem.trim(u8, entry, " \t"), .standard) orelse continue;
        for (internal) |text| {
            if (rule.overlaps(ip_match.parseRule(text, .standard).?)) return true;
        }
    }
    return false;
}

test coversProxyRange {
    try std.testing.expect(!coversProxyRange(""));
    try std.testing.expect(!coversProxyRange("203.0.113.10, 2001:db8::/64"));
    try std.testing.expect(!coversProxyRange("not-an-ip"));
    try std.testing.expect(coversProxyRange("203.0.113.10,127.0.0.1"));
    try std.testing.expect(coversProxyRange("::1"));
    try std.testing.expect(coversProxyRange("192.168.1.0/24"));
    try std.testing.expect(coversProxyRange("fd00::5"));
    try std.testing.expect(coversProxyRange("0.0.0.0/0"));
}

/// Reserved status needs a client IP that is really the client's: either the
/// request was not forwarded, or the forwarding headers were honored (trust_proxy
/// with a trusted peer), so the IP came from them rather than the proxy socket.
fn reservedAllowed(headers_honored: bool, forwarded: bool) bool {
    return headers_honored or !forwarded;
}

/// A request is treated as proxied if it carries X-Forwarded-For or X-Real-IP.
/// httpz silently drops headers past its table size, so a full table may have
/// lost a proxy's X-Forwarded-For and counts as forwarded too.
fn isForwarded(xff: ?[]const u8, xrip: ?[]const u8, headers_full: bool) bool {
    return xff != null or xrip != null or headers_full;
}

test isForwarded {
    try std.testing.expect(!isForwarded(null, null, false));
    try std.testing.expect(isForwarded("1.2.3.4", null, false));
    try std.testing.expect(isForwarded(null, "127.0.0.1", false));
    try std.testing.expect(isForwarded("", null, false));
    try std.testing.expect(isForwarded(null, null, true));
}

test reservedAllowed {
    try std.testing.expect(reservedAllowed(false, false));
    try std.testing.expect(reservedAllowed(true, false));
    try std.testing.expect(reservedAllowed(true, true));
    // trust_proxy off (or an untrusted peer) and the request was relayed: the
    // client IP is the proxy's, so loopback in reserved_ips must not match it.
    try std.testing.expect(!reservedAllowed(false, isForwarded("203.0.113.9", null, false)));
    try std.testing.expect(!reservedAllowed(false, isForwarded(null, "203.0.113.9", false)));
    try std.testing.expect(!reservedAllowed(false, isForwarded(null, null, true)));
}

test metricsAllowed {
    try std.testing.expect(metricsAllowed(false, "127.0.0.1", false));
    try std.testing.expect(metricsAllowed(false, "::1", false));
    try std.testing.expect(!metricsAllowed(false, "127.0.0.1", isForwarded("1.2.3.4", null, false)));
    try std.testing.expect(!metricsAllowed(false, "127.0.0.1", isForwarded(null, "127.0.0.1", false)));
    try std.testing.expect(!metricsAllowed(false, "::ffff:127.0.0.1", true));
    try std.testing.expect(!metricsAllowed(false, "10.0.0.1", false));
    try std.testing.expect(!metricsAllowed(false, "unknown", false));
    try std.testing.expect(metricsAllowed(true, "10.0.0.1", false));
    try std.testing.expect(metricsAllowed(true, "127.0.0.1", true));
}

test isLoopback {
    for ([_][]const u8{ "127.0.0.1", "127.255.0.9", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "::FFFF:127.1.2.3" }) |ip| {
        try std.testing.expect(isLoopback(ip));
    }
    for ([_][]const u8{ "", "unknown", "10.0.0.1", "128.0.0.1", "1.127.0.0", "::", "::2", "::ffff:10.0.0.1", "::127.0.0.1", "fe80::1", "127.0.0.1, 10.0.0.1", "localhost" }) |ip| {
        try std.testing.expect(!isLoopback(ip));
    }
}

const PoolConfig = struct { workers: u16, pool: u16 };

// Each httpz worker runs one epoll loop and dispatches connection work to its own
// thread pool. httpz defaults to 1 worker, so the epoll/accept readiness loop is
// single-threaded; scaling workers with CPU count (capped at 4) spreads that
// syscall load across cores. The per-worker pool runs the WS message handlers, so
// total handler concurrency is workers * pool. We split a fixed budget (httpz's
// single-worker default of 32) across workers rather than running 32 per worker,
// so extra workers buy epoll parallelism without multiplying thread/buffer memory
// (4 workers * 32 = ~50 MB extra RSS otherwise). Floor division holds the total at
// the budget when it divides evenly (1/2/4 workers) and just under it otherwise
// (30 on a 3-CPU host). The pool floor of 4 keeps each pool usable should the
// worker cap ever exceed the budget; at the current cap of 4 it never binds.
//
// configured_workers comes from config.workers: 0 keeps the CPU-derived default,
// any positive value overrides it (a personal or memory-constrained relay can set
// 1 to shed the extra per-worker buffer pools and threads). The override is clamped
// to max_workers so a typo (e.g. workers = 65535) cannot spawn tens of thousands of
// threads and buffer pools, which would defeat the memory budget this feature exists
// to protect.
fn computePoolConfig(cpu_count: usize, configured_workers: u16) PoolConfig {
    const total_handler_budget: usize = 32;
    const max_workers: usize = 64;
    const worker_count = if (configured_workers > 0)
        @min(@as(usize, configured_workers), max_workers)
    else
        @max(@as(usize, 1), @min(cpu_count, 4));
    const pool_count = @max(@as(usize, 4), @divTrunc(total_handler_budget, worker_count));
    return .{ .workers = @intCast(worker_count), .pool = @intCast(pool_count) };
}

test "safeIp" {
    var buf: [64]u8 = undefined;
    // IPv4 and IPv6 addresses pass through unchanged.
    try std.testing.expectEqualStrings("192.168.1.1", App.safeIp("192.168.1.1", &buf));
    try std.testing.expectEqualStrings("2001:db8::ff00", App.safeIp("2001:db8::ff00", &buf));
    // Terminal-escape / control bytes from a forged X-Forwarded-For become '?'.
    try std.testing.expectEqualStrings("1.2??31?.3", App.safeIp("1.2\x1b[31m.3", &buf));
    try std.testing.expectEqualStrings("10.0?.0?.1", App.safeIp("10.0\n.0\r.1", &buf));
    // Non-hex letters are scrubbed; hex digits (a-f/A-F) are allowed.
    try std.testing.expectEqualStrings("?eef??", App.safeIp("xeefgz", &buf));
    // Over-length input is truncated to the 64-byte buffer, no overflow.
    const long = &@as([100]u8, @splat('1'));
    try std.testing.expectEqual(@as(usize, 64), App.safeIp(long, &buf).len);
}

test computePoolConfig {
    // 1 worker gets the full budget.
    try std.testing.expectEqual(PoolConfig{ .workers = 1, .pool = 32 }, computePoolConfig(1, 0));
    // Budget splits evenly across 2 and 4 workers, holding the total at 32.
    try std.testing.expectEqual(PoolConfig{ .workers = 2, .pool = 16 }, computePoolConfig(2, 0));
    try std.testing.expectEqual(PoolConfig{ .workers = 4, .pool = 8 }, computePoolConfig(4, 0));
    // 3 workers: floor division leaves the total just under budget (3 * 10 = 30).
    try std.testing.expectEqual(PoolConfig{ .workers = 3, .pool = 10 }, computePoolConfig(3, 0));
    // Worker count is capped at 4, so more CPUs do not shrink the pool further.
    try std.testing.expectEqual(PoolConfig{ .workers = 4, .pool = 8 }, computePoolConfig(8, 0));
    try std.testing.expectEqual(PoolConfig{ .workers = 4, .pool = 8 }, computePoolConfig(64, 0));
    // Degenerate cpu_count of 0 (e.g. getCpuCount failure fallback) still yields one worker.
    try std.testing.expectEqual(PoolConfig{ .workers = 1, .pool = 32 }, computePoolConfig(0, 0));

    // A configured worker count overrides the CPU-derived default regardless of cpu_count.
    try std.testing.expectEqual(PoolConfig{ .workers = 1, .pool = 32 }, computePoolConfig(16, 1));
    try std.testing.expectEqual(PoolConfig{ .workers = 2, .pool = 16 }, computePoolConfig(16, 2));
    // The budget still splits across configured workers, with the pool floor of 4.
    try std.testing.expectEqual(PoolConfig{ .workers = 16, .pool = 4 }, computePoolConfig(16, 16));
    // The override is clamped at 64, so a runaway value cannot spawn unbounded workers.
    try std.testing.expectEqual(PoolConfig{ .workers = 64, .pool = 4 }, computePoolConfig(4, 64));
    try std.testing.expectEqual(PoolConfig{ .workers = 64, .pool = 4 }, computePoolConfig(4, 65535));

    // Total handler concurrency never exceeds the budget on the auto path.
    var cpu: usize = 0;
    while (cpu <= 128) : (cpu += 1) {
        const cfg = computePoolConfig(cpu, 0);
        try std.testing.expect(@as(usize, cfg.workers) >= 1);
        try std.testing.expect(@as(usize, cfg.workers) * @as(usize, cfg.pool) <= 32);
    }
}

/// Owns the httpz server plus the per-IP limiter / filter / id counter that the
/// App points into.
// Without these, httpz defaults both to MAX_TIMEOUT and never reaps a connection
// that completes the handshake and then says nothing. Such sockets hold a worker
// slot forever, so a trivial slowloris walks a worker up to max_conn, accept
// pauses, and the watchdog reads the silence as a wedge and restarts us: a
// remote, unauthenticated kill. They bound only the HTTP phase; a connection
// leaves both timeout lists once it upgrades, so idle WebSocket clients are
// unaffected. Keepalive is short because a relay client either upgrades
// immediately or fetches NIP-11 once, and every second here is a second an
// attacker can hold a slot.
pub const http_request_timeout_s: u32 = 10;
pub const http_keepalive_timeout_s: u32 = 15;

/// How long the relay may need to clear connections that occupy worker slots
/// without doing anything. Nothing may conclude the relay is wedged until this
/// has had a chance to run, or ordinary capacity pressure looks like a wedge.
pub const self_heal_seconds: u32 = @as(u32, @max(http_request_timeout_s, http_keepalive_timeout_s)) + 10;

pub const Server = struct {
    allocator: std.mem.Allocator,
    httpz_server: httpz.Server(App),
    conn_limiter: rate_limiter.ConnectionLimiter,
    ip_filter: rate_limiter.IpFilter,
    trusted_proxy_filter: rate_limiter.IpFilter,
    reserved_filter: rate_limiter.IpFilter,
    next_id: std.atomic.Value(u64),

    pub fn init(
        self: *Server,
        allocator: std.mem.Allocator,
        io: std.Io,
        config: *const Config,
        msg_handler: *MsgHandler,
        subs: *Subscriptions,
        shutdown: *std.atomic.Value(bool),
        nip86_handler: *Nip86Handler,
    ) !void {
        self.allocator = allocator;
        self.next_id = std.atomic.Value(u64).init(0);
        self.conn_limiter = rate_limiter.ConnectionLimiter.init(allocator, config.max_connections_per_ip, .{
            .max_connections = config.max_connections_per_subnet,
            .prefix_v4 = config.subnet_prefix_v4,
            .prefix_v6 = config.subnet_prefix_v6,
        });
        if (self.conn_limiter.subnet.max_connections != config.max_connections_per_subnet) {
            log.warn("max_connections_per_subnet {d} is below max_connections_per_ip {d}; using {d}", .{
                config.max_connections_per_subnet,
                config.max_connections_per_ip,
                self.conn_limiter.subnet.max_connections,
            });
        }
        self.ip_filter = rate_limiter.IpFilter.init(allocator);
        try self.ip_filter.loadWhitelist(config.ip_whitelist);
        try self.ip_filter.loadBlacklist(config.ip_blacklist);
        self.trusted_proxy_filter = rate_limiter.IpFilter.init(allocator);
        try self.trusted_proxy_filter.loadWhitelist(config.trusted_proxies);
        self.reserved_filter = rate_limiter.IpFilter.init(allocator);
        try self.reserved_filter.loadWhitelist(config.reserved_ips);
        if (config.reserved_connections > 0 and config.reserved_ips.len == 0) {
            log.warn("reserved_connections = {d} but reserved_ips is not set: no client can use those slots", .{config.reserved_connections});
        }
        if (!config.trust_proxy and coversProxyRange(config.reserved_ips)) {
            log.warn("reserved_ips includes a loopback or private range but trust_proxy is off: behind a proxy on such an address every proxied client would be reserved. Set trust_proxy, or keep reserved_ips to addresses that connect directly. Requests carrying X-Forwarded-For or X-Real-IP are never reserved while their headers are ignored", .{});
        }

        const app = App{
            .allocator = allocator,
            .config = config,
            .msg_handler = msg_handler,
            .subs = subs,
            .shutdown = shutdown,
            .nip86_handler = nip86_handler,
            .conn_limiter = &self.conn_limiter,
            .ip_filter = &self.ip_filter,
            .trusted_proxies = &self.trusted_proxy_filter,
            .reserved_ips = &self.reserved_filter,
            .next_id = &self.next_id,
        };

        // Fail fast rather than silently binding loopback: defaulting to 127.0.0.1
        // on a bad host would leave the relay unreachable with no indication why.
        const ip = std.Io.net.IpAddress.parse(config.host, config.port) catch |err| {
            log.err("Invalid bind address {s}:{d}: {} (host must be an IP literal)", .{ config.host, config.port, err });
            return err;
        };
        const address = httpz.Config.Address{ .ip = ip };

        // See computePoolConfig: workers scale with CPU count to spread epoll/accept
        // syscalls, while the handler thread pool is split from a fixed budget so
        // total handler concurrency does not multiply thread/buffer memory per worker.
        const cpu_count = std.Thread.getCpuCount() catch 1;
        const pool_config = computePoolConfig(cpu_count, config.workers);

        // HTTP requests to a relay are small: a WS upgrade (GET /), a NIP-11 doc
        // (GET /), or a NIP-86 management call (POST /). Events arrive over the
        // WebSocket, bounded separately by max_message_size. So the httpz worker
        // buffers are sized for small HTTP bodies, not for event payloads: the
        // per-worker large-buffer pool (large_buffer_count * max_body_size) and
        // the connection preallocation (min_conn) are the main idle-memory draws.
        const max_conn: ?u16 = if (config.max_conn > 0) config.max_conn else null;
        self.httpz_server = try httpz.Server(App).init(io, allocator, .{
            .address = address,
            .request = .{ .max_body_size = 65536 },
            .timeout = .{ .request = http_request_timeout_s, .keepalive = http_keepalive_timeout_s },
            .workers = .{
                .count = pool_config.workers,
                .large_buffer_count = 4,
                // Preallocating more connections than the cap allows is wasteful,
                // and httpz does not clamp it for us.
                .min_conn = if (max_conn) |m| @min(8, m) else 8,
                .max_conn = max_conn,
            },
            .thread_pool = .{ .count = pool_config.pool },
            .websocket = .{ .max_message_size = config.max_message_size },
        }, app);

        var router = try self.httpz_server.router(.{});
        router.get("/", App.getRoot, .{});
        router.get("/metrics", App.getMetrics, .{});
        router.post("/", App.postRoot, .{});
        router.options("/", App.optionsRoot, .{});

        log.info("Server running on {s}:{d}", .{ config.host, config.port });
    }

    pub fn listen(self: *Server) !void {
        try self.httpz_server.listen();
    }

    pub fn stop(self: *Server) void {
        self.httpz_server.stop();
    }

    pub fn deinit(self: *Server) void {
        self.httpz_server.deinit();
        self.conn_limiter.deinit();
        self.ip_filter.deinit();
        self.trusted_proxy_filter.deinit();
        self.reserved_filter.deinit();
    }
};

const testing = std.testing;

// WsConn's lifecycle without an httpz worker: a socketpair stands in for the
// upgraded client socket so afterInit's writes have somewhere to go.
const TestPeer = struct {
    fds: [2]std.c.fd_t,
    ws: websocket.Conn,

    fn init(self: *TestPeer) !void {
        if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &self.fds) != 0) return error.SocketPair;
        self.ws = .{
            .io = nostr.io.io(),
            ._closed = false,
            .started = 0,
            .stream = .{ .socket = .{ .handle = self.fds[0], .address = try std.Io.net.IpAddress.parse("127.0.0.1", 0) } },
            .address = try std.Io.net.IpAddress.parse("127.0.0.1", 0),
        };
    }

    fn deinit(self: *TestPeer) void {
        _ = std.c.close(self.fds[0]);
        _ = std.c.close(self.fds[1]);
    }

    // closeWs() shuts down the read half of the server side, which then reads
    // EOF; an open socket with nothing queued would report EAGAIN instead.
    fn serverReadShutDown(self: *TestPeer) bool {
        var b: [1]u8 = undefined;
        return std.c.recv(self.fds[0], &b, 1, std.c.MSG.DONTWAIT) == 0;
    }

    // Non-blocking read of whatever WsConn wrote to the client side.
    fn received(self: *TestPeer, buf: []u8) []const u8 {
        const n = std.c.recv(self.fds[1], buf.ptr, buf.len, std.c.MSG.DONTWAIT);
        return if (n > 0) buf[0..@intCast(n)] else buf[0..0];
    }
};

const TestRelay = struct {
    config: Config,
    subs: Subscriptions,
    limiter: rate_limiter.ConnectionLimiter,
    ip_filter: rate_limiter.IpFilter,
    reserved_ips: rate_limiter.IpFilter,
    next_id: std.atomic.Value(u64),

    fn init(self: *TestRelay, max_connections: u32, max_per_ip: u32, max_per_subnet: u32) void {
        self.config = Config.defaults();
        self.config.max_connections = max_connections;
        self.subs = Subscriptions.init(testing.allocator);
        self.limiter = rate_limiter.ConnectionLimiter.init(testing.allocator, max_per_ip, .{ .max_connections = max_per_subnet });
        self.ip_filter = rate_limiter.IpFilter.init(testing.allocator);
        self.reserved_ips = rate_limiter.IpFilter.init(testing.allocator);
        self.next_id = .init(0);
    }

    fn deinit(self: *TestRelay) void {
        self.subs.deinit();
        self.limiter.deinit();
        self.ip_filter.deinit();
        self.reserved_ips.deinit();
    }

    fn ctx(self: *TestRelay, ip: []const u8) WsContext {
        var c = WsContext{
            .app = .{
                .allocator = testing.allocator,
                .config = &self.config,
                .msg_handler = undefined,
                .subs = &self.subs,
                .shutdown = undefined,
                .nip86_handler = undefined,
                .conn_limiter = &self.limiter,
                .ip_filter = &self.ip_filter,
                .trusted_proxies = undefined,
                .reserved_ips = &self.reserved_ips,
                .next_id = &self.next_id,
            },
            .client_ip = undefined,
            .client_ip_len = 0,
            .may_be_reserved = true,
        };
        c.setIp(ip);
        return c;
    }
};

test "WsConn init registers the connection and close releases the registry entry and per-IP slot" {
    var relay: TestRelay = undefined;
    relay.init(10, 1, 1);
    defer relay.deinit();
    var peer: TestPeer = undefined;
    try peer.init();
    defer peer.deinit();

    const ctx = relay.ctx("10.0.0.1");
    var ws = try WsConn.init(&peer.ws, &ctx);
    try testing.expectEqual(@as(usize, 1), relay.subs.connectionCount());
    try testing.expectEqualStrings("10.0.0.1", ws.connection.getClientIp());
    try testing.expect(ws.connection.ws_conn == &peer.ws);
    try testing.expect(!relay.limiter.canConnect("10.0.0.1"));

    ws.close();
    try testing.expectEqual(@as(usize, 0), relay.subs.connectionCount());
    try testing.expect(relay.limiter.canConnect("10.0.0.1"));

    // The released slot is reusable, and each connection gets a fresh id.
    var ws2 = try WsConn.init(&peer.ws, &ctx);
    try testing.expectEqual(@as(u64, 1), ws2.connection.id);
    ws2.close();
    try testing.expectEqual(@as(usize, 0), relay.subs.connectionCount());
}

test "WsConn init per-IP rejection leaves the registry untouched" {
    var relay: TestRelay = undefined;
    relay.init(10, 1, 1);
    defer relay.deinit();
    var peer: TestPeer = undefined;
    try peer.init();
    defer peer.deinit();

    const ctx = relay.ctx("10.0.0.2");
    var ws = try WsConn.init(&peer.ws, &ctx);
    defer ws.close();
    try testing.expectError(error.TooManyConnectionsPerIp, WsConn.init(&peer.ws, &ctx));
    try testing.expectEqual(@as(usize, 1), relay.subs.connectionCount());
}

test "WsConn init global-limit rejection gives back the per-IP and subnet slots and frees the connection" {
    var relay: TestRelay = undefined;
    relay.init(1, 1, 2);
    defer relay.deinit();
    var peer: TestPeer = undefined;
    try peer.init();
    defer peer.deinit();

    const ctx_a = relay.ctx("10.0.0.3");
    var ws = try WsConn.init(&peer.ws, &ctx_a);
    defer ws.close();

    // A different IP passes the per-IP check, then hits the global cap. Its
    // bucket must be released, or that IP stays locked out after the rejection.
    // testing.allocator flags the Connection if the errdefer chain leaks it.
    const ctx_b = relay.ctx("10.0.0.4");
    try testing.expectError(error.TooManyConnections, WsConn.init(&peer.ws, &ctx_b));
    try testing.expect(relay.limiter.canConnect("10.0.0.4"));
    try testing.expectEqual(@as(usize, 1), relay.subs.connectionCount());

    // Its subnet slot is back too: the /24 (cap 2) holds only 10.0.0.3, so
    // exactly one more address fits.
    try testing.expectEqual(rate_limiter.ConnectionLimiter.Admission.admitted, relay.limiter.acquire("10.0.0.5"));
    try testing.expectEqual(rate_limiter.ConnectionLimiter.Admission.per_subnet_limit, relay.limiter.acquire("10.0.0.6"));
    relay.limiter.removeConnection("10.0.0.5");
}

test "WsConn init per-subnet rejection holds no slots and other subnets still connect" {
    var relay: TestRelay = undefined;
    relay.init(10, 1, 2);
    defer relay.deinit();
    var peer: TestPeer = undefined;
    try peer.init();
    defer peer.deinit();

    const ctx_a = relay.ctx("185.220.100.1");
    const ctx_b = relay.ctx("::ffff:185.220.100.2");
    const ctx_c = relay.ctx("185.220.100.3");
    var ws_a = try WsConn.init(&peer.ws, &ctx_a);
    var ws_b = try WsConn.init(&peer.ws, &ctx_b);
    defer ws_b.close();

    try testing.expectError(error.TooManyConnectionsPerSubnet, WsConn.init(&peer.ws, &ctx_c));
    try testing.expectEqual(@as(usize, 2), relay.subs.connectionCount());
    // The rejected address's per-IP slot was given back.
    try testing.expect(relay.limiter.canConnect("185.220.100.3"));

    const ctx_other = relay.ctx("185.220.101.1");
    var ws_other = try WsConn.init(&peer.ws, &ctx_other);
    ws_other.close();

    // Closing one connection in the full /24 lets the next address in.
    ws_a.close();
    var ws_c = try WsConn.init(&peer.ws, &ctx_c);
    ws_c.close();
    try testing.expectEqual(@as(usize, 1), relay.subs.connectionCount());
}

test "WsConn afterInit sends the NIP-42 challenge only when auth is configured" {
    var relay: TestRelay = undefined;
    relay.init(10, 10, 10);
    defer relay.deinit();
    var peer: TestPeer = undefined;
    try peer.init();
    defer peer.deinit();
    var buf: [512]u8 = undefined;

    const ctx = relay.ctx("10.0.0.5");
    {
        var ws = try WsConn.init(&peer.ws, &ctx);
        defer ws.close();
        try ws.afterInit();
        try testing.expect(!ws.connection.challenge_sent);
        try testing.expectEqual(@as(usize, 0), peer.received(&buf).len);
    }

    relay.config.auth_required = true;
    {
        var ws = try WsConn.init(&peer.ws, &ctx);
        defer ws.close();
        try ws.afterInit();
        try testing.expect(ws.connection.challenge_sent);
        var hex_buf: [64]u8 = undefined;
        const challenge = std.fmt.bufPrint(&hex_buf, "{x}", .{&ws.connection.auth_challenge}) catch unreachable;
        const frame = peer.received(&buf);
        // A single unmasked text frame carrying ["AUTH","<challenge hex>"].
        try testing.expect(frame.len > 2);
        try testing.expectEqual(@as(u8, 0x81), frame[0]);
        try testing.expect(std.mem.indexOf(u8, frame, "[\"AUTH\",\"") != null);
        try testing.expect(std.mem.indexOf(u8, frame, challenge) != null);
    }
}

test "WsConn concurrent init/close leaves no registry entries or per-IP slots behind" {
    const threads = 8;
    const iterations = 200;
    var relay: TestRelay = undefined;
    relay.init(threads, threads, threads);
    defer relay.deinit();
    var peers: [threads]TestPeer = undefined;
    for (&peers) |*p| try p.init();
    defer for (&peers) |*p| p.deinit();

    const Worker = struct {
        fn run(r: *TestRelay, p: *TestPeer, failures: *std.atomic.Value(u32)) void {
            const ctx = r.ctx("10.0.0.6");
            for (0..iterations) |_| {
                var ws = WsConn.init(&p.ws, &ctx) catch {
                    _ = failures.fetchAdd(1, .monotonic);
                    continue;
                };
                ws.close();
            }
        }
    };
    var failures = std.atomic.Value(u32).init(0);
    var handles: [threads]std.Thread = undefined;
    for (&handles, &peers) |*h, *p| h.* = try std.Thread.spawn(.{}, Worker.run, .{ &relay, p, &failures });
    for (handles) |h| h.join();

    // With per-IP and global limits both equal to the thread count, no init
    // can be rejected unless a close failed to give its slot back.
    try testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), relay.subs.connectionCount());
    try testing.expectEqual(@as(u64, threads * iterations), relay.next_id.load(.monotonic));
    for (0..threads) |_| try testing.expect(relay.limiter.tryAcquireConnection("10.0.0.6"));
    try testing.expect(!relay.limiter.tryAcquireConnection("10.0.0.6"));
}

fn idleFor(ws: *WsConn, seconds: i64) void {
    ws.connection.last_activity.store(nostr.io.timestamp() - seconds, .monotonic);
}

test "reserved slots admit only reserved_ips clients, not ip_whitelist or proxied ones" {
    var relay: TestRelay = undefined;
    relay.init(4, 10, 10);
    defer relay.deinit();
    relay.config.reserved_connections = 2;
    relay.config.evict_idle_seconds = 0;
    try relay.reserved_ips.loadWhitelist("203.0.113.0/24");
    try relay.ip_filter.loadWhitelist("198.51.100.7");
    var peer: TestPeer = undefined;
    try peer.init();
    defer peer.deinit();

    // Two ordinary idle clients fill the unreserved part of the pool.
    const ctx_a = relay.ctx("10.0.0.1");
    const ctx_b = relay.ctx("10.0.1.1");
    var ws_a = try WsConn.init(&peer.ws, &ctx_a);
    defer ws_a.close();
    var ws_b = try WsConn.init(&peer.ws, &ctx_b);
    defer ws_b.close();
    idleFor(&ws_a, 600);
    idleFor(&ws_b, 600);

    // An ordinary newcomer is refused though two slots are free, and gives
    // its limiter slot back.
    const ctx_c = relay.ctx("10.0.2.1");
    try testing.expectError(error.TooManyConnections, WsConn.init(&peer.ws, &ctx_c));
    try testing.expectEqual(@as(usize, 2), relay.subs.connectionCount());
    try testing.expect(relay.limiter.canConnect("10.0.2.1"));

    // ip_whitelist only gates who may connect; it grants no reserved slot.
    const ctx_w = relay.ctx("198.51.100.7");
    try testing.expectError(error.TooManyConnections, WsConn.init(&peer.ws, &ctx_w));

    // A reserved_ips address relayed by a proxy whose headers are not honored
    // is really the proxy's address, so it is not reserved either.
    var ctx_p = relay.ctx("203.0.113.11");
    ctx_p.may_be_reserved = false;
    try testing.expectError(error.TooManyConnections, WsConn.init(&peer.ws, &ctx_p));
    try testing.expectEqual(@as(usize, 2), relay.subs.connectionCount());

    // reserved_ips matches, also seen as IPv4-mapped, get in.
    const ctx_r = relay.ctx("::ffff:203.0.113.9");
    var ws_r = try WsConn.init(&peer.ws, &ctx_r);
    defer ws_r.close();
    try testing.expect(ws_r.connection.reserved);
    const ctx_r2 = relay.ctx("203.0.113.10");
    var ws_r2 = try WsConn.init(&peer.ws, &ctx_r2);
    defer ws_r2.close();
    try testing.expect(!ws_a.connection.reserved);
    try testing.expectEqual(@as(usize, 4), relay.subs.connectionCount());

    // max_connections still binds reserved clients.
    const ctx_r3 = relay.ctx("203.0.113.12");
    try testing.expectError(error.TooManyConnections, WsConn.init(&peer.ws, &ctx_r3));
}

test "a newcomer evicts the longest-idle connection, whose limiter slots free on close" {
    var relay: TestRelay = undefined;
    relay.init(3, 1, 1);
    defer relay.deinit();
    var peers: [4]TestPeer = undefined;
    for (&peers) |*p| try p.init();
    defer for (&peers) |*p| p.deinit();

    const ctx_0 = relay.ctx("10.0.1.1");
    const ctx_1 = relay.ctx("10.0.2.1");
    const ctx_2 = relay.ctx("10.0.3.1");
    var ws_0 = try WsConn.init(&peers[0].ws, &ctx_0);
    defer ws_0.close();
    var ws_1 = try WsConn.init(&peers[1].ws, &ctx_1);
    var ws_2 = try WsConn.init(&peers[2].ws, &ctx_2);
    defer ws_2.close();
    idleFor(&ws_0, 300);
    idleFor(&ws_1, 400);
    // Silent for less than evict_idle_seconds (120): never a candidate.
    idleFor(&ws_2, 5);

    const ctx_new = relay.ctx("10.0.4.1");
    var ws_new = try WsConn.init(&peers[3].ws, &ctx_new);
    defer ws_new.close();
    try testing.expectEqual(@as(usize, 3), relay.subs.connectionCount());

    // Only the longest-idle connection was told to close.
    try testing.expect(peers[1].serverReadShutDown());
    try testing.expect(!peers[0].serverReadShutDown());
    try testing.expect(!peers[2].serverReadShutDown());
    try testing.expect(!peers[3].serverReadShutDown());

    // The victim keeps its limiter slots until its worker runs close().
    try testing.expect(!relay.limiter.canConnect("10.0.2.1"));
    ws_1.close();
    try testing.expectEqual(@as(usize, 3), relay.subs.connectionCount());
    try testing.expect(relay.limiter.canConnect("10.0.2.1"));
    try testing.expectEqual(rate_limiter.ConnectionLimiter.Admission.admitted, relay.limiter.acquire("10.0.2.2"));
    relay.limiter.removeConnection("10.0.2.2");

    // The next newcomer takes the remaining idle connection, never the recent one.
    const ctx_next = relay.ctx("10.0.5.1");
    var ws_next = try WsConn.init(&peers[1].ws, &ctx_next);
    defer ws_next.close();
    try testing.expect(peers[0].serverReadShutDown());
    try testing.expect(!peers[2].serverReadShutDown());
}

test "a full pool of subscribed, recently active or reserved connections refuses newcomers" {
    var relay: TestRelay = undefined;
    relay.init(3, 10, 10);
    defer relay.deinit();
    try relay.reserved_ips.loadWhitelist("203.0.113.5");
    var peers: [3]TestPeer = undefined;
    for (&peers) |*p| try p.init();
    defer for (&peers) |*p| p.deinit();

    var req = try nostr.ClientMsg.parse("[\"REQ\",\"s\",{\"kinds\":[1]}]");
    defer req.deinit();

    const ctx_sub = relay.ctx("10.0.0.1");
    var ws_sub = try WsConn.init(&peers[0].ws, &ctx_sub);
    defer ws_sub.close();
    try relay.subs.subscribe(ws_sub.connection, "s", try req.getFilters(ws_sub.connection.allocator()), 5);
    const ctx_recent = relay.ctx("10.0.1.1");
    var ws_recent = try WsConn.init(&peers[1].ws, &ctx_recent);
    defer ws_recent.close();
    const ctx_res = relay.ctx("203.0.113.5");
    var ws_res = try WsConn.init(&peers[2].ws, &ctx_res);
    defer ws_res.close();
    idleFor(&ws_sub, 600);
    idleFor(&ws_recent, 1);
    idleFor(&ws_res, 600);

    const ctx_new = relay.ctx("10.0.2.1");
    try testing.expectError(error.TooManyConnections, WsConn.init(&peers[0].ws, &ctx_new));
    try testing.expectEqual(@as(usize, 3), relay.subs.connectionCount());
    try testing.expect(relay.limiter.canConnect("10.0.2.1"));
    for (&peers) |*p| try testing.expect(!p.serverReadShutDown());

    // A long-idle connection with an open subscription is still protected.
    // Clear the no-victim backoff the refusal above set, so this really scans.
    try relay.subs.subscribe(ws_recent.connection, "s", try req.getFilters(ws_recent.connection.allocator()), 5);
    idleFor(&ws_recent, 600);
    relay.subs.noteEvictable();
    try testing.expectError(error.TooManyConnections, WsConn.init(&peers[0].ws, &ctx_new));
    for (&peers) |*p| try testing.expect(!p.serverReadShutDown());

    // Closing its last subscription makes a connection evictable again.
    relay.subs.unsubscribe(ws_sub.connection, "s");
    var peer_new: TestPeer = undefined;
    try peer_new.init();
    defer peer_new.deinit();
    var ws_new = try WsConn.init(&peer_new.ws, &ctx_new);
    defer ws_new.close();
    try testing.expect(peers[0].serverReadShutDown());
    try testing.expect(!peers[1].serverReadShutDown());
    try testing.expect(!peers[2].serverReadShutDown());
}

test "a refused scan backs off for a second; closing a NIP-77 session or the last subscription clears it" {
    var relay: TestRelay = undefined;
    relay.init(2, 10, 10);
    defer relay.deinit();
    var peers: [3]TestPeer = undefined;
    for (&peers) |*p| try p.init();
    defer for (&peers) |*p| p.deinit();

    const ctx_a = relay.ctx("10.0.0.1");
    var ws_a = try WsConn.init(&peers[0].ws, &ctx_a);
    defer ws_a.close();
    const ctx_b = relay.ctx("10.0.1.1");
    var ws_b = try WsConn.init(&peers[1].ws, &ctx_b);
    defer ws_b.close();
    idleFor(&ws_a, 1);
    idleFor(&ws_b, 1);

    // An all-active pool: the scan finds nobody and records now + 1.
    const ctx_new = relay.ctx("10.0.2.1");
    const before = nostr.io.timestamp();
    try testing.expectError(error.TooManyConnections, WsConn.init(&peers[2].ws, &ctx_new));
    const after = nostr.io.timestamp();
    const t = relay.subs.no_victim_before.load(.monotonic);
    try testing.expect(t >= before + 1 and t <= after + 1);

    // While the backoff holds, a connection that turned evictable without
    // telling the registry is not found yet. (Pin the backoff in the future so
    // a second boundary cannot end it mid-test.)
    idleFor(&ws_a, 600);
    relay.subs.no_victim_before.store(nostr.io.timestamp() + 60, .monotonic);
    try testing.expectError(error.TooManyConnections, WsConn.init(&peers[2].ws, &ctx_new));
    try testing.expect(!peers[0].serverReadShutDown());

    // An open NIP-77 session protects an idle connection like a subscription.
    _ = try ws_a.connection.addNegSession("neg");
    relay.subs.noteEvictable();
    try testing.expectError(error.TooManyConnections, WsConn.init(&peers[2].ws, &ctx_new));
    try testing.expect(!peers[0].serverReadShutDown());

    // Closing it (the handler calls noteEvictable once the last one is gone)
    // makes the next upgrade rescan at once and evict.
    relay.subs.no_victim_before.store(nostr.io.timestamp() + 60, .monotonic);
    ws_a.connection.removeNegSession("neg");
    try testing.expectEqual(@as(u32, 0), ws_a.connection.neg_session_count.load(.monotonic));
    relay.subs.noteEvictable();
    var ws_new = try WsConn.init(&peers[2].ws, &ctx_new);
    defer ws_new.close();
    try testing.expect(peers[0].serverReadShutDown());
    try testing.expect(!peers[1].serverReadShutDown());

    // unsubscribe() clears the backoff itself when the last subscription goes.
    var req = try nostr.ClientMsg.parse("[\"REQ\",\"s\",{\"kinds\":[1]}]");
    defer req.deinit();
    try relay.subs.subscribe(ws_b.connection, "s", try req.getFilters(ws_b.connection.allocator()), 5);
    relay.subs.no_victim_before.store(nostr.io.timestamp() + 60, .monotonic);
    relay.subs.unsubscribe(ws_b.connection, "s");
    try testing.expectEqual(@as(i64, 0), relay.subs.no_victim_before.load(.monotonic));
}

test "reserved headroom and eviction together" {
    var relay: TestRelay = undefined;
    relay.init(4, 10, 10);
    defer relay.deinit();
    relay.config.reserved_connections = 1;
    try relay.reserved_ips.loadWhitelist("203.0.113.0/24");
    var peers: [7]TestPeer = undefined;
    for (&peers) |*p| try p.init();
    defer for (&peers) |*p| p.deinit();

    // Ordinary clients fill max_connections - reserved_connections.
    const ctx_a = relay.ctx("10.0.0.1");
    var ws_a = try WsConn.init(&peers[0].ws, &ctx_a);
    defer ws_a.close();
    const ctx_b = relay.ctx("10.0.1.1");
    var ws_b = try WsConn.init(&peers[1].ws, &ctx_b);
    defer ws_b.close();
    const ctx_c = relay.ctx("10.0.2.1");
    var ws_c = try WsConn.init(&peers[2].ws, &ctx_c);
    defer ws_c.close();
    idleFor(&ws_a, 600);
    idleFor(&ws_b, 500);
    idleFor(&ws_c, 400);

    // An ordinary newcomer at the unreserved limit evicts, though the
    // headroom slot is still free: it may not use that slot.
    const ctx_d = relay.ctx("10.0.3.1");
    var ws_d = try WsConn.init(&peers[3].ws, &ctx_d);
    defer ws_d.close();
    try testing.expect(peers[0].serverReadShutDown());
    try testing.expectEqual(@as(usize, 3), relay.subs.connectionCount());

    // A reserved client takes the free headroom slot without evicting anyone.
    const ctx_r1 = relay.ctx("203.0.113.1");
    var ws_r1 = try WsConn.init(&peers[4].ws, &ctx_r1);
    defer ws_r1.close();
    try testing.expect(!peers[1].serverReadShutDown());
    try testing.expectEqual(@as(usize, 4), relay.subs.connectionCount());
    // Reserved clients are never victims, however long idle.
    idleFor(&ws_r1, 3600);
    idleFor(&ws_d, 1);

    // With every slot taken, a reserved newcomer evicts the longest-idle
    // ordinary connection.
    const ctx_r2 = relay.ctx("203.0.113.2");
    var ws_r2 = try WsConn.init(&peers[5].ws, &ctx_r2);
    defer ws_r2.close();
    try testing.expect(peers[1].serverReadShutDown());
    try testing.expect(!peers[2].serverReadShutDown());
    try testing.expect(!peers[3].serverReadShutDown());
    try testing.expect(!peers[4].serverReadShutDown());
    try testing.expectEqual(@as(usize, 4), relay.subs.connectionCount());
}

test "EvictionLog flushes a pending count once per interval, including after the evictions stop" {
    var el: EvictionLog = .{};
    try testing.expectEqual(@as(?u64, null), el.take(1000));
    _ = el.pending.fetchAdd(3, .monotonic);
    try testing.expectEqual(@as(?u64, 3), el.take(1000));
    // A burst inside the interval waits; the periodic flush picks it up once
    // the interval has passed, with no further eviction needed.
    _ = el.pending.fetchAdd(2, .monotonic);
    try testing.expectEqual(@as(?u64, null), el.take(1030));
    try testing.expectEqual(@as(?u64, 2), el.take(1060));
    try testing.expectEqual(@as(?u64, null), el.take(1200));
}

test "eviction disabled keeps the 503 when the pool is full of idle connections" {
    var relay: TestRelay = undefined;
    relay.init(1, 10, 10);
    defer relay.deinit();
    relay.config.evict_idle_seconds = 0;
    var peers: [2]TestPeer = undefined;
    for (&peers) |*p| try p.init();
    defer for (&peers) |*p| p.deinit();

    const ctx_a = relay.ctx("10.0.0.1");
    var ws_a = try WsConn.init(&peers[0].ws, &ctx_a);
    defer ws_a.close();
    idleFor(&ws_a, 3600);
    const ctx_b = relay.ctx("10.0.1.1");
    try testing.expectError(error.TooManyConnections, WsConn.init(&peers[1].ws, &ctx_b));
    try testing.expect(!peers[0].serverReadShutDown());
}
