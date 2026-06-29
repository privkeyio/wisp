const std = @import("std");
const httpz = @import("httpz");
const websocket = httpz.websocket;
const nostr = @import("nostr.zig");

const Config = @import("config.zig").Config;
const MsgHandler = @import("handler.zig").Handler;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const Connection = @import("connection.zig").Connection;
const nip11 = @import("nip11.zig");
const rate_limiter = @import("rate_limiter.zig");
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
            var ctx = WsContext{ .app = app, .client_ip_len = 0, .client_ip = undefined };
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
                error.TooManyConnections => {
                    res.status = 503;
                    res.content_type = .TEXT;
                    res.body = "server connection limit reached";
                    log.warn("connection rejected (global limit): {s}", .{safeIp(client_ip, &log_ip_buf)});
                    return;
                },
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

        if (app.config.admin_pubkeys.len == 0) {
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

    /// GET /metrics — Prometheus operational metrics. Honors the same IP policy
    /// as the relay, so an operator allowlist/blocklist also covers the scraper.
    pub fn getMetrics(app: App, req: *httpz.Request, res: *httpz.Response) !void {
        var ip_buf: [64]u8 = undefined;
        if (app.ipDenied(app.clientIp(req, res, &ip_buf))) {
            res.status = 403;
            return;
        }
        res.header("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
        const w = res.writer();
        try metrics.write(w, app.subs.connectionCount());
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

        // Atomic per-IP connection limit.
        if (!app.conn_limiter.tryAcquireConnection(ip)) {
            metrics.rateLimited();
            return error.TooManyConnectionsPerIp;
        }
        errdefer app.conn_limiter.removeConnection(ip);

        const connection = try app.allocator.create(Connection);
        errdefer app.allocator.destroy(connection);
        const id = app.next_id.fetchAdd(1, .monotonic);
        connection.init(app.allocator, id);
        connection.setWsConn(conn);
        connection.setClientIp(ip);

        // Restore the accept-time socket tuning the worker-pool migration dropped:
        // disable Nagle, and bound how long a write to a stalled client can block.
        // Broadcast and REQ-stream writes are synchronous, so without a send timeout
        // a stuck client pins a worker (and, for REQ, an open LMDB read txn) until it
        // disconnects. On timeout the write errors and the stream/broadcast unwinds.
        const fd = conn.stream.socket.handle;
        const TCP_NODELAY = 1;
        std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, TCP_NODELAY, &std.mem.toBytes(@as(i32, 1))) catch {};
        const send_timeout = std.posix.timeval{ .sec = 10, .usec = 0 };
        std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, &std.mem.toBytes(send_timeout)) catch {};
        errdefer connection.deinit();

        // Global connection limit + registry.
        app.subs.tryAddConnection(connection, app.config.max_connections) catch |err| {
            metrics.rateLimited();
            return err;
        };
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

fn formatPeerIp(address: anytype, buf: *[64]u8) []const u8 {
    const formatted = std.fmt.bufPrint(buf, "{f}", .{address}) catch return "unknown";
    // IPv6 is "[addr]:port"; return the bracketed address.
    if (formatted.len > 0 and formatted[0] == '[') {
        if (std.mem.indexOfScalar(u8, formatted, ']')) |end| return formatted[1..end];
    }
    if (std.mem.lastIndexOf(u8, formatted, ":")) |colon| return formatted[0..colon];
    return formatted;
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
    const long = "1" ** 100;
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
pub const Server = struct {
    allocator: std.mem.Allocator,
    httpz_server: httpz.Server(App),
    conn_limiter: rate_limiter.ConnectionLimiter,
    ip_filter: rate_limiter.IpFilter,
    trusted_proxy_filter: rate_limiter.IpFilter,
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
        self.conn_limiter = rate_limiter.ConnectionLimiter.init(allocator, config.max_connections_per_ip);
        self.ip_filter = rate_limiter.IpFilter.init(allocator);
        try self.ip_filter.loadWhitelist(config.ip_whitelist);
        try self.ip_filter.loadBlacklist(config.ip_blacklist);
        self.trusted_proxy_filter = rate_limiter.IpFilter.init(allocator);
        try self.trusted_proxy_filter.loadWhitelist(config.trusted_proxies);

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
        self.httpz_server = try httpz.Server(App).init(io, allocator, .{
            .address = address,
            .request = .{ .max_body_size = 65536 },
            .workers = .{
                .count = pool_config.workers,
                .large_buffer_count = 4,
                .min_conn = 8,
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
    }
};
