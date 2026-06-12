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
            if (try httpz.upgradeWebsocket(WsConn, req, res, &ctx) == false) {
                res.status = 400;
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
                try nip11.write(app.config, app.nip86_handler, w);
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
        const xff = req.header("x-forwarded-for");
        const xrip = req.header("x-real-ip");
        return rate_limiter.extractClientIp(xff, xrip, socket_ip, true);
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
        if (!app.conn_limiter.tryAcquireConnection(ip)) return error.TooManyConnectionsPerIp;
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
        try app.subs.tryAddConnection(connection, app.config.max_connections);

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

/// Owns the httpz server plus the per-IP limiter / filter / id counter that the
/// App points into.
pub const Server = struct {
    allocator: std.mem.Allocator,
    httpz_server: httpz.Server(App),
    conn_limiter: rate_limiter.ConnectionLimiter,
    ip_filter: rate_limiter.IpFilter,
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

        const app = App{
            .allocator = allocator,
            .config = config,
            .msg_handler = msg_handler,
            .subs = subs,
            .shutdown = shutdown,
            .nip86_handler = nip86_handler,
            .conn_limiter = &self.conn_limiter,
            .ip_filter = &self.ip_filter,
            .next_id = &self.next_id,
        };

        // Fail fast rather than silently binding loopback: defaulting to 127.0.0.1
        // on a bad host would leave the relay unreachable with no indication why.
        const ip = std.Io.net.IpAddress.parse(config.host, config.port) catch |err| {
            log.err("Invalid bind address {s}:{d}: {} (host must be an IP literal)", .{ config.host, config.port, err });
            return err;
        };
        const address = httpz.Config.Address{ .ip = ip };

        // Each httpz worker runs one epoll loop and dispatches connection work
        // to its own thread pool; a single connection is never processed by two
        // threads at once. httpz defaults to 1 worker, so the epoll readiness
        // loop is single-threaded; adding workers spreads that epoll/accept
        // syscall load across cores. The per-worker thread pool runs the actual
        // WS message handlers (REQ streaming, EVENT broadcast), which do
        // blocking socket writes, so it stays at httpz's default of 32 to keep
        // the slow-client tolerance the single-worker default already had.
        const cpu_count = std.Thread.getCpuCount() catch 1;
        const worker_count: u16 = @intCast(@max(@as(usize, 1), @min(cpu_count, 4)));

        self.httpz_server = try httpz.Server(App).init(io, allocator, .{
            .address = address,
            .request = .{ .max_body_size = 131072 },
            .workers = .{ .count = worker_count },
            .thread_pool = .{ .count = 32 },
            .websocket = .{ .max_message_size = config.max_message_size },
        }, app);

        var router = try self.httpz_server.router(.{});
        router.get("/", App.getRoot, .{});
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
    }
};
