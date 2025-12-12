const std = @import("std");
const httpz = @import("httpz");
const websocket = httpz.websocket;

const Config = @import("config.zig").Config;
const MsgHandler = @import("handler.zig").Handler;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const Connection = @import("connection.zig").Connection;
const nip11 = @import("nip11.zig");
const nostr = @import("nostr.zig");
const rate_limiter = @import("rate_limiter.zig");
const posix = std.posix;

pub const std_options = std.Options{ .log_scope_levels = &[_]std.log.ScopeLevel{
    .{ .scope = .websocket, .level = .err },
} };

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    handler: *MsgHandler,
    subs: *Subscriptions,

    next_id: u64 = 0,
    mutex: std.Thread.Mutex,

    http_server: ?HttpServer = null,

    conn_limiter: rate_limiter.ConnectionLimiter,
    ip_filter: rate_limiter.IpFilter,

    const HttpServer = httpz.Server(Handler);

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const Config,
        handler: *MsgHandler,
        subs: *Subscriptions,
    ) !Server {
        var ip_filter = rate_limiter.IpFilter.init(allocator);
        try ip_filter.loadWhitelist(config.ip_whitelist);
        try ip_filter.loadBlacklist(config.ip_blacklist);

        return .{
            .allocator = allocator,
            .config = config,
            .handler = handler,
            .subs = subs,
            .mutex = .{},
            .conn_limiter = rate_limiter.ConnectionLimiter.init(allocator, config.max_connections_per_ip),
            .ip_filter = ip_filter,
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.http_server) |*s| {
            s.deinit();
        }
        self.conn_limiter.deinit();
        self.ip_filter.deinit();
    }

    pub fn run(self: *Server, shutdown: *std.atomic.Value(bool)) !void {
        _ = shutdown;

        const h = Handler{
            .server = self,
        };

        var server = try HttpServer.init(self.allocator, .{
            .port = self.config.port,
            .address = self.config.host,
        }, h);
        self.http_server = server;

        defer server.deinit();
        defer server.stop();

        var router = try server.router(.{});
        router.get("/", index, .{});

        std.log.info("Server running on {s}:{d}", .{ self.config.host, self.config.port });

        try server.listen();
    }

    pub fn send(self: *Server, conn_id: u64, data: []const u8) void {
        if (self.subs.getConnection(conn_id)) |conn| {
            conn.send(data);
        }
    }

    pub fn connectionCount(self: *Server) usize {
        return self.subs.connectionCount();
    }
};

const Handler = struct {
    server: *Server,

    pub const WebsocketHandler = WsClient;
};

const WsClient = struct {
    id: u64,
    conn: *websocket.Conn,
    connection: *Connection,
    server: *Server,

    pub const Context = struct {
        server: *Server,
        client_ip: []const u8,
    };

    pub fn init(ws_conn: *websocket.Conn, ctx: *const Context) !WsClient {
        const server = ctx.server;
        const allocator = server.allocator;
        const client_ip = ctx.client_ip;

        const TCP_NODELAY = 1;
        posix.setsockopt(ws_conn.stream.handle, posix.IPPROTO.TCP, TCP_NODELAY, &std.mem.toBytes(@as(i32, 1))) catch {};

        if (!server.ip_filter.isAllowed(client_ip)) {
            return error.IpBlocked;
        }

        if (!server.conn_limiter.canConnect(client_ip)) {
            return error.TooManyConnectionsFromIp;
        }

        server.mutex.lock();
        if (server.subs.connectionCount() >= server.config.max_connections) {
            server.mutex.unlock();
            return error.TooManyConnections;
        }
        const conn_id = server.next_id;
        server.next_id += 1;
        server.mutex.unlock();

        const connection = try allocator.create(Connection);
        connection.init(allocator, conn_id);
        connection.setClientIp(client_ip);

        connection.ws_conn = ws_conn;

        server.subs.addConnection(connection) catch {
            connection.deinit();
            allocator.destroy(connection);
            return error.ConnectionFailed;
        };

        server.conn_limiter.addConnection(client_ip);

        return WsClient{
            .id = conn_id,
            .conn = ws_conn,
            .connection = connection,
            .server = server,
        };
    }

    fn sendAuthChallenge(self: *WsClient) void {
        if (self.connection.challenge_sent) return;

        var buf: [256]u8 = undefined;
        const auth_msg = nostr.RelayMsg.auth(&self.connection.auth_challenge, &buf) catch return;
        self.conn.write(auth_msg) catch {};
        self.connection.challenge_sent = true;
    }

    pub fn clientMessage(self: *WsClient, data: []const u8) !void {
        if (self.server.config.auth_required or self.server.config.auth_to_write) {
            self.sendAuthChallenge();
        }

        if (data.len > self.server.config.max_message_size) {
            var buf: [256]u8 = undefined;
            const notice = nostr.RelayMsg.notice("error: message too large", &buf) catch return;
            try self.conn.write(notice);
            return;
        }

        self.server.handler.handle(self.connection, data);
    }

    pub fn close(self: *WsClient) void {
        const server = self.server;
        const allocator = server.allocator;

        const client_ip = self.connection.getClientIp();
        if (client_ip.len > 0) {
            server.conn_limiter.removeConnection(client_ip);
        }

        server.subs.removeConnection(self.id);
        self.connection.deinit();
        allocator.destroy(self.connection);
    }
};

fn index(h: Handler, req: *httpz.Request, res: *httpz.Response) !void {
    if (req.header("upgrade")) |upgrade| {
        if (std.ascii.eqlIgnoreCase(upgrade, "websocket")) {
            var addr_buf: [64]u8 = undefined;
            const remote_addr = std.fmt.bufPrint(&addr_buf, "{any}", .{req.address}) catch "unknown";

            const client_ip = rate_limiter.extractClientIp(
                req.header("x-forwarded-for"),
                req.header("x-real-ip"),
                remote_addr,
                h.server.config.trust_proxy,
            );

            const ctx = WsClient.Context{ .server = h.server, .client_ip = client_ip };
            if (try httpz.upgradeWebsocket(WsClient, req, res, &ctx) == false) {
                res.status = 400;
                res.body = "invalid websocket handshake";
            }
            return;
        }
    }

    if (req.header("accept")) |accept| {
        if (std.mem.indexOf(u8, accept, "application/nostr+json") != null) {
            res.header("Content-Type", "application/nostr+json");
            res.header("Access-Control-Allow-Origin", "*");
            res.header("Access-Control-Allow-Headers", "*");
            res.header("Access-Control-Allow-Methods", "GET, OPTIONS");
            nip11.write(h.server.config, res.writer()) catch {
                res.status = 500;
            };
            return;
        }
    }

    res.content_type = .HTML;
    res.body =
        \\<!DOCTYPE html>
        \\<html><head><title>Wisp</title></head>
        \\<body>
        \\<h1>Wisp Nostr Relay</h1>
        \\<p>Connect via WebSocket at this URL.</p>
        \\</body></html>
    ;
}
