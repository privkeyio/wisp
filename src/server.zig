const std = @import("std");
const httpz = @import("httpz");
const websocket = httpz.websocket;

const Config = @import("config.zig").Config;
const MsgHandler = @import("handler.zig").Handler;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const Connection = @import("connection.zig").Connection;
const nip11 = @import("nip11.zig");
const nostr = @import("nostr.zig");

// Limit websocket.zig verbosity to errors only
pub const std_options = std.Options{ .log_scope_levels = &[_]std.log.ScopeLevel{
    .{ .scope = .websocket, .level = .err },
} };

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    handler: *MsgHandler,
    subs: *Subscriptions,

    connections: std.AutoHashMap(u64, *WsClient),
    next_id: u64 = 0,
    mutex: std.Thread.Mutex,

    http_server: ?HttpServer = null,

    const HttpServer = httpz.Server(Handler);

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const Config,
        handler: *MsgHandler,
        subs: *Subscriptions,
    ) !Server {
        return .{
            .allocator = allocator,
            .config = config,
            .handler = handler,
            .subs = subs,
            .connections = std.AutoHashMap(u64, *WsClient).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.http_server) |*s| {
            s.deinit();
        }
        self.connections.deinit();
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
        self.mutex.lock();
        const client = self.connections.get(conn_id);
        self.mutex.unlock();

        if (client) |c| {
            c.conn.write(data) catch {};
        }
    }
};

// Handler struct required by httpz for WebSocket support
const Handler = struct {
    server: *Server,

    pub const WebsocketHandler = WsClient;
};

// WebSocket client handler
const WsClient = struct {
    id: u64,
    conn: *websocket.Conn,
    connection: *Connection,
    server: *Server,

    pub const Context = struct {
        server: *Server,
    };

    pub fn init(ws_conn: *websocket.Conn, ctx: *const Context) !WsClient {
        const server = ctx.server;
        const allocator = server.allocator;

        server.mutex.lock();
        if (server.connections.count() >= server.config.max_connections) {
            server.mutex.unlock();
            return error.TooManyConnections;
        }
        const conn_id = server.next_id;
        server.next_id += 1;
        server.mutex.unlock();

        const connection = try allocator.create(Connection);
        connection.* = Connection.init(allocator, conn_id);

        var client = WsClient{
            .id = conn_id,
            .conn = ws_conn,
            .connection = connection,
            .server = server,
        };

        server.mutex.lock();
        server.connections.put(conn_id, &client) catch {
            server.mutex.unlock();
            connection.deinit();
            allocator.destroy(connection);
            return error.ConnectionFailed;
        };
        server.mutex.unlock();

        server.subs.addConnection(connection) catch {};

        return client;
    }

    pub fn clientMessage(self: *WsClient, data: []const u8) !void {
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

        server.mutex.lock();
        _ = server.connections.remove(self.id);
        server.mutex.unlock();

        server.subs.removeConnection(self.id);
        self.connection.deinit();
        allocator.destroy(self.connection);
    }
};

// HTTP route handlers
fn index(h: Handler, req: *httpz.Request, res: *httpz.Response) !void {
    // Check for WebSocket upgrade
    if (req.header("upgrade")) |upgrade| {
        if (std.ascii.eqlIgnoreCase(upgrade, "websocket")) {
            const ctx = WsClient.Context{ .server = h.server };
            if (try httpz.upgradeWebsocket(WsClient, req, res, &ctx) == false) {
                res.status = 400;
                res.body = "invalid websocket handshake";
            }
            return;
        }
    }

    // Check for NIP-11 request
    if (req.header("accept")) |accept| {
        if (std.mem.indexOf(u8, accept, "application/nostr+json") != null) {
            var body_buf: [4096]u8 = undefined;
            const body = nip11.serialize(h.server.config, &body_buf) catch {
                res.status = 500;
                return;
            };
            res.header("Content-Type", "application/nostr+json");
            res.header("Access-Control-Allow-Origin", "*");
            res.header("Access-Control-Allow-Headers", "*");
            res.header("Access-Control-Allow-Methods", "GET, OPTIONS");
            res.body = body;
            return;
        }
    }

    // Default HTML response
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
