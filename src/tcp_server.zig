const std = @import("std");
const net = std.net;
const posix = std.posix;
const nostr = @import("nostr.zig");
const ws = nostr.ws;

const Config = @import("config.zig").Config;
const MsgHandler = @import("handler.zig").Handler;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const Connection = @import("connection.zig").Connection;
const nip11 = @import("nip11.zig");
const rate_limiter = @import("rate_limiter.zig");
const write_queue = @import("write_queue.zig");

const WsWriter = struct {
    stream: net.Stream,
    mutex: std.Thread.Mutex = .{},
    failed: bool = false,

    fn write(ctx: *anyopaque, data: []const u8) void {
        const self: *WsWriter = @ptrCast(@alignCast(ctx));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.failed) return;
        self.writeWsFrame(data) catch {
            self.failed = true;
        };
    }

    fn writeWsFrame(self: *WsWriter, data: []const u8) !void {
        var header: [14]u8 = undefined;
        var header_len: usize = 2;

        header[0] = 0x81;

        if (data.len < 126) {
            header[1] = @intCast(data.len);
        } else if (data.len < 65536) {
            header[1] = 126;
            header[2] = @intCast((data.len >> 8) & 0xFF);
            header[3] = @intCast(data.len & 0xFF);
            header_len = 4;
        } else {
            header[1] = 127;
            const len64: u64 = data.len;
            header[2] = @intCast((len64 >> 56) & 0xFF);
            header[3] = @intCast((len64 >> 48) & 0xFF);
            header[4] = @intCast((len64 >> 40) & 0xFF);
            header[5] = @intCast((len64 >> 32) & 0xFF);
            header[6] = @intCast((len64 >> 24) & 0xFF);
            header[7] = @intCast((len64 >> 16) & 0xFF);
            header[8] = @intCast((len64 >> 8) & 0xFF);
            header[9] = @intCast(len64 & 0xFF);
            header_len = 10;
        }

        var iovecs = [_]std.posix.iovec_const{
            .{ .base = &header, .len = header_len },
            .{ .base = data.ptr, .len = data.len },
        };
        _ = try self.stream.writev(&iovecs);
    }
};

pub const TcpServer = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    handler: *MsgHandler,
    subs: *Subscriptions,

    next_id: u64 = 0,
    mutex: std.Thread.Mutex = .{},

    listener: ?net.Server = null,
    shutdown: *std.atomic.Value(bool),

    conn_limiter: rate_limiter.ConnectionLimiter,
    ip_filter: rate_limiter.IpFilter,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const Config,
        handler: *MsgHandler,
        subs: *Subscriptions,
        shutdown: *std.atomic.Value(bool),
    ) !TcpServer {
        var ip_filter = rate_limiter.IpFilter.init(allocator);
        try ip_filter.loadWhitelist(config.ip_whitelist);
        try ip_filter.loadBlacklist(config.ip_blacklist);

        return .{
            .allocator = allocator,
            .config = config,
            .handler = handler,
            .subs = subs,
            .shutdown = shutdown,
            .conn_limiter = rate_limiter.ConnectionLimiter.init(allocator, config.max_connections_per_ip),
            .ip_filter = ip_filter,
        };
    }

    pub fn deinit(self: *TcpServer) void {
        if (self.listener) |*l| {
            l.deinit();
            self.listener = null;
        }
        self.conn_limiter.deinit();
        self.ip_filter.deinit();
    }

    pub fn run(self: *TcpServer) !void {
        const address = try net.Address.parseIp(self.config.host, self.config.port);
        self.listener = try address.listen(.{
            .reuse_address = true,
        });

        std.log.info("Server running on {s}:{d}", .{ self.config.host, self.config.port });

        const idle_thread = std.Thread.spawn(.{}, idleTimeoutThread, .{ self, self.shutdown }) catch null;
        defer if (idle_thread) |t| t.join();

        while (!self.shutdown.load(.acquire)) {
            const conn = self.listener.?.accept() catch |err| {
                if (err == error.SocketNotListening) break;
                continue;
            };

            const thread = std.Thread.spawn(.{}, handleConnection, .{ self, conn }) catch |err| {
                std.log.warn("Failed to spawn connection thread: {}", .{err});
                conn.stream.close();
                continue;
            };
            thread.detach();
        }

        std.log.info("Shutting down server...", .{});
        if (self.listener) |*l| {
            l.deinit();
            self.listener = null;
        }
        std.Thread.sleep(200 * std.time.ns_per_ms);
    }

    fn idleTimeoutThread(self: *TcpServer, shutdown: *std.atomic.Value(bool)) void {
        const check_interval_s: u64 = 30;
        var seconds_waited: u64 = 0;

        while (!shutdown.load(.acquire)) {
            std.Thread.sleep(std.time.ns_per_s);
            if (shutdown.load(.acquire)) break;
            seconds_waited += 1;
            if (seconds_waited < check_interval_s) continue;
            seconds_waited = 0;

            if (self.config.idle_seconds == 0) continue;

            const idle_conn_ids = self.subs.getIdleConnections(self.config.idle_seconds);
            defer self.allocator.free(idle_conn_ids);

            for (idle_conn_ids) |conn_id| {
                var buf: [128]u8 = undefined;
                const notice = nostr.RelayMsg.notice("connection closed: idle timeout", &buf) catch continue;
                if (self.subs.closeIdleConnection(conn_id, notice)) {
                    std.log.debug("Closed idle connection {d}", .{conn_id});
                }
            }
        }
    }

    pub fn stop(self: *TcpServer) void {
        if (self.listener) |*l| {
            l.deinit();
            self.listener = null;
        }
    }

    fn handleConnection(self: *TcpServer, conn: net.Server.Connection) void {
        defer conn.stream.close();

        // Check shutdown early to avoid accessing freed resources
        if (self.shutdown.load(.acquire)) return;

        var addr_buf: [64]u8 = undefined;
        const client_ip = extractIp(conn.address, &addr_buf);

        if (self.shutdown.load(.acquire)) return;

        if (!self.ip_filter.isAllowed(client_ip)) {
            return;
        }

        if (!self.conn_limiter.canConnect(client_ip)) {
            return;
        }

        var buf: [8192]u8 = undefined;
        const n = conn.stream.read(&buf) catch return;
        if (n == 0) return;

        const req_data = buf[0..n];

        if (isWebsocketUpgrade(req_data)) {
            self.handleWebsocket(conn, client_ip, req_data) catch |err| {
                std.log.debug("Websocket error: {}", .{err});
            };
        } else {
            self.handleHttp(conn, req_data) catch {};
        }
    }

    fn handleWebsocket(self: *TcpServer, conn: net.Server.Connection, client_ip: []const u8, initial_data: []const u8) !void {
        const TCP_NODELAY = 1;
        posix.setsockopt(conn.stream.handle, posix.IPPROTO.TCP, TCP_NODELAY, &std.mem.toBytes(@as(i32, 1))) catch {};

        const req, const consumed = try ws.handshake.Req.parse(initial_data);
        _ = consumed;

        const accept = ws.handshake.secAccept(req.key);
        var response_buf: [256]u8 = undefined;
        const response = try std.fmt.bufPrint(&response_buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept});
        try conn.stream.writeAll(response);

        var ws_writer = WsWriter{ .stream = conn.stream };

        self.mutex.lock();
        const conn_id = self.next_id;
        self.next_id += 1;
        self.mutex.unlock();

        const connection = try self.allocator.create(Connection);
        connection.init(self.allocator, conn_id);
        connection.setClientIp(client_ip);
        connection.setSocketHandle(conn.stream.handle);
        connection.setDirectWriter(WsWriter.write, @ptrCast(&ws_writer));
        connection.startWriteQueue(WsWriter.write, @ptrCast(&ws_writer));

        self.subs.tryAddConnection(connection, self.config.max_connections) catch |err| {
            connection.stopWriteQueue();
            connection.clearDirectWriter();
            connection.deinit();
            self.allocator.destroy(connection);
            return err;
        };
        self.conn_limiter.addConnection(client_ip);

        defer {
            connection.stopWriteQueue();
            connection.clearDirectWriter();
            self.subs.removeConnection(conn_id);
            self.conn_limiter.removeConnection(client_ip);
            connection.deinit();
            self.allocator.destroy(connection);
        }

        if (self.config.auth_required or self.config.auth_to_write) {
            var auth_buf: [256]u8 = undefined;
            const auth_msg = nostr.RelayMsg.auth(&connection.auth_challenge, &auth_buf) catch return;
            connection.sendDirect(auth_msg);
            connection.challenge_sent = true;
        }

        var frame_buf: [65536]u8 = undefined;
        var read_pos: usize = 0;

        while (!self.shutdown.load(.acquire)) {
            if (read_pos >= frame_buf.len) {
                var close_response: [16]u8 = undefined;
                const close_frame = ws.Frame{ .fin = 1, .opcode = .close, .payload = &.{}, .mask = 0 };
                const close_len = close_frame.encode(&close_response, 1002);
                conn.stream.writeAll(close_response[0..close_len]) catch {};
                return;
            }

            const bytes_read = conn.stream.read(frame_buf[read_pos..]) catch |err| {
                if (err == error.ConnectionResetByPeer or err == error.BrokenPipe) break;
                return err;
            };
            if (bytes_read == 0) break;

            read_pos += bytes_read;
            connection.touch();

            while (read_pos > 0) {
                if (try self.checkOversizedFrame(connection, conn, frame_buf[0..read_pos])) return;

                const frame, const frame_len = ws.Frame.parse(frame_buf[0..read_pos]) catch |err| {
                    if (err == error.SplitBuffer) break;
                    return err;
                };

                try frame.assertValid(false);

                if (frame.opcode == .close) {
                    var close_response: [16]u8 = undefined;
                    const close_frame = ws.Frame{ .fin = 1, .opcode = .close, .payload = &.{}, .mask = 0 };
                    const close_len = close_frame.encode(&close_response, 1000);
                    conn.stream.writeAll(close_response[0..close_len]) catch {};
                    return;
                } else if (frame.opcode == .ping) {
                    var pong_buf: [256]u8 = undefined;
                    const pong_frame = ws.Frame{ .fin = 1, .opcode = .pong, .payload = frame.payload, .mask = 0 };
                    const pong_len = pong_frame.encode(&pong_buf, 0);
                    conn.stream.writeAll(pong_buf[0..pong_len]) catch {};
                } else if (frame.opcode == .text or frame.opcode == .binary) {
                    self.handler.handle(connection, frame.payload);
                }

                if (frame_len < read_pos) {
                    std.mem.copyForwards(u8, &frame_buf, frame_buf[frame_len..read_pos]);
                }
                read_pos -= frame_len;
            }
        }
    }

    fn checkOversizedFrame(self: *TcpServer, connection: *Connection, conn: net.Server.Connection, data: []const u8) !bool {
        if (data.len < 2) return false;
        const payload_len_byte: u8 = data[1] & 0b0111_1111;
        const payload_len: u64 = switch (payload_len_byte) {
            126 => blk: {
                if (data.len < 4) return false;
                break :blk std.mem.readInt(u16, data[2..4], .big);
            },
            127 => blk: {
                if (data.len < 10) return false;
                break :blk std.mem.readInt(u64, data[2..10], .big);
            },
            else => payload_len_byte,
        };
        if (payload_len > self.config.max_message_size) {
            var notice_buf: [256]u8 = undefined;
            const notice = nostr.RelayMsg.notice("error: message too large", &notice_buf) catch {
                return true;
            };
            connection.sendDirect(notice);
            var close_response: [16]u8 = undefined;
            const close_frame = ws.Frame{ .fin = 1, .opcode = .close, .payload = &.{}, .mask = 0 };
            const close_len = close_frame.encode(&close_response, 1009);
            conn.stream.writeAll(close_response[0..close_len]) catch {};
            return true;
        }
        return false;
    }

    fn handleHttp(self: *TcpServer, conn: net.Server.Connection, req_data: []const u8) !void {
        const accepts_json = std.mem.indexOf(u8, req_data, "application/nostr+json") != null;

        if (accepts_json) {
            var response_buf: [4096]u8 = undefined;
            var content_buf: [2048]u8 = undefined;

            var content_stream = std.io.fixedBufferStream(&content_buf);
            try nip11.write(self.config, content_stream.writer());
            const content = content_stream.getWritten();

            const response = try std.fmt.bufPrint(&response_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {d}\r\n\r\n{s}", .{ content.len, content });
            try conn.stream.writeAll(response);
        } else {
            const html =
                \\<!DOCTYPE html>
                \\<html><head><title>Wisp</title></head>
                \\<body>
                \\<h1>Wisp Nostr Relay</h1>
                \\<p>Connect via WebSocket at this URL.</p>
                \\</body></html>
            ;
            const response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " ++ std.fmt.comptimePrint("{d}", .{html.len}) ++ "\r\n\r\n" ++ html;
            try conn.stream.writeAll(response);
        }
    }

    fn isWebsocketUpgrade(data: []const u8) bool {
        return std.ascii.indexOfIgnoreCase(data, "upgrade: websocket") != null;
    }

    fn extractIp(address: net.Address, buf: []u8) []const u8 {
        const formatted = std.fmt.bufPrint(buf, "{any}", .{address}) catch return "unknown";
        if (std.mem.lastIndexOf(u8, formatted, ":")) |colon| {
            return formatted[0..colon];
        }
        return formatted;
    }

    pub fn send(self: *TcpServer, conn_id: u64, data: []const u8) void {
        _ = self.subs.sendToConnection(conn_id, data);
    }

    pub fn connectionCount(self: *TcpServer) usize {
        return self.subs.connectionCount();
    }
};
