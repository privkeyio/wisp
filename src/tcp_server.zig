const std = @import("std");
const net = std.Io.net;
const posix = std.posix;
const nostr = @import("nostr.zig");
const ws = nostr.ws;

fn streamWriteAll(stream: net.Stream, data: []const u8) !void {
    const io = nostr.io.io();
    var buf: [512]u8 = undefined;
    var sw = stream.writer(io, &buf);
    try sw.interface.writeAll(data);
    try sw.interface.flush();
}

fn streamRead(stream: net.Stream, buf: []u8) !usize {
    return std.posix.read(stream.socket.handle, buf);
}

const Config = @import("config.zig").Config;
const MsgHandler = @import("handler.zig").Handler;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const Connection = @import("connection.zig").Connection;
const nip11 = @import("nip11.zig");
const rate_limiter = @import("rate_limiter.zig");
const write_queue = @import("write_queue.zig");
const Nip86Handler = @import("nip86.zig").Nip86Handler;

const WsWriter = struct {
    stream: net.Stream,
    mutex: std.Io.Mutex = .init,
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn write(ctx: *anyopaque, data: []const u8) void {
        const self: *WsWriter = @ptrCast(@alignCast(ctx));
        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.failed.load(.acquire)) return;
        self.writeWsFrame(data) catch {
            self.failed.store(true, .release);
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

        // SO_SNDTIMEO can surface as a write error; writeVecAll loops until every
        // byte is written so a slow client can never leave a truncated frame
        // behind (which would corrupt all later frames).
        const io = nostr.io.io();
        var sw = self.stream.writer(io, &.{});
        var vecs = [_][]const u8{ header[0..header_len], data };
        try sw.interface.writeVecAll(&vecs);
        try sw.interface.flush();
    }
};

pub const TcpServer = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    handler: *MsgHandler,
    subs: *Subscriptions,

    next_id: u64 = 0,
    mutex: std.Io.Mutex = .init,

    listener: ?net.Server = null,
    shutdown: *std.atomic.Value(bool),
    nip86_handler: *Nip86Handler,

    conn_limiter: rate_limiter.ConnectionLimiter,
    ip_filter: rate_limiter.IpFilter,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const Config,
        handler: *MsgHandler,
        subs: *Subscriptions,
        shutdown: *std.atomic.Value(bool),
        nip86_handler: *Nip86Handler,
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
            .nip86_handler = nip86_handler,
            .conn_limiter = rate_limiter.ConnectionLimiter.init(allocator, config.max_connections_per_ip),
            .ip_filter = ip_filter,
        };
    }

    pub fn deinit(self: *TcpServer) void {
        if (self.listener) |*l| {
            l.deinit(nostr.io.io());
            self.listener = null;
        }
        self.conn_limiter.deinit();
        self.ip_filter.deinit();
    }

    pub fn run(self: *TcpServer) !void {
        const io = nostr.io.io();
        const address = try net.IpAddress.parse(self.config.host, self.config.port);
        self.listener = try address.listen(io, .{
            .reuse_address = true,
        });

        // Poll the listener with a 1s timeout so the loop observes the shutdown
        // flag promptly. 0.16's Io.Threaded accept panics on EAGAIN, so the old
        // SO_RCVTIMEO-on-accept trick is gone; poll first, accept only when ready.
        std.log.info("Server running on {s}:{d}", .{ self.config.host, self.config.port });

        const idle_thread = std.Thread.spawn(.{}, idleTimeoutThread, .{ self, self.shutdown }) catch null;
        defer if (idle_thread) |t| t.join();

        while (!self.shutdown.load(.acquire)) {
            var pfd = [_]posix.pollfd{.{ .fd = self.listener.?.socket.handle, .events = posix.POLL.IN, .revents = 0 }};
            const ready = posix.poll(&pfd, 1000) catch 0;
            if (ready == 0) continue;
            const stream = self.listener.?.accept(io) catch |err| {
                if (err == error.SocketNotListening) break;
                continue;
            };

            if (self.subs.connectionCount() >= self.config.max_connections) {
                stream.close(io);
                continue;
            }

            const thread = std.Thread.spawn(.{}, handleConnection, .{ self, stream }) catch |err| {
                std.log.warn("Failed to spawn connection thread: {}", .{err});
                stream.close(io);
                continue;
            };
            thread.detach();
        }

        std.log.info("Shutting down server...", .{});
        if (self.listener) |*l| {
            l.deinit(io);
            self.listener = null;
        }
        std.Io.sleep(io, .{ .nanoseconds = 200 * std.time.ns_per_ms }, .awake) catch {};
    }

    fn idleTimeoutThread(self: *TcpServer, shutdown: *std.atomic.Value(bool)) void {
        const check_interval_s: u64 = 30;
        var seconds_waited: u64 = 0;

        while (!shutdown.load(.acquire)) {
            std.Io.sleep(nostr.io.io(), .{ .nanoseconds = std.time.ns_per_s }, .awake) catch {};
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
            l.deinit(nostr.io.io());
            self.listener = null;
        }
    }

    fn handleConnection(self: *TcpServer, stream: net.Stream) void {
        defer stream.close(nostr.io.io());

        // Check shutdown early to avoid accessing freed resources
        if (self.shutdown.load(.acquire)) return;

        var addr_buf: [64]u8 = undefined;
        const socket_ip = extractIp(stream.socket.handle, &addr_buf);

        if (self.shutdown.load(.acquire)) return;

        var buf: [8192]u8 = undefined;
        const n = streamRead(stream, &buf) catch return;
        if (n == 0) return;

        const req_data = buf[0..n];

        const client_ip = if (self.config.trust_proxy) blk: {
            const xff = extractHeader(req_data, "X-Forwarded-For: ");
            const xrip = extractHeader(req_data, "X-Real-IP: ");
            break :blk rate_limiter.extractClientIp(xff, xrip, socket_ip, true);
        } else socket_ip;

        if (!self.ip_filter.isAllowed(client_ip)) {
            return;
        }

        if (self.nip86_handler.mgmt_store.isIpBlocked(client_ip)) {
            return;
        }

        if (!self.conn_limiter.canConnect(client_ip)) {
            return;
        }

        if (isWebsocketUpgrade(req_data)) {
            self.handleWebsocket(stream, client_ip, req_data) catch |err| {
                std.log.debug("Websocket error: {}", .{err});
            };
        } else {
            self.handleHttp(stream, req_data) catch {};
        }
    }

    fn handleWebsocket(self: *TcpServer, stream: net.Stream, client_ip: []const u8, initial_data: []const u8) !void {
        const TCP_NODELAY = 1;
        posix.setsockopt(stream.socket.handle, posix.IPPROTO.TCP, TCP_NODELAY, &std.mem.toBytes(@as(i32, 1))) catch {};

        // Bound how long a write to a slow/stalled client can block. REQ results
        // are streamed synchronously while an LMDB read txn is open, so without
        // this a stuck client would pin a reader indefinitely. On timeout the
        // write errors and the direct writer is marked failed; the REQ streaming
        // loop observes that and breaks early, releasing the read txn promptly.
        const send_timeout = posix.timeval{ .sec = 10, .usec = 0 };
        posix.setsockopt(stream.socket.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, &std.mem.toBytes(send_timeout)) catch {};

        const req, const consumed = try ws.handshake.Req.parse(initial_data);
        _ = consumed;

        const accept = ws.handshake.secAccept(req.key);
        var response_buf: [256]u8 = undefined;
        const response = try std.fmt.bufPrint(&response_buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept});
        try streamWriteAll(stream, response);

        var ws_writer = WsWriter{ .stream = stream };

        const io = nostr.io.io();
        self.mutex.lockUncancelable(io);
        const conn_id = self.next_id;
        self.next_id += 1;
        self.mutex.unlock(io);

        const connection = try self.allocator.create(Connection);
        connection.init(self.allocator, conn_id);
        connection.setClientIp(client_ip);
        connection.setSocketHandle(stream.socket.handle);
        connection.setDirectWriter(WsWriter.write, @ptrCast(&ws_writer));
        connection.setDirectWriteFailedFlag(&ws_writer.failed);
        connection.startWriteQueue(WsWriter.write, @ptrCast(&ws_writer));

        self.subs.tryAddConnection(connection, self.config.max_connections) catch |err| {
            connection.stopWriteQueue();
            connection.clearDirectWriter();
            connection.deinit();
            self.allocator.destroy(connection);
            return err;
        };
        if (!self.conn_limiter.tryAcquireConnection(client_ip)) {
            connection.stopWriteQueue();
            connection.clearDirectWriter();
            self.subs.removeConnection(conn_id);
            connection.deinit();
            self.allocator.destroy(connection);
            return;
        }

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
                streamWriteAll(stream, close_response[0..close_len]) catch {};
                return;
            }

            const bytes_read = streamRead(stream, frame_buf[read_pos..]) catch |err| {
                if (err == error.ConnectionResetByPeer or err == error.BrokenPipe) break;
                return err;
            };
            if (bytes_read == 0) break;

            read_pos += bytes_read;
            connection.touch();

            while (read_pos > 0) {
                if (try self.checkOversizedFrame(connection, stream, frame_buf[0..read_pos])) return;

                const frame, const frame_len = ws.Frame.parse(frame_buf[0..read_pos]) catch |err| {
                    if (err == error.SplitBuffer) break;
                    return err;
                };

                try frame.assertValid(false);

                if (frame.opcode == .close) {
                    var close_response: [16]u8 = undefined;
                    const close_frame = ws.Frame{ .fin = 1, .opcode = .close, .payload = &.{}, .mask = 0 };
                    const close_len = close_frame.encode(&close_response, 1000);
                    streamWriteAll(stream, close_response[0..close_len]) catch {};
                    return;
                } else if (frame.opcode == .ping) {
                    var pong_buf: [256]u8 = undefined;
                    const pong_frame = ws.Frame{ .fin = 1, .opcode = .pong, .payload = frame.payload, .mask = 0 };
                    const pong_len = pong_frame.encode(&pong_buf, 0);
                    streamWriteAll(stream, pong_buf[0..pong_len]) catch {};
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

    fn checkOversizedFrame(self: *TcpServer, connection: *Connection, stream: net.Stream, data: []const u8) !bool {
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
            streamWriteAll(stream, close_response[0..close_len]) catch {};
            return true;
        }
        return false;
    }

    fn handleHttp(self: *TcpServer, stream: net.Stream, req_data: []const u8) !void {
        const is_options = std.mem.startsWith(u8, req_data, "OPTIONS ");
        const is_nip86_rpc = std.mem.indexOf(u8, req_data, "application/nostr+json+rpc") != null;
        const accepts_json = std.mem.indexOf(u8, req_data, "application/nostr+json") != null;

        if (is_nip86_rpc or is_options) {
            try self.handleNip86(stream, req_data);
        } else if (accepts_json) {
            var response_buf: [4096]u8 = undefined;
            var content_buf: [2048]u8 = undefined;

            var content_stream = std.Io.Writer.fixed(&content_buf);
            try nip11.write(self.config, self.nip86_handler, &content_stream);
            const content = content_stream.buffered();

            const response = try std.fmt.bufPrint(&response_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {d}\r\n\r\n{s}", .{ content.len, content });
            try streamWriteAll(stream, response);
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
            try streamWriteAll(stream, response);
        }
    }

    fn handleNip86(self: *TcpServer, stream: net.Stream, req_data: []const u8) !void {
        if (std.mem.startsWith(u8, req_data, "OPTIONS ")) {
            const response = "HTTP/1.1 204 No Content\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Max-Age: 86400\r\n\r\n";
            try streamWriteAll(stream, response);
            return;
        }

        if (!std.mem.startsWith(u8, req_data, "POST ")) {
            const response = "HTTP/1.1 405 Method Not Allowed\r\nAllow: POST, OPTIONS\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 0\r\n\r\n";
            try streamWriteAll(stream, response);
            return;
        }

        if (self.config.admin_pubkeys.len == 0) {
            const response = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 39\r\n\r\n{\"error\":\"management API not enabled\"}";
            try streamWriteAll(stream, response);
            return;
        }

        const header_end = std.mem.indexOf(u8, req_data, "\r\n\r\n") orelse {
            const response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 32\r\n\r\n{\"error\":\"missing request body\"}";
            try streamWriteAll(stream, response);
            return;
        };
        const body_offset = header_end + 4;

        const max_body_size: usize = 65536;
        const content_length = blk: {
            const cl_str = extractHeader(req_data[0..header_end], "Content-Length: ") orelse {
                const response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 34\r\n\r\n{\"error\":\"missing Content-Length\"}";
                try streamWriteAll(stream, response);
                return;
            };
            break :blk std.fmt.parseInt(usize, cl_str, 10) catch {
                const response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 34\r\n\r\n{\"error\":\"invalid Content-Length\"}";
                try streamWriteAll(stream, response);
                return;
            };
        };

        if (content_length > max_body_size) {
            const response = "HTTP/1.1 413 Content Too Large\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 34\r\n\r\n{\"error\":\"request body too large\"}";
            try streamWriteAll(stream, response);
            return;
        }

        const initial_body = req_data[body_offset..];
        var body: []const u8 = "";
        var body_buf: ?[]u8 = null;
        defer if (body_buf) |b| self.allocator.free(b);

        if (initial_body.len >= content_length) {
            body = initial_body[0..content_length];
        } else {
            body_buf = self.allocator.alloc(u8, content_length) catch {
                const response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 25\r\n\r\n{\"error\":\"out of memory\"}";
                try streamWriteAll(stream, response);
                return;
            };
            @memcpy(body_buf.?[0..initial_body.len], initial_body);
            var total_read = initial_body.len;
            while (total_read < content_length) {
                const bytes = streamRead(stream, body_buf.?[total_read..content_length]) catch {
                    return;
                };
                if (bytes == 0) return;
                total_read += bytes;
            }
            body = body_buf.?[0..content_length];
        }

        const auth_header = extractHeader(req_data, "Authorization: ");

        var url_buf: [512]u8 = undefined;
        const request_url = if (self.config.relay_url.len > 0)
            self.config.relay_url
        else
            std.fmt.bufPrint(&url_buf, "http://{s}:{d}", .{ self.config.host, self.config.port }) catch "";

        const result = self.nip86_handler.handle(body, auth_header, request_url);

        const reason = statusReason(result.status);
        var response_buf: [65536]u8 = undefined;
        const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nContent-Length: {d}\r\n\r\n{s}", .{ result.status, reason, result.body.len, result.body }) catch return;
        streamWriteAll(stream, response) catch {};

        if (result.owned) {
            self.allocator.free(result.body);
        }
    }

    fn statusReason(status: u16) []const u8 {
        return switch (status) {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            413 => "Content Too Large",
            500 => "Internal Server Error",
            else => "Unknown",
        };
    }

    fn extractHeader(data: []const u8, header_name: []const u8) ?[]const u8 {
        var pos: usize = 0;
        while (pos < data.len) {
            const line_end = std.mem.indexOfPos(u8, data, pos, "\r\n") orelse data.len;
            const line = data[pos..line_end];
            if (std.ascii.startsWithIgnoreCase(line, header_name)) {
                return line[header_name.len..];
            }
            if (line.len == 0) break;
            pos = line_end + 2;
        }
        return null;
    }

    fn isWebsocketUpgrade(data: []const u8) bool {
        return std.ascii.indexOfIgnoreCase(data, "upgrade: websocket") != null;
    }

    fn extractIp(fd: posix.socket_t, buf: []u8) []const u8 {
        var storage: posix.sockaddr.storage = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        posix.getpeername(fd, @ptrCast(&storage), &len) catch return "unknown";

        const addr: net.IpAddress = switch (storage.family) {
            posix.AF.INET => blk: {
                const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(&storage));
                break :blk .{ .ip4 = .{ .bytes = @bitCast(sin.addr), .port = std.mem.bigToNative(u16, sin.port) } };
            },
            posix.AF.INET6 => blk: {
                const sin6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&storage));
                break :blk .{ .ip6 = .{ .port = std.mem.bigToNative(u16, sin6.port), .bytes = sin6.addr } };
            },
            else => return "unknown",
        };

        const formatted = std.fmt.bufPrint(buf, "{f}", .{addr}) catch return "unknown";
        // IPv6 is formatted as "[addr]:port" — return the bracketed address so
        // ACLs and per-IP limits see a plain IP (e.g. "::1", not "[::1]").
        if (formatted.len > 0 and formatted[0] == '[') {
            if (std.mem.indexOfScalar(u8, formatted, ']')) |end| {
                return formatted[1..end];
            }
        }
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
