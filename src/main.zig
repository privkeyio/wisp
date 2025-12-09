const std = @import("std");
const Config = @import("config.zig").Config;
const Lmdb = @import("lmdb.zig").Lmdb;
const Store = @import("store.zig").Store;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const Handler = @import("handler.zig").Handler;
const Broadcaster = @import("broadcaster.zig").Broadcaster;
const Server = @import("server.zig").Server;
const nostr = @import("nostr.zig");

var g_server: ?*Server = null;
var g_shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn signalHandler(_: c_int) callconv(std.builtin.CallingConvention.c) void {
    g_shutdown.store(true, .release);
}

fn sendCallback(conn_id: u64, data: []const u8) void {
    if (g_server) |s| {
        s.send(conn_id, data);
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const config_path: ?[]const u8 = if (args.len > 1) args[1] else null;

    var config = if (config_path) |path|
        Config.load(allocator, path) catch |err| {
            std.log.err("Failed to load config: {}", .{err});
            return err;
        }
    else
        Config.defaults();
    defer if (config_path != null) config.deinit();

    config.loadEnv();

    try nostr.init();
    defer nostr.cleanup();

    std.log.info("Wisp v0.1.0 starting", .{});
    std.log.info("Listening on {s}:{d}", .{ config.host, config.port });
    std.log.info("Storage: {s}", .{config.storage_path});

    var lmdb = try Lmdb.init(allocator, config.storage_path, config.storage_map_size_mb);
    defer lmdb.deinit();

    var store = try Store.init(allocator, &lmdb);
    defer store.deinit();

    var subs = Subscriptions.init(allocator);
    defer subs.deinit();

    var broadcaster = Broadcaster.init(allocator, &subs, sendCallback);

    var handler = Handler.init(allocator, &config, &store, &subs, &broadcaster, sendCallback);

    var server = try Server.init(allocator, &config, &handler, &subs);
    defer server.deinit();

    g_server = &server;
    defer g_server = null;

    const sa = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    try server.run(&g_shutdown);

    std.log.info("Shutdown complete", .{});
}
