const std = @import("std");
const Config = @import("config.zig").Config;
const Lmdb = @import("lmdb.zig").Lmdb;
const Store = @import("store.zig").Store;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const Handler = @import("handler.zig").Handler;
const Broadcaster = @import("broadcaster.zig").Broadcaster;
const Server = @import("server.zig").Server;
const Spider = @import("spider.zig").Spider;
const nostr = @import("nostr.zig");
const rate_limiter = @import("rate_limiter.zig");

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

const Command = enum {
    relay,
    import_cmd,
    export_cmd,
    help,
};

fn parseCommand(arg: []const u8) Command {
    if (std.mem.eql(u8, arg, "import")) return .import_cmd;
    if (std.mem.eql(u8, arg, "export")) return .export_cmd;
    if (std.mem.eql(u8, arg, "help") or std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return .help;
    return .relay;
}

fn printHelp() void {
    const help =
        \\Usage: wisp <command> [options]
        \\
        \\Commands:
        \\  relay [config]  Start the relay server (default)
        \\  import          Import events from stdin (JSONL format)
        \\  export          Export all events to stdout (JSONL format)
        \\  help            Show this help
        \\
        \\Options:
        \\  --db <path>     Database path (default: ./data)
        \\
        \\Examples:
        \\  wisp                          Start relay with defaults
        \\  wisp relay config.ini         Start relay with config file
        \\  wisp import < events.jsonl    Import events from file
        \\  wisp export > backup.jsonl    Export all events to file
        \\  wisp import --db ./mydata     Import to specific database
        \\
    ;
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    stdout.writeAll(help) catch {};
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var cmd = Command.relay;
    var config_path: ?[]const u8 = null;
    var db_path: []const u8 = "./data";
    var cmd_set = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--db")) {
            i += 1;
            if (i < args.len) {
                db_path = args[i];
            }
        } else if (!cmd_set) {
            cmd = parseCommand(arg);
            cmd_set = true;
            if (cmd == .relay and !std.mem.startsWith(u8, arg, "-")) {
                config_path = arg;
            }
        }
    }

    switch (cmd) {
        .help => {
            printHelp();
            return;
        },
        .import_cmd => {
            return runImport(allocator, db_path);
        },
        .export_cmd => {
            return runExport(allocator, db_path);
        },
        .relay => {},
    }

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

    var event_limiter = rate_limiter.EventRateLimiter.init(allocator, config.events_per_minute);
    defer event_limiter.deinit();

    var handler = Handler.init(allocator, &config, &store, &subs, &broadcaster, sendCallback, &event_limiter);

    var server = try Server.init(allocator, &config, &handler, &subs);
    defer server.deinit();

    g_server = &server;
    defer g_server = null;

    // Initialize Spider if enabled
    var spider: ?Spider = null;
    if (config.spider_enabled) {
        spider = Spider.init(allocator, &config, &store, &broadcaster) catch |err| {
            std.log.err("Failed to initialize Spider: {}", .{err});
            return err;
        };
        spider.?.start() catch |err| {
            std.log.err("Failed to start Spider: {}", .{err});
            spider.?.deinit();
            return err;
        };
        std.log.info("Spider enabled", .{});
    }
    defer if (spider) |*s| {
        s.stop();
        s.deinit();
    };

    const sa = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    const cleanup_thread = std.Thread.spawn(.{}, storeCleanupThread, .{ &store, &config, &g_shutdown }) catch null;
    defer if (cleanup_thread) |t| t.join();

    try server.run(&g_shutdown);

    std.log.info("Shutdown complete", .{});
}

fn storeCleanupThread(store: *Store, config: *const Config, shutdown: *std.atomic.Value(bool)) void {
    const hour_ns: u64 = 3600 * std.time.ns_per_s;

    while (!shutdown.load(.acquire)) {
        std.Thread.sleep(hour_ns);
        if (shutdown.load(.acquire)) break;

        if (config.deleted_retention_days > 0) {
            const max_age_seconds: i64 = @as(i64, @intCast(config.deleted_retention_days)) * 86400;
            _ = store.cleanupDeletedEntries(max_age_seconds) catch |err| {
                std.log.err("Failed to cleanup deleted entries: {}", .{err});
            };
        }
    }
}

fn runImport(allocator: std.mem.Allocator, db_path: []const u8) !void {
    try nostr.init();
    defer nostr.cleanup();

    var lmdb = try Lmdb.init(allocator, db_path, 10240);
    defer lmdb.deinit();

    var store = try Store.init(allocator, &lmdb);
    defer store.deinit();

    const stdin_file = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stderr_file = std.fs.File{ .handle = std.posix.STDERR_FILENO };

    var imported: u64 = 0;
    var failed: u64 = 0;
    var duplicates: u64 = 0;

    var line_list: std.ArrayListUnmanaged(u8) = .{};
    defer line_list.deinit(allocator);

    var read_buf: [65536]u8 = undefined;

    while (true) {
        const bytes_read = stdin_file.read(&read_buf) catch break;
        if (bytes_read == 0) break;

        for (read_buf[0..bytes_read]) |byte| {
            if (byte == '\n') {
                if (line_list.items.len > 0) {
                    processImportLine(allocator, &store, line_list.items, &imported, &failed, &duplicates);
                }
                line_list.clearRetainingCapacity();
            } else {
                line_list.append(allocator, byte) catch {
                    failed += 1;
                    line_list.clearRetainingCapacity();
                };
            }
        }

        if ((imported + duplicates + failed) % 10000 == 0 and (imported + duplicates + failed) > 0) {
            printStatus(stderr_file, "Progress: {d} imported, {d} duplicates, {d} failed\n", .{ imported, duplicates, failed });
        }
    }

    if (line_list.items.len > 0) {
        processImportLine(allocator, &store, line_list.items, &imported, &failed, &duplicates);
    }

    lmdb.sync();

    printStatus(stderr_file, "Import complete: {d} imported, {d} duplicates, {d} failed\n", .{ imported, duplicates, failed });
}

fn processImportLine(allocator: std.mem.Allocator, store: *Store, line: []const u8, imported: *u64, failed: *u64, duplicates: *u64) void {
    var event = nostr.Event.parseWithAllocator(line, allocator) catch {
        failed.* += 1;
        return;
    };
    defer event.deinit();

    event.validate() catch {
        failed.* += 1;
        return;
    };

    // Handle NIP-09 deletions
    if (nostr.isDeletion(&event)) {
        const ids_to_delete = nostr.getDeletionIds(allocator, &event) catch {
            failed.* += 1;
            return;
        };
        defer allocator.free(ids_to_delete);

        const pubkey = event.pubkey();
        for (ids_to_delete) |target_id| {
            _ = store.delete(&target_id, pubkey) catch {};
        }
    }

    const result = store.store(&event, line) catch {
        failed.* += 1;
        return;
    };

    if (result.stored) {
        imported.* += 1;
    } else if (std.mem.startsWith(u8, result.message, "duplicate")) {
        duplicates.* += 1;
    } else {
        failed.* += 1;
    }
}

fn printStatus(file: std.fs.File, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    file.writeAll(msg) catch {};
}

fn runExport(allocator: std.mem.Allocator, db_path: []const u8) !void {
    var lmdb = try Lmdb.init(allocator, db_path, 10240);
    defer lmdb.deinit();

    var store = try Store.init(allocator, &lmdb);
    defer store.deinit();

    const stdout_file = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    const stderr_file = std.fs.File{ .handle = std.posix.STDERR_FILENO };

    const empty_filters = [_]nostr.Filter{};
    var iter = try store.query(&empty_filters, std.math.maxInt(u32));
    defer iter.deinit();

    var exported: u64 = 0;

    while (try iter.next()) |json| {
        stdout_file.writeAll(json) catch return;
        stdout_file.writeAll("\n") catch return;
        exported += 1;
    }

    printStatus(stderr_file, "Exported {d} events\n", .{exported});
}
