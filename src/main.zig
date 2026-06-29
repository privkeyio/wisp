const std = @import("std");
const Config = @import("config.zig").Config;

pub const std_options = std.Options{
    .log_level = .info,
    .log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .websocket, .level = .err },
    },
};
const Lmdb = @import("lmdb.zig").Lmdb;
const Store = @import("store.zig").Store;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const Handler = @import("handler.zig").Handler;
const Broadcaster = @import("broadcaster.zig").Broadcaster;
const Server = @import("server.zig").Server;
const Spider = @import("spider.zig").Spider;
const nostr = @import("nostr.zig");
const rate_limiter = @import("rate_limiter.zig");
const ManagementStore = @import("management_store.zig").ManagementStore;
const Nip86Handler = @import("nip86.zig").Nip86Handler;
const Writer = @import("writer.zig").Writer;

var g_shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

// Only set the atomic flag here: server.stop() does mutex/thread coordination
// that is not async-signal-safe. The cleanup thread observes the flag and drives
// the actual shutdown from normal thread context.
fn signalHandler(_: std.posix.SIG) callconv(std.builtin.CallingConvention.c) void {
    g_shutdown.store(true, .release);
}

fn stdFile(handle: std.posix.fd_t) std.Io.File {
    return .{ .handle = handle, .flags = .{ .nonblocking = false } };
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
        \\Usage: wisp [command] [options]
        \\
        \\Commands:
        \\  relay [config]  Start the relay server (default)
        \\  import          Import events from stdin (JSONL format)
        \\  export          Export all events to stdout (JSONL format)
        \\  help            Show this help
        \\
        \\Options:
        \\  --spider-admin <npub|hex>  Enable spider, follow this pubkey's contacts
        \\  --db <path>                Database path (default: ./data)
        \\
        \\Examples:
        \\  wisp                                  Start relay with defaults
        \\  wisp --spider-admin npub1abc...      Pull your feed automatically
        \\  wisp relay config.toml                Start relay with config file
        \\  wisp export > backup.jsonl            Export all events
        \\
    ;
    stdFile(std.posix.STDOUT_FILENO).writeStreamingAll(nostr.io.io(), help) catch {};
}

pub fn main(init: std.process.Init) !void {
    // Use c_allocator for production - better memory behavior than GPA
    const allocator = std.heap.c_allocator;

    var arg_it = std.process.Args.Iterator.init(init.minimal.args);
    defer arg_it.deinit();
    var arg_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer arg_list.deinit(allocator);
    while (arg_it.next()) |a| try arg_list.append(allocator, a);
    const args = arg_list.items;

    var cmd = Command.relay;
    var config_path: ?[]const u8 = null;
    var db_path: []const u8 = "./data";
    var spider_admin_arg: ?[]const u8 = null;
    defer if (spider_admin_arg) |admin| allocator.free(admin);
    var cmd_set = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--db")) {
            i += 1;
            if (i < args.len) {
                db_path = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--spider-admin")) {
            i += 1;
            if (i < args.len) {
                const decoded = nostr.bech32.decodeNostr(allocator, args[i]) catch {
                    std.log.err("Invalid pubkey: {s}", .{args[i]});
                    return error.InvalidPubkey;
                };
                const hex = std.fmt.bytesToHex(decoded.pubkey, .lower);
                spider_admin_arg = try allocator.dupe(u8, &hex);
            }
        } else if (!cmd_set and !std.mem.endsWith(u8, arg, ".toml")) {
            cmd = parseCommand(arg);
            cmd_set = true;
        } else if (cmd == .relay and config_path == null and !std.mem.startsWith(u8, arg, "-")) {
            config_path = arg;
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

    if (spider_admin_arg) |admin| {
        config.spider_enabled = true;
        config.spider_admin = admin;
        if (config.spider_relays.len == 0) {
            config.spider_relays = "wss://relay.damus.io,wss://nos.lol,wss://relay.nostr.band";
        }
    }

    try nostr.init();
    defer nostr.cleanup();

    const sync_mode = Lmdb.SyncMode.fromString(config.storage_sync) orelse {
        std.log.err("Invalid storage sync mode '{s}', valid options are: none, meta, full", .{config.storage_sync});
        return error.InvalidSyncMode;
    };

    std.log.info("Wisp v0.5.9 starting", .{});
    std.log.info("Listening on {s}:{d}", .{ config.host, config.port });
    std.log.info("Storage: {s} (sync={s})", .{ config.storage_path, @tagName(sync_mode) });

    var lmdb = try Lmdb.init(allocator, config.storage_path, config.storage_map_size_mb, sync_mode);
    defer lmdb.deinit();

    var store = try Store.init(allocator, &lmdb);
    defer store.deinit();

    var mgmt_store = try ManagementStore.init(allocator, &lmdb);

    var nip86_handler = Nip86Handler.init(allocator, &config, &mgmt_store);
    defer nip86_handler.deinit();
    nip86_handler.loadRelaySettings();

    var subs = Subscriptions.init(allocator);
    defer subs.deinit();

    var broadcaster = Broadcaster.init(allocator, &subs);

    var event_limiter = rate_limiter.EventRateLimiter.init(allocator, config.events_per_minute);
    defer event_limiter.deinit();

    var query_limiter = rate_limiter.EventRateLimiter.init(allocator, config.queries_per_minute);
    defer query_limiter.deinit();

    // The group-commit writer exists only for durable sync modes, where batching
    // amortizes the fsync. In the default non-durable mode events are stored
    // synchronously, which is faster with nothing to flush.
    var writer = Writer.init(allocator, &store, &broadcaster, &subs);
    const writer_ptr: ?*Writer = if (sync_mode == .none) null else blk: {
        try writer.start();
        break :blk &writer;
    };
    defer if (writer_ptr) |w| w.deinit();

    var handler = Handler.init(allocator, &config, &store, &subs, &broadcaster, &event_limiter, &query_limiter, &g_shutdown, &mgmt_store, writer_ptr);

    var server: Server = undefined;
    try server.init(allocator, init.io, &config, &handler, &subs, &g_shutdown, &nip86_handler);
    defer server.deinit();

    var spider: ?Spider = null;
    if (config.spider_enabled) {
        spider = Spider.init(allocator, &config, &store, &broadcaster, &g_shutdown) catch |err| {
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

    // Ignore SIGPIPE: a client disconnecting mid-write must surface as an EPIPE
    // error (handled by the write paths), not terminate the process.
    const ignore_sa = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.PIPE, &ignore_sa, null);

    // Mandatory: the cleanup thread also drives graceful shutdown (it calls
    // server.stop() after observing the flag the signal handler sets). Without it
    // running, a SIGINT/SIGTERM would set the flag but nothing would unblock listen().
    const cleanup_thread = try std.Thread.spawn(.{}, storeCleanupThread, .{ &server, &store, &config, &subs, &g_shutdown, &server.conn_limiter, &event_limiter, &query_limiter });
    defer cleanup_thread.join();

    try server.listen();

    std.log.info("Shutdown complete", .{});
}

fn storeCleanupThread(server: *Server, store: *Store, config: *const Config, subs: *Subscriptions, shutdown: *std.atomic.Value(bool), conn_limiter: *rate_limiter.ConnectionLimiter, event_limiter: *rate_limiter.EventRateLimiter, query_limiter: *rate_limiter.EventRateLimiter) void {
    const check_interval_ns: u64 = std.time.ns_per_s;
    const hour_checks: u64 = 3600;
    const limiter_cleanup_checks: u64 = 300;
    const sync_checks: u64 = 60;
    const idle_checks: u64 = 30;
    var checks: u64 = 0;

    while (!shutdown.load(.acquire)) {
        std.Io.sleep(nostr.io.io(), .{ .nanoseconds = check_interval_ns }, .awake) catch {};
        if (shutdown.load(.acquire)) break;
        checks += 1;

        if (config.idle_seconds != 0 and checks % idle_checks == 0) {
            const idle_ids = subs.getIdleConnections(config.idle_seconds);
            defer subs.allocator.free(idle_ids);
            for (idle_ids) |conn_id| {
                var notice_buf: [128]u8 = undefined;
                const notice = nostr.RelayMsg.notice("connection closed: idle timeout", &notice_buf) catch continue;
                _ = subs.closeIdleConnection(conn_id, notice);
            }
        }

        if (checks % sync_checks == 0) {
            store.lmdb.sync();
        }

        if (checks % limiter_cleanup_checks == 0) {
            conn_limiter.cleanup();
            event_limiter.cleanup();
            query_limiter.cleanup();
        }

        if (checks < hour_checks) continue;
        checks = 0;

        if (config.deleted_retention_days > 0) {
            const max_age_seconds: i64 = @as(i64, @intCast(config.deleted_retention_days)) * 86400;
            _ = store.cleanupDeletedEntries(max_age_seconds) catch |err| {
                std.log.err("Failed to cleanup deleted entries: {}", .{err});
            };
        }
    }

    // Drive the shutdown from this normal thread context (the signal handler only
    // sets the flag) so listen() returns and main can join and clean up.
    server.stop();
}

fn runImport(allocator: std.mem.Allocator, db_path: []const u8) !void {
    try nostr.init();
    defer nostr.cleanup();

    var lmdb = try Lmdb.init(allocator, db_path, 10240, .none);
    defer lmdb.deinit();

    var store = try Store.init(allocator, &lmdb);
    defer store.deinit();

    const stderr_file = stdFile(std.posix.STDERR_FILENO);

    var imported: u64 = 0;
    var failed: u64 = 0;
    var duplicates: u64 = 0;

    var line_list: std.ArrayListUnmanaged(u8) = .empty;
    defer line_list.deinit(allocator);

    var read_buf: [65536]u8 = undefined;

    while (true) {
        const bytes_read = std.posix.read(std.posix.STDIN_FILENO, &read_buf) catch |err| {
            printStatus(stderr_file, "Import aborted: read error: {}\n", .{err});
            return err;
        };
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

fn printStatus(file: std.Io.File, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    file.writeStreamingAll(nostr.io.io(), msg) catch {};
}

fn runExport(allocator: std.mem.Allocator, db_path: []const u8) !void {
    var lmdb = try Lmdb.init(allocator, db_path, 10240, .none);
    defer lmdb.deinit();

    var store = try Store.init(allocator, &lmdb);
    defer store.deinit();

    const io = nostr.io.io();
    const stdout_file = stdFile(std.posix.STDOUT_FILENO);
    const stderr_file = stdFile(std.posix.STDERR_FILENO);

    const empty_filters = [_]nostr.Filter{};
    var iter = try store.query(&empty_filters, std.math.maxInt(u32));
    defer iter.deinit();

    var exported: u64 = 0;

    while (try iter.next()) |json| {
        stdout_file.writeStreamingAll(io, json) catch |err| {
            printStatus(stderr_file, "Export aborted: write error: {}\n", .{err});
            return err;
        };
        stdout_file.writeStreamingAll(io, "\n") catch |err| {
            printStatus(stderr_file, "Export aborted: write error: {}\n", .{err});
            return err;
        };
        exported += 1;
    }

    printStatus(stderr_file, "Exported {d} events\n", .{exported});
}

test {
    _ = @import("connection.zig");
    _ = @import("handler.zig");
    _ = @import("nip86.zig");
    _ = @import("rate_limiter.zig");
    _ = @import("server.zig");
    _ = @import("relay_metrics.zig");
}
