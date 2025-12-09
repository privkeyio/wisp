const std = @import("std");

const c = @cImport({
    @cInclude("lmdb.h");
});

pub fn main() !void {
    std.debug.print("=== LMDB Test ===\n", .{});

    var env: ?*c.MDB_env = null;

    // Create environment
    var rc = c.mdb_env_create(&env);
    if (rc != 0) {
        std.debug.print("mdb_env_create failed: {d}\n", .{rc});
        return error.EnvCreate;
    }
    defer c.mdb_env_close(env);

    // Set map size (10MB)
    rc = c.mdb_env_set_mapsize(env, 10 * 1024 * 1024);
    if (rc != 0) {
        std.debug.print("mdb_env_set_mapsize failed: {d}\n", .{rc});
        return error.EnvSetMapSize;
    }

    // Create test directory
    std.fs.cwd().makePath("./test_data") catch {};

    // Open environment
    rc = c.mdb_env_open(env, "./test_data/test.mdb", c.MDB_NOSUBDIR, 0o644);
    if (rc != 0) {
        std.debug.print("mdb_env_open failed: {d}\n", .{rc});
        return error.EnvOpen;
    }
    std.debug.print("Environment opened\n", .{});

    // Begin transaction
    var txn: ?*c.MDB_txn = null;
    rc = c.mdb_txn_begin(env, null, 0, &txn);
    if (rc != 0) {
        std.debug.print("mdb_txn_begin failed: {d}\n", .{rc});
        return error.TxnBegin;
    }

    // Open database
    var dbi: c.MDB_dbi = undefined;
    rc = c.mdb_dbi_open(txn, null, 0, &dbi);
    if (rc != 0) {
        c.mdb_txn_abort(txn);
        std.debug.print("mdb_dbi_open failed: {d}\n", .{rc});
        return error.DbiOpen;
    }

    // Put key-value
    const key_data = "test_key";
    const val_data = "test_value_from_zig";

    var key = c.MDB_val{
        .mv_size = key_data.len,
        .mv_data = @constCast(@ptrCast(key_data.ptr)),
    };
    var val = c.MDB_val{
        .mv_size = val_data.len,
        .mv_data = @constCast(@ptrCast(val_data.ptr)),
    };

    rc = c.mdb_put(txn, dbi, &key, &val, 0);
    if (rc != 0) {
        c.mdb_txn_abort(txn);
        std.debug.print("mdb_put failed: {d}\n", .{rc});
        return error.Put;
    }
    std.debug.print("Stored: {s} -> {s}\n", .{ key_data, val_data });

    // Commit
    rc = c.mdb_txn_commit(txn);
    if (rc != 0) {
        std.debug.print("mdb_txn_commit failed: {d}\n", .{rc});
        return error.Commit;
    }
    std.debug.print("Transaction committed\n", .{});

    // Now read it back
    rc = c.mdb_txn_begin(env, null, c.MDB_RDONLY, &txn);
    if (rc != 0) {
        std.debug.print("mdb_txn_begin (read) failed: {d}\n", .{rc});
        return error.TxnBegin;
    }
    defer c.mdb_txn_abort(txn);

    var read_val: c.MDB_val = undefined;
    rc = c.mdb_get(txn, dbi, &key, &read_val);
    if (rc != 0) {
        std.debug.print("mdb_get failed: {d}\n", .{rc});
        return error.Get;
    }

    const retrieved = @as([*]const u8, @ptrCast(read_val.mv_data))[0..read_val.mv_size];
    std.debug.print("Retrieved: {s} -> {s}\n", .{ key_data, retrieved });

    if (!std.mem.eql(u8, retrieved, val_data)) {
        std.debug.print("ERROR: Value mismatch!\n", .{});
        return error.ValueMismatch;
    }

    // Test cursor iteration
    std.debug.print("\n--- Cursor Test ---\n", .{});

    var cursor: ?*c.MDB_cursor = null;
    rc = c.mdb_cursor_open(txn, dbi, &cursor);
    if (rc != 0) {
        std.debug.print("mdb_cursor_open failed: {d}\n", .{rc});
        return error.CursorOpen;
    }
    defer c.mdb_cursor_close(cursor);

    var cursor_key: c.MDB_val = undefined;
    var cursor_val: c.MDB_val = undefined;
    rc = c.mdb_cursor_get(cursor, &cursor_key, &cursor_val, c.MDB_FIRST);
    while (rc == 0) {
        const k = @as([*]const u8, @ptrCast(cursor_key.mv_data))[0..cursor_key.mv_size];
        const v = @as([*]const u8, @ptrCast(cursor_val.mv_data))[0..cursor_val.mv_size];
        std.debug.print("  {s}: {s}\n", .{ k, v });
        rc = c.mdb_cursor_get(cursor, &cursor_key, &cursor_val, c.MDB_NEXT);
    }

    std.debug.print("\n=== LMDB test passed! ===\n", .{});
}
