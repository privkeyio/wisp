const std = @import("std");

const c = @cImport({
    @cInclude("lmdb.h");
});

pub const LmdbError = error{
    EnvCreate,
    EnvSetMapSize,
    EnvSetMaxDbs,
    EnvOpen,
    TxnBegin,
    DbiOpen,
    Put,
    Get,
    Del,
    Cursor,
    CursorGet,
    MapFull,
    KeyNotFound,
    KeyExists,
    Unknown,
};

pub const Lmdb = struct {
    env: *c.MDB_env,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, path: []const u8, map_size_mb: u32) !Lmdb {
        var env: ?*c.MDB_env = null;

        if (c.mdb_env_create(&env) != 0) {
            return error.EnvCreate;
        }
        errdefer c.mdb_env_close(env);

        const map_size = @as(usize, map_size_mb) * 1024 * 1024;
        if (c.mdb_env_set_mapsize(env, map_size) != 0) {
            return error.EnvSetMapSize;
        }

        if (c.mdb_env_set_maxdbs(env, 16) != 0) {
            return error.EnvSetMaxDbs;
        }

        _ = c.mdb_env_set_maxreaders(env, 512);

        if (std.fs.path.dirname(path)) |parent| {
            std.fs.cwd().makePath(parent) catch {};
        }

        const path_z = try allocator.dupeZ(u8, path);
        defer allocator.free(path_z);

        const flags: c_uint = c.MDB_NOSUBDIR | c.MDB_NOSYNC | c.MDB_NOMETASYNC | c.MDB_WRITEMAP | c.MDB_MAPASYNC | c.MDB_NORDAHEAD;
        const rc = c.mdb_env_open(env, path_z.ptr, flags, 0o644);
        if (rc != 0) {
            std.log.err("LMDB open failed: {}", .{rc});
            return error.EnvOpen;
        }

        return .{
            .env = env.?,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Lmdb) void {
        _ = c.mdb_env_sync(self.env, 1);
        c.mdb_env_close(self.env);
    }

    pub fn sync(self: *Lmdb) void {
        _ = c.mdb_env_sync(self.env, 1);
    }

    pub fn beginTxn(self: *Lmdb, readonly: bool) !Txn {
        var txn: ?*c.MDB_txn = null;
        const flags: c_uint = if (readonly) c.MDB_RDONLY else 0;

        if (c.mdb_txn_begin(self.env, null, flags, &txn) != 0) {
            return error.TxnBegin;
        }

        return .{ .txn = txn.?, .lmdb = self };
    }

    pub fn openDbi(self: *Lmdb, txn: *Txn, name: []const u8) !Dbi {
        var dbi: c.MDB_dbi = undefined;

        const name_z = try self.allocator.dupeZ(u8, name);
        defer self.allocator.free(name_z);

        const flags: c_uint = c.MDB_CREATE;
        if (c.mdb_dbi_open(txn.txn, name_z.ptr, flags, &dbi) != 0) {
            return error.DbiOpen;
        }

        return .{ .dbi = dbi };
    }
};

pub const Txn = struct {
    txn: *c.MDB_txn,
    lmdb: *Lmdb,

    pub fn commit(self: *Txn) !void {
        const rc = c.mdb_txn_commit(self.txn);
        if (rc != 0) {
            return error.Unknown;
        }
    }

    pub fn abort(self: *Txn) void {
        c.mdb_txn_abort(self.txn);
    }

    pub fn put(self: *Txn, dbi: Dbi, key: []const u8, value: []const u8) !void {
        var k = c.MDB_val{ .mv_size = key.len, .mv_data = @constCast(@ptrCast(key.ptr)) };
        var v = c.MDB_val{ .mv_size = value.len, .mv_data = @constCast(@ptrCast(value.ptr)) };

        const rc = c.mdb_put(self.txn, dbi.dbi, &k, &v, 0);
        if (rc == c.MDB_MAP_FULL) return error.MapFull;
        if (rc != 0) return error.Put;
    }

    pub fn putNoOverwrite(self: *Txn, dbi: Dbi, key: []const u8, value: []const u8) !void {
        var k = c.MDB_val{ .mv_size = key.len, .mv_data = @constCast(@ptrCast(key.ptr)) };
        var v = c.MDB_val{ .mv_size = value.len, .mv_data = @constCast(@ptrCast(value.ptr)) };

        const rc = c.mdb_put(self.txn, dbi.dbi, &k, &v, c.MDB_NOOVERWRITE);
        if (rc == c.MDB_KEYEXIST) return error.KeyExists;
        if (rc == c.MDB_MAP_FULL) return error.MapFull;
        if (rc != 0) return error.Put;
    }

    pub fn get(self: *Txn, dbi: Dbi, key: []const u8) !?[]const u8 {
        var k = c.MDB_val{ .mv_size = key.len, .mv_data = @constCast(@ptrCast(key.ptr)) };
        var v: c.MDB_val = undefined;

        const rc = c.mdb_get(self.txn, dbi.dbi, &k, &v);
        if (rc == c.MDB_NOTFOUND) return null;
        if (rc != 0) return error.Get;

        return @as([*]const u8, @ptrCast(v.mv_data))[0..v.mv_size];
    }

    pub fn delete(self: *Txn, dbi: Dbi, key: []const u8) !void {
        var k = c.MDB_val{ .mv_size = key.len, .mv_data = @constCast(@ptrCast(key.ptr)) };

        const rc = c.mdb_del(self.txn, dbi.dbi, &k, null);
        if (rc == c.MDB_NOTFOUND) return error.KeyNotFound;
        if (rc != 0) return error.Del;
    }

    pub fn cursor(self: *Txn, dbi: Dbi) !Cursor {
        var cur: ?*c.MDB_cursor = null;
        if (c.mdb_cursor_open(self.txn, dbi.dbi, &cur) != 0) {
            return error.Cursor;
        }
        return .{ .cursor = cur.? };
    }
};

pub const Dbi = struct {
    dbi: c.MDB_dbi,
};

pub const Cursor = struct {
    cursor: *c.MDB_cursor,

    pub fn close(self: *Cursor) void {
        c.mdb_cursor_close(self.cursor);
    }

    pub fn get(self: *Cursor, op: CursorOp) !?Entry {
        var k: c.MDB_val = undefined;
        var v: c.MDB_val = undefined;

        const rc = c.mdb_cursor_get(self.cursor, &k, &v, @intFromEnum(op));
        if (rc == c.MDB_NOTFOUND) return null;
        if (rc != 0) return error.CursorGet;

        return .{
            .key = @as([*]const u8, @ptrCast(k.mv_data))[0..k.mv_size],
            .value = @as([*]const u8, @ptrCast(v.mv_data))[0..v.mv_size],
        };
    }

    pub fn seek(self: *Cursor, key: []const u8) !?Entry {
        var k = c.MDB_val{ .mv_size = key.len, .mv_data = @constCast(@ptrCast(key.ptr)) };
        var v: c.MDB_val = undefined;

        const rc = c.mdb_cursor_get(self.cursor, &k, &v, c.MDB_SET_RANGE);
        if (rc == c.MDB_NOTFOUND) return null;
        if (rc != 0) return error.CursorGet;

        return .{
            .key = @as([*]const u8, @ptrCast(k.mv_data))[0..k.mv_size],
            .value = @as([*]const u8, @ptrCast(v.mv_data))[0..v.mv_size],
        };
    }

    pub fn del(self: *Cursor) !void {
        const rc = c.mdb_cursor_del(self.cursor, 0);
        if (rc != 0) return error.CursorDel;
    }
};

pub const CursorOp = enum(c_uint) {
    first = c.MDB_FIRST,
    last = c.MDB_LAST,
    next = c.MDB_NEXT,
    prev = c.MDB_PREV,
    current = c.MDB_GET_CURRENT,
};

pub const Entry = struct {
    key: []const u8,
    value: []const u8,
};
