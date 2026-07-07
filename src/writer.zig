const std = @import("std");
const nostr = @import("nostr.zig");
const Store = @import("store.zig").Store;
const Broadcaster = @import("broadcaster.zig").Broadcaster;
const Subscriptions = @import("subscriptions.zig").Subscriptions;
const metrics = @import("relay_metrics.zig");

// Group-commit writer. EVENT and deletion jobs are queued by the worker threads
// (after synchronous validation) and drained by a single writer thread that
// batches up to MAX_BATCH jobs into one LMDB transaction, so a durable sync mode
// pays one fsync per batch instead of one per event. OK replies and broadcasts
// happen only after the batch commits, so an acknowledged write is on disk.
const MAX_BATCH = 1000;
const MAX_QUEUE = 200_000;
// Cap total bytes of queued JSON so a flood (or a slow fsync in a durable sync
// mode) can't grow the queue into an OOM regardless of max_message_size.
const MAX_QUEUE_BYTES = 256 * 1024 * 1024;

const JobKind = enum { event, deletion };

const Job = struct {
    kind: JobKind,
    conn_id: u64,
    json: []u8,
};

const Processed = struct {
    conn_id: u64,
    event: nostr.Event,
    success: bool,
    message: []const u8,
    broadcast: bool,
};

pub const Writer = struct {
    allocator: std.mem.Allocator,
    store: *Store,
    broadcaster: *Broadcaster,
    subs: *Subscriptions,

    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    queue: std.ArrayListUnmanaged(Job) = .empty,
    queued_bytes: usize = 0,
    shutdown: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    pub fn init(
        allocator: std.mem.Allocator,
        store: *Store,
        broadcaster: *Broadcaster,
        subs: *Subscriptions,
    ) Writer {
        return .{
            .allocator = allocator,
            .store = store,
            .broadcaster = broadcaster,
            .subs = subs,
        };
    }

    pub fn start(self: *Writer) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn deinit(self: *Writer) void {
        const io = nostr.io.io();
        // Set shutdown under the mutex so it can't slip between the writer
        // thread's predicate check and its wait, which would be a lost wakeup
        // and deadlock the join below.
        self.mutex.lockUncancelable(io);
        self.shutdown.store(true, .release);
        self.mutex.unlock(io);
        self.cond.broadcast(io);
        if (self.thread) |t| t.join();
        for (self.queue.items) |job| self.allocator.free(job.json);
        self.queue.deinit(self.allocator);
    }

    // Queue a job. Returns false when overloaded (caller replies error) or on OOM.
    pub fn submit(self: *Writer, kind: JobKind, conn_id: u64, json: []const u8) bool {
        const io = nostr.io.io();
        const copy = self.allocator.dupe(u8, json) catch return false;
        self.mutex.lockUncancelable(io);
        if (self.queue.items.len >= MAX_QUEUE or self.queued_bytes + copy.len > MAX_QUEUE_BYTES) {
            self.mutex.unlock(io);
            self.allocator.free(copy);
            return false;
        }
        self.queue.append(self.allocator, .{ .kind = kind, .conn_id = conn_id, .json = copy }) catch {
            self.mutex.unlock(io);
            self.allocator.free(copy);
            return false;
        };
        self.queued_bytes += copy.len;
        self.mutex.unlock(io);
        self.cond.signal(io);
        return true;
    }

    fn run(self: *Writer) void {
        const io = nostr.io.io();
        while (true) {
            self.mutex.lockUncancelable(io);
            while (self.queue.items.len == 0 and !self.shutdown.load(.acquire)) {
                self.cond.waitUncancelable(io, &self.mutex);
            }
            if (self.queue.items.len == 0) {
                self.mutex.unlock(io);
                break; // queue drained and shutdown requested
            }
            // Take everything queued so far. Under load many events accumulate
            // between wakeups and commit together, amortizing the fsync; at low
            // load batches are small but commits are cheap anyway.
            var pending = self.queue;
            self.queue = .empty;
            self.queued_bytes = 0;
            self.mutex.unlock(io);

            var i: usize = 0;
            while (i < pending.items.len) {
                const end = @min(i + MAX_BATCH, pending.items.len);
                self.processBatch(pending.items[i..end]);
                i = end;
            }
            pending.deinit(self.allocator);
        }
    }

    fn processBatch(self: *Writer, jobs: []Job) void {
        const processed = self.allocator.alloc(Processed, jobs.len) catch {
            self.replyErrorAll(jobs);
            self.freeJobs(jobs);
            return;
        };
        defer self.allocator.free(processed);

        var txn = self.store.lmdb.beginTxn(false) catch {
            self.replyErrorAll(jobs);
            self.freeJobs(jobs);
            return;
        };

        var n: usize = 0;
        var stored_any = false;
        var fatal = false;

        for (jobs) |job| {
            var event = nostr.Event.parse(job.json) catch {
                std.log.warn("writer: dropping job, failed to re-parse queued event", .{});
                continue;
            };
            const p = self.applyJob(&txn, job, &event) catch {
                event.deinit();
                fatal = true;
                break;
            };
            if (p.success and p.broadcast) stored_any = true;
            processed[n] = p;
            n += 1;
        }

        if (fatal) {
            txn.abort();
            for (processed[0..n]) |*p| p.event.deinit();
            self.replyErrorAll(jobs);
            self.freeJobs(jobs);
            return;
        }

        txn.commit() catch {
            for (processed[0..n]) |*p| p.event.deinit();
            self.replyErrorAll(jobs);
            self.freeJobs(jobs);
            return;
        };

        if (stored_any) self.store.query_cache.invalidate();

        for (processed[0..n]) |*p| {
            if (p.broadcast) metrics.eventStored() else if (!p.success) metrics.eventRejected();
            self.reply(p.conn_id, p.event.id(), p.success, p.message);
            if (p.broadcast) self.broadcaster.broadcast(&p.event);
            p.event.deinit();
        }

        self.freeJobs(jobs);
    }

    // Apply one job within the shared txn and return how to reply. Returns an
    // error only on a fatal txn failure (which aborts the whole batch).
    fn applyJob(self: *Writer, txn: anytype, job: Job, event: *nostr.Event) !Processed {
        if (job.kind == .deletion) {
            const ids = nostr.getDeletionIds(self.allocator, event) catch null;
            defer if (ids) |slice| self.allocator.free(slice);
            const slice = ids orelse return .{ .conn_id = job.conn_id, .event = event.*, .success = false, .message = "error: failed to parse deletion", .broadcast = false };
            for (slice) |target| {
                _ = try self.store.deleteInTxn(txn, &target, event.pubkey());
            }
            _ = try self.store.storeInTxn(txn, event, job.json);
            return .{ .conn_id = job.conn_id, .event = event.*, .success = true, .message = "", .broadcast = true };
        }

        const result = try self.store.storeInTxn(txn, event, job.json);
        // Stored, OR ephemeral (relayed but not persisted, NIP-01): ack and broadcast to subscribers.
        if (result.stored or result.ephemeral) {
            return .{ .conn_id = job.conn_id, .event = event.*, .success = true, .message = "", .broadcast = true };
        }
        const dup = std.mem.startsWith(u8, result.message, "duplicate");
        return .{ .conn_id = job.conn_id, .event = event.*, .success = dup, .message = result.message, .broadcast = false };
    }

    fn reply(self: *Writer, conn_id: u64, event_id: *const [32]u8, success: bool, message: []const u8) void {
        var buf: [512]u8 = undefined;
        const msg = nostr.RelayMsg.ok(event_id, success, message, &buf) catch return;
        self.subs.sendTo(conn_id, msg);
    }

    fn replyErrorAll(self: *Writer, jobs: []Job) void {
        for (jobs) |job| {
            metrics.eventRejected();
            var event = nostr.Event.parse(job.json) catch continue;
            defer event.deinit();
            self.reply(job.conn_id, event.id(), false, "error: storage failed");
        }
    }

    fn freeJobs(self: *Writer, jobs: []Job) void {
        for (jobs) |job| self.allocator.free(job.json);
    }
};
