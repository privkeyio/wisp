const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const nostr = b.dependency("nostr", .{
        .target = target,
        .optimize = optimize,
    });
    // websocket client for spider outbound connections
    const websocket = b.dependency("websocket", .{
        .target = target,
        .optimize = optimize,
    });
    // http.zig: HTTP + WebSocket epoll worker-pool server
    const httpz = b.dependency("httpz", .{
        .target = target,
        .optimize = optimize,
    });

    const lmdb_c = b.addTranslateC(.{
        .root_source_file = b.path("src/lmdb_c.h"),
        .target = target,
        .optimize = optimize,
    });
    lmdb_c.linkSystemLibrary("lmdb", .{});
    const lmdb_c_mod = lmdb_c.createModule();

    const exe = b.addExecutable(.{
        .name = "wisp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "nostr", .module = nostr.module("nostr") },
                .{ .name = "websocket", .module = websocket.module("websocket") },
                .{ .name = "httpz", .module = httpz.module("httpz") },
                .{ .name = "lmdb_c", .module = lmdb_c_mod },
            },
        }),
    });

    exe.root_module.strip = optimize == .small or optimize == .fast;


    // System libraries
    exe.root_module.linkSystemLibrary("lmdb", .{});
    exe.root_module.link_libc = true;

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run the relay").dependOn(&run_cmd.step);

    const test_lmdb = b.addExecutable(.{
        .name = "test_lmdb",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/test_lmdb.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "lmdb_c", .module = lmdb_c_mod },
            },
        }),
    });
    test_lmdb.root_module.linkSystemLibrary("lmdb", .{});
    test_lmdb.root_module.link_libc = true;
    b.installArtifact(test_lmdb);

    const run_test_lmdb = b.addRunArtifact(test_lmdb);
    run_test_lmdb.step.dependOn(b.getInstallStep());
    b.step("test-lmdb", "Test LMDB bindings").dependOn(&run_test_lmdb.step);

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "nostr", .module = nostr.module("nostr") },
                .{ .name = "websocket", .module = websocket.module("websocket") },
                .{ .name = "httpz", .module = httpz.module("httpz") },
                .{ .name = "lmdb_c", .module = lmdb_c_mod },
            },
        }),
    });
    unit_tests.root_module.linkSystemLibrary("lmdb", .{});
    unit_tests.root_module.link_libc = true;

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // The regression tests wisp added to vendor/httpz. Upstream's own suite
    // starts servers on fixed ports, so it is left to manual runs.
    const httpz_tests = b.addTest(.{
        .root_module = httpz.module("httpz"),
        .filters = &.{"wisp: "},
        .test_runner = .{ .path = httpz.path("test_runner.zig"), .mode = .simple },
    });
    test_step.dependOn(&b.addRunArtifact(httpz_tests).step);
}
