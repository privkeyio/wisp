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

    const exe = b.addExecutable(.{
        .name = "wisp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "nostr", .module = nostr.module("nostr") },
                .{ .name = "websocket", .module = websocket.module("websocket") },
            },
        }),
    });

    exe.root_module.strip = optimize == .ReleaseSmall or optimize == .ReleaseFast;


    // System libraries
    exe.root_module.linkSystemLibrary("lmdb", .{});
    exe.linkLibC();

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    b.step("run", "Run the relay").dependOn(&run_cmd.step);

    const test_lmdb = b.addExecutable(.{
        .name = "test_lmdb",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/test_lmdb.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_lmdb.root_module.linkSystemLibrary("lmdb", .{});
    test_lmdb.linkLibC();
    b.installArtifact(test_lmdb);

    const run_test_lmdb = b.addRunArtifact(test_lmdb);
    run_test_lmdb.step.dependOn(b.getInstallStep());
    b.step("test-lmdb", "Test LMDB bindings").dependOn(&run_test_lmdb.step);
}
