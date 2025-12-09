const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Import http.zig and websocket.zig dependencies
    const httpz = b.dependency("httpz", .{
        .target = target,
        .optimize = optimize,
    });
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
                .{ .name = "httpz", .module = httpz.module("httpz") },
                .{ .name = "websocket", .module = websocket.module("websocket") },
            },
        }),
    });

    exe.root_module.strip = optimize == .ReleaseSmall or optimize == .ReleaseFast;

    exe.addIncludePath(.{ .cwd_relative = "../libnostr-c/include" });
    exe.addIncludePath(.{ .cwd_relative = "../libnostr-c/build/include" });
    exe.addLibraryPath(.{ .cwd_relative = "../libnostr-c/build" });
    exe.linkSystemLibrary("nostr");
    exe.linkSystemLibrary("lmdb");
    exe.linkLibC();

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    b.step("run", "Run the relay").dependOn(&run_cmd.step);

    const test_nostr = b.addExecutable(.{
        .name = "test_nostr",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/test_nostr.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_nostr.addIncludePath(.{ .cwd_relative = "../libnostr-c/include" });
    test_nostr.addIncludePath(.{ .cwd_relative = "../libnostr-c/build/include" });
    test_nostr.addLibraryPath(.{ .cwd_relative = "../libnostr-c/build" });
    test_nostr.linkSystemLibrary("nostr");
    test_nostr.linkLibC();
    b.installArtifact(test_nostr);

    const run_test_nostr = b.addRunArtifact(test_nostr);
    run_test_nostr.step.dependOn(b.getInstallStep());
    b.step("test-nostr", "Test libnostr-c bindings").dependOn(&run_test_nostr.step);

    const test_lmdb = b.addExecutable(.{
        .name = "test_lmdb",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/test_lmdb.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_lmdb.linkSystemLibrary("lmdb");
    test_lmdb.linkLibC();
    b.installArtifact(test_lmdb);

    const run_test_lmdb = b.addRunArtifact(test_lmdb);
    run_test_lmdb.step.dependOn(b.getInstallStep());
    b.step("test-lmdb", "Test LMDB bindings").dependOn(&run_test_lmdb.step);
}
