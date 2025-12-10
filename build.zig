const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Import dependencies
    const httpz = b.dependency("httpz", .{
        .target = target,
        .optimize = optimize,
    });
    // Get websocket from httpz to avoid version conflicts
    const httpz_dep = httpz.builder.dependency("websocket", .{
        .target = target,
        .optimize = optimize,
    });
    const noscrypt = b.dependency("noscrypt", .{
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
                .{ .name = "websocket", .module = httpz_dep.module("websocket") },
            },
        }),
    });

    exe.root_module.strip = optimize == .ReleaseSmall or optimize == .ReleaseFast;

    // Link noscrypt (statically built by Zig)
    exe.linkLibrary(noscrypt.artifact("noscrypt"));
    exe.root_module.addIncludePath(noscrypt.path("include"));

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
