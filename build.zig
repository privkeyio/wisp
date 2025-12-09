const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Test: libnostr-c FFI
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

    // Test: LMDB
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
