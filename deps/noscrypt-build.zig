const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build monocypher as a static library
    const monocypher_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const monocypher = b.addLibrary(.{
        .name = "monocypher",
        .root_module = monocypher_mod,
        .linkage = .static,
    });

    monocypher_mod.addCSourceFile(.{
        .file = b.path("vendor/monocypher/monocypher.c"),
        .flags = &.{ "-std=c99", "-O3" },
    });
    monocypher_mod.addIncludePath(b.path("vendor/monocypher"));

    // Build noscrypt static library
    const noscrypt_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const noscrypt = b.addLibrary(.{
        .name = "noscrypt",
        .root_module = noscrypt_mod,
        .linkage = .static,
    });

    noscrypt_mod.addCSourceFiles(.{
        .files = &.{
            "src/noscrypt.c",
            "src/hkdf.c",
            "src/nc-crypto.c",
        },
        .flags = &.{
            "-std=gnu99", // noscrypt uses inline functions
            "-fstack-protector",
            "-DOPENSSL_CRYPTO_LIB",
            "-DNC_ENABLE_MONOCYPHER",
        },
    });

    noscrypt_mod.addIncludePath(b.path("include"));
    noscrypt_mod.addIncludePath(b.path("src"));
    noscrypt_mod.addIncludePath(b.path("vendor"));
    noscrypt_mod.addIncludePath(b.path("vendor/monocypher"));

    // Link dependencies
    noscrypt.linkLibrary(monocypher);
    noscrypt_mod.linkSystemLibrary("secp256k1", .{});
    noscrypt_mod.linkSystemLibrary("crypto", .{}); // OpenSSL

    b.installArtifact(noscrypt);
}
