const std = @import("std");

// noscrypt C bindings
const nc = @cImport({
    @cInclude("noscrypt.h");
});

const NC_SUCCESS: i64 = 0;

var ctx: ?*nc.NCContext = null;
var initialized = false;

pub const CryptoError = error{
    InitFailed,
    InvalidKey,
    SignatureFailed,
    VerificationFailed,
};

pub fn init() !void {
    if (initialized) return;

    // Get shared context
    ctx = nc.NCGetSharedContext();
    if (ctx == null) return error.InitFailed;

    // Generate random entropy for context
    var entropy: [32]u8 = undefined;
    std.crypto.random.bytes(&entropy);

    const result = nc.NCInitContext(ctx, &entropy);
    if (result != NC_SUCCESS) {
        return error.InitFailed;
    }

    initialized = true;
}

pub fn cleanup() void {
    if (ctx) |c| {
        _ = nc.NCDestroyContext(c);
        ctx = null;
    }
    initialized = false;
}

pub fn verifySignature(pubkey: *const [32]u8, message: *const [32]u8, sig: *const [64]u8) !void {
    if (!initialized) try init();

    const pk = nc.NCByteCastToPublicKey(pubkey);

    // NCVerifyDigest verifies a schnorr signature against a 32-byte digest
    const result = nc.NCVerifyDigest(ctx, pk, message, sig);

    if (result != NC_SUCCESS) {
        return error.VerificationFailed;
    }
}

pub fn sign(secret_key: *const [32]u8, message: *const [32]u8, sig_out: *[64]u8) !void {
    if (!initialized) try init();

    const sk = nc.NCByteCastToSecretKey(secret_key);

    // Generate random for signing
    var random: [32]u8 = undefined;
    std.crypto.random.bytes(&random);

    const result = nc.NCSignDigest(ctx, sk, &random, message, sig_out);

    if (result != NC_SUCCESS) {
        return error.SignatureFailed;
    }
}

pub fn getPublicKey(secret_key: *const [32]u8, pubkey_out: *[32]u8) !void {
    if (!initialized) try init();

    const sk = nc.NCByteCastToSecretKey(secret_key);
    const pk = nc.NCByteCastToPublicKey(pubkey_out);

    const result = nc.NCGetPublicKey(ctx, sk, pk);

    if (result != NC_SUCCESS) {
        return error.InvalidKey;
    }
}

pub fn validateSecretKey(secret_key: *const [32]u8) !void {
    if (!initialized) try init();

    const sk = nc.NCByteCastToSecretKey(secret_key);

    const result = nc.NCValidateSecretKey(ctx, sk);

    if (result != NC_SUCCESS) {
        return error.InvalidKey;
    }
}

// Test
test "crypto init" {
    try init();
    defer cleanup();
}
