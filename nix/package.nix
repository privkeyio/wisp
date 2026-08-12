# Hermetic Zig 0.16 build of the wisp relay. build.zig.zon declares two fetched dependencies
# (websocket, nostr) plus a path dependency on vendor/httpz, and deps.nix pins that whole transitive
# closure by URL+hash, fetches each as a fixed-output derivation, and links them into Zig's global
# package cache, so the build needs no network. deps.nix is maintained BY HAND and cannot be
# regenerated with zon2nix (it cannot express the path dependency); see the header there.
# System libs: lmdb (linked directly by build.zig), plus secp256k1 + openssl
# (pulled in via the noscrypt crypto dependency).
{
  lib,
  stdenv,
  callPackage,
  zig_0_16,
  lmdb,
  secp256k1,
  openssl,
  src ? lib.cleanSource ../.,
}:
let
  zigDeps = callPackage ./deps.nix { };
in
stdenv.mkDerivation (finalAttrs: {
  pname = "wisp";
  version = "0.6.0"; # keep in sync with build.zig.zon .version
  inherit src;

  nativeBuildInputs = [ zig_0_16 ];
  buildInputs = [
    lmdb
    secp256k1
    openssl
  ];

  # Zig manages its own configure/build; drive it by hand so the pre-fetched deps cache is in place.
  dontConfigure = true;
  dontInstall = true; # `zig build install --prefix $out` installs directly

  buildPhase = ''
    runHook preBuild

    # A writable Zig cache for build artifacts (o/, z/); the DEPENDENCIES come from --system below.
    export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-cache"
    mkdir -p "$ZIG_GLOBAL_CACHE_DIR"

    # `--system <dir>` resolves every build.zig.zon dependency from the pre-fetched FOD package set
    # instead of the network, so the build is hermetic.
    #
    # The hash is a LOOKUP KEY here, not an attestation. In --system mode zig only checks that a
    # directory of that name exists and adopts it; the "hash mismatch" comparison lives on the
    # network fetch path and is never reached. Verified by experiment, not by reading: appending a
    # line to a package's source inside the system dir and rebuilding still succeeds. So the
    # `hash =` values in deps.nix are the ONLY integrity gate on this build, and an entry whose url
    # and hash are changed together would be adopted with no complaint. scripts/verify-nix-deps.sh
    # is what ties each entry's url back to the revision the manifest asks for.
    # Target the BASELINE microarchitecture, not the build machine's native CPU: Zig otherwise bakes in
    # host CPU features (AVX2, etc.) and the binary SIGILLs on older/emulated CPUs. Baseline is the
    # portable, reproducible choice for a distributed package; SIMD-heavy deps do runtime dispatch.
    zig build install \
      --system ${zigDeps} \
      -Doptimize=ReleaseFast \
      -Dcpu=baseline \
      --prefix "$out" \
      --search-prefix ${lib.getLib lmdb} \
      --search-prefix ${lib.getLib secp256k1} \
      --search-prefix ${lib.getLib openssl} \
      --color off --summary all

    # build.zig also installs a test_lmdb helper; the package ships only the relay binary.
    rm -f "$out/bin/test_lmdb"

    runHook postBuild
  '';

  meta = {
    description = "Fast, lightweight nostr relay written in Zig";
    homepage = "https://github.com/privkeyio/wisp";
    license = lib.licenses.mit;
    mainProgram = "wisp";
    platforms = lib.platforms.linux;
  };
})
