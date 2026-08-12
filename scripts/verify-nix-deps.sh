#!/usr/bin/env bash
# Checks nix/deps.nix and nix/package.nix against the Zig manifests, offline.
#
# Why this exists at all: in `--system` mode (which nix/package.nix uses) the Zig
# package hash is a LOOKUP KEY, not an attestation. Zig checks that a directory
# of that name exists and adopts it; the "hash mismatch" comparison lives on the
# network fetch path and is never reached. Verified by experiment: appending a
# line to a package's source inside the system dir and rebuilding still succeeds.
# So the `hash =` values in deps.nix are the only integrity gate on the Nix
# build, and an entry whose url and hash were changed together would be fetched
# and adopted without anything disagreeing.
#
# What this closes: it ties each cache entry's url back to the revision the
# manifest actually asks for. Combined with nix's fixed-output hash (url ->
# content) and the network `zig build` in the other CI jobs (manifest hash ->
# content), the chain from manifest to compiled bytes is complete.
#
# It also catches two drift classes cheaply:
#   1. A direct dependency missing from the cache. `nix build` catches this too,
#      but takes ~2 minutes and reports a store path; this names the hash in a
#      second.
#   2. nix/package.nix's version drifting from build.zig.zon. Nothing compared
#      these, and it silently lagged from 0.5.10 across two releases. NIP-11
#      reports its own literal, so the packaged version is invisible at runtime.
#
# What it deliberately does NOT catch, and why: an entry that no manifest
# requires (the obsolete httpz entry was one), and the url of a TRANSITIVE entry
# such as noscrypt or StringZilla. Both need the full closure, and the transitive
# manifests live inside fetched packages rather than the repo -- zig-pkg/ is
# gitignored. Resolving them means network fetches on every run. Upgrade path if
# that becomes worth it: walk the closure from a populated ZIG_GLOBAL_CACHE_DIR
# after `zig build --fetch`, then assert set equality and cross-check every url.
#
# Usage: scripts/verify-nix-deps.sh   (from anywhere in the repo)
# Requires: bash, grep, awk, comm. No nix, no network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0

# "<hash> <owner>/<repo>@<rev>" per direct dependency, from both in-repo
# manifests. Path dependencies have no .url/.hash and so contribute nothing:
# httpz is part of the source tree rather than the cache, which is why it has no
# entry here or in deps.nix.
#
# Manifest urls look like https://github.com/<o>/<r>/archive/<rev>.tar.gz or
# .../archive/refs/tags/<tag>.tar.gz.
manifest_pairs() {
  awk '
    /\.url = "/ {
      line = $0
      sub(/.*\.url = "/, "", line); sub(/".*/, "", line)
      url = line
      next
    }
    /\.hash = "/ && url != "" {
      line = $0
      sub(/.*\.hash = "/, "", line); sub(/".*/, "", line)
      slug = url
      sub(/^https:\/\/github\.com\//, "", slug)
      repo = slug; sub(/\/archive\/.*/, "", repo)
      rev = slug; sub(/^.*\/archive\//, "", rev); sub(/\.tar\.gz$/, "", rev)
      print line, repo "@" rev
      url = ""
    }
  ' "$@" | sort -u
}

# "<name> <owner>/<repo>@<rev>" per cache entry.
# deps.nix urls look like https://codeload.github.com/<o>/<r>/tar.gz/<rev> or
# .../tar.gz/refs/tags/<tag>.
deps_pairs() {
  awk '
    /^    name = "/ {
      line = $0
      sub(/.*name = "/, "", line); sub(/".*/, "", line)
      name = line
      next
    }
    /^      url = "/ && name != "" {
      line = $0
      sub(/.*url = "/, "", line); sub(/".*/, "", line)
      slug = line
      sub(/^https:\/\/codeload\.github\.com\//, "", slug)
      repo = slug; sub(/\/tar\.gz\/.*/, "", repo)
      rev = slug; sub(/^.*\/tar\.gz\//, "", rev)
      print name, repo "@" rev
      name = ""
    }
  ' nix/deps.nix | sort -u
}

required_pairs="$(manifest_pairs build.zig.zon vendor/httpz/build.zig.zon)"
present_pairs="$(deps_pairs)"

required_hashes="$(printf '%s\n' "$required_pairs" | awk '{print $1}' | sort -u)"
present_hashes="$(printf '%s\n' "$present_pairs" | awk '{print $1}' | sort -u)"

# Subset, not equality: deps.nix also legitimately carries transitive entries
# (noscrypt and StringZilla arrive via libnostr-z) that no in-repo manifest names.
missing="$(comm -23 <(printf '%s\n' "$required_hashes") <(printf '%s\n' "$present_hashes") || true)"
if [ -n "$missing" ]; then
  echo "FAIL - nix/deps.nix is missing entries the manifests require:"
  printf '  %s\n' $missing
  echo "       nix build would fail with \"package not found\" for these."
  fail=1
fi

# The check that matters: same hash on both sides must mean the same revision.
checked=0
while read -r hash want; do
  [ -n "$hash" ] || continue
  got="$(printf '%s\n' "$present_pairs" | awk -v h="$hash" '$1 == h {print $2}')"
  [ -n "$got" ] || continue   # already reported as missing above
  if [ "$got" != "$want" ]; then
    echo "FAIL - $hash points at different revisions:"
    echo "         manifest asks for $want"
    echo "         nix/deps.nix fetches $got"
    echo "       In --system mode zig does not verify content against the hash, so"
    echo "       this would be adopted silently."
    fail=1
  else
    checked=$((checked + 1))
  fi
done <<< "$required_pairs"

zon_version="$(grep -oP '(?<=\.version = ")[^"]+' build.zig.zon | head -1)"
nix_version="$(grep -oP '(?<=^  version = ")[^"]+' nix/package.nix | head -1)"
if [ -z "$zon_version" ] || [ -z "$nix_version" ]; then
  echo "FAIL - could not read a version from build.zig.zon ('$zon_version') or nix/package.nix ('$nix_version')"
  fail=1
elif [ "$zon_version" != "$nix_version" ]; then
  echo "FAIL - version mismatch: build.zig.zon says '$zon_version', nix/package.nix says '$nix_version'"
  fail=1
fi

[ "$fail" -eq 0 ] || exit 1

echo "ok - $checked direct entries match the manifests by hash and revision; package version $zon_version"
