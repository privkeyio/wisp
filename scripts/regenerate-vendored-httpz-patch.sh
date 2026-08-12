#!/usr/bin/env bash
# Rewrite vendor/httpz.patch to match the current vendor/httpz tree.
#
# Run this after deliberately changing the vendored httpz sources, then review
# the resulting patch: it is the complete record of how the vendored copy
# differs from upstream, and it is what CI enforces.
set -euo pipefail

UPSTREAM_REPO="https://github.com/karlseguin/http.zig"
UPSTREAM_COMMIT="dce2cb07f1cd9beca6146869e1eec48025cf9f6f"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git -c gc.auto=0 -c maintenance.auto=false clone --quiet --filter=blob:none --no-checkout "$UPSTREAM_REPO" "$tmp/upstream"
git -C "$tmp/upstream" checkout --quiet "$UPSTREAM_COMMIT"
# Deliberately not removed: git may still be writing into .git from background
# maintenance spawned by the clone or checkout, which makes `rm -rf` fail with
# "Directory not empty" and, under `set -e`, abort the run. The diff below
# excludes .git instead, so its contents cannot affect the comparison anyway.

cp -a "$repo_root/vendor/httpz" "$tmp/vendor"

( cd "$tmp" && diff -ruN --exclude=.git upstream vendor || true ) \
    | sed -E -e 's/\t[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+ [+-][0-9]{4}$//' \
             -e "s/^diff -ruN '--exclude=\.git' /diff -ruN /" > "$repo_root/vendor/httpz.patch"

echo "wrote vendor/httpz.patch ($(wc -l < "$repo_root/vendor/httpz.patch") lines)"
