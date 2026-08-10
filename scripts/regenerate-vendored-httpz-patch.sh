#!/usr/bin/env bash
# Rewrite vendor/httpz.patch to match the current vendor/httpz tree.
#
# Run this after deliberately changing the vendored httpz sources, then review
# the resulting patch: it is the complete record of how the vendored copy
# differs from upstream, and it is what CI enforces.
set -euo pipefail

UPSTREAM_REPO="https://github.com/karlseguin/http.zig"
UPSTREAM_COMMIT="01dc09453ae50b82cc74ac2f90e9cd57e0b38500"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git clone --quiet --filter=blob:none --no-checkout "$UPSTREAM_REPO" "$tmp/upstream"
git -C "$tmp/upstream" checkout --quiet "$UPSTREAM_COMMIT"
rm -rf "$tmp/upstream/.git"

cp -a "$repo_root/vendor/httpz" "$tmp/vendor"

( cd "$tmp" && diff -ruN upstream vendor || true ) \
    | sed -E 's/\t[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+ [+-][0-9]{4}$//' > "$repo_root/vendor/httpz.patch"

echo "wrote vendor/httpz.patch ($(wc -l < "$repo_root/vendor/httpz.patch") lines)"
