#!/usr/bin/env bash
# Assert that vendor/httpz is exactly upstream http.zig at the pinned commit plus
# the delta recorded in vendor/httpz.patch.
#
# build.zig.zon depends on vendor/httpz by path, which means the Zig package
# manager no longer hashes it. Nothing else in the repo would notice an edit to
# 15k lines of vendored HTTP and WebSocket code, so this check stands in for the
# hash that the path dependency removed.
#
# Upstream is fetched by commit SHA rather than by release tarball on purpose:
# a SHA is content-addressed and cannot drift, whereas GitHub's generated
# archives are not guaranteed to stay byte-identical over time.
set -euo pipefail

UPSTREAM_REPO="https://github.com/karlseguin/http.zig"
UPSTREAM_COMMIT="01dc09453ae50b82cc74ac2f90e9cd57e0b38500"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vendor_dir="$repo_root/vendor/httpz"
patch_file="$repo_root/vendor/httpz.patch"

[ -d "$vendor_dir" ] || { echo "missing $vendor_dir" >&2; exit 1; }
[ -f "$patch_file" ] || { echo "missing $patch_file" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git clone --quiet --filter=blob:none --no-checkout "$UPSTREAM_REPO" "$tmp/upstream"
git -C "$tmp/upstream" checkout --quiet "$UPSTREAM_COMMIT"

got="$(git -C "$tmp/upstream" rev-parse HEAD)"
if [ "$got" != "$UPSTREAM_COMMIT" ]; then
    echo "upstream checkout resolved to $got, expected $UPSTREAM_COMMIT" >&2
    exit 1
fi
rm -rf "$tmp/upstream/.git"

cp -a "$vendor_dir" "$tmp/vendor"

# Paths are relative to $tmp so the headers are stable across machines, and the
# trailing mtimes are stripped so the output depends only on content.
( cd "$tmp" && diff -ruN upstream vendor || true ) \
    | sed -E 's/\t[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+ [+-][0-9]{4}$//' > "$tmp/actual.patch"

if diff -u "$patch_file" "$tmp/actual.patch" > "$tmp/drift.diff"; then
    echo "vendor/httpz matches upstream $UPSTREAM_COMMIT plus vendor/httpz.patch"
    exit 0
fi

cat >&2 <<EOF
vendor/httpz does not match upstream $UPSTREAM_COMMIT plus vendor/httpz.patch.

Either vendor/httpz was edited without updating the recorded patch, or the
patch was changed without updating the tree. Review the drift below; if the
vendored change is intended, regenerate the patch with:

    scripts/regenerate-vendored-httpz-patch.sh

EOF
cat "$tmp/drift.diff" >&2
exit 1
