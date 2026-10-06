#!/usr/bin/env bash
# Assert that vendor/httpz is exactly upstream http.zig at the pinned commit plus
# the delta recorded in vendor/httpz.patch, with the same file types, executable
# bits and symlink targets.
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

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# A full SHA only: a branch, tag or short prefix could resolve differently later.
UPSTREAM_COMMIT="$(tr -d '[:space:]' < "$repo_root/vendor/httpz.commit")"
[[ "$UPSTREAM_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
    || { echo "vendor/httpz.commit must hold a full 40-character commit SHA" >&2; exit 1; }

vendor_dir="$repo_root/vendor/httpz"
patch_file="$repo_root/vendor/httpz.patch"

[ -d "$vendor_dir" ] || { echo "missing $vendor_dir" >&2; exit 1; }
[ -f "$patch_file" ] || { echo "missing $patch_file" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git -c gc.auto=0 -c maintenance.auto=false clone --quiet --filter=blob:none --no-checkout "$UPSTREAM_REPO" "$tmp/upstream"
git -C "$tmp/upstream" checkout --quiet "$UPSTREAM_COMMIT"

got="$(git -C "$tmp/upstream" rev-parse HEAD)"
if [ "$got" != "$UPSTREAM_COMMIT" ]; then
    echo "upstream checkout resolved to $got, expected $UPSTREAM_COMMIT" >&2
    exit 1
fi
# Deliberately not removed: git may still be writing into .git from background
# maintenance spawned by the clone or checkout, which makes `rm -rf` fail with
# "Directory not empty" and, under `set -e`, abort the run. The diff below
# excludes .git instead, so its contents cannot affect the comparison anyway.

cp -a "$vendor_dir" "$tmp/vendor"

# Paths are relative to $tmp so the headers are stable across machines, and the
# trailing mtimes are stripped so the output depends only on content.
( cd "$tmp" && diff -ruN --exclude=.git upstream vendor || true ) \
    | sed -E -e 's/\t[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+ [+-][0-9]{4}$//' \
             -e "s/^diff -ruN '--exclude=\.git' /diff -ruN /" > "$tmp/actual.patch"

# diff compares content only: it ignores modes and follows symlinks. So compare
# each path's type, executable bit and symlink target separately. The executable
# bit is the only permission git records; the rest follow the local umask.
# f = file, x = executable file, d = directory, l = symlink with its target.
# POSIX find only (no -printf) so this also runs with BSD find on macOS.
manifest() {
    ( cd "$1" && find . -path ./.git -prune -o -print | while IFS= read -r p; do
        if [ -L "$p" ]; then printf '%s\tl -> %s\n' "$p" "$(readlink "$p")"
        elif [ -f "$p" ] && [ -n "$(find "$p" -prune -perm -u+x)" ]; then printf '%s\tx\n' "$p"
        elif [ -f "$p" ]; then printf '%s\tf\n' "$p"
        elif [ -d "$p" ]; then printf '%s\td\n' "$p"
        else printf '%s\t?\n' "$p"
        fi
    done ) | LC_ALL=C sort
}
manifest "$tmp/upstream" > "$tmp/upstream.manifest"
manifest "$tmp/vendor" > "$tmp/vendor.manifest"
# A path in both trees must match. A path only upstream is a deletion and one
# only in vendor an addition, which the patch records; an addition may only be a
# plain file or directory, since the patch cannot record anything else.
mode_drift="$(awk -F'\t' '
    NR == FNR { up[$1] = $2; next }
    $1 in up { if (up[$1] != $2) printf "  %s: upstream %s, vendor %s\n", $1, up[$1], $2; next }
    $2 != "f" && $2 != "d" { printf "  %s: added as %s\n", $1, $2 }
' "$tmp/upstream.manifest" "$tmp/vendor.manifest")"

content_ok=1
diff -u "$patch_file" "$tmp/actual.patch" > "$tmp/drift.diff" || content_ok=0

if [ "$content_ok" -eq 1 ] && [ -z "$mode_drift" ]; then
    echo "vendor/httpz matches upstream $UPSTREAM_COMMIT plus vendor/httpz.patch"
    exit 0
fi

if [ -n "$mode_drift" ]; then
    cat >&2 <<EOF
vendor/httpz differs from upstream $UPSTREAM_COMMIT in file type, executable
bit or symlink target, which vendor/httpz.patch cannot record. Restore these to
match upstream (f = file, x = executable file, d = directory, l = symlink):

$mode_drift

EOF
fi

[ "$content_ok" -eq 1 ] && exit 1

cat >&2 <<EOF
vendor/httpz does not match upstream $UPSTREAM_COMMIT plus vendor/httpz.patch.

Either vendor/httpz was edited without updating the recorded patch, or the
patch was changed without updating the tree. Review the drift below; if the
vendored change is intended, regenerate the patch with:

    scripts/regenerate-vendored-httpz-patch.sh

EOF
cat "$tmp/drift.diff" >&2
exit 1
