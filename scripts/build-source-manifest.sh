#!/bin/sh
# Regenerate SOURCE_MANIFEST.sha256 from the Git index.
#
# The manifest records one SHA-256 digest per tracked source file and is the
# release provenance record verified by tests/test_release_integrity.py. It
# excludes itself, because a manifest cannot contain its own digest.
#
# Digests are taken from the working tree, so the tree must be free of
# unstaged modifications to tracked files. Otherwise the manifest would
# describe content that the recorded commit does not contain.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
cd "$ROOT"

MANIFEST=SOURCE_MANIFEST.sha256

git rev-parse --git-dir >/dev/null 2>&1 || {
    echo "Not a Git working tree: $ROOT" >&2
    exit 2
}

# Tracked files with unstaged changes would be recorded with digests that do
# not match any commit. Refuse rather than publish a misleading manifest.
UNSTAGED=$(git diff --name-only -- . | grep -v "^${MANIFEST}\$" || true)
if [ -n "$UNSTAGED" ]; then
    echo "Refusing to build manifest: tracked files have unstaged changes:" >&2
    printf '  %s\n' $UNSTAGED >&2
    echo "Stage or revert them first (git add -A), then re-run." >&2
    exit 2
fi

if command -v sha256 >/dev/null 2>&1; then
    digest() { sha256 -q "$1"; }
elif command -v sha256sum >/dev/null 2>&1; then
    digest() { sha256sum "$1" | awk '{print $1}'; }
else
    echo "Neither sha256 nor sha256sum is available" >&2
    exit 2
fi

TMP=$(mktemp "${TMPDIR:-/tmp}/gatebsd-manifest.XXXXXX") || exit 2
trap 'rm -f "$TMP"' EXIT HUP INT TERM

# Sorted by digest, matching the established on-disk format. LC_ALL=C keeps
# the ordering stable regardless of the caller's locale.
git ls-files -z | tr '\0' '\n' | while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ "$path" != "$MANIFEST" ] || continue
    [ -f "$path" ] || {
        echo "Tracked path is missing from the working tree: $path" >&2
        exit 2
    }
    printf '%s  ./%s\n' "$(digest "$path")" "$path"
done | LC_ALL=C sort > "$TMP"

[ -s "$TMP" ] || { echo "Refusing to write an empty manifest" >&2; exit 2; }

COUNT=$(wc -l < "$TMP" | tr -d ' ')
TRACKED=$(git ls-files | grep -cv "^${MANIFEST}\$")
[ "$COUNT" = "$TRACKED" ] || {
    echo "Manifest entry count $COUNT does not match $TRACKED tracked files" >&2
    exit 2
}

cat "$TMP" > "$MANIFEST"
printf 'Wrote %s (%s entries)\n' "$MANIFEST" "$COUNT"
