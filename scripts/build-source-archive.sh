#!/bin/sh
# Build a reproducible GateBSD source archive that preserves POSIX file modes.
#
# The contents come from `git ls-files`, the same list build-source-manifest.sh
# uses. It used to walk the tree instead, which meant the archive was whatever
# happened to be lying in the working directory:
#
#   * every untracked file, including `.secrets/forgejo-api-token` and the
#     three .env files beside it, and a subscription token that arrived in the
#     tree once. .gitignore had no say -- os.walk does not read it;
#   * the whole of `.git`, history and all;
#   * files being written while the archive was being built. That is not a
#     theoretical race: the build failed outright on an editor's live state
#     file, so `make source-archive` could not complete in a working tree that
#     anything else was touching.
#
# "Reproducible" is the first word of this script's job, and a build whose
# output depends on what else is in the directory is not. Tracked files are
# the source; everything else is local.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
OUTPUT=${1:-$(dirname "$ROOT")/netgate.zip}
case "$OUTPUT" in
    /*) ;;
    *) OUTPUT=$(pwd -P)/$OUTPUT ;;
esac
case "$OUTPUT" in
    "$ROOT"|"$ROOT"/*)
        echo "Archive must be created outside the source tree" >&2
        exit 2
        ;;
esac

PYTHON_CMD=${PYTHON_CMD:-$(command -v python3 2>/dev/null || true)}
[ -n "$PYTHON_CMD" ] && [ -x "$PYTHON_CMD" ] || {
    echo "A generic Python 3 interpreter is required to build the source archive" >&2
    exit 2
}
command -v unzip >/dev/null 2>&1 || { echo "unzip is required for archive verification" >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "git is required: the archive contents come from git ls-files" >&2; exit 2; }
git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 || {
    echo "Not a git repository: $ROOT" >&2
    exit 2
}

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}
case "$SOURCE_DATE_EPOCH" in ''|*[!0-9]*) echo "Invalid SOURCE_DATE_EPOCH" >&2; exit 2 ;; esac
export SOURCE_DATE_EPOCH

mkdir -p "$(dirname "$OUTPUT")"
TMP_OUTPUT="${OUTPUT}.tmp.$$"
rm -f "$TMP_OUTPUT"
FILE_LIST="${OUTPUT}.files.$$"
rm -f "$FILE_LIST"
cleanup() {
    rm -f "$TMP_OUTPUT" "$FILE_LIST"
    [ -z "${VERIFY_DIR:-}" ] || rm -rf "$VERIFY_DIR"
}
trap cleanup EXIT HUP INT TERM

# NUL-separated: paths may contain anything but NUL, and the Python side is
# handed a file rather than stdin because stdin is already the script.
git -C "$ROOT" ls-files -z > "$FILE_LIST"
[ -s "$FILE_LIST" ] || { echo "git ls-files listed nothing in $ROOT" >&2; exit 2; }

"$PYTHON_CMD" - "$ROOT" "$TMP_OUTPUT" "$FILE_LIST" <<'PY'
from __future__ import annotations

import hashlib
import os
import stat
import sys
import time
import zipfile
from pathlib import Path

root = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2]).resolve()
file_list = Path(sys.argv[3])
archive_root = root.name
source_epoch = int(os.environ["SOURCE_DATE_EPOCH"])
source_epoch = max(source_epoch, 315532800)  # ZIP timestamps begin in 1980.
date_time = time.gmtime(source_epoch)[:6]

# The tracked set, exactly as `git ls-files -z` reported it. Nothing is skipped
# here: a file is in the archive because it is in the repository, and the way
# to keep something out is not to track it.
tracked = [
    name for name in file_list.read_bytes().split(b"\0")
    if name
]

entries: list[tuple[Path, os.stat_result]] = []
seen_dirs: set[Path] = set()
for raw in sorted(tracked):
    relative = Path(os.fsdecode(raw))
    path = root / relative
    if not path.is_symlink() and not path.exists():
        # Tracked but not in the working tree: the archive would silently be
        # missing source. Say so instead.
        raise RuntimeError(f"tracked file is absent from the working tree: {relative}")
    # Directory entries carry modes of their own and the verification step
    # below checks them, so every parent of a tracked file is emitted once.
    for parent in reversed(relative.parents):
        if parent == Path("."):
            continue
        if parent in seen_dirs:
            continue
        seen_dirs.add(parent)
        parent_path = root / parent
        entries.append((parent_path, parent_path.lstat()))
    entries.append((path, path.lstat()))

expected: dict[str, tuple[int, str, bytes | str | None]] = {}
with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=False) as archive:
    root_info = zipfile.ZipInfo(f"{archive_root}/", date_time)
    root_mode = root.lstat().st_mode
    root_info.create_system = 3
    root_info.external_attr = (root_mode & 0xFFFF) << 16
    root_info.external_attr |= 0x10
    archive.writestr(root_info, b"")
    expected[root_info.filename] = (stat.S_IMODE(root_mode), "dir", None)

    for path, before in sorted(entries, key=lambda item: item[0].relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        arcname = f"{archive_root}/{relative}"
        mode = before.st_mode
        info = zipfile.ZipInfo(arcname + ("/" if stat.S_ISDIR(mode) else ""), date_time)
        info.create_system = 3
        info.external_attr = (mode & 0xFFFF) << 16

        if stat.S_ISDIR(mode):
            info.external_attr |= 0x10
            archive.writestr(info, b"")
            expected[info.filename] = (stat.S_IMODE(mode), "dir", None)
        elif stat.S_ISLNK(mode):
            target = os.readlink(path)
            payload = target.encode("utf-8", "surrogateescape")
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
            expected[info.filename] = (stat.S_IMODE(mode), "symlink", target)
        elif stat.S_ISREG(mode):
            with path.open("rb") as handle:
                data = handle.read()
            after = path.lstat()
            identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            if identity_before != identity_after:
                raise RuntimeError(f"source changed while archiving: {path}")
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
            expected[info.filename] = (
                stat.S_IMODE(mode),
                "file",
                hashlib.sha256(data).digest(),
            )
        else:
            raise RuntimeError(f"unsupported special file in source tree: {path}")

with zipfile.ZipFile(output, "r") as archive:
    corrupt = archive.testzip()
    if corrupt is not None:
        raise RuntimeError(f"archive CRC verification failed: {corrupt}")
    items = {item.filename: item for item in archive.infolist()}
    if set(items) != set(expected):
        missing = sorted(set(expected) - set(items))
        extra = sorted(set(items) - set(expected))
        raise RuntimeError(f"archive inventory verification failed; missing={missing}, extra={extra}")
    for name, (expected_mode, expected_type, expected_payload) in expected.items():
        item = items[name]
        actual_mode = (item.external_attr >> 16) & 0o7777
        if actual_mode != expected_mode:
            raise RuntimeError(
                f"archive mode verification failed for {name}: "
                f"expected {expected_mode:o}, got {actual_mode:o}"
            )
        data = archive.read(item)
        if expected_type == "dir":
            if not item.is_dir() or data:
                raise RuntimeError(f"archive directory verification failed: {name}")
        elif expected_type == "symlink":
            target = data.decode("utf-8", "surrogateescape")
            if target != expected_payload:
                raise RuntimeError(f"archive symlink verification failed: {name}")
        elif hashlib.sha256(data).digest() != expected_payload:
            raise RuntimeError(f"archive content verification failed: {name}")
PY

mv -f "$TMP_OUTPUT" "$OUTPUT"

VERIFY_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gatebsd-archive-verify.XXXXXX") || exit 2
unzip -tq "$OUTPUT" >/dev/null
unzip -q "$OUTPUT" -d "$VERIFY_DIR"
# Over the tracked list, not the tree: an untracked executable lying about is
# not in the archive and must not be looked for there. `tr` is safe because
# `ls-files -z` does not quote, and a path may hold anything but NUL -- the
# same reading build-source-manifest.sh takes.
tr '\0' '\n' < "$FILE_LIST" > "$VERIFY_DIR/tracked.list"
while IFS= read -r _relative; do
    [ -n "$_relative" ] || continue
    [ -x "$ROOT/$_relative" ] || continue
    [ -x "$VERIFY_DIR/$(basename "$ROOT")/$_relative" ] || {
        echo "Archive lost executable mode for $_relative" >&2
        exit 2
    }
done < "$VERIFY_DIR/tracked.list"

if command -v sha256 >/dev/null 2>&1; then
    DIGEST=$(sha256 -q "$OUTPUT")
else
    DIGEST=$(sha256sum "$OUTPUT" | awk '{print $1}')
fi
printf 'Created %s\nSHA-256 %s\n' "$OUTPUT" "$DIGEST"
