#!/bin/sh
# Verify that staging contains every backend source and that every module imports.
set -eu

[ "$#" -eq 3 ] || {
    echo "Usage: verify-python-tree.sh SOURCE_BACKEND STAGED_BACKEND PYTHON_LAUNCHER" >&2
    exit 2
}

SOURCE_BACKEND=$1
STAGED_BACKEND=$2
PYTHON_LAUNCHER=$3

for _dir in "$SOURCE_BACKEND" "$STAGED_BACKEND"; do
    [ -d "$_dir/gatebsd_ui" ] && [ ! -L "$_dir" ] && [ ! -L "$_dir/gatebsd_ui" ] || {
        echo "Invalid GateBSD backend directory: $_dir" >&2
        exit 2
    }
done

case "$PYTHON_LAUNCHER" in
    /*) ;;
    *) echo "Python launcher must be an absolute path: $PYTHON_LAUNCHER" >&2; exit 2 ;;
esac
[ -x "$PYTHON_LAUNCHER" ] || {
    echo "Python launcher is not executable: $PYTHON_LAUNCHER" >&2
    exit 2
}

if find "$SOURCE_BACKEND/gatebsd_ui" "$STAGED_BACKEND/gatebsd_ui" -type l -print | grep -q .; then
    echo "Python backend must not contain symbolic links" >&2
    exit 2
fi
if find "$STAGED_BACKEND/gatebsd_ui" \( -name '*.pyc' -o -name __pycache__ \) -print | grep -q .; then
    echo "Staged Python backend contains bytecode/cache artifacts" >&2
    exit 2
fi

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/gatebsd-python-verify.XXXXXX") || exit 2
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT HUP INT TERM

(
    cd "$SOURCE_BACKEND"
    find gatebsd_ui -type f -name '*.py' -print | LC_ALL=C sort
) > "$WORKDIR/source.list"
(
    cd "$STAGED_BACKEND"
    find gatebsd_ui -type f -name '*.py' -print | LC_ALL=C sort
) > "$WORKDIR/staged.list"

if ! cmp -s "$WORKDIR/source.list" "$WORKDIR/staged.list"; then
    echo "Staged GateBSD backend is incomplete or contains unexpected Python modules" >&2
    diff -u "$WORKDIR/source.list" "$WORKDIR/staged.list" >&2 || true
    exit 2
fi

# Compile without writing into the staged package, then import every module from
# an empty environment through the same stable launcher used at runtime.
env -i PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin \
    HOME=/nonexistent LANG=C.UTF-8 PYTHONPYCACHEPREFIX="$WORKDIR/pycache" \
    "$PYTHON_LAUNCHER" -m compileall -q "$STAGED_BACKEND/gatebsd_ui"
env -i PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin \
    HOME=/nonexistent LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="$STAGED_BACKEND" \
    "$PYTHON_LAUNCHER" -m gatebsd_ui.integrity
