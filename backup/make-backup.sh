#!/bin/sh
# Source-tree wrapper for the canonical GateBSD image backup implementation.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
SOURCE_HELPER="$SCRIPT_DIR/../sbin/gatebsd-backup.sh"
if [ -x "$SOURCE_HELPER" ]; then
    exec "$SOURCE_HELPER" "$@"
fi
exec /usr/local/sbin/gatebsd-backup.sh "$@"
