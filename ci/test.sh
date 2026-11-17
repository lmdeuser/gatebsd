#!/bin/sh
# GateBSD CI test - uses fresh jail for each run
# Usage: ci/test.sh [version]
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="${1:-$(cat "$REPO_DIR/VERSION")}"
REVISION="${PKG_REVISION:-$(cat "$REPO_DIR/PKG_REVISION" 2>/dev/null || printf 0)}"
case "$VERSION" in ''|*[!A-Za-z0-9+_.-]*|[.-]*|*..*) echo "Invalid VERSION: $VERSION" >&2; exit 2 ;; esac
case "$REVISION" in
    0|'') PKG_VERSION="$VERSION" ;;
    *[!0-9]*) echo "Invalid PKG_REVISION: $REVISION" >&2; exit 2 ;;
    *) PKG_VERSION="${VERSION}_${REVISION}" ;;
esac
DIST="/tank/packages/gatebsd-build/dist"
PKG="$DIST/gatebsd-${PKG_VERSION}-nodeps.pkg"
JAIL_NAME="gatebsd-ci-${VERSION}-${REVISION}"
JAIL_PATH="/tank/packages/poudriere/jails/${JAIL_NAME}"
LOG="/tank/packages/gatebsd-build/logs/ci-$(date +%Y%m%d-%H%M%S).log"
PASS=0; FAIL=0
JAIL_CREATED=0
DEVFS_MOUNTED=0

cleanup() {
    if [ "$DEVFS_MOUNTED" -eq 1 ]; then
        umount "${JAIL_PATH}/dev" 2>/dev/null || true
        DEVFS_MOUNTED=0
    fi
    jail -r "$JAIL_NAME" 2>/dev/null || true
    if [ "$JAIL_CREATED" -eq 1 ]; then
        poudriere jail -d -j "$JAIL_NAME" >/dev/null 2>&1 || true
        JAIL_CREATED=0
    fi
}
trap cleanup EXIT HUP INT TERM

log() { echo "$(date '+%H:%M:%S') $*" | tee -a "$LOG"; }

mkdir -p /tank/packages/gatebsd-build/logs

log "=== GateBSD CI Test v${PKG_VERSION} ==="

# Verify package exists
[ -f "$PKG" ] || { log "ERROR: Package not found: $PKG"; exit 1; }
log "Package: $PKG ($(ls -lh "$PKG" | awk '{print $5}'))"

# Destroy previous test jail (fresh every time)
if poudriere jail -l 2>/dev/null | grep -q "^${JAIL_NAME}"; then
    log "Destroying previous test jail..."
    jail -r "$JAIL_NAME" 2>/dev/null || true
    poudriere jail -d -j "$JAIL_NAME" 2>&1 | tail -1
fi

# Create fresh jail
log "Creating fresh jail ${JAIL_NAME}..."
poudriere jail -c -j "$JAIL_NAME" -v 15.1-RELEASE -a amd64 -m ftp >> "$LOG" 2>&1
JAIL_CREATED=1
log "Jail created"

# Copy one immutable package name into the private jail.
mkdir -p "${JAIL_PATH}/tmp"
install -m 0600 "$PKG" "${JAIL_PATH}/tmp/gatebsd-test.pkg"

# Mount devfs
mount -t devfs devfs "${JAIL_PATH}/dev"
DEVFS_MOUNTED=1

# Install package
log "Installing GateBSD..."
INSTALL_OUTPUT=$(chroot "${JAIL_PATH}" /bin/sh -c "
    pkg bootstrap -y >/dev/null 2>&1 || true
    env ASSUME_ALWAYS_YES=yes pkg add -f /tmp/gatebsd-test.pkg 2>&1
" 2>&1)
echo "$INSTALL_OUTPUT" >> "$LOG"

# Check if installation actually succeeded
if ! chroot "${JAIL_PATH}" /bin/sh -c "pkg info gatebsd >/dev/null 2>&1"; then
    log "FAIL: Package installation failed"
    log "Install output: $(echo "$INSTALL_OUTPUT" | tail -5)"
    exit 1
fi

# Install test dependencies
log "Installing test dependencies..."
chroot "${JAIL_PATH}" /bin/sh -c '
    set -eu
    pkg install -y python3 >/dev/null 2>&1
    python_cmd=$(realpath /usr/local/bin/python3)
    python_base=${python_cmd##*/}
    python_version=${python_base#python}
    python_flavor=py$(printf "%s" "$python_version" | tr -d .)
    pkg install -y "${python_flavor}-sqlite3" >/dev/null 2>&1
    "$python_cmd" -c "import sqlite3"
' >> "$LOG" 2>&1

# Run tests
run_test() {
    name="$1"; shift
    echo -n "  ${name}: "
    R=$(chroot "${JAIL_PATH}" /bin/sh -c "$@" 2>&1)
    if [ "$R" = "OK" ]; then
        echo "PASS" | tee -a "$LOG"
        PASS=$((PASS+1))
    else
        echo "FAIL: $R" | tee -a "$LOG"
        FAIL=$((FAIL+1))
    fi
}

log "Tests:"
run_test "Package installed" "pkg info gatebsd >/dev/null 2>&1 && echo OK || echo FAIL"
run_test "VERSION file" "V=\$(cat /usr/local/share/gatebsd/VERSION 2>/dev/null); [ -n \"\$V\" ] && echo OK || echo FAIL"
run_test "Storage migration" "env PYTHONPATH=/usr/local/share/gatebsd/webui/backend /usr/local/libexec/gatebsd-python -c \"from gatebsd_ui import storage; print('OK' if storage.migrate()==storage.SCHEMA_VERSION else 'FAIL')\""
run_test "Recovery module" "env PYTHONPATH=/usr/local/share/gatebsd/webui/backend /usr/local/libexec/gatebsd-python -c \"
import tempfile; from pathlib import Path; from gatebsd_ui import recovery
d=Path(tempfile.mkdtemp()); recovery.AUTO_STATE_PATH=d/'s.json'
recovery._healthy=lambda:(True,{'ip':True,'dns':True,'https':True})
recovery._default_interface=lambda:'awg0'
c,r=recovery.auto_recover(); print('OK' if c==200 and r['ok'] else 'FAIL')
\""
run_test "All modules" "env PYTHONPATH=/usr/local/share/gatebsd/webui/backend /usr/local/libexec/gatebsd-python -c \"
import importlib; ms=['storage','recovery','command','config','paths','routing','failover']
print('OK' if all(importlib.import_module('gatebsd_ui.'+m) for m in ms) else 'FAIL')
\""

# Cleanup is handled by the EXIT trap, including failures.

# Report
log ""
log "=== Results: ${PASS} passed, ${FAIL} failed ==="
log "Log: ${LOG}"

[ "$FAIL" -eq 0 ] && { log "ALL TESTS PASSED"; exit 0; } || { log "SOME TESTS FAILED"; exit 1; }
