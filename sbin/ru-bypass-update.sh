#!/bin/sh
# Download, validate, atomically publish, and apply the RU prefix table.
set -eu

PATH=${GATEBSD_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}
CONF=${GATEBSD_GATEWAY_CONF:-/usr/local/etc/amnezia/gateway.conf}
RU_TABLE=${RU_TABLE:-/usr/local/etc/amnezia/ru_bypass.table}
DIRECT_EXCEPTIONS=${GATEBSD_DIRECT_EXCEPTIONS:-/usr/local/etc/amnezia/direct-exceptions.conf}
URL=${RU_TABLE_URL:-https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone}
MIN_PREFIXES=${RU_TABLE_MIN_PREFIXES:-1000}
MAX_BYTES=${RU_TABLE_MAX_BYTES:-16777216}
LOCK_FILE=${GATEBSD_RU_UPDATE_LOCK:-/var/run/gatebsd/ru-bypass-update.lock}
PYTHON_LAUNCHER=${GATEBSD_PYTHON_LAUNCHER:-/usr/local/libexec/gatebsd-python}
BACKEND=${GATEBSD_BACKEND:-/usr/local/share/gatebsd/webui/backend}
RU_ROUTES_HELPER=${GATEBSD_RU_ROUTES_HELPER:-/usr/local/sbin/ru-routes.sh}

log() { logger -t ru-bypass-update "$*" 2>/dev/null || true; printf '[ru-bypass-update] %s\n' "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

safe_source() {
    _path=$1
    [ -e "$_path" ] || return 0
    [ -f "$_path" ] && [ ! -L "$_path" ] || die "unsafe config: $_path"
    _uid=$(stat -f '%u' "$_path" 2>/dev/null || printf '%s' -1)
    _mode=$(stat -f '%Lp' "$_path" 2>/dev/null || printf '%s' 777)
    [ "$_uid" = 0 ] || die "config must be owned by root: $_path"
    case "$_mode" in *[2367][0-7]|*[0-7][2367]) die "config must not be group/world writable: $_path" ;; esac
    # shellcheck disable=SC1090 -- root-owned fixed configuration path.
    . "$_path"
}
safe_source "$CONF"

# Create a directory if it is missing, and otherwise leave its ownership alone.
#
# Same helper, same name and same reason as in sbin/ru-routes.sh.
# `install -d -o root -g wheel` re-applies owner, group and mode to a directory
# that already exists, and one of the two calls this replaced was aimed at
# /var/run/gatebsd -- not this tool's private directory but the shared one
# holding the agent's unix socket. The web UI runs as the unprivileged service
# account and needs the group's traverse bit to reach that socket, so the
# nightly prefix update was enough to lock it out. Measured on the router on
# 3 August: the package restart at 02:39 left the directory group `gatebsd`,
# cron ran this script at 03:01, and from that minute every panel request
# answered 503 "agent unavailable" while the agent itself was healthy.
ensure_private_root_dir() {
    _dir=$1
    _group=${2:-wheel}
    if [ -e "$_dir" ] || [ -L "$_dir" ]; then
        [ -d "$_dir" ] && [ ! -L "$_dir" ] || die "unsafe directory: $_dir"
        _uid=$(stat -f '%u' "$_dir" 2>/dev/null || printf '%s' -1)
        _mode=$(stat -f '%Lp' "$_dir" 2>/dev/null || printf '%s' 777)
        [ "$_uid" = 0 ] || die "directory must be root-owned: $_dir"
        case "$_mode" in
            *[2367][0-7]|*[0-7][2367]) die "directory must not be group/world writable: $_dir" ;;
        esac
    else
        install -d -o root -g "$_group" -m 0750 "$_dir"
    fi
}

case "$MIN_PREFIXES:$MAX_BYTES" in *[!0-9:]*) die "invalid prefix or response-size limit" ;; esac
[ "$MIN_PREFIXES" -gt 0 ] || die "minimum prefix count must be positive"
[ "$MAX_BYTES" -ge 1024 ] || die "response-size limit is too small"
# Keep this floor in step with sbin/ru-routes.sh: a prefix the downloader
# accepts but the route applier rejects would fail every apply after publish.
MIN_PREFIX_LEN=${GATEBSD_RU_MIN_PREFIX_LEN:-8}
case "$MIN_PREFIX_LEN" in
    ''|*[!0-9]*) MIN_PREFIX_LEN=8 ;;
esac
[ "$MIN_PREFIX_LEN" -ge 1 ] && [ "$MIN_PREFIX_LEN" -le 32 ] || MIN_PREFIX_LEN=8
case "$URL" in https://*|http://*) ;; *) die "RU_TABLE_URL must use http or https" ;; esac
printf '%s\n' "$URL" | grep -Eq '^https?://[^[:space:]]+$' || die "RU_TABLE_URL contains whitespace or control characters"
[ -x "$PYTHON_LAUNCHER" ] || die "Python launcher is unavailable"
[ -x "$RU_ROUTES_HELPER" ] || die "RU route helper is unavailable"

if [ "${GATEBSD_RU_UPDATE_LOCK_HELD:-0}" != 1 ]; then
    ensure_private_root_dir "$(dirname "$LOCK_FILE")" "${GATEBSD_SERVICE_GROUP:-gatebsd}"
    exec env -i PATH="$PATH" GATEBSD_PATH="$PATH" HOME=/root LANG=C.UTF-8 \
        GATEBSD_RU_UPDATE_LOCK_HELD=1 \
        GATEBSD_GATEWAY_CONF="$CONF" RU_TABLE="$RU_TABLE" \
        GATEBSD_DIRECT_EXCEPTIONS="$DIRECT_EXCEPTIONS" \
        ${GATEBSD_VPN_OVERRIDE_TABLE:+GATEBSD_VPN_OVERRIDE_TABLE="$GATEBSD_VPN_OVERRIDE_TABLE"} \
        RU_TABLE_URL="$URL" RU_TABLE_MIN_PREFIXES="$MIN_PREFIXES" \
        RU_TABLE_MAX_BYTES="$MAX_BYTES" GATEBSD_RU_UPDATE_LOCK="$LOCK_FILE" \
        GATEBSD_PYTHON_LAUNCHER="$PYTHON_LAUNCHER" \
        GATEBSD_BACKEND="$BACKEND" \
        GATEBSD_RU_ROUTES_HELPER="$RU_ROUTES_HELPER" \
        lockf -t 5 "$LOCK_FILE" "$0" "$@"
fi

TABLE_DIR=$(dirname "$RU_TABLE")
ensure_private_root_dir "$TABLE_DIR" wheel
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/ru-bypass.XXXXXX") || die "cannot allocate work directory"
DOWNLOAD="$WORKDIR/download"
CANDIDATE="$WORKDIR/candidate"
PREVIOUS="$WORKDIR/previous"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT HUP INT TERM

_file_blocks=$(( (MAX_BYTES + 511) / 512 ))
if ! (ulimit -f "$_file_blocks" 2>/dev/null || true; fetch -q -T 30 -o "$DOWNLOAD" "$URL"); then
    die "download failed; existing table preserved"
fi
_size=$(stat -f '%z' "$DOWNLOAD" 2>/dev/null || printf '%s' 0)
[ "$_size" -gt 0 ] || die "downloaded table is empty"
[ "$_size" -le "$MAX_BYTES" ] || die "download exceeds $MAX_BYTES bytes"

: > "$CANDIDATE"
INVALID=0
while IFS= read -r prefix || [ -n "$prefix" ]; do
    prefix=$(printf '%s' "$prefix" | tr -d '\r' | awk '{$1=$1};1')
    case "$prefix" in ''|'#'*) continue ;; esac
    # Reject prefixes shorter than MIN_PREFIX_LEN. 0.0.0.0/0 is the default
    # route on FreeBSD, so a downloaded list containing it could hijack and then
    # withdraw the site's only default route.
    if printf '%s\n' "$prefix" | awk -F/ -v minlen="$MIN_PREFIX_LEN" '
        NF != 2 || $2 !~ /^[0-9]+$/ || $2 + 0 < minlen || $2 + 0 > 32 {exit 1}
        { n=split($1,o,"."); if(n!=4) exit 1; for(i=1;i<=4;i++) if(o[i] !~ /^[0-9]+$/ || o[i] < 0 || o[i] > 255) exit 1 }
    '; then
        printf '%s\n' "$prefix" >> "$CANDIDATE"
    else
        INVALID=$((INVALID + 1))
    fi
done < "$DOWNLOAD"
sort -u "$CANDIDATE" -o "$CANDIDATE"
[ "$INVALID" -eq 0 ] || die "download rejected: $INVALID invalid prefixes"
chmod 0600 "$CANDIDATE"
if [ -e "$DIRECT_EXCEPTIONS" ] || [ -L "$DIRECT_EXCEPTIONS" ]; then
    [ -f "$DIRECT_EXCEPTIONS" ] && [ ! -L "$DIRECT_EXCEPTIONS" ] || die "unsafe direct exceptions path"
fi
if [ -e "$RU_TABLE" ] || [ -L "$RU_TABLE" ]; then
    [ -f "$RU_TABLE" ] && [ ! -L "$RU_TABLE" ] || die "unsafe RU table path"
fi

: > "$PREVIOUS"
chmod 0600 "$PREVIOUS"
PUBLISH_OUTPUT=$(env PYTHONPATH="$BACKEND" \
    GATEBSD_RU_TABLE="$RU_TABLE" \
    GATEBSD_DIRECT_EXCEPTIONS="$DIRECT_EXCEPTIONS" \
    ${GATEBSD_VPN_OVERRIDE_TABLE:+GATEBSD_VPN_OVERRIDE_TABLE="$GATEBSD_VPN_OVERRIDE_TABLE"} \
    "$PYTHON_LAUNCHER" -m gatebsd_ui.vpn_policy merge \
    --candidate "$CANDIDATE" \
    --min-prefixes "$MIN_PREFIXES" \
    --backup "$PREVIOUS") \
    || die "failed to merge and publish validated table"
COUNT=$(printf '%s\n' "$PUBLISH_OUTPUT" | sed -n 's/^count=//p')
NEW_SHA=$(printf '%s\n' "$PUBLISH_OUTPUT" | sed -n 's/^new_sha256=//p')
[ -n "$COUNT" ] || die "publisher did not return a prefix count"
[ -n "$NEW_SHA" ] || die "publisher did not return a table digest"
log "installed $COUNT prefixes"

watchdog_pid=
if [ -r /var/run/gatebsd/watchdog.pid ] && [ -f /var/run/gatebsd/watchdog.pid ] && [ ! -L /var/run/gatebsd/watchdog.pid ]; then
    watchdog_pid=$(cat /var/run/gatebsd/watchdog.pid 2>/dev/null || true)
fi
if [ -n "$watchdog_pid" ] && kill -0 "$watchdog_pid" 2>/dev/null; then
    log "watchdog will converge the new route table"
else
    if ! RU_TABLE="$RU_TABLE" "$RU_ROUTES_HELPER" apply; then
        log "route application failed; restoring previous published table"
        env PYTHONPATH="$BACKEND" \
            "$PYTHON_LAUNCHER" -m gatebsd_ui.ru_table "$RU_TABLE" "$PREVIOUS" --expected-sha256 "$NEW_SHA" >/dev/null \
            || die "route apply failed and table rollback was refused because the table changed concurrently"
        die "route application failed; previous table restored"
    fi
fi
