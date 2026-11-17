#!/bin/sh
# Create one atomically published compressed ZFS stream without stopping services.
set -eu

PATH=${GATEBSD_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}
VERSION_FILE=${GATEBSD_VERSION_FILE:-/usr/local/share/gatebsd/VERSION}
BACKUP_DIR=${GATEBSD_IMAGE_BACKUP_DIR:-/var/backups/gatebsd-image}
DATASET=${GATEBSD_ROOT_DATASET:-zroot/ROOT/default}
LOCK_FILE=${GATEBSD_IMAGE_BACKUP_LOCK:-/var/run/gatebsd/image-backup.lock}
MIN_FREE_KIB=${GATEBSD_IMAGE_BACKUP_MIN_FREE_KIB:-10485760}
KEEP=${GATEBSD_IMAGE_BACKUP_KEEP:-1}

log() { printf '[gatebsd-backup] %s\n' "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

require_space() {
    _available=$(df -Pk "$1" | awk 'NR > 1 {value=$4} END {print value}')
    case "$_available" in ''|*[!0-9]*) die "cannot determine free space on $1" ;; esac
    [ "$_available" -ge $(($2 + MIN_FREE_KIB)) ] || \
        die "insufficient free space on $1: need $2 KiB plus $MIN_FREE_KIB KiB reserve, $_available KiB available"
}

prune_old_backups() {
    find "$BACKUP_DIR" -type f -name 'gatebsd-*.img.gz' -exec stat -f '%m %N' {} + \
        | sort -rn \
        | while read -r _mtime _path; do
            [ "$_path" != "$FINAL" ] || continue
            _count=$((${_count:-0} + 1))
            [ "$_count" -lt "$KEEP" ] || rm -f -- "$_path"
        done
}

safe_private_root() {
    _root=$1
    case "$_root" in
        /*) ;;
        *) return 1 ;;
    esac
    case "$_root" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/libexec|/media|/mnt|/proc|/rescue|/root|/sbin|/sys|/tmp|/usr|/usr/local|/var|/var/backups)
            return 1
            ;;
        *[!A-Za-z0-9_./-]*|*//*|*/../*|*/..|*/./*|*/.)
            return 1
            ;;
    esac
    return 0
}

# Create the shared runtime directory if it is missing, and otherwise leave its
# ownership alone.
#
# /var/run/gatebsd holds the agent's unix socket, and the web UI runs as the
# unprivileged service account, which needs the group's traverse bit to reach
# it. `install -d -o root -g wheel` re-applies owner, group and mode to a
# directory that already exists, so a single backup run was enough to make the
# panel answer 503 "agent unavailable" to everything. Validate what is there;
# never re-own it. Full account in sbin/ru-bypass-update.sh, where the same
# call took the router's panel down on 3 August.
ensure_runtime_dir() {
    _dir=$1
    if [ -e "$_dir" ] || [ -L "$_dir" ]; then
        [ -d "$_dir" ] && [ ! -L "$_dir" ] || die "unsafe runtime directory: $_dir"
        _dir_uid=$(stat -f '%u' "$_dir" 2>/dev/null || printf '%s' -1)
        _dir_mode=$(stat -f '%Lp' "$_dir" 2>/dev/null || printf '%s' 777)
        [ "$_dir_uid" = 0 ] || die "runtime directory must be root-owned: $_dir"
        case "$_dir_mode" in
            *[2367][0-7]|*[0-7][2367]) die "runtime directory must not be group/world writable: $_dir" ;;
        esac
    else
        install -d -o root -g "${GATEBSD_SERVICE_GROUP:-gatebsd}" -m 0750 "$_dir"
    fi
}
[ "$(id -u)" -eq 0 ] || die "run as root"
command -v zfs >/dev/null 2>&1 || die "zfs is required"
command -v gzip >/dev/null 2>&1 || die "gzip is required"
command -v zstreamdump >/dev/null 2>&1 || die "zstreamdump is required"
case "$MIN_FREE_KIB:$KEEP" in *[!0-9:]*|:*|*:) die "invalid backup space limits" ;; esac
[ "$KEEP" -ge 1 ] || die "image backup retention must keep at least one copy"

ensure_runtime_dir "$(dirname "$LOCK_FILE")"
if [ "${GATEBSD_IMAGE_BACKUP_LOCK_HELD:-0}" != 1 ]; then
    exec env -i PATH="$PATH" HOME=/root LANG=C.UTF-8 \
        GATEBSD_IMAGE_BACKUP_LOCK_HELD=1 \
        GATEBSD_PATH="$PATH" \
        GATEBSD_VERSION_FILE="$VERSION_FILE" \
        GATEBSD_IMAGE_BACKUP_DIR="$BACKUP_DIR" \
        GATEBSD_ROOT_DATASET="$DATASET" \
        GATEBSD_IMAGE_BACKUP_LOCK="$LOCK_FILE" \
        GATEBSD_IMAGE_BACKUP_MIN_FREE_KIB="$MIN_FREE_KIB" \
        GATEBSD_IMAGE_BACKUP_KEEP="$KEEP" \
        lockf -t 0 "$LOCK_FILE" "$0" "$@"
fi

VERSION=unknown
if [ -f "$VERSION_FILE" ] && [ ! -L "$VERSION_FILE" ]; then
    _version_size=$(stat -f '%z' "$VERSION_FILE" 2>/dev/null || printf '%s' 0)
    if [ "$_version_size" -gt 0 ] && [ "$_version_size" -le 128 ]; then
        _version_value=$(sed -n '1p' "$VERSION_FILE" | tr -d '\r\n')
        case "$_version_value" in ''|*[!A-Za-z0-9+_.-]*) ;; *) VERSION=$_version_value ;; esac
    fi
fi
case "$DATASET" in ''|*[!A-Za-z0-9_./:-]*|*@*) die "unsafe dataset name" ;; esac
safe_private_root "$BACKUP_DIR" || die "unsafe backup directory"
if [ -e "$BACKUP_DIR" ] || [ -L "$BACKUP_DIR" ]; then
    [ -d "$BACKUP_DIR" ] && [ ! -L "$BACKUP_DIR" ] || die "unsafe backup directory"
fi
install -d -o root -g wheel -m 0700 "$BACKUP_DIR"
zfs list -H "$DATASET" >/dev/null 2>&1 || die "dataset does not exist: $DATASET"

STAMP=$(date '+%Y%m%d-%H%M%S')
SNAP_NAME="gatebsd-${VERSION}-${STAMP}-$$"
SNAPSHOT="${DATASET}@${SNAP_NAME}"
FINAL="$BACKUP_DIR/gatebsd-${VERSION}-${STAMP}-$$.img.gz"
TMP="$BACKUP_DIR/.gatebsd-${VERSION}-${STAMP}.$$.tmp"
FIFO="$BACKUP_DIR/.gatebsd-${VERSION}-${STAMP}.$$.fifo"
VERIFY_FIFO="$BACKUP_DIR/.gatebsd-${VERSION}-${STAMP}.$$.verify.fifo"
[ ! -e "$FINAL" ] && [ ! -L "$FINAL" ] || die "backup destination already exists"
SNAP_CREATED=0
GZIP_PID=
cleanup() {
    [ -z "$GZIP_PID" ] || kill "$GZIP_PID" 2>/dev/null || true
    rm -f "$FIFO" "$VERIFY_FIFO" "$TMP"
    [ "$SNAP_CREATED" -eq 0 ] || zfs destroy "$SNAPSHOT" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

log "creating snapshot $SNAPSHOT"
zfs snapshot "$SNAPSHOT" || die "snapshot creation failed"
SNAP_CREATED=1
ESTIMATE=$(zfs send -nvP "$SNAPSHOT" 2>&1) || die "cannot estimate ZFS stream size"
ESTIMATED_BYTES=$(printf '%s\n' "$ESTIMATE" | awk '$1 == "size" {value=$2} END {print value}')
case "$ESTIMATED_BYTES" in ''|*[!0-9]*) die "cannot parse ZFS stream size estimate" ;; esac
REQUIRED_KIB=$(((ESTIMATED_BYTES + 1023) / 1024))
require_space "$BACKUP_DIR" "$REQUIRED_KIB"
mkfifo -m 0600 "$FIFO"
gzip -9 < "$FIFO" > "$TMP" &
GZIP_PID=$!
if zfs send "$SNAPSHOT" > "$FIFO"; then
    SEND_OK=1
else
    SEND_OK=0
fi
rm -f "$FIFO"
if wait "$GZIP_PID"; then
    GZIP_OK=1
else
    GZIP_OK=0
fi
GZIP_PID=
[ "$SEND_OK" -eq 1 ] && [ "$GZIP_OK" -eq 1 ] || die "ZFS stream export failed"
[ -s "$TMP" ] || die "backup output is empty"
gzip -t "$TMP" || die "compressed backup verification failed"
mkfifo -m 0600 "$VERIFY_FIFO"
zstreamdump < "$VERIFY_FIFO" >/dev/null 2>&1 &
VERIFY_PID=$!
VERIFY_GZIP_OK=0
gzip -dc "$TMP" > "$VERIFY_FIFO" && VERIFY_GZIP_OK=1 || true
rm -f "$VERIFY_FIFO"
VERIFY_DUMP_OK=0
wait "$VERIFY_PID" && VERIFY_DUMP_OK=1 || true
[ "$VERIFY_GZIP_OK" -eq 1 ] && [ "$VERIFY_DUMP_OK" -eq 1 ] || die "created backup is not a valid ZFS stream"
chmod 0600 "$TMP"
sync
mv "$TMP" "$FINAL"
sync
zfs destroy "$SNAPSHOT" || die "backup created but temporary snapshot cleanup failed"
SNAP_CREATED=0
prune_old_backups
trap - EXIT HUP INT TERM
log "backup created: $FINAL"
sha256 "$FINAL"
