#!/bin/sh
# Restore a validated GateBSD ZFS stream onto one explicitly selected empty disk.
set -eu

PATH=${GATEBSD_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}
BACKUP_FILE=${BACKUP_FILE:-/mnt/usb/gatebsd-backup.img.gz}
CONFIG_BACKUP_FILE=${CONFIG_BACKUP_FILE:-}
MAX_CONFIG_ARCHIVE_BYTES=${GATEBSD_MAX_CONFIG_ARCHIVE_BYTES:-268435456}
MAX_CONFIG_EXPANDED_BYTES=${GATEBSD_MAX_CONFIG_EXPANDED_BYTES:-536870912}
MAX_CONFIG_ENTRIES=${GATEBSD_MAX_CONFIG_ENTRIES:-10000}
SWAP_SIZE=${SWAP_SIZE:-16G}
EFI_SIZE=${EFI_SIZE:-260M}

log() { printf '[OK] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
err() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || err "run as root"
[ -f "$BACKUP_FILE" ] && [ ! -L "$BACKUP_FILE" ] || err "backup must be a regular non-symlink file"
_backup_uid=$(stat -f '%u' "$BACKUP_FILE" 2>/dev/null || printf '%s' -1)
_backup_mode=$(stat -f '%Lp' "$BACKUP_FILE" 2>/dev/null || printf '%s' 777)
[ "$_backup_uid" = 0 ] || err "backup must be owned by root"
case "$_backup_mode" in *[2367][0-7]|*[0-7][2367]) err "backup must not be group/world writable" ;; esac
for _size in "$SWAP_SIZE" "$EFI_SIZE"; do
    printf '%s\n' "$_size" | awk '/^[0-9]+([KkMmGgTt])?$/ {ok=1} END {exit !ok}' \
        || err "invalid partition size: $_size"
done
case "$MAX_CONFIG_ARCHIVE_BYTES:$MAX_CONFIG_EXPANDED_BYTES:$MAX_CONFIG_ENTRIES" in
    *[!0-9:]*) err "invalid config archive limits" ;;
esac
VALIDATION_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gatebsd-restore-validate.XXXXXX") || err "cannot allocate validation directory"
validation_cleanup() { rm -rf "$VALIDATION_DIR"; }
trap validation_cleanup EXIT HUP INT TERM

validate_zfs_stream() {
    _stream=$1
    _fifo="$VALIDATION_DIR/zfs.fifo"
    rm -f "$_fifo"
    mkfifo -m 0600 "$_fifo" || return 1
    zstreamdump < "$_fifo" >/dev/null 2>&1 &
    _dump_pid=$!
    _gzip_ok=0
    gzip -dc "$_stream" > "$_fifo" && _gzip_ok=1 || true
    rm -f "$_fifo"
    _dump_ok=0
    wait "$_dump_pid" && _dump_ok=1 || true
    [ "$_gzip_ok" -eq 1 ] && [ "$_dump_ok" -eq 1 ]
}

log "Checking compressed ZFS stream before touching any disk"
gzip -t "$BACKUP_FILE" || err "backup gzip integrity check failed"
command -v zstreamdump >/dev/null 2>&1 || err "zstreamdump is required to validate the ZFS stream"
validate_zfs_stream "$BACKUP_FILE" || err "backup is not a valid ZFS stream"

validate_config_archive() {
    _archive=$1
    [ -f "$_archive" ] && [ ! -L "$_archive" ] || err "config backup must be a regular non-symlink file"
    _archive_size=$(stat -f '%z' "$_archive" 2>/dev/null || printf '%s' 0)
    [ "$_archive_size" -gt 0 ] && [ "$_archive_size" -le "$MAX_CONFIG_ARCHIVE_BYTES" ] \
        || err "config backup is outside the compressed size limit"
    gzip -t "$_archive" || err "config backup gzip integrity check failed"
    tar -tzf "$_archive" > "$VALIDATION_DIR/config.names" || err "config backup cannot be listed"
    while IFS= read -r _name; do
        _name=${_name#./}
        case "$_name" in
            ''|.|*/../*|../*|*/..|/*|*[!A-Za-z0-9_./@+-]*) err "unsafe path in config backup: $_name" ;;
            etc|etc/*|usr|usr/local|usr/local/etc|usr/local/etc/*|var|var/db|var/db/gatebsd|var/db/gatebsd/*) ;;
            *) err "path is outside the config restore allowlist: $_name" ;;
        esac
    done < "$VALIDATION_DIR/config.names"
    LC_ALL=C sort "$VALIDATION_DIR/config.names" | uniq -d > "$VALIDATION_DIR/config.duplicates"
    [ ! -s "$VALIDATION_DIR/config.duplicates" ] || err "config backup contains duplicate paths"
    tar -tvzf "$_archive" > "$VALIDATION_DIR/config.types" || err "config backup metadata cannot be read"
    while IFS= read -r _line; do
        case "$_line" in
            -*) ;;
            d*) ;;
            *) err "config backup contains links, devices, or another unsupported entry type" ;;
        esac
    done < "$VALIDATION_DIR/config.types"
    awk -v max_bytes="$MAX_CONFIG_EXPANDED_BYTES" -v max_entries="$MAX_CONFIG_ENTRIES" '
        {
            entries++
            if (entries > max_entries) exit 1
            if (substr($1,1,1) == "-") {
                if ($5 !~ /^[0-9]+$/) exit 1
                total += $5
                if (total > max_bytes) exit 1
            }
        }
    ' "$VALIDATION_DIR/config.types" || err "config backup exceeds expanded size or entry limits"
}

CONFIG_STAGE=
if [ -n "$CONFIG_BACKUP_FILE" ]; then
    [ -f "$CONFIG_BACKUP_FILE" ] && [ ! -L "$CONFIG_BACKUP_FILE" ] \
        || err "config backup must be a regular non-symlink file"
    CONFIG_COPY="$VALIDATION_DIR/config-backup.tar.gz"
    command -v sha256 >/dev/null 2>&1 || err "sha256 is required for immutable config staging"
    _config_digest=$(sha256 -q "$CONFIG_BACKUP_FILE") || err "cannot hash config backup"
    install -m 0600 "$CONFIG_BACKUP_FILE" "$CONFIG_COPY" || err "cannot make a private config backup copy"
    [ "$(sha256 -q "$CONFIG_COPY" 2>/dev/null || true)" = "$_config_digest" ] \
        || err "config backup changed while it was copied"
    validate_config_archive "$CONFIG_COPY"
    CONFIG_STAGE="$VALIDATION_DIR/config-stage"
    mkdir -m 0700 "$CONFIG_STAGE" || err "cannot allocate config staging directory"
    tar -xzpf "$CONFIG_COPY" --no-same-owner -C "$CONFIG_STAGE" \
        || err "cannot extract the validated config backup"
    if find "$CONFIG_STAGE" \( -type l -o -type b -o -type c -o -type p -o -type s \) -print -quit | grep -q .; then
        err "config archive produced an unsafe filesystem entry"
    fi
    if find "$CONFIG_STAGE" \( -type f -o -type d \) -perm -0022 -print -quit | grep -q .; then
        err "config archive contains a group/world-writable entry"
    fi
fi

AVAILABLE_DISKS=$(sysctl -n kern.disks 2>/dev/null) || err "cannot enumerate disks"
printf '%s\n' "=== GateBSD Restore ===" "Available disks:"
printf '%s\n' "$AVAILABLE_DISKS" | tr ' ' '\n'
printf 'Target disk (for example ada0): '
read -r TARGET_DISK
case "$TARGET_DISK" in
    ''|*[!A-Za-z0-9._-]*|[0-9.-]*) err "invalid target disk name" ;;
esac
printf '%s\n' "$AVAILABLE_DISKS" | tr ' ' '\n' | grep -Fqx "$TARGET_DISK" \
    || err "target is not present in kern.disks"
[ -c "/dev/$TARGET_DISK" ] || err "target /dev/$TARGET_DISK is not a character device"

# Never allow the running root pool, any mounted partition, or active swap.
if mount -p 2>/dev/null | awk -v dev="/dev/$TARGET_DISK" '$1 == dev || index($1, dev) == 1 {found=1} END{exit !found}'; then
    err "target disk or one of its partitions is mounted"
fi
if swapinfo -k 2>/dev/null | awk -v dev="/dev/$TARGET_DISK" 'NR>1 && ($1 == dev || index($1, dev) == 1) {found=1} END{exit !found}'; then
    err "target disk or one of its partitions is active swap"
fi
if zpool status -P 2>/dev/null | awk -v dev="/dev/$TARGET_DISK" '$1 == dev || index($1, dev) == 1 {found=1} END{exit !found}'; then
    err "target disk belongs to an imported ZFS pool"
fi
zpool list -H zroot >/dev/null 2>&1 && err "a zroot pool is already imported; export it before restore"

printf 'ALL DATA ON /dev/%s WILL BE DESTROYED. Type "ERASE %s": ' "$TARGET_DISK" "$TARGET_DISK"
read -r CONFIRM
[ "$CONFIRM" = "ERASE $TARGET_DISK" ] || err "cancelled"

POOL_CREATED=0
EFI_MOUNTED=0
ROOT_MOUNTED=0
cleanup() {
    [ "$EFI_MOUNTED" -eq 0 ] || umount /mnt/boot/efi 2>/dev/null || true
    [ "$ROOT_MOUNTED" -eq 0 ] || zfs unmount zroot/ROOT/default 2>/dev/null || true
    [ "$POOL_CREATED" -eq 0 ] || zpool export zroot 2>/dev/null || true
    rm -rf "$VALIDATION_DIR" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

log "Creating GPT layout"
gpart destroy -F "$TARGET_DISK" 2>/dev/null || true
gpart create -s gpt "$TARGET_DISK"
set -- $(gpart add -a 4k -t efi -s "$EFI_SIZE" "$TARGET_DISK")
EFI_PART_NAME=$1
set -- $(gpart add -a 4k -t freebsd-swap -s "$SWAP_SIZE" "$TARGET_DISK")
SWAP_PART_NAME=$1
set -- $(gpart add -a 4k -t freebsd-zfs "$TARGET_DISK")
ZFS_PART_NAME=$1
case "$EFI_PART_NAME:$SWAP_PART_NAME:$ZFS_PART_NAME" in *[!A-Za-z0-9._:-]*) err "gpart returned unsafe partition names" ;; esac
EFIPART="/dev/$EFI_PART_NAME"
SWAPPART="/dev/$SWAP_PART_NAME"
ZFSPART="/dev/$ZFS_PART_NAME"
for _part in "$EFIPART" "$SWAPPART" "$ZFSPART"; do [ -c "$_part" ] || err "partition was not created: $_part"; done
newfs_msdos -F 32 "$EFIPART"

log "Creating target ZFS pool"
zpool create -f \
    -o altroot=/mnt \
    -o cachefile=none \
    -o failmode=continue \
    -O compression=lz4 \
    -O atime=off \
    -O mountpoint=none \
    zroot "$ZFSPART"
POOL_CREATED=1
zfs create -o mountpoint=none zroot/ROOT

log "Receiving boot environment"
RECEIVE_FIFO="$VALIDATION_DIR/receive.fifo"
mkfifo -m 0600 "$RECEIVE_FIFO"
zfs receive -F zroot/ROOT/default < "$RECEIVE_FIFO" &
RECEIVE_PID=$!
RECEIVE_GZIP_OK=0
gzip -dc "$BACKUP_FILE" > "$RECEIVE_FIFO" && RECEIVE_GZIP_OK=1 || true
rm -f "$RECEIVE_FIFO"
RECEIVE_ZFS_OK=0
wait "$RECEIVE_PID" && RECEIVE_ZFS_OK=1 || true
[ "$RECEIVE_GZIP_OK" -eq 1 ] && [ "$RECEIVE_ZFS_OK" -eq 1 ] || err "failed to receive the validated ZFS stream"
zfs set mountpoint=/ zroot/ROOT/default
zfs set canmount=noauto zroot/ROOT/default
zpool set bootfs=zroot/ROOT/default zroot

create_dataset() {
    dataset=$1
    shift
    zfs list -H "$dataset" >/dev/null 2>&1 || zfs create "$@" "$dataset"
}

log "Creating standard FreeBSD datasets"
create_dataset zroot/home -o mountpoint=/home
create_dataset zroot/tmp -o mountpoint=/tmp -o setuid=off
create_dataset zroot/usr -o mountpoint=/usr -o canmount=off
create_dataset zroot/usr/ports -o setuid=off
create_dataset zroot/usr/src
create_dataset zroot/var -o mountpoint=/var -o canmount=off
create_dataset zroot/var/audit -o exec=off -o setuid=off
create_dataset zroot/var/crash -o exec=off -o setuid=off
create_dataset zroot/var/log -o exec=off -o setuid=off
create_dataset zroot/var/mail
create_dataset zroot/var/tmp -o exec=off -o setuid=off

zfs mount zroot/ROOT/default
ROOT_MOUNTED=1
mkdir -p /mnt/boot/efi /mnt/boot/zfs
mount_msdosfs "$EFIPART" /mnt/boot/efi
EFI_MOUNTED=1

log "Installing the restored FreeBSD loader"
[ -f /mnt/boot/loader.efi ] || err "restored system does not contain /boot/loader.efi"
mkdir -p /mnt/boot/efi/EFI/FreeBSD /mnt/boot/efi/EFI/BOOT
install -m 0644 /mnt/boot/loader.efi /mnt/boot/efi/EFI/FreeBSD/loader.efi
install -m 0644 /mnt/boot/loader.efi /mnt/boot/efi/EFI/BOOT/BOOTX64.efi
zpool set cachefile=/mnt/boot/zfs/zpool.cache zroot

cat > /mnt/etc/fstab <<EOF_FSTAB
# Device             Mountpoint  FStype  Options  Dump  Pass
$EFIPART              /boot/efi   msdosfs rw       0     0
$SWAPPART             none        swap    sw       0     0
EOF_FSTAB

if [ -n "$CONFIG_STAGE" ]; then
    log "Applying allowlisted configuration archive"

    safe_restore_parent() {
        _relative=$1
        _parent=${_relative%/*}
        [ "$_parent" != "$_relative" ] || _parent=
        _current=/mnt
        _old_ifs=$IFS
        IFS=/
        set -- $_parent
        IFS=$_old_ifs
        for _component in "$@"; do
            [ -n "$_component" ] || continue
            _current="$_current/$_component"
            if [ -e "$_current" ] || [ -L "$_current" ]; then
                [ -d "$_current" ] && [ ! -L "$_current" ] || err "unsafe restore parent: $_current"
            else
                mkdir -m 0755 "$_current" || err "cannot create restore parent: $_current"
            fi
        done
        printf '%s\n' "$_current"
    }

    find "$CONFIG_STAGE" -type d -print | LC_ALL=C sort > "$VALIDATION_DIR/config.dirs"
    while IFS= read -r _source; do
        [ "$_source" != "$CONFIG_STAGE" ] || continue
        _relative=${_source#"$CONFIG_STAGE"/}
        safe_restore_parent "$_relative" >/dev/null
        _destination="/mnt/$_relative"
        if [ -e "$_destination" ] || [ -L "$_destination" ]; then
            [ -d "$_destination" ] && [ ! -L "$_destination" ] || err "unsafe restore directory: $_destination"
        else
            _mode=$(stat -f '%Lp' "$_source" 2>/dev/null || printf '%s' 755)
            mkdir -m "$_mode" "$_destination" || err "cannot create restore directory: $_destination"
        fi
    done < "$VALIDATION_DIR/config.dirs"

    find "$CONFIG_STAGE" -type f -print | LC_ALL=C sort > "$VALIDATION_DIR/config.files"
    while IFS= read -r _source; do
        _relative=${_source#"$CONFIG_STAGE"/}
        _parent=$(safe_restore_parent "$_relative")
        _destination="/mnt/$_relative"
        if [ -e "$_destination" ] || [ -L "$_destination" ]; then
            [ -f "$_destination" ] && [ ! -L "$_destination" ] || err "unsafe restore destination: $_destination"
        fi
        _mode=$(stat -f '%Lp' "$_source" 2>/dev/null || printf '%s' 600)
        _temporary=$(mktemp "$_parent/.gatebsd-restore.XXXXXX") || err "cannot create restore temporary file"
        if ! install -m "$_mode" "$_source" "$_temporary" || ! mv -f "$_temporary" "$_destination"; then
            rm -f "$_temporary"
            err "cannot publish restored configuration: $_relative"
        fi
    done < "$VALIDATION_DIR/config.files"

    [ ! -d /mnt/var/db/gatebsd ] || chown -R gatebsd:gatebsd /mnt/var/db/gatebsd 2>/dev/null || true
else
    warn "No CONFIG_BACKUP_FILE supplied; configuration from the ZFS image is used"
fi

sync
umount /mnt/boot/efi
EFI_MOUNTED=0
zfs unmount zroot/ROOT/default
ROOT_MOUNTED=0
zpool export zroot
POOL_CREATED=0
rm -rf "$VALIDATION_DIR"
trap - EXIT HUP INT TERM
log "Restore completed. Remove rescue media and boot from $TARGET_DISK"
