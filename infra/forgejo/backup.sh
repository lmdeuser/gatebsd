#!/bin/sh
set -eu

DATASET=${FORGEJO_BACKUP_DATASET:-tank/forgejo}
BACKUP_ROOT=${FORGEJO_BACKUP_ROOT:-/tank/backups/forgejo}
LOCK_FILE=${FORGEJO_BACKUP_LOCK:-/var/run/forgejo-backup.lock}
MIN_FREE_KIB=${FORGEJO_BACKUP_MIN_FREE_KIB:-10485760}
KEEP=${FORGEJO_BACKUP_KEEP:-3}
SECRETS_PASSPHRASE_FILE=${FORGEJO_SECRETS_PASSPHRASE_FILE:-/root/.secrets/backup-passphrase}
SECRETS_PATHS=${FORGEJO_SECRETS_PATHS:-/usr/local/etc/forgejo/conf/app.ini /root/.secrets /usr/local/etc/step /usr/local/etc/pkg/keys /usr/local/etc/ssl/keys /usr/local/etc/ssl/n100-tls}

die() { echo "forgejo-backup: ERROR: $*" >&2; exit 1; }

checksum_file() {
    if command -v sha256 >/dev/null 2>&1; then
        sha256 "$1"
    else
        sha256sum "$1"
    fi
}

backup_encrypted_secrets() {
    if [ ! -f "$SECRETS_PASSPHRASE_FILE" ] || [ -L "$SECRETS_PASSPHRASE_FILE" ] || [ ! -s "$SECRETS_PASSPHRASE_FILE" ]; then
        echo "forgejo-backup: WARNING: secrets passphrase file missing or unsafe ($SECRETS_PASSPHRASE_FILE); skipping encrypted secrets archive" >&2
        return 0
    fi
    set --
    for _p in $SECRETS_PATHS; do
        [ -e "$_p" ] || continue
        set -- "$@" "${_p#/}"
    done
    [ "$#" -gt 0 ] || return 0

    secrets_enc="${BACKUP_ROOT}/stand-secrets-${timestamp}.tar.enc"
    _tar_rc_file="${BACKUP_ROOT}/.secrets-tar.$$.rc"
    (
        rc=0
        tar -cf - -C / "$@" || rc=$?
        printf '%s\n' "$rc" > "$_tar_rc_file"
    ) | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
        -pass "file:${SECRETS_PASSPHRASE_FILE}" -out "${secrets_enc}.tmp"
    _tar_rc=$(cat "$_tar_rc_file" 2>/dev/null || printf '1')
    rm -f "$_tar_rc_file"
    if [ "$_tar_rc" != "0" ]; then
        rm -f "${secrets_enc}.tmp"
        die "failed to archive host secrets (tar rc=${_tar_rc})"
    fi
    chown root:wheel "${secrets_enc}.tmp"
    chmod 0600 "${secrets_enc}.tmp"
    mv -f "${secrets_enc}.tmp" "$secrets_enc"
    checksum_file "$secrets_enc" > "${secrets_enc}.sha256"
    chmod 0600 "${secrets_enc}.sha256"
}

require_space() {
    _available=$(df -Pk "$1" | awk 'NR > 1 {value=$4} END {print value}')
    case "$_available" in ''|*[!0-9]*) die "cannot determine free space on $1" ;; esac
    [ "$_available" -ge $(($2 + MIN_FREE_KIB)) ] || \
        die "insufficient free space on $1: need $2 KiB plus $MIN_FREE_KIB KiB reserve, $_available KiB available"
}

[ "$(id -u)" -eq 0 ] || die 'Run as root'
case "$MIN_FREE_KIB:$KEEP" in ''|*[!0-9:]*|:*|*:) die "invalid backup space limits" ;; esac
[ "$KEEP" -ge 1 ] || die "backup retention must keep at least one copy"

if [ "${1:-}" != _locked ]; then
    exec lockf -t 0 "$LOCK_FILE" "$0" _locked
fi

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
snapshot="${DATASET}@backup-${timestamp}"
dump="${BACKUP_ROOT}/forgejo-${timestamp}.tar.zst"

if [ -e "$BACKUP_ROOT" ] || [ -L "$BACKUP_ROOT" ]; then
    [ -d "$BACKUP_ROOT" ] && [ ! -L "$BACKUP_ROOT" ] || die "unsafe backup root: $BACKUP_ROOT"
    chown root:git "$BACKUP_ROOT"
    chmod 0710 "$BACKUP_ROOT"
else
    install -d -o root -g git -m 0710 "$BACKUP_ROOT"
fi
REFERENCED_BYTES=$(zfs list -H -p -o refer "$DATASET") || die "cannot estimate Forgejo data size"
case "$REFERENCED_BYTES" in ''|*[!0-9]*) die "cannot parse Forgejo data size" ;; esac
REQUIRED_KIB=$(((REFERENCED_BYTES + 1023) / 1024))
require_space "$BACKUP_ROOT" "$REQUIRED_KIB"

stage_dir=
cleanup_stopped() {
    [ -z "$stage_dir" ] || rm -rf "$stage_dir"
    service forgejo start </dev/null >/dev/null 2>&1 || true
}
cleanup_stage() {
    [ -z "$stage_dir" ] || rm -rf "$stage_dir"
}

service forgejo stop
trap cleanup_stopped EXIT HUP INT TERM
zfs snapshot "$snapshot"
stage_dir=$(mktemp -d "${BACKUP_ROOT}/.forgejo-dump.XXXXXX")
chown git:git "$stage_dir"
chmod 0700 "$stage_dir"
stage_dump="${stage_dir}/forgejo-${timestamp}.tar.zst"
case "$stage_dump" in
    *[!A-Za-z0-9_./-]*) die "unsafe dump path: $stage_dump" ;;
esac
su -m git -c "/usr/local/sbin/forgejo --work-path /var/db/forgejo --config /usr/local/etc/forgejo/conf/app.ini dump --type tar.zst --file '$stage_dump' --tempdir /var/db/forgejo/tmp"
service forgejo start </dev/null >/dev/null 2>&1
trap cleanup_stage EXIT HUP INT TERM

[ -d "$stage_dir" ] && [ ! -L "$stage_dir" ] || die "unsafe Forgejo staging dir: $stage_dir"
chown root:wheel "$stage_dir"
chmod 0700 "$stage_dir"
[ -f "$stage_dump" ] && [ ! -L "$stage_dump" ] || die "missing Forgejo dump: $stage_dump"
_dump_links=$(stat -c '%h' "$stage_dump" 2>/dev/null || stat -f '%l' "$stage_dump" 2>/dev/null || printf 1)
case "$_dump_links" in ''|*[!0-9]*) _dump_links=1 ;; esac
[ "$_dump_links" -eq 1 ] || die "Forgejo dump has unexpected hardlinks: $stage_dump"
chown root:wheel "$stage_dump"
chmod 0600 "$stage_dump"
mv -f "$stage_dump" "$dump"
rmdir "$stage_dir"
stage_dir=
trap - EXIT HUP INT TERM

checksum_file "$dump" > "${dump}.sha256"
chmod 0600 "${dump}.sha256"
backup_encrypted_secrets

prune_prefix() {
    _pattern=$1
    _ext=$2
    find "$BACKUP_ROOT" -maxdepth 1 -type f -name "${_pattern}*.${_ext}" -print |
        sed 's|.*/||' |
        sort |
        awk -v keep="$KEEP" '{ files[NR] = $0 } END {
            for (i = 1; i <= NR - keep; i++) print files[i]
        }' |
        while IFS= read -r _old; do
            [ -n "$_old" ] || continue
            rm -f -- "${BACKUP_ROOT}/${_old}" "${BACKUP_ROOT}/${_old}.sha256"
        done
}

prune_prefix 'forgejo-' 'tar.zst'
prune_prefix 'stand-secrets-' 'tar.enc'
zfs list -H -t snapshot -o name -s creation -r "$DATASET" \
    | awk -v keep="$KEEP" '/@backup-/ {seen[++count]=$0} END {for (i=1; i<=count-keep; i++) print seen[i]}' \
    | while IFS= read -r old; do [ -z "$old" ] || zfs destroy "$old"; done

echo "$dump"
