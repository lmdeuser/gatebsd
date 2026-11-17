#!/bin/sh
# Full FreeBSD 15.1 amd64 release and snapshot mirror with atomic publication.
set -eu

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

if [ "${1:-}" != _locked ]; then
    exec lockf -t 0 /var/run/freebsd-15-amd64-mirror.lock "$0" _locked
fi

[ "$(id -u)" -eq 0 ] || exit 77

upstream=rsync://ftp.de.FreeBSD.org/FreeBSD
root=/tank/mirror/pub
versions=${root}/versions
status_dir=/tank/mirror/status
run_id=$(date -u '+%Y%m%dT%H%M%SZ')
partial=${versions}/.staging
published=${versions}/${run_id}
log=/tank/mirror/log/freebsd-15-amd64-sync.log
skipped_paths=${status_dir}/.freebsd-15-amd64-skipped.$$
# Published versions are hardlink farms against the previous run, so each adds
# only its delta, but the count still has to be bounded.
keep_versions=${KEEP_VERSIONS:-4}
case "${keep_versions}" in
    ''|*[!0-9]*) echo 'KEEP_VERSIONS must be a positive integer' >&2; exit 2 ;;
esac
[ "${keep_versions}" -ge 1 ] || { echo 'KEEP_VERSIONS must be >= 1' >&2; exit 2; }

mkdir -p "${versions}" "${status_dir}" /tank/mirror/log
touch "${log}"
chmod 0644 "${log}"
: >"${skipped_paths}"

log_message()
{
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" |
        tee -a "${log}"
}

write_status()
{
    state=$1
    tmp="${status_dir}/freebsd-15-amd64-sync.txt.tmp.$$"
    {
        echo "UPDATED_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "STATUS=${state}"
        echo "UPSTREAM=${upstream}"
        echo "SCOPE=FreeBSD_15.1_amd64_release_and_stable_snapshots"
        if [ -s "${skipped_paths}" ]; then
            echo "SKIPPED_ABSENT_UPSTREAM=$(tr '\n' ',' <"${skipped_paths}" |
                sed 's/,$//')"
        fi
        [ "${state}" != OK ] || echo "PUBLISHED=${published}"
    } >"${tmp}"
    chmod 0644 "${tmp}"
    mv "${tmp}" "${status_dir}/freebsd-15-amd64-sync.txt"
}

cleanup()
{
    rc=$?
    trap - EXIT HUP INT TERM
    if [ "${rc}" -ne 0 ]; then
        write_status FAILED
        log_message "sync failed rc=${rc}; staging data retained for resume"
    fi
    rm -f "${skipped_paths}"
    exit "${rc}"
}
trap cleanup EXIT HUP INT TERM

write_status IN_PROGRESS
mkdir -p "${partial}/FreeBSD"

sync_path()
{
    path=$1
    destination="${partial}/FreeBSD/${path}"
    mkdir -p "${destination}"
    link_args=
    if [ -d "${root}/current/FreeBSD/${path}" ]; then
        link_args="--link-dest=${root}/current/FreeBSD/${path}"
    fi
    log_message "sync ${path}"
    # shellcheck disable=SC2086
    rsync -aH --safe-links --delete --delete-delay --partial --timeout=600 \
        ${link_args} "${upstream}/${path}/" "${destination}/" >>"${log}" 2>&1
}

# Snapshot trees follow a moving branch, so upstream retires them without
# notice: FreeBSD removed snapshots/amd64/amd64/15.1-STABLE once 15.1 stopped
# being the STABLE snapshot branch. Treating that as a hard error wedges the
# mirror, and therefore CI readiness, on an upstream decision we do not
# control. An absent optional path is recorded and skipped; a path that exists
# upstream but fails to transfer is still fatal. Release trees are immutable
# and stay mandatory.
sync_optional_path()
{
    path=$1
    if ! rsync --list-only --timeout=120 "${upstream}/${path}/" \
            >/dev/null 2>&1; then
        log_message "skip ${path}: absent upstream"
        printf '%s\n' "${path}" >>"${skipped_paths}"
        return 0
    fi
    sync_path "${path}"
}

sync_batch()
{
    mode=$1
    shift
    pids=
    failed=0
    for path in "$@"; do
        case "${mode}" in
            required) sync_path "${path}" & ;;
            optional) sync_optional_path "${path}" & ;;
            *) echo "sync_batch: unknown mode ${mode}" >&2; return 2 ;;
        esac
        pids="${pids} $!"
    done
    for pid in ${pids}; do
        wait "${pid}" || failed=1
    done
    [ "${failed}" -eq 0 ]
}

# Four independent rsync streams keep the WAN link busy without overloading
# the N100 or the public upstream.
sync_batch required \
    releases/amd64/amd64/15.1-RELEASE \
    releases/amd64/amd64/ISO-IMAGES/15.1 \
    releases/VM-IMAGES/15.1-RELEASE/amd64 \
    releases/CI-IMAGES/15.1-RELEASE/amd64

sync_batch required \
    releases/OCI-IMAGES/15.1-RELEASE/amd64 \
    releases/PKGBASE-REPOS/15.1-RELEASE/amd64

sync_batch optional \
    snapshots/amd64/amd64/15.1-STABLE \
    snapshots/amd64/amd64/ISO-IMAGES/15.1 \
    snapshots/VM-IMAGES/15.1-STABLE/amd64 \
    snapshots/CI-IMAGES/15.1-STABLE/amd64

sync_batch optional \
    snapshots/OCI-IMAGES/15.1-STABLE/amd64 \
    snapshots/PKGBASE-REPOS/15.1-STABLE/amd64

verify_manifest()
{
    manifest=$1
    [ -f "${manifest}" ] && [ ! -L "${manifest}" ] || {
        echo "unsafe manifest file: ${manifest}" >&2
        exit 1
    }
    directory=$(dirname "${manifest}")
    count=0
    entries=$(awk '/^SHA256 \(.+\) = [0-9a-f]{64}$/ {
        name=$0; sub(/^SHA256 \(/, "", name); sub(/\) = [0-9a-f]{64}$/, "", name)
        hash=$0; sub(/^.*\) = /, "", hash)
        print hash "|" name
    }' "${manifest}")
    printf '%s\n' "${entries}" | while IFS='|' read -r expected name; do
        [ -n "${name}" ] || continue
        case "${name}" in
            /*|*../*|..|*/..|*/*/*|*[[:cntrl:]]*)
                echo "unsafe manifest target name: ${name}" >&2
                exit 1
                ;;
        esac
        file="${directory}/${name}"
        [ -f "${file}" ] && [ ! -L "${file}" ] || {
            echo "missing or symlinked checksum target: ${file}" >&2
            exit 1
        }
        actual=$(sha256 -q "${file}")
        [ "${actual}" = "${expected}" ] || {
            echo "checksum mismatch: ${file}" >&2
            exit 1
        }
        count=$((count + 1))
    done
    [ -n "${entries}" ] || {
        echo "empty checksum manifest: ${manifest}" >&2
        exit 1
    }
}

log_message "verify SHA256 manifests"
find "${partial}/FreeBSD" -type f -name 'CHECKSUM.SHA256*' ! -name '*.asc' |
while IFS= read -r manifest; do
    verify_manifest "${manifest}"
done

# The release base system and installer image are what CI actually builds
# against, so they remain mandatory. Snapshot content is best-effort.
test -s "${partial}/FreeBSD/releases/amd64/amd64/15.1-RELEASE/base.txz"
test -s "${partial}/FreeBSD/releases/amd64/amd64/ISO-IMAGES/15.1/FreeBSD-15.1-RELEASE-amd64-disc1.iso"

find "${partial}" -type d -exec chmod 0755 {} +
find "${partial}" -type f -exec chmod 0644 {} +
chown -R root:wheel "${partial}"
mv "${partial}" "${published}"
ln -s "versions/${run_id}" "${root}/.current.${run_id}"
mv -fh "${root}/.current.${run_id}" "${root}/current"

write_status OK
log_message "published ${published}"

# Retire superseded versions oldest-first, never the live one. Run IDs are
# fixed-width UTC stamps, so a lexical sort is chronological.
current_target=$(readlink "${root}/current" || true)
current_id=${current_target#versions/}
ls "${versions}" 2>/dev/null |
    grep -E '^[0-9]{8}T[0-9]{6}Z$' |
    sort |
    awk -v keep="${keep_versions}" '{ ids[NR] = $0 } END {
        for (i = 1; i <= NR - keep; i++) print ids[i]
    }' |
while IFS= read -r stale; do
    [ -n "${stale}" ] || continue
    [ "${stale}" != "${current_id}" ] || continue
    log_message "prune ${versions}/${stale}"
    rm -rf "${versions}/${stale}"
done

trap - EXIT HUP INT TERM
exit 0
