#!/bin/sh
# Verified atomic FreeBSD Git mirror synchronization for n100-BSD.
# Upstream fetch uses pinned anon-SSH. Each repository is updated in staging,
# verified, and only then atomically published.

set -eu

PATH=${MIRROR_SYNC_GIT_PATH:-/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin}
LC_ALL=C
TZ=Asia/Yekaterinburg
GIT_TERMINAL_PROMPT=0
export PATH LC_ALL TZ GIT_TERMINAL_PROMPT

EXPECTED_HOSTS=${EXPECTED_HOSTS:-'stand-bsd n100-BSD'}
GIT_ROOT='/tank/mirror/git'
STAGING_ROOT='/tank/mirror/git/.staging'
ROLLBACK_ROOT='/tank/mirror/git/.rollback'
# How many previous copies of each repository to keep for rollback.
#
# Nothing pruned these until 27 August 2026, and by then .rollback held 104
# copies going back to 19 July -- 180 GB, on a 596 GB pool. The pool filled,
# `mirror-sync-freebsd-15-amd64` began failing with rc=1, and the release
# mirror silently stopped updating for four days. Nothing said a word, because
# a full disk is not an error any single script reports.
#
# Two, not one: the newest is what a failed publication restores, and the one
# before it is what a bad-but-successful sync is rolled back to.
KEEP_ROLLBACKS=${KEEP_ROLLBACKS:-2}
# Validated, because 0 would make prune_rollbacks delete the copy it had just
# created -- the one a bad-but-successful sync is rolled back to. A pruner that
# can be told to keep nothing is a deleter.
case "${KEEP_ROLLBACKS}" in
    ''|*[!0-9]*) echo 'KEEP_ROLLBACKS must be a positive integer' >&2; exit 2 ;;
esac
[ "${KEEP_ROLLBACKS}" -ge 1 ] || { echo 'KEEP_ROLLBACKS must be >= 1' >&2; exit 2; }
STATUS_DIR='/tank/mirror/status'
LOG_DIR='/tank/mirror/log'
LOCK_ROOT='/tank/mirror/.locks'
LOCK_DIR='/tank/mirror/.locks/mirror-sync-git.lock'
LOG_FILE='/tank/mirror/log/mirror-sync-git.log'
KNOWN_HOSTS=${KNOWN_HOSTS:-/tank/mirror/status/git-FreeBSD-org-ed25519.known_hosts}

FETCH_ATTEMPTS=3
RETRY_DELAY=60
LS_REMOTE_TIMEOUT=300
UPDATE_TIMEOUT=7200
FSCK_TIMEOUT=14400
LOCK_HELD=0
RUN_ID=$(date -u '+%Y%m%dT%H%M%SZ')

GIT_SSH_COMMAND="/usr/bin/ssh -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile=${KNOWN_HOSTS} -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=20 -o ServerAliveInterval=30 -o ServerAliveCountMax=6"
export GIT_SSH_COMMAND

log()
{
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "${LOG_FILE}"
    logger -t mirror-sync-git -- "$*" 2>/dev/null || true
}

cleanup()
{
    rc=$?
    trap - EXIT HUP INT TERM
    if [ "${LOCK_HELD}" -eq 1 ]; then
        rm -rf "${LOCK_DIR}" 2>/dev/null || true
    fi
    log "sync process finished rc=${rc}"
    exit "${rc}"
}

valid_sha()
{
    value=$1
    case "${value}" in
        *[!0-9a-f]*|'') return 1 ;;
    esac
    [ "${#value}" -eq 40 ]
}

remote_sha()
{
    fetch_url=$1
    wanted_ref=$2
    output_file="${STATUS_DIR}/.ls-remote.$$.tmp"

    if ! timeout "${LS_REMOTE_TIMEOUT}" git ls-remote --heads \
        "${fetch_url}" "${wanted_ref}" >"${output_file}" 2>&1; then
        cat "${output_file}" >>"${LOG_FILE}" 2>/dev/null || true
        rm -f "${output_file}"
        return 1
    fi

    value=$(awk -v wanted="${wanted_ref}" '$2 == wanted {print $1; exit}' "${output_file}")
    rm -f "${output_file}"
    valid_sha "${value}" || return 1
    printf '%s\n' "${value}"
}

fetch_ref()
{
    repo_path=$1
    fetch_url=$2
    wanted_ref=$3
    repo_name=$4

    attempt=1
    while [ "${attempt}" -le "${FETCH_ATTEMPTS}" ]; do
        attempt_log="${STATUS_DIR}/.${repo_name}.fetch.$$.${attempt}.tmp"

        if timeout "${UPDATE_TIMEOUT}" \
            git -C "${repo_path}" \
                -c gc.auto=0 \
                -c fetch.writeCommitGraph=false \
                fetch --progress --no-tags --force \
                "${fetch_url}" "+${wanted_ref}:${wanted_ref}" \
                >"${attempt_log}" 2>&1; then
            cat "${attempt_log}" >>"${LOG_FILE}" 2>/dev/null || true
            rm -f "${attempt_log}"
            return 0
        else
            rc=$?
        fi

        cat "${attempt_log}" >>"${LOG_FILE}" 2>/dev/null || true
        rm -f "${attempt_log}"
        log "${repo_name}: fetch ${wanted_ref} attempt ${attempt}/${FETCH_ATTEMPTS} failed rc=${rc}"

        if [ "${attempt}" -lt "${FETCH_ATTEMPTS}" ]; then
            sleep "${RETRY_DELAY}"
        fi
        attempt=$((attempt + 1))
    done

    return 1
}

configure_refspecs()
{
    repo_path=$1
    shift

    git -C "${repo_path}" config --unset-all remote.origin.fetch >/dev/null 2>&1 || true
    for wanted_ref in "$@"; do
        git -C "${repo_path}" config --add remote.origin.fetch "+${wanted_ref}:${wanted_ref}"
    done
    git -C "${repo_path}" config --unset-all remote.origin.mirror >/dev/null 2>&1 || true
}

write_status()
{
    repo_name=$1
    repo_path=$2
    origin_url=$3
    scope=$4
    status_path="${STATUS_DIR}/git-freebsd-${repo_name}-sync.txt"
    status_tmp="${status_path}.tmp.$$"

    {
        printf 'LAST_SYNC_UTC=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'REPO=%s\n' "${origin_url}"
        printf 'PATH=%s\n' "${repo_path}"
        printf 'MIRROR_SCOPE=%s\n' "${scope}"
        printf 'HEAD_SYMBOLIC=refs/heads/main\n'
        printf 'BARE=true\n'
        printf 'SHALLOW=false\n'
        printf 'FSCK_RESULT=PASSED\n'
        printf 'SERVER_INFO=UPDATED\n'
        printf 'SYNC_MODE=STAGING_ATOMIC_PUBLISH\n'
        printf 'STATUS=OK\n'
    } >"${status_tmp}"

    chmod 0644 "${status_tmp}"
    mv "${status_tmp}" "${status_path}"
}

sync_repo()
{
    repo_name=$1
    origin_url=$2
    fetch_url=$3
    shift 3

    live_path="${GIT_ROOT}/freebsd-${repo_name}.git"
    stage_path="${STAGING_ROOT}/freebsd-${repo_name}.git.${RUN_ID}.$$"
    old_path="${ROLLBACK_ROOT}/freebsd-${repo_name}.git.pre-${RUN_ID}"
    scope=''

    [ -d "${live_path}" ] || {
        log "${repo_name}: live repository missing: ${live_path}"
        return 1
    }
    [ "$(git -C "${live_path}" rev-parse --is-bare-repository 2>/dev/null)" = 'true' ] || return 1
    [ "$(git -C "${live_path}" rev-parse --is-shallow-repository 2>/dev/null)" = 'false' ] || return 1
    [ "$(git -C "${live_path}" config --get remote.origin.url 2>/dev/null)" = "${origin_url}" ] || return 1
    [ ! -e "${stage_path}" ] || return 1
    [ ! -e "${old_path}" ] || return 1

    # A plain path, NOT file://. The URL form disables git's local-clone
    # optimisation and pulls the whole repository through the transport; the
    # path form hardlinks the object store when source and destination share a
    # filesystem, which here they do -- .staging lives inside GIT_ROOT.
    #
    # Measured on this stand, 27 August 2026, on the smallest of the three
    # mirrors (freebsd-doc.git):
    #
    #     file://      92 s, 356 MB of new data
    #     plain path    0 s, 0 bytes -- same inode, link count 2
    #
    # Nightly that was ~5.3 GB rewritten across the three repositories for
    # nothing. The first attempt to measure this cloned into /tank/var_tmp and
    # saw no hardlinks at all: that is a different ZFS dataset, and links do not
    # cross one. Measure where production works, not where it is convenient.
    #
    # Hardlinking is only unsafe if the source changes during the clone. It
    # cannot: this runs under the lock in LOCK_ROOT, and readers over HTTP only
    # read. If source and destination ever stop sharing a filesystem, git falls
    # back to copying on its own.
    log "${repo_name}: cloning current production into staging"
    timeout "${UPDATE_TIMEOUT}" git clone --mirror "${live_path}" "${stage_path}" >>"${LOG_FILE}" 2>&1 || return 1

    git -C "${stage_path}" remote set-url origin "${origin_url}" || return 1
    configure_refspecs "${stage_path}" "$@" || return 1

    for wanted_ref in "$@"; do
        fetch_ref "${stage_path}" "${fetch_url}" "${wanted_ref}" "${repo_name}" || return 1
        upstream_sha=$(remote_sha "${fetch_url}" "${wanted_ref}") || return 1
        local_sha=$(git -C "${stage_path}" rev-parse "${wanted_ref}") || return 1
        [ "${local_sha}" = "${upstream_sha}" ] || {
            log "${repo_name}: SHA mismatch for ${wanted_ref}: local=${local_sha} upstream=${upstream_sha}"
            return 1
        }
        if [ -z "${scope}" ]; then
            scope=${wanted_ref}
        else
            scope="${scope},${wanted_ref}"
        fi
    done

    git -C "${stage_path}" symbolic-ref HEAD refs/heads/main || return 1
    git -C "${stage_path}" update-server-info || return 1
    timeout "${FSCK_TIMEOUT}" git -C "${stage_path}" fsck --strict --no-dangling >>"${LOG_FILE}" 2>&1 || return 1

    log "${repo_name}: staging verified; publishing"
    mv "${live_path}" "${old_path}" || return 1
    if ! mv "${stage_path}" "${live_path}"; then
        mv "${old_path}" "${live_path}" 2>/dev/null || true
        log "${repo_name}: publication failed; previous production restored"
        return 1
    fi

    write_status "${repo_name}" "${live_path}" "${origin_url}" "${scope}"
    log "${repo_name}: atomic publication complete; scope=${scope}; rollback=${old_path}"
    prune_rollbacks "${repo_name}"
    return 0
}

# Keep the newest KEEP_ROLLBACKS copies of ONE repository and remove the rest.
#
# Per repository, not globally: the three are synchronised in one run but a
# global count would let a busy repository evict another's only rollback.
# Called after publication rather than before, so a run that fails to publish
# never widens the gap it might have to roll back through.
prune_rollbacks() {
    _repo=$1
    _kept=0
    for _old in $(ls -td "${ROLLBACK_ROOT}/freebsd-${_repo}.git."* 2>/dev/null); do
        _kept=$((_kept + 1))
        [ "${_kept}" -le "${KEEP_ROLLBACKS}" ] && continue
        rm -rf "${_old}" && log "${_repo}: pruned rollback $(basename "${_old}")"
    done
    return 0
}

[ "$(id -u)" -eq 0 ] || exit 77
_actual_host=$(hostname -s)
_host_ok=0
for _expected in ${EXPECTED_HOSTS}; do
    if [ "${_actual_host}" = "${_expected}" ]; then
        _host_ok=1
        break
    fi
done
[ "${_host_ok}" -eq 1 ] || exit 78
[ -f "${KNOWN_HOSTS}" ] || exit 79

mkdir -p "${STATUS_DIR}" "${LOG_DIR}" "${LOCK_ROOT}" "${STAGING_ROOT}" "${ROLLBACK_ROOT}"

# Staging directories belong to one run and are removed by cleanup(). One that
# outlives its run is the debris of a kill or a panic, and it is never claimed
# again -- the name carries the run id and the pid. Three of them, from 17 and
# 18 July, were still there on 27 August holding 1.2 GB.
find "${STAGING_ROOT}" -mindepth 1 -maxdepth 1 -type d -mtime +1 -exec rm -rf {} + 2>/dev/null || true
touch "${LOG_FILE}"
chmod 0644 "${LOG_FILE}"
trap cleanup EXIT HUP INT TERM

if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
    existing_pid=$(cat "${LOCK_DIR}/pid" 2>/dev/null || printf 'unknown')
    printf 'mirror-sync-git lock exists; pid=%s\n' "${existing_pid}" >&2
    exit 73
fi
printf '%s\n' "$$" >"${LOCK_DIR}/pid"
LOCK_HELD=1

sync_repo 'src' \
    'https://git.FreeBSD.org/src.git' \
    'ssh://anongit@git.FreeBSD.org/src.git' \
    'refs/heads/main' \
    'refs/heads/releng/15.1'

sync_repo 'ports' \
    'https://git.FreeBSD.org/ports.git' \
    'ssh://anongit@git.FreeBSD.org/ports.git' \
    'refs/heads/main' \
    'refs/heads/2026Q3' \
    'refs/heads/2026Q4'

sync_repo 'doc' \
    'https://git.FreeBSD.org/doc.git' \
    'ssh://anongit@git.FreeBSD.org/doc.git' \
    'refs/heads/main'

status_tmp="${STATUS_DIR}/git-sync-status.txt.tmp.$$"
{
    printf 'LAST_GIT_SYNC_UTC=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'GIT_SYNC_ERRORS=0\n'
    printf 'MIRROR_SCOPE_SRC=refs/heads/main,refs/heads/releng/15.1\n'
    printf 'MIRROR_SCOPE_PORTS=refs/heads/main,refs/heads/2026Q3,refs/heads/2026Q4\n'
    printf 'MIRROR_SCOPE_DOC=refs/heads/main\n'
    printf 'UPSTREAM_TRANSPORT=SSH_PINNED_ED25519\n'
    printf 'PUBLICATION_MODE=STAGING_ATOMIC_PUBLISH\n'
    printf 'STATUS=OK\n'
    printf 'FREEBSD_GIT_MIRRORS_VERIFIED_READY=YES\n'
} >"${status_tmp}"
chmod 0644 "${status_tmp}"
mv "${status_tmp}" "${STATUS_DIR}/git-sync-status.txt"

log 'all required FreeBSD Git refs synchronized and atomically published'
exit 0
