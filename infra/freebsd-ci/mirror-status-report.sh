#!/bin/sh
# Report the mirror's published readiness. Reads only; writes nothing.
#
# `ci-mirror-status` used to run a health check, and running one is not
# reporting one -- the checker writes /tank/mirror/status/health-ready-ok and
# health-ready.txt, so asking for the status decided it. That is how a stale
# generation of the checker, scheduled by a leftover cron file, could put the
# release-blocking verdict back at 05:15; and it is why an operation named
# "status" must not be able to.
#
# It could not work anyway. Over SSH the dispatcher runs as ci_deployer, uid
# 1002 group operator, and the checker is 0750 root:wheel -- no execute -- and
# /tank/mirror/status is root:www 0755 -- no write. The operation has been
# dead since it was written. The status files themselves are 0644, so reading
# them is exactly what that account can do.
#
# Staleness is reported, not hidden. A flag written a week ago is not a verdict
# about now, and answering READY from it is the same trap as a daemon serving
# configuration that the file underneath stopped agreeing with. The hourly job
# rewrites it at :45, so anything older than three hours means the checker
# itself has stopped.
#
# Exit status: 0 published READY and fresh, 1 NOT_READY or stale, 2 nothing to
# read.
set -eu

PATH=${GATEBSD_PATH:-/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin}
export PATH

status_dir=${MIRROR_STATUS_DIR:-/tank/mirror/status}
max_age=${MIRROR_STATUS_MAX_AGE:-10800}

ready_file="${status_dir}/health-ready.txt"
detail_file="${status_dir}/health-detail.txt"

# `awk` on a missing file exits 2, and 2>/dev/null hides the message but not
# the status -- under `set -e` that kills the script on the assignment itself.
# Test for readability first.
[ -r "${ready_file}" ] || {
    echo "No published mirror status: ${ready_file} is not readable" >&2
    exit 2
}

verdict=$(sed -n '1p' "${ready_file}")

echo "=== GateBSD mirror status (published, not recomputed) ==="
if [ -r "${detail_file}" ]; then
    cat "${detail_file}"
else
    echo "detail=UNAVAILABLE"
fi

# The checker records when it ran. Prefer that over the file's mtime: it is
# what the checker itself claims, and it survives a copy.
checked=''
if [ -r "${detail_file}" ]; then
    checked=$(sed -n 's/^checked_utc=//p' "${detail_file}" | sed -n '1p')
fi

age=''
if [ -n "${checked}" ]; then
    # BSD first, then GNU. On FreeBSD `date -d` is an illegal option, and on
    # GNU `date -j` is not a thing -- so the order matters and each branch has
    # to be allowed to fail without taking the script with it.
    checked_epoch=$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "${checked}" '+%s' 2>/dev/null) || checked_epoch=''
    if [ -z "${checked_epoch}" ]; then
        checked_epoch=$(date -u -d "${checked}" '+%s' 2>/dev/null) || checked_epoch=''
    fi
    if [ -n "${checked_epoch}" ]; then
        age=$(( $(date -u '+%s') - checked_epoch ))
    fi
fi

if [ -n "${age}" ]; then
    echo "age_seconds=${age}"
else
    echo "age_seconds=UNKNOWN"
fi
echo "verdict=${verdict}"

if [ -n "${age}" ] && [ "${age}" -gt "${max_age}" ]; then
    printf 'STALE: last checked %s seconds ago, limit %s. The hourly check has stopped.\n' \
        "${age}" "${max_age}" >&2
    exit 1
fi

[ "${verdict}" = "READY" ]
