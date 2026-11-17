#!/bin/sh
# End-to-end readiness check for the local FreeBSD CI mirror.
set -eu

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

# Roots are overridable so the regression harness can point the whole check at
# a fabricated mirror. Production passes nothing and gets the real paths.
mirror_root=${MIRROR_ROOT:-/tank/mirror}
status_dir="${mirror_root}/status"
base_url=${MIRROR_BASE_URL:-http://127.0.0.1}
ready=1
details="${status_dir}/health-detail.txt.tmp.$$"

mkdir -p "${status_dir}"
: >"${details}"

record()
{
    printf '%s=%s\n' "$1" "$2" >>"${details}"
}

check_git()
{
    name=$1
    branch=$2
    repo="${mirror_root}/git/freebsd-${name}.git"
    url="${base_url}/freebsd/git/${name}/"
    if [ -d "${repo}" ] &&
       git -C "${repo}" rev-parse --verify "refs/heads/${branch}" >/dev/null 2>&1 &&
       git ls-remote "${url}" "refs/heads/${branch}" 2>/dev/null |
           grep -q "refs/heads/${branch}"; then
        record "git_freebsd_${name}" "OK"
    else
        record "git_freebsd_${name}" "FAIL"
        ready=0
    fi
}

if pgrep -x nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
    record nginx OK
else
    record nginx FAIL
    ready=0
fi

if zpool status tank 2>/dev/null | grep -q 'state: ONLINE'; then
    record zfs OK
else
    record zfs FAIL
    ready=0
fi

check_git src main
check_git ports main
check_git doc main

release_base=${mirror_root}/releases/15.1/amd64/iso
if [ -s "${release_base}/FreeBSD-15.1-RELEASE-amd64-disc1.iso.xz" ] &&
   [ -s "${release_base}/FreeBSD-15.1-RELEASE-amd64-memstick.img.xz" ] &&
   [ -s ${mirror_root}/status/release-15.1-amd64.txt ]; then
    record releases OK
else
    record releases FAIL
    ready=0
fi

if find ${mirror_root}/distfiles -type f -size +0c -print -quit 2>/dev/null |
   grep -q .; then
    record distfiles OK
else
    record distfiles FAIL
    ready=0
fi

package_root=/tank/packages/poudriere/data/packages/freebsd_151_amd64-default
if [ -e "${package_root}/meta.conf" ] && [ -e "${package_root}/packagesite.pkg" ]; then
    record poudriere_packages OK
else
    record poudriere_packages FAIL
    ready=0
fi

# poudriere's build jail is the image every builder is cloned from, and it has
# to carry nothing at all.
#
# Until 27 August `prepare-gatebsd-build-jail.sh` installed the appliance's 73
# packages straight into it, perl5 among them. While the ports tree wanted the
# same perl the jail happened to hold, nothing showed. When the tree moved from
# 5.42.2 to 5.42.3 on 26 August the dependency `perl5>=5.42.r<5.43` was
# satisfied by the stale in-jail copy, poudriere never queued a rebuild, and
# five p5- ports died on `env: /usr/local/bin/perl5.42.3: No such file or
# directory` -- taking lang/go126, print/texinfo, dns/unbound, www/nginx and 40
# more down as skipped, net/amnezia-tools and net/amneziawg-go included. A clean
# rebuild did not help, because the contamination was in the image rather than
# in the packages.
#
# The separation was fixed the same day and nothing checked that it held, which
# is how it would quietly come back. A jail that is not pristine stops a
# release, because a release is exactly what it silently spoiled last time.
#
# Measured 2026-08-27 on the stand: against the pristine jail `pkg -r` exits 0
# and prints nothing, against the CI base it exits 0 and prints 73 names, and
# against a root that does not exist it exits 1. So an empty answer means empty
# and a refusal means the question could not be asked -- which is reported as
# unknown rather than as health.
pkg_cmd=${MIRROR_PKG:-pkg}
poudriere_jail=${MIRROR_POUDRIERE_JAIL:-/tank/packages/poudriere/jails/freebsd_151_amd64}
if jail_packages=$("${pkg_cmd}" -r "${poudriere_jail}" query '%n' 2>/dev/null); then
    installed=$(printf '%s' "${jail_packages}" | grep -c . || true)
    record poudriere_jail_packages "${installed}"
    if [ "${installed}" -eq 0 ]; then
        record poudriere_jail_pristine OK
    else
        record poudriere_jail_pristine CONTAMINATED
        ready=0
    fi
else
    record poudriere_jail_pristine UNKNOWN
fi

# Readiness depends only on the immutable 15.1-RELEASE tree that CI builds
# against. Snapshot trees track a moving branch and are retired upstream
# without notice, so their absence must not make the mirror unusable.
#
# It also depends only on what is *published*. The sync builds a new tree in
# versions/.staging and moves the `current` symlink in one step when it is
# complete, so a sync in flight leaves the served tree untouched -- yet
# readiness used to require STATUS=OK in the sync report, which is only true
# between runs. The nightly sync takes hours, so every push inside that window
# failed the release pipeline on "mirror: FAIL" while the mirror was serving
# perfectly well, and the message gave no hint that the cause was a refresh
# rather than a fault. Measured 2026-08-01: sync started 00:15, still running
# at 03:00, `current` intact the whole time, base.txz answering 206 over HTTP.
#
# The sync outcome is still worth seeing, so it is reported as its own field
# below -- visible, but not a reason to call a good mirror unusable.
full_status=${mirror_root}/status/freebsd-15-amd64-sync.txt
full_base=${mirror_root}/pub/current/FreeBSD
if [ -L "${mirror_root}/pub/current" ] &&
   [ -s "${full_base}/releases/amd64/amd64/15.1-RELEASE/base.txz" ] &&
   [ -s "${full_base}/releases/amd64/amd64/ISO-IMAGES/15.1/FreeBSD-15.1-RELEASE-amd64-disc1.iso" ] &&
   curl -fsS --range 0-0 -o /dev/null \
       "${base_url}/pub/FreeBSD/releases/amd64/amd64/15.1-RELEASE/base.txz"; then
    record freebsd_15_amd64_full OK
else
    record freebsd_15_amd64_full FAIL
    ready=0
fi

# Reported for visibility only; never gates readiness. A sync that is running,
# or one that failed, still leaves the previously published tree in place.
full_sync_state=$(sed -n 's/^STATUS=//p' "${full_status}" 2>/dev/null | sed -n '1p')
record freebsd_15_amd64_sync "${full_sync_state:-UNKNOWN}"

# Reported for visibility only; never gates readiness.
if [ -s "${full_base}/snapshots/amd64/amd64/15.1-STABLE/base.txz" ]; then
    record freebsd_15_amd64_snapshots OK
else
    record freebsd_15_amd64_snapshots ABSENT_UPSTREAM
fi

# Free space on the pool the mirror lives in.
#
# This is here because a full pool is the one failure that reports itself as
# somebody else's error. On 23 August 2026 tank reached 100%,
# `mirror-sync-freebsd-15-amd64` began exiting rc=1, and the release mirror
# stopped updating for four days while every check on this list stayed green --
# the published tree was still there and still served, it just never moved.
#
# Reported at 80% and failing at 90%, so the warning arrives while there is
# still room to act rather than after a sync has already died. The thresholds
# are overridable for the regression harness.
pool=${MIRROR_POOL:-tank}
# Overridable so the harness can point this at a stub: a guard that cannot be
# made to go red has not been shown to work, and zpool(8) does not exist on the
# machine the tests run on.
zpool_cmd=${MIRROR_ZPOOL:-zpool}
warn_at=${MIRROR_POOL_WARN:-80}
fail_at=${MIRROR_POOL_FAIL:-90}
capacity=$("${zpool_cmd}" list -H -o capacity "${pool}" 2>/dev/null | tr -d '% ')
case "${capacity}" in
    ''|*[!0-9]*)
        record pool_capacity UNKNOWN
        ;;
    *)
        record pool_capacity "${capacity}%"
        record pool_free "$("${zpool_cmd}" list -H -o free "${pool}" 2>/dev/null)"
        if [ "${capacity}" -ge "${fail_at}" ]; then
            record pool_space FULL
            ready=0
        elif [ "${capacity}" -ge "${warn_at}" ]; then
            record pool_space LOW
        else
            record pool_space OK
        fi
        ;;
esac

record checked_utc "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [ "${ready}" -eq 1 ]; then
    printf 'READY\n' >"${status_dir}/health-ready-ok.tmp.$$"
    chmod 0644 "${status_dir}/health-ready-ok.tmp.$$"
    mv "${status_dir}/health-ready-ok.tmp.$$" "${status_dir}/health-ready-ok"
    printf 'READY\n' >"${status_dir}/health-ready.txt.tmp.$$"
else
    rm -f "${status_dir}/health-ready-ok"
    printf 'NOT_READY\n' >"${status_dir}/health-ready.txt.tmp.$$"
fi

chmod 0644 "${details}" "${status_dir}/health-ready.txt.tmp.$$"
mv "${details}" "${status_dir}/health-detail.txt"
mv "${status_dir}/health-ready.txt.tmp.$$" "${status_dir}/health-ready.txt"

[ "${ready}" -eq 1 ]
