#!/bin/sh
set -eu

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

status_dir=/tank/mirror/status
output="${status_dir}/mirror-status.txt"
tmp="${output}.tmp.$$"

mkdir -p "${status_dir}"

repo_line()
{
    name=$1
    repo="/tank/mirror/git/freebsd-${name}.git"
    if [ -d "${repo}" ]; then
        size=$(du -sh "${repo}" | cut -f1)
        head=$(git -C "${repo}" rev-parse --short refs/heads/main)
        echo "${name}: OK size=${size} main=${head}"
    else
        echo "${name}: MISSING"
    fi
}

{
    echo "=== Local FreeBSD CI Mirror ==="
    echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo
    echo "--- Readiness ---"
    cat "${status_dir}/health-ready.txt" 2>/dev/null || echo UNKNOWN
    echo
    echo "--- Git ---"
    repo_line src
    repo_line ports
    repo_line doc
    echo
    echo "--- Content ---"
    echo "releases: $(du -sh /tank/mirror/releases 2>/dev/null | cut -f1)"
    echo "distfiles: $(du -sh /tank/mirror/distfiles 2>/dev/null | cut -f1)"
    echo "poudriere packages: $(du -sh /tank/packages/poudriere/data/packages 2>/dev/null | cut -f1)"
    if [ -d /tank/mirror/pub/current/FreeBSD ]; then
        echo "FreeBSD 15.1 amd64 full mirror: $(du -shL /tank/mirror/pub/current/FreeBSD | cut -f1)"
    else
        echo "FreeBSD 15.1 amd64 full mirror: NOT_READY"
    fi
    echo
    echo "--- Storage ---"
    zfs list -H -o name,used,avail tank/mirror
    echo
    echo "--- Last Git sync ---"
    cat "${status_dir}/git-sync-status.txt" 2>/dev/null || echo UNKNOWN
} >"${tmp}"

chmod 0644 "${tmp}"
mv "${tmp}" "${output}"
