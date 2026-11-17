#!/bin/sh
# Verify and atomically publish the selected FreeBSD 15.1 release artifacts.
set -eu

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

[ "$(id -u)" -eq 0 ] || exit 77

version=15.1
arch=amd64
release_root=/tank/mirror/releases
stage="${release_root}/.staging/${version}/${arch}"
live="${release_root}/${version}/${arch}"
status_dir=/tank/mirror/status

[ -d "${stage}/iso" ] && [ ! -L "${stage}" ] && [ ! -L "${stage}/iso" ] || {
    [ -d "${live}/iso" ] && [ ! -L "${stage}" ] && exit 0
    echo "release staging directory is missing or unsafe: ${stage}" >&2
    exit 1
}
[ ! -e "${live}" ] && [ ! -L "${live}" ] || {
    echo "release is already published: ${live}" >&2
    exit 1
}

checksum_file="${stage}/iso/CHECKSUM.SHA256-FreeBSD-${version}-RELEASE-${arch}"
[ -s "${checksum_file}" ] && [ -f "${checksum_file}" ] && [ ! -L "${checksum_file}" ]

verify_file()
{
    file=$1
    expected=$(awk -v prefix="SHA256 (${file}) = " '
        index($0, prefix) == 1 {
            hash = substr($0, length(prefix) + 1)
            if (hash ~ /^[0-9a-f]{64}$/) { print hash; exit }
        }
    ' "${checksum_file}")
    [ -n "${expected}" ] || {
        echo "checksum entry is missing: ${file}" >&2
        exit 1
    }
    target_iso="${stage}/iso/${file}"
    [ -f "${target_iso}" ] && [ ! -L "${target_iso}" ] || {
        echo "release target is missing or symlinked: ${target_iso}" >&2
        exit 1
    }
    actual=$(sha256 -q "${target_iso}")
    [ "${actual}" = "${expected}" ] || {
        echo "checksum mismatch: ${file}" >&2
        exit 1
    }
    echo "verified: ${file}"
}

verify_file "FreeBSD-${version}-RELEASE-${arch}-disc1.iso.xz"
verify_file "FreeBSD-${version}-RELEASE-${arch}-memstick.img.xz"

mkdir -p "${release_root}/${version}" "${status_dir}"
chmod 0755 "${release_root}" "${release_root}/${version}"
mv "${stage}" "${live}"
chown -R root:wheel "${live}"
find "${live}" -type d -exec chmod 0755 {} +
find "${live}" -type f -exec chmod 0644 {} +

tmp="${status_dir}/release-${version}-${arch}.txt.tmp.$$"
{
    echo "LAST_PUBLISH_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "VERSION=${version}"
    echo "ARCH=${arch}"
    echo "SCOPE=disc1.iso.xz,memstick.img.xz"
    echo "SHA256_RESULT=PASSED"
    echo "STATUS=OK"
} >"${tmp}"
chmod 0644 "${tmp}"
mv "${tmp}" "${status_dir}/release-${version}-${arch}.txt"

echo "FreeBSD ${version} ${arch} release subset published"
