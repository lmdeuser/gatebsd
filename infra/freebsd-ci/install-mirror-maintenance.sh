#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || {
    echo "run as root" >&2
    exit 77
}

src_dir=${1:-.}

install -o root -g wheel -m 0750 "${src_dir}/mirror-publish-http.sh" /usr/local/sbin/mirror-publish-http
install -o root -g wheel -m 0750 "${src_dir}/mirror-publish-release.sh" /usr/local/sbin/mirror-publish-release
install -o root -g wheel -m 0750 "${src_dir}/mirror-health-check.sh" /usr/local/sbin/mirror-health-check
install -o root -g wheel -m 0750 "${src_dir}/mirror-status-update.sh" /usr/local/sbin/mirror-status-update
install -o root -g wheel -m 0750 "${src_dir}/mirror-sync-freebsd-15-amd64.sh" /usr/local/sbin/mirror-sync-freebsd-15-amd64
install -o root -g wheel -m 0644 "${src_dir}/freebsd-mirror.cron" /usr/local/etc/cron.d/freebsd-local-repo

# Carry off the older generations of everything just written. This matters most
# for the crontab: cron(8) reads every file in cron.d whatever it is named, so
# `freebsd-local-repo.before-mirror-fix-20260721-223439` was not a backup but a
# second live schedule -- and one such copy ran an unmanaged
# mirror-health-check-v2 that wrote the working checker's readiness flag.
#
# It works from deployment.manifest, so it also retires leftovers beside the CI
# files this script does not install. Same host, same mess; scoping it to this
# script's own files would leave half the directory as it was.
sh "${src_dir}/retire-leftovers.sh"

/usr/local/sbin/mirror-publish-http
/usr/local/sbin/mirror-publish-release
/usr/local/sbin/mirror-health-check
/usr/local/sbin/mirror-status-update

nginx -t
service nginx reload

echo "Local FreeBSD mirror maintenance installed"
