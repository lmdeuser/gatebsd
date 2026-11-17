#!/bin/sh
# Rebuild the stand's local package repository from gatebsd-pkglist.
#
# Was a heredoc inside ci/host/configure_freebsd_mirror.sh, which is also where
# the package list came from. Neither file was in deployment.manifest, so
# nothing compared either one to this repository -- and the list on the stand
# had in fact been edited by hand. Both are managed now.
#
# Deliberately NOT scheduled. See freebsd-mirror.cron for why: `poudriere ports
# -u` moves the ports tree, so a nightly run of this would quietly change the
# toolchain underneath a release. An operator runs it when the package set is
# meant to move.
set -eu
export LC_ALL=C

# One at a time. A second run starting while the first is still building would
# have two poudriere bulk jobs writing one repository directory -- the same
# two-writers defect that corrupted the resolver's configuration on the router.
# -t 0 means fail immediately rather than queue: from cron a queued copy is
# indistinguishable from a stuck one.
if [ "${1:-}" != "_locked" ]; then
    exec lockf -t 0 /var/run/freebsd-local-repo.lock "$0" _locked
fi

poudriere ports -u -p default
poudriere jail -u -j freebsd_151_amd64

# -O gatebsd is load-bearing for the Python security-patch overlays below.
# Amnezia no longer uses this overlay: official amnezia-kmod 3.1 and
# amnezia-tools 3.1 carry the complete AWG 3.1 FreeBSD nvlist ABI.
#
# The flag cannot be moved into poudriere.conf: bulk.sh sources the config and
# then assigns OVERLAYS="" unconditionally, so a setting there is a silent
# no-op. See the comment on the same subject in infra/freebsd-ci/poudriere.conf.
poudriere bulk -j freebsd_151_amd64 -p default -O gatebsd \
    -f /usr/local/etc/poudriere.d/gatebsd-pkglist

if [ -d /tank/mirror/src.git ]; then
    git -C /tank/mirror/src.git remote update --prune
else
    git clone --mirror https://git.FreeBSD.org/src.git /tank/mirror/src.git
fi
