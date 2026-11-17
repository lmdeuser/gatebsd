#!/bin/sh
# Bare-metal bring-up for the stand: dataset layout, build jail, ports tree.
#
# Step 2 of the recovery order in ../README.md, and it no longer writes
# /usr/local/etc/poudriere.conf. It used to install this directory's
# poudriere.conf over the live one wholesale, behind a dated
# `cp -p ... .before-gatebsd-<timestamp>`, which made it the third writer of
# that file -- ci/host/configure_freebsd_mirror.sh rewrote eleven keys of it
# with awk, and a hand edit had added nine more that neither script knew about.
#
# The wholesale install was the dangerous one. Because nothing compared the
# repository's copy to the deployed file, that copy drifted into something
# that had never been on the machine: no PKG_REPO_SIGNING_KEY, no URL_BASE,
# none of the log or HTML paths. Running this during a recovery -- the one
# moment nobody is watching the build host closely -- would have replaced a
# working configuration with it and left the stand publishing an unsigned
# package repository. The router's pkg.conf asks for
# `signature_type: "pubkey"`, so the appliance would simply have stopped
# installing anything, and the trail back to a recovery step would be cold by
# the time anyone noticed.
#
# poudriere.conf is deployed from deployment.manifest by install-ci-host.sh
# now, and verify-deployment.sh compares it. This script reads it and refuses
# to run without it rather than falling back to installing one: a bring-up
# that supplies its own configuration when it cannot find the managed one is
# the same second writer, just later.
#
# Order: install-ci-host.sh first, then this, then
# ci/host/configure_freebsd_mirror.sh.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }

# The test suite overrides these to run this script for real against a
# synthetic tree. A wiring test that reads a script looking for the absence of
# an `install` line passes just as happily with the line present and sitting
# behind a condition that is never true.
LOCALBASE=${GATEBSD_LOCALBASE:-/usr/local}
TANK=${GATEBSD_TANK:-/tank}

POUDRIERE_CONF="$LOCALBASE/etc/poudriere.conf"

[ -s "$POUDRIERE_CONF" ] || {
    echo "$POUDRIERE_CONF is missing or empty." >&2
    echo "It is deployed from the repository; run install-ci-host.sh first." >&2
    exit 1
}

# The stand is a virtual machine, and both its pools live on virtual disks
# backed by the hypervisor's storage. Three settings follow from that and from
# nothing else -- on the physical N100 this replaced, none of them mattered.
#
#   atime=off    every read otherwise writes metadata, and inside a guest that
#                write is amplified the whole way down to the host's disk.
#
#   autotrim=on  freed blocks are handed back to the host, so a dynamically
#                expanding disk stops growing monotonically. Both pools said
#                "(untrimmed)" on 27 August 2026: 285 GB had been freed inside
#                the guest that day and the host still held every byte of it.
#
#   zpool trim   autotrim only covers blocks freed from now on. Everything
#                released before it was turned on needs one explicit pass, and
#                it is cheap: tank's 600 GB took 22 seconds, zroot's 48 GB
#                took 8.
#
# Both virtual disks report delete_method UNMAP, which is what makes any of
# this reach the host at all. On storage that does not, the trim is a no-op
# rather than a hazard.
for _pool in tank zroot; do
    zpool list -H -o name "$_pool" >/dev/null 2>&1 || continue
    zpool set autotrim=on "$_pool"
    zpool trim "$_pool" 2>/dev/null || true
done
# Set on the pool root, and inherited: a child with its own local atime keeps
# it, and the ones on this stand had exactly that.
zfs list -H -o name tank >/dev/null 2>&1 && {
    for _dataset in $(zfs list -H -o name -r tank); do
        zfs inherit atime "$_dataset" 2>/dev/null || true
    done
    zfs set atime=off tank
}

install -d -o root -g wheel -m 0755 "$TANK/mirror/distfiles"
install -d -o root -g wheel -m 0755 "$TANK/packages/poudriere/data/logs/bulk"
install -d -o root -g wheel -m 0755 "$TANK/packages/gatebsd-build"
install -d -o root -g operator -m 0750 "$TANK/ci"
install -d -o root -g operator -m 0750 "$TANK/ci/work" "$TANK/ci/logs"
install -d -o root -g www -m 0755 "$TANK/ci/artifacts"

poudriere jail -l -n | grep -qx freebsd_151_amd64 || {
    poudriere jail -c -j freebsd_151_amd64 -v 15.1-RELEASE -a amd64 -m ftp
}
poudriere ports -l -n | grep -qx default || {
    poudriere ports -c -p default -m git+https
}

echo "GateBSD FreeBSD CI base initialized"
poudriere jail -l
poudriere ports -l
