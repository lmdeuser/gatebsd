#!/bin/sh
# Build the immutable base snapshot that CI clones for each package build.
#
# The base must hold the packages the APPLIANCE runs, from the repository the
# appliance takes them from. Until 7 August it held neither: the jail resolved
# against pkg.FreeBSD.org quarterly while the router has upstream disabled and
# takes everything from this stand. Measured on the two machines the same day:
#
#   package        build jail (upstream)   appliance repository
#   amnezia-tools  1.0.20250903            3.0.20260805_1
#   amneziawg-go   0.2.16_7                3.0.20260805
#   nginx          1.30.4,3                1.30.3_3,3
#
# `ci/build.sh` reads each dependency's version off the package installed here,
# so a release declared versions of packages the appliance never sees. The
# published gatebsd-2.9.58 asks for nginx-1.30.4,3; this stand has 1.30.3_3,3
# and the router runs 1.30.3_3,3. It only ever worked because a declared
# dependency version is a floor rather than an equality.
#
# And the list of what to install is no longer written out here. It was the
# fourth copy of "what the appliance needs" -- beside build.sh's deps, the
# mirror's pkglist and EXPECTED_ORIGINS -- and copies drift in silence: releases
# 2.9.64, 2.9.65 and 2.9.66 all died on `Required package is not installed or
# lacks metadata: amneziawg-go`, three runs against a list that had simply not
# been updated. The pkglist is the declaration; this reads it.
set -eu

[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }

JAIL_NAME=freebsd_151_amd64
# The base this builds is NOT poudriere's build jail, and the difference is the
# whole point of the two datasets below.
#
# Until 27 August it was: this script installed the appliance's package set
# straight into /tank/packages/poudriere/jails/freebsd_151_amd64, which is the
# image poudriere clones every builder from. So every port poudriere built saw
# 73 packages that a clean base does not have -- among them perl5. While the
# ports tree wanted the same perl the jail happened to carry, nothing showed.
# When the tree moved from perl 5.42.2 to 5.42.3 on 26 August, the dependency
# `perl5>=5.42.r<5.43` was satisfied by the stale in-jail 5.42.2, poudriere
# never queued a rebuild, and five p5- ports died on
# `env: /usr/local/bin/perl5.42.3: No such file or directory` -- taking
# lang/go126, print/texinfo, dns/unbound, www/nginx and 40 more down as skipped,
# net/amnezia-tools and net/amneziawg-go included. A clean rebuild did not help,
# because the contamination was in the image rather than in the packages.
#
# poudriere's jail is therefore left pristine, and the CI base is a clone of it.
POUDRIERE_JAIL_DATASET=tank/packages/poudriere/jails/${JAIL_NAME}
POUDRIERE_JAIL_ROOT=/tank/packages/poudriere/jails/${JAIL_NAME}
PRISTINE_SNAPSHOT=${POUDRIERE_JAIL_DATASET}@gatebsd-pristine
JAIL_DATASET=tank/ci/base/${JAIL_NAME}
JAIL_ROOT=/tank/ci/base/${JAIL_NAME}
SNAPSHOT=${JAIL_DATASET}@gatebsd-ci-clean
PKGLIST=${GATEBSD_PKGLIST:-/usr/local/etc/poudriere.d/gatebsd-pkglist}
PUBKEY=${GATEBSD_PUBKEY:-/usr/local/etc/pkg/keys/gatebsd-stand.pub}
# The mirror tree is rooted at the project slug, not at this product's name.
# Default `gatebsd` keeps the URL identical to the one the appliance carries.
# `-` and not `:-`: an explicitly empty PROJECT_SLUG means a caller computed
# one and came back with nothing, and defaulting there would publish a second
# product under this one's root. Only an unset variable asks for the default.
PROJECT_SLUG=${PROJECT_SLUG-gatebsd}
case "$PROJECT_SLUG" in
    ''|*[!a-z0-9-]*)
        echo "PROJECT_SLUG must be non-empty and match [a-z0-9-]: $PROJECT_SLUG" >&2
        exit 2 ;;
esac
# The same URL the appliance is configured with, so the two resolve identically.
REPO_URL=${GATEBSD_REPO_URL:-http://mirror.example.lan/${PROJECT_SLUG}/packages/${JAIL_NAME}-default/latest}

# The source has to be pristine, and that is checked rather than assumed: a
# populated poudriere jail is exactly the defect this layout removes, and it is
# invisible until a ports tree moves underneath it months later.
installed=$(pkg -r "$POUDRIERE_JAIL_ROOT" info 2>/dev/null | wc -l | tr -d ' ')
if [ "${installed:-0}" -ne 0 ]; then
    echo "poudriere's build jail carries $installed installed packages." >&2
    echo "It must be a bare base system -- every builder is cloned from it." >&2
    echo "Recreate it: poudriere jail -d -j $JAIL_NAME && poudriere jail -c -j $JAIL_NAME -v 15.1-RELEASE -a amd64 -m ftp && poudriere jail -u -j $JAIL_NAME" >&2
    exit 2
fi

# Inputs are checked BEFORE anything is destroyed. They were checked after,
# and that ordering meant a missing pkglist -- or an unreachable repository, or
# a kill halfway through -- left the old base gone and the new one without its
# @gatebsd-ci-clean snapshot. The next CI build would then have nothing to
# clone from, and the cause would be a run that failed hours earlier.
[ -f "$PKGLIST" ] || { echo "package list not found: $PKGLIST" >&2; exit 2; }
[ -f "$PUBKEY" ] || { echo "repository key not found: $PUBKEY" >&2; exit 2; }

zfs list -H -o name tank/ci/base >/dev/null 2>&1 || zfs create -p tank/ci/base

# A build in flight is cloned from ${JAIL_DATASET}@gatebsd-ci-clean, and ZFS
# will not destroy a snapshot that a clone still depends on. Say so plainly:
# without this the destroy fails, `|| true` swallows it, and the run dies later
# on a confusing "dataset already exists".
if zfs list -H -o origin -r tank/ci 2>/dev/null | grep -q "^${JAIL_DATASET}@"; then
    echo "A build is using $JAIL_DATASET as its base; refusing to rebuild it." >&2
    echo "Wait for the build to finish, or remove its jail dataset first." >&2
    exit 3
fi

poudriere jail -u -j "$JAIL_NAME"
installed=$(pkg -r "$POUDRIERE_JAIL_ROOT" info 2>/dev/null | wc -l | tr -d ' ')
if [ "${installed:-0}" -ne 0 ]; then
    echo "poudriere's build jail carries $installed installed packages after update." >&2
    exit 2
fi

# The new base is built beside the old one and only takes its place once it is
# complete. Until the rename at the end, a failure leaves the working base
# exactly as it was.
STAGING_DATASET=${JAIL_DATASET}-new
STAGING_ROOT=${JAIL_ROOT}-new
# The previous base can still be a clone of the pristine snapshot. Keep that
# snapshot when it is busy, and make staging independent with send/receive:
# another clone would preserve the very origin dependency that the final swap
# has to remove. A fresh snapshot is created whenever the old one is unused.
zfs destroy -r "$STAGING_DATASET" >/dev/null 2>&1 || true
zfs destroy "$PRISTINE_SNAPSHOT" >/dev/null 2>&1 || true
zfs list -H "$PRISTINE_SNAPSHOT" >/dev/null 2>&1 || zfs snapshot "$PRISTINE_SNAPSHOT"
zfs send "$PRISTINE_SNAPSHOT" | zfs receive "$STAGING_DATASET"
zfs set mountpoint="$STAGING_ROOT" "$STAGING_DATASET"
JAIL_DATASET_FINAL=$JAIL_DATASET
JAIL_ROOT_FINAL=$JAIL_ROOT
JAIL_DATASET=$STAGING_DATASET
JAIL_ROOT=$STAGING_ROOT

DEVFS_MOUNTED=0
cleanup() {
    rc=$?
    trap - EXIT HUP INT TERM
    if [ "$DEVFS_MOUNTED" -eq 1 ]; then
        umount "$JAIL_ROOT/dev" 2>/dev/null || true
    fi
    # Never leave the resolver of a published base pointing at the build host.
    rm -f "$JAIL_ROOT/etc/resolv.conf"
    exit "$rc"
}
trap cleanup EXIT HUP INT TERM

# pkg needs /dev/null and /dev/random inside the chroot. Without devfs mounted,
# `pkg bootstrap` fails with "Cannot open dev/null" and then falls back to
# fetching from the network, which both defeats the local mirror and leaves the
# base without pkg installed.
mount -t devfs devfs "$JAIL_ROOT/dev"
DEVFS_MOUNTED=1

cp -p /etc/resolv.conf "$JAIL_ROOT/etc/resolv.conf"

# Upstream is disabled rather than left as a lower-priority fallback, the way
# the appliance has it: a fallback would silently reintroduce a package nobody
# here built, and the version stamped into the release would come from it.
mkdir -p "$JAIL_ROOT/usr/local/etc/pkg/repos" "$JAIL_ROOT/usr/local/etc/pkg/keys"
cp -p "$PUBKEY" "$JAIL_ROOT/usr/local/etc/pkg/keys/gatebsd-stand.pub"
cat > "$JAIL_ROOT/usr/local/etc/pkg/repos/gatebsd.conf" <<EOF
# Written by prepare-gatebsd-build-jail.sh. The build base takes its packages
# from the same repository as the appliance, and from nowhere else.
FreeBSD-ports: { enabled: no }
FreeBSD-ports-kmods: { enabled: no }
gatebsd-packages: {
    url: "$REPO_URL",
    mirror_type: "none",
    signature_type: "pubkey",
    pubkey: "/usr/local/etc/pkg/keys/gatebsd-stand.pub",
    enabled: yes
}
EOF

chroot "$JAIL_ROOT" env ASSUME_ALWAYS_YES=yes pkg bootstrap -f
chroot "$JAIL_ROOT" env ASSUME_ALWAYS_YES=yes pkg update -f

# Origins, straight out of the pkglist, flavours included -- `pkg install`
# accepts `databases/py-sqlite3@py312` as written there. Taking origins rather
# than package names is what keeps this from becoming another copy: the file
# poudriere builds from and the file this installs from are the same file.
ORIGINS=$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$PKGLIST" | awk '{ print $1 }')
[ -n "$ORIGINS" ] || { echo "package list is empty: $PKGLIST" >&2; exit 2; }
# shellcheck disable=SC2086
chroot "$JAIL_ROOT" env ASSUME_ALWAYS_YES=yes pkg install -y $ORIGINS

# No `python3` meta-package: the pkglist names lang/python312 outright, and
# ci/resolve-python.sh looks for versioned interpreters anyway -- it rejects a
# command that is not pythonX.Y. Pick the highest one present, the same way.
python_cmd=$(chroot "$JAIL_ROOT" sh -c 'ls /usr/local/bin/python3.* 2>/dev/null' \
    | sed -n 's/.*\/\(python3\.[0-9][0-9]*\)$/\1/p' | sort -t. -k2,2n | tail -1)
[ -n "$python_cmd" ] || { echo 'no versioned Python 3 in the base' >&2; exit 2; }
python_cmd=/usr/local/bin/$python_cmd

# Verify the runtime the built package will actually use, so a broken base is
# caught here rather than during a build. sqlite3 comes from the pkglist's
# databases/py-sqlite3@py312 and its flavour must match the interpreter above --
# if the pkglist moves to another Python, this import is what says so.
chroot "$JAIL_ROOT" "$python_cmd" -c 'import sqlite3, json, hashlib, ssl; print("runtime OK")'

umount "$JAIL_ROOT/dev"
DEVFS_MOUNTED=0
rm -f "$JAIL_ROOT/etc/resolv.conf"

# Snapshot the finished base, then swap it into place. The snapshot travels
# with the dataset through the rename, so what CI clones is what was verified
# above rather than something assembled afterwards.
zfs destroy "${JAIL_DATASET}@gatebsd-ci-clean" >/dev/null 2>&1 || true
zfs snapshot "${JAIL_DATASET}@gatebsd-ci-clean"
zfs destroy -r "$JAIL_DATASET_FINAL" >/dev/null 2>&1 || true
zfs rename "$JAIL_DATASET" "$JAIL_DATASET_FINAL"
zfs set mountpoint="$JAIL_ROOT_FINAL" "$JAIL_DATASET_FINAL"
zfs list -H -o name "$SNAPSHOT"
echo "Prepared immutable build base: $SNAPSHOT"
