#!/bin/sh
# One-shot poudriere bring-up for the stand: pool layout, signing key, ports
# tree, build jail, and the first bulk build of the appliance's package set.
#
# What it deliberately does NOT do is write any file that
# infra/freebsd-ci/deployment.manifest claims. It used to write four of them,
# and every one was a second writer of a file the manifest also owns. Three
# came out of heredocs:
#
#   /usr/local/etc/cron.d/freebsd-local-repo   the mirror schedule. The heredoc
#       carried a single 04:15 line, so a re-run would have replaced the FreeBSD
#       mirror sync, the health check, the status update and the TLS renewal
#       with it -- and cron would have picked that up silently, the way it does.
#
#   /usr/local/etc/poudriere.d/gatebsd-pkglist the appliance's package set. The
#       live copy had been edited by hand to lang/python312 and the two amnezia
#       ports the router's VPN runs on; the heredoc still said lang/python3 and
#       had never heard of amnezia. A re-run would have dropped the VPN's ports
#       from the built set.
#
#   /usr/local/sbin/update-freebsd-local-repo  the rebuild script that reads
#       that list.
#
# The fourth was not a heredoc, which is why it outlived them:
#
#   /usr/local/etc/poudriere.conf              rewritten key by key with awk,
#       eleven keys of it, behind a dated `cp -p` of the previous file. Editing
#       in place rather than overwriting is what made it look safe -- the nine
#       keys this script has never heard of did survive each run. What did not
#       survive is any way to say what the file is supposed to contain: the
#       repository's copy of it was in no manifest, so nothing compared them,
#       and it drifted into a version that had never been deployed anywhere.
#       The dated copies are still on the stand, three of them, from July.
#
# All four now live in infra/freebsd-ci/ and are deployed by
# install-ci-host.sh, which means verify-deployment.sh compares them to this
# repository and retire-leftovers.sh carries off the older copies. This script
# READS the package list and the poudriere configuration, and refuses to run
# without either.
#
# Order: install-ci-host.sh first, then this.
set -eu
export LC_ALL=C

[ "$(id -u)" -eq 0 ] || {
    echo "Run as root" >&2
    exit 1
}

JAIL_NAME="freebsd_151_amd64"
PORTS_NAME="default"
OVERLAY_NAME="gatebsd"

# Every absolute path this script touches hangs off these two. The test suite
# overrides them to run the script for real against a synthetic tree: a wiring
# test that reads a script for the absence of a heredoc passes just as happily
# with the heredoc present and unreachable.
LOCALBASE=${GATEBSD_LOCALBASE:-/usr/local}
TANK=${GATEBSD_TANK:-/tank}

CONF="$LOCALBASE/etc/poudriere.conf"
PKGLIST="$LOCALBASE/etc/poudriere.d/gatebsd-pkglist"
# No dash in the name: poudriere parses one as a SETNAME (-z).
OVERLAY_DIR="$LOCALBASE/share/gatebsd/ports-overlay"

# Deployed by install-ci-host.sh from infra/freebsd-ci/gatebsd-pkglist. Not
# generated here, and not defaulted to something plausible either: a bring-up
# that invents its own package set is how the set diverged in the first place.
[ -s "$PKGLIST" ] || {
    echo "$PKGLIST is missing or empty." >&2
    echo "It is deployed from the repository; run install-ci-host.sh first." >&2
    exit 1
}

# Read, never written. This script used to rewrite eleven keys here in place
# and keep a dated copy of the previous file beside the live one, which is how
# /usr/local/etc collected three poudriere.conf.before-local-repo-20260714-*
# generations. The same refusal as the package list above, for the same
# reason: a bring-up that repairs the configuration it finds is a second
# writer whose edit nobody sees until the next build behaves differently.
[ -s "$CONF" ] || {
    echo "$CONF is missing or empty." >&2
    echo "It is deployed from the repository; run install-ci-host.sh first." >&2
    exit 1
}

install -d -o root -g wheel -m 0755 "$LOCALBASE/etc/ssl/keys"
install -d -o root -g wheel -m 0755 "$LOCALBASE/etc/ssl/certs"
install -d -o root -g wheel -m 0755 "$TANK/mirror/distfiles"

if [ ! -s "$LOCALBASE/etc/ssl/keys/pkg.key" ]; then
    openssl genrsa -out "$LOCALBASE/etc/ssl/keys/pkg.key" 4096
    chmod 0600 "$LOCALBASE/etc/ssl/keys/pkg.key"
fi
openssl rsa -in "$LOCALBASE/etc/ssl/keys/pkg.key" -pubout \
    -out "$LOCALBASE/etc/ssl/certs/pkg.pub"
install -o root -g wheel -m 0644 "$LOCALBASE/etc/ssl/certs/pkg.pub" "$TANK/mirror/pkg.pub"

# The ports tree comes from the stand's own git mirror, not from
# git.FreeBSD.org. /tank/mirror/git holds bare mirrors of ports, src and doc,
# refreshed nightly by mirror-sync-git -- and until 27 August 2026 nothing read
# them. The only requests they ever served were 1704 probes from 127.0.0.1: the
# health check confirming the mirror was alive. A mirror whose sole consumer is
# its own health check is not a mirror.
#
# file:// and not http://: the HTTP locations serve directory listings, not a
# working git transport (see the comment in freebsd-mirror.conf). Locally that
# does not matter -- git clones a path directly, and faster.
PORTS_GIT_URL=${PORTS_GIT_URL:-file:///tank/mirror/git/freebsd-ports.git}
if ! poudriere ports -l -n | grep -qx "$PORTS_NAME"; then
    poudriere ports -c -p "$PORTS_NAME" -m git+file -U "$PORTS_GIT_URL"
else
    # An existing tree keeps its checkout; only where it fetches from moves.
    tree_path=$(poudriere ports -l | awk -v n="$PORTS_NAME" '$1 == n { print $NF }')
    if [ -n "$tree_path" ] && [ -d "$tree_path/.git" ]; then
        current=$(git -C "$tree_path" config --get remote.origin.url 2>/dev/null || true)
        [ "$current" = "$PORTS_GIT_URL" ] || \
            git -C "$tree_path" remote set-url origin "$PORTS_GIT_URL"
    fi
    poudriere ports -u -p "$PORTS_NAME"
fi

# The overlay holding the ports this project carries itself. Its content is
# deployed from the repository by install-ci-host.sh (see deployment.manifest);
# this only registers the directory with poudriere. Method 'null' means poudriere
# never updates it -- the repository does.
#
# Deliberately NOT expressed as OVERLAYS= in poudriere.conf: bulk.sh sources the
# config and then assigns OVERLAYS="" unconditionally, so a setting there builds
# the upstream version while looking configured. It has to be -O on every build
# command, which is why the flag appears at both invocations below.
if ! poudriere ports -l -n | grep -qx "$OVERLAY_NAME"; then
    poudriere ports -c -p "$OVERLAY_NAME" -m null -M "$OVERLAY_DIR" -f none
fi

if ! poudriere jail -l -n | grep -qx "$JAIL_NAME"; then
    poudriere jail -c -j "$JAIL_NAME" -v 15.1-RELEASE -a amd64 -m ftp
else
    poudriere jail -u -j "$JAIL_NAME"
fi

cat > "$TANK/mirror/GateBSD.conf.sample" <<'PKGCONF'
GateBSD-local: {
  url: "pkg+http://mirror.example.lan/packages/freebsd_151_amd64-default",
  enabled: yes,
  priority: 100,
  signature_type: "pubkey",
  pubkey: "/usr/local/etc/pkg/keys/gatebsd-local.pub"
}
PKGCONF
chmod 0644 "$TANK/mirror/GateBSD.conf.sample"

nginx -t
service nginx reload

poudriere bulk -j "$JAIL_NAME" -p "$PORTS_NAME" -O "$OVERLAY_NAME" -f "$PKGLIST"

echo "FreeBSD local package repository configured"
poudriere jail -l
poudriere ports -l
find "$TANK/packages/poudriere/data/packages/${JAIL_NAME}-${PORTS_NAME}" \
    -maxdepth 2 -type f -print | head -n 30
