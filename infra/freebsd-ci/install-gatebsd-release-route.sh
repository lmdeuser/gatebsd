#!/bin/sh
# Publish the GateBSD release tree over HTTP at a stable, version-addressed URL.
#
# The CI pipeline used to advertise releases only as
# /ci/artifacts/<BUILD_ID>/, a path nobody could derive without reading the job
# log and which artifact retention reclaimed. gatebsd-ci-build now publishes to
# /tank/gatebsd/releases with `current` and `versions/<VERSION>` symlinks; this
# installer exposes that tree so a pkg(8) client can point at
#   http://mirror.example.lan/gatebsd/releases/versions/2.9.4/
# and keep working across later builds.
#
# Idempotent: re-running it changes nothing once the location is present.
set -eu

PATH=${GATEBSD_PATH:-/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin}
export PATH

DEPLOYED_CONF=/usr/local/etc/nginx/conf.d/freebsd-mirror.conf

conf=${GATEBSD_MIRROR_CONF:-$DEPLOYED_CONF}
conf_owner=${GATEBSD_CONF_OWNER:-root}
conf_group=${GATEBSD_CONF_GROUP:-wheel}
# Editing the deployed config needs root. A test pointing this at its own copy
# is not touching the stand, so it does not -- the same gate, and the same
# reasoning, as install-poudriere-repo-route.sh next to it.
if [ "${conf}" = "${DEPLOYED_CONF}" ] && [ "$(id -u)" -ne 0 ]; then
    exit 77
fi

# One stand serves more than one product, so the tree is rooted at the project
# slug instead of at this product's name. The default is `gatebsd`, so the
# location and the alias come out exactly as the deployed config already has
# them and a re-run stays the no-op it has always been.
# `-` and not `:-`: an explicitly empty PROJECT_SLUG means a caller computed
# one and came back with nothing, and defaulting there would publish a second
# product under this one's root. Only an unset variable asks for the default.
PROJECT_SLUG=${PROJECT_SLUG-gatebsd}
case "$PROJECT_SLUG" in
    ''|*[!a-z0-9-]*)
        echo "PROJECT_SLUG must be non-empty and match [a-z0-9-]: $PROJECT_SLUG" >&2
        exit 2 ;;
esac
tank_root=${GATEBSD_TANK_ROOT:-/tank}
release_root=${tank_root}/${PROJECT_SLUG}/releases
timestamp=$(date -u '+%Y%m%dT%H%M%SZ')

[ -f "${conf}" ] || { echo "nginx mirror config is missing: ${conf}" >&2; exit 69; }

# The build host creates these too, but the route must resolve even before the
# first release is published -- otherwise nginx serves a confusing 500 for a
# missing alias root rather than an empty index.
install -d -o "${conf_owner}" -g "${GATEBSD_TREE_GROUP:-www}" -m 0755 \
    "${tank_root}/${PROJECT_SLUG}" "${release_root}" \
    "${release_root}/builds" "${release_root}/versions"

location="/${PROJECT_SLUG}/releases/"

if grep -qF "location ${location}" "${conf}"; then
    echo 'GateBSD release route is already installed.'
    exit 0
fi

tmp=$(mktemp "${TMPDIR:-/var/tmp}/freebsd-mirror.conf.XXXXXX")
trap 'rm -f "${tmp}"' EXIT HUP INT TERM

# Anchor on the CI artifacts block, which every deployed copy of this config has.
awk -v location="${location}" -v root="${release_root}" '
    /# ===== CI Artifacts/ && !inserted {
        print "    # ===== GateBSD signed releases ====="
        print "    # Version-addressed and retained by version, unlike /ci/artifacts/."
        print "    location " location " {"
        print "        alias " root "/;"
        print "        autoindex on;"
        print "        autoindex_exact_size off;"
        print "        autoindex_localtime on;"
        print "        sendfile on;"
        print "        tcp_nopush on;"
        print "        # current and versions/<VERSION> are symlinks into builds/."
        print "        disable_symlinks off;"
        print "        limit_except GET HEAD { deny all; }"
        print "    }"
        print ""
        inserted = 1
    }
    { print }
    END { if (!inserted) exit 1 }
' "${conf}" >"${tmp}" || {
    echo 'Could not find the CI artifacts block to anchor the release route.' >&2
    exit 1
}

grep -qF "location ${location}" "${tmp}" || {
    echo 'Release route was not inserted.' >&2
    exit 1
}

cp -p "${conf}" "${conf}.before-releases-${timestamp}"
install -o "${conf_owner}" -g "${conf_group}" -m 0644 "${tmp}" "${conf}"
# Validate before reloading: a bad config would otherwise take the mirror, the
# package repository and the Forgejo web UI down together.
nginx -t || {
    echo 'nginx rejected the new configuration; restoring the previous one.' >&2
    install -o "${conf_owner}" -g "${conf_group}" -m 0644 "${conf}.before-releases-${timestamp}" "${conf}"
    exit 1
}
service nginx reload

echo "GateBSD release route installed: http://mirror.example.lan/${PROJECT_SLUG}/releases/current/"
