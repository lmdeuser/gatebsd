#!/bin/sh
# Expose the poudriere package repository over HTTP at a dot-free URL.
#
# /gatebsd/packages/ already aliases the poudriere tree, but a pkg(8) client
# cannot use it: poudriere publishes each build into `.real_<epoch>` and points
# a `.latest` symlink at it, and both begin with a dot. The mirror config
# denies dotted paths --
#
#     location ~ /\. { deny all; log_not_found off; }
#
# -- so every catalogue fetch under .latest/ answered 403 Forbidden, and
# autoindex hid the directory besides. The repository built fine and was
# unreachable, which is why the router still points at upstream quarterly
# instead of at the stand.
#
# The dot is a poudriere implementation detail, not something a client should
# have to spell. This installs a regex location that accepts `latest` and
# resolves the dot server-side, so the request URI never contains one and the
# hardening rule keeps applying everywhere else:
#
#     http://mirror.example.lan/gatebsd/packages/freebsd_151_amd64-default/latest/
#
# Idempotent: re-running it changes nothing once the location is present.
set -eu

PATH=${GATEBSD_PATH:-/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin}
export PATH

DEPLOYED_CONF=/usr/local/etc/nginx/conf.d/freebsd-mirror.conf

conf=${GATEBSD_MIRROR_CONF:-$DEPLOYED_CONF}
# One stand serves more than one product, so the tree is rooted at the project
# slug instead of at this product's name. The default is `gatebsd`, so both the
# anchor this looks for and the location it writes come out exactly as the
# deployed config already has them.
# `-` and not `:-`: an explicitly empty PROJECT_SLUG means a caller computed
# one and came back with nothing, and defaulting there would publish a second
# product under this one's root. Only an unset variable asks for the default.
PROJECT_SLUG=${PROJECT_SLUG-gatebsd}
# The slug goes into an nginx regex location, so anything outside [a-z0-9-]
# would either change what that regex matches or make nginx reject the config
# after this script has already replaced it.
case "$PROJECT_SLUG" in
    ''|*[!a-z0-9-]*)
        echo "PROJECT_SLUG must be non-empty and match [a-z0-9-]: $PROJECT_SLUG" >&2
        exit 2 ;;
esac
packages_root=${GATEBSD_PACKAGES_ROOT:-/tank/packages/poudriere/data/packages}
conf_owner=${GATEBSD_CONF_OWNER:-root}
conf_group=${GATEBSD_CONF_GROUP:-wheel}
timestamp=$(date -u '+%Y%m%dT%H%M%SZ')

# Editing the deployed config needs root. A test pointing this at its own copy
# is not touching the stand, so it does not.
if [ "${conf}" = "${DEPLOYED_CONF}" ] && [ "$(id -u)" -ne 0 ]; then
    echo 'Installing the deployed route requires root.' >&2
    exit 77
fi

[ -f "${conf}" ] || { echo "nginx mirror config is missing: ${conf}" >&2; exit 69; }

# The prefix location this one completes, matched as a literal substring: it is
# both the anchor awk inserts after and, with `~ ^` in front, the marker that
# says the work is already done.
anchor="location /${PROJECT_SLUG}/packages/ {"
marker="location ~ ^/${PROJECT_SLUG}/packages/"

if grep -qF "${marker}" "${conf}"; then
    echo 'Poudriere repository route is already installed.'
    exit 0
fi

tmp=$(mktemp "${TMPDIR:-/var/tmp}/freebsd-mirror.conf.XXXXXX")
trap 'rm -f "${tmp}"' EXIT HUP INT TERM

# Anchor on the prefix location this one completes. nginx tries regex locations
# in order of appearance and the first match wins, but the dotted-path deny
# cannot match a URI that carries no dot, so placement only has to be readable.
#
# `([^/.][^/]*)` refuses a leading dot in the master name as well: the point of
# this route is to resolve one known dot server-side, not to reopen the hole
# the deny rule closes.
awk '
    index($0, anchor) && !inserted {
        print "    # ===== poudriere repository, addressed without poudriere'"'"'s dot ====="
        print "    # .latest/.real_<epoch> are denied by the dotted-path rule above and"
        print "    # hidden from autoindex, so a pkg(8) client is given `latest` instead"
        print "    # and the dot is resolved server-side."
        print "    " marker "([^/.][^/]*)/latest/(.*)$ {"
        print "        alias " root "/$1/.latest/$2;"
        print "        autoindex on;"
        print "        autoindex_exact_size off;"
        print "        autoindex_localtime on;"
        print "        # .latest is a symlink into .real_<epoch>."
        print "        disable_symlinks off;"
        print "        limit_except GET HEAD { deny all; }"
        print "    }"
        print ""
        inserted = 1
    }
    { print }
    END { if (!inserted) exit 1 }
' root="${packages_root}" anchor="${anchor}" marker="${marker}" "${conf}" >"${tmp}" || {
    echo "Could not find the /${PROJECT_SLUG}/packages/ block to anchor the repository route." >&2
    exit 1
}

grep -qF "${marker}" "${tmp}" || {
    echo 'Repository route was not inserted.' >&2
    exit 1
}

backup="${conf}.before-poudriere-route-${timestamp}"
cp -p "${conf}" "${backup}"
install -o "${conf_owner}" -g "${conf_group}" -m 0644 "${tmp}" "${conf}"
# Validate before reloading: a bad config would otherwise take the mirror, the
# package repository and the Forgejo web UI down together.
nginx -t || {
    echo 'nginx rejected the new configuration; restoring the previous one.' >&2
    install -o "${conf_owner}" -g "${conf_group}" -m 0644 "${backup}" "${conf}"
    exit 1
}
service nginx reload

echo "Poudriere repository route installed:"
echo "  http://mirror.example.lan/${PROJECT_SLUG}/packages/freebsd_151_amd64-default/latest/"
