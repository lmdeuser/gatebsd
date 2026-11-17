#!/bin/sh
# Make poudriere's build UI at /poudriere/ actually show builds.
#
# The page loaded and stayed empty. poudriere's UI is static HTML whose
# JavaScript resolves its data *relative to itself* -- assets/poudriere.js sets
#
#     data_url = "data/"                                  (overview)
#     data_url = "data/<mastername>/"                     (jail)
#     data_url = "data/<mastername>/<buildname>/"          (build)
#
# and then fetches `data_url + ".data.json"`. Two things followed from that, and
# the deployed config got both wrong:
#
#   * the app sat at /poudriere/ and its data at /poudriere-data/, so every
#     fetch went to /poudriere/data/... -- a prefix that did not exist;
#   * the file it asks for begins with a dot, and the hardening rule
#
#         location ~ /\. { deny all; log_not_found off; }
#
#     answered 403 at either address. This is the same trap that hid the
#     package repository behind `.latest`.
#
# So 140 built packages had no build log anybody could read, and the UI reported
# no error -- an empty table looks like an idle builder.
#
# The dot here cannot be resolved server-side the way the repository route does
# it: the client is poudriere's own JavaScript and the name is hardcoded. `^~`
# takes this one subtree out of regex matching instead, and the guards that
# matter are restated inside it, so the deny rules keep applying everywhere else.
#
# Replaces the two old blocks rather than appending a third: this config is
# already an append log, and a second /poudriere/ location would be dead text
# that still has to be read by whoever debugs it next.
#
# Idempotent: re-running it changes nothing once the route is present.
set -eu

PATH=${GATEBSD_PATH:-/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin}
export PATH

DEPLOYED_CONF=/usr/local/etc/nginx/conf.d/freebsd-mirror.conf

conf=${GATEBSD_MIRROR_CONF:-$DEPLOYED_CONF}
html_root=${GATEBSD_POUDRIERE_HTML:-/usr/local/share/poudriere/html}
logs_root=${GATEBSD_POUDRIERE_LOGS:-/tank/packages/poudriere/data/logs/bulk}
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

if grep -q 'location \^~ /poudriere/data/ {' "${conf}"; then
    echo 'Poudriere web route is already installed.'
    exit 0
fi

tmp=$(mktemp "${TMPDIR:-/var/tmp}/freebsd-mirror.conf.XXXXXX")
trap 'rm -f "${tmp}"' EXIT HUP INT TERM

# Both old blocks are flat: `location ... {` at one indent, contents at the
# next, a closing brace alone on its own line. `limit_except ... { deny all; }`
# is balanced within its line, so waiting for a lone `}` is enough.
awk '
    /^[[:space:]]*#[[:space:]]*=+[[:space:]]*Poudriere Web UI/ { next }

    /^[[:space:]]*location \/poudriere(-data)?\/ \{/ {
        if (!inserted) {
            print "    # ===== Poudriere Web UI ====="
            print "    # The UI is static HTML; assets/poudriere.js resolves its data"
            print "    # relative to the page (\"data/\", \"data/<mastername>/\", ...) and fetches"
            print "    # \".data.json\" from there. The app and its data therefore share one"
            print "    # prefix, and the name it asks for begins with a dot."
            print "    #"
            print "    # Before this, the app was at /poudriere/ and the data at"
            print "    # /poudriere-data/, so the fetch went to a prefix that did not exist --"
            print "    # and where it did, the dotted-path deny above answered 403. The page"
            print "    # loaded, stayed empty and reported nothing."
            print "    location /poudriere/ {"
            print "        alias " html "/;"
            print "        index index.html;"
            print "        limit_except GET HEAD { deny all; }"
            print "    }"
            print ""
            print "    # `^~` stops nginx from testing the regex locations for this subtree,"
            print "    # which is the only way poudriere'"'"'s own dotted names can resolve. It"
            print "    # is scoped to this prefix; the deny rules keep covering the rest of"
            print "    # the server, and the ones that matter here are restated inside."
            print "    location ^~ /poudriere/data/ {"
            print "        alias " logs "/;"
            print "        autoindex on;"
            print "        autoindex_exact_size off;"
            print "        autoindex_localtime on;"
            print "        # `latest` is a symlink into a dated build directory."
            print "        disable_symlinks off;"
            print "        limit_except GET HEAD { deny all; }"
            print ""
            print "        # poudriere'"'"'s build-time state is not part of the published UI."
            print "        location ~ /\\.poudriere\\. { deny all; log_not_found off; }"
            print "        location ~ \\.(key|pem|crt|csr|p12|pfx|disabled|lock)$ { deny all; log_not_found off; }"
            print "    }"
            print ""
            print "    # The overview page links here relatively, but the tree lives in the"
            print "    # data directory."
            print "    location /poudriere/latest-per-pkg/ {"
            print "        rewrite ^/poudriere/latest-per-pkg/(.*)$ /poudriere/data/latest-per-pkg/$1 permanent;"
            print "    }"
            print ""
            print "    # The address the logs used to answer on, kept working."
            print "    location /poudriere-data/ {"
            print "        rewrite ^/poudriere-data/(.*)$ /poudriere/data/$1 permanent;"
            print "    }"
            inserted = 1
        }
        skipping = 1
        next
    }

    skipping {
        if ($0 ~ /^[[:space:]]*\}[[:space:]]*$/) { skipping = 0 }
        next
    }

    { print }
    END { if (!inserted) exit 1 }
' html="${html_root}" logs="${logs_root}" "${conf}" >"${tmp}" || {
    echo 'Could not find a /poudriere/ block to replace.' >&2
    exit 1
}

grep -q 'location \^~ /poudriere/data/ {' "${tmp}" || {
    echo 'Poudriere web route was not inserted.' >&2
    exit 1
}

# The old data block aliased the log tree; if a copy of it survived the rewrite
# there are now two answers for one prefix.
if grep -q '^[[:space:]]*location /poudriere-data/ {' "${tmp}" &&
   grep -q "alias ${logs_root}/;" "${tmp}" &&
   [ "$(grep -c "alias ${logs_root}/;" "${tmp}")" -ne 1 ]; then
    echo 'The previous /poudriere-data/ block was not replaced.' >&2
    exit 1
fi

backup="${conf}.before-poudriere-web-${timestamp}"
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

echo "Poudriere web UI route installed:"
echo "  http://mirror.example.lan/poudriere/"
