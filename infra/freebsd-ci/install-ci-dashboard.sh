#!/bin/sh
# Install the CI/CD dashboard generator, add it to cron, and publish its route
# in nginx so the dashboard becomes reachable at /ci/.
#
# Idempotent: re-running it updates the generator and template in place.
set -eu

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

[ "$(id -u)" -eq 0 ] || exit 77

src_dir=${1:-.}
[ -f "${src_dir}/ci-dashboard-update.sh" ] || {
    echo "ci-dashboard-update.sh not found in ${src_dir}" >&2
    exit 69
}
[ -f "${src_dir}/ci-dashboard.html" ] || {
    echo "ci-dashboard.html not found in ${src_dir}" >&2
    exit 69
}

conf=/usr/local/etc/nginx/conf.d/freebsd-mirror.conf
cron=/etc/cron.d/ci-dashboard
timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
tmp=$(mktemp /tmp/nginx-ci-dashboard.XXXXXX)
trap 'rm -f "${tmp}"' EXIT HUP INT TERM

# --- install generator and template ----------------------------------------

install -d -o root -g wheel -m 0755 /usr/local/sbin /usr/local/share/gatebsd-ci
install -o root -g wheel -m 0755 "${src_dir}/ci-dashboard-update.sh" \
    /usr/local/sbin/ci-dashboard-update
install -o root -g wheel -m 0644 "${src_dir}/ci-dashboard.html" \
    /usr/local/share/gatebsd-ci/ci-dashboard.html

# The dashboard writes to /tank/mirror/www/ci, so that must exist before the
# first run. The generator itself creates the output tree atomically, but the
# parent must already be there.
install -d -o root -g www -m 0755 /tank/mirror/www

# --- nginx route -----------------------------------------------------------

# The /ci/ route is anchored after /ci/artifacts/ so the dashboard's own /ci/
# does not shadow the narrower /ci/artifacts/ that was already there. Both can
# coexist: nginx matches the longest prefix first.

# Anchor the guard to the exact route. A plain `grep 'location /ci/'` also
# matches the pre-existing `location /ci/artifacts/`, so the installer would
# report the route as present and silently never insert it, leaving /ci/ a 404.
if grep -qE '^[[:space:]]*location /ci/ \{' "${conf}"; then
    echo "nginx: /ci/ route already present in ${conf}"
else
    awk '
        /^[[:space:]]*location \/ci\/artifacts\// {
            in_artifacts = 1
        }
        in_artifacts && /^[[:space:]]*}/ {
            print
            print ""
            print "    location = /ci {"
            print "        return 301 /ci/;"
            print "    }"
            print ""
            print "    # CI/CD dashboard: pipeline runs, jobs, logs, artifacts, releases"
            print "    #"
            print "    # The redirect is not cosmetic. `location /ci/` does not match a"
            print "    # request for /ci, and nginx only synthesises the trailing-slash"
            print "    # redirect automatically for `root`, not for `alias`. Without this"
            print "    # an operator typing the obvious URL gets a 404 from the catch-all."
            print "    location /ci/ {"
            print "        alias /tank/mirror/www/ci/;"
            print "        autoindex on;"
            print "        autoindex_exact_size off;"
            print "        autoindex_localtime on;"
            print "        index index.html;"
            print "        limit_except GET HEAD { deny all; }"
            print "    }"
            in_artifacts = 0
            inserted = 1
            next
        }
        { print }
        END { if (!inserted) exit 1 }
    ' "${conf}" >"${tmp}" || {
        echo 'Could not find /ci/artifacts/ block to anchor the /ci/ route.' >&2
        exit 1
    }

    grep -qE '^[[:space:]]*location /ci/ \{' "${tmp}" || {
        echo 'CI route was not inserted.' >&2
        exit 1
    }

    cp -p "${conf}" "${conf}.before-ci-dashboard-${timestamp}"
    install -o root -g wheel -m 0644 "${tmp}" "${conf}"
    nginx -t || {
        echo 'nginx rejected the new configuration; restoring the previous one.' >&2
        install -o root -g wheel -m 0644 \
            "${conf}.before-ci-dashboard-${timestamp}" "${conf}"
        exit 1
    }
    service nginx reload
    echo "nginx: /ci/ route installed"
fi

# --- cron ------------------------------------------------------------------

# Run every 3 minutes: frequent enough to feel current, infrequent enough that
# a stuck generator won't spawn 20 concurrent instances. The generator itself
# reads the DB read-only and renders into a staging tree before swapping it in,
# so overlapping runs would not corrupt the published dashboard -- but they
# would waste cycles and hold a SQLite read lock longer than necessary.

cat > "${cron}" <<'CRON'
# CI/CD dashboard refresh. Reads Forgejo's database (read-only) and publishes
# pipeline status, job logs, and release artifacts as static HTML.
SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin

*/3 * * * * root /usr/local/sbin/ci-dashboard-update >> /var/log/ci-dashboard.log 2>&1
CRON

chmod 0644 "${cron}"
echo "cron: dashboard refresh installed (every 3 minutes)"

# --- initial run -----------------------------------------------------------

# Generate the dashboard now so the route resolves immediately rather than
# serving a 404 until the first cron tick.
echo "Running initial dashboard generation..."
/usr/local/sbin/ci-dashboard-update

echo "CI/CD dashboard installed: http://mirror.example.lan/ci/"
