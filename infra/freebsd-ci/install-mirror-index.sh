#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || {
    echo "run as root" >&2
    exit 77
}

src_dir=${1:-.}
conf=/usr/local/etc/nginx/conf.d/freebsd-mirror.conf
timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
tmp=$(mktemp /tmp/freebsd-mirror.conf.XXXXXX)
trap 'rm -f "${tmp}"' EXIT HUP INT TERM

install -d -o root -g wheel -m 0755 /tank/mirror/www
install -o root -g wheel -m 0644 "${src_dir}/mirror-index.html" \
    /tank/mirror/www/index.html

awk '
    /^[[:space:]]*location = \/ \{/ {
        print "    location = / {"
        print "        root /tank/mirror/www;"
        print "        index index.html;"
        print "        try_files /index.html =404;"
        print "        access_log off;"
        print "    }"
        replacing=1
        next
    }
    replacing && /^[[:space:]]*}/ { replacing=0; next }
    !replacing { print }
' "${conf}" >"${tmp}"

cp -p "${conf}" "${conf}.before-index-${timestamp}"
install -o root -g wheel -m 0644 "${tmp}" "${conf}"

nginx -t
service nginx reload
echo "Mirror landing page installed"
