#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || exit 77
conf=/usr/local/etc/nginx/conf.d/freebsd-mirror.conf
timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
tmp=$(mktemp /tmp/freebsd-mirror.conf.XXXXXX)
trap 'rm -f "${tmp}"' EXIT HUP INT TERM

if grep -q 'location /pub/FreeBSD/' "${conf}"; then
    cp "${conf}" "${tmp}"
else
    awk '
        /# ===== Mirror Status =====/ {
            print "    # ===== Full FreeBSD 15.1 amd64 mirror ====="
            print "    location /pub/FreeBSD/ {"
            print "        alias /tank/mirror/pub/current/FreeBSD/;"
            print "        autoindex on;"
            print "        autoindex_exact_size off;"
            print "        autoindex_localtime on;"
            print "        sendfile on;"
            print "        tcp_nopush on;"
            print "        limit_except GET HEAD { deny all; }"
            print "    }"
            print ""
        }
        { print }
    ' "${conf}" >"${tmp}"
fi

cp -p "${conf}" "${conf}.before-full-amd64-${timestamp}"
install -o root -g wheel -m 0644 "${tmp}" "${conf}"
nginx -t
service nginx reload
