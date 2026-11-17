#!/bin/sh
# Prepare verified bare FreeBSD repositories for read-only dumb HTTP clones.
set -eu

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

[ "$(id -u)" -eq 0 ] || exit 77

git_root=/tank/mirror/git

for name in src ports doc; do
    repo="${git_root}/freebsd-${name}.git"
    [ -d "${repo}" ] || {
        echo "missing repository: ${repo}" >&2
        exit 1
    }
    [ "$(git -C "${repo}" rev-parse --is-bare-repository)" = true ]
    git -C "${repo}" update-server-info
    chgrp -R www "${repo}"
    find "${repo}" -type d -exec chmod 0750 {} +
    find "${repo}" -type f -exec chmod 0640 {} +
done

echo "FreeBSD Git mirrors published for read-only HTTP access"
