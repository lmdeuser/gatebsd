#!/bin/sh
# Install GateBSD's loader settings.
#
# One implementation for both delivery paths -- `make install-safe` and the
# package staging in ci/build.sh -- because the same fact written in two files
# is how this product has already lost a blocklist and a boot.
#
# The lua loader processes /boot/loader.conf.d/*.conf. Shipping a file there
# rather than editing /boot/loader.conf keeps the operator's file the
# operator's: two writers on one file is the recurring failure here.
set -eu

usage() {
    echo "usage: install-loader-conf.sh [-s source] <destination-directory>" >&2
    exit 2
}

src=""
while getopts s: opt; do
    case "$opt" in
        s) src=$OPTARG ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ "$#" -eq 1 ] || usage
dest=$1

if [ -z "$src" ]; then
    # Resolve relative to this script so the caller's working directory does
    # not decide which file gets shipped.
    src=$(dirname "$0")/../etc/loader.conf.d/gatebsd.conf
fi
[ -f "$src" ] || { echo "install-loader-conf: no such source: $src" >&2; exit 1; }

# /boot is shared with the base system and with boot environments. Following a
# symlink here would write outside the directory the caller named.
if [ -e "$dest" ] || [ -L "$dest" ]; then
    { [ -d "$dest" ] && [ ! -L "$dest" ]; } || {
        echo "install-loader-conf: unsafe loader config directory: $dest" >&2
        exit 1
    }
fi

install -d "$dest"
install -m 0644 "$src" "$dest/gatebsd.conf"
