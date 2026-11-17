#!/bin/sh
# Stamp the product version into the staged frontend.
#
# The browser is the last hop of delivery, and it was the one hop that never
# got the new release. index.html referenced its assets as `/app.js?v=2.4.1`
# with the version frozen as a literal, and nginx serves them
# `cache-control: public, immutable` -- which tells the browser never to
# revalidate. The URL never changed from release to release, so a browser that
# had once fetched app.js kept that copy for a week no matter how many packages
# were installed underneath it. A customer on 2.9.9 was running the 2.9.7
# frontend: a stale nav table against a newer API, raw view ids in place of
# titles, and `undefined.map` where a section had been added since.
#
# Both delivery paths call this -- the package build and `make install` -- so
# the image and a field upgrade land on the same asset URLs, which is the whole
# promise of the dual delivery model. With the version in the query string,
# `immutable` becomes correct rather than harmful.
#
# The repository copy carries a placeholder rather than a real version, so an
# unstamped file is detectably wrong instead of silently a year out of date.
set -eu

PLACEHOLDER='__GATEBSD_VERSION__'

usage() {
    echo "Usage: $0 <frontend-directory> [version]" >&2
    exit 2
}

[ $# -ge 1 ] || usage
DIR=$1
VERSION=${2:-}

if [ -z "$VERSION" ]; then
    _root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
    [ -f "$_root/VERSION" ] || { echo "stamp-frontend-version: no VERSION file at $_root" >&2; exit 1; }
    VERSION=$(sed -n '1p' "$_root/VERSION" | tr -d '[:space:]')
fi

# Digits, dots and the underscore the package revision uses (2.9.9_2). Anything
# else would end up inside a URL in the shipped HTML.
case "$VERSION" in
    ''|*[!0-9._]*) echo "stamp-frontend-version: refusing malformed version: $VERSION" >&2; exit 1 ;;
esac
[ -d "$DIR" ] || { echo "stamp-frontend-version: not a directory: $DIR" >&2; exit 1; }

_stamped=0
for _file in "$DIR"/*.html; do
    [ -f "$_file" ] || continue
    grep -q "$PLACEHOLDER" "$_file" || continue
    _tmp="$_file.stamp.$$"
    sed "s/$PLACEHOLDER/$VERSION/g" "$_file" > "$_tmp"
    # Write the content back over the original rather than renaming onto it.
    # The file keeps its own inode, owner and mode, so the staged tree is
    # installed exactly as the build laid it out -- and this needs no `stat`,
    # whose flags differ between the FreeBSD build host and the Linux test
    # container. `mv` plus a `stat`-derived chmod silently aborted the whole
    # script under `set -e` on Linux and shipped unstamped placeholders.
    cat "$_tmp" > "$_file"
    rm -f "$_tmp"
    _stamped=$((_stamped + 1))
done

[ "$_stamped" -gt 0 ] || {
    echo "stamp-frontend-version: no placeholder found in $DIR; refusing to ship unversioned assets" >&2
    exit 1
}
printf 'stamped %s file(s) with version %s\n' "$_stamped" "$VERSION"
