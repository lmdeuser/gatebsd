#!/bin/sh
# Carry every leftover generation out of the live directories.
#
# /usr/local/sbin held five generations of the mirror health check, /usr/local/
# libexec three of the CI build script, and /usr/local/etc/cron.d two older
# copies of the mirror crontab -- one of which scheduled an unmanaged
# `mirror-health-check-v2` at 05:15 that wrote the same readiness flag as the
# working checker, and could therefore undo the mirror gate fix on any night it
# ran. cron(8) reads every file in that directory, so a leftover there is not
# clutter: it is a second live configuration.
#
# verify-deployment.sh has reported all of this for a while. Reporting was not
# enough -- the fourteen findings sat there until someone moved the files by
# hand, which is the step that does not happen. This is that step, and the
# installers call it.
#
# Moves, never copies, and never deletes. A copy beside the live file is what
# made the mess; a delete would make the one irreversible operation here the
# default. Everything lands under a dated directory outside every path that
# cron, rcorder or nginx reads, and the previous content is in git besides.
#
# And it never moves a file something still calls. `mirror-health-check-v2`
# looks exactly like an older generation of `mirror-health-check` and is not
# one: the CI dispatcher ran it for `ci-mirror-status`, so retiring it would
# have broken that operation on the first run of this script. A name is not
# evidence of what a file is -- check who calls it before carrying it off.
# That check covers the managed scripts and the cron files, which is where
# every reference found here has been; it is not a whole-machine search.
#
# The rule for what is a leftover comes from leftovers.sh, the same file
# verify-deployment.sh reads it from. Neither tool owns the rule.
#
# Exit status: 0 whether or not anything needed retiring, 2 on a usage or
# environment error.
set -eu

PATH=${GATEBSD_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
MANIFEST=${GATEBSD_DEPLOY_MANIFEST:-$SCRIPT_DIR/deployment.manifest}
SCAN=${GATEBSD_DEPLOY_SCAN:-$SCRIPT_DIR/deployment.scan}
BACKUP_ROOT=${GATEBSD_LEFTOVER_BACKUP_ROOT:-/var/backups/gatebsd-stand}
CRON_DIRS=${GATEBSD_CRON_DIRS:-/etc/cron.d /usr/local/etc/cron.d}
DRY_RUN=0

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--dry-run) DRY_RUN=1 ;;
        -h|--help) echo "Usage: $0 [-n|--dry-run]"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }
[ -f "$SCRIPT_DIR/leftovers.sh" ] || {
    echo "leftovers.sh not found beside $0" >&2
    exit 2
}
. "$SCRIPT_DIR/leftovers.sh"

WORK=$(mktemp -d) || { echo "cannot create a work directory" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT

sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$MANIFEST" > "$WORK/rows"

# Managed targets and the gaps deployment.scan declares, exactly as
# verify-deployment.sh anchors its own sweep. Whether a file is a leftover must
# not depend on which of the two tools is asking -- a retirer with a narrower
# anchor set leaves behind precisely what the verifier keeps reporting, and the
# twenty-two dated copies of nginx's mirror site file were invisible to both
# for the one reason that no manifest row named the file they were copies of.
awk '{print $2}' "$WORK/rows" > "$WORK/anchors"
if [ -f "$SCAN" ]; then
    sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$SCAN" |
        awk '$1 == "gap" && NF >= 2 {print $2}' >> "$WORK/anchors"
fi

: > "$WORK/found"
while IFS= read -r anchor; do
    [ -n "${anchor:-}" ] || continue
    leftovers_beside "$anchor" >> "$WORK/found"
done < "$WORK/anchors"

# Two managed files in one directory can name the same leftover only by
# accident, but sort -u costs nothing and moving a path twice would fail.
sort -u "$WORK/found" > "$WORK/candidates"

# The places a still-live reference has actually been found: the managed
# scripts themselves, and the cron files that schedule them.
: > "$WORK/callers"
while IFS= read -r anchor; do
    [ -n "${anchor:-}" ] || continue
    [ -f "$anchor" ] && [ -r "$anchor" ] || continue
    printf '%s\n' "$anchor" >> "$WORK/callers"
done < "$WORK/anchors"
for _dir in $CRON_DIRS; do
    [ -d "$_dir" ] || continue
    find "$_dir" -mindepth 1 -maxdepth 1 -type f 2>/dev/null >> "$WORK/callers"
done

# A file that something still calls is not a leftover, whatever it is called.
# It is held back and named, so the reference gets fixed rather than the file
# quietly disappearing from under its caller.
: > "$WORK/leftovers"
held=0
while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    _name=$(basename "$candidate")
    _referrer=''
    while IFS= read -r caller; do
        [ -n "$caller" ] || continue
        # A leftover never counts as a reference to itself.
        [ "$caller" != "$candidate" ] || continue
        if grep -Fq -- "$_name" "$caller" 2>/dev/null; then
            _referrer=$caller
            break
        fi
    done < "$WORK/callers"
    if [ -n "$_referrer" ]; then
        echo "still referenced, kept: $candidate (by $_referrer)" >&2
        held=$((held + 1))
        continue
    fi
    printf '%s\n' "$candidate" >> "$WORK/leftovers"
done < "$WORK/candidates"

if [ ! -s "$WORK/leftovers" ]; then
    echo "No leftovers beside managed files."
    if [ "$held" -gt 0 ]; then
        printf '%s candidate(s) kept because something still calls them.\n' "$held"
    fi
    exit 0
fi

# The dated directory is created only once there is something to put in it.
# A run that finds nothing must not litter /var/backups with empty directories,
# or the retirement itself becomes the next thing to clean up.
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
dest_root="$BACKUP_ROOT/retired-$stamp"

# The retired set includes the CI dispatcher's older generations, which are
# 0550 root:operator because that script is the trust boundary. mv preserves
# each file's own mode; this keeps the directories above them closed too.
umask 077

retired=0
while IFS= read -r leftover; do
    [ -n "$leftover" ] || continue

    # Manifest targets are absolute, so appending keeps the original location
    # legible in the backup: .../retired-<stamp>/usr/local/sbin/<name>.
    dest="$dest_root$leftover"
    if [ -e "$dest" ]; then
        echo "refusing to overwrite an already retired copy: $dest" >&2
        exit 2
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'would retire  %s -> %s\n' "$leftover" "$dest"
        retired=$((retired + 1))
        continue
    fi

    mkdir -p "$(dirname "$dest")"
    mv -- "$leftover" "$dest"
    printf 'retired       %s -> %s\n' "$leftover" "$dest"
    retired=$((retired + 1))
done < "$WORK/leftovers"

echo
if [ "$DRY_RUN" -eq 1 ]; then
    printf '%s leftover(s) would be retired to %s\n' "$retired" "$dest_root"
else
    printf '%s leftover(s) retired to %s\n' "$retired" "$dest_root"
fi
if [ "$held" -gt 0 ]; then
    printf '%s candidate(s) kept because something still calls them.\n' "$held"
fi
