#!/bin/sh
# Deploy the stand's host-side components from this repository.
#
# Everything it installs is listed in deployment.manifest, which
# verify-deployment.sh reads too -- so an installer that puts a file somewhere
# and a verifier that looks for it elsewhere cannot disagree.
#
# Deliberately does not keep a dated backup of what it replaces. That habit is
# what left /usr/local/sbin holding four generations of the mirror health check
# with a cron file naming two of them. The previous content is in git; a copy
# beside the live file is not a backup, it is a second live file.
#
# Idempotent: re-running it changes nothing once the tree matches.
set -eu

PATH=${GATEBSD_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_DIR=${GATEBSD_REPO_DIR:-$(dirname "$(dirname "$SCRIPT_DIR")")}
MANIFEST=${GATEBSD_DEPLOY_MANIFEST:-$SCRIPT_DIR/deployment.manifest}
PACKAGES=${GATEBSD_DEPLOY_PACKAGES:-$SCRIPT_DIR/packages.list}
# Not read here -- installing is the manifest's business. It is resolved so the
# retirement pass at the end can be handed the same declaration this run used,
# rather than falling back to whatever sits beside the script.
SCAN=${GATEBSD_DEPLOY_SCAN:-$SCRIPT_DIR/deployment.scan}
DRY_RUN=0
CHECK=0

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--dry-run) DRY_RUN=1 ;;
        # --check answers one question: is this machine at this commit? Same
        # comparison as --dry-run, but it exits non-zero when anything is stale
        # instead of printing it among a hundred `unchanged` lines.
        #
        # It exists because a fix can sit in git and never reach the machine.
        # `amneziawg-go` was added to the build jail's install list in 366620d
        # and the stand kept running the previous copy, so releases 2.9.64 and
        # 2.9.65 both died on
        #     Required package is not installed or lacks metadata: amneziawg-go
        # -- twice, with the repository already correct both times.
        --check) DRY_RUN=1; CHECK=1 ;;
        -h|--help) echo "Usage: $0 [-n|--dry-run] [--check]"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }
[ "$DRY_RUN" -eq 1 ] || [ "$(id -u)" = 0 ] || {
    echo "must run as root (or pass --dry-run)" >&2
    exit 2
}

digest() {
    if command -v sha256 >/dev/null 2>&1; then sha256 -q "$1"; else sha256sum "$1" | cut -d' ' -f1; fi
}

file_mode() {
    _mode=$(stat -f '%Lp' "$1" 2>/dev/null) || _mode=''
    case "$_mode" in
        ''|*[!0-7]*) _mode=$(stat -c '%a' "$1" 2>/dev/null) || _mode='' ;;
    esac
    printf '%s' "$_mode"
}

file_owner() {
    if [ "$(uname -s)" = "FreeBSD" ]; then
        _owner=$(stat -f '%Su:%Sg' "$1" 2>/dev/null) || _owner=''
    else
        _owner=$(stat -c '%U:%G' "$1" 2>/dev/null) || _owner=''
    fi
    printf '%s' "$_owner"
}

case "${GATEBSD_VERIFY_OWNERSHIP:-auto}" in
    1|true|yes) VERIFY_OWNERSHIP=1 ;;
    0|false|no) VERIFY_OWNERSHIP=0 ;;
    *)
        if [ "$(id -u)" -eq 0 ] && [ "$(uname -s)" = "FreeBSD" ]; then
            VERIFY_OWNERSHIP=1
        else
            VERIFY_OWNERSHIP=0
        fi
        ;;
esac

# The loops below run in a pipeline, so they are subshells and a variable set
# inside one does not survive it. Stale entries are collected in a file instead.
STALE=$(mktemp) || { echo "cannot create a work file" >&2; exit 2; }
trap 'rm -f "$STALE"' EXIT INT TERM

sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$MANIFEST" |
while read -r source target mode owner group; do
    [ -n "${target:-}" ] || continue
    repo_file="$REPO_DIR/$source"
    [ -f "$repo_file" ] || { echo "missing in repository: $source" >&2; exit 1; }

    if [ -f "$target" ] && [ "$(digest "$repo_file")" = "$(digest "$target")" ]; then
        actual_mode=$(file_mode "$target")
        mode_ok=1
        if [ -n "$actual_mode" ] && [ "0$actual_mode" != "$mode" ] && [ "$actual_mode" != "$mode" ]; then
            mode_ok=0
        fi
        owner_ok=1
        if [ "$VERIFY_OWNERSHIP" -eq 1 ]; then
            actual_owner=$(file_owner "$target")
            if [ -n "$actual_owner" ] && [ "$actual_owner" != "${owner}:${group}" ]; then
                owner_ok=0
            fi
        fi
        if [ "$mode_ok" -eq 1 ] && [ "$owner_ok" -eq 1 ]; then
            printf 'unchanged  %s\n' "$target"
            continue
        fi
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'would install  %s -> %s (%s %s:%s)\n' "$source" "$target" "$mode" "$owner" "$group"
        printf 'file  %s\n' "$target" >> "$STALE"
        continue
    fi

    install -d -m 0755 "$(dirname "$target")"
    # install(1) writes to a temporary name and renames, so a script that is
    # executing when this runs is never modified underneath itself.
    install -m "$mode" -o "$owner" -g "$group" "$repo_file" "$target"
    printf 'installed  %s\n' "$target"
done

echo
# Writing the current generation is only half of making a directory
# reproducible. Leaving the four older ones next to it adds a fifth, and one of
# those older generations was still being scheduled by cron. Retiring runs
# after the installs, so a failed install leaves the machine untouched.
#
# One invocation, with the mode carried in a variable rather than an if/else
# around two calls. Written as a branch, an edit that inverts the condition
# turns `--dry-run` into a real move -- which is exactly what happened while
# testing this: the dry run silently retired the file for real. There is no
# second call site here to get the wrong one.
# Packages, from the same kind of single source as the files above. Done after
# the files and before retiring leftovers: installing a package cannot break a
# deployed script, and a failed pkg run should not leave the machine half
# retired.
#
# Only what is MISSING is installed. `pkg install` on an already-installed
# package is not harmless here -- it can pull an upgrade, and a build host that
# quietly moves its toolchain underneath a release is the opposite of what this
# directory is for.
if [ -f "$PACKAGES" ]; then
    echo
    sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$PACKAGES" |
    while read -r pkgname _rest; do
        [ -n "${pkgname:-}" ] || continue
        if pkg info -e "$pkgname" 2>/dev/null; then
            printf 'present    %s\n' "$pkgname"
            continue
        fi
        if [ "$DRY_RUN" -eq 1 ]; then
            printf 'would install package  %s\n' "$pkgname"
            printf 'package  %s\n' "$pkgname" >> "$STALE"
            continue
        fi
        if pkg install -y "$pkgname" >/dev/null 2>&1; then
            printf 'installed  %s\n' "$pkgname"
        else
            # Loud, and not fatal. A stand that cannot reach the package
            # repository still deploys its files correctly, and reporting the
            # one failure beats abandoning the run half done.
            printf 'FAILED to install package  %s\n' "$pkgname" >&2
        fi
    done
fi

retire_mode=''
[ "$DRY_RUN" -eq 0 ] || retire_mode='--dry-run'
GATEBSD_DEPLOY_MANIFEST="$MANIFEST" GATEBSD_DEPLOY_SCAN="$SCAN" GATEBSD_PATH="$PATH" \
    sh "$SCRIPT_DIR/retire-leftovers.sh" $retire_mode

echo
if [ "$CHECK" -eq 1 ]; then
    if [ -s "$STALE" ]; then
        echo "This machine is not at this commit:"
        sed 's/^/  /' "$STALE"
        echo "Run install-ci-host.sh on it before building."
        exit 1
    fi
    echo "This machine matches the repository."
    exit 0
fi
echo "Run verify-deployment.sh to confirm the stand now matches the repository."
