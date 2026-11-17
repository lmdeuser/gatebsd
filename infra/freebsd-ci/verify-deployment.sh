#!/bin/sh
# Report every way the stand has drifted from this repository.
#
# "Reproducible infrastructure" is a claim about a property, and a property
# nobody measures is a hope. This measures it.
#
# Five kinds of drift, each of which has already caused a real failure here:
#
#   1. A deployed script whose content differs from the repository. Deployed
#      copies do not update themselves; forgetting to copy one cost two
#      debugging cycles because the pipeline kept running the previous version.
#
#   2. A leftover beside a managed file -- `.bak`, `.before-<date>`, `-v2`.
#      /usr/local/sbin holds mirror-health-check and mirror-health-check-v2,
#      and a cron file names each. Which one is "the" health check is then a
#      matter of which line you read. What counts as a leftover is defined in
#      leftovers.sh, which retire-leftovers.sh reads too: the tool that reports
#      them and the tool that carries them off must not judge by different
#      rules.
#
#   3. A command scheduled by more than one cron file. cron(8) parses every
#      file in a cron.d directory, dotted names included, so a single leftover
#      registers the same job twice. Two concurrent copies of the adblock
#      updater is what corrupted unbound's configuration on the production
#      router; two concurrent copies of mirror-sync-git are scheduled here.
#
#   4. A scheduled command with no source in this repository at all.
#
#   5. A file in one of those directories that nothing accounts for: no
#      manifest row, no package. This is the one the four above could not see.
#      Kind 4 needs a cron file to name the command; a hand-installed script
#      that merely sits in root's PATH is named by nothing and was therefore
#      reported by nothing. /usr/local/sbin/configure-freebsd-mirror sat there
#      from July, still carrying a writer of /usr/local/etc/poudriere.conf that
#      the repository had removed, and was found by listing the directory by
#      hand. Which directories are expected to be fully accounted for, and what
#      in them is knowingly not, is declared in deployment.scan.
#
# Read-only: it inspects and reports, and changes nothing. Run it before
# trusting a build, and after any deployment.
#
# Exit status: 0 clean, 1 drift found.
set -eu

PATH=${GATEBSD_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_DIR=${GATEBSD_REPO_DIR:-$(dirname "$(dirname "$SCRIPT_DIR")")}
MANIFEST=${GATEBSD_DEPLOY_MANIFEST:-$SCRIPT_DIR/deployment.manifest}
PACKAGES=${GATEBSD_DEPLOY_PACKAGES:-$SCRIPT_DIR/packages.list}
SCAN=${GATEBSD_DEPLOY_SCAN:-$SCRIPT_DIR/deployment.scan}
CRON_DIRS=${GATEBSD_CRON_DIRS:-/etc/cron.d /usr/local/etc/cron.d}

DRIFT_ONLY=0
for _arg in "$@"; do
    case "$_arg" in
        --drift-only) DRIFT_ONLY=1 ;;
        *) echo "usage: $0 [--drift-only]" >&2; exit 2 ;;
    esac
done

[ -f "$SCRIPT_DIR/leftovers.sh" ] || {
    echo "leftovers.sh not found beside $0" >&2
    exit 2
}
. "$SCRIPT_DIR/leftovers.sh"

WORK=$(mktemp -d) || { echo "cannot create a work directory" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT
FINDINGS="$WORK/findings"
NOTES="$WORK/notes"
: > "$FINDINGS"

# Findings go to a file rather than a counter: every loop below reads from a
# pipe, so it runs in a subshell and any variable it increments is discarded
# when that subshell exits.
report() {
    printf '%s\n' "$*" | tee -a "$FINDINGS"
}

# A declared gap counts as a finding BY DEFAULT, and that is deliberate.
# mirror-sync-git was reported on every run since the manifest existed, and
# that report is the only reason anyone remembered it had no source in the
# repository -- the script that turned out to be filling the disk. Naming a gap
# says "this was decided", not "stop mentioning it".
#
# --drift-only exists for one caller: a pipeline gate. There the question is
# narrower -- has the stand diverged from the commit being built -- and a check
# that is red for ever on two long-standing decisions cannot answer it. The gap
# is still printed in that mode; it just does not decide the exit status.
GAP_IS_DRIFT=$([ "$DRIFT_ONLY" -eq 1 ] && echo 0 || echo 1)
note() {
    if [ "$GAP_IS_DRIFT" -eq 1 ]; then
        report "$@"
    else
        printf '%s\n' "$*" | tee -a "$NOTES"
    fi
}

digest() {
    # sha256 is FreeBSD's spelling, sha256sum the GNU one; the stand is FreeBSD
    # and the test suite runs on Linux, and both must reach the same verdict.
    if command -v sha256 >/dev/null 2>&1; then
        sha256 -q "$1"
    else
        sha256sum "$1" | cut -d' ' -f1
    fi
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

manifest_rows() {
    sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$MANIFEST"
}

manifest_rows > "$WORK/rows"

# The manifest's targets, and the scan declaration's three record kinds. Read
# once, up here, because two sections below need them: the leftover sweep
# anchors on managed files and on declared gaps alike, and the scan itself
# needs the same list of managed targets the cron check does.
awk '{print $2}' "$WORK/rows" | sort -u > "$WORK/managed"
: > "$WORK/scanroots"
: > "$WORK/statepaths"
: > "$WORK/gaps"
if [ -f "$SCAN" ]; then
    sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$SCAN" > "$WORK/scanrows"
    awk '$1 == "scan"  && NF >= 2 {print $2}' "$WORK/scanrows" | sort -u > "$WORK/scanroots"
    awk '$1 == "state" && NF >= 2 {print $2}' "$WORK/scanrows" | sort -u > "$WORK/statepaths"
    awk '$1 == "gap"   && NF >= 2 {print $2}' "$WORK/scanrows" | sort -u > "$WORK/gaps"
fi

echo "== deployed content against the repository =="
while read -r source target mode owner group; do
    [ -n "${target:-}" ] || continue
    repo_file="$REPO_DIR/$source"
    if [ ! -f "$repo_file" ]; then
        report "MISSING IN REPO   $source"
        continue
    fi
    if [ ! -f "$target" ]; then
        report "NOT DEPLOYED      $target"
        continue
    fi
    # Some managed files are deliberately unreadable to the invoking user --
    # the CI dispatcher is mode 0550 root:operator because it is the trust
    # boundary. "I could not read it" must not be reported as "it differs":
    # a verifier that cries wolf is one people learn to ignore.
    if [ ! -r "$target" ]; then
        report "CANNOT VERIFY     $target is not readable; re-run as root"
        continue
    fi
    if [ "$(digest "$repo_file")" != "$(digest "$target")" ]; then
        report "DRIFTED           $target differs from $source"
        continue
    fi
    actual_mode=$(file_mode "$target")
    if [ -n "$actual_mode" ] && [ "0$actual_mode" != "$mode" ] && [ "$actual_mode" != "$mode" ]; then
        report "WRONG MODE        $target is $actual_mode, manifest says $mode"
        continue
    fi
    if [ "$VERIFY_OWNERSHIP" -eq 1 ]; then
        actual_owner=$(file_owner "$target")
        if [ -n "$actual_owner" ] && [ "$actual_owner" != "${owner}:${group}" ]; then
            report "WRONG OWNER       $target is $actual_owner, manifest says ${owner}:${group}"
            continue
        fi
    fi
    printf 'ok                %s\n' "$target"
done < "$WORK/rows"

echo
echo "== leftovers beside managed files =="
# Managed targets and declared gaps alike. A gap is a file we have decided not
# to manage, not one we have stopped caring about: mirror-sync-git had
# mirror-sync-git-v2 and mirror-sync-git-v2.bak2 beside it for three weeks, and
# nginx's two site files had twenty-two dated copies, all invisible to this
# sweep for the single reason that no manifest row named the file they were
# copies of.
: > "$WORK/leftoverpaths"
{ awk '{print $2}' "$WORK/rows"; cat "$WORK/gaps"; } | sort -u > "$WORK/anchors"
while IFS= read -r _anchor; do
    [ -n "${_anchor:-}" ] || continue
    # Anything whose name is an anchor's name plus a generation marker: an older
    # generation, a dated backup, a hand-made copy. `retire-leftovers.sh` moves
    # exactly this set out of the way.
    leftovers_beside "$_anchor" > "$WORK/stale"
    while IFS= read -r _stale; do
        [ -n "$_stale" ] || continue
        grep -qxF "$_stale" "$WORK/leftoverpaths" && continue
        printf '%s\n' "$_stale" >> "$WORK/leftoverpaths"
        report "LEFTOVER          $_stale"
    done < "$WORK/stale"
done < "$WORK/anchors"

echo
echo "== duplicate and unmanaged cron registrations =="
: > "$WORK/scheduled"
for _dir in $CRON_DIRS; do
    [ -d "$_dir" ] || continue
    # Every file, not just well-named ones: that is what cron itself does.
    find "$_dir" -maxdepth 1 -type f 2>/dev/null | sort > "$WORK/cronfiles"
    while IFS= read -r _file; do
        [ -n "$_file" ] || continue
        # Take the command portion of each cron line -- fields seven onward,
        # after the five time fields and the user -- rather than matching a
        # path prefix. One line can chain several commands with `&&`, and
        # redirections name log files that are not commands at all.
        sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$_file" 2>/dev/null |
            awk 'NF >= 7 && $1 ~ /^[0-9*@]/ { $1=$2=$3=$4=$5=$6=""; print }' |
            sed -e 's/[0-9]*>>*[[:space:]]*[^[:space:]]*//g' -e 's/2>&1//g' |
            grep -oE '/[A-Za-z0-9._/-]+' |
            sort -u > "$WORK/commands" || true
        while IFS= read -r _command; do
            [ -n "$_command" ] || continue
            printf '%s\t%s\n' "$_command" "$_file" >> "$WORK/scheduled"
        done < "$WORK/commands"
    done < "$WORK/cronfiles"
done

if [ -s "$WORK/scheduled" ]; then
    cut -f1 "$WORK/scheduled" | sort | uniq -d > "$WORK/dups"
    while IFS= read -r _dup; do
        [ -n "$_dup" ] || continue
        _where=$(awk -F'\t' -v c="$_dup" '$1 == c {printf "%s ", $2}' "$WORK/scheduled")
        report "SCHEDULED TWICE   $_dup by: $_where"
    done < "$WORK/dups"

    # Only our own namespace. FreeBSD's base crontab schedules atrun,
    # save-entropy, newsyslog and periodic; reporting those as unmanaged would
    # bury the findings that matter under noise that can never be actioned.
    MANAGED_PREFIX=${GATEBSD_MANAGED_PREFIX:-/usr/local/}
    cut -f1 "$WORK/scheduled" | sort -u > "$WORK/unique"
    while IFS= read -r _command; do
        [ -n "$_command" ] || continue
        case "$_command" in "$MANAGED_PREFIX"*) ;; *) continue ;; esac
        grep -qxF "$_command" "$WORK/managed" && continue
        report "UNMANAGED         $_command is scheduled but has no source in the repository"
    done < "$WORK/unique"
fi

echo
echo "== files nothing accounts for =="
# The class the four sections above cannot see. Each of them starts from
# something that names a file -- a manifest row, a managed name, a cron line --
# so a file nothing names is a file nothing checks. This one starts from the
# directory instead and asks of every file in it: does anything account for
# this?
#
# "Accounted for" is deliberately generous, because a verifier that reports two
# hundred lines is one nobody reads: a manifest row, a package, or the copy a
# port installs and lets the first install put in place. What is left after
# that is genuinely ours or genuinely nobody's, and there are a dozen of them.
#
# Declared gaps are reported too, not suppressed. Naming one in deployment.scan
# says "this was decided", not "stop mentioning it" -- mirror-sync-git has been
# reported on every run since the manifest existed and that is why anyone still
# remembers it has no source.
if [ -s "$WORK/scanroots" ]; then
    while IFS= read -r _root; do
        [ -n "${_root:-}" ] || continue
        [ -d "$_root" ] || continue
        find "$_root" \( -type f -o -type l \) 2>/dev/null | sort > "$WORK/present"
        while IFS= read -r _file; do
            [ -n "$_file" ] || continue

            # Runtime state a daemon owns. Matched as a whole path or a whole
            # path component, never as a string prefix: /usr/local/etc/ssl must
            # not excuse /usr/local/etc/sslmirror.conf.
            _skip=0
            while IFS= read -r _state; do
                [ -n "${_state:-}" ] || continue
                case "$_file" in
                    "$_state"|"$_state"/*) _skip=1; break ;;
                esac
            done < "$WORK/statepaths"
            [ "$_skip" -eq 0 ] || continue

            grep -qxF "$_file" "$WORK/managed" && continue
            # Already named as a leftover above. Reporting the same file twice
            # under two verdicts would make the count meaningless and the
            # second verdict is the less useful one.
            grep -qxF "$_file" "$WORK/leftoverpaths" && continue

            if grep -qxF "$_file" "$WORK/gaps"; then
                note "KNOWN GAP         $_file is unmanaged by decision; see deployment.scan"
                continue
            fi

            path_has_package_source "$_file" && continue
            report "UNACCOUNTED       $_file is in no manifest row and belongs to no package"
        done < "$WORK/present"
    done < "$WORK/scanroots"
fi

# A sixth kind of drift, and the one that hid the longest: a package the stand
# requires is simply not installed. Nothing declared the dependencies, so
# nothing could notice. smartmontools was absent on a host that keeps the
# mirror, Forgejo and every release on one mechanical disk -- it could not read
# that disk's health, and the machine reported nothing wrong because nothing
# was looking.
if [ -f "$PACKAGES" ]; then
    sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$PACKAGES" > "$WORK/packages"
    while read -r _pkg _rest; do
        [ -n "${_pkg:-}" ] || continue
        pkg info -e "$_pkg" 2>/dev/null && continue
        report "PACKAGE MISSING   $_pkg is required by packages.list and is not installed"
    done < "$WORK/packages"
fi

echo
if [ ! -s "$FINDINGS" ]; then
    if [ -s "$NOTES" ]; then
        printf 'No drift: the stand matches the repository, with %s declared gap(s) above.\n' \
            "$(wc -l < "$NOTES" | tr -d ' ')"
    else
        echo "No drift: the stand matches the repository."
    fi
    exit 0
fi
printf 'Drift found: %s finding(s).\n' "$(wc -l < "$FINDINGS" | tr -d ' ')"
# Only --drift-only fills NOTES; in the default mode gaps are inside the count
# above, and printing an empty second number said nothing twice.
[ -s "$NOTES" ] && printf 'Declared gaps passed over: %s.\n' "$(wc -l < "$NOTES" | tr -d ' ')"
echo "The stand cannot be rebuilt from the repository as it stands."
exit 1
