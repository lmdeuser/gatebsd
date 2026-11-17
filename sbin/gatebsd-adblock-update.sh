#!/bin/sh
# Atomically update the GateBSD DNS blocklist and safely reload Unbound.
set -eu

PATH=${GATEBSD_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}

# One Western general-purpose list used to be the whole of it. It is a good
# list and it is not enough here: RU advertising and tracking networks are
# thinly covered, and it carries nothing aimed at advertising inside mobile
# applications, which is where the complaints actually come from.
#
# GATEBSD_ADBLOCK_URL still works and still means "exactly this one list".
SOURCE_URLS=${GATEBSD_ADBLOCK_URLS:-${GATEBSD_ADBLOCK_URL:-\
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
https://adaway.org/hosts.txt \
https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt \
https://filters.adtidy.org/extension/ublock/filters/11.txt \
https://filters.adtidy.org/extension/ublock/filters/1.txt \
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt}}

# The AdGuard DNS filter above is the one AdGuard Home itself uses: the same
# rules the phone app applies, already reduced to what a resolver can act on.
# The two adtidy lists next to it are AdGuard's *browser* filters, which is a
# different and smaller thing -- we had those and not this one, which is why a
# phone running AdGuard blocked names this router let through.
#
# Hagezi Pro was chosen by measurement, not reputation. Five candidates were
# compared against the live list on 3 August:
#
#   list           own names   new to us   caught 12 names we found by hand
#   hagezi_pro       216,244    +128,533   5
#   hagezi_ult       269,115    +180,191   5
#   oisd_big         429,861    +344,844   2
#   1hosts_lite      210,218    +148,028   3
#   1hosts_xtra    1,099,070  +1,015,063   5
#
# Size turned out to be a bad predictor. OISD Big brings the second most names
# and finds almost nothing we had actually met; 1Hosts Xtra brings a million
# and calls itself aggressive. Hagezi Pro has the best hit rate per name added
# and is curated against breakage, so it is the only one taken.
#
# The right lesson from that table is not about lists at all: SEVEN of the
# twelve names we found by hand are in none of them -- mytracker.mail.ru,
# trk.mail.ru, tracker.mail.ru, ads.vk.ru, ads.rustore.ru's neighbours and
# imasdk.googleapis.com, which curators seem to leave out on purpose because
# it stalls players. For this locale our own hunting is the primary channel
# and adblock-extra is not a footnote to the downloaded lists.

# What a blocked name answers with. NXDOMAIN says "this name does not exist",
# which a client reads as a broken resolver rather than as a policy: it retries,
# and some clients fall back to a resolver of their own -- so the verdict was
# pushing traffic around the very blocklist that issued it. always_null answers
# 0.0.0.0/:: instead, the connection fails at once and locally, and nothing
# concludes that DNS is down. This is what Pi-hole and AdGuard Home return.
#
# The Firefox canary keeps NXDOMAIN, in unbound.conf: there the "does not
# exist" answer *is* the documented signal, and a 0.0.0.0 would not be.
ADBLOCK_VERDICT=${GATEBSD_ADBLOCK_VERDICT:-always_null}
UNBOUND_CONF=${GATEBSD_UNBOUND_CONF:-/usr/local/etc/unbound/unbound.conf}
BLOCKLIST=${GATEBSD_ADBLOCK_CONF:-/usr/local/etc/unbound/adblock.conf}
LOG=${GATEBSD_ADBLOCK_LOG:-/var/log/gatebsd-adblock.log}
MIN_DOMAINS=${GATEBSD_ADBLOCK_MIN_DOMAINS:-1000}
MIN_RATIO=${GATEBSD_ADBLOCK_MIN_RATIO:-50}
MAX_BYTES=${GATEBSD_ADBLOCK_MAX_BYTES:-67108864}
# Our own additions, in hosts format, merged with the downloaded sources so
# they go through the same parser and the same shrink protection. This is where
# a name we caught ourselves belongs -- editing a downloaded list is pointless,
# the next update overwrites it.
EXTRA_FILE=${GATEBSD_ADBLOCK_EXTRA:-/usr/local/etc/gatebsd/adblock-extra}
LOCK_FILE=${GATEBSD_ADBLOCK_LOCK:-${UNBOUND_CONF}.gatebsd.lock}
PYTHON_LAUNCHER=${GATEBSD_PYTHON_LAUNCHER:-/usr/local/libexec/gatebsd-python}
PYTHONPATH_VALUE=${GATEBSD_PYTHONPATH:-/usr/local/share/gatebsd/webui/backend}
INCLUDE_LINE="include: \"$BLOCKLIST\""

# A record of what the published blocklist was actually built from: the source
# URL list and a verbatim copy of our own additions. Written only after a run
# succeeds, so it always describes the file that is live.
#
# It exists so an upgrade can tell whether it needs to rebuild. Installing a
# package that changes adblock-extra does NOT rebuild the list -- the generated
# adblock.conf stays as the previous build left it until the six-hourly cron
# fires. Seen on the router twice, with 2.9.45 and 2.9.47: the new names were
# on the device and not in the resolver, and a customer would have waited up to
# six hours seeing an unchanged product with no way to know why.
STAMP_FILE=${GATEBSD_ADBLOCK_STAMP:-/var/db/gatebsd-system/adblock-inputs}

# What the last rebuild actually did, for the panel to read.
#
# The published blocklist cannot answer this. When a run refuses to publish,
# the file on disk is the *previous* run's, and its header still states six
# sources and a date -- read on its own it says "all is well", which is the
# very silence this record exists to break. On 4 August a run published five
# sources instead of six and 307943 domains instead of 384499, and the only
# trace was one WARNING line in a log nobody reads.
#
# One writer, this script, under the same lock as everything else here. It is
# deliberately not the stamp file next to it: the stamp answers "what was this
# built from", this answers "what happened last time", and the two have
# different lifetimes -- a refused run leaves the stamp untouched on purpose.
STATUS_FILE=${GATEBSD_ADBLOCK_STATUS:-/var/db/gatebsd-system/adblock-status.json}

# --if-changed: rebuild only when those inputs differ from the stamp. This is
# what the upgrade path calls; cron still rebuilds unconditionally, because the
# downloaded lists move under us and no stamp can see that.
IF_CHANGED=0
for _arg in "$@"; do
    case "$_arg" in
        --if-changed) IF_CHANGED=1 ;;
        *) echo "unknown option: $_arg" >&2; exit 2 ;;
    esac
done

# The inputs, rendered into one comparable document.
write_inputs() {
    _out=$1
    printf '# blocklist inputs\nsources:\n' > "$_out" || return 1
    for _u in $SOURCE_URLS; do
        printf '%s\n' "$_u" >> "$_out" || return 1
    done
    printf 'extra:\n' >> "$_out" || return 1
    if [ -f "$EXTRA_FILE" ] && [ ! -L "$EXTRA_FILE" ]; then
        cat "$EXTRA_FILE" >> "$_out" || return 1
    fi
    return 0
}

# Serialize cron, UI and manual updates with the same flock contract as the
# Python DNS writer.  The Python parent retains the lock while this script runs.
if [ "${GATEBSD_ADBLOCK_LOCK_HELD:-0}" != 1 ]; then
    [ -x "$PYTHON_LAUNCHER" ] || { echo "Python launcher is unavailable" >&2; exit 1; }
    exec env -i PATH="$PATH" HOME=/root LANG=C.UTF-8 \
        GATEBSD_ADBLOCK_LOCK_HELD=1 \
        GATEBSD_PATH="$PATH" \
        GATEBSD_ADBLOCK_URLS="$SOURCE_URLS" \
        GATEBSD_ADBLOCK_VERDICT="$ADBLOCK_VERDICT" \
        GATEBSD_UNBOUND_CONF="$UNBOUND_CONF" \
        GATEBSD_ADBLOCK_CONF="$BLOCKLIST" \
        GATEBSD_ADBLOCK_LOG="$LOG" \
        GATEBSD_ADBLOCK_MIN_DOMAINS="$MIN_DOMAINS" \
        GATEBSD_ADBLOCK_MIN_RATIO="$MIN_RATIO" \
        GATEBSD_ADBLOCK_MAX_BYTES="$MAX_BYTES" \
        GATEBSD_ADBLOCK_LOCK="$LOCK_FILE" \
        GATEBSD_ADBLOCK_EXTRA="$EXTRA_FILE" \
        GATEBSD_ADBLOCK_STAMP="$STAMP_FILE" \
        GATEBSD_ADBLOCK_STATUS="$STATUS_FILE" \
        GATEBSD_PYTHON_LAUNCHER="$PYTHON_LAUNCHER" \
        GATEBSD_PYTHONPATH="$PYTHONPATH_VALUE" \
        PYTHONPATH="$PYTHONPATH_VALUE" \
        "$PYTHON_LAUNCHER" -m gatebsd_ui.lockrun "$LOCK_FILE" -- "$0" "$@"
fi

LOG_DIR=$(dirname "$LOG")
install -d -m 0755 "$LOG_DIR"
if [ -L "$LOG" ] || { [ -e "$LOG" ] && [ ! -f "$LOG" ]; }; then
    echo "unsafe adblock log path: $LOG" >&2
    exit 1
fi
: >> "$LOG"
chmod 0640 "$LOG" 2>/dev/null || true

# Scratch space for the rebuild, in RAM rather than on the root mirror.
#
# The job writes about 50 MB per run -- the five sources concatenated, the
# parsed block and allow lists, both sorted copies, and the generated
# blocklist -- and it runs every six hours. On this appliance that is roughly
# 7% of everything written to disk in a day, and /tmp is a dataset on a
# two-SSD mirror, so every one of those bytes is written twice. Keeping the
# scratch in RAM removes all of it.
#
# It buys no speed: the run is awk over ~450k lines and two sorts, which is
# CPU, not I/O. Writes are the whole point.
#
# Deliberately NOT /tmp system-wide. That would mean either editing
# /etc/fstab from a package or an rc.d script that has to mount before
# anything uses /tmp -- and boot ordering has already cost this project days
# of "agent unavailable". Mounting our own directory here has no boot order
# to get wrong.
ADBLOCK_TMPFS=${GATEBSD_ADBLOCK_TMPFS:-/var/run/gatebsd/adblock-work}
# A ceiling, not a reservation: tmpfs occupies only what is written to it, so
# a generous number costs nothing until something goes wrong. It was 512m,
# which was already close for a working set that grows with every source
# added. 2g on a 7.8 GB box still leaves over 3 GB free even if it were
# somehow filled, and it is the difference between "the run falls back to disk
# because a list grew" and "the run does what it was asked".
ADBLOCK_TMPFS_SIZE=${GATEBSD_ADBLOCK_TMPFS_SIZE:-2g}

WORKDIR=
BLOCK_TMP=
CONF_TMP=
TMPFS_MOUNTED=
cleanup() {
    [ -z "${BLOCK_TMP:-}" ] || rm -f "$BLOCK_TMP" 2>/dev/null || true
    [ -z "${CONF_TMP:-}" ] || rm -f "$CONF_TMP" 2>/dev/null || true
    [ -z "${WORKDIR:-}" ] || rm -rf "$WORKDIR" 2>/dev/null || true
    # After the workdir, never before: unmounting first would strand it.
    [ -z "${TMPFS_MOUNTED:-}" ] || umount "$TMPFS_MOUNTED" 2>/dev/null || true
}

# Mount the scratch filesystem, and carry on without it if that fails.
#
# This is an optimisation, and an optimisation that can refuse to run is a new
# way for the blocklist to stop updating. Anything unexpected here -- no tmpfs
# support, a full memory, a directory we cannot create -- falls back to the
# ordinary TMPDIR and the run proceeds exactly as it did before.
mount_scratch() {
    [ -n "${GATEBSD_ADBLOCK_NO_TMPFS:-}" ] && return 1

    # Already mounted by a run that died before its trap fired. Reuse it and
    # leave it alone -- mounting again would stack a second filesystem on the
    # same point, and the one underneath would be invisible and unreclaimed.
    if mount -t tmpfs | grep -q " on $ADBLOCK_TMPFS "; then
        TMPDIR=$ADBLOCK_TMPFS
        export TMPDIR
        return 0
    fi

    # mkdir only, never chown. `install -d -o root -g wheel` re-applies
    # ownership to a directory that already exists, and that has broken both
    # shared runtime directories on this box before.
    [ -d "$ADBLOCK_TMPFS" ] || mkdir -p "$ADBLOCK_TMPFS" 2>/dev/null || return 1

    mount -t tmpfs -o "size=$ADBLOCK_TMPFS_SIZE" tmpfs "$ADBLOCK_TMPFS" 2>/dev/null || return 1
    TMPFS_MOUNTED=$ADBLOCK_TMPFS
    TMPDIR=$ADBLOCK_TMPFS
    export TMPDIR
    return 0
}

SCRATCH_IN_RAM=no
if mount_scratch; then
    SCRATCH_IN_RAM=yes
fi

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/gatebsd-adblock.XXXXXX")
trap 'cleanup' EXIT
trap 'exit 1' HUP INT TERM
log() {
    _line="$(date '+%Y-%m-%d %H:%M:%S') $*"
    printf '%s\n' "$_line" >> "$LOG" 2>/dev/null || true
    printf '%s\n' "$_line"
}

# Counters the status record reports. Declared here, before anything can fail,
# because fail() writes the record and `set -u` would turn a missing variable
# into a second, unrelated failure on the way out of the first.
SOURCES_OK=0
SOURCES_FAILED=""
SOURCES_TOTAL=0
for _u in $SOURCE_URLS; do SOURCES_TOTAL=$((SOURCES_TOTAL + 1)); done
# Set once the download loop has actually run. Without it a failure that
# happens before any download -- an unknown verdict, a missing command --
# would publish "sources_used: 0", which reads as "every feed is down". That
# is the same lie as the watchdog reporting an unknown handshake age as 0.
SOURCES_MEASURED=0
TOTAL=

source_details() {
    _details=""
    for _meta in "$WORKDIR"/meta.*; do
        [ -f "$_meta" ] || continue
        IFS="$(printf '\t')" read -r _index _url _downloaded _source_state _source_reason < "$_meta"
        _parsed=0
        if [ -r "$WORKDIR/parsed.$_index" ]; then
            _parsed=$(sed -n '1p' "$WORKDIR/parsed.$_index")
        fi
        case "$_downloaded" in ''|*[!0-9]*) _downloaded=0 ;; esac
        case "$_parsed" in ''|*[!0-9]*) _parsed=0 ;; esac
        _url_json=$(printf '%s' "$_url" | sed 's/\\/\\\\/g; s/"/\\"/g')
        _item="{\"url\":\"$_url_json\",\"downloaded\":$_downloaded,\"parsed\":$_parsed,\"status\":\"$_source_state\",\"reason\":\"$_source_reason\"}"
        _details="${_details:+$_details,}$_item"
    done
    printf '%s' "$_details"
}

# Never fatal: a record we could not write must not take down the update it is
# only describing. Written to a temporary file and moved into place, so a
# reader never sees half a document.
write_status() {
    _outcome=$1
    _reason=$2
    _status_dir=$(dirname "$STATUS_FILE")
    if [ ! -d "$_status_dir" ] || [ -L "$_status_dir" ]; then
        return 0
    fi
    if [ "$SOURCES_MEASURED" = 1 ]; then _used=$SOURCES_OK; else _used=null; fi
    case "${TOTAL:-}" in
        ''|*[!0-9]*) _domains=null ;;
        *) _domains=$TOTAL ;;
    esac
    _now=$(date +%s)
    _previous_success=""
    _previous_sources=""
    if [ -f "$STATUS_FILE" ] && [ ! -L "$STATUS_FILE" ] && [ -r "$STATUS_FILE" ]; then
        _previous_success=$(sed -n 's/.*"last_success_at":\([0-9][0-9]*\).*/\1/p' "$STATUS_FILE" | head -1)
        _previous_sources=$(sed -n 's/.*"sources":\[\(.*\)\]}$/\1/p' "$STATUS_FILE" | head -1)
    fi
    case "$_previous_success" in ''|*[!0-9]*) _previous_success=null ;; esac
    case "$_outcome" in
        published|unchanged) _success=$_now ;;
        *) _success=$_previous_success ;;
    esac
    _details=$(source_details)
    [ -n "$_details" ] || _details=$_previous_sources
    _reason_json=$(printf '%s' "$_reason" | sed 's/\\/\\\\/g; s/"/\\"/g')
    _skipped_json=$(printf '%s' "${SOURCES_FAILED# }" | sed 's/\\/\\\\/g; s/"/\\"/g')
    _status_tmp="$_status_dir/.adblock-status.$$"
    if printf '%s\n' "{\"schema\":2,\"checked_at\":$_now,\"last_success_at\":$_success,\"outcome\":\"$_outcome\",\"sources_configured\":$SOURCES_TOTAL,\"sources_used\":$_used,\"sources_skipped\":\"$_skipped_json\",\"domains\":$_domains,\"reason\":\"$_reason_json\",\"sources\":[$_details]}" > "$_status_tmp" \
        && chmod 0640 "$_status_tmp" \
        && mv -f "$_status_tmp" "$STATUS_FILE"; then
        return 0
    fi
    rm -f "$_status_tmp" 2>/dev/null || true
    log "WARNING: cannot record the blocklist run status at $STATUS_FILE"
    return 0
}

fail() { log "ERROR: $*"; write_status failed "$*"; exit 1; }

# Decided under the lock, so a rebuild finishing right now cannot be missed.
if [ "$IF_CHANGED" = 1 ]; then
    _wanted="$WORKDIR/inputs"
    if ! write_inputs "$_wanted"; then
        log "cannot read blocklist inputs; rebuilding"
    elif [ ! -s "$BLOCKLIST" ]; then
        log "no blocklist published yet; rebuilding"
    elif [ ! -f "$STAMP_FILE" ] || [ -L "$STAMP_FILE" ]; then
        log "no record of what the blocklist was built from; rebuilding"
    elif cmp -s "$_wanted" "$STAMP_FILE"; then
        log "Blocklist inputs unchanged; keeping the published list"
        write_status unchanged ""
        exit 0
    else
        log "Blocklist inputs changed; rebuilding"
    fi
fi

case "$MIN_DOMAINS:$MAX_BYTES:$MIN_RATIO" in *[!0-9:]*) fail "invalid domain, ratio or response-size limit" ;; esac
[ "$MIN_DOMAINS" -gt 0 ] || fail "minimum domain count must be positive"
[ "$MIN_RATIO" -ge 0 ] && [ "$MIN_RATIO" -le 100 ] || fail "shrink guard must be a percentage"
[ "$MAX_BYTES" -ge 1024 ] || fail "response-size limit is too small"
[ -n "$SOURCE_URLS" ] || fail "no blocklist source configured"
for _url in $SOURCE_URLS; do
    case "$_url" in https://*|http://*) ;; *) fail "blocklist URL must use http or https: $_url" ;; esac
    printf '%s\n' "$_url" | grep -Eq '^https?://[^[:space:]]+$' || fail "blocklist URL contains whitespace"
done
case "$ADBLOCK_VERDICT" in
    always_null|always_nxdomain|always_refuse) ;;
    *) fail "unsupported blocklist verdict: $ADBLOCK_VERDICT" ;;
esac
for command in fetch awk sort comm wc unbound-checkconf; do
    command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[ -f "$UNBOUND_CONF" ] || fail "Unbound config not found: $UNBOUND_CONF"
[ ! -L "$UNBOUND_CONF" ] || fail "refusing symlink Unbound config: $UNBOUND_CONF"
if [ -e "$BLOCKLIST" ]; then
    [ -f "$BLOCKLIST" ] && [ ! -L "$BLOCKLIST" ] || fail "refusing unsafe blocklist path: $BLOCKLIST"
fi

if [ "$SCRATCH_IN_RAM" = yes ]; then
    log "Scratch in RAM: $ADBLOCK_TMPFS (size=$ADBLOCK_TMPFS_SIZE)"
else
    log "Scratch on disk: ${TMPDIR:-/tmp} (tmpfs unavailable)"
fi
log "Downloading blocklists"
_file_blocks=$(( (MAX_BYTES + 511) / 512 ))
: > "$WORKDIR/sources"
_index=0
for _url in $SOURCE_URLS; do
    _index=$((_index + 1))
    _download="$WORKDIR/source.$_index"
    if ! (ulimit -f "$_file_blocks" 2>/dev/null || true; fetch -q -T 180 -o "$_download" "$_url"); then
        printf '%s\t%s\t%s\t%s\t%s\n' "$_index" "$_url" 0 rejected download_failed > "$WORKDIR/meta.$_index"
        SOURCES_FAILED="$SOURCES_FAILED $_url"
        log "WARNING: download failed, skipping source: $_url"
        continue
    fi
    _size=$(stat -f '%z' "$_download" 2>/dev/null || printf '%s' 0)
    if [ "$_size" -le 0 ] || [ "$_size" -gt "$MAX_BYTES" ]; then
        printf '%s\t%s\t%s\t%s\t%s\n' "$_index" "$_url" 0 rejected invalid_size > "$WORKDIR/meta.$_index"
        SOURCES_FAILED="$SOURCES_FAILED $_url"
        log "WARNING: unusable size $_size, skipping source: $_url"
        continue
    fi
    _downloaded=$(wc -l < "$_download" | tr -d '[:space:]')
    printf '%s\t%s\t%s\t%s\t%s\n' "$_index" "$_url" "$_downloaded" ok '' > "$WORKDIR/meta.$_index"
    printf '# GATEBSD_SOURCE %s\n' "$_index" >> "$WORKDIR/sources"
    cat "$_download" >> "$WORKDIR/sources"
    printf '\n' >> "$WORKDIR/sources"
    SOURCES_OK=$((SOURCES_OK + 1))
done
SOURCES_MEASURED=1

# How many feeds this run is required to have. The shrink guard below counts
# DOMAINS, and that is why it missed this: on 4 August one of six sources
# failed to download, the run published 307943 names instead of 384499, and
# 80% is comfortably above the 50% floor. A whole feed vanishing is
# indistinguishable, to a domain count, from a quiet day at the filter authors.
#
# A missing feed is not "fewer new names". It is a failed download, and a
# failed download must not be published quietly.
#
# The bar is the number of sources the CURRENTLY PUBLISHED list was built from,
# capped by how many are configured now -- the same shape as the shrink guard,
# which compares against what is live rather than against a constant:
#
#   six configured, six published, five downloaded -> refuse, a feed dropped
#   five configured, six published, five downloaded -> publish, we removed one
#   nothing published yet, five of six downloaded   -> publish, see below
#
# The middle case is what makes retiring a dead feed a normal release rather
# than a fight with this guard, and that matters, because refusing is not free:
# while a feed stays down the list is frozen, and names we add to adblock-extra
# do not reach the resolver either. The answer to a feed that is gone for good
# is to take its URL out of SOURCE_URLS and ship that -- which is why this
# refusal has to be visible in the panel and not only here in the log.
#
# The last case is deliberate: on a freshly flashed device there is nothing to
# preserve, and a partial list beats no filtering at all.
PREVIOUS_SOURCES=0
if [ -f "$BLOCKLIST" ] && [ ! -L "$BLOCKLIST" ]; then
    PREVIOUS_SOURCES=$(awk '/^# Sources used: [0-9]+$/ { print $4; exit }' "$BLOCKLIST" || printf '%s' 0)
    case "$PREVIOUS_SOURCES" in ''|*[!0-9]*) PREVIOUS_SOURCES=0 ;; esac
fi
if [ "$PREVIOUS_SOURCES" -le 0 ]; then
    # No published list, or one written before this header existed. Nothing to
    # compare against, so only the original rule applies for this one run; the
    # next run has a header and the guard engages by itself.
    REQUIRED_SOURCES=1
elif [ "$PREVIOUS_SOURCES" -lt "$SOURCES_TOTAL" ]; then
    REQUIRED_SOURCES=$PREVIOUS_SOURCES
else
    REQUIRED_SOURCES=$SOURCES_TOTAL
fi
[ "$SOURCES_OK" -ge "$REQUIRED_SOURCES" ] || fail "only $SOURCES_OK of $REQUIRED_SOURCES sources downloaded; current blocklist preserved (skipped:$SOURCES_FAILED)"

# Tested for readability before being read: a missing file is the normal case
# on a device that never added anything, and under `set -e` a bare cat of one
# kills the update on the spot.
if [ -r "$EXTRA_FILE" ]; then
    if [ -x "$PYTHON_LAUNCHER" ] && env -i PATH="$PATH" LANG=C.UTF-8 PYTHONPATH="$PYTHONPATH_VALUE" \
        "$PYTHON_LAUNCHER" -m gatebsd_ui.resolver --normalize-adblock-extra "$EXTRA_FILE" >> "$WORKDIR/sources" 2>/dev/null; then
        printf '\n' >> "$WORKDIR/sources"
    else
        cat "$EXTRA_FILE" >> "$WORKDIR/sources"
        printf '\n' >> "$WORKDIR/sources"
    fi
    log "Merged local additions from $EXTRA_FILE"
fi

# Two formats. hosts lines ("0.0.0.0 example.com") are what this always read.
# Adblock Plus syntax is what the mobile and RU lists publish, and only its
# unambiguous subset is taken: "||domain^" with nothing after the separator.
# Anything carrying a path, a wildcard or $options describes a request, not a
# name, and a resolver cannot honour it -- treating those as domain blocks is
# how a DNS blocklist starts breaking sites its author never intended to touch.
#
# "@@||domain^" is the author's exception to their own rules, so those names
# are collected and subtracted at the end rather than ignored.
awk -v block_file="$WORKDIR/block.list" -v allow_file="$WORKDIR/allow.list" -v parsed_dir="$WORKDIR" '
    function clean(domain) {
        sub(/\.$/, "", domain)
        return tolower(domain)
    }
    function acceptable(domain,   labels, part, j) {
        if (domain == "" || domain == "localhost" || domain == "localhost.localdomain" || domain == "broadcasthost") return 0
        if (length(domain) > 253 || domain !~ /^[a-z0-9.-]+$/ || domain ~ /\.\./) return 0
        labels = split(domain, part, ".")
        if (labels < 2) return 0
        for (j = 1; j <= labels; j++) {
            if (length(part[j]) < 1 || length(part[j]) > 63) return 0
            if (part[j] !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) return 0
        }
        if (domain ~ /\.local$/ || domain ~ /\.lan$/ || domain ~ /\.invalid$/) return 0
        # A name whose last label is all digits is an ADDRESS, not a domain.
        # Some sources carry "0.0.0.0 203.0.113.7" -- blocking by address in a
        # file that can only express names -- and every label of that passes
        # the structural checks above, so 73 of them were sitting in the live
        # blocklist as local-zone entries for names nobody will ever look up.
        # Harmless, but a list that claims to hold domains should hold domains.
        # No real TLD is numeric, so this rejects addresses and nothing else.
        if (part[labels] ~ /^[0-9]+$/) return 0
        return 1
    }
    {
        sub(/\r$/, "")
        line = $0
        if (line ~ /^# GATEBSD_SOURCE [0-9]+$/) { source_index = $3; next }
        if (line ~ /^[[:space:]]*$/) next

        # Adblock Plus exception, then block. Checked before the comment rule:
        # "!" starts a comment there, "#" does not always.
        if (line ~ /^@@\|\|[A-Za-z0-9.-]+\^$/) {
            domain = clean(substr(line, 5, length(line) - 5))
            if (acceptable(domain)) print domain > allow_file
            next
        }
        if (line ~ /^\|\|[A-Za-z0-9.-]+\^$/) {
            domain = clean(substr(line, 3, length(line) - 3))
            if (acceptable(domain)) { print domain > block_file; parsed[source_index]++ }
            next
        }
        if (line ~ /^[[:space:]]*[#!]/) next

        address = tolower($1)
        if (address != "0.0.0.0" && address != "127.0.0.1") next
        for (i = 2; i <= NF; i++) {
            domain = tolower($i)
            if (domain ~ /^#/) break
            while (domain ~ /^(0\.0\.0\.0|127\.0\.0\.1)\./) {
                sub(/^(0\.0\.0\.0|127\.0\.0\.1)\./, "", domain)
            }
            domain = clean(domain)
            if (acceptable(domain)) { print domain > block_file; parsed[source_index]++ }
        }
    }
    END {
        if (parsed_dir != "") { for (source_id in parsed) print parsed[source_id] > (parsed_dir "/parsed." source_id) }
    }
' "$WORKDIR/sources"

: >> "$WORKDIR/block.list"
: >> "$WORKDIR/allow.list"
sort -u "$WORKDIR/block.list" > "$WORKDIR/block.sorted"
sort -u "$WORKDIR/allow.list" > "$WORKDIR/allow.sorted"
comm -23 "$WORKDIR/block.sorted" "$WORKDIR/allow.sorted" > "$WORKDIR/final.list"
EXCLUDED=$(comm -12 "$WORKDIR/block.sorted" "$WORKDIR/allow.sorted" | wc -l | tr -d ' ')

{
    printf '# GateBSD Ad Blocker\n'
    printf '# Sources: %s\n' "$SOURCE_URLS"
    printf '# Sources used: %s\n' "$SOURCES_OK"
    printf '# Verdict: %s\n' "$ADBLOCK_VERDICT"
    printf '# Allowlisted by source authors: %s\n' "$EXCLUDED"
    printf '# Generated: %s\n' "$(date -u '+%Y-%m-%d %H:%M UTC')"
    printf '# Total: __TOTAL__ domains\n'
    printf 'server:\n'
    awk -v verdict="$ADBLOCK_VERDICT" '{ print "    local-zone: \"" $0 ".\" " verdict }' "$WORKDIR/final.list"
} > "$WORKDIR/adblock.conf.raw"

TOTAL=$(grep -c '^[[:space:]]*local-zone:' "$WORKDIR/adblock.conf.raw" || true)
[ "$TOTAL" -ge "$MIN_DOMAINS" ] || fail "only $TOTAL domains parsed; refusing to replace current list"

# A source that answers 200 with a truncated or reshaped body passes every
# check above and still halves the list. Compare against what is already
# published: a large shrink is a bad download, not a quiet day at the filter
# authors. Only guards downwards -- growth is what an update is for.
if [ -f "$BLOCKLIST" ]; then
    PREVIOUS=$(grep -c '^[[:space:]]*local-zone:' "$BLOCKLIST" 2>/dev/null || printf '%s' 0)
    if [ "$PREVIOUS" -gt 0 ]; then
        _floor=$(( PREVIOUS * MIN_RATIO / 100 ))
        [ "$TOTAL" -ge "$_floor" ] || fail "$TOTAL domains is under $MIN_RATIO% of the published $PREVIOUS; refusing to replace current list"
    fi
fi
sed "s/__TOTAL__/$TOTAL/" "$WORKDIR/adblock.conf.raw" > "$WORKDIR/adblock.conf"
unbound-checkconf "$WORKDIR/adblock.conf" >/dev/null 2>&1 || fail "generated blocklist has invalid Unbound syntax"

BLOCK_DIR=$(dirname "$BLOCKLIST")
CONF_DIR=$(dirname "$UNBOUND_CONF")
mkdir -p "$BLOCK_DIR"
BLOCK_TMP=$(mktemp "$BLOCK_DIR/.adblock.conf.XXXXXX")
CONF_TMP=$(mktemp "$CONF_DIR/.unbound.conf.XXXXXX")
BLOCK_BACKUP="$WORKDIR/blocklist.previous"
CONF_BACKUP="$WORKDIR/unbound.previous"
BLOCK_EXISTED=0

if [ -f "$BLOCKLIST" ]; then
    cp -p "$BLOCKLIST" "$BLOCK_BACKUP"
    BLOCK_EXISTED=1
fi
cp -p "$UNBOUND_CONF" "$CONF_BACKUP"

rollback() {
    _rollback_failed=0
    log "Rolling back adblock configuration"

    if [ "$BLOCK_EXISTED" -eq 1 ]; then
        if ! rm -f "$BLOCK_TMP" 2>/dev/null; then
            _rollback_failed=1
        fi
        if cp -p "$BLOCK_BACKUP" "$BLOCK_TMP" && mv -f "$BLOCK_TMP" "$BLOCKLIST"; then
            :
        else
            _rollback_failed=1
            log "ERROR: failed to restore previous blocklist"
        fi
    else
        if ! rm -f "$BLOCKLIST" "$BLOCK_TMP" 2>/dev/null; then
            _rollback_failed=1
            log "ERROR: failed to remove newly published blocklist"
        fi
    fi

    if ! rm -f "$CONF_TMP" 2>/dev/null; then
        _rollback_failed=1
    fi
    if cp -p "$CONF_BACKUP" "$CONF_TMP" && mv -f "$CONF_TMP" "$UNBOUND_CONF"; then
        :
    else
        _rollback_failed=1
        log "ERROR: failed to restore previous Unbound configuration"
    fi

    if service unbound reload >/dev/null 2>&1 || service unbound restart >/dev/null 2>&1; then
        :
    else
        _rollback_failed=1
        log "ERROR: previous files were restored but Unbound did not reload"
    fi

    [ "$_rollback_failed" -eq 0 ]
}

install -m 0644 "$WORKDIR/adblock.conf" "$BLOCK_TMP"

if awk -v target="$BLOCKLIST" '
    function include_path(line) {
        sub(/^[[:space:]]*include:[[:space:]]*/, "", line)
        sub(/[[:space:]]+#.*$/, "", line)
        sub(/^[[:space:]]*/, "", line)
        sub(/[[:space:]]*$/, "", line)
        if (line ~ /^".*"$/) {
            sub(/^"/, "", line)
            sub(/"$/, "", line)
        }
        return line
    }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*include:[[:space:]]*/ {
        if (include_path($0) == target) found=1
    }
    END { exit found ? 0 : 1 }
' "$UNBOUND_CONF"; then
    cp -p "$UNBOUND_CONF" "$CONF_TMP"
else
    cat "$UNBOUND_CONF" > "$CONF_TMP"
    printf '\n# GateBSD DNS ad/tracker blocking\n%s\n' "$INCLUDE_LINE" >> "$CONF_TMP"
fi
CONF_MODE=$(stat -f '%Lp' "$UNBOUND_CONF" 2>/dev/null || true)
case "$CONF_MODE" in
    [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
    *) CONF_MODE=0644 ;;
esac
chmod "$CONF_MODE" "$CONF_TMP" || fail "cannot preserve Unbound config mode"

# Validate the exact candidate blocklist through a temporary include path.
# The parser accepts both quoted and unquoted include directives, but rejects
# duplicate matching includes because their load order would be ambiguous.
CHECK_CONF="$WORKDIR/unbound.check.conf"
if ! awk -v final="$BLOCKLIST" -v candidate="$BLOCK_TMP" '
    function include_path(line) {
        sub(/^[[:space:]]*include:[[:space:]]*/, "", line)
        sub(/[[:space:]]+#.*$/, "", line)
        sub(/^[[:space:]]*/, "", line)
        sub(/[[:space:]]*$/, "", line)
        if (line ~ /^".*"$/) {
            sub(/^"/, "", line)
            sub(/"$/, "", line)
        }
        return line
    }
    {
        line=$0
        if (line !~ /^[[:space:]]*#/ && line ~ /^[[:space:]]*include:[[:space:]]*/ && include_path(line) == final) {
            indent=line
            sub(/[^[:space:]].*$/, "", indent)
            print indent "include: \"" candidate "\""
            replaced++
            next
        }
        print line
    }
    END { exit replaced == 1 ? 0 : 1 }
' "$CONF_TMP" > "$CHECK_CONF"; then
    fail "cannot construct an unambiguous candidate Unbound configuration"
fi
if ! unbound-checkconf "$CHECK_CONF" >/dev/null 2>&1; then
    fail "combined Unbound configuration is invalid"
fi

if ! mv -f "$BLOCK_TMP" "$BLOCKLIST"; then
    fail "failed to publish blocklist"
fi
if ! mv -f "$CONF_TMP" "$UNBOUND_CONF"; then
    if rollback; then
        fail "failed to publish Unbound configuration; previous configuration restored"
    fi
    fail "failed to publish Unbound configuration and rollback was incomplete"
fi

if ! service unbound reload >/dev/null 2>&1; then
    if ! service unbound restart >/dev/null 2>&1; then
        if rollback; then
            fail "Unbound failed to load the new blocklist; previous configuration restored"
        fi
        fail "Unbound failed to load the new blocklist and rollback was incomplete"
    fi
fi

log "Adblock active: $TOTAL domains from $SOURCES_OK source(s), verdict $ADBLOCK_VERDICT"
[ -z "$SOURCES_FAILED" ] || log "WARNING: sources skipped:$SOURCES_FAILED"

# Record what this run built from, now that it is live. Written last and
# published atomically: a stamp that ran ahead of the blocklist would tell the
# next upgrade there was nothing to do while the old list was still in place --
# the very failure this stamp exists to prevent.
#
# A stamp that cannot be written is logged and not fatal. The list is already
# serving; the only cost is that the next upgrade rebuilds when it need not.
_stamp_dir=$(dirname "$STAMP_FILE")
_stamp_tmp="$_stamp_dir/.adblock-inputs.$$"
if [ -d "$_stamp_dir" ] && [ ! -L "$_stamp_dir" ] \
    && write_inputs "$_stamp_tmp" \
    && chmod 0640 "$_stamp_tmp" \
    && mv -f "$_stamp_tmp" "$STAMP_FILE"; then
    :
else
    rm -f "$_stamp_tmp"
    log "WARNING: cannot record the blocklist inputs at $STAMP_FILE"
fi

# Last, like the stamp, and for the same reason: it describes a list that is
# already serving.
write_status published ""
exit 0
