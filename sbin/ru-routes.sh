#!/bin/sh
# Transactionally synchronise RU bypass routes with compensating rollback.
set -eu

PATH=${GATEBSD_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}
CONF=${GATEBSD_GATEWAY_CONF:-/usr/local/etc/amnezia/gateway.conf}
RU_TABLE=${RU_TABLE:-/usr/local/etc/amnezia/ru_bypass.table}
STATE_FILE=${RU_STATE_FILE:-/var/db/gatebsd-system/ru-routes.applied}
VPN_OVERRIDE_TABLE=${GATEBSD_VPN_OVERRIDE_TABLE:-$(dirname "$RU_TABLE")/vpn_override.table}
VPN_OVERRIDE_STATE_FILE=${VPN_OVERRIDE_STATE_FILE:-$(dirname "$STATE_FILE")/vpn-override.applied}
WATCHDOG_STATE=${GATEBSD_WATCHDOG_STATE:-/var/run/gatebsd/watchdog.json}
STATE_READER=${GATEBSD_STATE_READER:-/usr/local/sbin/gatebsd-state-value}
LOCK_FILE=${GATEBSD_RU_ROUTE_LOCK:-${GATEBSD_GATEWAY_LOCK_FILE:-/var/run/gatebsd/gatewayctl.lock}}
ACTION=${1:-apply}

log() { logger -t ru-routes "$*" 2>/dev/null || true; printf '[ru-routes] %s\n' "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

safe_source() {
    _path=$1
    [ -e "$_path" ] || return 0
    [ -f "$_path" ] && [ ! -L "$_path" ] || die "unsafe config: $_path"
    _uid=$(stat -f '%u' "$_path" 2>/dev/null || printf '%s' -1)
    _mode=$(stat -f '%Lp' "$_path" 2>/dev/null || printf '%s' 777)
    [ "$_uid" = 0 ] || die "config must be owned by root: $_path"
    case "$_mode" in
        *[2367][0-7]|*[0-7][2367]) die "config must not be group/world writable: $_path" ;;
    esac
    # shellcheck disable=SC1090 -- path is fixed or root-controlled and validated.
    . "$_path"
}
safe_source "$CONF"

WAN_IF=${GATEBSD_ACTIVE_WAN_IF:-${WAN_IF:-ng0}}
BACKUP_IF=${BACKUP_IF:-ue0}
VPN_IF=${GATEBSD_VPN_IF:-${VPN_IF:-awg0}}
APPLY_TIMEOUT=${GATEBSD_RU_APPLY_TIMEOUT:-${RU_APPLY_TIMEOUT:-300}}
# Shortest bypass prefix accepted. On FreeBSD 0.0.0.0/0 *is* the default route,
# so a /0 entry would let the bypass table hijack the default and then delete it
# during a clear -- with the clear reporting success. Anything wider than /8 is
# also refused: no legitimate country-scoped bypass entry needs it, and the
# blast radius of a bad one is most of the internet.
MIN_PREFIX_LEN=${GATEBSD_RU_MIN_PREFIX_LEN:-8}
case "$MIN_PREFIX_LEN" in
    ''|*[!0-9]*) MIN_PREFIX_LEN=8 ;;
esac
[ "$MIN_PREFIX_LEN" -ge 1 ] || MIN_PREFIX_LEN=8
[ "$MIN_PREFIX_LEN" -le 32 ] || MIN_PREFIX_LEN=8

is_iface() {
    [ -n "$1" ] && [ ${#1} -le 32 ] || return 1
    case "$1" in *[!A-Za-z0-9_.-]*|[0-9.-]*) return 1 ;; esac
}
ensure_private_root_dir() {
    _dir=$1
    _group=${2:-wheel}
    if [ -e "$_dir" ] || [ -L "$_dir" ]; then
        [ -d "$_dir" ] && [ ! -L "$_dir" ] || die "unsafe directory: $_dir"
        _uid=$(stat -f '%u' "$_dir" 2>/dev/null || printf '%s' -1)
        _mode=$(stat -f '%Lp' "$_dir" 2>/dev/null || printf '%s' 777)
        [ "$_uid" = 0 ] || die "directory must be root-owned: $_dir"
        case "$_mode" in
            *[2367][0-7]|*[0-7][2367]) die "directory must not be group/world writable: $_dir" ;;
        esac
    else
        install -d -o root -g "$_group" -m 0750 "$_dir"
    fi
}

is_ipv4() {
    printf '%s\n' "$1" | awk -F. '
        NF != 4 {exit 1}
        { for (i=1; i<=4; i++) if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1 }
    '
}
is_iface "$WAN_IF" || die "invalid WAN interface: $WAN_IF"
is_iface "$VPN_IF" || die "invalid VPN interface: $VPN_IF"
case "$APPLY_TIMEOUT" in ''|*[!0-9]*) die "invalid route transaction timeout: $APPLY_TIMEOUT" ;; esac
[ "$APPLY_TIMEOUT" -ge 30 ] && [ "$APPLY_TIMEOUT" -le 3600 ] \
    || die "route transaction timeout must be between 30 and 3600 seconds"
[ -x "$STATE_READER" ] || die "state reader is unavailable: $STATE_READER"

if [ "${GATEBSD_RU_ROUTE_LOCK_HELD:-0}" != 1 ] && [ "${GATEBSD_GATEWAY_LOCK_HELD:-0}" != 1 ]; then
    ensure_private_root_dir "$(dirname "$LOCK_FILE")" gatebsd
    exec env -i PATH="$PATH" GATEBSD_PATH="$PATH" HOME=/root LANG=C.UTF-8 \
        GATEBSD_RU_ROUTE_LOCK_HELD=1 \
        GATEBSD_GATEWAY_CONF="$CONF" RU_TABLE="$RU_TABLE" \
        RU_STATE_FILE="$STATE_FILE" GATEBSD_WATCHDOG_STATE="$WATCHDOG_STATE" \
        GATEBSD_VPN_OVERRIDE_TABLE="$VPN_OVERRIDE_TABLE" \
        VPN_OVERRIDE_STATE_FILE="$VPN_OVERRIDE_STATE_FILE" \
        GATEBSD_RU_ROUTE_LOCK="$LOCK_FILE" GATEBSD_ACTIVE_WAN_IF="$WAN_IF" \
        GATEBSD_VPN_IF="$VPN_IF" \
        GATEBSD_STATE_READER="$STATE_READER" \
        GATEBSD_RU_APPLY_TIMEOUT="$APPLY_TIMEOUT" \
        BACKUP_IF="$BACKUP_IF" GATEBSD_ACTIVE_WAN_GW="${GATEBSD_ACTIVE_WAN_GW:-}" \
        lockf -T -k -t 5 "$LOCK_FILE" "$0" "$@"
fi

for _path in "$RU_TABLE" "$STATE_FILE" "$VPN_OVERRIDE_TABLE" "$VPN_OVERRIDE_STATE_FILE"; do
    if [ -e "$_path" ] || [ -L "$_path" ]; then
        [ -f "$_path" ] && [ ! -L "$_path" ] || die "unsafe file: $_path"
    fi
done

# Work out which underlay is active and what its gateway is, setting WAN_IF and
# GW. Both, together, because they are one fact.
#
# This must be called plainly -- `resolve_wan || true` -- and never through a
# command substitution. It used to be a function that printed the gateway,
# called as `GW=$(wan_gw)`, and the correction it makes to WAN_IF for a backup
# underlay therefore died with the subshell that ran it. Routing stayed correct
# (prefixes are installed by gateway alone, `route add -net <prefix> $GW`), but
# every log line and the "no valid WAN gateway" error paired the new gateway
# with the interface it did not belong to -- `gateway=192.168.0.1 interface=ng0`
# during the 1 August outage, which cost real time to disbelieve. The same trap
# has already cost this project the finding counter in verify-deployment.sh.
resolve_wan() {
    GW=
    if [ -n "${GATEBSD_ACTIVE_WAN_GW:-}" ]; then
        # The caller already knows which underlay it is acting for and passed
        # both halves; do not second-guess it from shared state.
        is_ipv4 "$GATEBSD_ACTIVE_WAN_GW" || return 1
        GW=$GATEBSD_ACTIVE_WAN_GW
        return 0
    fi
    _active=
    if [ -r "$WATCHDOG_STATE" ]; then
        _active=$("$STATE_READER" "$WATCHDOG_STATE" active_wan) || return 1
    fi
    if [ "$_active" = backup ]; then
        WAN_IF=$BACKUP_IF
    fi
    # The next hop is a field. An encapsulating interface prints `tunnel inet A
    # --> B` above its address, and that line matches the shape too -- see the
    # note over pppoe_gw in gatebsd-watchdog.sh.
    _gateway=$(ifconfig "$WAN_IF" 2>/dev/null | awk '$1 == "inet" && $3 == "-->" {print $4; exit}')
    if ! is_ipv4 "$_gateway" && [ "$WAN_IF" = "$BACKUP_IF" ]; then
        _gateway=$(awk '/option routers/ {gsub(";","",$3); g=$3} END{print g}' "/var/db/dhclient.leases.${WAN_IF}" 2>/dev/null)
    fi
    is_ipv4 "$_gateway" || return 1
    GW=$_gateway
}

route_gateway() {
    _addr=${1%/*}
    route -n get "$_addr" 2>/dev/null | awk '/gateway:/ {print $2; exit}'
}

route_interface() {
    _addr=${1%/*}
    route -n get "$_addr" 2>/dev/null | awk '/interface:/ {print $2; exit}'
}

STATE_DIR=$(dirname "$STATE_FILE")
ensure_private_root_dir "$STATE_DIR" wheel
ensure_private_root_dir "$(dirname "$VPN_OVERRIDE_STATE_FILE")" wheel
WORKDIR=$(mktemp -d "$STATE_DIR/.ru-routes.XXXXXX") || die "cannot allocate work directory"
CANDIDATE="$WORKDIR/candidate"
PREVIOUS="$WORKDIR/previous"
PREFIXES="$WORKDIR/prefixes"
OBSOLETE="$WORKDIR/obsolete"
SNAPSHOT="$WORKDIR/snapshot"
TOUCHED="$WORKDIR/touched"
ROLLBACK_PLAN="$WORKDIR/rollback-plan"
OVERRIDE_CANDIDATE="$WORKDIR/override-candidate"
OVERRIDE_PREVIOUS="$WORKDIR/override-previous"
OVERRIDE_OBSOLETE="$WORKDIR/override-obsolete"
OVERRIDE_TOUCHED="$WORKDIR/override-touched"
: > "$CANDIDATE"
: > "$PREVIOUS"
: > "$PREFIXES"
: > "$OBSOLETE"
: > "$SNAPSHOT"
: > "$TOUCHED"
: > "$ROLLBACK_PLAN"
: > "$OVERRIDE_CANDIDATE"
: > "$OVERRIDE_PREVIOUS"
: > "$OVERRIDE_OBSOLETE"
: > "$OVERRIDE_TOUCHED"

TRANSACTION_ACTIVE=0
TRANSACTION_KIND=
DEADLINE=0
DEADLINE_COUNTER=0

publish_state_file() {
    _source=$1
    _dest=$2
    _new="$WORKDIR/state.new"
    install -o root -g wheel -m 0640 "$_source" "$_new"
    mv -f "$_new" "$_dest"
}

publish_state() {
    publish_state_file "$1" "$STATE_FILE"
}

rollback_routes() {
    _failed=0
    : > "$ROLLBACK_PLAN"
    awk -F '\t' '
        NR == FNR { previous[$1] = $2; next }
        $1 in previous && !seen[$1]++ { print $1 "\t" previous[$1] }
    ' "$SNAPSHOT" "$TOUCHED" > "$ROLLBACK_PLAN"
    while IFS="$(printf '\t')" read -r _prefix _gateway; do
        [ -n "$_prefix" ] || continue
        if [ "$_gateway" = - ]; then
            route delete -net "$_prefix" >/dev/null 2>&1 || true
        elif ! route change -net "$_prefix" "$_gateway" >/dev/null 2>&1 \
                && ! route add -net "$_prefix" "$_gateway" >/dev/null 2>&1; then
            _failed=1
            log "rollback failed for $_prefix via $_gateway"
        fi
    done < "$ROLLBACK_PLAN"
    if [ -s "$OVERRIDE_TOUCHED" ]; then
        _override_plan="$WORKDIR/override-rollback-plan"
        awk '!seen[$0]++' "$OVERRIDE_TOUCHED" > "$_override_plan"
        while IFS= read -r _prefix; do
            [ -n "$_prefix" ] || continue
            if grep -Fxq "$_prefix" "$OVERRIDE_PREVIOUS"; then
                if ! route change -net "$_prefix" -interface "$VPN_IF" >/dev/null 2>&1 \
                        && ! route add -net "$_prefix" -interface "$VPN_IF" >/dev/null 2>&1; then
                    _failed=1
                    log "rollback failed for override $_prefix via $VPN_IF"
                fi
            else
                route delete -net "$_prefix" >/dev/null 2>&1 || true
            fi
        done < "$_override_plan"
    fi
    return "$_failed"
}

rollback_transaction() {
    _rollback_failed=0
    rollback_routes || _rollback_failed=1
    if [ "$TRANSACTION_KIND" = clear ]; then
        publish_state "$PREVIOUS" || _rollback_failed=1
        if [ -s "$OVERRIDE_PREVIOUS" ]; then
            publish_state_file "$OVERRIDE_PREVIOUS" "$VPN_OVERRIDE_STATE_FILE" || _rollback_failed=1
        fi
    fi
    return "$_rollback_failed"
}

on_exit() {
    _rc=$?
    trap - EXIT HUP INT TERM
    if [ "$TRANSACTION_ACTIVE" -eq 1 ]; then
        log "interrupted route transaction; restoring the previous route set"
        rollback_transaction || log "CRITICAL: interrupted route transaction rollback was incomplete"
        TRANSACTION_ACTIVE=0
    fi
    rm -rf "$WORKDIR"
    exit "$_rc"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

start_deadline() {
    _now=$(date +%s) || die "cannot read system clock"
    DEADLINE=$((_now + APPLY_TIMEOUT))
    DEADLINE_COUNTER=0
}

deadline_ok() {
    DEADLINE_COUNTER=$((DEADLINE_COUNTER + 1))
    if [ "$DEADLINE_COUNTER" -lt 32 ]; then
        return 0
    fi
    DEADLINE_COUNTER=0
    _now=$(date +%s) || return 1
    [ "$_now" -lt "$DEADLINE" ]
}

deadline_or_die() {
    deadline_ok || die "route transaction exceeded ${APPLY_TIMEOUT}s while $1"
}

validate_prefix_file() {
    _src=$1
    _dest=$2
    _label=$3
    _allow_comments=$4
    _raw="$WORKDIR/$(basename "$_dest").raw"
    if ! awk -v minlen="$MIN_PREFIX_LEN" -v comments="$_allow_comments" -v label="$_label" '
        function invalid() {
            printf "invalid %s prefix at line %d: %s\n", label, NR, $0 > "/dev/stderr"
            exit 2
        }
        {
            if (comments == 1) {
                sub(/\r$/, "")
                gsub(/^[[:space:]]+/, "")
                gsub(/[[:space:]]+$/, "")
                if ($0 == "" || substr($0, 1, 1) == "#") next
            } else if ($0 == "") {
                next
            }
            # A prefix length below MIN_PREFIX_LEN is refused outright.
            # 0.0.0.0/0 is the default route on FreeBSD: accepting it lets a
            # bypass entry hijack and then delete the default route, and
            # near-zero lengths would blackhole most of the internet.
            if (split($0, network, "/") != 2 || network[2] !~ /^[0-9]+$/ \
                    || network[2] + 0 < minlen || network[2] + 0 > 32) invalid()
            if (split(network[1], octet, "[.]") != 4) invalid()
            for (i = 1; i <= 4; i++) {
                if (octet[i] !~ /^[0-9]+$/ || octet[i] < 0 || octet[i] > 255) invalid()
            }
            print network[1] "/" network[2]
        }
    ' "$_src" > "$_raw"; then
        die "$_label validation failed"
    fi
    LC_ALL=C sort -u "$_raw" > "$_dest"
}

normalise_table() {
    [ -r "$RU_TABLE" ] || die "RU table is missing: $RU_TABLE"
    validate_prefix_file "$RU_TABLE" "$CANDIDATE" "RU table" 1
}

normalise_override_table() {
    : > "$OVERRIDE_CANDIDATE"
    [ -s "$VPN_OVERRIDE_TABLE" ] || return 0
    [ -r "$VPN_OVERRIDE_TABLE" ] || die "VPN override table is unreadable: $VPN_OVERRIDE_TABLE"
    validate_prefix_file "$VPN_OVERRIDE_TABLE" "$OVERRIDE_CANDIDATE" "VPN override table" 1
}

load_previous_state() {
    : > "$PREVIOUS"
    [ -f "$STATE_FILE" ] || return 0
    validate_prefix_file "$STATE_FILE" "$PREVIOUS" "RU route state" 0
}

load_previous_override_state() {
    : > "$OVERRIDE_PREVIOUS"
    [ -f "$VPN_OVERRIDE_STATE_FILE" ] || return 0
    validate_prefix_file "$VPN_OVERRIDE_STATE_FILE" "$OVERRIDE_PREVIOUS" "VPN override state" 0
}

runtime_matches_candidate() {
    [ -f "$STATE_FILE" ] || return 1
    cmp -s "$CANDIDATE" "$PREVIOUS" || return 1
    for _prefix in "$(sed -n '1p' "$PREVIOUS")" "$(sed -n '$p' "$PREVIOUS")"; do
        [ -n "$_prefix" ] || continue
        [ "$(route_gateway "$_prefix" || true)" = "$GW" ] || return 1
    done
    if [ -s "$OVERRIDE_CANDIDATE" ] || [ -s "$OVERRIDE_PREVIOUS" ]; then
        [ -f "$VPN_OVERRIDE_STATE_FILE" ] || return 1
        cmp -s "$OVERRIDE_CANDIDATE" "$OVERRIDE_PREVIOUS" || return 1
        for _prefix in "$(sed -n '1p' "$OVERRIDE_PREVIOUS")" "$(sed -n '$p' "$OVERRIDE_PREVIOUS")"; do
            [ -n "$_prefix" ] || continue
            [ "$(route_interface "$_prefix" || true)" = "$VPN_IF" ] || return 1
        done
    fi
}

prepare_snapshot() {
    LC_ALL=C sort -u "$CANDIDATE" "$PREVIOUS" > "$PREFIXES"
    : > "$SNAPSHOT"
    while IFS= read -r _prefix; do
        [ -n "$_prefix" ] || continue
        deadline_or_die "preparing rollback snapshot"
        _old=$(route_gateway "$_prefix" || true)
        [ -n "$_old" ] || _old=-
        printf '%s\t%s\n' "$_prefix" "$_old" >> "$SNAPSHOT"
    done < "$PREFIXES"
}

apply_candidate() {
    while IFS= read -r _prefix; do
        [ -n "$_prefix" ] || continue
        deadline_ok || return 2
        printf '%s\n' "$_prefix" >> "$TOUCHED" || return 1
        route change -net "$_prefix" "$GW" >/dev/null 2>&1 \
            || route add -net "$_prefix" "$GW" >/dev/null 2>&1 \
            || return 1
    done < "$CANDIDATE"
}

remove_obsolete() {
    LC_ALL=C comm -23 "$PREVIOUS" "$CANDIDATE" > "$OBSOLETE"
    while IFS= read -r _prefix; do
        [ -n "$_prefix" ] || continue
        deadline_ok || return 2
        printf '%s\n' "$_prefix" >> "$TOUCHED" || return 1
        route delete -net "$_prefix" >/dev/null 2>&1 || return 1
    done < "$OBSOLETE"
}

apply_override_candidate() {
    [ -s "$OVERRIDE_CANDIDATE" ] || return 0
    while IFS= read -r _prefix; do
        [ -n "$_prefix" ] || continue
        deadline_ok || return 2
        printf '%s\n' "$_prefix" >> "$OVERRIDE_TOUCHED" || return 1
        route change -net "$_prefix" -interface "$VPN_IF" >/dev/null 2>&1 \
            || route add -net "$_prefix" -interface "$VPN_IF" >/dev/null 2>&1 \
            || return 1
    done < "$OVERRIDE_CANDIDATE"
}

remove_obsolete_override() {
    [ -s "$OVERRIDE_PREVIOUS" ] || return 0
    LC_ALL=C comm -23 "$OVERRIDE_PREVIOUS" "$OVERRIDE_CANDIDATE" > "$OVERRIDE_OBSOLETE"
    while IFS= read -r _prefix; do
        [ -n "$_prefix" ] || continue
        deadline_ok || return 2
        printf '%s\n' "$_prefix" >> "$OVERRIDE_TOUCHED" || return 1
        route delete -net "$_prefix" >/dev/null 2>&1 || return 1
    done < "$OVERRIDE_OBSOLETE"
}

abort_transaction() {
    _reason=$1
    _rollback_message="previous routes restored"
    if ! rollback_transaction; then
        _rollback_message="CRITICAL: rollback incomplete"
    fi
    TRANSACTION_ACTIVE=0
    die "$_reason; $_rollback_message"
}

apply_routes() {
    start_deadline
    normalise_table
    normalise_override_table
    load_previous_state
    load_previous_override_state
    resolve_wan || true
    [ -n "$GW" ] || die "$WAN_IF has no valid WAN gateway"

    if runtime_matches_candidate; then
        _count=$(wc -l < "$CANDIDATE" | awk '{$1=$1};1')
        log "already-active=$_count gateway=$GW interface=$WAN_IF"
        return 0
    fi

    prepare_snapshot
    TRANSACTION_KIND=apply
    TRANSACTION_ACTIVE=1

    if apply_candidate; then
        :
    else
        _rc=$?
        [ "$_rc" -ne 2 ] || abort_transaction "route application timed out"
        abort_transaction "route set could not be applied"
    fi

    if remove_obsolete; then
        :
    else
        _rc=$?
        [ "$_rc" -ne 2 ] || abort_transaction "obsolete-route removal timed out"
        abort_transaction "obsolete routes could not be removed"
    fi

    if [ -s "$OVERRIDE_CANDIDATE" ] || [ -s "$OVERRIDE_PREVIOUS" ]; then
        if apply_override_candidate; then
            :
        else
            _rc=$?
            [ "$_rc" -ne 2 ] || abort_transaction "VPN override route application timed out"
            abort_transaction "VPN override routes could not be applied"
        fi
        if remove_obsolete_override; then
            :
        else
            _rc=$?
            [ "$_rc" -ne 2 ] || abort_transaction "obsolete VPN override removal timed out"
            abort_transaction "obsolete VPN override routes could not be removed"
        fi
    fi

    publish_state "$CANDIDATE"
    if [ -s "$OVERRIDE_CANDIDATE" ]; then
        publish_state_file "$OVERRIDE_CANDIDATE" "$VPN_OVERRIDE_STATE_FILE"
    elif [ -e "$VPN_OVERRIDE_STATE_FILE" ]; then
        rm -f "$VPN_OVERRIDE_STATE_FILE"
    fi
    TRANSACTION_ACTIVE=0
    _count=$(wc -l < "$CANDIDATE" | awk '{$1=$1};1')
    log "applied=$_count gateway=$GW interface=$WAN_IF"
}

clear_routes() {
    start_deadline
    load_previous_state
    load_previous_override_state
    [ -s "$PREVIOUS" ] || [ -s "$OVERRIDE_PREVIOUS" ] || {
        [ ! -f "$STATE_FILE" ] || rm -f "$STATE_FILE"
        [ ! -f "$VPN_OVERRIDE_STATE_FILE" ] || rm -f "$VPN_OVERRIDE_STATE_FILE"
        log "nothing to clear"
        return 0
    }
    prepare_snapshot
    TRANSACTION_KIND=clear
    TRANSACTION_ACTIVE=1

    while IFS= read -r _prefix; do
        [ -n "$_prefix" ] || continue
        deadline_ok || abort_transaction "route clear timed out"
        printf '%s\n' "$_prefix" >> "$TOUCHED" \
            || abort_transaction "cannot record route clear rollback state"
        route delete -net "$_prefix" >/dev/null 2>&1 \
            || abort_transaction "route set could not be cleared"
    done < "$PREVIOUS"

    while IFS= read -r _prefix; do
        [ -n "$_prefix" ] || continue
        deadline_ok || abort_transaction "VPN override clear timed out"
        printf '%s\n' "$_prefix" >> "$OVERRIDE_TOUCHED" \
            || abort_transaction "cannot record VPN override rollback state"
        route delete -net "$_prefix" >/dev/null 2>&1 \
            || abort_transaction "VPN override routes could not be cleared"
    done < "$OVERRIDE_PREVIOUS"

    rm -f "$STATE_FILE" "$VPN_OVERRIDE_STATE_FILE"
    TRANSACTION_ACTIVE=0
    log "cleared previously applied RU routes"
}

check_routes() {
    normalise_table
    normalise_override_table
    load_previous_state
    load_previous_override_state
    [ -f "$STATE_FILE" ] || return 1
    resolve_wan || true
    [ -n "$GW" ] || return 1
    runtime_matches_candidate
}

case "$ACTION" in
    apply) apply_routes ;;
    clear) clear_routes ;;
    check) check_routes ;;
    *) echo "Usage: ru-routes.sh {apply|clear|check}" >&2; exit 2 ;;
esac
