#!/bin/sh
# gatebsd-watchdog — unified daemon replacing vpn-watchdog + wan-failover + ru_bypass
# Single process manages all route state: VPN health, WAN failover, RU bypass routes.
# Runs as a persistent daemon via rc.d/gatebsd_failover.
set -eu

# awg lives in /usr/local/bin, which is absent from the rc/cron default PATH
# (/sbin:/bin:/usr/sbin:/usr/bin). Without it `awg show` fails with ENOENT, the
# handshake age reads as unknown for a healthy tunnel, and the VPN gets rolled
# back on every tick. The local dirs are appended rather than assigned so that a
# caller-supplied PATH (test stubs) keeps priority.
case ":${PATH}:" in
    *:/usr/local/bin:*) ;;
    *) PATH="${PATH}:/usr/local/sbin:/usr/local/bin" ;;
esac
export PATH

# ── Configuration ──────────────────────────────────────────────────────────
CONF="${GATEBSD_FAILOVER_CONF:-/usr/local/etc/gatebsd/failover.conf}"
STARTUP_ARG=${1:-}
safe_source() {
    _path=$1
    _fatal=${2:-1}
    [ -e "$_path" ] || return 0
    if [ ! -f "$_path" ] || [ -L "$_path" ]; then
        echo "Unsafe config: $_path" >&2
        [ "$_fatal" -eq 1 ] && exit 2 || return 1
    fi
    _uid=$(stat -f '%u' "$_path" 2>/dev/null || printf '%s' -1)
    _mode=$(stat -f '%Lp' "$_path" 2>/dev/null || printf '%s' 777)
    if [ "$_uid" != 0 ]; then
        echo "Config must be owned by root: $_path" >&2
        [ "$_fatal" -eq 1 ] && exit 2 || return 1
    fi
    case "$_mode" in
        *[2367][0-7]|*[0-7][2367])
            echo "Config must not be group/world writable: $_path" >&2
            [ "$_fatal" -eq 1 ] && exit 2 || return 1
            ;;
    esac
    # Declarative KEY=VALUE parser: never execute shell code from failover.conf.
    while IFS= read -r _line || [ -n "$_line" ]; do
        _line=${_line%"$(printf '\r')"}
        _line=${_line#"${_line%%[![:space:]]*}"}
        case "$_line" in
            ''|'#'*) continue ;;
            *=*) ;;
            *)
                if [ "$_fatal" -eq 1 ] && [ "$STARTUP_ARG" = "--locked" ]; then
                    echo "Ignoring malformed config line in $_path" >&2
                fi
                continue
                ;;
        esac
        _key=${_line%%=*}
        _key=${_key%"${_key##*[![:space:]]}"}
        _raw=${_line#*=}
        _raw=${_raw#"${_raw%%[![:space:]]*}"}
        case "$_raw" in
            \"*)
                _after=${_raw#\"}
                case "$_after" in
                    *\"*)
                        _val=${_after%%\"*}
                        _rest=${_after#*\"}
                        _rest=${_rest#"${_rest%%[![:space:]]*}"}
                        case "$_rest" in
                            ''|'#'*) ;;
                            *)
                                echo "Malformed quoted value for $_key in $_path" >&2
                                [ "$_fatal" -eq 1 ] && exit 2 || return 1
                                ;;
                        esac
                        ;;
                    *)
                        echo "Unclosed quote for $_key in $_path" >&2
                        [ "$_fatal" -eq 1 ] && exit 2 || return 1
                        ;;
                esac
                ;;
            \'*)
                _after=${_raw#\'}
                case "$_after" in
                    *\'*)
                        _val=${_after%%\'*}
                        _rest=${_after#*\'}
                        _rest=${_rest#"${_rest%%[![:space:]]*}"}
                        case "$_rest" in
                            ''|'#'*) ;;
                            *)
                                echo "Malformed quoted value for $_key in $_path" >&2
                                [ "$_fatal" -eq 1 ] && exit 2 || return 1
                                ;;
                        esac
                        ;;
                    *)
                        echo "Unclosed quote for $_key in $_path" >&2
                        [ "$_fatal" -eq 1 ] && exit 2 || return 1
                        ;;
                esac
                ;;
            *)
                _val=${_raw%%#*}
                _val=${_val%"${_val##*[![:space:]]}"}
                ;;
        esac
        case "$_key" in
            PRIMARY_IF) PRIMARY_IF=$_val ;;
            BACKUP_IF) BACKUP_IF=$_val ;;
            VPN_IF) VPN_IF=$_val ;;
            CHECK_TARGETS) CHECK_TARGETS=$_val ;;
            RU_CHECK_TARGETS) RU_CHECK_TARGETS=$_val ;;
            CHECK_TCP_PORT) CHECK_TCP_PORT=$_val ;;
            CHECK_INTERVAL) CHECK_INTERVAL=$_val ;;
            PING_TIMEOUT) PING_TIMEOUT=$_val ;;
            FAIL_THRESHOLD) FAIL_THRESHOLD=$_val ;;
            RECOVERY_THRESHOLD) RECOVERY_THRESHOLD=$_val ;;
            MIN_BACKUP_HOLD) MIN_BACKUP_HOLD=$_val ;;
            SWITCH_COOLDOWN) SWITCH_COOLDOWN=$_val ;;
            PRIMARY_FIB) PRIMARY_FIB=$_val ;;
            BACKUP_FIB) BACKUP_FIB=$_val ;;
            FAILOVER_MODE) FAILOVER_MODE=$_val ;;
            VPN_HANDSHAKE_MAX) VPN_HANDSHAKE_MAX=$_val ;;
            VPN_RECOVERY_HANDSHAKE) VPN_RECOVERY_HANDSHAKE=$_val ;;
            VPN_NET_FAIL_THRESHOLD) VPN_NET_FAIL_THRESHOLD=$_val ;;
            VPN_RETRY_INTERVAL) VPN_RETRY_INTERVAL=$_val ;;
            SERVICE_RESTART_COOLDOWN) SERVICE_RESTART_COOLDOWN=$_val ;;
            VPN_SETTLE_AFTER_SWITCH) VPN_SETTLE_AFTER_SWITCH=$_val ;;
            REQUEST_TIMEOUT) REQUEST_TIMEOUT=$_val ;;
            EVENT_LOG) EVENT_LOG=$_val ;;
            RU_TABLE) RU_TABLE=$_val ;;
            RU_STATE_FILE) RU_STATE_FILE=$_val ;;
            *)
                if [ "$_fatal" -eq 1 ] && [ "$STARTUP_ARG" = "--locked" ]; then
                    echo "Ignoring unknown config key in $_path: $_key" >&2
                fi
                ;;
        esac
    done < "$_path"
}
safe_source "$CONF" 1

PRIMARY_IF="${PRIMARY_IF:-ng0}"
BACKUP_IF="${BACKUP_IF:-ue0}"
VPN_IF="${VPN_IF:-awg0}"
CHECK_TARGETS="${CHECK_TARGETS:-1.1.1.1 8.8.8.8 9.9.9.9}"
RU_CHECK_TARGETS="${RU_CHECK_TARGETS-77.88.8.8}"
# ICMP echo is not a universal liveness signal. The backup uplink here is a
# carrier that forwards UDP and TCP but drops echo to public addresses, so an
# ICMP-only check calls a working link dead and failover never fires. A TCP
# handshake to this port is tried once echo has failed on every target. 0
# disables the fallback.
CHECK_TCP_PORT="${CHECK_TCP_PORT:-443}"
CHECK_INTERVAL="${CHECK_INTERVAL:-10}"
PING_TIMEOUT="${PING_TIMEOUT:-2}"
FAIL_THRESHOLD="${FAIL_THRESHOLD:-3}"
RECOVERY_THRESHOLD="${RECOVERY_THRESHOLD:-8}"
MIN_BACKUP_HOLD="${MIN_BACKUP_HOLD:-120}"
SWITCH_COOLDOWN="${SWITCH_COOLDOWN:-60}"
PRIMARY_FIB="${PRIMARY_FIB:-1}"
BACKUP_FIB="${BACKUP_FIB:-2}"
FAILOVER_MODE="${FAILOVER_MODE:-observe}"
VPN_HANDSHAKE_MAX="${VPN_HANDSHAKE_MAX:-180}"
VPN_RECOVERY_HANDSHAKE="${VPN_RECOVERY_HANDSHAKE:-90}"
VPN_NET_FAIL_THRESHOLD="${VPN_NET_FAIL_THRESHOLD:-3}"
# How often to re-attempt `gatewayctl apply` while the VPN is wanted but absent
# from the default route. Each attempt runs awg-quick and waits for a handshake,
# so this must be well above the tick interval or the loop would spend all its
# time there and stop measuring the WAN links.
VPN_RETRY_INTERVAL="${VPN_RETRY_INTERVAL:-60}"
SERVICE_RESTART_COOLDOWN="${SERVICE_RESTART_COOLDOWN:-300}"
# Grace given to a freshly moved underlay before the tunnel on top of it is
# judged again.
#
# A switch re-pins the VPN endpoint to the new gateway, and the tunnel needs a
# moment to notice: measured on this device, the handshake refreshes 16s after
# the pin moves. Judging it any sooner condemns the tunnel for the underlay's
# outage. 0 disables the grace period.
VPN_SETTLE_AFTER_SWITCH="${VPN_SETTLE_AFTER_SWITCH:-45}"
REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-300}"

# The run directory is fixed in production. It is overridable only when the
# caller also sets GATEBSD_ALLOW_TEST_RUN_DIR, which the regression harness does
# so the failover state machine can be exercised without touching live state.
# Both are root-only in production, so this does not widen any trust boundary.
STATE_DIR="${GATEBSD_RUN_DIR:-/var/run/gatebsd}"
case "$STATE_DIR" in
    /var/run/gatebsd) ;;
    /*) [ "${GATEBSD_ALLOW_TEST_RUN_DIR:-0}" = 1 ] || { echo "refusing non-standard run directory: $STATE_DIR" >&2; exit 2; } ;;
    *) echo "run directory must be absolute: $STATE_DIR" >&2; exit 2 ;;
esac
STATE_FILE="${GATEBSD_WATCHDOG_STATE:-${STATE_DIR}/watchdog.json}"
LOCK_FILE="${STATE_DIR}/watchdog.lock"
MANUAL_WAN_FILE="${STATE_DIR}/manual-wan"
VPN_DISABLED_FLAG="${GATEBSD_VPN_DISABLED_FLAG:-/var/db/gatebsd/vpn_disabled}"
# dhclient writes the backup WAN lease here; the gateway is parsed out of it.
DHCLIENT_LEASE_DIR="${GATEBSD_DHCLIENT_LEASE_DIR:-/var/db}"
EVENT_LOG="${EVENT_LOG:-/var/log/gatebsd-watchdog.log}"
RU_TABLE="${RU_TABLE:-/usr/local/etc/amnezia/ru_bypass.table}"
RU_STATE_FILE="${RU_STATE_FILE:-/var/db/gatebsd-system/ru-routes.applied}"
RU_ROUTES_HELPER="${GATEBSD_RU_ROUTES_HELPER:-/usr/local/sbin/ru-routes.sh}"
ROUTE_HELPER="${GATEBSD_ROUTE_HELPER:-/usr/local/sbin/gatebsd-route-op}"
# Named like the other helpers so the regression harness can substitute it;
# the daemon otherwise calls it by absolute path and nothing could observe it.
GATEWAY_HELPER="${GATEBSD_GATEWAY_HELPER:-/usr/local/sbin/gatewayctl}"
STATE_READER="${GATEBSD_STATE_READER:-/usr/local/sbin/gatebsd-state-value}"

# ── Helpers ────────────────────────────────────────────────────────────────
ensure_root_dir() {
    _dir=$1
    _group=$2
    if [ -e "$_dir" ] || [ -L "$_dir" ]; then
        [ -d "$_dir" ] && [ ! -L "$_dir" ] || { echo "Unsafe directory: $_dir" >&2; exit 2; }
        _uid=$(stat -f '%u' "$_dir" 2>/dev/null || printf '%s' -1)
        _mode=$(stat -f '%Lp' "$_dir" 2>/dev/null || printf '%s' 777)
        [ "$_uid" = 0 ] || { echo "Directory must be root-owned: $_dir" >&2; exit 2; }
        case "$_mode" in *[2367][0-7]|*[0-7][2367]) echo "Directory must not be group/world writable: $_dir" >&2; exit 2 ;; esac
    else
        install -d -o root -g "$_group" -m 0750 "$_dir"
    fi
}
ensure_root_dir "$STATE_DIR" "${GATEBSD_SERVICE_GROUP:-gatebsd}"
ensure_root_dir "$(dirname "$RU_STATE_FILE")" wheel

# FreeBSD lockf locks a pathname and runs a child while holding that lock.  It
# does not lock an already-open shell descriptor.  Re-exec through lockf so a
# second rc/cron start cannot create another watchdog.
if [ "${1:-}" != "--locked" ]; then
    exec lockf -s -T -t 0 "$LOCK_FILE" "$0" --locked
fi
DAEMON_PIDFILE="${STATE_DIR}/watchdog.pid"
echo $$ > "$DAEMON_PIDFILE"

log() {
    local msg
    msg="$(date '+%Y-%m-%d %H:%M:%S') $*"
    echo "$msg" >> "$EVENT_LOG"
    logger -t gatebsd-watchdog "$*"
}

now() { date +%s; }

# Run a command and copy its output into the event log, without ever reading it
# through a pipe.
#
# `service ... start` hands the daemon it launches this process's stdout, and
# that daemon is free to pass the descriptor to a child that outlives the start.
# awg-quick does exactly this -- it backgrounds a route monitor after printing
# "Backgrounding route monitor" -- so the write end of `cmd | while read` stays
# open with nobody left to close it. The reader then waits for an EOF that never
# comes: observed live on 31 July after the USB modem was pulled, with the main
# process in `wait`, the reader in `piperd`, and not one further tick for six
# minutes. From outside the service still answered "running" while failover was
# in fact dead until a human restarted the daemon.
#
# A regular file cannot stall a reader that way: the lingering child may hold
# that descriptor as long as it likes. It is unlinked before it is recreated so
# such a leftover writer keeps the old inode instead of scribbling into the next
# start's output. stdin comes from /dev/null for the same class of reason --
# nothing started from here may block waiting to be typed at.
run_logged() {
    _rl_out="${STATE_DIR}/service-output"
    rm -f "$_rl_out"
    if "$@" </dev/null >"$_rl_out" 2>&1; then
        _rl_rc=0
    else
        _rl_rc=$?
    fi
    if [ -r "$_rl_out" ]; then
        while IFS= read -r _rl_line; do log "  $_rl_line"; done < "$_rl_out"
        rm -f "$_rl_out"
    fi
    return "$_rl_rc"
}

is_ipv4() {
    printf '%s\n' "$1" | awk -F. '
        NF != 4 {exit 1}
        {
            for (i=1; i<=4; i++) {
                if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1
            }
        }
    '
}

is_hostname() {
    _host=$1
    [ ${#_host} -le 253 ] || return 1
    case "$_host" in
        ''|*[!A-Za-z0-9.-]*|.*|*..*|*-|*.|-* ) return 1 ;;
    esac
    return 0
}

valid_network_target() {
    is_ipv4 "$1" || is_hostname "$1"
}

is_iface() {
    [ -n "$1" ] && [ ${#1} -le 32 ] || return 1
    case "$1" in *[!A-Za-z0-9_.-]*|[0-9.-]*) return 1 ;; esac
}

# ── Network checks ─────────────────────────────────────────────────────────
for _numeric in CHECK_INTERVAL PING_TIMEOUT FAIL_THRESHOLD RECOVERY_THRESHOLD MIN_BACKUP_HOLD SWITCH_COOLDOWN PRIMARY_FIB BACKUP_FIB CHECK_TCP_PORT VPN_HANDSHAKE_MAX VPN_RECOVERY_HANDSHAKE VPN_NET_FAIL_THRESHOLD SERVICE_RESTART_COOLDOWN VPN_SETTLE_AFTER_SWITCH REQUEST_TIMEOUT; do
    eval "_value=\${$_numeric}"
    case "$_value" in ''|*[!0-9]*) echo "Invalid $_numeric=$_value" >&2; exit 2 ;; esac
done
[ "$CHECK_TCP_PORT" -le 65535 ] || { echo "Invalid CHECK_TCP_PORT=$CHECK_TCP_PORT" >&2; exit 2; }
[ "$REQUEST_TIMEOUT" -le 3600 ] || { echo "Invalid REQUEST_TIMEOUT=$REQUEST_TIMEOUT" >&2; exit 2; }
# How many routing tables the kernel actually has. Zero means "could not read
# it"; the FIB sync then attempts the install and reports the kernel's own
# error rather than refusing on a guess.
FIB_COUNT="$(sysctl -n net.fibs 2>/dev/null || true)"
case "$FIB_COUNT" in ''|*[!0-9]*) FIB_COUNT=0 ;; esac
case "$FAILOVER_MODE" in observe|automatic|manual) ;; *) echo "Invalid FAILOVER_MODE=$FAILOVER_MODE" >&2; exit 2 ;; esac
for _iface in "$PRIMARY_IF" "$BACKUP_IF" "$VPN_IF"; do
    is_iface "$_iface" || { echo "Invalid interface name: $_iface" >&2; exit 2; }
done
[ -x "$RU_ROUTES_HELPER" ] || { echo "Missing RU route helper: $RU_ROUTES_HELPER" >&2; exit 2; }
[ -x "$ROUTE_HELPER" ] || { echo "Missing route transaction helper: $ROUTE_HELPER" >&2; exit 2; }
_target_count=0
for _target in $CHECK_TARGETS; do
    valid_network_target "$_target" || { echo "Invalid CHECK_TARGETS entry: $_target" >&2; exit 2; }
    _target_count=$((_target_count + 1))
done
[ "$_target_count" -gt 0 ] || { echo "CHECK_TARGETS is empty" >&2; exit 2; }
for _target in $RU_CHECK_TARGETS; do
    valid_network_target "$_target" || { echo "Invalid RU_CHECK_TARGETS entry: $_target" >&2; exit 2; }
done

run_in_fib() {
    _fib="$1"; shift
    if command -v setfib >/dev/null 2>&1; then
        setfib "$_fib" "$@"
    else
        "$@"
    fi
}

# Give a WAN health check a routing table it can actually leave through.
#
# PRIMARY_FIB/BACKUP_FIB exist so a link can be measured independently of the
# system default, which on this box points at the VPN. Nothing ever populated
# those tables: mpd5 and dhclient install their routes into FIB 0 only, so every
# probe left through a table holding nothing but lo0 and both uplinks read as
# dead forever -- 243 consecutive failures on a working line, the site parked in
# PRIMARY_DEGRADED, and failover to the backup unreachable because it is gated
# on BACKUP_OK.
#
# Convergence lives here, on the watchdog's own tick, rather than in link-up
# hooks: mpd5 and dhclient are two separate integrations that say nothing when
# they fail to fire, whereas this is idempotent, costs one route lookup per link
# per tick, and repairs itself when a PPPoE reconnect hands out a different peer
# address. The two facts it needs -- source address and next hop -- are the ones
# check_iface already reads out of ifconfig.
#
# The route is installed in two steps because a fresh FIB has no connected route
# either: `route add default <gw>` alone fails with ENETUNREACH until the next
# hop itself is reachable on-link. `route -fib N` does not exist on FreeBSD 15
# (route(8) takes only -46dnqtv), so the table is selected with setfib.
# Log a FIB sync outcome only when it differs from the previous one. Without
# this a permanently unusable link would write a line every CHECK_INTERVAL.
fib_sync_report() {
    _fr_fib=$1
    _fr_state=$2
    _fr_message=$3
    eval "_fr_previous=\${FIB_SYNC_STATE_${_fr_fib}:-}"
    [ "$_fr_previous" != "$_fr_state" ] || return 0
    eval "FIB_SYNC_STATE_${_fr_fib}=\$_fr_state"
    [ -z "$_fr_message" ] || log "$_fr_message"
}

sync_fib_default() {
    _sf_iface=$1
    _sf_fib=$2
    _sf_gw=$3
    # FIB 0 is the live table carrying customer traffic. Never write to it here.
    [ "$_sf_fib" != 0 ] || return 0
    if [ "$FIB_COUNT" -gt 0 ] && [ "$_sf_fib" -ge "$FIB_COUNT" ]; then
        fib_sync_report "$_sf_fib" missing "routing table $_sf_fib does not exist (net.fibs=$FIB_COUNT); cannot measure $_sf_iface"
        return 1
    fi
    if [ -z "$_sf_gw" ]; then
        # The link has no address or no next hop. A default left behind would
        # answer for a link that is gone, so withdraw it.
        run_in_fib "$_sf_fib" route delete default >/dev/null 2>&1 || true
        fib_sync_report "$_sf_fib" down "fib $_sf_fib: $_sf_iface has no gateway; default withdrawn"
        return 1
    fi
    _sf_current="$(run_in_fib "$_sf_fib" route -n get default 2>/dev/null)"
    if [ "$(printf '%s\n' "$_sf_current" | awk '/interface:/ {print $2; exit}')" = "$_sf_iface" ] \
        && [ "$(printf '%s\n' "$_sf_current" | awk '/gateway:/ {print $2; exit}')" = "$_sf_gw" ]; then
        fib_sync_report "$_sf_fib" ok ""
        return 0
    fi
    run_in_fib "$_sf_fib" route change -host "$_sf_gw" -iface "$_sf_iface" >/dev/null 2>&1 \
        || run_in_fib "$_sf_fib" route add -host "$_sf_gw" -iface "$_sf_iface" >/dev/null 2>&1 \
        || true
    if run_in_fib "$_sf_fib" route change default "$_sf_gw" >/dev/null 2>&1 \
        || run_in_fib "$_sf_fib" route add default "$_sf_gw" >/dev/null 2>&1; then
        log "fib $_sf_fib: default now $_sf_gw via $_sf_iface"
        eval "FIB_SYNC_STATE_${_sf_fib}=ok"
        return 0
    fi
    fib_sync_report "$_sf_fib" failed "fib $_sf_fib: cannot install default $_sf_gw via $_sf_iface"
    return 1
}

route_op() {
    GATEBSD_GATEWAY_CONF="${GATEBSD_GATEWAY_CONF:-/usr/local/etc/amnezia/gateway.conf}" \
        GATEBSD_RU_ROUTES_HELPER="$RU_ROUTES_HELPER" \
        RU_TABLE="$RU_TABLE" RU_STATE_FILE="$RU_STATE_FILE" \
        "$ROUTE_HELPER" "$@"
}

replace_default_gateway() {
    route_op set-default-gw "$1"
}

replace_default_interface() {
    route_op set-default-if "$1"
}

# Gateway lookups return empty output and exit 0 when no gateway is available.
# Propagating a non-zero status instead is unsafe here: every call site assigns
# through a command substitution, and FreeBSD's /bin/sh aborts the whole script
# under `set -e` when the substituted command fails. That would kill the daemon
# at exactly the moment it is needed -- on the failover path, where the primary
# gateway is missing by definition. Callers already test for empty output.
# Whether an interface can carry anything at all right now.
#
# An address outlives the link it is configured on. `ifconfig ng0 down` leaves
# the inet line and its `--> peer` in place, so a gateway read out of that line
# looks perfectly alive while nothing can reach it -- and the watchdog then
# hands that corpse to switch_underlay and to the VPN rollback path as a usable
# way out. Observed on 31 July: the underlay had already moved to the backup and
# the endpoint pin stayed on the dead ng0. UP is the administrative state and
# RUNNING is the carrier; a way out needs both.
iface_is_live() {
    ifconfig "$1" 2>/dev/null | awk '
        NR == 1 && match($0, /<[^>]*>/) {
            split(substr($0, RSTART + 1, RLENGTH - 2), flag, ",")
            for (i in flag) {
                if (flag[i] == "UP") up = 1
                if (flag[i] == "RUNNING") running = 1
            }
        }
        END { exit !(up && running) }
    '
}

# The next hop is a *field*, not a shape of line. `inet ` plus `-->` anywhere on
# the line also describes what an encapsulating interface prints above its
# address:
#
#     tunnel inet 198.18.20.2 --> 198.18.20.9      <- gif, gre, ovpn
#         inet 10.99.1.2 --> 10.99.1.1 netmask 0xffffffff
#
# and the tunnel line comes first, so `$4` is the arrow itself. The link then has
# no gateway as far as this daemon is concerned, and a perfectly healthy
# point-to-point primary is reported down for ever. `ng0` has no such line, which
# is why the field never showed it -- the rig did, and 0.2 plans a p2p backup on
# `umb0`. Anchoring on `$1` costs nothing and does not care what is above.
pppoe_gw() {
    iface_is_live "$PRIMARY_IF" || return 0
    _gateway=$(ifconfig "$PRIMARY_IF" 2>/dev/null | awk '$1 == "inet" && $3 == "-->" {print $4; exit}')
    if is_ipv4 "$_gateway"; then
        printf '%s\n' "$_gateway"
    fi
    return 0
}

backup_gw() {
    # A lease outlives the link even more readily than an address does: the file
    # sits on disk after the stick is unplugged. Same rule as the primary.
    iface_is_live "$BACKUP_IF" || return 0
    # `2>/dev/null` hides awk's message but not its exit status, and awk exits 2
    # on a missing file. The trailing `return 0` below is then never reached:
    # `set -e` kills the daemon on the assignment itself. A backup link that
    # never got a lease is the normal state of a device whose spare WAN is
    # unplugged, so the file has to be tested before it is read.
    _lease="${DHCLIENT_LEASE_DIR}/dhclient.leases.${BACKUP_IF}"
    [ -r "$_lease" ] && [ -f "$_lease" ] || return 0
    _gateway=$(awk '/option routers/ {gsub(";","",$3); g=$3} END{print g}' "$_lease")
    if is_ipv4 "$_gateway"; then
        printf '%s\n' "$_gateway"
    fi
    return 0
}

gateway_for() {
    case "$1" in
        primary) pppoe_gw ;;
        backup) backup_gw ;;
        *) return 0 ;;
    esac
}

iface_for() {
    case "$1" in
        primary) printf '%s\n' "$PRIMARY_IF" ;;
        backup) printf '%s\n' "$BACKUP_IF" ;;
        *) return 1 ;;
    esac
}

# Gateway of whichever underlay currently has one.
#
# Note this reports the *other* underlay's gateway when the active one has none,
# and logs when it does. That is correct for VPN-rollback and RU-convergence
# paths, which only need a usable way out. It is deliberately NOT used to choose
# an underlay: silently installing the backup gateway as the system default
# while ACTIVE still read "primary" left the kernel routing through ue0 while
# the state file, failoverctl and the UI all reported primary, LAST_SWITCH was
# never updated, and MIN_BACKUP_HOLD/SWITCH_COOLDOWN never engaged. Cross-WAN
# moves go through switch_underlay, which uses gateway_for directly so recorded
# state stays truthful.
usable_gateway() {
    _candidate="$(gateway_for "$ACTIVE")"
    if [ -n "$_candidate" ]; then
        printf '%s\n' "$_candidate"
        return 0
    fi
    if [ "$ACTIVE" = primary ]; then
        _candidate="$(backup_gw)"
        _other=backup
    else
        _candidate="$(pppoe_gw)"
        _other=primary
    fi
    if [ -n "$_candidate" ]; then
        log "no gateway on $ACTIVE underlay; $_other has $_candidate"
        printf '%s\n' "$_candidate"
    fi
    return 0
}

probe_icmp() {
    _pi_fib=$1
    _pi_src=$2
    _pi_targets=${3:-$CHECK_TARGETS}
    [ -n "$_pi_targets" ] || return 1
    for _pi_target in $_pi_targets; do
        if [ -n "$_pi_src" ]; then
            run_in_fib "$_pi_fib" ping -S "$_pi_src" -c 1 -W "$((PING_TIMEOUT * 1000))" "$_pi_target" >/dev/null 2>&1 && return 0
        else
            run_in_fib "$_pi_fib" ping -c 1 -W "$((PING_TIMEOUT * 1000))" "$_pi_target" >/dev/null 2>&1 && return 0
        fi
    done
    return 1
}

probe_tcp() {
    _pt_fib=$1
    _pt_src=$2
    _pt_targets=${3:-$CHECK_TARGETS}
    [ -n "$_pt_targets" ] || return 1
    [ "$CHECK_TCP_PORT" != 0 ] || return 1
    command -v nc >/dev/null 2>&1 || return 1
    for _pt_target in $_pt_targets; do
        if [ -n "$_pt_src" ]; then
            run_in_fib "$_pt_fib" nc -z -w "$PING_TIMEOUT" -s "$_pt_src" "$_pt_target" "$CHECK_TCP_PORT" >/dev/null 2>&1 && return 0
        else
            run_in_fib "$_pt_fib" nc -z -w "$PING_TIMEOUT" "$_pt_target" "$CHECK_TCP_PORT" >/dev/null 2>&1 && return 0
        fi
    done
    return 1
}

# Reachability of the wider internet from one routing table.
#
# Two probes, because "no echo reply" and "no transit" are different facts. The
# backup carrier on this device forwards TCP and UDP but drops ICMP echo to
# public addresses; an echo-only check therefore reported a perfectly usable
# backup as dead, BACKUP_OK never became true, and the automatic failover branch
# -- which requires it -- could not run. Whichever probe last answered on a FIB
# is tried first, so a link behind an echo-filtering carrier does not pay a full
# round of ping timeouts on every tick.
check_net() {
    local fib="${1:-0}" src="${2:-}" targets="${3:-$CHECK_TARGETS}" prefvar pref
    [ -n "$targets" ] || return 1
    prefvar="PROBE_PREF_${fib}"
    eval "pref=\${$prefvar:-icmp}"
    if [ "$pref" = tcp ]; then
        probe_tcp "$fib" "$src" "$targets" && return 0
        if probe_icmp "$fib" "$src" "$targets"; then
            eval "$prefvar=icmp"
            return 0
        fi
    else
        probe_icmp "$fib" "$src" "$targets" && return 0
        if probe_tcp "$fib" "$src" "$targets"; then
            eval "$prefvar=tcp"
            return 0
        fi
    fi
    return 1
}

# Whether the interface exists on this machine at all.
#
# "Absent" and "present but down" are different facts, and collapsing them cost
# this product its own credibility on a supported configuration. A device sold
# with a single uplink has no ue0. Every tick then counted a failure for it, so
# backup_failures climbed without bound and the panel showed the spare link
# permanently red with a five-figure error count. Nothing was wrong. There was
# simply no spare link fitted, which is a normal delivery, not a fault -- and an
# alarm that is always on is an alarm nobody reads when it finally means
# something.
iface_present() {
    ifconfig "$1" >/dev/null 2>&1
}

# Said once, on transition, not every tick.
BACKUP_ABSENT_REPORTED=false
report_backup_absent() {
    [ "$BACKUP_ABSENT_REPORTED" = false ] || return 0
    BACKUP_ABSENT_REPORTED=true
    log "no backup interface fitted ($BACKUP_IF is absent); running on a single uplink"
}

check_iface() {
    local iface="$1" fib="$2" src gw
    LAST_IFACE_RU_OK=false
    if ! iface_is_live "$iface"; then
        # Same reasoning as iface_is_live's own: a link without UP and RUNNING
        # still answers ifconfig with its address. Withdraw whatever default it
        # left in its own table so the next check cannot be answered by a route
        # to a dead link.
        sync_fib_default "$iface" "$fib" "" || true
        return 1
    fi
    # Both read a field, not a line shape -- see pppoe_gw. On an encapsulating
    # interface the `tunnel inet` line above the address matches first and hands
    # back the literal words "inet" and "-->".
    src="$(ifconfig "$iface" 2>/dev/null | awk '$1 == "inet" {print $2; exit}')"
    gw=""
    if [ -n "$src" ]; then
        gw="$(ifconfig "$iface" 2>/dev/null | awk '$1 == "inet" && $3 == "-->" {print $4; exit}')"
        # The readability test is not decoration. FreeBSD /bin/sh aborts the
        # whole script under `set -e` when a command substitution in an
        # assignment fails, and awk exits 2 on a missing file -- so reading the
        # lease of a backup link that never got one would kill the daemon at the
        # exact moment failover needs it.
        if [ -z "$gw" ] && [ -r "${DHCLIENT_LEASE_DIR}/dhclient.leases.${iface}" ]; then
            gw="$(awk '/option routers/ {gsub(";","",$3); gateway=$3} END{print gateway}' "${DHCLIENT_LEASE_DIR}/dhclient.leases.${iface}")"
        fi
    fi
    if ! is_ipv4 "$src" || ! is_ipv4 "$gw"; then
        # Withdraw any default this link left in its own table before reporting
        # it down, so the next check cannot be answered by a stale route.
        sync_fib_default "$iface" "$fib" "" || true
        return 1
    fi
    sync_fib_default "$iface" "$fib" "$gw" || return 1
    run_in_fib "$fib" ping -S "$src" -c 1 -W "$((PING_TIMEOUT * 1000))" "$gw" >/dev/null 2>&1 || return 1
    if check_net "$fib" "$src" "$CHECK_TARGETS"; then
        LAST_IFACE_RU_OK=true
        return 0
    fi
    if [ -n "$RU_CHECK_TARGETS" ] && check_net "$fib" "$src" "$RU_CHECK_TARGETS"; then
        LAST_IFACE_RU_OK=true
    fi
    return 1
}

vpn_handshake_age() {
    # Machine-readable output: <public-key><TAB><unix-epoch>. Human-readable
    # output is locale/version dependent and must not drive failover.
    #
    # "Age unknown" and "age huge" are different facts and must not collapse
    # into one value: a tunnel that just came up has no handshake yet, and a
    # failed `awg` invocation says nothing about the tunnel at all. Both used to
    # return the 99999 sentinel, which exceeds VPN_HANDSHAKE_MAX and triggered a
    # rollback of a perfectly healthy VPN. Unknown is reported as empty output,
    # which every caller already guards with [ -n "$VPN_AGE" ].
    if ! _raw=$(awg show "$VPN_IF" latest-handshakes 2>/dev/null); then
        return 0
    fi
    _latest=$(printf '%s\n' "$_raw" | awk '
        NF >= 2 && $2 ~ /^[0-9]+$/ { if ($2 > max) max=$2; peers++ }
        END {
            if (peers == 0) print "nopeers"
            else if (max == 0) print "nohandshake"
            else print max
        }
    ')
    case "$_latest" in
        ''|nopeers|nohandshake) return 0 ;;
        *[!0-9]*) return 0 ;;
        *)
            _now=$(now)
            if [ "$_latest" -gt "$_now" ]; then
                printf '%s\n' 0
            else
                printf '%s\n' $((_now - _latest))
            fi
            ;;
    esac
}
vpn_is_up() {
    ifconfig "$VPN_IF" 2>/dev/null | grep -q 'UP'
}

vpn_exists() {
    ifconfig "$VPN_IF" >/dev/null 2>&1
}

# ── VPN endpoint routing ───────────────────────────────────────────────────
route_endpoint() {
    _iface=$1
    _gw=$2
    route_op pin-endpoint "$_iface" "$_gw" || return 1
    log "endpoint routed via $_iface gw $_gw"
}

# ── RU bypass routes ────────────────────────────────────────────────────────
# A single helper owns route-set transactions and compensating rollback.
ru_apply() {
    route_op ru-apply "$1" "$2"
}

ru_state_valid() {
    _gw=$1
    [ -r "$RU_TABLE" ] || return 1
    GATEBSD_ACTIVE_WAN_IF="$(iface_for "$ACTIVE")" GATEBSD_ACTIVE_WAN_GW="$_gw" \
        RU_TABLE="$RU_TABLE" RU_STATE_FILE="$RU_STATE_FILE" \
        "$RU_ROUTES_HELPER" check
}

ru_clear() {
    route_op ru-clear
}

# ── Service health check ──────────────────────────────────────────────────
# Restart crashed services in dependency order. Rate-limited per service.
LAST_RESTART_MPD5=0
LAST_RESTART_AMNEZIA=0
LAST_RESTART_UNBOUND=0
_SVC_RESTARTED=false
# Rate-limits the "VPN wanted but not in the default route" recovery attempt.
LAST_VPN_ATTEMPT=0

check_service() {
    local name="$1" varname="$2"
    local last_restart
    eval "last_restart=\$$varname"

    service "$name" status >/dev/null 2>&1 && return 0

    local now_ts
    now_ts="$(now)"
    if [ $((now_ts - last_restart)) -lt "$SERVICE_RESTART_COOLDOWN" ]; then
        return 1
    fi

    log "ALERT: $name is DOWN — restarting"
    # Failed starts need the same cooldown as successful starts. Otherwise a
    # bad config causes a destructive restart attempt every loop iteration.
    eval "$varname=$now_ts"
    # Ensure DNSSEC keys exist before unbound start (prevents checkconf failure)
    if [ "$name" = "unbound" ] && [ ! -f /usr/local/etc/unbound/unbound_server.key ]; then
        log "  Generating unbound DNSSEC keys"
        run_logged unbound-control-setup || true
    fi
    run_logged service "$name" start || true
    sleep 3
    if service "$name" status >/dev/null 2>&1; then
        log "OK: $name restarted successfully"
        _SVC_RESTARTED=true
        return 0
    else
        log "ERROR: $name restart FAILED"
        return 1
    fi
}

# ── Underlay settling ──────────────────────────────────────────────────────
# True while the tunnel is still catching up with an underlay that just moved.
# Said once per switch, not once per tick.
VPN_SETTLE_REPORTED_FOR=""
underlay_settling() {
    [ "$VPN_SETTLE_AFTER_SWITCH" -gt 0 ] || return 1
    [ "$LAST_SWITCH" -gt 0 ] || return 1
    _us_age=$(( $(now) - LAST_SWITCH ))
    [ "$_us_age" -ge 0 ] && [ "$_us_age" -lt "$VPN_SETTLE_AFTER_SWITCH" ] || return 1
    if [ "$VPN_SETTLE_REPORTED_FOR" != "$LAST_SWITCH" ]; then
        VPN_SETTLE_REPORTED_FOR="$LAST_SWITCH"
        log "underlay moved ${_us_age}s ago; holding VPN judgement for up to ${VPN_SETTLE_AFTER_SWITCH}s"
    fi
    return 0
}

# ── Underlay switch ────────────────────────────────────────────────────────
switch_underlay() {
    local target="$1" force="${2:-no}" iface gw defif ts old_active old_iface old_gw
    ts="$(now)"
    if [ "$force" != yes ] && [ $((ts - LAST_SWITCH)) -lt "$SWITCH_COOLDOWN" ]; then
        return 1
    fi

    old_active=$ACTIVE
    old_iface="$(iface_for "$old_active")"
    old_gw="$(gateway_for "$old_active")"
    if [ "$target" = primary ]; then
        iface="$PRIMARY_IF"; gw="$(pppoe_gw)"
    else
        iface="$BACKUP_IF"; gw="$(backup_gw)"
    fi
    [ -n "$gw" ] || { log "cannot switch to $target: gateway unavailable"; return 1; }

    defif="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')"
    _rollback_gw=${old_gw:--}
    route_op switch-underlay "$iface" "$gw" "$old_iface" "$_rollback_gw" "$VPN_IF" || {
        log "route transaction failed while switching to $target; retained $old_active"
        return 1
    }

    ACTIVE="$target"
    LAST_SWITCH="$ts"
    # The carrier changed underneath the resolver, so whatever it learned about
    # unreachable names over the old one is now a lie it will keep telling. Same
    # reason as in gatewayctl, and never fatal: a failed flush costs stale
    # negative answers, a refused switch costs the internet.
    route_op flush-resolver-negative \
        || log "WARNING: resolver negative cache not flushed after underlay switch"
    log "switched underlay to $target ($iface via $gw), default=$defif"
    return 0
}

# ── JSON state ─────────────────────────────────────────────────────────────
write_state() {
    local tmp reason_json age_json request_error_json
    tmp="$(mktemp "${STATE_FILE}.XXXXXX")" || return 1
    reason_json=$(printf '%s' "$REASON" | sed 's/\\/\\\\/g; s/"/\\"/g')
    request_error_json=$(printf '%s' "${REQUEST_ERROR:-}" | sed 's/\\/\\\\/g; s/"/\\"/g')
    # An unknown handshake age must not be reported as 0, which readers would
    # take to mean "handshake just happened". JSON null says "not measured".
    age_json=${VPN_AGE:-null}
    cat > "$tmp" <<JSON
{"schema":8,"timestamp":$(now),"state":"$STATE","mode":"$FAILOVER_MODE","active_wan":"$ACTIVE","manual_request":"${MANUAL_REQUEST:-}","request_id":"${MANUAL_REQUEST:-}","request_status":"${REQUEST_STATUS:-}","request_error":"$request_error_json","request_started":${REQUEST_STARTED:-0},"vpn_ok":$VPN_OK,"vpn_rolled_back":${VPN_ROLLED_BACK:-false},"primary_ok":$PRIMARY_OK,"backup_ok":$BACKUP_OK,"primary_ru_ok":${PRIMARY_RU_OK:-false},"backup_ru_ok":${BACKUP_RU_OK:-false},"backup_fitted":$BACKUP_FITTED,"primary_failures":$PFAIL,"primary_recoveries":$PRECOVER,"backup_failures":$BFAIL,"vpn_net_fail":$VPN_NET_FAIL,"last_switch":$LAST_SWITCH,"reason":"$reason_json","vpn_handshake_age":${age_json}}
JSON
    chmod 640 "$tmp"
    mv -f "$tmp" "$STATE_FILE"
}

# ── Signal handling ────────────────────────────────────────────────────────
REASON="startup"
STATE="INIT"
# VPN rollback is tracked separately from STATE.
#
# Previously "we rolled the VPN back to the raw WAN" was encoded by setting
# STATE=VPN_ROLLBACK, and the WAN failover section was skipped whenever STATE
# held that value. Leaving VPN_ROLLBACK required a fresh VPN handshake, and a
# fresh handshake requires working WAN transit -- so if the VPN went down and
# then the primary WAN went down, failover to a healthy backup never ran. The
# two faults deadlocked each other. VPN health and WAN selection are independent
# concerns and now have independent state.
VPN_ROLLED_BACK=false
# Set on the way out of a stop we were asked for, so the exit trap below can
# tell that apart from a death nobody ordered.
STOP_REQUESTED=0
trap 'STOP_REQUESTED=1; REASON="stopped"; STATE="STOPPED"; write_state; rm -f "$DAEMON_PIDFILE" 2>/dev/null; exit 0' INT TERM
# A watchdog that dies must not die quietly.
#
# On 31 July the daemon started by a package upgrade was gone within a minute
# and left no trace at all: the TERM trap had not run, so the state file still
# described the *previous* stop; syslog had nothing; the stale pidfile made
# `service ... status` the only way to find out, and only for someone who
# thought to ask. Meanwhile the router had no failover and no one knew.
#
# `set -e` in a daemon this size means any unguarded command can end it between
# two log lines. That property is worth keeping -- a watchdog that carries on
# with a broken assumption is worse -- but it must be audible. rc.d supervises
# this process and restarts it; this trap is what says the restart happened and
# from which line, which is what today's outage cost us to find out.
trap '_exit_rc=$?; [ "$STOP_REQUESTED" = 1 ] || log "ERROR: watchdog exited unexpectedly (status $_exit_rc); supervisor should restart it"' EXIT
# newsyslog signals this pidfile after rotating gatebsd-watchdog.log. The shell
# default for SIGHUP is terminate, so without this trap every log rotation killed
# WAN and VPN failover until the cron supervisor noticed, up to five minutes
# later. log() reopens the file on each write, so nothing needs to be done here
# beyond surviving the signal.
trap 'log "log rotated (SIGHUP); continuing"' HUP

# ── State init ─────────────────────────────────────────────────────────────
ACTIVE="primary"; PFAIL=0; PRECOVER=0; BFAIL=0; LAST_SWITCH=0
VPN_NET_FAIL=0; MANUAL_REQUEST=""; REQUEST_STATUS=""; REQUEST_ERROR=""; REQUEST_STARTED=0
PRIMARY_OK=true; PRIMARY_RU_OK=true; BACKUP_OK=true; BACKUP_RU_OK=true; VPN_OK=true
# Assume fitted until the first tick looks; absent is the surprising answer.
BACKUP_FITTED=true
[ -x "$STATE_READER" ] || { echo "State reader is unavailable: $STATE_READER" >&2; exit 2; }
if [ -r "$STATE_FILE" ]; then
    LAST_SWITCH="$("$STATE_READER" "$STATE_FILE" last_switch)"
    _saved_active="$("$STATE_READER" "$STATE_FILE" active_wan)"
    [ -z "$_saved_active" ] || ACTIVE="$_saved_active"
    MANUAL_REQUEST="$("$STATE_READER" "$STATE_FILE" manual_request)"
    REQUEST_STATUS="$("$STATE_READER" "$STATE_FILE" request_status)"
    REQUEST_ERROR="$("$STATE_READER" "$STATE_FILE" request_error)"
    REQUEST_STARTED="$("$STATE_READER" "$STATE_FILE" request_started)"
fi
LAST_SWITCH="${LAST_SWITCH:-0}"
REQUEST_STARTED="${REQUEST_STARTED:-0}"

log "started mode=$FAILOVER_MODE primary=$PRIMARY_IF backup=$BACKUP_IF vpn=$VPN_IF"

# ── Startup: restore VPN as default if VPN is healthy ──
if [ ! -f "$VPN_DISABLED_FLAG" ]; then
    _defif="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')"
    if vpn_is_up && [ "$_defif" != "$VPN_IF" ]; then
        log "VPN is UP but default is $_defif - restoring default via $VPN_IF"
        _gw="$(usable_gateway)"
        _restore_rc=0
        if [ -n "$_gw" ]; then
            route_op enable-vpn "$(iface_for "$ACTIVE")" "$_gw" "$VPN_IF" || _restore_rc=$?
        else
            _restore_rc=1
        fi
        if [ "$_restore_rc" -eq 0 ]; then
            _defif="$VPN_IF"
        elif [ "$_restore_rc" -eq 75 ]; then
            log "gateway lock is held by another operation; deferring startup VPN restore"
            _defif="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')"
        else
            log "ERROR: failed to restore VPN route transaction"
            _defif="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')"
        fi
    fi
    if [ "$_defif" = "$VPN_IF" ]; then
        log "VPN is default on startup, applying RU bypass routes"
        _gw="$(usable_gateway)"
        if [ -n "$_gw" ]; then
            _ru_check_rc=0
            ru_state_valid "$_gw" || _ru_check_rc=$?
            if [ "$_ru_check_rc" -eq 0 ]; then
                log "RU bypass routes already valid"
            elif [ "$_ru_check_rc" -eq 75 ]; then
                log "gateway lock is held by another operation; deferring startup RU bypass check"
            else
                _ru_apply_rc=0
                ru_apply "$(iface_for "$ACTIVE")" "$_gw" || _ru_apply_rc=$?
                if [ "$_ru_apply_rc" -eq 75 ]; then
                    log "gateway lock is held by another operation; deferring startup RU bypass apply"
                fi
            fi
        fi
    fi
fi

# ── Tick sections ──────────────────────────────────────────────────────────
# One function per section, so the order in which a tick runs them is stated in
# one place -- the main loop at the bottom -- instead of being whatever the file
# grew into. That order is load-bearing; the loop says why.

# Measure both uplinks. Nothing here decides anything.
measure_links() {
    if check_iface "$PRIMARY_IF" "$PRIMARY_FIB"; then
        PRIMARY_OK=true; PRIMARY_RU_OK=true; PFAIL=0
    else
        PRIMARY_OK=false; PRIMARY_RU_OK=$LAST_IFACE_RU_OK; PFAIL=$((PFAIL + 1))
    fi
    if iface_present "$BACKUP_IF"; then
        BACKUP_FITTED=true
        BACKUP_ABSENT_REPORTED=false
        if check_iface "$BACKUP_IF" "$BACKUP_FIB"; then
            BACKUP_OK=true; BACKUP_RU_OK=true; BFAIL=0
        else
            BACKUP_OK=false; BACKUP_RU_OK=$LAST_IFACE_RU_OK; BFAIL=$((BFAIL + 1))
        fi
    else
        # Not a failure: nothing is fitted to fail. The counter stays at zero so
        # that a real backup, plugged in later, starts from a truthful number.
        BACKUP_FITTED=false
        BACKUP_OK=false
        BACKUP_RU_OK=false
        BFAIL=0
        report_backup_absent
    fi
    return 0
}

underlay_state() {
    case "${ACTIVE:-primary}" in
        backup) printf '%s' 'BACKUP' ;;
        *) printf '%s' 'PRIMARY' ;;
    esac
}

# Judge the tunnel -- on top of whichever underlay has already been chosen.
judge_vpn() {
    if [ -f "$VPN_DISABLED_FLAG" ]; then
        VPN_OK=false
        VPN_AGE=""
        defif="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')"
        if [ "$defif" = "$VPN_IF" ]; then
            log "VPN manually disabled via flag, rolling back default route to WAN"
            _gw="$(usable_gateway)"
            if [ -n "$_gw" ] && route_op vpn-rollback "$_gw" "$VPN_IF"; then
                STATE="$(underlay_state)"; REASON="vpn disabled manually"
            else
                VPN_ROLLED_BACK=true; STATE="VPN_ROLLBACK"; REASON="vpn disabled rollback failed"
                log "ERROR: failed to restore WAN and clear RU routes"
            fi
        fi
    else
        defif="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')"
        VPN_AGE=""
        if [ "$defif" = "$VPN_IF" ]; then
            # VPN is the default — monitor it
            if ! vpn_is_up; then
                VPN_OK=false
                log "ALERT: $VPN_IF is DOWN, rolling back to WAN"
                # Rollback: restore default to WAN, clear RU routes
                _gw="$(usable_gateway)"
                if [ -z "$_gw" ]; then
                    log "ERROR: rollback skipped — no WAN gateway available (PPPoE down?)"
                    STATE="NO_CONNECTIVITY"; REASON="vpn down, no wan gw"
                else
                    if route_op vpn-rollback "$_gw" "$VPN_IF"; then
                        VPN_ROLLED_BACK=true; STATE="VPN_ROLLBACK"; REASON="vpn interface down"
                    else
                        STATE="NO_CONNECTIVITY"; REASON="vpn down rollback failed"
                        log "ERROR: VPN rollback transaction failed"
                    fi
                fi
            else
                VPN_AGE="$(vpn_handshake_age)"
                if underlay_settling; then
                    # The endpoint pin moved with the underlay a moment ago and
                    # the peer has not answered through the new path yet. Both
                    # verdicts below would read that as a broken tunnel and roll
                    # back the one route that still works. The counter is reset
                    # rather than frozen so the window cannot end with a rollback
                    # already armed by failures the underlay caused.
                    VPN_NET_FAIL=0
                elif [ -n "$VPN_AGE" ] && [ "$VPN_AGE" -gt "$VPN_HANDSHAKE_MAX" ]; then
                    VPN_OK=false
                    log "ALERT: $VPN_IF handshake stale (${VPN_AGE}s > ${VPN_HANDSHAKE_MAX}s), rolling back"
                    _gw="$(usable_gateway)"
                    if [ -z "$_gw" ]; then
                        log "ERROR: rollback skipped — no WAN gateway available (PPPoE down?)"
                        STATE="NO_CONNECTIVITY"; REASON="handshake stale, no wan gw"
                    else
                        if route_op vpn-rollback "$_gw" "$VPN_IF"; then
                            VPN_ROLLED_BACK=true; STATE="VPN_ROLLBACK"; REASON="handshake stale ${VPN_AGE}s"
                        else
                            STATE="NO_CONNECTIVITY"; REASON="handshake rollback failed"
                            log "ERROR: VPN rollback transaction failed"
                        fi
                    fi
                elif ! check_net; then
                    VPN_NET_FAIL=$((VPN_NET_FAIL + 1))
                    if [ "$VPN_NET_FAIL" -ge "$VPN_NET_FAIL_THRESHOLD" ]; then
                        VPN_OK=false
                        VPN_NET_FAIL=0
                        log "ALERT: internet check failed $VPN_NET_FAIL_THRESHOLD times via $VPN_IF, rolling back"
                        _gw="$(usable_gateway)"
                        if [ -z "$_gw" ]; then
                            log "ERROR: rollback skipped — no WAN gateway available (PPPoE down?)"
                            STATE="NO_CONNECTIVITY"; REASON="vpn unreachable, no wan gw"
                        else
                            if route_op vpn-rollback "$_gw" "$VPN_IF"; then
                                VPN_ROLLED_BACK=true; STATE="VPN_ROLLBACK"; REASON="internet unreachable via vpn"
                            else
                                STATE="NO_CONNECTIVITY"; REASON="vpn network rollback failed"
                                log "ERROR: VPN rollback transaction failed"
                            fi
                        fi
                    fi
                else
                    VPN_OK=true
                    VPN_NET_FAIL=0
                    # Recover from a previous VPN rollback if the VPN is healthy.
                    if [ "$VPN_ROLLED_BACK" = true ]; then
                        VPN_ROLLED_BACK=false
                        log "Internet restored via VPN, applying RU routes"
                        _gw="$(usable_gateway)"
                        # The RU prefixes are installed via the *underlay*
                        # gateway, so that is the interface the helper must be
                        # told about; naming the VPN here is how its log line
                        # came to report a WAN gateway beside a tunnel.
                        [ -n "$_gw" ] && ru_apply "$(iface_for "$ACTIVE")" "$_gw" || true
                        STATE="$(underlay_state)"; REASON="vpn recovered"
                    fi
                fi
            fi
        else
            # The VPN is wanted -- no operator marker -- but the default route is
            # not on it. Two ways to get here, and only one of them used to be
            # handled: a rollback earlier in this run (VPN_ROLLED_BACK), or a boot
            # on which `gatewayctl apply` never succeeded at all. The second case
            # is the common one, because apply runs while PPPoE is still dialling,
            # and it left VPN_ROLLED_BACK false -- so this branch did nothing, for
            # as long as the router stayed up, and the LAN ran on the bare WAN
            # until a human noticed. Converge on the wanted state instead of
            # waiting to be told, rate-limited so a persistently unreachable peer
            # cannot starve the WAN checks.
            #
            # No handshake precondition is applied. `gatewayctl apply` requires a
            # completed handshake before it commits the default route, and
            # checks reachability again afterwards -- over TCP as well as ICMP,
            # so a carrier that filters echo cannot fake a failure -- restoring
            # the WAN by itself otherwise. A failed attempt therefore costs a
            # bounded wait and leaves the previous, working routing in place.
            #
            # It does not prove the tunnel carries traffic before committing:
            # a handshake is necessary, not sufficient, and a tunnel with too
            # large an MTU handshakes and then black-holes anything big. That is
            # caught after the commit, not before, and costs one rollback.
            VPN_OK=false
            _now="$(now)"
            if [ "$((_now - LAST_VPN_ATTEMPT))" -ge "$VPN_RETRY_INTERVAL" ]; then
                LAST_VPN_ATTEMPT="$_now"
                if [ -z "$(usable_gateway)" ]; then
                    log "VPN is wanted but no WAN gateway is available yet; deferring"
                    STATE="NO_CONNECTIVITY"; REASON="vpn wanted, no wan gw"
                else
                    log "VPN is wanted but default is ${defif:-none} - running gatewayctl apply"
                    "$GATEWAY_HELPER" apply >> "$EVENT_LOG" 2>&1 && _apply_rc=0 || _apply_rc=$?
                    if [ "$_apply_rc" -eq 0 ]; then
                        VPN_OK=true; VPN_NET_FAIL=0; VPN_ROLLED_BACK=false
                        STATE="$(underlay_state)"; REASON="vpn restored"
                        log "VPN restored, default is now $VPN_IF"
                    elif [ "$_apply_rc" -eq 75 ]; then
                        # EX_TEMPFAIL from lockf: somebody else -- the panel
                        # switching a profile, an operator running down -- holds
                        # the gateway lock. That is not a VPN failure, and
                        # recording it as one is how a rollback nobody performed
                        # reaches the panel: VPN_ROLLED_BACK survives into
                        # watchdog.json and the operator reads "rollback" about an
                        # operation that is still running. Say what happened and
                        # let the next tick find the work done.
                        log "gateway lock is held by another operation; deferring this tick"
                        REASON="gateway busy, deferring"
                    else
                        VPN_ROLLED_BACK=true
                        STATE="VPN_ROLLBACK"; REASON="vpn down, retrying"
                    fi
                fi
            fi
        fi
    fi

    # Converge a newly published RU table even when WAN/VPN state did not change.
    if [ "${defif:-}" = "$VPN_IF" ]; then
        _gw="$(usable_gateway)"
        if [ -n "$_gw" ]; then
            _ru_check_rc=0
            ru_state_valid "$_gw" || _ru_check_rc=$?
            if [ "$_ru_check_rc" -ne 0 ] && [ "$_ru_check_rc" -ne 75 ]; then
                _ru_apply_rc=0
                ru_apply "$(iface_for "$ACTIVE")" "$_gw" || _ru_apply_rc=$?
                if [ "$_ru_apply_rc" -eq 75 ]; then
                    log "gateway lock is held by another operation; deferring RU route convergence"
                elif [ "$_ru_apply_rc" -ne 0 ]; then
                    log "ERROR: RU route convergence failed"
                fi
            fi
        fi
    fi
    return 0
}

# Restart the daemons that provide the links, in dependency order.
supervise_services() {
    _SVC_RESTARTED=false
    check_service mpd5 LAST_RESTART_MPD5 || true
    if [ ! -f "$VPN_DISABLED_FLAG" ]; then
        check_service amnezia LAST_RESTART_AMNEZIA || true
    fi
    check_service unbound LAST_RESTART_UNBOUND || true

    # If a critical service was restarted, re-evaluate VPN default
    if [ "$_SVC_RESTARTED" = true ] && [ ! -f "$VPN_DISABLED_FLAG" ]; then
        _defif="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')"
        if [ "$_defif" != "$VPN_IF" ] && vpn_is_up; then
            log "Service restarted — restoring VPN default"
            "$GATEWAY_HELPER" apply >> "$EVENT_LOG" 2>&1 || true
        fi
    fi
    return 0
}

# Choose the underlay that carries traffic, from this tick's measurements.
#
# Runs unconditionally. Which underlay carries traffic is independent of
# whether the VPN is currently usable: if anything, a VPN outage makes a
# healthy WAN more important, not less. Gating this section on VPN state is
# what previously allowed a VPN outage plus a primary-WAN outage to deadlock
# into a permanent loss of connectivity with a healthy backup link idle.
select_underlay() {
    if [ "$FAILOVER_MODE" = manual ] && [ -r "$MANUAL_WAN_FILE" ]; then
        _request_line="$(sed -n '1p' "$MANUAL_WAN_FILE" | tr -d '\r\n')"
        _requested=${_request_line%% *}
        _request_id=${_request_line#* }
        case "$_request_id" in ''|*[!A-Za-z0-9._-]*) _request_id=invalid ;; esac
        case "$_requested:$_request_id" in
            primary:invalid|backup:invalid)
                MANUAL_REQUEST=""
                REQUEST_STATUS="failed"
                REQUEST_ERROR="invalid manual WAN request identifier"
                log "ignoring manual WAN request with invalid identifier"
                rm -f "$MANUAL_WAN_FILE"
                ;;
            primary:*|backup:*)
                MANUAL_REQUEST=$_request_id
                REQUEST_STATUS="pending"
                REQUEST_ERROR=""
                REQUEST_STARTED=$(now)
                if [ "$_requested" != "$ACTIVE" ]; then
                    STATE="SWITCHING_TO_$(printf '%s' "$_requested" | tr '[:lower:]' '[:upper:]')"
                    write_state
                    if switch_underlay "$_requested" yes; then
                        STATE="$(printf '%s' "$_requested" | tr '[:lower:]' '[:upper:]')"
                        REASON="manual switch to $_requested"
                    else
                        STATE="$(printf '%s' "$ACTIVE" | tr '[:lower:]' '[:upper:]')"
                        REASON="manual switch to $_requested failed"
                        REQUEST_STATUS="failed"
                        REQUEST_ERROR="$REASON"
                    fi
                else
                    STATE="$(printf '%s' "$ACTIVE" | tr '[:lower:]' '[:upper:]')"
                    REASON="manual $ACTIVE active"
                    REQUEST_STATUS="succeeded"
                fi
                ;;
            *)
                MANUAL_REQUEST=""
                REQUEST_STATUS="failed"
                REQUEST_ERROR="invalid manual WAN request"
                log "ignoring invalid manual WAN request"
                rm -f "$MANUAL_WAN_FILE"
                ;;
        esac
    elif [ "$ACTIVE" = primary ]; then
        if [ "$PRIMARY_OK" = true ]; then
            STATE="PRIMARY"; REASON="primary healthy"
        elif [ "$PFAIL" -ge "$FAIL_THRESHOLD" ]; then
            STATE="PRIMARY_DEGRADED"; REASON="primary failed threshold"
            if [ "$FAILOVER_MODE" = automatic ] && [ "$BACKUP_OK" = true ]; then
                STATE="SWITCHING_TO_BACKUP"
                if switch_underlay backup; then
                    STATE="BACKUP"; REASON="backup active"
                else
                    STATE="PRIMARY_DEGRADED"; REASON="switch to backup failed"
                fi
            fi
        fi
    else
        # On backup — require consecutive healthy checks before recovery.
        held=$(( $(now) - LAST_SWITCH ))
        if [ "$PRIMARY_OK" = true ]; then
            PRECOVER=$((PRECOVER + 1))
        else
            PRECOVER=0
        fi
        if [ "$PRIMARY_OK" = true ] && [ "$PRECOVER" -ge "$RECOVERY_THRESHOLD" ] && [ "$held" -ge "$MIN_BACKUP_HOLD" ]; then
            STATE="PRIMARY_RECOVERING"; REASON="primary stable for $PRECOVER checks"
            if [ "$FAILOVER_MODE" = automatic ]; then
                STATE="SWITCHING_TO_PRIMARY"
                if switch_underlay primary; then
                    PRECOVER=0
                    STATE="PRIMARY"; REASON="primary restored"
                else
                    STATE="BACKUP"; REASON="switch to primary failed"
                fi
            fi
        elif [ "$BACKUP_OK" = true ]; then
            STATE="BACKUP"; REASON="backup active"
        else
            STATE="NO_CONNECTIVITY"; REASON="both links unavailable"
        fi
    fi
    return 0
}

complete_manual_request() {
    [ -n "${MANUAL_REQUEST:-}" ] || return 0
    [ "${REQUEST_STATUS:-}" = pending ] || return 0
    if [ -f "$VPN_DISABLED_FLAG" ] || [ "${VPN_ROLLED_BACK:-false}" = true ]; then
        REQUEST_STATUS="succeeded"
        REQUEST_ERROR=""
        return 0
    fi
    if [ ! -r "$RU_TABLE" ]; then
        REQUEST_STATUS="succeeded"
        REQUEST_ERROR=""
        return 0
    fi
    _request_gw=$(gateway_for "$ACTIVE")
    if [ -n "$_request_gw" ] && ru_state_valid "$_request_gw"; then
        REQUEST_STATUS="succeeded"
        REQUEST_ERROR=""
        return 0
    fi
    if [ $(( $(now) - ${REQUEST_STARTED:-0} )) -ge "$REQUEST_TIMEOUT" ]; then
        REQUEST_STATUS="failed"
        REQUEST_ERROR="RU route convergence timed out after ${REQUEST_TIMEOUT}s"
        log "ERROR: manual request $MANUAL_REQUEST failed: $REQUEST_ERROR"
    fi
    return 0
}

# ── Main loop ──────────────────────────────────────────────────────────────
# The order below is the fix for what happened on 1 August, and it is the whole
# point of splitting the tick into named sections.
#
# The primary PPPoE died. The VPN section ran first, saw the internet check fail
# through awg0, and concluded the *tunnel* was broken -- it was not; the ground
# under it had gone. It spent 45s rolling a healthy tunnel back to a WAN that no
# longer had a gateway, the rollback failed for exactly that reason, and the
# underlay switch that finally ran inherited a half-applied route set and failed
# too. `awg0: loop detected` filled the console at a hundred lines a second
# throughout.
#
# So: measure the ground, choose the ground, repair the daemons that provide the
# ground, and only then judge what is carried over it. A tunnel cannot be
# assessed against an underlay that is about to be replaced in the same tick.
while :; do
    safe_source "$CONF" 0 || true
    measure_links
    select_underlay
    supervise_services
    judge_vpn
    complete_manual_request

    write_state
    if [ -n "${MANUAL_REQUEST:-}" ] && [ -f "$MANUAL_WAN_FILE" ]; then
        rm -f "$MANUAL_WAN_FILE"
    fi

    sleep "$CHECK_INTERVAL"
done
