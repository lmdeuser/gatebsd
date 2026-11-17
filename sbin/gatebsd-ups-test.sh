#!/bin/sh
# Monthly controlled UPS self-test with serialized cleanup.
set -eu
PATH=${GATEBSD_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}
DURATION=${GATEBSD_UPS_TEST_DURATION:-60}
RECOVERY_TIMEOUT=${GATEBSD_UPS_RECOVERY_TIMEOUT:-30}
LOCK_FILE=${GATEBSD_UPS_TEST_LOCK:-/var/run/gatebsd/ups-test.lock}
UPSMON_CONF=${GATEBSD_UPSMON_CONF:-/usr/local/etc/nut/upsmon.conf}
UPSD_USERS=${GATEBSD_UPSD_USERS:-/usr/local/etc/nut/upsd.users}
STARTED=0

log() { logger -t gatebsd-ups-test -- "$*" 2>/dev/null || printf '%s\n' "$*" >&2; }

# Create the shared runtime directory if it is missing, and otherwise leave its
# ownership alone.
#
# /var/run/gatebsd holds the agent's unix socket, and the web UI runs as the
# unprivileged service account, which needs the group's traverse bit to reach
# it. `install -d -o root -g wheel` re-applies owner, group and mode to a
# directory that already exists, so the monthly battery test was enough to make
# the panel answer 503 "agent unavailable" until something recreated the
# directory -- a month later nobody would connect the two. Validate what is
# there; never re-own it. Full account in sbin/ru-bypass-update.sh.
ensure_runtime_dir() {
    _dir=$1
    if [ -e "$_dir" ] || [ -L "$_dir" ]; then
        [ -d "$_dir" ] && [ ! -L "$_dir" ] || { log "unsafe runtime directory: $_dir"; exit 1; }
        _dir_uid=$(stat -f '%u' "$_dir" 2>/dev/null || printf '%s' -1)
        _dir_mode=$(stat -f '%Lp' "$_dir" 2>/dev/null || printf '%s' 777)
        [ "$_dir_uid" = 0 ] || { log "runtime directory must be root-owned: $_dir"; exit 1; }
        case "$_dir_mode" in
            *[2367][0-7]|*[0-7][2367]) log "runtime directory must not be group/world writable: $_dir"; exit 1 ;;
        esac
    else
        install -d -o root -g "${GATEBSD_SERVICE_GROUP:-gatebsd}" -m 0750 "$_dir"
    fi
}
case "$DURATION" in ''|*[!0-9]*) log "invalid test duration"; exit 2 ;; esac
[ "$DURATION" -ge 10 ] && [ "$DURATION" -le 600 ] || { log "test duration out of range"; exit 2; }
case "$RECOVERY_TIMEOUT" in ''|*[!0-9]*) log "invalid recovery timeout"; exit 2 ;; esac
[ "$RECOVERY_TIMEOUT" -ge 1 ] && [ "$RECOVERY_TIMEOUT" -le 300 ] || { log "recovery timeout out of range"; exit 2; }
if [ "${GATEBSD_UPS_TEST_LOCK_HELD:-0}" != 1 ]; then
    ensure_runtime_dir "$(dirname "$LOCK_FILE")"
    exec env -i PATH="$PATH" HOME=/root LANG=C.UTF-8 \
        GATEBSD_UPS_TEST_LOCK_HELD=1 \
        GATEBSD_UPS_TEST_DURATION="$DURATION" \
        GATEBSD_UPS_RECOVERY_TIMEOUT="$RECOVERY_TIMEOUT" \
        GATEBSD_UPS_TEST_LOCK="$LOCK_FILE" \
        GATEBSD_UPSMON_CONF="$UPSMON_CONF" \
        GATEBSD_UPSD_USERS="$UPSD_USERS" \
        GATEBSD_UPS_TARGET="${GATEBSD_UPS_TARGET:-}" \
        NUT_USER="${NUT_USER:-}" NUT_PASS="${NUT_PASS:-}" \
        lockf -t 0 "$LOCK_FILE" "$0" "$@"
fi

[ -f "$UPSMON_CONF" ] && [ ! -L "$UPSMON_CONF" ] || { log "unsafe or missing upsmon.conf"; exit 1; }
[ -f "$UPSD_USERS" ] && [ ! -L "$UPSD_USERS" ] || { log "unsafe or missing upsd.users"; exit 1; }
_monitor=$(awk '$1 == "MONITOR" && NF >= 6 {print $2 " " $4 " " $5; exit}' "$UPSMON_CONF")
set -- $_monitor
[ "$#" -eq 3 ] || { log "cannot parse UPS monitor credentials"; exit 1; }
TARGET=${GATEBSD_UPS_TARGET:-$1}
NUT_USER=${NUT_USER:-$2}
NUT_PASS=${NUT_PASS:-$3}
case "$TARGET:$NUT_USER" in *[!A-Za-z0-9_.@:-]*) log "unsafe UPS target or user"; exit 1 ;; esac
[ -n "$NUT_PASS" ] || { log "unsafe or empty NUT password"; exit 1; }
if printf '%s' "$NUT_PASS" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    log "unsafe NUT password"
    exit 1
fi

stop_test() {
    if [ "$STARTED" -eq 1 ]; then
        upscmd -u "$NUT_USER" -p "$NUT_PASS" "$TARGET" test.battery.stop >/dev/null 2>&1 || true
        STARTED=0
    fi
}
cleanup() { stop_test; }
trap cleanup EXIT HUP INT TERM
query() { upsc "$TARGET" "$1" 2>/dev/null || true; }
is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
has_status() { case " $1 " in *" $2 "*) return 0 ;; *) return 1 ;; esac; }

charge_before=$(query battery.charge)
status_before=$(query ups.status)
charge_int=${charge_before%%.*}
log "test start target=$TARGET charge=${charge_before:-unknown}% status=${status_before:-unknown}"

# "Could not read" and "not now" are different answers and must not share a
# message or an exit status.
#
# This used to say "SKIP: UPS is not on line power" and exit 0 whenever the
# status was empty -- which is what it logged on 2026-08-01 while the link to
# the UPS had been dead since the previous night. The line was untrue, the exit
# status said success, and the monthly battery test had therefore probably
# never run at all. A test that reports success for not running is worse than
# no test.
if [ -z "$status_before" ]; then
    log "FAIL: cannot read $TARGET -- the battery test did not run"
    exit 1
fi
if ! is_uint "$charge_int"; then
    log "FAIL: battery charge is unreadable (${charge_before:-empty}) -- the battery test did not run"
    exit 1
fi
# From here the readings are real, so a skip is a genuine "not now".
has_status "$status_before" OL || { log "SKIP: UPS is on ${status_before}, not line power"; exit 0; }
[ "$charge_int" -ge 50 ] || { log "SKIP: battery charge is ${charge_before}%, below 50%"; exit 0; }

if ! upscmd -u "$NUT_USER" -p "$NUT_PASS" "$TARGET" test.battery.start.quick >/dev/null 2>&1; then
    log "ERROR: test.battery.start.quick failed"
    exit 1
fi
STARTED=1

# Acceptance by upscmd is not evidence that the UPS actually performed a
# battery test. Observe the state exported by the driver while the command is
# active. Without CAL/OB/DISCHRG this run fails closed instead of creating a
# fictitious successful monthly test.
observed_test=0
elapsed=0
while [ "$elapsed" -lt "$DURATION" ]; do
    status_during=$(query ups.status)
    if [ -z "$status_during" ]; then
        log "FAIL: UPS telemetry disappeared during the battery test"
        exit 1
    fi
    if has_status "$status_during" CAL || has_status "$status_during" OB || has_status "$status_during" DISCHRG; then
        observed_test=1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done
stop_test

if [ "$observed_test" -ne 1 ]; then
    log "FAIL: UPS accepted the command but no CAL/OB/DISCHRG state was observed"
    exit 1
fi

# A completed test is safe only after the UPS is observably back on utility
# power. Give the driver a bounded interval to publish that transition.
recovery_elapsed=0
status_after=''
while [ "$recovery_elapsed" -lt "$RECOVERY_TIMEOUT" ]; do
    status_after=$(query ups.status)
    has_status "$status_after" OL && break
    sleep 1
    recovery_elapsed=$((recovery_elapsed + 1))
done
if ! has_status "$status_after" OL; then
    log "FAIL: UPS did not return to OL after the battery test (status=${status_after:-unknown})"
    exit 1
fi

charge_after=$(query battery.charge)
voltage_after=$(query battery.voltage)
log "test end charge=${charge_after:-unknown}% status=${status_after:-unknown} voltage=${voltage_after:-unknown}V"
after_int=${charge_after%%.*}
if is_uint "$after_int"; then
    drain=$((charge_int - after_int))
    log "battery drain=${drain}% duration=${DURATION}s"
    [ "$drain" -le 20 ] || log "WARNING: high drain rate may indicate battery degradation"
fi
voltage_int=${voltage_after%%.*}
if is_uint "$voltage_int"; then
    if [ "$voltage_int" -lt 21 ]; then log "CRITICAL: battery voltage is too low"
    elif [ "$voltage_int" -lt 23 ]; then log "WARNING: battery voltage is low"
    else log "battery voltage is healthy"; fi
fi
trap - EXIT HUP INT TERM
log "monthly UPS test completed"
