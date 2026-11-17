#!/bin/sh
# Periodic read-only UPS health check.
set -eu
PATH=${GATEBSD_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}
ALERT_THRESHOLD=${GATEBSD_UPS_ALERT_THRESHOLD:-80}
UPSMON_CONF=${GATEBSD_UPSMON_CONF:-/usr/local/etc/nut/upsmon.conf}
STATE_FILE=${GATEBSD_UPS_HEALTH_STATE:-/var/run/gatebsd/ups-health.state}
ERRORS=0

log() { logger -t gatebsd-ups-health -- "$*" 2>/dev/null || printf '%s\n' "$*" >&2; }
alert() { log "ALERT: $*"; ERRORS=$((ERRORS + 1)); }
case "$ALERT_THRESHOLD" in ''|*[!0-9]*) log "invalid alert threshold"; exit 2 ;; esac
[ "$ALERT_THRESHOLD" -le 100 ] || { log "alert threshold out of range"; exit 2; }

ups_target() {
    if [ -n "${GATEBSD_UPS_TARGET:-}" ]; then printf '%s\n' "$GATEBSD_UPS_TARGET"; return; fi
    if [ -f "$UPSMON_CONF" ] && [ ! -L "$UPSMON_CONF" ]; then
        awk '$1 == "MONITOR" && NF >= 2 {print $2; exit}' "$UPSMON_CONF"
        return
    fi
    _name=$(upsc -l 2>/dev/null | sed -n '1p')
    [ -z "$_name" ] || printf '%s@localhost\n' "$_name"
}

TARGET=$(ups_target)
case "$TARGET" in ''|*[!A-Za-z0-9_.@:-]*) log "no safe UPS target is configured"; exit 1 ;; esac
query() { upsc "$TARGET" "$1" 2>/dev/null || true; }
integer_part() { printf '%s\n' "${1%%.*}"; }
is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
has_status() { case " $1 " in *" $2 "*) return 0 ;; *) return 1 ;; esac; }

charge=$(query battery.charge)
voltage=$(query battery.voltage)
status=$(query ups.status)
temp=$(query ups.temperature)
load=$(query ups.load)
log "health target=$TARGET charge=${charge:-unknown}% voltage=${voltage:-unknown}V status=${status:-unknown} temp=${temp:-unknown}C load=${load:-unknown}%"

# A UPS that cannot be read is not a healthy UPS.
#
# Every check below is guarded by "is this a number" or "is the status OL", so
# when upsd answers nothing they all pass and the run exits 0. That is exactly
# what happened: the link to the UPS died on 2026-07-31 at 23:42, this check
# logged `charge=unknown status=unknown` at 06:00 on two mornings, raised
# nothing, and the machine lost power on the second of them with nobody aware
# it had been unmonitored for a day.
#
# "I could not read it" must never be reported as "it is fine".
if [ -z "$status" ]; then
    alert "cannot read $TARGET: upsd returned nothing -- the driver is down or the link to the UPS is gone"
elif ! is_uint "$(integer_part "$charge")"; then
    # battery.charge is the only low-battery criterion that works on this
    # hardware: the driver mis-parses the model string, so battery.runtime
    # comes back as a word and every comparison against it is meaningless.
    # Losing charge as well leaves nothing watching the battery at all.
    alert "battery charge is unreadable (${charge:-empty}) while the UPS answers -- nothing is watching the battery"
fi

charge_int=$(integer_part "$charge")
if has_status "$status" OL && is_uint "$charge_int" && [ "$charge_int" -lt "$ALERT_THRESHOLD" ]; then
    alert "battery at ${charge}% while on line power"
fi
voltage_int=$(integer_part "$voltage")
if is_uint "$voltage_int" && [ "$voltage_int" -lt 22 ]; then
    alert "battery voltage ${voltage}V is critically low"
fi
service nut onestatus >/dev/null 2>&1 || alert "NUT server or UPS driver is not running"
service nut_upsmon onestatus >/dev/null 2>&1 || alert "NUT upsmon is not running"
[ "$(sysrc -n nut_upsshut 2>/dev/null || true)" = YES ] || alert "nut_upsshut is not enabled"

USERS=/usr/local/etc/nut/upsd.users
if [ -e "$USERS" ] || [ -L "$USERS" ]; then
    if [ ! -f "$USERS" ] || [ -L "$USERS" ]; then
        alert "upsd.users is unsafe"
    elif grep -Eq '^[[:space:]]*upsmon[[:space:]]*=' "$USERS"; then
        alert "upsd.users contains invalid upsmon assignment syntax"
    fi
fi
if has_status "$status" OL && [ -e /etc/killpower ]; then alert "stale /etc/killpower exists while UPS is on line power"; fi

publish_state() {
    _now=$(date +%s)
    _previous=""
    if [ -f "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] && [ -r "$STATE_FILE" ]; then
        _previous=$(sed -n 's/^last_response_at=//p' "$STATE_FILE" | head -1)
        case "$_previous" in ''|*[!0-9]*) _previous="" ;; esac
    fi
    _response=$_previous
    [ -z "$status" ] || _response=$_now
    _ok=false
    [ "$ERRORS" -ne 0 ] || _ok=true
    _tmp=$(mktemp "${STATE_FILE}.XXXXXX") || { alert "cannot create health state"; return 1; }
    if ! {
        printf 'schema=1\nchecked_at=%s\nok=%s\nerrors=%s\nlast_response_at=%s\nstatus=%s\ncharge=%s\n' \
            "$_now" "$_ok" "$ERRORS" "$_response" "$status" "$charge" > "$_tmp" &&
        chmod 0644 "$_tmp" && mv -f "$_tmp" "$STATE_FILE"
    }; then
        rm -f "$_tmp"
        alert "cannot publish health state"
        return 1
    fi
}
publish_state
[ "$ERRORS" -eq 0 ]
