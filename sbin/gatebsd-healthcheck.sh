#!/bin/sh
# Lightweight supervisor for GateBSD services with PID-bound watchdog checks.
set -eu

PATH=${GATEBSD_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}
PIDFILE=${GATEBSD_WATCHDOG_PIDFILE:-/var/run/gatebsd/watchdog.pid}
UPSMON_CONF=${GATEBSD_UPSMON_CONF:-/usr/local/etc/nut/upsmon.conf}
UPS_BOOTSTRAP=${GATEBSD_UPS_BOOTSTRAP:-/usr/local/sbin/gatebsd-ups-bootstrap}
UPS_STATE=${GATEBSD_UPS_SUPERVISOR_STATE:-/var/run/gatebsd/ups-supervisor.failures}
UPS_RESTART_AFTER=${GATEBSD_UPS_RESTART_AFTER:-3}
UPS_RESTART_COOLDOWN=${GATEBSD_UPS_RESTART_COOLDOWN:-15}

case "$UPS_RESTART_AFTER:$UPS_RESTART_COOLDOWN" in
    *[!0-9:]*|:*|*:) echo "invalid UPS supervisor limits" >&2; exit 2 ;;
esac
[ "$UPS_RESTART_AFTER" -ge 1 ] && [ "$UPS_RESTART_COOLDOWN" -ge 1 ] || {
    echo "invalid UPS supervisor limits" >&2
    exit 2
}

log() {
    logger -t gatebsd-healthcheck -- "$*" 2>/dev/null || printf '%s\n' "$*" >&2
}

ensure_service() {
    service "$1" onestatus >/dev/null 2>&1 && return 0
    log "$1 is down; restarting"
    service "$1" restart >/dev/null 2>&1 || service "$1" start >/dev/null 2>&1 || {
        log "$1 restart failed"
        return 1
    }
}

ups_target() {
    if [ -n "${GATEBSD_UPS_TARGET:-}" ]; then printf '%s\n' "$GATEBSD_UPS_TARGET"; return; fi
    [ -f "$UPSMON_CONF" ] && [ ! -L "$UPSMON_CONF" ] || return 0
    awk '$1 == "MONITOR" && NF >= 2 {print $2; exit}' "$UPSMON_CONF"
}

ups_restart_allowed() {
    [ ! -L "${UPS_STATE}.restart" ] || { log "unsafe UPS restart marker"; return 1; }
    [ ! -f "${UPS_STATE}.restart" ] && return 0
    # FreeBSD find supports -mmin. A marker newer than the cooldown blocks a
    # new attempt, bounding a persistent USB/link fault to one restart per
    # cooldown instead of one every cron minute.
    [ -z "$(find "${UPS_STATE}.restart" -mmin "-${UPS_RESTART_COOLDOWN}" -print -quit 2>/dev/null)" ]
}

mark_ups_restart() {
    umask 077
    _tmp="${UPS_STATE}.restart.$$"
    : > "$_tmp" 2>/dev/null || return 1
    mv -f "$_tmp" "${UPS_STATE}.restart" 2>/dev/null || { rm -f "$_tmp"; return 1; }
}

restart_ups_once() {
    _reason=$1
    if ! ups_restart_allowed; then
        log "UPS $_reason; restart suppressed by cooldown"
        return 1
    fi
    mark_ups_restart || { log "cannot record UPS restart cooldown"; return 1; }
    log "UPS $_reason; restarting nut"
    service nut restart >/dev/null 2>&1 || service nut start >/dev/null 2>&1 || {
        log "nut restart failed"
        return 1
    }
}

supervise_ups() {
    [ "$(sysrc -n nut_enable 2>/dev/null || true)" = YES ] || return 0

    if [ ! -x "$UPS_BOOTSTRAP" ] || ! "$UPS_BOOTSTRAP" --check >/dev/null 2>&1; then
        log "UPS configuration is incomplete or inconsistent; not restarting NUT"
        return 0
    fi

    if ! service nut onestatus >/dev/null 2>&1; then
        restart_ups_once "service is down" || true
    fi
    if [ "$(sysrc -n nut_upsmon_enable 2>/dev/null || true)" = YES ]; then
        ensure_service nut_upsmon || true
    fi

    _target=$(ups_target)
    case "$_target" in
        ''|*[!A-Za-z0-9_.@:-]*) log "UPS target is missing or unsafe"; return 0 ;;
    esac
    if upsc "$_target" ups.status >/dev/null 2>&1; then
        [ ! -f "$UPS_STATE" ] || rm -f "$UPS_STATE"
        return 0
    fi

    _failures=0
    if [ -L "$UPS_STATE" ]; then
        log "unsafe UPS supervisor state"
        return 0
    fi
    if [ -r "$UPS_STATE" ]; then
        _failures=$(sed -n '1p' "$UPS_STATE" 2>/dev/null || true)
    fi
    case "$_failures" in ''|*[!0-9]*) _failures=0 ;; esac
    _failures=$((_failures + 1))
    umask 077
    _tmp="${UPS_STATE}.$$"
    if printf '%s\n' "$_failures" > "$_tmp" 2>/dev/null; then
        mv -f "$_tmp" "$UPS_STATE" 2>/dev/null || rm -f "$_tmp"
    fi
    log "UPS telemetry unavailable ($_failures consecutive checks)"
    if [ "$_failures" -ge "$UPS_RESTART_AFTER" ]; then
        restart_ups_once "telemetry is unavailable" || true
    fi
}

watchdog_running() {
    [ -f "$PIDFILE" ] && [ ! -L "$PIDFILE" ] || return 1
    _pid=$(sed -n '1p' "$PIDFILE" 2>/dev/null | tr -d '\r\n')
    case "$_pid" in ''|*[!0-9]*) return 1 ;; esac
    [ "$_pid" -gt 1 ] 2>/dev/null || return 1
    kill -0 "$_pid" 2>/dev/null || return 1
    _command=$(ps -p "$_pid" -o command= 2>/dev/null || true)
    case "$_command" in *gatebsd-watchdog.sh*) return 0 ;; *) return 1 ;; esac
}

# Before restarting anything, make sure there is a configuration to restart
# into. Without this the guard only runs at upgrade time, and a config corrupted
# by some other writer stays dormant until then -- which is how an eight-day-old
# defect gets to look like the upgrade's fault.
CONFIG_GUARD=${GATEBSD_CONFIG_GUARD:-/usr/local/sbin/gatebsd-config-guard}
UNSTARTABLE=''
if [ -x "$CONFIG_GUARD" ]; then
    guard_status=0
    guard_out=$("$CONFIG_GUARD" 2>/dev/null) || guard_status=$?
    if [ "$guard_status" -eq 2 ]; then
        UNSTARTABLE=$(printf '%s\n' "$guard_out" | sed -n 's/^UNSTARTABLE://p')
        log "config guard condemned:${UNSTARTABLE:- (nothing named)}"
    elif [ "$guard_status" -ne 0 ]; then
        log "config guard exited $guard_status"
    fi
fi

# Restarting a service the guard has condemned loads a file already known not to
# parse -- the outage this script runs to prevent, delivered by the supervisor
# itself. Only the named services are spared: a broken dhcpd.conf is no reason
# to leave the uplink watchdog down.
condemned() {
    case " $UNSTARTABLE " in *" $1 "*) return 0 ;; esac
    return 1
}

ensure_service gatebsd || true
if condemned nginx; then
    log "nginx configuration is unstartable; not restarting nginx"
else
    ensure_service nginx || true
fi
supervise_ups
watchdog_running && exit 0

log "watchdog is not running; restarting gatebsd_failover"
service gatebsd_failover restart >/dev/null 2>&1 || service gatebsd_failover start >/dev/null 2>&1 || {
    log "gatebsd_failover restart failed"
    exit 1
}
