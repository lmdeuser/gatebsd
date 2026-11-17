"""Dependency-aware, serialized internet recovery for the GateBSD UI."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from . import paths
from .command import CommandResult, run
from .fsutil import atomic_write_text, exclusive_lock, read_regular_text
from .adapters.helpers import WAN_IF, BACKUP_IF, VPN_IF, LAN_IF
from .adapters.vpn_path import classify, measure_operator_disabled, measure_rolled_back


LOCK_PATH = Path("/var/run/gatebsd/internet-recovery.lock")
REPORT_PATH = Path("/var/db/gatebsd/last-recovery.json")
AUTO_STATE_PATH = Path("/var/db/gatebsd/auto-recovery-state.json")
VPN_DISABLED = paths.VPN_DISABLED
AUTO_FAIL_THRESHOLD = 2
AUTO_COOLDOWN = 180


def _detail(result: CommandResult, fallback: str) -> str:
    text = "\n".join(part for part in (result.stdout, result.stderr, result.error or "") if part)
    return (text or fallback)[:500]


def _iface_up(name: str) -> bool:
    result = run(["ifconfig", name], timeout=3)
    return result.ok and "UP" in result.stdout


def _ping() -> CommandResult:
    return run(["ping", "-c", "2", "-W", "2000", "1.1.1.1"], timeout=7)


def _interface_ipv4(name: str) -> str | None:
    result = run(["ifconfig", name], timeout=3)
    if not result.ok:
        return None
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "inet":
            return fields[1]
    return None


def _dns() -> CommandResult:
    # Resolve in a separate process so command.run can enforce a hard timeout.
    command = ["/usr/local/libexec/gatebsd-python", "-m", "gatebsd_ui.resolver"]
    env = {"PYTHONPATH": "/usr/local/share/gatebsd/webui/backend"}
    server = _interface_ipv4(LAN_IF)
    if server:
        result = run([*command, "--server", server, "one.one.one.one"], timeout=7, env=env)
        if result.ok:
            return result
    return run([*command, "one.one.one.one"], timeout=7, env=env)


def _https() -> CommandResult:
    return run(["fetch", "-T", "5", "-qo", "/dev/null", "https://one.one.one.one/cdn-cgi/trace"], timeout=8)


def _default_interface() -> str | None:
    result = run(["route", "-n", "get", "default"], timeout=3)
    if not result.ok:
        return None
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "interface:":
            return fields[1]
    return None


def _healthy() -> tuple[bool, dict[str, bool]]:
    checks = {"ip": _ping().ok, "dns": _dns().ok, "https": _https().ok}
    return all(checks.values()), checks


def _vpn_state() -> dict[str, Any]:
    """Which of the five VPN states we are in, measured now.

    Recovery used to collapse this into one boolean, `preferred_path`, and that
    boolean was true whenever the operator's marker was present -- so the button
    reported "the internet is working normally" over a household whose traffic
    had been outside the tunnel for two and a half hours. The verdict is the
    same; what changed is that the report can now name the path it approved.
    """
    return classify(
        interface_up=_iface_up(VPN_IF),
        default_iface=_default_interface(),
        operator_disabled=measure_operator_disabled(),
        rolled_back=measure_rolled_back(),
    )


def _working_message(vpn: dict[str, Any]) -> str:
    """What to say when the checks pass and the path is the configured one."""
    if vpn.get("in_tunnel"):
        return "Internet is working normally"
    return (
        f"Internet works, but not via VPN: {vpn['label']}. "
        f"Traffic routes directly via {vpn.get('default_iface') or 'unknown interface'}."
    )


def _failover_request() -> dict[str, Any]:
    try:
        text, _metadata = read_regular_text(
            paths.FAILOVER_STATE, max_size=256 * 1024, errors="strict"
        )
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}


def _save_report(report: dict[str, Any]) -> None:
    try:
        atomic_write_text(
            REPORT_PATH,
            json.dumps(report, ensure_ascii=False) + "\n",
            mode=0o640,
            preserve_metadata=REPORT_PATH.exists(),
        )
    except OSError:
        pass


def _load_auto_state() -> dict[str, int]:
    try:
        text, _metadata = read_regular_text(AUTO_STATE_PATH, max_size=64 * 1024, errors="strict")
        data = json.loads(text)
        return {"failures": int(data.get("failures", 0)),
                "last_attempt": int(data.get("last_attempt", 0))}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {"failures": 0, "last_attempt": 0}


def _save_auto_state(state: dict[str, Any]) -> None:
    try:
        atomic_write_text(
            AUTO_STATE_PATH,
            json.dumps(state, ensure_ascii=False) + "\n",
            mode=0o640,
            preserve_metadata=AUTO_STATE_PATH.exists(),
        )
    except OSError:
        pass


def recover_internet() -> tuple[int, dict[str, Any]]:
    """Repair only failed layers, preserving the existing gateway config."""
    steps: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str, action: bool = False) -> None:
        steps.append({"name": name, "ok": ok, "detail": detail, "action": action})

    try:
        lock_context = exclusive_lock(LOCK_PATH, nonblocking=True)
        lock_context.__enter__()
    except BlockingIOError:
        return 409, {"ok": False, "busy": True, "steps": [], "message": "Recovery is already running"}
    except OSError as exc:
        return 500, {"ok": False, "steps": [], "message": f"Failed to acquire recovery lock: {exc}"}

    try:
        failover_request = _failover_request()
        if failover_request.get("request_status") == "pending":
            request_id = failover_request.get("request_id") or failover_request.get("manual_request") or "unknown"
            return 409, {
                "ok": False,
                "busy": True,
                "steps": [],
                "message": f"WAN switch already in progress: {request_id}",
            }

        healthy, initial = _healthy()
        vpn = _vpn_state()
        vpn_enabled = not vpn["operator_disabled"] if vpn["operator_disabled"] is not None else True
        preferred_path = vpn["expected"] is True
        add("Initial diagnostics", healthy,
            f"IP={initial['ip']} DNS={initial['dns']} HTTPS={initial['https']} VPN={vpn['label']}")
        if healthy and preferred_path:
            report = {"ok": True, "already_working": True, "degraded": False, "vpn": vpn,
                      "timestamp": int(time.time()), "steps": steps, "message": _working_message(vpn)}
            _save_report(report)
            return 200, report

        # Underlay must exist before VPN or routes can be repaired.
        if not _iface_up(WAN_IF):
            result = run(["service", "mpd5", "restart"], timeout=20)
            time.sleep(5)
            add("PPPoE recovery", _iface_up(WAN_IF), _detail(result, "mpd5 restarted"), True)
        else:
            add("PPPoE", True, f"{WAN_IF} active")

        underlay_ok = _iface_up(WAN_IF) or _iface_up(BACKUP_IF)
        if not underlay_ok:
            report = {"ok": False, "already_working": False, "degraded": False,
                      "timestamp": int(time.time()), "steps": steps,
                      "message": "Primary and backup WANs are unreachable"}
            _save_report(report)
            return 200, report

        if vpn_enabled and not _iface_up(VPN_IF):
            # Validate without exposing the stripped configuration or secrets.
            validation = run(["awg-quick", "strip", VPN_IF], timeout=8)
            if validation.ok:
                result = run(["service", "amnezia", "restart"], timeout=25)
                time.sleep(4)
                add("VPN recovery", _iface_up(VPN_IF), _detail(result, "amnezia restarted"), True)
            else:
                add("VPN config check", False,
                    "Configuration invalid; unsafe restart loop blocked")
        elif vpn_enabled:
            add("VPN", True, f"{VPN_IF} active")
        else:
            add("VPN", True, "VPN disabled by operator")

        if vpn_enabled and _iface_up(VPN_IF):
            result = run(["/usr/local/sbin/gatewayctl", "apply"], timeout=20)
            add("VPN route recovery", result.ok, _detail(result, "routes applied"), True)

        if not _dns().ok:
            result = run(["service", "unbound", "restart"], timeout=15)
            time.sleep(2)
            add("DNS recovery", _dns().ok, _detail(result, "unbound restarted"), True)
        else:
            add("DNS", True, "local resolver responding")

        healthy, final_checks = _healthy()
        degraded = False
        if not healthy and vpn_enabled and _iface_up(VPN_IF):
            # A broken tunnel must not take the whole household offline.  The
            # watchdog can restore VPN later after a fresh handshake.
            #
            # `bypass-transient`, not `bypass`, is what makes that sentence true.
            # Plain `bypass` writes the operator's disabled marker, and the
            # watchdog honours it by skipping its entire VPN section -- so this
            # escalation, taken over a health probe read seconds after the route
            # moved, used to be permanent.  Recovery is not the operator: it is
            # buying the household connectivity for the next minute, and saying
            # nothing at all about whether the VPN is wanted.
            result = run(["/usr/local/sbin/gatewayctl", "bypass-transient"], timeout=20)
            time.sleep(2)
            healthy, final_checks = _healthy()
            degraded = healthy
            add("Emergency direct WAN", healthy, _detail(result, "VPN temporarily bypassed"), True)

        vpn_final = _vpn_state()
        preferred_final = vpn_final["expected"] is True
        final_ok = healthy and preferred_final
        add("Final check", final_ok,
            f"IP={final_checks['ip']} DNS={final_checks['dns']} HTTPS={final_checks['https']} "
            f"route={vpn_final.get('default_iface') or 'unknown'} VPN={vpn_final['label']}")
        message = "Connectivity restored via direct WAN; traffic bypasses VPN" if degraded else (
            _working_message(vpn_final) if final_ok else (
                f"Connectivity works, but traffic bypasses tunnel: {vpn_final['label']}" if healthy else
                "Auto-recovery incomplete"))
        report = {"ok": final_ok, "already_working": False, "degraded": degraded, "vpn": vpn_final,
                  "timestamp": int(time.time()), "steps": steps, "message": message}
        _save_report(report)
        # A completed recovery workflow is a valid API response even when the
        # final health verdict is negative; the UI must render its step report.
        return 200, report
    finally:
        lock_context.__exit__(None, None, None)


def auto_recover() -> tuple[int, dict[str, Any]]:
    """Escalate persistent failures and restore the preferred VPN path."""
    now = int(time.time())

    # Undo an unconfirmed firewall change before anything else. If the new
    # ruleset locked out management access the operator cannot reach the confirm
    # endpoint, so this is the only path back short of a console. It runs first
    # because every check below depends on the firewall.
    reverted_pf: dict[str, Any] | None = None
    try:
        from .writers import pf_revert_expired_commit

        did_revert, pf_detail = pf_revert_expired_commit()
        if did_revert:
            reverted_pf = pf_detail
    except Exception as exc:  # never let this stop the rest of recovery
        reverted_pf = {"error": f"{type(exc).__name__}: {exc}"}

    state = _load_auto_state()
    healthy, checks = _healthy()
    vpn = _vpn_state()
    preferred_path = vpn["expected"] is True

    if healthy and preferred_path:
        state.update({"failures": 0, "last_check": now, "healthy": True})
        _save_auto_state(state)
        result = {"ok": True, "action": False, "checks": checks, "vpn": vpn,
                  "message": _working_message(vpn)}
        if reverted_pf is not None:
            result["pf_reverted"] = reverted_pf
        return 200, result

    state["failures"] = 0 if healthy else state.get("failures", 0) + 1
    state.update({"last_check": now, "healthy": healthy})
    actionable = healthy and not preferred_path
    if not actionable and state["failures"] < AUTO_FAIL_THRESHOLD:
        _save_auto_state(state)
        return 200, {"ok": False, "action": False, "checks": checks, "vpn": vpn,
                     "message": "Waiting for repeated failure confirmation"}

    if now - state.get("last_attempt", 0) < AUTO_COOLDOWN:
        _save_auto_state(state)
        return 200, {"ok": healthy, "action": False, "cooldown": True,
                     "checks": checks, "vpn": vpn, "message": "Auto-recovery on cooldown"}

    state["last_attempt"] = now
    _save_auto_state(state)
    status, report = recover_internet()
    if report.get("ok"):
        state["failures"] = 0
    state.update({"last_result": int(bool(report.get("ok"))), "last_check": int(time.time())})
    _save_auto_state(state)
    report["automatic"] = True
    report["action"] = True
    if reverted_pf is not None:
        report["pf_reverted"] = reverted_pf
    return status, report


if __name__ == "__main__":
    status, result = auto_recover()
    print(json.dumps({"status": status, **result}, ensure_ascii=False))
