"""Failover status and diagnostics for the unified GateBSD watchdog."""
from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path
from typing import Any

from . import paths
from .adapters.helpers import parse_key_value_file, service_state, WAN_IF, BACKUP_IF, VPN_IF, _safe_config_text
from .command import run


STATES = [
    "PRIMARY",
    "PRIMARY_DEGRADED",
    "SWITCHING_TO_BACKUP",
    "BACKUP",
    "PRIMARY_RECOVERING",
    "SWITCHING_TO_PRIMARY",
    "NO_CONNECTIVITY",
    "VPN_ROLLBACK",
    "INIT",
    "STOPPED",
]


def _raw_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    text = _safe_config_text(path)
    if not text:
        return values
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        values[key] = value.strip().strip('"')
    return values


def _positive_int(value: str | None, default: int) -> int:
    try:
        result = int(value or "")
    except ValueError:
        return default
    return result if result >= 0 else default


def _check_interface(iface: str) -> dict[str, Any]:
    r = run(["ifconfig", iface], timeout=3)
    if not r.ok:
        return {"exists": False, "up": False, "has_ip": False, "addresses": []}
    flags_match = re.search(r"flags=\w+<([^>]*)>", r.stdout)
    flags = set((flags_match.group(1) if flags_match else "").split(","))
    addrs = re.findall(r"inet\s+(\S+)", r.stdout)
    return {
        "exists": True,
        "up": "UP" in flags and "RUNNING" in flags,
        "has_ip": bool(addrs),
        "addresses": addrs,
    }


def _check_gateway(iface: str) -> dict[str, Any]:
    r = run(["ifconfig", iface], timeout=3)
    if not r.ok:
        return {"has_gw": False, "gateway": ""}
    point_to_point = re.search(r"inet\s+(\S+).*-->\s*(\S+)", r.stdout)
    if point_to_point:
        return {
            "has_gw": True,
            "gateway": point_to_point.group(2),
            "local_ip": point_to_point.group(1),
        }

    local_match = re.search(r"inet\s+(\S+)", r.stdout)
    lease = Path(f"/var/db/dhclient.leases.{iface}")
    gateway = ""
    try:
        lease_text = _safe_config_text(lease, limit=1024 * 1024)
        matches = re.findall(r"option\s+routers\s+([^;\s]+)\s*;", lease_text)
        if matches:
            gateway = matches[-1]
    except (OSError, UnicodeError):
        pass
    return {
        "has_gw": bool(gateway),
        "gateway": gateway,
        "local_ip": local_match.group(1) if local_match else "",
    }


def _check_dns(*, fib: int | None = None) -> dict[str, Any]:
    command = ["/usr/local/libexec/gatebsd-python", "-m", "gatebsd_ui.resolver"]
    if fib is not None:
        command = [*command, "--server", "1.1.1.1"]
    command = [*command, "one.one.one.one"]
    setfib = shutil.which("setfib")
    if fib is not None and setfib:
        command = [setfib, str(fib), *command]
    r = run(
        command,
        timeout=7,
        env={"PYTHONPATH": "/usr/local/share/gatebsd/webui/backend"},
    )
    return {"ok": r.ok, "fib": fib, "output": (r.stdout or r.stderr or r.error or "").strip()}


def _check_tcp(target: str = "1.1.1.1", port: int = 443, *, fib: int | None = None) -> dict[str, Any]:
    command = ["nc", "-z", "-w", "3", target, str(port)]
    setfib = shutil.which("setfib")
    if fib is not None and setfib:
        command = [setfib, str(fib), *command]
    r = run(command, timeout=5)
    return {"ok": r.ok, "target": target, "port": port, "fib": fib}


def _check_https(*, fib: int) -> dict[str, Any]:
    command = ["fetch", "-T", "5", "-qo", "/dev/null", "https://one.one.one.one/cdn-cgi/trace"]
    setfib = shutil.which("setfib")
    if setfib:
        command = [setfib, str(fib), *command]
    r = run(command, timeout=8)
    return {"ok": r.ok, "fib": fib}


def _check_ping(fib: int, src: str, targets: list[str], timeout_s: int) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    setfib = shutil.which("setfib")
    for target in targets:
        command = ["ping", "-c", "1", "-W", str(timeout_s * 1000)]
        if src:
            command.extend(["-S", src])
        command.append(target)
        if setfib:
            command = [setfib, str(fib), *command]
        result = run(command, timeout=max(3, timeout_s + 2))
        latency = None
        match = re.search(r"time[=<]([0-9.]+)", result.stdout)
        if match:
            latency = float(match.group(1))
        attempts.append({"target": target, "ok": result.ok, "latency_ms": latency})
        if result.ok:
            return {
                "ok": True,
                "target": target,
                "latency_ms": latency,
                "fib": fib,
                "source": src,
                "attempts": attempts,
            }
    return {"ok": False, "fib": fib, "source": src, "attempts": attempts}


def _check_pppoe_session() -> dict[str, Any]:
    service = run(["service", "mpd5", "status"], timeout=3)
    interface = run(["ifconfig", WAN_IF], timeout=3)
    match = re.search(r"-->\s*(\S+)", interface.stdout)
    return {"running": service.ok, "peer_gw": match.group(1) if match else ""}


def _check_awg_handshake() -> dict[str, Any]:
    result = run(["awg", "show", VPN_IF, "latest-handshakes"], timeout=4)
    if not result.ok:
        return {"exists": False, "handshake_age_s": None}
    newest = 0
    peers = 0
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[1].isdigit():
            continue
        peers += 1
        newest = max(newest, int(fields[1]))
    age = None if newest <= 0 else max(0, int(time.time()) - newest)
    return {
        "exists": True,
        "peers": peers,
        "latest_handshake_epoch": newest or None,
        "handshake_age_s": age,
    }


def failover_warnings(state: dict[str, Any]) -> list[str]:
    """Return warnings when an uplink is in domestic allowlist mode."""
    items: list[str] = []
    if state.get("primary_ok") is False and state.get("primary_ru_ok") is True:
        items.append(
            "Primary uplink is in domestic allowlist mode: only domestic hosts are reachable; "
            "global internet and external VPN are unavailable."
        )
    if (
        state.get("backup_fitted") is not False
        and state.get("backup_ok") is False
        and state.get("backup_ru_ok") is True
    ):
        items.append(
            "Backup uplink is restricted (allowlist mode): only domestic hosts are reachable; "
            "external internet and VPN are unavailable."
        )
    return items


def health_checks() -> dict[str, Any]:
    """Check the same per-FIB paths that the watchdog uses."""
    config = _raw_key_values(paths.FAILOVER_CONF)
    targets = [item for item in config.get("CHECK_TARGETS", "1.1.1.1 8.8.8.8 9.9.9.9").split() if item]
    if not targets:
        targets = ["1.1.1.1"]
    ru_targets = [item for item in config.get("RU_CHECK_TARGETS", "77.88.8.8").split() if item]
    timeout_s = max(1, _positive_int(config.get("PING_TIMEOUT"), 2))
    primary_fib = _positive_int(config.get("PRIMARY_FIB"), 1)
    backup_fib = _positive_int(config.get("BACKUP_FIB"), 2)

    wan_info = _check_interface(WAN_IF)
    backup_info = _check_interface(BACKUP_IF)
    vpn_info = _check_interface(VPN_IF)
    wan_gw = _check_gateway(WAN_IF)
    backup_gw = _check_gateway(BACKUP_IF)

    wan_ping = (
        _check_ping(primary_fib, str(wan_gw.get("local_ip", "")), targets, timeout_s)
        if wan_gw.get("has_gw")
        else {"ok": False, "error": "gateway unavailable", "fib": primary_fib}
    )
    backup_ping = (
        _check_ping(backup_fib, str(backup_gw.get("local_ip", "")), targets, timeout_s)
        if backup_gw.get("has_gw")
        else {"ok": False, "error": "gateway unavailable", "fib": backup_fib}
    )

    wan_block: dict[str, Any] = {
        "interface": wan_info,
        "gateway": wan_gw,
        "ping": wan_ping,
        "pppoe": _check_pppoe_session(),
    }
    if wan_gw.get("has_gw") and not wan_ping.get("ok") and ru_targets:
        wan_block["ru_ping"] = _check_ping(primary_fib, str(wan_gw.get("local_ip", "")), ru_targets, timeout_s)

    backup_block: dict[str, Any] = {
        "interface": backup_info,
        "gateway": backup_gw,
        "ping": backup_ping,
    }
    if backup_gw.get("has_gw") and not backup_ping.get("ok") and ru_targets:
        backup_block["ru_ping"] = _check_ping(backup_fib, str(backup_gw.get("local_ip", "")), ru_targets, timeout_s)

    return {
        "wan": wan_block,
        "backup": backup_block,
        "vpn": {"interface": vpn_info, "handshake": _check_awg_handshake()},
        "dns": _check_dns(),
        "tcp_443": _check_tcp(),
    }


def status(*, include_health: bool = True) -> dict[str, Any]:
    state: dict[str, Any] = {}
    try:
        state_text = _safe_config_text(paths.FAILOVER_STATE, limit=256 * 1024)
        loaded = json.loads(state_text) if state_text else {}
        if isinstance(loaded, dict):
            state = loaded
        else:
            state = {"error": "failover state is not a JSON object"}
    except FileNotFoundError:
        pass
    except (OSError, UnicodeError, json.JSONDecodeError):
        state = {"error": "invalid failover state JSON"}

    config = parse_key_value_file(str(paths.FAILOVER_CONF))
    return {
        "service": service_state("gatebsd_failover").get("gatebsd_failover", "unknown"),
        "states": STATES,
        "config": config,
        "state": state,
        "health": health_checks() if include_health else {},
        "mode": state.get("mode") or config.get("FAILOVER_MODE", "observe"),
        "current_state": state.get("state", "UNKNOWN"),
        "active_wan": state.get("active_wan", "unknown"),
        "last_switch": state.get("last_switch", 0),
        "primary_ok": state.get("primary_ok", False),
        "backup_ok": state.get("backup_ok", False),
        "primary_ru_ok": state.get("primary_ru_ok", False),
        "backup_ru_ok": state.get("backup_ru_ok", False),
        "warnings": failover_warnings(state),
        "safe_default": "observe",
    }
