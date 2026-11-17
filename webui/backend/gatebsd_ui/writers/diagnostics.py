"""Network diagnostics, discovery, and failover control."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from ..command import run
from .. import discovery
from ..resolver import normalize_host


def normalize_target(value: object) -> str | None:
    """Return a safe IP address or DNS hostname for command arguments."""
    return normalize_host(value)


def traceroute(target: object) -> tuple[int, dict[str, Any]]:
    normalized = normalize_target(target)
    if normalized is None:
        return 400, {"error": "invalid target"}
    r = run(["traceroute", "-m", "15", "-w", "2", "-n", normalized], timeout=30)
    return 200, {"output": r.stdout + r.stderr, "ok": r.ok}


def nslookup(target: object) -> tuple[int, dict[str, Any]]:
    normalized = normalize_target(target)
    if normalized is None:
        return 400, {"error": "invalid target"}
    r = run(
        ["/usr/local/libexec/gatebsd-python", "-m", "gatebsd_ui.resolver", normalized],
        timeout=7,
        env={"PYTHONPATH": "/usr/local/share/gatebsd/webui/backend"},
    )
    output = r.stdout if r.ok else (r.stderr or r.error or "DNS lookup failed")
    return 200, {"output": output, "ok": r.ok}


def discovery_scan() -> tuple[int, dict[str, Any]]:
    try:
        payload = discovery.save_scan()
        return 200, {"ok": True, **payload}
    except Exception as exc:
        return 500, {"ok": False, "error": str(exc)}


def import_existing() -> tuple[int, dict[str, Any]]:
    try:
        payload = discovery.import_existing()
        return 200, {"ok": True, **payload}
    except Exception as exc:
        return 500, {"ok": False, "error": str(exc)}


def failover_mode(mode: str) -> tuple[int, dict[str, Any]]:
    if mode not in {"observe", "automatic", "manual"}:
        return 400, {"error": "mode must be observe, automatic or manual"}
    r = run(["/usr/local/sbin/gatebsd-failoverctl", mode], timeout=20)
    return (200 if r.ok else 500), {"ok": r.ok, "output": r.stdout + r.stderr, "mode": mode}


def failover_switch(target: object) -> tuple[int, dict[str, Any]]:
    if target not in {"primary", "backup"}:
        return 400, {"error": "target must be primary or backup"}
    r = run(["/usr/local/sbin/gatebsd-failoverctl", str(target)], timeout=20)
    return (200 if r.ok else 500), {"ok": r.ok, "output": r.stdout + r.stderr, "target": str(target)}


def vpn_diagnose(mode_value: object, target_value: object) -> tuple[int, dict[str, Any]]:
    """Run a constrained route plus HTTPS/traceroute diagnostic for a host."""
    if mode_value not in {"curl", "traceroute"}:
        return 400, {"error": "mode must be curl or traceroute"}
    if not isinstance(target_value, str) or not target_value.strip():
        return 400, {"error": "target is required"}
    target = normalize_target(target_value)
    if target is None:
        return 400, {"error": "invalid target"}
    try:
        is_ipv6 = isinstance(ipaddress.ip_address(target), ipaddress.IPv6Address)
    except ValueError:
        is_ipv6 = False
    url_host = f"[{target}]" if is_ipv6 else target

    route = run(["route", "-n", "get", target], timeout=8)
    if mode_value == "traceroute":
        command = run(["traceroute", "-m", "15", "-w", "2", "-n", target], timeout=40)
    else:
        command = run(["fetch", "-T", "10", "-qo", "/dev/null", f"https://{url_host}/"], timeout=15)

    def serialize(result: Any) -> dict[str, Any]:
        return {
            "ok": result.ok,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "error": result.error,
        }

    return 200, {
        "ok": route.ok and command.ok,
        "target": target,
        "mode": mode_value,
        "route": serialize(route),
        "command": serialize(command),
    }
