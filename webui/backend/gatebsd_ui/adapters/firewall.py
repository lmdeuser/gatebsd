"""PF firewall, DHCP, DNS, UPS, WiFi, health, and logs."""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any

from .. import paths
from ..command import lines, run
from .helpers import PF_CONF, DHCPD_LEASES, DHCPD_CONF, UNBOUND_CONF, UPS_NAME, _safe_config_text


def firewall() -> dict[str, Any]:
    info = run(["pfctl", "-s", "info"], timeout=3)
    nat  = run(["pfctl", "-s", "nat"], timeout=3)
    rules = run(["pfctl", "-s", "rules"], timeout=3)
    pf_conf_text = _safe_config_text(PF_CONF, limit=2 * 1024 * 1024)
    enabled = "Enabled" in (info.stdout or "")
    return {
        "state": "enabled" if enabled else "disabled",
        "info": info.stdout,
        "nat_rules": lines(nat.stdout),
        "filter_rules": lines(rules.stdout),
        "conf": pf_conf_text,
    }


def firewall_detail() -> dict[str, Any]:
    states = run(["pfctl", "-s", "states"], timeout=5)
    return {
        "states": lines(states.stdout),
        "count": len(lines(states.stdout)),
    }


def dhcpd() -> dict[str, Any]:
    """ISC DHCPD leases (FreeBSD)."""
    leases: list[dict[str, Any]] = []
    active: dict[str, Any] = {}
    text = _safe_config_text(DHCPD_LEASES, limit=16 * 1024 * 1024)
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"lease\s+([\d.]+)\s*\{", line)
        if m:
            active = {"ip": m.group(1)}
            leases.append(active)
        elif active:
            if line.startswith("hardware ethernet"):
                active["mac"] = line.split()[-1].rstrip(";")
            elif line.startswith("client-hostname"):
                active["hostname"] = line.split(None, 1)[-1].strip('";')
            elif line.startswith("binding state"):
                active["state"] = line.split()[-1].rstrip(";")
            elif line.startswith("ends"):
                parts = line.split()
                active["expires"] = " ".join(parts[1:]).rstrip(";") if len(parts) > 1 else ""
            elif line == "}":
                active = {}

    static: list[dict[str, str]] = []
    try:
        in_host = False
        host_entry: dict[str, str] = {}
        for line in _safe_config_text(DHCPD_CONF, limit=2 * 1024 * 1024).splitlines():
            line = line.strip()
            if line.startswith("host "):
                in_host = True
                host_entry = {"hostname": line.split()[1].rstrip("{"), "mac": "", "ip": ""}
            elif in_host and line.startswith("hardware ethernet"):
                host_entry["mac"] = line.split()[-1].rstrip(";")
            elif in_host and line.startswith("fixed-address"):
                host_entry["ip"] = line.split()[-1].rstrip(";")
            elif in_host and line == "}":
                static.append(host_entry)
                in_host = False
                host_entry = {}
    except OSError:
        pass

    static_hosts = [f"{s['mac']},{s['hostname']},{s['ip']}" for s in static if s.get('mac') and s.get('ip')]

    # Syntax check via dhcpd -t (outputs to stderr)
    syntax = ""
    dhcp_text = _safe_config_text(DHCPD_CONF, limit=2 * 1024 * 1024)
    if dhcp_text:
        r = run(["/usr/local/sbin/dhcpd", "-q", "-t", "-cf", str(DHCPD_CONF)], timeout=5)
        output = r.stderr.strip() or r.stdout.strip()
        if r.returncode != 0:
            syntax = f"ERROR (exit {r.returncode}):\n{output}"
        else:
            syntax = output or "OK (dhcpd -q -t)"

    range_start = range_end = ""
    default_lease = ""
    try:
        range_match = re.search(
            r"(?im)^\s*range\s+(\d+(?:\.\d+){3})\s+(\d+(?:\.\d+){3})\s*;",
            dhcp_text,
        )
        if range_match:
            range_start, range_end = range_match.groups()
        lease_match = re.search(r"(?im)^\s*default-lease-time\s+(\d+)\s*;", dhcp_text)
        if lease_match:
            default_lease = lease_match.group(1)
    except OSError:
        pass

    upstreams: list[str] = []
    try:
        from ..writers.dns import parse_forwarders
        upstreams = parse_forwarders(_safe_config_text(UNBOUND_CONF, limit=2 * 1024 * 1024))
    except (OSError, UnicodeError):
        pass

    return {
        "leases": [l for l in leases if l.get("state") == "active"],
        "all_leases": leases,
        "static": static,
        "static_hosts": static_hosts,
        "syntax": syntax,
        "range_start": range_start,
        "range_end": range_end,
        "default_lease": default_lease,
        "upstreams": upstreams,
    }


def _ups_health_check() -> dict[str, Any]:
    path = paths.UPS_HEALTH_STATE
    if path.is_symlink():
        return {"available": False, "error": "health state is a symlink"}
    try:
        if path.stat().st_size > 64 * 1024:
            return {"available": False, "error": "health state is too large"}
        values = dict(
            (key, value) for line in path.read_text(encoding="utf-8").splitlines()
            if "=" in line for key, value in [line.split("=", 1)]
        )
        return {
            "available": True,
            "checked_at": int(values["checked_at"]),
            "ok": values.get("ok") == "true",
            "errors": int(values.get("errors", "0")),
            "last_response_at": int(values["last_response_at"]) if values.get("last_response_at") else None,
            "status": values.get("status", ""),
            "charge": values.get("charge", ""),
        }
    except (OSError, UnicodeError, ValueError) as exc:
        return {"available": False, "error": str(exc)}


def _ups_float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _ups_warnings(data: dict[str, str]) -> list[str]:
    warnings = []
    charge = _ups_float(data.get("battery.charge", ""))
    if charge is None:
        warnings.append("Battery charge not measured")
    elif not 0 <= charge <= 100:
        warnings.append(f"Suspicious battery charge: {charge:g}%")
    elif charge < 20:
        warnings.append(f"Low battery charge: {charge:g}%")
    input_voltage = _ups_float(data.get("input.voltage", ""))
    if "OL" in data.get("ups.status", "").split() and input_voltage == 0:
        warnings.append("Suspicious input voltage: 0 V while online")
    load = _ups_float(data.get("ups.load", ""))
    if load is not None and not 0 <= load <= 100:
        warnings.append(f"Suspicious UPS load: {load:g}%")
    return warnings


def ups() -> dict[str, Any]:
    devices = run(["/usr/local/bin/upsc", "-l"], timeout=5)
    device = next((line.strip() for line in devices.stdout.splitlines() if line.strip()), "")
    target = UPS_NAME if not device else (device if "@" in device else f"{device}@localhost")
    r = run(["/usr/local/bin/upsc", target], timeout=5)
    data: dict[str, str] = {}
    if r.ok:
        for line in r.stdout.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                data[k.strip()] = v.strip()
    commands_result = run(["/usr/local/bin/upscmd", "-l", target], timeout=8)
    available_commands = []
    for line in commands_result.stdout.splitlines():
        if " - " not in line:
            continue
        name, description = line.split(" - ", 1)
        available_commands.append({"name": name.strip(), "description": description.strip()})
    checked_at = int(time.time())
    last_check = _ups_health_check()
    payload = {
        "name": target,
        "ok": r.ok,
        "data": data,
        "status": data.get("ups.status", "unknown"),
        "charge": data.get("battery.charge", ""),
        "runtime": data.get("battery.runtime", ""),
        "voltage": data.get("battery.voltage", ""),
        "input_voltage": data.get("input.voltage", ""),
        "available_commands": available_commands,
        "checked_at": checked_at,
        "last_response_at": checked_at if r.ok else last_check.get("last_response_at"),
        "last_check": last_check,
        "warnings": _ups_warnings(data) if r.ok else [],
    }
    if not r.ok:
        payload["error"] = r.stderr or r.error or "upsc failed"
    if not commands_result.ok:
        payload["commands_error"] = commands_result.stderr or commands_result.error or "upscmd -l failed"
    return payload


def health() -> dict[str, Any]:
    from .services import services as _services
    svc = _services()
    checks = [
        {"name": "PF", "ok": svc.get("pf") == "active"},
        {"name": "PPPoE", "ok": svc.get("mpd5") == "active"},
        {"name": "DNS", "ok": svc.get("unbound") == "active"},
        {"name": "DHCP", "ok": svc.get("dhcpd") == "active"},
        {"name": "AWG", "ok": svc.get("awg0") == "active"},
    ]
    score = int(100 * sum(1 for item in checks if item["ok"]) / max(1, len(checks)))
    return {"score": score, "status": "good" if score >= 80 else "degraded", "checks": checks}


def logs(query: dict[str, list[str]] | None = None) -> dict[str, Any]:
    query = query or {}
    limit = query.get("limit", ["200"])[0]
    try:
        safe_limit = max(10, min(int(limit), 1000))
    except ValueError:
        safe_limit = 200
    r = run(["tail", "-n", str(safe_limit), "/var/log/messages"], timeout=5)
    return {"lines": lines(r.stdout if r.ok else r.stderr), "ok": r.ok}
