"""Shared helpers, interface constants, and low-level parsing."""
from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any

from ..command import run
from ..fsutil import read_regular_text
from .. import paths
from ..redact import redact_value

# ── Paths (all BSD-native) ───────────────────────────────────────────────────

DB_DIR            = paths.DB_DIR
AMNEZIA_CONFIG    = paths.AMNEZIA_CONFIG
AMNEZIA_CONF_DIR  = paths.AMNEZIA_CONF_DIR
GATEWAY_CONF      = paths.GATEWAY_CONF
RU_TABLE          = paths.RU_TABLE
PF_CONF           = paths.PF_CONF
DHCPD_LEASES      = paths.DHCPD_LEASES
DHCPD_CONF        = paths.DHCPD_CONF
UNBOUND_CONF      = paths.UNBOUND_CONF
UPS_NAME          = os.environ.get("GATEBSD_UPS_NAME",            "ippon@localhost")

# ── Interface names (from gateway.conf or env) ────────────────────────────────

def _safe_config_text(path: Path, limit: int = 64 * 1024) -> str:
    """Read one stable regular configuration file without following symlinks."""
    try:
        text, _metadata = read_regular_text(Path(path), max_size=limit, errors="strict")
        return text
    except (OSError, UnicodeError, ValueError):
        return ""


def _gw_conf() -> dict[str, str]:
    data: dict[str, str] = {}
    for raw in _safe_config_text(GATEWAY_CONF).splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None:
            continue
        data[key] = value.strip().strip('"')
    return data


def _interface_name(value: str, fallback: str) -> str:
    if 1 <= len(value) <= 32 and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", value):
        return value
    return fallback

_conf = _gw_conf()

WAN_IF     = _interface_name(_conf.get("WAN_IF", os.environ.get("GATEBSD_WAN_IF", "ng0")), "ng0")
BACKUP_IF  = _interface_name(_conf.get("BACKUP_IF", os.environ.get("GATEBSD_BACKUP_IF", "ue0")), "ue0")
LAN_IF     = _interface_name(_conf.get("LAN_IF", os.environ.get("GATEBSD_LAN_IF", "re1")), "re1")
VPN_IF     = _interface_name(_conf.get("VPN_IF", os.environ.get("GATEBSD_VPN_IF", "awg0")), "awg0")
def _lan_network(value: str, fallback: str = "10.88.0.0/24") -> str:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return fallback
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen < 16 or network.prefixlen > 30:
        return fallback
    return str(network)


def _check_target(value: str, fallback: str = "1.1.1.1") -> str:
    text = value.strip().rstrip(".")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        labels = text.split(".")
        if labels and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", item) for item in labels):
            return text.lower()
    return fallback


LAN_NET = _lan_network(_conf.get("LAN_NET", os.environ.get("GATEBSD_LAN_NET", "10.88.0.0/24")))
CHECK_IP = _check_target(_conf.get("CHECK_IP", os.environ.get("GATEBSD_CHECK_IP", "1.1.1.1")))

# ── Helpers ───────────────────────────────────────────────────────────────────


def parse_key_value_file(path: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw in _safe_config_text(Path(path)).splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        key = k.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None:
            continue
        data[key] = redact_value(key, v.strip().strip('"'))
    return data


def service_state(*names: str) -> dict[str, str]:
    """FreeBSD: service X status → exit 0=running, else stopped."""
    states: dict[str, str] = {}
    for name in names:
        r = run(["service", name, "status"], timeout=3)
        if r.ok:
            states[name] = "active"
        elif r.returncode is None:
            states[name] = "unknown"
        else:
            states[name] = "inactive"
    return states


def _ifconfig_iface(name: str) -> dict[str, Any]:
    """Parse `ifconfig <name>` into a dict."""
    r = run(["ifconfig", name], timeout=3)
    if not r.ok:
        return {"name": name, "state": "missing", "addresses": [], "flags": ""}
    text = r.stdout
    flags_m = re.search(r"flags=\w+<([^>]*)>", text)
    flags = flags_m.group(1) if flags_m else ""
    up = "UP" in flags
    running = "RUNNING" in flags
    addrs = re.findall(r"inet\s+(\S+)", text)
    inet6 = re.findall(r"inet6\s+(\S+)", text)
    mtu_m = re.search(r"mtu\s+(\d+)", text)
    state = "UP" if up and running else ("DOWN" if up else "missing")
    return {
        "name": name,
        "state": state,
        "flags": flags,
        "addresses": addrs,
        "addresses6": inet6,
        "mtu": int(mtu_m.group(1)) if mtu_m else None,
        "raw": text,
    }
