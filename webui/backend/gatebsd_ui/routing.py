"""Routing table and split tunnel management."""
from __future__ import annotations

import os
import re
import stat
from typing import Any

from . import paths
from .command import lines, run
from .adapters.helpers import LAN_IF, VPN_IF


def _read_ru_entries(limit: int = 16 * 1024 * 1024) -> list[str]:
    path = paths.RU_TABLE
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(path, flags)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            return []
        payload = bytearray()
        while len(payload) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > limit:
            return []
        text = bytes(payload).decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        return []
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def route_table() -> dict[str, Any]:
    """Full routing table information."""
    routes_v4 = run(["netstat", "-rn", "-f", "inet"], timeout=5)
    routes_v6 = run(["netstat", "-rn", "-f", "inet6"], timeout=5)
    default = run(["route", "-n", "get", "default"], timeout=3)

    # Parse default route details
    default_iface = ""
    default_gw = ""
    for line in default.stdout.splitlines():
        if "interface:" in line:
            default_iface = line.split()[-1]
        if "gateway:" in line:
            default_gw = line.split()[-1]

    return {
        "default": default.stdout,
        "default_iface": default_iface,
        "default_gw": default_gw,
        "routes_v4": lines(routes_v4.stdout),
        "routes_v6": lines(routes_v6.stdout),
    }


def split_tunnel() -> dict[str, Any]:
    """Split tunnel status with detailed route and table information."""
    pf_tables = run(["pfctl", "-s", "Tables"], timeout=4)
    routes = route_table()

    # RU bypass routes
    ru_entries = _read_ru_entries()

    # Count routes by interface
    route_lines = routes["routes_v4"]
    if_count = {}
    for row in route_lines:
        parts = row.split()
        if len(parts) >= 6:
            iface = parts[5].rstrip("*")
            if iface and not iface.startswith("lo"):
                if_count[iface] = if_count.get(iface, 0) + 1

    # Count static routes
    static_routes = [row for row in route_lines if "UGS" in row or "static" in row.lower()]

    # Count gateway routes (non-link-local)
    gw_routes = [row for row in route_lines if re.match(r"^\s*[0-9]", row) and "link#" not in row]

    pf_table_lines = lines(pf_tables.stdout)
    return {
        "modules": {
            "ru": {
                "table": str(paths.RU_TABLE),
                "count": len(ru_entries),
                "imported": bool(ru_entries),
                "sample": ru_entries[:5] if ru_entries else [],
            },
            "lan": {
                "detected": any("link#" in row for row in route_lines),
                "interface": LAN_IF,
                "routes": if_count.get(LAN_IF, 0),
            },
            "vpn": {
                "interface": VPN_IF,
                "detected": if_count.get(VPN_IF, 0) > 0 or routes["default_iface"] == VPN_IF,
                "routes": if_count.get(VPN_IF, 0),
            },
            "static": {
                "count": len(static_routes),
                "routes": [row.split()[0] for row in static_routes[:10]],
            },
            "custom": {
                "pf_tables": pf_table_lines,
                "table_count": len(pf_table_lines),
            },
        },
        "route_summary": {
            "total_v4": len(route_lines),
            "by_interface": if_count,
            "gateway_routes": len(gw_routes),
            "default_iface": routes["default_iface"],
            "default_gw": routes["default_gw"],
        },
        "routes": routes,
        "policy": "import-only; GateBSD does not recreate routes unless an explicit write action is requested",
    }
