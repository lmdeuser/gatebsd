"""AmneziaWG, PPPoE, LTE modem."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from .. import backup, paths
from ..command import run
from .helpers import (
    _ifconfig_iface, VPN_IF, WAN_IF, BACKUP_IF,
    AMNEZIA_CONFIG, AMNEZIA_CONF_DIR, RU_TABLE, _safe_config_text,
)


def pppoe() -> dict[str, Any]:
    mpd_conf = paths.MPD_CONF
    ng0 = _ifconfig_iface(WAN_IF)
    mpd_r = run(["service", "mpd5", "status"], timeout=3)

    peer_gw = ""
    m = re.search(r"-->\s*(\S+)", ng0.get("raw", ""))
    if m:
        peer_gw = m.group(1)

    conf_lines: list[str] = []
    for line in _safe_config_text(mpd_conf, limit=2 * 1024 * 1024).splitlines():
        l = line.strip()
        if l and not l.startswith("#"):
            l = re.sub(r'(?i)^(\s*set\s+\S+\s+(?:password|secret|key)\s+).*$', r'\1"******"', l)
            l = re.sub(r'(?i)\b(password|secret)\s+\S+', r'\1 "******"', l)
            conf_lines.append(l)

    return {
        "interface": WAN_IF,
        "state": ng0["state"],
        "addresses": ng0["addresses"],
        "peer_gw": peer_gw,
        "mpd5_running": mpd_r.ok,
        "config": conf_lines,
    }


def modem() -> dict[str, Any]:
    """LTE backup modem (ue0)."""
    ue = _ifconfig_iface(BACKUP_IF)
    lease_file = Path(f"/var/db/dhclient.leases.{BACKUP_IF}")
    gw = ""
    for line in _safe_config_text(lease_file, limit=1024 * 1024).splitlines():
        m = re.search(r"option routers\s+([\d.]+)", line)
        if m:
            gw = m.group(1)
    return {
        "interface": BACKUP_IF,
        "state": ue["state"],
        "addresses": ue["addresses"],
        "gateway": gw,
    }


def _awg_conf_summary(path: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {"name": path.name, "path": str(path), "exists": False}
    try:
        raw, metadata = backup._read_regular_bytes(path)
        summary["exists"] = True
    except FileNotFoundError:
        return summary
    except OSError as exc:
        summary.update({"exists": True, "error": str(exc)})
        return summary
    text = raw.decode("utf-8", errors="replace")
    section = ""
    iface: dict[str, str] = {}
    peer: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").lower()
            continue
        if "=" not in line:
            continue
        k, v = [x.strip() for x in line.split("=", 1)]
        if k.lower() in {"privatekey", "presharedkey"}:
            continue
        if section == "interface":
            iface[k] = v
        elif section == "peer":
            peer.setdefault(k, v)
    summary.update({
        "size": metadata.st_size,
        "mtime": int(metadata.st_mtime),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "address": iface.get("Address", ""),
        "endpoint": peer.get("Endpoint", ""),
        "allowed_ips": peer.get("AllowedIPs", ""),
        "persistent_keepalive": peer.get("PersistentKeepalive", ""),
        "table": iface.get("Table", "auto"),
        "mtu": iface.get("MTU", ""),
    })
    return summary


def amnezia() -> dict[str, Any]:
    """AmneziaWG status on FreeBSD."""
    awg_iface = _ifconfig_iface(VPN_IF)
    awg_show = run(["awg", "show", VPN_IF], timeout=4)
    kldstat = run(["kldstat", "-q", "-n", "if_amn"], timeout=3)
    ru_count = sum(1 for line in _safe_config_text(RU_TABLE, limit=16 * 1024 * 1024).splitlines()
                   if line.strip() and not line.lstrip().startswith("#"))

    handshake = ""
    m = re.search(r"latest handshake:\s+(.+)", awg_show.stdout)
    if m:
        handshake = m.group(1).strip()

    active_profile_path = None
    if AMNEZIA_CONFIG.exists():
        try:
            active_profile_path = AMNEZIA_CONFIG.resolve()
        except OSError:
            active_profile_path = AMNEZIA_CONFIG

    config_files: list[dict[str, Any]] = []
    try:
        profile_entries = sorted(AMNEZIA_CONF_DIR.glob("*.conf")) if AMNEZIA_CONF_DIR.is_dir() and not AMNEZIA_CONF_DIR.is_symlink() else []
    except OSError:
        profile_entries = []
    non_profiles = {"gateway.conf", "awg0.conf", "direct-exceptions.conf"}
    if AMNEZIA_CONFIG.name:
        non_profiles.add(AMNEZIA_CONFIG.name)
    if paths.DIRECT_EXCEPTIONS.name:
        non_profiles.add(paths.DIRECT_EXCEPTIONS.name)
    for cf in profile_entries:
        if cf == AMNEZIA_CONFIG or cf == paths.DIRECT_EXCEPTIONS or cf.name in non_profiles:
            continue
        summary = _awg_conf_summary(cf)
        is_active = False
        if active_profile_path:
            try:
                is_active = (cf.resolve() == active_profile_path)
            except OSError:
                is_active = (cf == active_profile_path)
        summary["active"] = is_active
        config_files.append(summary)

    dr = run(["route", "-n", "get", "default"], timeout=3)
    default_iface = ""
    m2 = re.search(r"interface:\s+(\S+)", dr.stdout)
    if m2:
        default_iface = m2.group(1)

    watchdog_state: dict[str, Any] = {}
    try:
        state_text = _safe_config_text(paths.FAILOVER_STATE, limit=256 * 1024)
        loaded_state = json.loads(state_text) if state_text else {}
        if isinstance(loaded_state, dict):
            watchdog_state = loaded_state
    except (OSError, UnicodeError, json.JSONDecodeError):
        watchdog_state = {}

    active_config_dict = {
        "path": str(AMNEZIA_CONFIG),
        "name": "",
        "target_name": ""
    }
    if AMNEZIA_CONFIG.exists():
        if AMNEZIA_CONFIG.is_symlink():
            try:
                target = AMNEZIA_CONFIG.readlink()
                active_config_dict["target_name"] = target.name
                active_config_dict["name"] = target.stem
            except OSError:
                pass
        else:
            active_config_dict["name"] = "awg0"

    return {
        "module_loaded": kldstat.ok,
        "interface": awg_iface,
        "show": awg_show.stdout if awg_show.ok else awg_show.stderr,
        "handshake": handshake,
        "default_iface": default_iface,
        "vpn_is_default": default_iface == VPN_IF,
        "ru_bypass_count": ru_count,
        "ru_table": str(RU_TABLE),
        "config_files": config_files,
        "active_config": active_config_dict,
        "watchdog_state": watchdog_state,
        "commands": {
            "awg": shutil.which("awg") or "",
            "awg-quick": shutil.which("awg-quick") or "",
            "gatewayctl": shutil.which("gatewayctl") or "/usr/local/sbin/gatewayctl",
        },
    }
