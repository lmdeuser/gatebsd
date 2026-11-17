from __future__ import annotations

import argparse
import ipaddress
import os
import re
import time
from pathlib import Path
from typing import Any

from . import paths, ru_table
from .command import run
from .fsutil import atomic_write_bytes, atomic_write_text, exclusive_lock
from .resolver import display_host, normalize_domain

DRILL = os.environ.get("GATEBSD_DRILL", "drill")
DIRECTIONS = {"direct", "vpn", "default"}
CLOUDFLARE_IPV4_NETWORKS = (
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("131.0.72.0/22"),
)


def _shared_cdn_warnings(direction: str, value: str, networks: list[str]) -> list[dict[str, Any]]:
    """Warn when a direct rule overlaps shared Cloudflare CDN IPv4 space."""
    if direction != "direct" or not networks:
        return []
    matched: list[str] = []
    for raw in networks:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if net.version == 4 and any(net.overlaps(cf) for cf in CLOUDFLARE_IPV4_NETWORKS):
            matched.append(raw)
    if not matched:
        return []
    shown = display_host(value)
    label = f"{shown} ({value})" if shown and shown != value else value
    return [{
        "code": "cloudflare_shared_cdn",
        "level": "warn",
        "value": value,
        "addresses": matched,
        "msg": (
            f"{label}: IP {', '.join(matched)} belongs to shared Cloudflare CDN. "
            "Adding /32 directly to the bypass table routes all co-hosted sites outside VPN "
            "and may be blocked on TLS ECH. Prefer 'vpn' or 'default'."
        ),
    }]


def _normalize(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("domain or IPv4 network required")
    candidate = value.strip()
    if not candidate or any(ch.isspace() for ch in candidate):
        raise ValueError("invalid domain or IPv4 network")
    try:
        network = ipaddress.ip_network(candidate, strict=True)
    except ValueError:
        normalized_domain = normalize_domain(candidate)
        if normalized_domain is None:
            raise ValueError("invalid domain or IPv4 network") from None
        return normalized_domain
    if network.version != 4 or network.prefixlen < 8:
        raise ValueError("IPv4 prefix must be between /8 and /32")
    return network.with_prefixlen


def _direction(value: object) -> str:
    if not isinstance(value, str) or value not in DIRECTIONS:
        raise ValueError("direction must be direct, vpn or default")
    return value


def _read_bytes(path: Path) -> bytes:
    return ru_table.read_regular(path, missing_ok=True)


def _read_config() -> bytes:
    path = paths.DIRECT_EXCEPTIONS
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise OSError(f"unsafe direct exceptions config: {path}")
    return _read_bytes(path)


def _parse_rule(raw: bytes) -> tuple[str, str] | None:
    line = raw.strip()
    if not line or line.startswith(b"#"):
        return None
    first, separator, remainder = line.partition(b" ")
    if separator and first.decode("ascii", errors="ignore") in DIRECTIONS:
        return _direction(first.decode("ascii")), _normalize(remainder.decode("utf-8").strip())
    return "direct", _normalize(line.decode("utf-8"))


def _entries(config: bytes) -> list[tuple[str, str]]:
    result = []
    for raw in config.splitlines():
        entry = _parse_rule(raw)
        if entry is not None:
            result.append(entry)
    return result


def _values(config: bytes) -> list[str]:
    return [value for _direction_name, value in _entries(config)]


def _resolve(value: str) -> list[str]:
    if "/" in value:
        return [value]
    result = run([DRILL, "-Q", value, "A"], timeout=10)
    if not result.ok:
        raise ValueError(f"cannot resolve {value}")
    networks = set()
    for line in result.stdout.splitlines():
        try:
            address = ipaddress.ip_address(line.strip())
        except ValueError:
            continue
        if address.version == 4:
            networks.add(f"{address}/32")
    if not networks:
        raise ValueError(f"no IPv4 addresses for {value}")
    return sorted(networks)


def _custom_networks(config: bytes, direction: str = "direct") -> set[str]:
    return {
        network for direction_name, value in _entries(config) if direction_name == direction
        for network in _resolve(value)
    }


def _apply_custom(table: bytes, old: set[str], new: set[str]) -> bytes:
    kept = [line for line in table.splitlines(keepends=True) if line.strip().decode("ascii", errors="ignore") not in old]
    present = {line.strip().decode("ascii", errors="ignore") for line in kept}
    additions = sorted(new - present)
    if additions and kept and not kept[-1].endswith(b"\n"):
        kept[-1] += b"\n"
    kept.extend(f"{network}\n".encode("ascii") for network in additions)
    return b"".join(kept)


def _route(value: str) -> dict[str, str]:
    address = value.split("/", 1)[0]
    result = run(["route", "-n", "get", address], timeout=5)
    if not result.ok:
        return {"interface": "", "gateway": "", "error": result.stderr or result.error or "route lookup failed"}
    fields = {}
    for line in result.stdout.splitlines():
        key, separator, item = line.partition(":")
        if separator:
            fields[key.strip()] = item.strip()
    return {
        "interface": fields.get("interface", ""),
        "gateway": fields.get("gateway", ""),
        "error": "" if fields.get("interface") else "route has no interface",
    }


_DEFAULT_RU_TABLE = Path("/usr/local/etc/amnezia/ru_bypass.table")
_DEFAULT_VPN_OVERRIDE_TABLE = Path("/usr/local/etc/amnezia/vpn_override.table")


def _vpn_override_table_path() -> Path:
    if paths.VPN_OVERRIDE_TABLE != _DEFAULT_VPN_OVERRIDE_TABLE:
        return paths.VPN_OVERRIDE_TABLE
    env_override = os.environ.get("GATEBSD_VPN_OVERRIDE_TABLE", "").strip()
    if env_override:
        return Path(env_override)
    if paths.RU_TABLE != _DEFAULT_RU_TABLE:
        return paths.RU_TABLE.parent / "vpn_override.table"
    return paths.VPN_OVERRIDE_TABLE


def _format_override(networks: set[str]) -> bytes:
    return "".join(f"{network}\n" for network in sorted(networks)).encode("ascii")


def _prepare_override_update(override_path: Path, vpn_networks: set[str]) -> tuple[bytes, bytes, bool]:
    old_override = _read_bytes(override_path)
    desired_override = _format_override(vpn_networks)
    should_write = desired_override != old_override and (bool(desired_override) or override_path.exists())
    return old_override, desired_override, should_write


def trigger_route_convergence() -> dict[str, Any]:
    """Converge runtime bypass/override routes when VPN carries default traffic."""
    if os.environ.get("GATEBSD_FORCE_ROUTE_CONVERGE") != "1" and not Path("/etc/rc.subr").exists():
        return {"converged": False, "skipped": True, "reason": "host is not FreeBSD"}
    default_route = run(["route", "-n", "get", "default"], timeout=3)
    if not default_route.ok:
        return {"converged": False, "skipped": True, "reason": "default route unavailable"}
    default_iface = ""
    for line in default_route.stdout.splitlines():
        key, sep, val = line.partition(":")
        if sep and key.strip() == "interface":
            default_iface = val.strip()
            break
    vpn_if = os.environ.get("GATEBSD_VPN_IF") or paths.AMNEZIA_CONFIG.stem or "awg0"
    if default_iface != vpn_if:
        return {"converged": False, "skipped": True, "reason": "vpn default route inactive"}
    res = run(["service", "ru_bypass", "start"], timeout=10)
    return {
        "converged": res.ok,
        "skipped": False,
        "output": (res.stdout or res.stderr or res.error or "").strip(),
    }


def _count_table_prefixes(data: bytes) -> int:
    count = 0
    for raw_line in data.splitlines():
        stripped = raw_line.strip()
        if stripped and not stripped.startswith(b"#"):
            count += 1
    return count


def merge_file() -> dict[str, Any]:
    table_path = paths.RU_TABLE
    with exclusive_lock(table_path.with_suffix(table_path.suffix + ".lock")):
        table = _read_bytes(table_path)
        config = _read_config()
        direct = _custom_networks(config, "direct")
        vpn = _custom_networks(config, "vpn")
        merged = _apply_custom(table, vpn, direct)
        if merged != table:
            atomic_write_bytes(table_path, merged, mode=0o640, preserve_metadata=bool(table))
        override_path = _vpn_override_table_path()
        old_override, desired_override, write_override = _prepare_override_update(override_path, vpn)
        if write_override:
            atomic_write_bytes(override_path, desired_override, mode=0o640, preserve_metadata=bool(old_override))
    return {"ok": True, "custom": len(direct), "vpn": len(vpn)}


def merge_candidate(
    candidate_path: Path,
    *,
    min_prefixes: int = 0,
    backup_path: Path | None = None,
) -> dict[str, Any]:
    """Atomically merge live exceptions onto a validated candidate and publish under RU_TABLE.lock."""
    candidate_data = ru_table.read_regular(Path(candidate_path))
    table_path = paths.RU_TABLE
    with exclusive_lock(table_path.with_suffix(table_path.suffix + ".lock")):
        config = _read_config()
        direct = _custom_networks(config, "direct")
        vpn = _custom_networks(config, "vpn")
        merged = _apply_custom(candidate_data, vpn, direct)
        count = _count_table_prefixes(merged)
        if min_prefixes > 0 and count < min_prefixes:
            raise ValueError(f"download rejected: only {count} prefixes (minimum {min_prefixes})")
        previous = _read_bytes(table_path)
        if backup_path is not None:
            atomic_write_bytes(Path(backup_path), previous, mode=0o600, preserve_metadata=False)
        atomic_write_bytes(table_path, merged, mode=0o640, preserve_metadata=bool(previous))
        override_path = _vpn_override_table_path()
        old_override, desired_override, write_override = _prepare_override_update(override_path, vpn)
        if write_override:
            atomic_write_bytes(override_path, desired_override, mode=0o640, preserve_metadata=bool(old_override))
        return {
            "ok": True,
            "count": count,
            "custom": len(direct),
            "vpn": len(vpn),
            "old_sha256": ru_table.digest(previous),
            "new_sha256": ru_table.digest(merged),
        }


def status() -> dict[str, Any]:
    entries = []
    warnings = []
    checked_at = int(time.time())
    for direction, value in _entries(_read_config()):
        try:
            networks = _resolve(value)
            error = ""
        except ValueError as exc:
            networks, error = [], str(exc)
        route = _route(networks[0]) if networks else {"interface": "", "gateway": "", "error": error}
        entry_warnings = _shared_cdn_warnings(direction, value, networks)
        warnings.extend(entry_warnings)
        entries.append({
            "value": value,
            "display_value": display_host(value),
            "direction": direction,
            "networks": networks,
            "checked_at": checked_at,
            "route": route,
            "error": error,
            "warnings": entry_warnings,
        })
    return {"config": str(paths.DIRECT_EXCEPTIONS), "entries": entries, "warnings": warnings}


def _format_rule(direction: str, value: str) -> bytes:
    return f"{value}\n".encode("ascii") if direction == "direct" else f"{direction} {value}\n".encode("ascii")


def change(value: object, *, add: bool, direction: object = "direct") -> tuple[int, dict[str, Any]]:
    try:
        normalized = _normalize(value)
        direction_name = _direction(direction)
    except ValueError as exc:
        return 400, {"error": str(exc)}
    table_path = paths.RU_TABLE
    try:
        override_path = _vpn_override_table_path()
        with exclusive_lock(table_path.with_suffix(table_path.suffix + ".lock")):
            old_config = _read_config()
            old_entries = _entries(old_config)
            existing = next((item for item in old_entries if item[1] == normalized), None)
            if add and existing == (direction_name, normalized):
                old_vpn = _custom_networks(old_config, "vpn")
                old_override, desired_override, write_override = _prepare_override_update(override_path, old_vpn)
                if write_override:
                    atomic_write_bytes(override_path, desired_override, mode=0o640, preserve_metadata=bool(old_override))
                return 200, {"ok": True, "changed": False, **status()}
            if not add and existing is None:
                return 200, {"ok": True, "changed": False, **status()}
            if not add:
                new_config_parts = []
                for raw in old_config.splitlines(keepends=True):
                    entry = _parse_rule(raw)
                    if entry is not None and entry[1] == normalized:
                        continue
                    new_config_parts.append(raw)
                new_config = b"".join(new_config_parts)
            elif existing is None:
                separator = b"" if not old_config or old_config.endswith(b"\n") else b"\n"
                new_config = old_config + separator + _format_rule(direction_name, normalized)
            else:
                new_config_parts = []
                for raw in old_config.splitlines(keepends=True):
                    entry = _parse_rule(raw)
                    if entry is not None and entry[1] == normalized:
                        new_config_parts.append(_format_rule(direction_name, normalized))
                    else:
                        new_config_parts.append(raw)
                new_config = b"".join(new_config_parts)
            table = _read_bytes(table_path)
            old_direct = _custom_networks(old_config, "direct")
            old_vpn = _custom_networks(old_config, "vpn")
            new_direct = _custom_networks(new_config, "direct")
            new_vpn = _custom_networks(new_config, "vpn")
            merged = _apply_custom(table, old_direct | old_vpn | new_vpn, new_direct)
            old_override, desired_override, write_override = _prepare_override_update(override_path, new_vpn)
            try:
                atomic_write_text(paths.DIRECT_EXCEPTIONS, new_config.decode("utf-8"), mode=0o600, preserve_metadata=bool(old_config))
                if merged != table:
                    atomic_write_bytes(table_path, merged, mode=0o640, preserve_metadata=bool(table))
                if write_override:
                    atomic_write_bytes(override_path, desired_override, mode=0o640, preserve_metadata=bool(old_override))
            except Exception:
                atomic_write_text(paths.DIRECT_EXCEPTIONS, old_config.decode("utf-8"), mode=0o600, preserve_metadata=bool(old_config))
                if _read_bytes(table_path) != table:
                    atomic_write_bytes(table_path, table, mode=0o640, preserve_metadata=bool(table))
                if override_path.exists() and _read_bytes(override_path) != old_override:
                    atomic_write_bytes(override_path, old_override, mode=0o640, preserve_metadata=bool(old_override))
                raise
        converge = trigger_route_convergence()
        return 200, {"ok": True, "changed": True, "route_converge": converge, **status()}
    except (OSError, UnicodeError, ValueError) as exc:
        return 500, {"error": str(exc)}


def diagnose(value: object, *, direction: object = "direct") -> tuple[int, dict[str, Any]]:
    try:
        normalized = _normalize(value)
        direction_name = _direction(direction)
    except ValueError as exc:
        return 400, {"error": str(exc)}
    checked_at = int(time.time())
    is_network = "/" in normalized
    if is_network:
        networks = [normalized]
        dns = {"applicable": False, "ok": None, "addresses": networks, "error": ""}
    else:
        try:
            networks = _resolve(normalized)
            dns = {"applicable": True, "ok": True, "addresses": networks, "error": ""}
        except ValueError as exc:
            networks = []
            dns = {"applicable": True, "ok": False, "addresses": [], "error": str(exc)}
    route = _route(networks[0]) if networks else {"interface": "", "gateway": "", "error": dns["error"]}
    interface = route.get("interface", "")
    actual = "vpn" if interface.startswith(("awg", "wg")) else "direct" if interface else "unknown"
    route["path"] = actual
    route["matches"] = actual == direction_name if direction_name != "default" else None
    if is_network:
        https = {"applicable": False, "ok": None, "error": ""}
    elif not dns["ok"]:
        https = {"applicable": True, "ok": False, "error": "DNS resolution failed"}
    else:
        result = run(["fetch", "-T", "10", "-qo", "/dev/null", f"https://{normalized}/"], timeout=15)
        https = {
            "applicable": True,
            "ok": result.ok,
            "error": "" if result.ok else result.stderr or result.error or "HTTPS request failed",
        }
    ok = (
        dns["ok"] is not False
        and bool(interface)
        and route["matches"] is not False
        and https["ok"] is not False
    )
    return 200, {
        "ok": ok,
        "value": normalized,
        "display_value": display_host(normalized),
        "direction": direction_name,
        "checked_at": checked_at,
        "networks": networks,
        "dns": dns,
        "route": route,
        "https": https,
        "warnings": _shared_cdn_warnings(direction_name, normalized, networks),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="merge persistent direct VPN exceptions")
    parser.add_argument("action", choices=["merge"])
    parser.add_argument("--candidate")
    parser.add_argument("--min-prefixes", type=int, default=0)
    parser.add_argument("--backup")
    args = parser.parse_args()
    if args.action == "merge":
        if args.candidate:
            result = merge_candidate(
                Path(args.candidate),
                min_prefixes=args.min_prefixes,
                backup_path=Path(args.backup) if args.backup else None,
            )
            print(f"count={result['count']}")
            print(f"old_sha256={result['old_sha256']}")
            print(f"new_sha256={result['new_sha256']}")
        else:
            print(merge_file())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
