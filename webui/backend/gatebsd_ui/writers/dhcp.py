"""Safe edits for ISC DHCP static-host declarations."""
from __future__ import annotations

import ipaddress
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from .. import backup
from ..adapters import DHCPD_CONF
from ..command import run
from ..fsutil import exclusive_lock, atomic_write_text, read_regular_text

_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_ROUTERS_RE = re.compile(
    r"^\s*option\s+routers\s+([0-9., ]+?)\s*;", re.IGNORECASE
)
_FIXED_ADDRESS_RE = re.compile(
    r"^\s*fixed-address\s+(\d+(?:\.\d+){3})\s*;", re.IGNORECASE
)
_HOST_HEADER_RE = re.compile(
    r"^\s*host\s+([A-Za-z0-9_.-]+)", re.IGNORECASE
)


def _strip_comment(line: str) -> str:
    """Remove a trailing ISC-style comment.

    Brace counting must not see braces that only appear inside comments: a `}`
    in a comment closed a host block early and produced a config that failed
    validation, and a `{` in a comment made the block never close so an existing
    host reported as not found.
    """
    return line.split("#", 1)[0]


def _declared_routers(
    lines: list[str], block_start: int, block_end: int
) -> list[ipaddress.IPv4Address]:
    """Gateway addresses advertised to clients, subnet-scoped then global."""
    found: list[ipaddress.IPv4Address] = []
    scopes = (range(block_start, block_end), range(0, len(lines)))
    for scope in scopes:
        for index in scope:
            match = _ROUTERS_RE.match(_strip_comment(lines[index]))
            if not match:
                continue
            for token in match.group(1).replace(",", " ").split():
                try:
                    found.append(ipaddress.IPv4Address(token))
                except ipaddress.AddressValueError:
                    continue
        if found:
            break
    return found


def _static_reservations(lines: list[str]) -> list[tuple[ipaddress.IPv4Address, str]]:
    """Every fixed-address reservation, paired with its host name."""
    reservations: list[tuple[ipaddress.IPv4Address, str]] = []
    current = ""
    for raw in lines:
        line = _strip_comment(raw)
        header = _HOST_HEADER_RE.match(line)
        if header:
            current = header.group(1)
        match = _FIXED_ADDRESS_RE.match(line)
        if match:
            try:
                reservations.append((ipaddress.IPv4Address(match.group(1)), current))
            except ipaddress.AddressValueError:
                continue
    return reservations


def _normalize_mac(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if _MAC_RE.fullmatch(value) else None


def _normalize_ipv4(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ipaddress.AddressValueError:
        return None


def _normalize_hostname(value: object, mac: str) -> str | None:
    if value in (None, ""):
        return mac.replace(":", "-")
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if _HOST_RE.fullmatch(value) else None


def _validate_candidate(content: str, directory: Path) -> tuple[bool, str]:
    fd = -1
    temp_path: str | None = None
    try:
        fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".dhcpd.", suffix=".conf")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            fd = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        result = run(["/usr/local/sbin/dhcpd", "-q", "-t", "-cf", temp_path], timeout=10)
        return result.ok, result.stderr or result.stdout or result.error or ""
    except OSError as exc:
        return False, str(exc)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_path is not None:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except OSError:
                pass


def _commit_and_restart(content: str, reason: str) -> tuple[int, dict[str, Any]]:
    try:
        original, metadata = read_regular_text(DHCPD_CONF, max_size=2 * 1024 * 1024, errors="strict")
    except OSError as exc:
        return 500, {"error": f"failed to read dhcpd.conf: {exc}"}
    valid, detail = _validate_candidate(content, DHCPD_CONF.parent)
    if not valid:
        return 400, {"error": "dhcpd.conf validation failed", "detail": detail}

    backup_meta = backup.backup_files([DHCPD_CONF], reason=reason)
    try:
        atomic_write_text(DHCPD_CONF, content, mode=stat.S_IMODE(metadata.st_mode))
    except OSError as exc:
        return 500, {"error": f"failed to write dhcpd.conf: {exc}", "backup": backup_meta}

    restarted = run(["service", "isc-dhcpd", "restart"], timeout=15)
    if restarted.ok:
        return 200, {"ok": True, "backup": backup_meta}

    rollback_ok = False
    rollback_detail = ""
    try:
        atomic_write_text(DHCPD_CONF, original, mode=stat.S_IMODE(metadata.st_mode))
        rollback = run(["service", "isc-dhcpd", "restart"], timeout=15)
        rollback_ok = rollback.ok
        rollback_detail = rollback.stderr or rollback.stdout or rollback.error or ""
    except OSError as exc:
        rollback_detail = str(exc)
    return 500, {
        "error": "dhcpd restart failed; previous configuration restored",
        "detail": restarted.stderr or restarted.stdout or restarted.error or "",
        "rolled_back": rollback_ok,
        "rollback_detail": rollback_detail,
        "backup": backup_meta,
    }


def static_add(mac_value: object, ip_value: object, hostname_value: object = "") -> tuple[int, dict[str, Any]]:
    mac = _normalize_mac(mac_value)
    ip = _normalize_ipv4(ip_value)
    if mac is None or ip is None:
        return 400, {"error": "valid mac and IPv4 address are required"}
    hostname = _normalize_hostname(hostname_value, mac)
    if hostname is None:
        return 400, {"error": "invalid hostname"}
    try:
        if not DHCPD_CONF.exists():
            return 404, {"error": "dhcpd.conf not found"}
    except OSError as exc:
        return 500, {"error": f"failed to access dhcpd.conf: {exc}"}

    lock_path = DHCPD_CONF.with_suffix(DHCPD_CONF.suffix + ".lock")
    try:
        with exclusive_lock(lock_path):
            content, _metadata = read_regular_text(DHCPD_CONF, max_size=2 * 1024 * 1024, errors="strict")
            if re.search(rf"(?im)^\s*hardware\s+ethernet\s+{re.escape(mac)}\s*;", content):
                return 409, {"error": "static lease for mac already exists"}
            if re.search(rf"(?im)^\s*fixed-address\s+{re.escape(ip)}\s*;", content):
                return 409, {"error": "static lease for IPv4 address already exists"}
            block = (
                f"host {hostname} {{\n"
                f"  hardware ethernet {mac};\n"
                f"  fixed-address {ip};\n"
                "}\n"
            )
            return _commit_and_restart(content.rstrip() + "\n\n" + block, "dhcp-static-add")
    except OSError as exc:
        return 500, {"error": f"failed to update dhcpd.conf: {exc}"}


def _block_matches_mac(block_text: str, mac: str) -> bool:
    """Whether a host block declares the given hardware address.

    The directive is matched anywhere in the block rather than only at the start
    of a line, so a single-line ``host x { hardware ethernet ...; }`` declaration
    is recognised.
    """
    code = "\n".join(_strip_comment(line) for line in block_text.splitlines())
    return re.search(
        rf"(?i)\bhardware\s+ethernet\s+{re.escape(mac)}\s*;", code
    ) is not None


def static_remove(mac_value: object) -> tuple[int, dict[str, Any]]:
    mac = _normalize_mac(mac_value)
    if mac is None:
        return 400, {"error": "valid mac is required"}
    try:
        if not DHCPD_CONF.exists():
            return 404, {"error": "dhcpd.conf not found"}
    except OSError as exc:
        return 500, {"error": f"failed to access dhcpd.conf: {exc}"}

    lock_path = DHCPD_CONF.with_suffix(DHCPD_CONF.suffix + ".lock")
    try:
        with exclusive_lock(lock_path):
            content, _metadata = read_regular_text(DHCPD_CONF, max_size=2 * 1024 * 1024, errors="strict")
            lines = content.splitlines(keepends=True)
            output: list[str] = []
            block: list[str] = []
            depth = 0
            in_host = False
            found = False
            for line in lines:
                # Brace accounting ignores comments: a brace inside one is not
                # syntax. Counting it closed a block early (producing a config
                # that failed validation) or never closed it (reporting an
                # existing host as not found).
                code = _strip_comment(line)
                stripped = code.strip()
                if not in_host and re.match(r"^host\s+[A-Za-z0-9_.-]+\s*\{", stripped):
                    in_host = True
                    block = [line]
                    depth = code.count("{") - code.count("}")
                    if depth <= 0:
                        # Single-line declaration: the whole host is on this line.
                        if _block_matches_mac("".join(block), mac):
                            found = True
                        else:
                            output.extend(block)
                        in_host = False
                        block = []
                    continue
                if in_host:
                    block.append(line)
                    depth += code.count("{") - code.count("}")
                    if depth <= 0:
                        if _block_matches_mac("".join(block), mac):
                            found = True
                        else:
                            output.extend(block)
                        in_host = False
                        block = []
                    continue
                output.append(line)
            if in_host:
                output.extend(block)
            if not found:
                return 404, {"error": f"host with mac {mac} not found"}
            return _commit_and_restart("".join(output), "dhcp-static-remove")
    except OSError as exc:
        return 500, {"error": f"failed to update dhcpd.conf: {exc}"}


def _lease_seconds(value: object) -> int | None:
    if isinstance(value, int):
        seconds = value
    elif isinstance(value, str):
        text = value.strip().lower()
        match = re.fullmatch(r"(\d+)([smhd]?)", text)
        if not match:
            return None
        amount = int(match.group(1))
        factor = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
        seconds = amount * factor
    else:
        return None
    return seconds if 60 <= seconds <= 604800 else None


def _replace_first_assignment(text: str, key: str, value: str) -> str:
    pattern = re.compile(rf"^(\s*){re.escape(key)}\s+[^;]+;\s*$", re.IGNORECASE)
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        match = pattern.match(line)
        if match:
            lines[index] = f"{match.group(1)}{key} {value};"
            return "\n".join(lines).rstrip("\n") + "\n"
    # Global lease directives belong before the first subnet/host block.
    insert_at = next(
        (index for index, line in enumerate(lines) if re.match(r"^\s*(?:subnet|host)\b", line, re.IGNORECASE)),
        len(lines),
    )
    lines.insert(insert_at, f"{key} {value};")
    return "\n".join(lines).rstrip("\n") + "\n"


def _replace_range(text: str, start: ipaddress.IPv4Address, end: ipaddress.IPv4Address) -> tuple[str | None, str | None]:
    lines = text.splitlines()
    subnet_header = re.compile(
        r"^\s*subnet\s+(\d+(?:\.\d+){3})\s+netmask\s+(\d+(?:\.\d+){3})\s*\{",
        re.IGNORECASE,
    )
    candidates: list[tuple[int, int, ipaddress.IPv4Network]] = []
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        match = subnet_header.match(line)
        if not match:
            continue
        try:
            network = ipaddress.IPv4Network((match.group(1), match.group(2)), strict=True)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            continue
        depth = line.count("{") - line.count("}")
        end_index = len(lines)
        for cursor in range(index + 1, len(lines)):
            depth += lines[cursor].count("{") - lines[cursor].count("}")
            if depth <= 0:
                end_index = cursor + 1
                break
        if start in network and end in network:
            candidates.append((index, end_index, network))
    if len(candidates) != 1:
        return None, "range must belong to exactly one configured subnet"
    block_start, block_end, network = candidates[0]
    if start >= end or start in {network.network_address, network.broadcast_address} or end in {network.network_address, network.broadcast_address}:
        return None, "invalid DHCP range boundaries"

    # dhcpd -t accepts a range that contains the router's own address or an
    # existing static reservation, and then hands those addresses out. The
    # result is a duplicate-address conflict on the default gateway and clients
    # with a broken route and resolver -- a full site outage that no syntax
    # check can see.
    span = ipaddress.summarize_address_range(start, end)
    covered = list(span)

    def _in_range(address: ipaddress.IPv4Address) -> bool:
        return any(address in net for net in covered)

    for router in _declared_routers(lines, block_start, block_end):
        if _in_range(router):
            return None, (
                f"range includes the advertised gateway {router}; DHCP would "
                "hand out the router's own address"
            )

    for reserved, host in _static_reservations(lines):
        if _in_range(reserved):
            return None, (
                f"range includes {reserved}, already reserved for host "
                f"{host!r}; exclude it or remove the reservation"
            )

    range_re = re.compile(r"^(\s*)range\s+\d+(?:\.\d+){3}\s+\d+(?:\.\d+){3}\s*;\s*$", re.IGNORECASE)
    matches = [index for index in range(block_start + 1, block_end) if not lines[index].lstrip().startswith("#") and range_re.match(lines[index])]
    if len(matches) > 1:
        return None, "subnet contains multiple dynamic ranges; edit it manually"
    replacement = f"        range {start} {end};"
    if matches:
        match = range_re.match(lines[matches[0]])
        assert match is not None
        lines[matches[0]] = f"{match.group(1)}range {start} {end};"
    else:
        lines.insert(block_start + 1, replacement)
    return "\n".join(lines).rstrip("\n") + "\n", None


def range_set(start_value: object, end_value: object, lease_value: object) -> tuple[int, dict[str, Any]]:
    try:
        start = ipaddress.IPv4Address(str(start_value).strip())
        end = ipaddress.IPv4Address(str(end_value).strip())
    except (ipaddress.AddressValueError, ValueError):
        return 400, {"error": "valid IPv4 start and end addresses are required"}
    lease = _lease_seconds(lease_value)
    if lease is None:
        return 400, {"error": "lease must be 60-604800 seconds or use m/h/d suffix"}
    lock_path = DHCPD_CONF.with_suffix(DHCPD_CONF.suffix + ".lock")
    try:
        with exclusive_lock(lock_path):
            content, _metadata = read_regular_text(DHCPD_CONF, max_size=2 * 1024 * 1024, errors="strict")
            updated, error = _replace_range(content, start, end)
            if updated is None:
                return 400, {"error": error}
            updated = _replace_first_assignment(updated, "default-lease-time", str(lease))
            return _commit_and_restart(updated, "dhcp-range")
    except (OSError, UnicodeError) as exc:
        return 500, {"error": f"failed to update DHCP range: {exc}"}
