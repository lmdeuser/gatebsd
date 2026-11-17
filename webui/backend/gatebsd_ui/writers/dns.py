"""Safe Unbound forwarder configuration."""
from __future__ import annotations

from contextlib import nullcontext
import ipaddress
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from .. import backup, paths
from ..command import run
from ..fsutil import atomic_write_text, exclusive_lock, read_regular_text
from ..resolver import display_host, normalize_domain

_FORWARD_ZONE_RE = re.compile(r"^\s*forward-zone\s*:\s*$", re.IGNORECASE)
_NAME_ROOT_RE = re.compile(r"^\s*name\s*:\s*[\"']?\.[\"']?\s*$", re.IGNORECASE)
_FORWARD_ADDR_RE = re.compile(r"^\s*forward-addr\s*:", re.IGNORECASE)

DEFAULT_SPLIT_UPSTREAMS: tuple[str, ...] = ("77.88.8.8", "77.88.8.1")
FORBIDDEN_SPLIT_ZONES: frozenset[str] = frozenset({
    "ru", "su", "xn--p1ai",
    "com.ru", "net.ru", "org.ru", "pp.ru",
    "msk.ru", "spb.ru",
    "gov.ru", "mil.ru", "edu.ru", "ac.ru", "int.ru",
})


def _normalize_servers(value: object) -> tuple[list[str] | None, str | None]:
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        return None, "servers must be a list containing 1-8 IP addresses"
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            return None, "each DNS server must be a string"
        try:
            parsed = ipaddress.ip_address(item.strip())
        except ValueError:
            return None, f"invalid DNS server: {item!r}"
        # unbound-checkconf accepts any syntactically valid address, so these
        # have to be rejected here. Each one silently breaks resolution for the
        # entire site while the service still reports healthy: an unspecified,
        # multicast or reserved address makes every forward fail, and pointing
        # the forwarder at the router itself creates a query loop.
        if parsed.is_unspecified:
            return None, f"DNS server must not be the unspecified address: {parsed}"
        if parsed.is_loopback:
            return None, f"DNS server must not be a loopback address: {parsed}"
        if parsed.is_multicast:
            return None, f"DNS server must not be a multicast address: {parsed}"
        # Checked before is_reserved, which also matches 255.255.255.255 and
        # would report it less usefully.
        if parsed.version == 4 and parsed == ipaddress.IPv4Address("255.255.255.255"):
            return None, "DNS server must not be the broadcast address"
        if parsed.is_reserved:
            return None, f"DNS server must not be a reserved address: {parsed}"
        if parsed.is_link_local:
            return None, f"DNS server must not be a link-local address: {parsed}"
        if _is_local_address(parsed):
            return None, (
                f"DNS server {parsed} is configured on this router; forwarding to "
                "ourselves would create a resolution loop"
            )
        address = str(parsed)
        if address not in seen:
            result.append(address)
            seen.add(address)
    return result, None


def _is_local_address(candidate: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether an address is assigned to a local interface.

    Used to refuse a forwarder that points back at this router. Failing open on
    any error is deliberate: an unreadable ifconfig must not block a legitimate
    DNS change.
    """
    result = run(["ifconfig"], timeout=5)
    if not result.ok:
        return False
    target = str(candidate)
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] in {"inet", "inet6"}:
            local = fields[1].split("%", 1)[0]
            if local == target:
                return True
    return False


def parse_forwarders(text: str) -> list[str]:
    lines = text.splitlines()
    for start, line in enumerate(lines):
        if not _FORWARD_ZONE_RE.match(line):
            continue
        end = len(lines)
        for index in range(start + 1, len(lines)):
            candidate = lines[index]
            stripped = candidate.strip()
            if stripped and not stripped.startswith("#") and not candidate[:1].isspace():
                end = index
                break
        block = lines[start + 1:end]
        if not any(_NAME_ROOT_RE.match(item) for item in block):
            continue
        result: list[str] = []
        for item in block:
            if not _FORWARD_ADDR_RE.match(item):
                continue
            raw = item.split(":", 1)[1].strip().strip('"\'')
            # Unbound permits @port and #tls-name suffixes.  The web editor
            # intentionally manages plain IP forwarders only.
            raw = raw.split("@", 1)[0].split("#", 1)[0]
            try:
                result.append(str(ipaddress.ip_address(raw)))
            except ValueError:
                continue
        return result
    return []


def _replace_forwarders(text: str, servers: list[str]) -> str:
    lines = text.splitlines()
    root_start = root_end = -1
    name_index = -1
    for start, line in enumerate(lines):
        if not _FORWARD_ZONE_RE.match(line):
            continue
        end = len(lines)
        for index in range(start + 1, len(lines)):
            candidate = lines[index]
            stripped = candidate.strip()
            if stripped and not stripped.startswith("#") and not candidate[:1].isspace():
                end = index
                break
        for index in range(start + 1, end):
            if _NAME_ROOT_RE.match(lines[index]):
                root_start, root_end, name_index = start, end, index
                break
        if root_start >= 0:
            break

    forward_lines = [f"    forward-addr: {server}" for server in servers]
    if root_start < 0:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend(["forward-zone:", '    name: "."', *forward_lines])
        return "\n".join(lines).rstrip("\n") + "\n"

    output: list[str] = []
    inserted = False
    for index, line in enumerate(lines):
        if root_start < index < root_end and _FORWARD_ADDR_RE.match(line):
            continue
        output.append(line)
        if index == name_index:
            output.extend(forward_lines)
            inserted = True
    if not inserted:
        raise ValueError("root forward-zone has no name directive")
    return "\n".join(output).rstrip("\n") + "\n"


def _validate_candidate(content: str, directory: Path) -> tuple[bool, str]:
    fd = -1
    name: str | None = None
    try:
        fd, name = tempfile.mkstemp(dir=directory, prefix=".unbound.", suffix=".conf")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            fd = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        result = run(["unbound-checkconf", name], timeout=15)
        return result.ok, result.stderr or result.stdout or result.error or ""
    except OSError as exc:
        return False, str(exc)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if name is not None:
            try:
                Path(name).unlink(missing_ok=True)
            except OSError:
                pass


def set_upstreams(value: object) -> tuple[int, dict[str, Any]]:
    servers, error = _normalize_servers(value)
    if servers is None:
        return 400, {"error": error}
    config = paths.UNBOUND_CONF
    lock_path = config.with_suffix(config.suffix + ".gatebsd.lock")
    try:
        with exclusive_lock(lock_path):
            original, metadata = read_regular_text(config, max_size=2 * 1024 * 1024, errors="strict")
            updated = _replace_forwarders(original, servers)
            if updated == original:
                return 200, {"ok": True, "servers": servers, "changed": False}
            valid, detail = _validate_candidate(updated, config.parent)
            if not valid:
                return 400, {"error": "Unbound configuration validation failed", "detail": detail}
            backup_meta = backup.backup_files([config], reason="dns-upstreams")
            atomic_write_text(config, updated, mode=stat.S_IMODE(metadata.st_mode), preserve_metadata=True)
            reload_result = run(["service", "unbound", "reload"], timeout=20)
            if not reload_result.ok:
                reload_result = run(["service", "unbound", "restart"], timeout=30)
            if reload_result.ok:
                return 200, {"ok": True, "servers": servers, "changed": True, "backup": backup_meta}

            atomic_write_text(config, original, mode=stat.S_IMODE(metadata.st_mode), preserve_metadata=True)
            rollback = run(["service", "unbound", "restart"], timeout=30)
            return 500, {
                "error": "Unbound failed to load new forwarders; previous configuration restored",
                "detail": reload_result.stderr or reload_result.stdout or reload_result.error or "",
                "rolled_back": rollback.ok,
                "backup": backup_meta,
            }
    except (OSError, UnicodeError, ValueError) as exc:
        return 500, {"error": f"failed to update DNS upstreams: {exc}"}


def _unbound_lock(lock_path: Path):
    if os.environ.get("GATEBSD_UNBOUND_LOCK_HELD") == "1" or os.environ.get("GATEBSD_UPGRADE_CONFIG_LOCKS_HELD") == "1":
        return nullcontext()
    return exclusive_lock(lock_path)


def _normalize_split_upstreams(value: object) -> tuple[list[str] | None, str | None]:
    if value is None:
        return list(DEFAULT_SPLIT_UPSTREAMS), None
    servers, error = _normalize_servers(value)
    if servers is None:
        return None, error
    for item in servers:
        if ipaddress.ip_address(item).version != 4:
            return None, f"Split-DNS upstream must be IPv4: {item}"
    return servers, None


def _normalize_split_domain(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Split-DNS domain must be a string")
    raw = value.strip()
    single = normalize_domain(raw, require_multi_label=False)
    if single is None:
        raise ValueError(f"invalid Split-DNS domain: {value!r}")
    if "." not in single or single in FORBIDDEN_SPLIT_ZONES:
        raise ValueError(
            f"refusing broad or top-level zone {value!r}; list specific domains instead so root DNS stays in VPN"
        )
    normalized = normalize_domain(raw, require_multi_label=True)
    if normalized is None:
        raise ValueError(f"invalid Split-DNS domain: {value!r}")
    return normalized


def _normalize_split_domains(value: object) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("domains must be a list of domain strings")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        normalized = _normalize_split_domain(item)
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    return result


def parse_split_dns(text: str) -> dict[str, list[str]]:
    """Parse /usr/local/etc/gatebsd/split-dns.conf cleanly."""
    upstreams: list[str] | None = None
    domains: list[str] = []
    seen: set[str] = set()
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens = stripped.replace(",", " ").split()
        key = tokens[0].lower()
        if key == "upstreams":
            parsed_upstreams, error = _normalize_split_upstreams(tokens[1:])
            if parsed_upstreams is None:
                raise ValueError(f"line {line_no}: {error}")
            upstreams = parsed_upstreams
            continue
        if key == "domain":
            if len(tokens) != 2:
                raise ValueError(f"line {line_no}: expected 'domain HOSTNAME'")
            domain_token = tokens[1]
        elif len(tokens) == 1:
            domain_token = tokens[0]
        else:
            raise ValueError(f"line {line_no}: invalid split-dns directive")
        domain = _normalize_split_domain(domain_token)
        if domain not in seen:
            domains.append(domain)
            seen.add(domain)
    return {
        "upstreams": upstreams if upstreams is not None else list(DEFAULT_SPLIT_UPSTREAMS),
        "domains": domains,
    }


def render_split_dns_conf(domains: list[str], upstreams: list[str]) -> str:
    lines = [
        "# GateBSD targeted Split-DNS configuration.",
        "# Root zone \".\" stays over the VPN upstream; only listed domains bypass it.",
        f"upstreams {' '.join(upstreams)}",
        *domains,
    ]
    return "\n".join(lines) + "\n"


def render_unbound_split_dns(domains: list[str], upstreams: list[str]) -> str:
    lines = [
        "# Generated by GateBSD from /usr/local/etc/gatebsd/split-dns.conf — do not edit manually.",
    ]
    if not domains:
        lines.append("# No targeted Split-DNS domains configured.")
        return "\n".join(lines) + "\n"
    for domain in domains:
        lines.append("forward-zone:")
        lines.append(f'    name: "{domain}."')
        for server in upstreams:
            lines.append(f"    forward-addr: {server}")
    return "\n".join(lines) + "\n"


def _ensure_split_include(unbound_text: str, split_path: Path) -> str:
    target = str(split_path)
    include_pattern = re.compile(rf'^\s*include:\s*["\']?{re.escape(target)}["\']?\s*$')
    lines = unbound_text.splitlines()
    for line in lines:
        if include_pattern.match(line) and not line[:1].isspace():
            return unbound_text
    filtered = [line for line in lines if not include_pattern.match(line)]
    include_line = f'include: "{target}"'
    output: list[str] = []
    inserted = False
    for line in filtered:
        if not inserted and _FORWARD_ZONE_RE.match(line):
            if output and output[-1].strip():
                output.append("")
            output.append(include_line)
            output.append("")
            inserted = True
        output.append(line)
    if not inserted:
        if output and output[-1].strip():
            output.append("")
        output.append(include_line)
    return "\n".join(output).rstrip("\n") + "\n"


def _validate_split_candidate(
    unbound_text: str,
    split_text: str,
    unbound_conf: Path,
    split_unbound_conf: Path,
) -> tuple[bool, str]:
    split_unbound_conf.parent.mkdir(parents=True, exist_ok=True)
    fd = -1
    tmp_split: str | None = None
    try:
        fd, tmp_split = tempfile.mkstemp(dir=split_unbound_conf.parent, prefix=".split-dns.", suffix=".conf")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            fd = -1
            stream.write(split_text)
            stream.flush()
            os.fsync(stream.fileno())
        target = str(split_unbound_conf)
        tmp_unbound = re.sub(
            rf'(?m)^include:\s*["\']?{re.escape(target)}["\']?\s*$',
            f'include: "{tmp_split}"',
            unbound_text,
        )
        return _validate_candidate(tmp_unbound, unbound_conf.parent)
    except OSError as exc:
        return False, str(exc)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_split is not None:
            try:
                Path(tmp_split).unlink(missing_ok=True)
            except OSError:
                pass


def _snapshot_file(path: Path) -> tuple[str | None, int | None]:
    try:
        text, meta = read_regular_text(path, max_size=2 * 1024 * 1024, errors="strict")
        return text, stat.S_IMODE(meta.st_mode)
    except FileNotFoundError:
        return None, None


def _restore_file_state(path: Path, snapshot: tuple[str | None, int | None], default_mode: int) -> None:
    text, mode = snapshot
    if text is None:
        path.unlink(missing_ok=True)
        return
    atomic_write_text(path, text, mode=mode or default_mode, preserve_metadata=(mode is not None))


def get_split_dns() -> dict[str, Any]:
    """Read current targeted Split-DNS configuration."""
    split_conf = paths.SPLIT_DNS_CONF
    split_unbound_conf = paths.UNBOUND_SPLIT_DNS_CONF
    unbound_conf = paths.UNBOUND_CONF
    config_exists = split_conf.exists()
    include_present = False
    if unbound_conf.exists():
        try:
            utext, _ = read_regular_text(unbound_conf, max_size=2 * 1024 * 1024, errors="strict")
            include_present = any(
                re.match(rf'^\s*include:\s*["\']?{re.escape(str(split_unbound_conf))}["\']?\s*$', line)
                for line in utext.splitlines()
            )
        except (OSError, UnicodeError):
            include_present = False
    try:
        raw_text, _ = _snapshot_file(split_conf)
        parsed = parse_split_dns(raw_text or "")
        error = ""
    except (OSError, UnicodeError, ValueError) as exc:
        parsed = {"upstreams": list(DEFAULT_SPLIT_UPSTREAMS), "domains": []}
        error = str(exc)
    payload: dict[str, Any] = {
        "config": str(split_conf),
        "unbound_config": str(split_unbound_conf),
        "configured": config_exists and split_unbound_conf.exists() and include_present,
        "upstreams": parsed["upstreams"],
        "default_upstreams": list(DEFAULT_SPLIT_UPSTREAMS),
        "domains": [{"value": d, "display_value": display_host(d)} for d in parsed["domains"]],
    }
    if error:
        payload["error"] = error
    return payload


def sync_split_dns(*, reload_service: bool = True, check_running_for_reload: bool = False) -> bool:
    """Render Unbound split-dns.conf and ensure its include in unbound.conf."""
    unbound_conf = paths.UNBOUND_CONF
    split_conf = paths.SPLIT_DNS_CONF
    split_unbound_conf = paths.UNBOUND_SPLIT_DNS_CONF
    lock_path = unbound_conf.with_suffix(unbound_conf.suffix + ".gatebsd.lock")
    with _unbound_lock(lock_path):
        unbound_snap = _snapshot_file(unbound_conf)
        if unbound_snap[0] is None:
            return False
        split_snap = _snapshot_file(split_conf)
        split_unbound_snap = _snapshot_file(split_unbound_conf)
        parsed = parse_split_dns(split_snap[0] or "")
        new_split_unbound = render_unbound_split_dns(parsed["domains"], parsed["upstreams"])
        new_unbound = _ensure_split_include(unbound_snap[0], split_unbound_conf)
        if split_unbound_snap[0] == new_split_unbound and unbound_snap[0] == new_unbound:
            return True
        valid, detail = _validate_split_candidate(new_unbound, new_split_unbound, unbound_conf, split_unbound_conf)
        if not valid:
            raise ValueError(f"Unbound Split-DNS validation failed: {detail}")
        atomic_write_text(
            split_unbound_conf,
            new_split_unbound,
            mode=split_unbound_snap[1] or 0o644,
            preserve_metadata=(split_unbound_snap[1] is not None),
        )
        atomic_write_text(
            unbound_conf,
            new_unbound,
            mode=unbound_snap[1] or 0o644,
            preserve_metadata=True,
        )
        if not reload_service:
            return True
        if check_running_for_reload and not run(["service", "unbound", "onestatus"], timeout=10).ok:
            return True
        reload_result = run(["service", "unbound", "reload"], timeout=20)
        if not reload_result.ok:
            reload_result = run(["service", "unbound", "restart"], timeout=30)
        if reload_result.ok:
            return True
        _restore_file_state(split_unbound_conf, split_unbound_snap, 0o644)
        _restore_file_state(unbound_conf, unbound_snap, 0o644)
        run(["service", "unbound", "restart"], timeout=30)
        return False


def set_split_dns(domains_value: object, upstreams_value: object = None) -> tuple[int, dict[str, Any]]:
    """Validate and apply targeted Split-DNS configuration atomically."""
    try:
        domains = _normalize_split_domains(domains_value)
    except ValueError as exc:
        return 400, {"error": str(exc)}
    upstreams, error = _normalize_split_upstreams(upstreams_value)
    if upstreams is None:
        return 400, {"error": error}

    unbound_conf = paths.UNBOUND_CONF
    split_conf = paths.SPLIT_DNS_CONF
    split_unbound_conf = paths.UNBOUND_SPLIT_DNS_CONF
    lock_path = unbound_conf.with_suffix(unbound_conf.suffix + ".gatebsd.lock")
    try:
        with _unbound_lock(lock_path):
            unbound_snap = _snapshot_file(unbound_conf)
            if unbound_snap[0] is None:
                return 500, {"error": f"Unbound configuration not found: {unbound_conf}"}
            split_snap = _snapshot_file(split_conf)
            split_unbound_snap = _snapshot_file(split_unbound_conf)
            new_conf = render_split_dns_conf(domains, upstreams)
            new_split_unbound = render_unbound_split_dns(domains, upstreams)
            new_unbound = _ensure_split_include(unbound_snap[0], split_unbound_conf)
            if (
                split_snap[0] == new_conf
                and split_unbound_snap[0] == new_split_unbound
                and unbound_snap[0] == new_unbound
            ):
                return 200, {"ok": True, "changed": False, **get_split_dns()}

            valid, detail = _validate_split_candidate(new_unbound, new_split_unbound, unbound_conf, split_unbound_conf)
            if not valid:
                return 400, {"error": "Unbound Split-DNS validation failed", "detail": detail}

            to_backup = [p for p in (split_conf, split_unbound_conf, unbound_conf) if p.exists()]
            backup_meta = backup.backup_files(to_backup, reason="dns-split")
            split_conf.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(
                split_conf,
                new_conf,
                mode=split_snap[1] or 0o600,
                preserve_metadata=(split_snap[1] is not None),
            )
            atomic_write_text(
                split_unbound_conf,
                new_split_unbound,
                mode=split_unbound_snap[1] or 0o644,
                preserve_metadata=(split_unbound_snap[1] is not None),
            )
            atomic_write_text(
                unbound_conf,
                new_unbound,
                mode=unbound_snap[1] or 0o644,
                preserve_metadata=True,
            )

            reload_result = run(["service", "unbound", "reload"], timeout=20)
            if not reload_result.ok:
                reload_result = run(["service", "unbound", "restart"], timeout=30)
            if reload_result.ok:
                return 200, {"ok": True, "changed": True, **get_split_dns(), "backup": backup_meta}

            _restore_file_state(split_conf, split_snap, 0o600)
            _restore_file_state(split_unbound_conf, split_unbound_snap, 0o644)
            _restore_file_state(unbound_conf, unbound_snap, 0o644)
            rollback = run(["service", "unbound", "restart"], timeout=30)
            return 500, {
                "error": "Unbound failed to load Split-DNS configuration; previous configuration restored",
                "detail": reload_result.stderr or reload_result.stdout or reload_result.error or "",
                "rolled_back": rollback.ok,
                "backup": backup_meta,
            }
    except (OSError, UnicodeError, ValueError) as exc:
        return 500, {"error": f"failed to update Split-DNS: {exc}"}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "--sync-split-dns":
        if_running = "--if-running" in args[1:]
        try:
            ok = sync_split_dns(reload_service=True, check_running_for_reload=if_running)
            return 0 if ok else 1
        except (OSError, UnicodeError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    print("usage: python3 -m gatebsd_ui.writers.dns --sync-split-dns [--if-running]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
