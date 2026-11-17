"""Version-neutral DNS resolution used by GateBSD services and tools."""
from __future__ import annotations

import codecs
import encodings.idna
import ipaddress
import json
import random
import re
import socket
import struct
import sys
from pathlib import Path

from .fsutil import atomic_write_text, read_regular_text

_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_DOMAIN_TLD_RE = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _encode_idna_labels(host: str) -> str | None:
    if not host or any(ch.isspace() for ch in host) or any(ch in host for ch in ("/", ":", "*", "_")):
        return None
    if host.endswith(".."):
        return None
    clean = host.rstrip(".")
    if not clean:
        return None
    labels = clean.split(".")
    if not labels or "" in labels:
        return None
    ascii_labels: list[str] = []
    for label in labels:
        if label.isascii():
            ascii_label = label.lower()
        else:
            try:
                ascii_label = encodings.idna.ToASCII(label).decode("ascii").lower()
            except (UnicodeError, ValueError):
                return None
        if not _HOST_RE.fullmatch(ascii_label):
            return None
        ascii_labels.append(ascii_label)
    ascii_host = ".".join(ascii_labels)
    if not ascii_host or len(ascii_host) > 253 or ascii_host.startswith("-"):
        return None
    return ascii_host


def normalize_host(value: object) -> str | None:
    """Return a safe IP address or ASCII/IDNA punycode DNS hostname."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or raw.endswith(".."):
        return None
    host = raw.rstrip(".")
    if not host or len(host) > 253 or host.startswith("-"):
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return _encode_idna_labels(raw)


def normalize_domain(value: object, *, require_multi_label: bool = True) -> str | None:
    """Return a canonical lowercase ASCII/IDNA punycode domain name."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        ipaddress.ip_address(raw.rstrip("."))
        return None
    except ValueError:
        pass
    ascii_host = _encode_idna_labels(raw)
    if ascii_host is None:
        return None
    labels = ascii_host.split(".")
    if require_multi_label and len(labels) < 2:
        return None
    if not _DOMAIN_TLD_RE.fullmatch(labels[-1]):
        return None
    return ascii_host


def display_host(value: object) -> str:
    """Decode punycode labels to Unicode for display; keep ASCII/IP/CIDR unchanged."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or "/" in text:
        return text
    try:
        ipaddress.ip_address(text.rstrip("."))
        return text
    except ValueError:
        pass
    decoded: list[str] = []
    for label in text.split("."):
        if label.lower().startswith("xn--"):
            try:
                decoded.append(encodings.idna.ToUnicode(label))
                continue
            except (UnicodeError, ValueError):
                pass
        decoded.append(label)
    return ".".join(decoded)


def normalize_adblock_extra(text: str) -> str:
    """Normalize IDN hostnames inside hosts/ABP extra rules to lowercase punycode."""
    lines: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "!")):
            lines.append(raw)
            continue
        if stripped.startswith("@@||") and stripped.endswith("^"):
            domain = normalize_domain(stripped[4:-1])
            lines.append(f"@@||{domain}^" if domain else raw)
            continue
        if stripped.startswith("||") and stripped.endswith("^"):
            domain = normalize_domain(stripped[2:-1])
            lines.append(f"||{domain}^" if domain else raw)
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1"}:
            out_tokens = [parts[0]]
            changed = False
            for idx, token in enumerate(parts[1:], start=1):
                if token.startswith("#"):
                    out_tokens.extend(parts[idx:])
                    break
                domain = normalize_domain(token)
                if domain is not None:
                    out_tokens.append(domain)
                    changed = True
                else:
                    out_tokens.append(token)
            lines.append(" ".join(out_tokens) if changed else raw)
            continue
        lines.append(raw)
    return ("\n".join(lines) + "\n") if lines else ""


def resolve_ipv4(value: object) -> list[str]:
    """Resolve a validated host through the operating-system resolver."""
    host = normalize_host(value)
    if host is None:
        return []
    try:
        return [str(ipaddress.IPv4Address(host))]
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(host)
            return []
        except ipaddress.AddressValueError:
            pass

    addresses: list[str] = []
    try:
        results = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return []
    for result in results:
        address = result[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


def _dns_name(host: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in host.split(".")) + b"\0"


def _skip_dns_name(packet: bytes, offset: int) -> int:
    """Return the first byte after a possibly compressed DNS name."""
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            return offset + 2
        if length & 0xC0:
            raise ValueError("invalid DNS label")
        offset += 1 + length
    raise ValueError("truncated DNS name")


def resolve_ipv4_via_server(value: object, server: object, timeout: float = 3.0) -> list[str]:
    """Resolve an A record directly through one validated IPv4 DNS server."""
    host = normalize_host(value)
    try:
        nameserver = str(ipaddress.IPv4Address(str(server)))
    except ipaddress.AddressValueError:
        return []
    if host is None:
        return []
    try:
        return [str(ipaddress.IPv4Address(host))]
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(host)
            return []
        except ipaddress.AddressValueError:
            pass

    query_id = random.SystemRandom().randrange(0, 65536)
    query = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + _dns_name(host) + struct.pack("!HH", 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (nameserver, 53))
            packet, peer = sock.recvfrom(4096)
    except (OSError, socket.timeout):
        return []
    if peer != (nameserver, 53) or len(packet) < 12:
        return []
    response_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if response_id != query_id or not flags & 0x8000 or flags & 0x7800 or flags & 0x0200 or flags & 0x000F or qdcount != 1:
        return []
    try:
        offset = 12
        for _ in range(qdcount):
            offset = _skip_dns_name(packet, offset)
            if offset + 4 > len(packet):
                return []
            offset += 4
        addresses: list[str] = []
        for _ in range(ancount):
            offset = _skip_dns_name(packet, offset)
            if offset + 10 > len(packet):
                return []
            record_type, record_class, _ttl, data_len = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            if offset + data_len > len(packet):
                return []
            data = packet[offset:offset + data_len]
            offset += data_len
            if record_type == 1 and record_class == 1 and data_len == 4:
                address = socket.inet_ntoa(data)
                if address not in addresses:
                    addresses.append(address)
        return addresses
    except (ValueError, struct.error, OSError):
        return []


def _filter_ipv4(addresses: object) -> list[str]:
    """Return unique valid IPv4 string addresses from an iterable/list."""
    if not isinstance(addresses, list):
        return []
    result: list[str] = []
    for item in addresses:
        try:
            ip = str(ipaddress.IPv4Address(str(item)))
        except ipaddress.AddressValueError:
            continue
        if ip not in result:
            result.append(ip)
    return result


def _read_endpoint_cache(cache_path: Path) -> dict[str, list[str]]:
    """Read cached endpoint IPv4 addresses without following symlinks."""
    if cache_path.is_symlink():
        return {}
    try:
        raw, _ = read_regular_text(cache_path)
        payload = json.loads(raw)
    except (OSError, UnicodeDecodeError, ValueError, TypeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    entries: dict[str, list[str]] = {}
    for key, value in payload.items():
        normalized = normalize_host(key)
        if normalized is None:
            continue
        ips = _filter_ipv4(value)
        if ips:
            entries[normalized] = ips
    return entries


def _write_endpoint_cache(cache_path: Path, host: str, addresses: list[str]) -> None:
    """Persist live-resolved endpoint IPv4 addresses atomically with mode 0600."""
    ips = _filter_ipv4(addresses)
    if not ips or cache_path.is_symlink():
        return
    entries = _read_endpoint_cache(cache_path)
    entries[host] = ips
    try:
        atomic_write_text(
            cache_path,
            json.dumps(entries, sort_keys=True) + "\n",
            mode=0o600,
            preserve_metadata=False,
        )
    except OSError:
        return


def _parse_resolve_args(args: list[str]) -> tuple[list[str], bool, Path | None, str] | None:
    """Parse CLI arguments for endpoint resolution."""
    servers: list[str] = []
    os_fallback = False
    cache_file: Path | None = None
    positionals: list[str] = []
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--server":
            if idx + 1 >= len(args):
                return None
            servers.append(args[idx + 1])
            idx += 2
        elif arg == "--os-fallback":
            os_fallback = True
            idx += 1
        elif arg == "--cache-file":
            if idx + 1 >= len(args):
                return None
            cache_file = Path(args[idx + 1])
            idx += 2
        elif arg.startswith("-"):
            return None
        else:
            positionals.append(arg)
            idx += 1
    if len(positionals) != 1:
        return None
    return servers, os_fallback, cache_file, positionals[0]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "--normalize-adblock-extra":
        text = Path(args[1]).read_text(encoding="utf-8", errors="replace")
        codecs.getwriter("utf-8")(sys.stdout.buffer).write(normalize_adblock_extra(text))
        return 0
    parsed = _parse_resolve_args(args)
    if parsed is None:
        print(
            "usage: gatebsd-resolve [--server IPV4]... [--os-fallback] [--cache-file PATH] HOST",
            file=sys.stderr,
        )
        return 2
    servers, os_fallback, cache_file, host = parsed
    normalized = normalize_host(host)
    if normalized is None:
        print("invalid host", file=sys.stderr)
        return 2
    addresses: list[str] = []
    live_resolved = False
    for server in servers:
        addresses = _filter_ipv4(resolve_ipv4_via_server(normalized, server))
        if addresses:
            live_resolved = True
            break
    if not addresses and (os_fallback or not servers):
        addresses = _filter_ipv4(resolve_ipv4(normalized))
        if addresses:
            live_resolved = True
    if live_resolved and cache_file is not None:
        _write_endpoint_cache(cache_file, normalized, addresses)
    if not addresses and cache_file is not None:
        addresses = _read_endpoint_cache(cache_file).get(normalized, [])
    if not addresses:
        print(f"cannot resolve {normalized}", file=sys.stderr)
        return 1
    print("\n".join(addresses))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
