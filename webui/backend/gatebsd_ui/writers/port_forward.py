from __future__ import annotations

import argparse
import ipaddress
import json
import re
from typing import Any

from ..adapters.helpers import LAN_NET, PF_CONF, WAN_IF
from ..command import run
from ..fsutil import exclusive_lock, read_regular_text
from .firewall import pf_set_conf

_BEGIN = "# GateBSD port-forward: begin "
_PASS_BEGIN = "# GateBSD port-forward-pass: begin "
_END = "# GateBSD port-forward: end "
_PASS_END = "# GateBSD port-forward-pass: end "
_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")


def _managed_error() -> ValueError:
    return ValueError("invalid managed block in pf.conf")


def _ipv4(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an IPv4 address")
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"{label} must be an IPv4 address") from exc


def _port(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a single port")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a single port") from exc
    if isinstance(value, str) and value != str(port):
        raise ValueError(f"{label} must be a single port")
    if not 1 <= port <= 65535:
        raise ValueError(f"{label} must be between 1 and 65535")
    return port


def validate_rule(rule: object) -> dict[str, Any]:
    if not isinstance(rule, dict):
        raise ValueError("rule must be an object")
    identifier = rule.get("id")
    if not isinstance(identifier, str) or _ID_RE.fullmatch(identifier) is None:
        raise ValueError("id must start with a letter and contain only lowercase letters, digits and dashes")
    enabled = rule.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be boolean")
    protocol = rule.get("protocol")
    if protocol not in ("tcp", "udp"):
        raise ValueError("protocol must be tcp or udp")
    target_host = _ipv4(rule.get("target_host"), "target_host")
    network = ipaddress.IPv4Network(LAN_NET)
    target = ipaddress.IPv4Address(target_host)
    if target not in network or target in (network.network_address, network.broadcast_address):
        raise ValueError(f"target_host must belong to LAN {network}")
    raw_sources = rule.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ValueError("source allowlist is required")
    allow_any = rule.get("allow_any_source", False)
    if not isinstance(allow_any, bool):
        raise ValueError("allow_any_source must be boolean")
    sources: list[str] = []
    for raw in raw_sources:
        if not isinstance(raw, str):
            raise ValueError("source allowlist must contain IPv4 addresses or networks")
        try:
            source = ipaddress.IPv4Network(f"{raw}/32" if "/" not in raw else raw, strict=True)
        except ipaddress.AddressValueError as exc:
            raise ValueError("source allowlist must contain IPv4 addresses or networks") from exc
        except ipaddress.NetmaskValueError as exc:
            raise ValueError("source allowlist must contain IPv4 addresses or networks") from exc
        canonical = str(source)
        if canonical not in sources:
            sources.append(canonical)
    if "0.0.0.0/0" in sources:
        if not allow_any:
            raise ValueError("source 0.0.0.0/0 requires allow_any_source=true")
        sources = ["0.0.0.0/0"]
    return {
        "id": identifier,
        "enabled": enabled,
        "protocol": protocol,
        "external_port": _port(rule.get("external_port"), "external_port"),
        "target_host": target_host,
        "target_port": _port(rule.get("target_port"), "target_port"),
        "sources": sources,
        "allow_any_source": allow_any,
    }


def _source_expression(sources: list[str]) -> str:
    if sources == ["0.0.0.0/0"]:
        return "any"
    if len(sources) == 1:
        return sources[0]
    return "{ " + ", ".join(sources) + " }"


def _metadata(rule: dict[str, Any]) -> str:
    return (
        f"id={rule['id']} enabled={'yes' if rule['enabled'] else 'no'} "
        f"protocol={rule['protocol']} external={rule['external_port']} "
        f"target={rule['target_host']}:{rule['target_port']} "
        f"sources={','.join(rule['sources'])}"
    )


def _blocks(rule: dict[str, Any], gateway: str, interface: str) -> tuple[list[str], list[str]]:
    source = _source_expression(rule["sources"])
    rdr = [
        f"{_BEGIN}{_metadata(rule)}",
        "# disabled",
        f"{_END}{rule['id']}",
    ]
    passthrough = [
        f"{_PASS_BEGIN}id={rule['id']}",
        "# disabled",
        f"{_PASS_END}{rule['id']}",
    ]
    if rule["enabled"]:
        rdr[1] = (
            f"rdr on ${interface} proto {rule['protocol']} from {source} "
            f"to (${interface}) port {rule['external_port']} -> "
            f"{rule['target_host']} port {rule['target_port']}"
        )
        passthrough[1] = (
            f"pass in quick on ${interface} reply-to (${interface} {gateway}) "
            f"proto {rule['protocol']} from {source} "
            f"to {rule['target_host']} port {rule['target_port']} keep state"
        )
    return rdr, passthrough


def _block_bounds(lines: list[str], prefix: str, end_prefix: str, identifier: str) -> tuple[int, int] | None:
    begin = next((
        index for index, line in enumerate(lines)
        if line.startswith(prefix)
        and line[len(prefix):].split()
        and line[len(prefix):].split()[0] == f"id={identifier}"
    ), None)
    if begin is None:
        return None
    expected_end = f"{end_prefix}{identifier}"
    end = next((index for index in range(begin + 1, len(lines)) if lines[index] == expected_end), None)
    if end is None:
        raise _managed_error()
    return begin, end


def _remove_block(lines: list[str], prefix: str, end_prefix: str, identifier: str) -> list[str]:
    bounds = _block_bounds(lines, prefix, end_prefix, identifier)
    if bounds is None:
        return lines
    begin, end = bounds
    del lines[begin:end + 1]
    if begin > 0 and lines[begin - 1] == "":
        del lines[begin - 1]
    return lines


def _insert_block(lines: list[str], index: int, block: list[str]) -> None:
    lines[index:index] = ["", *block]


def _rule_from_metadata(text: str) -> dict[str, Any]:
    values: dict[str, str] = {}
    for token in text.split():
        if "=" not in token:
            raise _managed_error()
        key, value = token.split("=", 1)
        values[key] = value
    try:
        enabled = {"yes": True, "no": False}[values["enabled"]]
        target_host, separator, target_port = values["target"].rpartition(":")
        if not separator:
            raise _managed_error()
        sources = values["sources"].split(",")
        return validate_rule({
            "id": values["id"],
            "enabled": enabled,
            "protocol": values["protocol"],
            "external_port": values["external"],
            "target_host": target_host,
            "target_port": target_port,
            "sources": sources,
            "allow_any_source": sources == ["0.0.0.0/0"],
        })
    except (KeyError, ValueError) as exc:
        raise _managed_error() from exc


def parse_rules(conf: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    lines = conf.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith(_BEGIN):
            continue
        rule = _rule_from_metadata(line[len(_BEGIN):])
        if rule["id"] in seen or _block_bounds(lines, _BEGIN, _END, rule["id"]) is None:
            raise _managed_error()
        seen.add(rule["id"])
        rules.append(rule)
    return rules


def remove_rule(conf: str, identifier: str) -> str:
    if not isinstance(identifier, str) or _ID_RE.fullmatch(identifier) is None:
        raise ValueError("invalid rule id")
    parse_rules(conf)
    trailing_newline = conf.endswith("\n")
    lines = conf.splitlines()
    lines = _remove_block(lines, _BEGIN, _END, identifier)
    lines = _remove_block(lines, _PASS_BEGIN, _PASS_END, identifier)
    return "\n".join(lines) + ("\n" if trailing_newline else "")


def upsert_rule(conf: str, rule: object, *, gateway: str, interface: str = "wan_if") -> str:
    normalized = validate_rule(rule)
    gateway = _ipv4(gateway, "gateway")
    if re.fullmatch(r"[a-z_][a-z0-9_]*", interface) is None:
        raise ValueError("invalid WAN macro")
    existing = parse_rules(conf)
    for item in existing:
        if item["id"] != normalized["id"] and (item["protocol"], item["external_port"]) == (normalized["protocol"], normalized["external_port"]):
            raise ValueError("external protocol and port are already used by another rule")
    trailing_newline = conf.endswith("\n")
    lines = conf.splitlines()
    lines = _remove_block(lines, _BEGIN, _END, normalized["id"])
    lines = _remove_block(lines, _PASS_BEGIN, _PASS_END, normalized["id"])
    rdr, passthrough = _blocks(normalized, gateway, interface)
    rdr_indexes = [index for index, line in enumerate(lines) if line.startswith("rdr ")]
    if not rdr_indexes:
        raise ValueError("pf.conf has no translation section")
    _insert_block(lines, rdr_indexes[-1] + 1, rdr)
    block_indexes = [index for index, line in enumerate(lines) if line == "block in all"]
    if len(block_indexes) != 1:
        raise ValueError("pf.conf must contain exactly one 'block in all' anchor")
    _insert_block(lines, block_indexes[0] + 1, passthrough)
    return "\n".join(lines) + ("\n" if trailing_newline else "")


def reconcile_gateway(conf: str, *, gateway: str, interface: str = "wan_if") -> str:
    gateway = _ipv4(gateway, "gateway")
    rules = parse_rules(conf)
    trailing_newline = conf.endswith("\n")
    lines = conf.splitlines()
    for rule in rules:
        bounds = _block_bounds(lines, _PASS_BEGIN, _PASS_END, rule["id"])
        if bounds is None:
            raise _managed_error()
        begin, end = bounds
        _rdr, replacement = _blocks(rule, gateway, interface)
        lines[begin:end + 1] = replacement
    return "\n".join(lines) + ("\n" if trailing_newline else "")


def _read_conf() -> str:
    content, _metadata = read_regular_text(PF_CONF, max_size=2 * 1024 * 1024, errors="strict")
    return content


def _current_wan_gateway() -> str:
    result = run(["ifconfig", WAN_IF, "inet"], timeout=5)
    if not result.ok:
        raise ValueError(f"cannot read the gateway of {WAN_IF}")
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == "inet" and fields[2] == "-->":
            return _ipv4(fields[3], "gateway")
    raise ValueError(f"no point-to-point IPv4 gateway is available on {WAN_IF}")


def _apply(transform, *, require_confirmation: bool = True) -> tuple[int, dict[str, Any]]:
    lock_path = PF_CONF.with_suffix(PF_CONF.suffix + ".gatebsd.lock")
    with exclusive_lock(lock_path):
        candidate = transform(_read_conf())
        return pf_set_conf(
            candidate,
            require_confirmation=require_confirmation,
            lock_held=True,
        )


def list_rules() -> tuple[int, dict[str, Any]]:
    try:
        return 200, {
            "rules": parse_rules(_read_conf()),
            "lan_net": LAN_NET,
            "wan_if": WAN_IF,
            "gateway": _current_wan_gateway(),
        }
    except ValueError as exc:
        return 409, {"error": str(exc)}
    except (OSError, UnicodeError) as exc:
        return 500, {"error": f"failed to read port forwards: {exc}"}


def save_rule(rule: object) -> tuple[int, dict[str, Any]]:
    try:
        normalized = validate_rule(rule)
        gateway = _current_wan_gateway()
        status, payload = _apply(lambda conf: upsert_rule(conf, normalized, gateway=gateway))
        if status == 200:
            payload["rule"] = normalized
        return status, payload
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except (OSError, UnicodeError) as exc:
        return 500, {"error": f"failed to save port forward: {exc}"}


def delete_rule(identifier: object) -> tuple[int, dict[str, Any]]:
    try:
        if not isinstance(identifier, str):
            raise ValueError("invalid rule id")
        def remove(conf: str) -> str:
            if identifier not in {item["id"] for item in parse_rules(conf)}:
                raise KeyError(identifier)
            return remove_rule(conf, identifier)
        return _apply(remove)
    except KeyError:
        return 404, {"error": "port forward not found"}
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except (OSError, UnicodeError) as exc:
        return 500, {"error": f"failed to delete port forward: {exc}"}


def test_rule(identifier: object) -> tuple[int, dict[str, Any]]:
    try:
        if not isinstance(identifier, str):
            raise ValueError("invalid rule id")
        rule = next((item for item in parse_rules(_read_conf()) if item["id"] == identifier), None)
        if rule is None:
            return 404, {"error": "port forward not found"}
        if not rule["enabled"]:
            return 200, {"ok": False, "scope": "lan-target", "error": "rule is disabled"}
        command = ["nc"]
        if rule["protocol"] == "udp":
            command.append("-u")
        command.extend(["-z", "-w", "3", rule["target_host"], str(rule["target_port"])])
        result = run(command, timeout=5)
        return 200, {
            "ok": result.ok,
            "scope": "lan-target",
            "protocol": rule["protocol"],
            "target": f"{rule['target_host']}:{rule['target_port']}",
            "detail": result.stderr or result.stdout or result.error or "",
        }
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except (OSError, UnicodeError) as exc:
        return 500, {"error": f"failed to test port forward: {exc}"}


def apply_gateway(gateway: object) -> tuple[int, dict[str, Any]]:
    try:
        normalized = _ipv4(gateway, "gateway")
        def reconcile(conf: str) -> str:
            if not parse_rules(conf):
                raise LookupError("no port forwards")
            return reconcile_gateway(conf, gateway=normalized)
        try:
            return _apply(reconcile, require_confirmation=False)
        except LookupError:
            return 200, {"ok": True, "changed": False, "rules": 0}
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except (OSError, UnicodeError) as exc:
        return 500, {"error": f"failed to reconcile port forwards: {exc}"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gatebsd-port-forward")
    subcommands = parser.add_subparsers(dest="command", required=True)
    reconcile = subcommands.add_parser("reconcile")
    reconcile.add_argument("--gateway", required=True)
    args = parser.parse_args(argv)
    if args.command == "reconcile":
        status, payload = apply_gateway(args.gateway)
    else:
        return 2
    print(json.dumps(payload, ensure_ascii=False))
    return 0 if status == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
