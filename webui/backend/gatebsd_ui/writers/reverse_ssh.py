from __future__ import annotations

import base64
import ipaddress
import json
import os
import pwd
import re
from pathlib import Path
from typing import Any

from ..command import run
from ..fsutil import atomic_write_text, exclusive_lock, read_regular_text
from .port_forward import LAN_NET, _ipv4, _port

CONFIG_PATH = Path(os.environ.get("GATEBSD_REVERSE_SSH_CONFIG", "/usr/local/etc/gatebsd/reverse-ssh.json"))
KEY_DIR = Path(os.environ.get("GATEBSD_REVERSE_SSH_KEY_DIR", "/usr/local/etc/gatebsd/reverse-ssh-keys"))
RUN_DIR = Path(os.environ.get("GATEBSD_REVERSE_SSH_RUN_DIR", "/var/run/gatebsd/reverse-ssh"))
LOG_FILE = Path(os.environ.get("GATEBSD_REVERSE_SSH_LOG", "/var/log/gatebsd-reverse-ssh.log"))
_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_USER_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")


def _remote_host(value: object) -> str:
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("remote_host must be an IPv4 address or DNS hostname")
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        pass
    if _HOST_RE.fullmatch(value) is None or ".." in value:
        raise ValueError("remote_host must be an IPv4 address or DNS hostname")
    labels = value.split(".")
    if any(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) is None for label in labels):
        raise ValueError("remote_host must be an IPv4 address or DNS hostname")
    return value.lower()


def _host_key(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("host_key must contain an SSH public key")
    fields = value.strip().split()
    if len(fields) != 2 or fields[0] not in ("ssh-ed25519", "ecdsa-sha2-nistp256"):
        raise ValueError("host_key must be an ed25519 or nistp256 public key")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("host_key contains invalid base64") from exc
    if len(decoded) < 32:
        raise ValueError("host_key is too short")
    return f"{fields[0]} {fields[1]}"


def validate_rule(rule: object) -> dict[str, Any]:
    if not isinstance(rule, dict):
        raise ValueError("rule must be an object")
    identifier = rule.get("id")
    if not isinstance(identifier, str) or _ID_RE.fullmatch(identifier) is None:
        raise ValueError("invalid reverse SSH rule id")
    enabled = rule.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be boolean")
    remote_user = rule.get("remote_user")
    if not isinstance(remote_user, str) or _USER_RE.fullmatch(remote_user) is None or remote_user == "root":
        raise ValueError("remote_user must be a separate unprivileged account")
    remote_bind = _ipv4(rule.get("remote_bind_address", "127.0.0.1"), "remote_bind_address")
    allow_public = rule.get("allow_public", False)
    if not isinstance(allow_public, bool):
        raise ValueError("allow_public must be boolean")
    if not ipaddress.IPv4Address(remote_bind).is_loopback and not allow_public:
        raise ValueError("public bind requires allow_public=true")
    target_host = _ipv4(rule.get("target_host"), "target_host")
    network = ipaddress.IPv4Network(LAN_NET)
    target = ipaddress.IPv4Address(target_host)
    if target not in network or target in (network.network_address, network.broadcast_address):
        raise ValueError(f"target_host must belong to LAN {network}")
    return {
        "id": identifier,
        "enabled": enabled,
        "remote_host": _remote_host(rule.get("remote_host")),
        "remote_port": _port(rule.get("remote_port", 22), "remote_port"),
        "remote_user": remote_user,
        "remote_bind_address": remote_bind,
        "allow_public": allow_public,
        "external_port": _port(rule.get("external_port"), "external_port"),
        "target_host": target_host,
        "target_port": _port(rule.get("target_port"), "target_port"),
        "host_key": _host_key(rule.get("host_key")),
    }


def validate_rules(rules: object) -> list[dict[str, Any]]:
    if not isinstance(rules, list) or len(rules) > 64:
        raise ValueError("rules must be a list containing at most 64 entries")
    normalized = [validate_rule(rule) for rule in rules]
    ids: set[str] = set()
    endpoints: set[tuple[str, int, str, int]] = set()
    for rule in normalized:
        endpoint = (rule["remote_host"], rule["remote_port"], rule["remote_bind_address"], rule["external_port"])
        if rule["id"] in ids:
            raise ValueError(f"duplicate rule id: {rule['id']}")
        if endpoint in endpoints:
            raise ValueError("remote protocol and port are already used by another rule")
        ids.add(rule["id"])
        endpoints.add(endpoint)
    return normalized


def known_hosts_line(rule: object) -> str:
    normalized = validate_rule(rule)
    host = normalized["remote_host"]
    if normalized["remote_port"] != 22:
        host = f"[{host}]:{normalized['remote_port']}"
    return f"{host} {normalized['host_key']}"


def ssh_arguments(rule: object, identity: str, known_hosts: str) -> list[str]:
    normalized = validate_rule(rule)
    return [
        "/usr/bin/ssh", "-N", "-T",
        "-R", f"{normalized['remote_bind_address']}:{normalized['external_port']}:{normalized['target_host']}:{normalized['target_port']}",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "IdentitiesOnly=yes",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "PermitLocalCommand=no",
        "-i", identity,
        "-p", str(normalized["remote_port"]),
        f"{normalized['remote_user']}@{normalized['remote_host']}",
    ]


def _load_rules() -> list[dict[str, Any]]:
    try:
        text, _metadata = read_regular_text(CONFIG_PATH, max_size=1024 * 1024, errors="strict")
    except FileNotFoundError:
        return []
    record = json.loads(text)
    if not isinstance(record, dict) or record.get("version") != 1:
        raise ValueError("unsupported reverse SSH configuration")
    return validate_rules(record.get("rules"))


def _identity(identifier: str) -> str:
    return str(KEY_DIR / f"{identifier}.key")


def _known_hosts_path(identifier: str) -> str:
    return str(KEY_DIR / f"{identifier}.known_hosts")


def _supervisor_pidfile(identifier: str) -> Path:
    return RUN_DIR / f"{identifier}.supervisor.pid"


def _child_pidfile(identifier: str) -> Path:
    return RUN_DIR / f"{identifier}.pid"


def _pid_running(identifier: str) -> bool:
    path = _supervisor_pidfile(identifier)
    try:
        text, _metadata = read_regular_text(path, max_size=32, errors="strict")
        pid = int(text.strip())
    except (FileNotFoundError, OSError, UnicodeError, ValueError):
        return False
    if pid <= 1:
        return False
    result = run(["ps", "-p", str(pid), "-o", "command="], timeout=3)
    return result.ok and "daemon:" in result.stdout and _identity(identifier) in result.stdout


def start() -> dict[str, Any]:
    started: list[str] = []
    errors: dict[str, str] = {}
    RUN_DIR.mkdir(parents=True, exist_ok=True, mode=0o750)
    for rule in _load_rules():
        if not rule["enabled"] or _pid_running(rule["id"]):
            continue
        supervisor = _supervisor_pidfile(rule["id"])
        child = _child_pidfile(rule["id"])
        supervisor.unlink(missing_ok=True)
        child.unlink(missing_ok=True)
        command = [
            "/usr/sbin/daemon", "-u", "gatebsd-forward", "-r", "-R", "5",
            "-P", str(supervisor), "-p", str(child), "-o", str(LOG_FILE),
            *ssh_arguments(rule, _identity(rule["id"]), _known_hosts_path(rule["id"])),
        ]
        result = run(command, timeout=10)
        if result.ok:
            started.append(rule["id"])
        else:
            errors[rule["id"]] = result.stderr or result.stdout or result.error or "daemon failed"
    return {"started": started, "errors": errors}


def _supervisor_pid(identifier: str) -> int | None:
    try:
        text, _metadata = read_regular_text(_supervisor_pidfile(identifier), max_size=32, errors="strict")
        pid = int(text.strip())
    except (FileNotFoundError, OSError, UnicodeError, ValueError):
        return None
    return pid if pid > 1 else None


def stop() -> dict[str, Any]:
    stopped: list[str] = []
    errors: dict[str, str] = {}
    configured = {rule["id"] for rule in _load_rules()}
    orphaned = {
        path.name.removesuffix(".supervisor.pid")
        for path in RUN_DIR.glob("*.supervisor.pid")
    }
    for identifier in sorted(configured | orphaned):
        if _ID_RE.fullmatch(identifier) is None:
            continue
        pid = _supervisor_pid(identifier)
        if pid is not None and _pid_running(identifier):
            result = run(["kill", "-TERM", str(pid)], timeout=3)
            if result.ok:
                stopped.append(identifier)
            else:
                errors[identifier] = result.stderr or result.stdout or result.error or "kill failed"
        _supervisor_pidfile(identifier).unlink(missing_ok=True)
        _child_pidfile(identifier).unlink(missing_ok=True)
    return {"stopped": stopped, "errors": errors}


def status() -> dict[str, Any]:
    return {
        "rules": [
            {"id": rule["id"], "enabled": rule["enabled"], "running": _pid_running(rule["id"])}
            for rule in _load_rules()
        ]
    }


def _chown_forward(path: Path) -> None:
    account = pwd.getpwnam("gatebsd-forward")
    os.chown(path, account.pw_uid, account.pw_gid)


def _safe_private_directory(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise OSError(f"unsafe reverse SSH directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o750)
    if path.is_symlink():
        raise OSError(f"unsafe reverse SSH directory: {path}")


def _fingerprint(identifier: str) -> str:
    result = run(["ssh-keygen", "-l", "-f", _known_hosts_path(identifier)], timeout=5)
    fields = result.stdout.split()
    if not result.ok or len(fields) < 2:
        raise ValueError(result.stderr or result.stdout or result.error or "ssh-keygen rejected known_hosts")
    return fields[1]


def _ensure_material(rule: dict[str, Any]) -> None:
    _safe_private_directory(KEY_DIR)
    identifier = rule["id"]
    identity = Path(_identity(identifier))
    if identity.is_symlink():
        raise OSError("reverse SSH identity must not be a symlink")
    if not identity.exists():
        result = run([
            "ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(identity),
        ], timeout=15)
        if not result.ok:
            raise OSError(result.stderr or result.stdout or result.error or "ssh-keygen failed")
    if not identity.is_file() or identity.is_symlink():
        raise OSError("reverse SSH identity is not a regular file")
    identity.chmod(0o600)
    _chown_forward(identity)
    public = Path(f"{identity}.pub")
    if public.exists():
        public.chmod(0o644)
    known_hosts = Path(_known_hosts_path(identifier))
    atomic_write_text(known_hosts, known_hosts_line(rule) + "\n", mode=0o600)
    _chown_forward(known_hosts)
    _fingerprint(identifier)


def _public_material(rule: dict[str, Any]) -> dict[str, str]:
    public_path = Path(f"{_identity(rule['id'])}.pub")
    text, _metadata = read_regular_text(public_path, max_size=64 * 1024, errors="strict")
    fields = text.strip().split()
    if len(fields) < 2:
        raise ValueError("invalid generated public key")
    public_key = f"{fields[0]} {fields[1]}"
    hint = (
        f'no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc,'
        f'permitlisten="{rule["remote_bind_address"]}:{rule["external_port"]}" '
        f'{public_key} gatebsd-{rule["id"]}'
    )
    return {
        "public_key": public_key,
        "authorized_keys_hint": hint,
        "host_key_fingerprint": _fingerprint(rule["id"]),
    }


def _config_text() -> str | None:
    try:
        text, _metadata = read_regular_text(CONFIG_PATH, max_size=1024 * 1024, errors="strict")
        return text
    except FileNotFoundError:
        return None


def _write_config(rules: list[dict[str, Any]]) -> None:
    _safe_private_directory(CONFIG_PATH.parent)
    atomic_write_text(
        CONFIG_PATH,
        json.dumps({"version": 1, "rules": rules}, ensure_ascii=False, indent=2) + "\n",
        mode=0o600,
    )


def _restore_config(previous: str | None) -> None:
    if previous is None:
        CONFIG_PATH.unlink(missing_ok=True)
    else:
        atomic_write_text(CONFIG_PATH, previous, mode=0o600)


def _restart_service():
    return run(["service", "gatebsd_reverse_ssh", "restart"], timeout=45)


def save_config(rule: object) -> tuple[int, dict[str, Any]]:
    lock_path = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".gatebsd.lock")
    with exclusive_lock(lock_path):
        previous = _config_text()
        try:
            normalized = validate_rule(rule)
            existing = _load_rules()
            replaced = False
            updated = []
            for item in existing:
                if item["id"] == normalized["id"]:
                    updated.append(normalized)
                    replaced = True
                else:
                    updated.append(item)
            if not replaced:
                updated.append(normalized)
            validate_rules(updated)
            _ensure_material(normalized)
            _write_config(updated)
            restarted = _restart_service()
            if not restarted.ok:
                _restore_config(previous)
                rollback = _restart_service()
                return 500, {
                    "error": restarted.stderr or restarted.stdout or restarted.error or "reverse SSH restart failed",
                    "rolled_back": rollback.ok,
                }
            return 200, {"ok": True, "rule": normalized, **_public_material(normalized)}
        except ValueError as exc:
            return 400, {"error": str(exc)}
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            return 500, {"error": f"failed to save reverse SSH rule: {exc}"}


def list_config() -> tuple[int, dict[str, Any]]:
    try:
        rules = []
        for rule in _load_rules():
            item = {**rule, "running": _pid_running(rule["id"])}
            try:
                item.update(_public_material(rule))
            except FileNotFoundError:
                pass
            rules.append(item)
        return 200, {"rules": rules}
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return 500, {"error": f"failed to read reverse SSH rules: {exc}"}


def delete_config(identifier: object) -> tuple[int, dict[str, Any]]:
    lock_path = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".gatebsd.lock")
    with exclusive_lock(lock_path):
        previous = _config_text()
        try:
            if not isinstance(identifier, str):
                raise ValueError("invalid rule id")
            existing = _load_rules()
            updated = [item for item in existing if item["id"] != identifier]
            if len(updated) == len(existing):
                return 404, {"error": "reverse SSH rule not found"}
            _write_config(updated)
            restarted = _restart_service()
            if not restarted.ok:
                _restore_config(previous)
                rollback = _restart_service()
                return 500, {"error": restarted.stderr or restarted.error or "restart failed", "rolled_back": rollback.ok}
            for suffix in (".key", ".key.pub", ".known_hosts"):
                (KEY_DIR / f"{identifier}{suffix}").unlink(missing_ok=True)
            return 200, {"ok": True, "deleted": identifier}
        except ValueError as exc:
            return 400, {"error": str(exc)}
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            return 500, {"error": f"failed to delete reverse SSH rule: {exc}"}


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="gatebsd-reverse-ssh")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name in ("start", "stop", "status"):
        subcommands.add_parser(name)
    args = parser.parse_args(argv)
    payload = {"start": start, "stop": stop, "status": status}[args.command]()
    print(json.dumps(payload, ensure_ascii=False))
    if payload.get("errors"):
        return 1
    if args.command == "status" and any(rule["enabled"] and not rule["running"] for rule in payload["rules"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
