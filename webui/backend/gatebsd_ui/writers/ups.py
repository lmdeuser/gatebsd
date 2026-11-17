"""NUT configuration and UPS instant-command operations."""
from __future__ import annotations

import ipaddress
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any

from .. import backup, paths, storage
from ..command import run
from ..fsutil import atomic_write_bytes, atomic_write_text, exclusive_lock


NUT_DIR = paths.NUT_DIR
NUT_CONF = paths.NUT_CONF
UPS_CONF = paths.UPS_CONF
UPSD_CONF = paths.UPSD_CONF
UPSD_USERS = paths.UPSD_USERS
UPSMON_CONF = paths.UPSMON_CONF
NUT_FILES = (NUT_CONF, UPS_CONF, UPSD_CONF, UPSD_USERS, UPSMON_CONF)
NUT_CONFIG_LOCK = paths.NUT_CONFIG_LOCK

ALLOWED_COMMANDS = {
    "beeper.enable", "beeper.disable", "beeper.toggle",
    "test.battery.start.quick",
    "test.battery.stop", "driver.reload", "driver.reload-or-error",
    "load.on", "shutdown.stop",
}
DANGEROUS_COMMANDS: set[str] = set()


def _text(path: Path) -> str:
    try:
        data, _metadata = backup._read_regular_bytes(path)
        return data.decode("utf-8", errors="strict")
    except (FileNotFoundError, OSError, UnicodeError):
        return ""


def _sections(text: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        match = re.fullmatch(r"\[([A-Za-z0-9_.-]+)\]", line)
        if match:
            current = match.group(1)
            result.setdefault(current, {})
            continue
        if current and line and not line.startswith("#"):
            if "=" in line:
                key, value = line.split("=", 1)
                normalized = key.strip().lower()
                parsed = value.strip().strip('"')
                if normalized in result[current]:
                    result[current][normalized] += "," + parsed
                else:
                    result[current][normalized] = parsed
            elif line.lower().startswith("upsmon "):
                result[current]["upsmon"] = line.split(None, 1)[1].strip()
            else:
                result[current][line.lower()] = "true"
    return result


def _ups_values() -> tuple[str, dict[str, str]]:
    sections = _sections(_text(UPS_CONF))
    if not sections:
        return "", {}
    monitor_target, _, _ = _monitor_values()
    monitor_name = monitor_target.split("@", 1)[0]
    name = monitor_name if monitor_name in sections else next(iter(sections))
    return name, sections[name]


def _user_values() -> dict[str, dict[str, str]]:
    return _sections(_text(UPSD_USERS))


def _monitor_values() -> tuple[str, str, str]:
    for raw in _text(UPSMON_CONF).splitlines():
        parts = raw.strip().split()
        if len(parts) >= 6 and parts[0].upper() == "MONITOR":
            return parts[1], parts[3], parts[4]
    return "", "", ""


def ups_config() -> dict[str, Any]:
    name, values = _ups_values()
    users = _user_values()
    monitor_target, monitor_user, _ = _monitor_values()
    mode_match = re.search(r"^\s*MODE\s*=\s*(\S+)", _text(NUT_CONF), re.MULTILINE)
    listeners = []
    for raw in _text(UPSD_CONF).splitlines():
        parts = raw.strip().split()
        if len(parts) >= 3 and parts[0].upper() == "LISTEN":
            listeners.append({"address": parts[1], "port": int(parts[2]) if parts[2].isdigit() else 3493})
    master_user = monitor_user or next((u for u, v in users.items() if v.get("upsmon") in {"primary", "master"}), "")
    client_user = next((u for u, v in users.items() if v.get("upsmon") in {"secondary", "slave"}), "")
    command_users = [name for name, values in users.items() if _permitted_commands(values)]
    return {
        "name": name,
        "target": monitor_target or (f"{name}@localhost" if name else ""),
        "driver": values.get("driver", ""),
        "port": values.get("port", ""),
        "description": values.get("desc", ""),
        "mode": mode_match.group(1) if mode_match else "none",
        "listeners": listeners,
        "low_charge": values.get("override.battery.charge.low", ""),
        "low_runtime": values.get("override.battery.runtime.low", ""),
        "offdelay": values.get("offdelay", ""),
        "ondelay": values.get("ondelay", ""),
        "allow_killpower": "allow_killpower" in values,
        "master_user": master_user,
        "client_user": client_user,
        "command_access": bool(command_users),
        "command_user": command_users[0] if command_users else "",
        "nut_enable": run(["sysrc", "-n", "nut_enable"], timeout=3).stdout.strip().upper() == "YES",
        "nut_upsmon_enable": run(["sysrc", "-n", "nut_upsmon_enable"], timeout=3).stdout.strip().upper() == "YES",
        "nut_upsshut": run(["sysrc", "-n", "nut_upsshut"], timeout=3).stdout.strip().upper() == "YES",
        "dir": str(NUT_DIR),
    }


def _permitted_commands(values: dict[str, str]) -> set[str]:
    raw = values.get("instcmds", "")
    commands = {item.strip() for item in raw.split(",") if item.strip()}
    return set(ALLOWED_COMMANDS) if "ALL" in {item.upper() for item in commands} else commands


def _credentials(command: str) -> tuple[str, str]:
    users = _user_values()
    for name, values in users.items():
        password = values.get("password", "")
        if name and password and command in _permitted_commands(values):
            return name, password
    return "", ""


def ups_command(command: str, confirmation: str = "") -> tuple[int, dict[str, Any]]:
    if command not in ALLOWED_COMMANDS:
        return 403, {"ok": False, "error": "UPS command is not allowed"}
    if command in DANGEROUS_COMMANDS and confirmation != command:
        return 400, {"ok": False, "error": "exact command confirmation is required"}
    config = ups_config()
    target = str(config.get("target", ""))
    if not target:
        return 503, {"ok": False, "error": "UPS target is not configured"}
    listed = run(["/usr/local/bin/upscmd", "-l", target], timeout=8)
    available = {
        line.split(" - ", 1)[0].strip()
        for line in listed.stdout.splitlines()
        if " - " in line
    }
    if command not in available:
        return 409, {"ok": False, "error": f"UPS driver does not publish {command}"}
    username, password = _credentials(command)
    if not username or not password:
        return 409, {"ok": False, "error": "NUT command user is not configured; save NUT settings first"}
    result = run([
        "/usr/local/bin/upscmd", "-u", username, "-p", password, target, command,
    ], timeout=15, redact_args={4})
    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    storage.add_event("ups.command", f"UPS command {command}", severity="warning" if command in DANGEROUS_COMMANDS else "info", payload={"ok": result.ok})
    payload = {"ok": result.ok, "command": command, "output": output}
    if not result.ok:
        payload["error"] = output or result.error or "upscmd failed"
    return (200 if result.ok else 500), payload


def _clean_name(value: object, field: str) -> str:
    text = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63}", text):
        raise ValueError(f"invalid {field}")
    return text


def _number(body: dict[str, Any], field: str, minimum: int, maximum: int) -> int:
    try:
        value = int(body.get(field, ""))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {field}") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}")
    return value


def _write(path: Path, content: str, mode: int) -> None:
    atomic_write_text(
        path,
        content,
        mode=mode,
        preserve_metadata=path.exists(),
    )


def _update_assignment(text: str, key: str, value: str) -> str:
    lines = text.splitlines()
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=", re.IGNORECASE)
    for index, line in enumerate(lines):
        if pattern.match(line):
            lines[index] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    return "\n".join(lines).rstrip() + "\n"


def _directive_key(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    if "=" in stripped:
        return stripped.split("=", 1)[0].strip().lower()
    return stripped.split(None, 1)[0].lower()


def _update_section(
    text: str,
    name: str,
    remove_keys: set[str],
    directives: list[tuple[str, str | None]],
) -> str:
    lines = text.splitlines()
    header = re.compile(rf"^\s*\[{re.escape(name)}\]\s*$", re.IGNORECASE)
    start = next((index for index, line in enumerate(lines) if header.match(line)), -1)
    if start < 0:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"[{name}]")
        start = len(lines) - 1
        end = len(lines)
    else:
        end = next((index for index in range(start + 1, len(lines)) if re.match(r"^\s*\[[^]]+\]\s*$", lines[index])), len(lines))
    body = [line for line in lines[start + 1:end] if _directive_key(line) not in remove_keys]
    while body and not body[-1].strip():
        body.pop()
    if body:
        body.append("")
    for key, value in directives:
        if key.lower() == "upsmon" and value is not None:
            # upsd.users uses "upsmon primary", not an assignment.
            body.append(f"    {key} {value}")
        else:
            body.append(f"    {key}" if value is None else f"    {key} = {value}")
    lines[start + 1:end] = body
    return "\n".join(lines).rstrip() + "\n"


def _update_listeners(text: str, listeners: list[str]) -> str:
    lines = [line for line in text.splitlines() if _directive_key(line) != "listen"]
    while lines and not lines[-1].strip():
        lines.pop()
    if lines:
        lines.append("")
    lines.extend(f"LISTEN {address} 3493" for address in listeners)
    return "\n".join(lines).rstrip() + "\n"


def _update_primary_monitor(text: str, monitor: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        parts = line.strip().split()
        if len(parts) >= 6 and parts[0].upper() == "MONITOR" and parts[-1].lower() in {"primary", "master"}:
            lines[index] = monitor
            break
    else:
        lines.append(monitor)
    return "\n".join(lines).rstrip() + "\n"


def _safe_password(value: str, field: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._~!@$%^&*+=?-]{12,128}", value):
        raise ValueError(f"invalid {field}: use 12-128 safe ASCII characters")
    return value


def _restore(snapshot: dict[Path, tuple[bytes, int, int, int] | None]) -> None:
    errors: list[str] = []
    for path, saved in snapshot.items():
        try:
            if saved is None:
                path.unlink(missing_ok=True)
                continue
            content, mode, uid, gid = saved
            atomic_write_bytes(
                path,
                content,
                mode=mode,
                preserve_metadata=False,
                uid=uid,
                gid=gid,
            )
        except OSError as exc:
            errors.append(f"{path}: {exc}")
    if errors:
        raise OSError("; ".join(errors))


def _configure_ups_locked(body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    try:
        name = _clean_name(body.get("name"), "UPS name")
        driver = _clean_name(body.get("driver"), "driver")
        master_user = _clean_name(body.get("master_user"), "master user")
        client_user = _clean_name(body.get("client_user"), "client user")
        if master_user == client_user:
            raise ValueError("master and client users must be different")
        port = str(body.get("port", "")).strip()
        port_path = Path(port)
        if port_path.parent != Path("/dev") or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", port_path.name) is None:
            raise ValueError("invalid UPS port")
        try:
            port_meta = port_path.lstat()
        except OSError as exc:
            raise ValueError("UPS port does not exist") from exc
        if not stat.S_ISCHR(port_meta.st_mode):
            raise ValueError("UPS port must be a character device")
        mode = str(body.get("mode", "")).strip()
        if mode not in {"standalone", "netserver"}:
            raise ValueError("mode must be standalone or netserver")
        listener_values = [item.strip() for item in str(body.get("listeners", "")).split(",") if item.strip()]
        if not listener_values:
            raise ValueError("at least one LISTEN address is required")
        listeners = [str(ipaddress.ip_address(value)) for value in listener_values]
        low_charge = _number(body, "low_charge", 1, 95)
        low_runtime = _number(body, "low_runtime", 60, 86400)
        offdelay = _number(body, "offdelay", 0, 3600)
        ondelay = _number(body, "ondelay", 0, 7200)
        existing_users = _user_values()
        master_password = _safe_password(str(body.get("master_password", "")).strip() or existing_users.get(master_user, {}).get("password", "") or secrets.token_urlsafe(24), "master password")
        client_password = _safe_password(str(body.get("client_password", "")).strip() or existing_users.get(client_user, {}).get("password", "") or secrets.token_urlsafe(24), "client password")
        description = str(body.get("description", "")).strip()
        if len(description) > 200 or any(ord(char) < 32 or ord(char) == 127 for char in description):
            raise ValueError("invalid description")
        description = description.replace('"', "'")
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}

    allow_killpower = bool(body.get("allow_killpower", False))
    managed_files = NUT_FILES + (paths.RC_CONF,)
    snapshot: dict[Path, tuple[bytes, int, int, int] | None] = {}
    try:
        for path in managed_files:
            try:
                data, metadata = backup._read_regular_bytes(path)
            except FileNotFoundError:
                snapshot[path] = None
                continue
            snapshot[path] = (data, stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid)
        backup_meta = backup.backup_files(managed_files, reason="nut-config")
    except OSError as exc:
        return 500, {"ok": False, "error": f"failed to snapshot NUT configuration: {exc}"}

    ups_directives: list[tuple[str, str | None]] = [
        ("driver", driver), ("port", port), ("desc", f'"{description}"'),
        ("offdelay", str(offdelay)), ("ondelay", str(ondelay)),
        ("override.battery.charge.low", str(low_charge)),
        ("override.battery.runtime.low", str(low_runtime)),
    ]
    if allow_killpower:
        ups_directives.append(("allow_killpower", None))
    command_directives = [("password", master_password)]
    command_directives.extend(("instcmds", command) for command in sorted(ALLOWED_COMMANDS))
    command_directives.append(("upsmon", "primary"))
    try:
        NUT_DIR.mkdir(parents=True, exist_ok=True)
        _write(NUT_CONF, _update_assignment(_text(NUT_CONF), "MODE", mode), 0o640)
        _write(UPS_CONF, _update_section(
            _text(UPS_CONF), name,
            {"driver", "port", "desc", "offdelay", "ondelay", "override.battery.charge.low", "override.battery.runtime.low", "allow_killpower"},
            ups_directives,
        ), 0o640)
        _write(UPSD_CONF, _update_listeners(_text(UPSD_CONF), listeners), 0o640)
        users_text = _update_section(
            _text(UPSD_USERS), master_user,
            {"password", "actions", "instcmds", "upsmon"}, command_directives,
        )
        users_text = _update_section(
            users_text, client_user,
            {"password", "actions", "instcmds", "upsmon"},
            [("password", client_password), ("upsmon", "secondary")],
        )
        _write(UPSD_USERS, users_text, 0o640)
        _write(UPSMON_CONF, _update_primary_monitor(
            _text(UPSMON_CONF),
            f"MONITOR {name}@localhost 1 {master_user} {master_password} primary",
        ), 0o640)
        rc_results = [
            run(["sysrc", "nut_enable=YES"], timeout=5),
            run(["sysrc", "nut_upsmon_enable=YES"], timeout=5),
            run(["sysrc", f"nut_upsshut={'YES' if allow_killpower else 'NO'}"], timeout=5),
        ]
        nut_restart = run(["service", "nut", "restart"], timeout=120)
        monitor_restart = run(["service", "nut_upsmon", "restart"], timeout=30)
        probe = run(["/usr/local/bin/upsc", f"{name}@localhost"], timeout=10)
        if not (all(result.ok for result in rc_results) and nut_restart.ok and monitor_restart.ok and probe.ok):
            errors = [result.stderr or result.error or "" for result in (*rc_results, nut_restart, monitor_restart, probe) if not result.ok]
            raise RuntimeError("; ".join(error for error in errors if error) or "NUT verification failed")
    except (OSError, RuntimeError) as exc:
        rollback_error = ""
        try:
            _restore(snapshot)
        except OSError as restore_exc:
            rollback_error = str(restore_exc)
        run(["service", "nut", "restart"], timeout=120)
        run(["service", "nut_upsmon", "restart"], timeout=30)
        payload = {
            "ok": False,
            "error": str(exc),
            "rolled_back": not rollback_error,
            "backup": backup_meta,
        }
        if rollback_error:
            payload["rollback_error"] = rollback_error
        return 500, payload

    return 200, {
        "ok": True, "target": f"{name}@localhost", "backup": backup_meta,
        "probe": {"ok": True},
    }


def configure_ups(body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Serialize and atomically apply the complete NUT configuration."""
    try:
        NUT_DIR.mkdir(parents=True, exist_ok=True)
        with exclusive_lock(NUT_CONFIG_LOCK):
            with exclusive_lock(paths.RC_CONF.with_suffix(paths.RC_CONF.suffix + ".gatebsd.lock")):
                return _configure_ups_locked(body)
    except OSError as exc:
        return 500, {"ok": False, "error": f"failed to lock NUT configuration: {exc}"}
