from __future__ import annotations

import difflib
import os
import re
import shutil
import stat
import tempfile
from datetime import datetime
from contextlib import ExitStack
from pathlib import Path
from typing import Iterable

from . import paths
from .command import run
from .fsutil import _fsync_directory, atomic_write_bytes, exclusive_lock, read_regular_bytes, read_regular_text
from .redact import redact_text


_MAX_RESTORE_FILE_SIZE = 16 * 1024 * 1024
_MAX_BACKUP_TOTAL_SIZE = 64 * 1024 * 1024
_MIN_BACKUP_FREE_BYTES = 64 * 1024 * 1024
_MAX_BACKUP_STORE_SIZE = 512 * 1024 * 1024
_MAX_BACKUP_COUNT = 10
# Runtime state that a restore must carry alongside the config files. Losing
# DHCP leases means every LAN client can get a different address after a
# restore, breaking anything keyed on them; losing failover state means the
# watchdog restarts with no memory of which underlay was in use.
_EXTRA_CONFIG_PATHS = (
    Path("/etc/resolv.conf"),
    Path("/etc/hosts"),
    Path("/etc/sysctl.conf"),
    Path("/etc/newsyslog.conf.d/gatebsd.conf"),
    Path("/usr/local/etc/cron.d/gatebsd-adblock"),
    Path("/usr/local/etc/cron.d/gatebsd-healthcheck"),
    Path("/usr/local/etc/cron.d/gatebsd-ups-health"),
    Path("/usr/local/etc/cron.d/gatebsd-ups-test"),
    Path("/usr/local/etc/cron.d/gatebsd-ssl-renew"),
    Path("/usr/local/etc/gatebsd/duckdns.conf"),
    Path("/usr/local/etc/gatebsd/failover.conf"),
)


def _new_backup_directory() -> tuple[Path, Path]:
    paths.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    metadata = paths.BACKUP_DIR.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError(f"refusing unsafe backup root: {paths.BACKUP_DIR}")
    os.chmod(paths.BACKUP_DIR, 0o700)
    free_bytes = shutil.disk_usage(paths.BACKUP_DIR).free
    required_bytes = _MAX_BACKUP_TOTAL_SIZE + _MIN_BACKUP_FREE_BYTES
    if free_bytes < required_bytes:
        raise OSError(
            f"insufficient free space for configuration backup: "
            f"need {required_bytes} bytes, {free_bytes} available"
        )
    # Build each snapshot under a hidden name and publish it with one rename so
    # list/delete/restore never observe a partially written backup directory.
    base = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    for counter in range(1000):
        suffix = "" if counter == 0 else f"-{counter}"
        final = paths.BACKUP_DIR / f"{base}-{os.getpid()}{suffix}"
        staging = paths.BACKUP_DIR / f".{final.name}.{os.urandom(8).hex()}.tmp"
        if final.exists() or final.is_symlink():
            continue
        try:
            staging.mkdir(mode=0o700)
            return staging, final
        except FileExistsError:
            continue
    raise OSError("unable to allocate a unique backup directory")


def _resolve_backup_source(source: Path) -> Path:
    """Resolve the one supported logical symlink without leaving its root."""
    metadata = source.lstat()
    if stat.S_ISREG(metadata.st_mode):
        return source
    if not stat.S_ISLNK(metadata.st_mode) or source != paths.AMNEZIA_CONFIG:
        raise OSError(f"refusing non-regular backup source: {source}")
    root = paths.AMNEZIA_CONF_DIR.resolve(strict=True)
    resolved = source.resolve(strict=True)
    resolved_metadata = resolved.lstat()
    if resolved.parent != root or resolved.suffix != ".conf" or not stat.S_ISREG(resolved_metadata.st_mode):
        raise OSError(f"active profile points outside managed config directory: {source}")
    return resolved


def _read_regular_bytes(path: Path) -> tuple[bytes, os.stat_result]:
    try:
        return read_regular_bytes(path, max_size=_MAX_RESTORE_FILE_SIZE)
    except OSError as exc:
        raise OSError(f"unsafe or unreadable backup source {path}: {exc}") from exc


def _backup_retention_needed() -> bool:
    items = list_backups()["backups"]
    return (
        len(items) > _MAX_BACKUP_COUNT
        or sum(item["size"] for item in items) > _MAX_BACKUP_STORE_SIZE
    )


def _prune_backups(protected: Path) -> None:
    items = list_backups()["backups"]
    items.sort(
        key=lambda item: (item["path"] == str(protected), item["mtime"]),
        reverse=True,
    )
    total_size = sum(item["size"] for item in items)
    for index, item in enumerate(items):
        if index < _MAX_BACKUP_COUNT and total_size <= _MAX_BACKUP_STORE_SIZE:
            continue
        current = Path(item["path"])
        if current == protected:
            continue
        shutil.rmtree(current)
        total_size -= item["size"]


def backup_files(files: Iterable[Path], reason: str = "manual") -> dict:
    staging: Path | None = None
    destination: Path | None = None
    copied_names: list[tuple[str, str]] = []
    total_size = 0
    try:
        for source_value in files:
            source = Path(source_value)
            try:
                copy_source = _resolve_backup_source(source)
                data, metadata = _read_regular_bytes(copy_source)
            except FileNotFoundError:
                continue
            total_size += len(data)
            if total_size > _MAX_BACKUP_TOTAL_SIZE:
                raise OSError("backup exceeds the aggregate size limit")
            if staging is None or destination is None:
                staging, destination = _new_backup_directory()
            relative_name = str(source).lstrip("/").replace("/", "_")
            target = staging / relative_name
            if target.exists() or target.is_symlink():
                raise OSError(f"backup filename collision: {target.name}")
            atomic_write_bytes(
                target,
                data,
                mode=stat.S_IMODE(metadata.st_mode),
                preserve_metadata=False,
                uid=metadata.st_uid,
                gid=metadata.st_gid,
            )
            copied_names.append((str(source), relative_name))
        if staging is not None and destination is not None:
            os.replace(staging, destination)
            staging = None
            _fsync_directory(paths.BACKUP_DIR)
            if _backup_retention_needed():
                try:
                    with exclusive_lock(paths.BACKUP_DIR / ".mutation.lock", nonblocking=True):
                        _prune_backups(destination)
                except BlockingIOError:
                    # A restore already holds this lock and is creating its safety
                    # backup. A later successful backup will perform the pruning.
                    pass
    except Exception:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        raise
    copied = [
        {"source": source, "backup": str(destination / name)}
        for source, name in copied_names
        if destination is not None
    ]
    return {
        "timestamp": destination.name if destination is not None else "",
        "reason": reason,
        "dir": str(destination) if destination is not None else "",
        "files": copied,
        "size": total_size,
    }


def backup_known_configs(reason: str = "config-change") -> dict:
    return backup_files(paths.CONFIG_FILES.values(), reason=reason)


def list_backups() -> dict:
    items: list[dict] = []
    try:
        entries = list(paths.BACKUP_DIR.iterdir()) if paths.BACKUP_DIR.is_dir() else []
    except OSError:
        entries = []
    for item in entries:
        if item.name.startswith("."):
            continue
        try:
            metadata = item.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            continue
        size = 0
        try:
            for child in item.rglob("*"):
                child_metadata = child.lstat()
                if stat.S_ISREG(child_metadata.st_mode):
                    size += child_metadata.st_size
        except OSError:
            continue
        items.append({
            "name": item.name,
            "base": item.name,
            "path": str(item),
            "size": size,
            "mtime": int(metadata.st_mtime),
            "type": "directory",
        })
    items.sort(key=lambda entry: entry["mtime"], reverse=True)
    return {"dir": str(paths.BACKUP_DIR), "backups": items}


def _restore_mapping() -> dict[str, Path]:
    result: dict[str, Path] = {}
    for destination in (*paths.CONFIG_FILES.values(), *_EXTRA_CONFIG_PATHS):
        destination = Path(destination)
        archive_name = str(destination).lstrip("/").replace("/", "_")
        result[archive_name] = destination
    return result




def _resolve_restore_destination(destination: Path) -> Path:
    """Return the regular file that may be restored for a logical path.

    The active Amnezia config is intentionally a symlink to a managed profile.
    Restore the target profile content while preserving that link.  No other
    symlink destination is accepted.
    """
    destination = Path(destination)
    try:
        metadata = destination.lstat()
    except FileNotFoundError:
        return destination
    if stat.S_ISREG(metadata.st_mode):
        return destination
    if not stat.S_ISLNK(metadata.st_mode) or destination != paths.AMNEZIA_CONFIG:
        raise OSError(f"refusing unsafe destination: {destination}")
    root = paths.AMNEZIA_CONF_DIR.resolve(strict=True)
    target = destination.resolve(strict=True)
    target_meta = target.lstat()
    if target.parent != root or target.suffix != ".conf" or not stat.S_ISREG(target_meta.st_mode):
        raise OSError(f"active profile points outside managed config directory: {destination}")
    return target

def _restore_lock_paths(destination: Path) -> list[Path]:
    if destination == paths.DIRECT_EXCEPTIONS:
        return [paths.RU_TABLE.with_suffix(paths.RU_TABLE.suffix + ".lock")]
    if destination.parent == paths.NUT_DIR:
        # configure_ups writes all five files as one transaction under this
        # lock. A restore must join that transaction, not take five unrelated
        # per-file locks while the writer can change the other four.
        return [paths.NUT_CONFIG_LOCK]
    if destination == paths.PF_CONF:
        return [destination.with_suffix(destination.suffix + ".gatebsd.lock")]
    if destination == paths.DHCPD_CONF:
        return [destination.with_suffix(destination.suffix + ".lock")]
    if destination in {paths.UNBOUND_CONF, paths.SPLIT_DNS_CONF, paths.UNBOUND_SPLIT_DNS_CONF}:
        return [paths.UNBOUND_CONF.with_suffix(paths.UNBOUND_CONF.suffix + ".gatebsd.lock")]
    if destination == paths.RC_CONF:
        return [destination.with_suffix(destination.suffix + ".gatebsd.lock")]
    if destination == paths.RU_TABLE:
        return [destination.with_suffix(destination.suffix + ".lock")]
    if destination.parent == paths.AMNEZIA_CONF_DIR:
        return [
            paths.AMNEZIA_CONF_DIR / ".gatebsd-profiles.lock",
            destination.with_suffix(destination.suffix + ".lock"),
        ]
    return [destination.with_suffix(destination.suffix + ".gatebsd.lock")]


def _safe_new_file_mode(source_mode: int) -> int:
    # Restored configuration must never become executable or group/world writable.
    mode = source_mode & 0o640
    return mode or 0o600


def _restore_validator(destination: Path) -> list[str] | None:
    """Native syntax checker for a restored config, or None if there isn't one.

    Restoring a config without validating it arms a failure for the next boot
    rather than the current moment, which is far worse: an invalid /etc/pf.conf
    means rc.d/pf runs `pfctl -f` and fails, so PF never loads -- no block-in-all
    and no NAT, leaving the router open and the LAN offline. An invalid
    dhcpd.conf or unbound.conf means those services refuse to start, so the site
    loses address assignment and resolution. In every case the UI reported the
    restore as successful hours earlier.
    """
    if destination == paths.PF_CONF:
        return ["pfctl", "-nf"]
    if destination == paths.DHCPD_CONF:
        return ["dhcpd", "-q", "-t", "-cf"]
    if destination in {paths.UNBOUND_CONF, paths.UNBOUND_SPLIT_DNS_CONF}:
        return ["unbound-checkconf"]
    if destination in {paths.SSHD_CONF, paths.SSHD_GATEBSD_CONF}:
        return ["sshd", "-t", "-f"]
    if destination in {paths.SUDOERS_CONF, paths.SUDOERS_AGENT_CONF}:
        return ["visudo", "-c", "-f"]
    return None


def _validate_restore_payload(destination: Path, data: bytes) -> str | None:
    """Return an error string if the payload fails its native syntax check."""
    if destination == paths.SPLIT_DNS_CONF:
        try:
            text = data.decode("utf-8", errors="strict")
            from .writers import dns as _dns_writer
            _dns_writer.parse_split_dns(text)
            return None
        except (UnicodeError, ValueError) as exc:
            return f"{destination}: {exc}"
    validator = _restore_validator(destination)
    if validator is None:
        return None
    directory = destination.parent
    fd = -1
    candidate: str | None = None
    try:
        fd, candidate = tempfile.mkstemp(
            dir=directory, prefix=".gatebsd-restore.", suffix=destination.suffix or ".conf"
        )
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        result = run([*validator, candidate], timeout=30)
        if result.ok:
            return None
        detail = (result.stderr or result.stdout or result.error or "").strip()
        return f"{destination}: {detail[:400] or 'validation failed'}"
    except OSError as exc:
        # Fail closed: an unverifiable payload must not be published.
        return f"{destination}: cannot validate ({exc})"
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if candidate:
            try:
                Path(candidate).unlink(missing_ok=True)
            except OSError:
                pass


def _validate_nut_restore_payloads(payloads: list[tuple[Path, bytes, int]]) -> list[str]:
    """Validate the five-file NUT contract without starting a driver.

    NUT has no side-effect-free checker for this complete configuration set:
    driver-oriented checks can open the serial port, while daemon reloads alter
    the running service. Validate the directives GateBSD itself owns and fail
    closed on malformed UTF-8 or a partial NUT snapshot. Runtime connectivity
    is separately proven by ``upsc`` after restart and after package upgrades.
    """
    nut_paths = {paths.NUT_CONF, paths.UPS_CONF, paths.UPSD_CONF, paths.UPSD_USERS, paths.UPSMON_CONF}
    present = {destination for destination, _data, _mode in payloads if destination in nut_paths}
    if not present:
        return []
    if present != nut_paths:
        missing = ", ".join(sorted(path.name for path in nut_paths - present))
        return [f"incomplete NUT configuration snapshot; missing: {missing}"]
    try:
        texts = {
            destination: data.decode("utf-8", errors="strict")
            for destination, data, _mode in payloads
            if destination in nut_paths
        }
    except UnicodeError:
        return ["NUT configuration is not valid UTF-8"]

    errors: list[str] = []
    mode = re.search(r"^\s*MODE\s*=\s*(\S+)\s*$", texts[paths.NUT_CONF], re.MULTILINE | re.IGNORECASE)
    if mode is None or mode.group(1).lower() not in {"none", "standalone", "netserver", "netclient", "controlled"}:
        errors.append("nut.conf: missing or invalid MODE")
    ups_sections = re.findall(r"^\s*\[([A-Za-z0-9_.-]+)\]\s*$", texts[paths.UPS_CONF], re.MULTILINE)
    if not ups_sections or re.search(r"^\s*driver\s*=\s*\S+", texts[paths.UPS_CONF], re.MULTILINE | re.IGNORECASE) is None:
        errors.append("ups.conf: a named UPS with a driver is required")
    if re.search(r"^\s*LISTEN\s+\S+\s+\d+\s*$", texts[paths.UPSD_CONF], re.MULTILINE | re.IGNORECASE) is None:
        errors.append("upsd.conf: at least one LISTEN address and port is required")
    if re.search(r"^\s*\[[A-Za-z0-9_.-]+\]\s*$", texts[paths.UPSD_USERS], re.MULTILINE) is None or re.search(
        r"^\s*password\s*=\s*\S+", texts[paths.UPSD_USERS], re.MULTILINE | re.IGNORECASE
    ) is None:
        errors.append("upsd.users: a named user with a password is required")
    monitor = re.search(r"^\s*MONITOR\s+(\S+)\s+\d+\s+(\S+)\s+(\S+)\s+(primary|secondary|master|slave)\s*$", texts[paths.UPSMON_CONF], re.MULTILINE | re.IGNORECASE)
    if monitor is None:
        errors.append("upsmon.conf: a complete MONITOR directive is required")
    else:
        if ups_sections and monitor.group(1).split("@", 1)[0] not in ups_sections:
            errors.append("upsmon.conf: MONITOR references an UPS absent from ups.conf")
        user_section = re.search(
            rf"^\s*\[{re.escape(monitor.group(2))}\]\s*$([\s\S]*?)(?=^\s*\[|\Z)",
            texts[paths.UPSD_USERS], re.MULTILINE,
        )
        password = None if user_section is None else re.search(
            r"^\s*password\s*=\s*(\S+)\s*$", user_section.group(1), re.MULTILINE | re.IGNORECASE,
        )
        if password is None or password.group(1) != monitor.group(3):
            errors.append("upsmon.conf: MONITOR credentials do not match upsd.users")
    if any("CHANGEME_" in text for text in texts.values()):
        errors.append("NUT configuration contains image credentials")
    return errors


def _validate_destination_parent(destination: Path) -> None:
    parent = destination.parent
    try:
        metadata = parent.lstat()
    except FileNotFoundError:
        grandparent = parent.parent
        grandparent_meta = grandparent.lstat()
        if stat.S_ISLNK(grandparent_meta.st_mode) or not stat.S_ISDIR(grandparent_meta.st_mode):
            raise OSError(f"refusing unsafe destination parent: {grandparent}")
        parent.mkdir(mode=0o750)
        metadata = parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError(f"refusing unsafe destination parent: {parent}")


def restore_backup(name_value: object) -> tuple[int, dict]:
    """Restore an allowlisted backup while holding every writer-compatible lock."""
    if not isinstance(name_value, str) or not name_value or "/" in name_value or "\\" in name_value or name_value in {".", ".."}:
        return 400, {"error": "invalid backup name"}
    mutation_lock = paths.BACKUP_DIR / ".mutation.lock"
    originals: dict[Path, tuple[bytes, int, int, int] | None] = {}
    restored: list[Path] = []
    current_backup: dict | None = None
    rollback_errors: list[str] = []
    try:
        with exclusive_lock(mutation_lock):
            status, source_dir, error = _validated_backup_directory(name_value)
            if source_dir is None:
                return status, {"error": error or "backup unavailable"}
            mapping = _restore_mapping()
            payloads: list[tuple[Path, bytes, int]] = []
            total_size = 0
            for item in sorted(source_dir.iterdir(), key=lambda value: value.name):
                metadata = item.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    return 400, {"error": f"unsafe backup entry: {item.name}"}
                destination = mapping.get(item.name)
                if destination is None:
                    return 400, {"error": f"unknown backup entry: {item.name}"}
                if metadata.st_size > _MAX_RESTORE_FILE_SIZE:
                    return 413, {"error": f"backup entry too large: {item.name}"}
                data, stable_metadata = _read_regular_bytes(item)
                total_size += len(data)
                if total_size > _MAX_BACKUP_TOTAL_SIZE:
                    return 413, {"error": "backup exceeds the aggregate size limit"}
                payloads.append((destination, data, stat.S_IMODE(stable_metadata.st_mode)))
            if not payloads:
                return 400, {"error": "backup contains no restorable configuration files"}

            with ExitStack() as stack:
                resolved_payloads: list[tuple[Path, bytes, int]] = []
                expected_destinations: dict[Path, Path] = {}
                seen: set[Path] = set()
                for logical_destination, data, source_mode in payloads:
                    destination = _resolve_restore_destination(logical_destination)
                    if destination in seen:
                        return 409, {"error": f"backup maps multiple entries to {destination}"}
                    seen.add(destination)
                    expected_destinations[logical_destination] = destination
                    resolved_payloads.append((destination, data, source_mode))

                lock_paths = sorted(
                    {lock for destination, _data, _mode in resolved_payloads for lock in _restore_lock_paths(destination)},
                    key=str,
                )
                for lock_path in lock_paths:
                    stack.enter_context(exclusive_lock(lock_path))

                # Re-resolve active-profile symlinks after waiting for all locks.
                refreshed: list[tuple[Path, bytes, int]] = []
                for logical_destination, data, source_mode in payloads:
                    destination = _resolve_restore_destination(logical_destination)
                    if destination != expected_destinations[logical_destination]:
                        raise OSError("restore destination changed while waiting for locks")
                    _validate_destination_parent(destination)
                    refreshed.append((destination, data, source_mode))
                resolved_payloads = refreshed

                for destination, _data, _mode in resolved_payloads:
                    try:
                        metadata = destination.lstat()
                    except FileNotFoundError:
                        originals[destination] = None
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        return 409, {"error": f"refusing unsafe destination: {destination}"}
                    data, stable_metadata = _read_regular_bytes(destination)
                    originals[destination] = (
                        data,
                        stat.S_IMODE(stable_metadata.st_mode),
                        stable_metadata.st_uid,
                        stable_metadata.st_gid,
                    )

                # Validate every payload that has a native syntax checker before
                # publishing any of them. A snapshot can be stale or have been
                # captured mid-edit, and an invalid config restored to disk does
                # not fail now -- it fails at the next boot, when rc.d/pf cannot
                # load a ruleset or dhcpd/unbound refuse to start.
                validation_errors = [
                    error
                    for error in (
                        _validate_restore_payload(destination, data)
                        for destination, data, _mode in resolved_payloads
                    )
                    if error is not None
                ]
                validation_errors.extend(_validate_nut_restore_payloads(resolved_payloads))
                if validation_errors:
                    return 409, {
                        "error": "refusing to restore configuration that fails validation",
                        "detail": validation_errors,
                    }

                existing = [path for path, original in originals.items() if original is not None]
                current_backup = backup_files(existing, reason=f"before-restore-{name_value}")
                try:
                    for destination, data, source_mode in resolved_payloads:
                        original = originals[destination]
                        if original is None:
                            atomic_write_bytes(
                                destination,
                                data,
                                mode=_safe_new_file_mode(source_mode),
                                preserve_metadata=False,
                                uid=0,
                                gid=0,
                            )
                        else:
                            atomic_write_bytes(destination, data, preserve_metadata=True)
                        restored.append(destination)
                except Exception:
                    for destination in reversed(restored):
                        original = originals.get(destination)
                        try:
                            if original is None:
                                destination.unlink(missing_ok=True)
                                _fsync_directory(destination.parent)
                            else:
                                data, mode, uid, gid = original
                                atomic_write_bytes(
                                    destination,
                                    data,
                                    mode=mode,
                                    preserve_metadata=False,
                                    uid=uid,
                                    gid=gid,
                                )
                        except Exception as rollback_exc:
                            rollback_errors.append(f"{destination}: {rollback_exc}")
                    raise
    except Exception as exc:
        body = {"error": f"restore failed: {exc}", "restored": [str(path) for path in restored]}
        if rollback_errors:
            body["rollback_errors"] = rollback_errors
        if current_backup is not None:
            body["safety_backup"] = current_backup
        return 500, body

    return 200, {
        "ok": True,
        "restored": [str(path) for path in restored],
        "safety_backup": current_backup,
    }


def _validated_backup_directory(name_value: object) -> tuple[int, Path | None, str | None]:
    if not isinstance(name_value, str) or not name_value or "/" in name_value or "\\" in name_value or name_value in {".", ".."}:
        return 400, None, "invalid backup name"
    candidate = paths.BACKUP_DIR / name_value
    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        return 404, None, "backup not found"
    except OSError as exc:
        return 500, None, f"failed to access backup: {exc}"
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return 400, None, "backup must be a directory"
    return 200, candidate, None


def _text_for_diff(path: Path) -> tuple[str | None, str | None]:
    try:
        text, _metadata = read_regular_text(path, max_size=_MAX_RESTORE_FILE_SIZE, errors="strict")
        return text, None
    except FileNotFoundError:
        return "", None
    except UnicodeError:
        return None, "binary or invalid UTF-8"
    except OSError as exc:
        return None, str(exc)


def diff_backup(name: str) -> dict:
    """Compare every known file in one backup snapshot with live config."""
    status, source_dir, error = _validated_backup_directory(name)
    if source_dir is None:
        return {"error": error or "backup unavailable", "status": status}

    mapping = _restore_mapping()
    sections: list[str] = []
    compared = 0
    try:
        entries = sorted(source_dir.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        return {"error": f"failed to read backup: {exc}", "status": 500}

    for item in entries:
        destination = mapping.get(item.name)
        if destination is None:
            continue
        backup_text, backup_error = _text_for_diff(item)
        if backup_error is not None:
            sections.append(f"--- {item.name}\n+++ {destination}\n[backup: {backup_error}]\n")
            compared += 1
            continue
        try:
            live_path = _resolve_restore_destination(destination)
        except OSError as exc:
            sections.append(f"--- {item.name}\n+++ {destination}\n[current: {exc}]\n")
            compared += 1
            continue
        live_text, live_error = _text_for_diff(live_path)
        if live_error is not None:
            sections.append(f"--- {item.name}\n+++ {live_path}\n[current: {live_error}]\n")
            compared += 1
            continue
        assert backup_text is not None and live_text is not None
        diff = "".join(difflib.unified_diff(
            redact_text(live_text).splitlines(keepends=True),
            redact_text(backup_text).splitlines(keepends=True),
            fromfile=f"current:{live_path}",
            tofile=f"backup:{name}/{item.name}",
        ))
        sections.append(diff or f"# {item.name}: no differences\n")
        compared += 1

    if compared == 0:
        return {"error": "backup contains no comparable configuration files", "status": 400}
    return {
        "diff": "\n".join(sections),
        "base": name,
        "current_path": "multiple files",
        "files_compared": compared,
    }


def delete_backup(name_value: object) -> tuple[int, dict]:
    """Delete one backup snapshot directory without following symlinks."""
    status, source_dir, error = _validated_backup_directory(name_value)
    if source_dir is None:
        return status, {"error": error or "backup unavailable"}
    lock_path = paths.BACKUP_DIR / ".mutation.lock"
    try:
        with exclusive_lock(lock_path):
            # Revalidate after waiting for the lock.
            status2, current, error2 = _validated_backup_directory(name_value)
            if current is None:
                return status2, {"error": error2 or "backup unavailable"}
            shutil.rmtree(current)
        return 200, {"ok": True, "name": str(name_value)}
    except OSError as exc:
        return 500, {"error": f"failed to delete backup: {exc}"}
