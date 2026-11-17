"""System package management and generic service control."""
from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import subprocess
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .. import action_state, paths
from ..command import CommandResult, run
from ..fsutil import atomic_write_text, exclusive_lock

_UPDATE_LOG = Path("/var/log/gatebsd-upgrade.log")
_UPDATE_STATE = Path("/var/run/gatebsd/pkg-update-state.json")
_UPDATE_LOCK = Path("/var/run/gatebsd/pkg-update.lock")
_REQUIRED_PACKAGES = Path("/usr/local/share/gatebsd/etc/gatebsd/required-packages")
_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*$")
_UPDATE_START_LOCK = threading.Lock()
_PYTHON_LAUNCHER = Path(os.environ.get("GATEBSD_PYTHON_LAUNCHER", "/usr/local/libexec/gatebsd-python"))

# A system-wide `pkg upgrade` can replace mpd5, unbound, dhcpd, nginx and the
# AmneziaWG kernel module in one transaction. Nothing in pkg(8) can undo that,
# so the only real rollback is a ZFS boot environment taken beforehand.
_BE_NAME_PREFIX = "gatebsd-preupgrade-"
_BE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
# One boot environment is created per upgrade attempt and each holds a full
# clone of the root dataset. Nothing removed them, so a router that upgrades
# regularly fills the very pool _disk_preflight measures until it refuses its
# own upgrades. Keep the last few and destroy the rest.
_BE_KEEP = 3
# The services whose state the upgrade is responsible for. gatebsd_failover is
# on this list because the package's own pre-deinstall stops it together with
# gatebsd and nothing in the package starts either of them again; without it
# here the health gate reported success while automatic WAN failover was off.
# gatewayctl_apply is here for the same reason, one fix later: it is what puts
# the VPN in the traffic path, and without it the 2.9.3 -> 2.9.7 upgrade
# reported success while every LAN packet left the building unencrypted. A
# person noticed, not the system.
_HEALTH_SERVICES = (
    "mpd5", "unbound", "nginx", "gatebsd", "gatebsd_failover", "gatewayctl_apply",
    "nut", "nut_upsmon",
)
# `pkg upgrade` downloads into PKG_CACHEDIR and then writes the unpacked files.
# Running the root filesystem out of space mid-transaction leaves a partially
# installed system, so require the reported download size plus headroom.
_DISK_HEADROOM_BYTES = 2 * 1024 * 1024 * 1024
_DOWNLOAD_SIZE_RE = re.compile(
    r"^\s*([0-9]+(?:\.[0-9]+)?)\s*(B|KiB|MiB|GiB|TiB)\s+to be downloaded", re.MULTILINE
)
_SIZE_UNITS = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
# The watchdog's route transactions and this upgrade must not interleave: a
# package replacing mpd5 or the awg kernel module while a route transaction is
# half-applied leaves the routing table describing a tunnel that no longer
# exists. gatewayctl, gatebsd-route-op and the watchdog all serialise on this
# pathname, and FreeBSD lockf(1) and Python's flock are the same lock (verified
# on FreeBSD 15.1).
_GATEWAY_LOCK = Path("/var/run/gatebsd/gatewayctl.lock")
_CONFIG_GUARD = Path(
    os.environ.get("GATEBSD_CONFIG_GUARD", "/usr/local/sbin/gatebsd-config-guard")
)


def _safe_read_text(path: Path, limit: int = 8 * 1024 * 1024) -> str:
    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            return ""
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        total = sum(len(chunk) for chunk in chunks)
        if total > limit or (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
            return ""
        return b"".join(chunks).decode("utf-8", errors="replace")
    except OSError:
        return ""
    finally:
        if fd >= 0:
            os.close(fd)


def _write_update_state(**values: Any) -> None:
    state = {
        "running": False,
        "ok": None,
        "phase": "idle",
        "error": "",
        "started_at": None,
        "finished_at": None,
        "pid": None,
    }
    try:
        current = json.loads(_safe_read_text(_UPDATE_STATE) or "{}")
        if isinstance(current, dict):
            state.update(current)
    except (TypeError, ValueError):
        pass
    state.update(values)
    _UPDATE_STATE.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        _UPDATE_STATE,
        json.dumps(state, ensure_ascii=False, sort_keys=True) + "\n",
        mode=0o640,
        preserve_metadata=_UPDATE_STATE.exists(),
    )


def _append_update_log(text: str) -> None:
    _UPDATE_LOG.parent.mkdir(parents=True, exist_ok=True)
    payload = text.encode("utf-8", errors="replace")
    if text and not text.endswith("\n"):
        payload += b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(_UPDATE_LOG, flags, 0o640)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(f"refusing unsafe package update log: {_UPDATE_LOG}")
        os.fchmod(fd, 0o640)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write to package update log")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_required_packages() -> list[str]:
    """Return the package names required by the installed GateBSD build.

    The canonical list is generated by the package builder, so the Python
    package names follow the selected build flavor without hard-coding a minor
    version in the source tree.  Installed package metadata is a compatibility
    fallback for older GateBSD packages.
    """
    names: list[str] = []
    content = _safe_read_text(_REQUIRED_PACKAGES)
    for raw in content.splitlines():
        name = raw.strip()
        if not name or name.startswith("#"):
            continue
        if _PACKAGE_NAME_RE.fullmatch(name) is None:
            continue
        if name not in names:
            names.append(name)

    if names:
        return names

    metadata = run(["pkg", "query", "-g", "%dn", "gatebsd"], timeout=10)
    if metadata.ok:
        for raw in metadata.stdout.splitlines():
            name = raw.strip()
            if _PACKAGE_NAME_RE.fullmatch(name) is not None and name not in names:
                names.append(name)
    return names


def _package_is_installed(name: str) -> bool:
    result = run(["pkg", "query", "-e", f'%n = "{name}"', "%n"], timeout=5)
    return result.ok and any(line.strip() == name for line in result.stdout.splitlines())


def _missing_packages(required: list[str]) -> list[str]:
    return [name for name in required if not _package_is_installed(name)]


def _upgrade_lines(output: str) -> list[str]:
    result: list[str] = []
    in_package_section = False
    for raw in output.splitlines():
        line = raw.strip()
        upper = line.upper()
        if not line:
            in_package_section = False
            continue
        if upper.endswith("PACKAGES TO BE UPGRADED:") or upper.endswith("PACKAGES TO BE INSTALLED:") \
                or upper.endswith("PACKAGES TO BE REINSTALLED:") or upper.endswith("PACKAGES TO BE DOWNGRADED:"):
            in_package_section = True
            continue
        if in_package_section and raw[:1].isspace() and line not in result:
            result.append(line)
    return result


def _update_lock_is_held() -> bool:
    _UPDATE_LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        _UPDATE_LOCK,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(f"refusing unsafe package maintenance lock: {_UPDATE_LOCK}")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def pkg_upgrade_log() -> tuple[int, dict[str, Any]]:
    log_text = _safe_read_text(_UPDATE_LOG)
    try:
        state = json.loads(_safe_read_text(_UPDATE_STATE) or "{}")
        if not isinstance(state, dict):
            state = {}
    except (TypeError, ValueError):
        state = {}

    lock_running = _update_lock_is_held()
    pid = state.get("pid")
    pid_running = False
    if isinstance(pid, int) and pid > 1:
        try:
            os.kill(pid, 0)
            pid_running = True
        except ProcessLookupError:
            pass
        except PermissionError:
            # The privileged agent normally owns the worker.  Conservatively
            # report it as running if the kernel denies the probe.
            pid_running = True
    stale_state = bool(state.get("running")) and not pid_running and not lock_running
    running = pid_running or lock_running
    if stale_state:
        state["running"] = False
        state["ok"] = False
        state["phase"] = "interrupted"
        state["error"] = "previous package maintenance was interrupted"
    return 200, {
        "log": log_text,
        "lines": log_text.splitlines(),
        "running": running,
        "ok": state.get("ok"),
        "phase": state.get("phase", "idle"),
        "error": state.get("error", ""),
        "started_at": state.get("started_at"),
        "finished_at": state.get("finished_at"),
        # Surfaced so an operator who sees a failed upgrade knows which boot
        # environment to activate without reading the log.
        "boot_environment": state.get("boot_environment"),
        "config_backup": state.get("config_backup"),
    }


def pkg_updates(*, refresh: bool = False) -> tuple[int, dict[str, Any]]:
    refresh_result: CommandResult | None = None
    if refresh:
        refresh_result = run(["pkg", "update"], timeout=90)
        if not refresh_result.ok:
            return 500, {
                "ok": False,
                "error": "pkg update failed",
                "output": "\n".join(filter(None, [refresh_result.stdout, refresh_result.stderr])),
                "count": 0,
                "available": 0,
                "missing": [],
                "upgradable": [],
            }

    required = _read_required_packages()
    missing = _missing_packages(required)
    dry_run = run(["pkg", "upgrade", "-n"], timeout=30)
    if not dry_run.ok:
        return 500, {
            "ok": False,
            "error": "pkg upgrade dry-run failed",
            "output": "\n".join(filter(None, [dry_run.stdout, dry_run.stderr])),
            "count": len(missing),
            "available": len(missing),
            "missing": missing,
            "upgradable": [],
            "required": required,
        }

    upgradable = _upgrade_lines(dry_run.stdout)
    output_parts: list[str] = []
    if refresh_result is not None:
        output_parts.extend(filter(None, [refresh_result.stdout, refresh_result.stderr]))
    if missing:
        output_parts.append("Missing required packages:\n  " + "\n  ".join(missing))
    if dry_run.stdout:
        output_parts.append(dry_run.stdout)
    if not missing and not upgradable:
        output_parts.append("All required packages are installed; no upgrades are available.")

    count = len(missing) + len(upgradable)
    return 200, {
        "ok": True,
        "count": count,
        "available": count,
        "missing": missing,
        "upgradable": upgradable,
        "required": required,
        "output": "\n\n".join(output_parts),
    }


def _run_pkg_logged(command: list[str], *, phase: str, timeout: int) -> CommandResult:
    _write_update_state(running=True, phase=phase, error="")
    _append_update_log("\n$ " + " ".join(command))
    result = run(command, timeout=timeout)
    if result.stdout:
        _append_update_log(result.stdout)
    if result.stderr:
        _append_update_log(result.stderr)
    _append_update_log(f"[exit {result.returncode if result.returncode is not None else 'error'}]")
    return result


def _download_bytes(dry_run_output: str) -> int:
    """Parse pkg's "N MiB to be downloaded" line into bytes."""
    match = _DOWNLOAD_SIZE_RE.search(dry_run_output)
    if match is None:
        return 0
    try:
        return int(float(match.group(1)) * _SIZE_UNITS[match.group(2)])
    except (TypeError, ValueError, KeyError, OverflowError):
        return 0


def _free_bytes(path: str = "/") -> int | None:
    try:
        usage = os.statvfs(path)
    except OSError:
        return None
    return usage.f_bavail * usage.f_frsize


def _disk_preflight(dry_run_output: str) -> str | None:
    """Refuse to start when the root filesystem cannot hold the transaction.

    ``pkg upgrade`` has no atomic rollback: filling the pool halfway through
    leaves a partially installed system, and on this router that means services
    that no longer start and no way in to fix them.
    """
    required = _download_bytes(dry_run_output) + _DISK_HEADROOM_BYTES
    available = _free_bytes("/")
    if available is None:
        return None
    if available < required:
        return (
            f"insufficient free space: {available // (1024 * 1024)} MiB available, "
            f"{required // (1024 * 1024)} MiB required"
        )
    return None


def _boot_environment_supported() -> bool:
    return bool(run(["bectl", "check"], timeout=10).ok)


def _create_boot_environment() -> tuple[str | None, str | None]:
    """Snapshot the running system into a new inactive boot environment.

    Returns ``(name, error)``. This is the only mechanism that can undo a
    system-wide package upgrade, so a failure to create one is fatal to the
    upgrade rather than a warning.
    """
    name = f"{_BE_NAME_PREFIX}{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}"
    if _BE_NAME_RE.fullmatch(name) is None:
        return None, "generated boot environment name is unsafe"
    result = _run_pkg_logged(["bectl", "create", name], phase="boot-environment", timeout=120)
    if not result.ok:
        detail = result.stderr or result.stdout or result.error or "bectl create failed"
        return None, f"cannot create a rollback boot environment: {detail}"
    listing = run(["bectl", "list", "-H"], timeout=15)
    if not listing.ok or not any(
        line.split("\t", 1)[0] == name for line in listing.stdout.splitlines()
    ):
        return None, "the rollback boot environment was not created"
    return name, None


def _running_services() -> list[str]:
    """Snapshot which critical services are up, before the upgrade touches them.

    ``service X restart`` honours the rcvar, so a service the operator
    deliberately disabled cannot be restarted and would be reported as an
    upgrade failure. Something that was already down is also not something this
    upgrade broke. ``sbin/gatebsd-upgrade`` takes the same snapshot for the same
    reason.
    """
    return [
        service
        for service in _HEALTH_SERVICES
        if run(["service", service, "onestatus"], timeout=15).ok
    ]


def _prune_boot_environments(keep: int = _BE_KEEP) -> None:
    """Destroy superseded pre-upgrade boot environments, newest ``keep`` kept.

    Only environments this code created are considered, and never the one
    active now or on the next boot -- destroying either is unbootable.
    """
    listing = run(["bectl", "list", "-H"], timeout=15)
    if not listing.ok:
        return
    candidates: list[str] = []
    for line in listing.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        name, flags = fields[0], fields[1]
        if not name.startswith(_BE_NAME_PREFIX):
            continue
        if "N" in flags or "R" in flags:
            continue
        candidates.append(name)
    # The name carries a UTC timestamp, so lexical order is chronological.
    for name in sorted(candidates)[: max(len(candidates) - keep, 0)]:
        if run(["bectl", "destroy", "-F", name], timeout=120).ok:
            _append_update_log(f"Removed superseded rollback boot environment: {name}")


def _condemned_services(guard_output: str) -> set[str]:
    """Services the guard could not give a startable configuration.

    The contract is the guard's ``UNSTARTABLE:`` line, which names services
    rather than files. An absent line means the guard never said, and nothing
    is held back -- silently skipping every restart because a parser changed
    shape would be its own outage.
    """
    for line in reversed((guard_output or "").splitlines()):
        if line.startswith("UNSTARTABLE:"):
            return {name for name in line.split(":", 1)[1].split() if name}
    return set()


def _post_upgrade_health(previously_running: Sequence[str] | None = None) -> list[str]:
    """Report which critical services are unhealthy after the upgrade.

    Restart what the upgrade stopped before judging: pkg(8) does not restart
    services it replaces, so an unstarted unbound is expected rather than a
    failure. Only services that were running beforehand are restarted and
    judged; see :func:`_running_services`.
    """
    services = _HEALTH_SERVICES if previously_running is None else tuple(previously_running)
    failures: list[str] = []
    # Never restart a service into a configuration it cannot parse. The guard
    # restores the last copy that validated, so a file some other writer
    # corrupted days ago does not turn into an outage at upgrade time.
    guard = run([str(_CONFIG_GUARD)], timeout=120)
    condemned: set[str] = set()
    if guard.returncode == 1:
        _append_update_log("Configuration guard repaired an unstartable config before restarting")
    elif not guard.ok:
        _append_update_log(
            "ERROR: configuration guard reports an unstartable config: "
            + (guard.stdout or guard.stderr or "unknown")
        )
        failures.append("configuration")
        # Reporting the failure is not the same as acting on it. Falling through
        # into the restart loop is what turns a config corrupted days ago into
        # an outage at upgrade time -- the exact sequence the guard was written
        # to break. Only the services it named are held back; the rest still get
        # restarted, or one bad dhcpd.conf would leave the whole box down.
        condemned = _condemned_services(guard.stdout)
    for service in services:
        if service in condemned:
            _append_update_log(
                f"{service}: its configuration does not parse; not restarting it"
            )
            failures.append(service)
            continue
        if run(["service", service, "onestatus"], timeout=15).ok:
            continue
        _append_update_log(f"{service} is not running after the upgrade; restarting")
        restarted = run(["service", service, "restart"], timeout=60)
        if not restarted.ok:
            restarted = run(["service", service, "start"], timeout=60)
        if not restarted.ok:
            failures.append(service)
    if run(["pfctl", "-s", "info"], timeout=10).ok and not run(
        ["pfctl", "-nf", "/etc/pf.conf"], timeout=15
    ).ok:
        failures.append("pf ruleset")
    if not run(["route", "-n", "get", "default"], timeout=10).ok:
        failures.append("default route")
    return failures


def pkg_upgrade() -> tuple[int, dict[str, Any]]:
    """Upgrade the system with a boot environment as the rollback mechanism.

    ``pkg upgrade`` only acts on installed packages.  GateBSD therefore keeps a
    generated required-package list and explicitly installs missing entries
    before upgrading the rest of the system.

    The sequence is preflight (dry run, free space), configuration snapshot,
    boot-environment snapshot, upgrade, then a health gate. A failed health gate
    reports the boot environment to activate; it does not reboot on its own,
    since the router is the site's only uplink.
    """
    try:
        _UPDATE_LOCK.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = os.open(
            _UPDATE_LOCK,
            os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        metadata = os.fstat(lock_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(f"refusing unsafe package maintenance lock: {_UPDATE_LOCK}")
    except OSError as exc:
        return 500, {"ok": False, "error": f"cannot open package maintenance lock: {exc}"}
    locked = False
    try:
        os.fchmod(lock_fd, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError:
            return 409, {"ok": False, "error": "package maintenance is already running"}

        return _pkg_upgrade_locked()
    finally:
        if locked:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            os.close(lock_fd)
        except OSError:
            pass


def _pkg_upgrade_locked() -> tuple[int, dict[str, Any]]:
    # Bound outside the try so the failure path can still report the rollback
    # target. A `pkg upgrade` that fails after the boot environment exists is
    # exactly when an operator needs its name, and the failure state used to
    # omit it.
    boot_environment: str | None = None
    config_backup: dict[str, Any] | None = None
    try:
        started_at = int(time.time())
        atomic_write_text(_UPDATE_LOG, "", mode=0o640, preserve_metadata=_UPDATE_LOG.exists())
        _write_update_state(
            running=True,
            ok=None,
            phase="repository-update",
            error="",
            started_at=started_at,
            finished_at=None,
            pid=os.getpid(),
        )
        _append_update_log("GateBSD package maintenance started")

        refresh = _run_pkg_logged(["pkg", "update"], phase="repository-update", timeout=180)
        if not refresh.ok:
            raise RuntimeError("pkg update failed")

        required = _read_required_packages()
        if not required:
            raise RuntimeError("required package list is unavailable")

        # Preflight before anything is written. `pkg upgrade` cannot be undone
        # in place, so every reason to refuse must be found first.
        _write_update_state(running=True, phase="preflight", error="")
        plan = _run_pkg_logged(["pkg", "upgrade", "-n", "-U"], phase="preflight", timeout=300)
        if not plan.ok:
            raise RuntimeError("pkg upgrade dry-run failed")
        space_error = _disk_preflight(plan.stdout)
        if space_error:
            raise RuntimeError(space_error)

        # Configuration snapshot: cheap, and the only thing that survives a
        # boot-environment rollback, since /var and /usr/local/etc content
        # written after the snapshot is not reverted with the root dataset.
        try:
            from .. import backup as backup_module

            config_backup = backup_module.backup_known_configs(reason="pkg-upgrade")
            _append_update_log(f"Configuration snapshot: {config_backup.get('dir', 'unknown')}")
        except Exception as exc:  # noqa: BLE001 - a failed snapshot must abort
            raise RuntimeError(f"cannot snapshot configuration before upgrade: {exc}") from exc

        # Boot environment: the actual rollback mechanism. Refuse to upgrade
        # without one rather than leaving the router with no way back.
        if not _boot_environment_supported():
            raise RuntimeError(
                "boot environments are unavailable, so a system upgrade could not "
                "be rolled back; refusing to proceed"
            )
        boot_environment, be_error = _create_boot_environment()
        if be_error:
            raise RuntimeError(be_error)
        _append_update_log(f"Rollback boot environment: {boot_environment}")

        # Fetch everything first, without the routing lock held. Downloads are
        # the long part of an upgrade and they mutate nothing outside the cache,
        # so WAN failover stays available throughout.
        fetch = _run_pkg_logged(
            ["pkg", "upgrade", "-y", "-U", "-F"], phase="fetch", timeout=3600
        )
        if not fetch.ok:
            raise RuntimeError("cannot fetch the upgrade packages")

        # Only the install phase conflicts with route transactions: a package
        # replacing mpd5 or the AmneziaWG kernel module while the watchdog has a
        # transaction half-applied leaves the routing table describing a tunnel
        # that no longer exists. Hold the same lock gatewayctl, gatebsd-route-op
        # and the watchdog use -- FreeBSD lockf(1) and Python's flock are the
        # same lock, verified on FreeBSD 15.1 -- for the install window only,
        # rather than for the whole upgrade, so failover is not denied for the
        # tens of minutes a download can take.
        #
        # Record what is up before pkg(8) touches it: the GateBSD package's own
        # pre-deinstall stops gatebsd and gatebsd_failover, and nothing in the
        # package starts them again.
        previously_running = _running_services()
        _append_update_log("Running before the upgrade: " + (", ".join(previously_running) or "none"))
        missing = _missing_packages(required)
        try:
            with exclusive_lock(_GATEWAY_LOCK, nonblocking=True):
                if missing:
                    install = _run_pkg_logged(
                        ["pkg", "install", "-y", "-U", *missing],
                        phase="install-missing",
                        timeout=900,
                    )
                    if not install.ok:
                        raise RuntimeError("installation of required packages failed")
                else:
                    _append_update_log("All required GateBSD packages are already installed.")

                upgrade = _run_pkg_logged(
                    ["pkg", "upgrade", "-y", "-U"], phase="upgrade", timeout=1800
                )
                if not upgrade.ok:
                    raise RuntimeError("pkg upgrade failed")
                # pkg upgrades itself before the rest of the transaction.  A
                # catalogue written by the old pkg may then need a schema
                # rebuild; pkg 2.8.4 printed that requirement, skipped every
                # remaining package and still exited zero on the production
                # router.  Refresh and resume only for that explicit
                # diagnostic.  An unconditional second refresh could admit a
                # newly published package after the preflight/fetch boundary.
                upgrade_output = "\n".join(
                    part for part in (upgrade.stdout, upgrade.stderr) if part
                )
                if "need to re-create repo " in upgrade_output:
                    refresh = _run_pkg_logged(
                        ["pkg", "update"], phase="repository-refresh", timeout=180
                    )
                    if not refresh.ok:
                        raise RuntimeError(
                            "pkg upgraded itself but repository refresh failed"
                        )
                    resumed = _run_pkg_logged(
                        ["pkg", "upgrade", "-y", "-U"],
                        phase="upgrade-resumed",
                        timeout=1800,
                    )
                    if not resumed.ok:
                        raise RuntimeError("pkg upgrade failed after repository refresh")
        except BlockingIOError as exc:
            raise RuntimeError(
                "a routing transaction is in progress; the upgrade was not started"
            ) from exc

        remaining = _missing_packages(required)
        if remaining:
            raise RuntimeError("required packages remain missing: " + ", ".join(remaining))

        # Health gate. pkg(8) does not restart what it replaces, so restart
        # first and only then judge. A failure here is reported with the boot
        # environment to activate; it deliberately does not reboot the router by
        # itself, because an unattended reboot of the site's only uplink is an
        # operator decision.
        _write_update_state(running=True, phase="health-gate", error="")
        health_failures = _post_upgrade_health(previously_running)
        finished_at = int(time.time())
        if health_failures:
            message = "post-upgrade health check failed: " + ", ".join(health_failures)
            _append_update_log("ERROR: " + message)
            _append_update_log(
                f"Roll back with: bectl activate {boot_environment} && shutdown -r now"
            )
            _write_update_state(
                running=False,
                ok=False,
                phase="unhealthy",
                error=message,
                finished_at=finished_at,
                boot_environment=boot_environment,
                config_backup=(config_backup or {}).get("dir"),
                pid=None,
            )
            return 500, {
                "ok": False,
                "error": message,
                "boot_environment": boot_environment,
                "rollback_command": f"bectl activate {boot_environment} && shutdown -r now",
                "config_backup": (config_backup or {}).get("dir"),
                "reboot_required": True,
            }

        # Only once the new system is proven healthy: an older environment is
        # still the way back until then.
        _prune_boot_environments()

        _append_update_log("GateBSD package maintenance completed successfully.")
        _write_update_state(
            running=False,
            ok=True,
            phase="complete",
            error="",
            finished_at=finished_at,
            installed_missing=missing,
            boot_environment=boot_environment,
            config_backup=(config_backup or {}).get("dir"),
            pid=None,
        )
        return 200, {
            "ok": True,
            "installed": missing,
            "boot_environment": boot_environment,
            "config_backup": (config_backup or {}).get("dir"),
        }
    except Exception as exc:
        message = str(exc) or type(exc).__name__
        response: dict[str, Any] = {"ok": False, "error": message}
        if boot_environment:
            response["boot_environment"] = boot_environment
            response["rollback_command"] = (
                f"bectl activate {boot_environment} && shutdown -r now"
            )
        if config_backup:
            response["config_backup"] = config_backup.get("dir")
        try:
            _append_update_log("ERROR: " + message)
            if boot_environment:
                _append_update_log(
                    f"Roll back with: bectl activate {boot_environment} && shutdown -r now"
                )
            _write_update_state(
                running=False,
                ok=False,
                phase="failed",
                error=message,
                finished_at=int(time.time()),
                boot_environment=boot_environment,
                config_backup=(config_backup or {}).get("dir"),
                pid=None,
            )
        except OSError:
            pass
        return 500, response


def _reap_package_worker(process: subprocess.Popen[bytes]) -> None:
    try:
        process.wait()
    except Exception:
        # The state/lock files remain the source of truth.  Reaping is only to
        # avoid a zombie while the web agent itself stays alive.
        return


def pkg_upgrade_start() -> tuple[int, dict[str, Any]]:
    """Launch package maintenance outside the web request process.

    The worker is placed in its own session, so updating or restarting GateBSD
    does not abort an in-progress dependency installation.  The package lock
    remains authoritative across both old and new agent processes.
    """
    with _UPDATE_START_LOCK:
        try:
            if _update_lock_is_held():
                return 409, {"ok": False, "error": "package maintenance is already running"}
            state = json.loads(_safe_read_text(_UPDATE_STATE) or "{}")
            if isinstance(state, dict) and state.get("running") and state.get("phase") == "starting":
                started = state.get("started_at")
                if isinstance(started, int) and time.time() - started < 30:
                    return 409, {"ok": False, "error": "package maintenance is starting"}
        except (OSError, TypeError, ValueError) as exc:
            return 500, {"ok": False, "error": f"cannot inspect package maintenance state: {exc}"}

        if (
            not _PYTHON_LAUNCHER.is_absolute()
            or not _PYTHON_LAUNCHER.is_file()
            or not os.access(_PYTHON_LAUNCHER, os.X_OK)
        ):
            return 500, {"ok": False, "error": f"Python launcher is unavailable: {_PYTHON_LAUNCHER}"}

        started_at = int(time.time())
        try:
            _write_update_state(
                running=True,
                ok=None,
                phase="starting",
                error="",
                started_at=started_at,
                finished_at=None,
                pid=None,
            )
            environment = {
                "PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
                "PYTHONPATH": "/usr/local/share/gatebsd/webui/backend",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "HOME": "/root",
            }
            process = subprocess.Popen(
                [str(_PYTHON_LAUNCHER), "-m", "gatebsd_ui.pkg_maintenance"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                env=environment,
            )
        except (OSError, ValueError) as exc:
            _write_update_state(
                running=False,
                ok=False,
                phase="failed",
                error=f"cannot start package maintenance: {exc}",
                finished_at=int(time.time()),
                pid=None,
            )
            return 500, {"ok": False, "error": f"cannot start package maintenance: {exc}"}

        threading.Thread(
            target=_reap_package_worker,
            args=(process,),
            daemon=True,
            name=f"gatebsd-pkg-reaper-{process.pid}",
        ).start()
        return 200, {"ok": True, "pid": process.pid}


ALLOWED_SERVICES = {
    "mpd5", "pf", "unbound", "dhcpd", "isc-dhcpd", "isc-dhcpd6", "sshd", "ntpd",
    "nut", "nut_upsmon", "gatebsd_failover", "gatewayctl_apply", "amnezia",
    "gatebsd", "gatebsd_reverse_ssh", "smartd", "cron", "awg0",
}


def service_running(name: str) -> bool | None:
    """Is the service up right now -- or did we fail to find out.

    `service <name> status` exits non-zero both for "not running" and for "this
    rc script has no status command", and under `security.bsd.see_other_uids=0`
    an unprivileged caller is told "not running" about a live daemon. So the
    exit code alone is not an answer: the sentence rc.subr prints is. Anything
    else comes back as ``None`` and the caller reports `unverified` rather than
    inventing a verdict.
    """
    r = run(["service", name, "status"], timeout=10)
    text = (r.stdout or "") + (r.stderr or "")
    if "is not running" in text:
        return False
    if "is running" in text:
        return True
    return True if r.ok else None


def _awg0_running() -> tuple[bool | None, str]:
    r = run(["ifconfig", "awg0"], timeout=3)
    output = r.stdout + r.stderr
    if r.ok:
        return ("UP" in r.stdout), output
    if "does not exist" in output:
        return False, output
    return None, output


def service_control(name: str, action: str) -> tuple[int, dict[str, Any]]:
    """Run the action, then look at the world and report what it says.

    The old body returned `{"ok": r.ok, "output": ...}` and the panel printed
    `r.active` -- a field that was never in the reply, so every press toasted
    "unbound: undefined" in green, including the presses that did nothing. The
    exit code of `service(8)` is not the state of the service: `restart` on a
    daemon that dies on its config exits 0 just as happily.
    """
    if name not in ALLOWED_SERVICES:
        return 403, {"error": f"service {name!r} not allowed"}
    if action not in {"start", "stop", "restart", "status", "enable", "disable"}:
        return 400, {"error": f"invalid action: {action}"}

    if name == "awg0":
        if action in {"enable", "disable"}:
            r = run(["service", "amnezia", action], timeout=15)
            output = r.stdout + r.stderr
            payload: dict[str, Any] = {"output": output}
            if not r.ok:
                block = action_state.failed(name, f"{name}: command failed", action_name=action)
                return 500, action_state.attach(payload, block)
            block = action_state.unverified(
                name,
                f"{name}: {'enabled' if action == 'enable' else 'disabled'} in rc.conf, "
                "live service state unchanged",
                action_name=action,
            )
            return 200, action_state.attach(payload, block)
        if action == "status":
            running, output = _awg0_running()
            payload = {"output": output, "running": running}
            if running is None:
                block = action_state.unknown(name, f"{name}: state not readable", action_name=action)
            else:
                block = action_state.done(
                    name,
                    f"{name}: {'running' if running else 'stopped'}",
                    action_name=action,
                    running=running,
                )
            return 200, action_state.attach(payload, block)
        ctl_action = "down" if action == "stop" else "apply"
        r = run(["/usr/local/sbin/gatewayctl", ctl_action], timeout=45)
        output = r.stdout + r.stderr
        payload = {"output": output}
        if not r.ok:
            block = action_state.failed(name, f"{name}: command failed", action_name=action)
            return 500, action_state.attach(payload, block)
        running, _ = _awg0_running()
        payload["running"] = running
        wanted = action in {"start", "restart"}
        if running is None:
            block = action_state.unverified(
                name,
                f"{name}: command succeeded, service state could not be read",
                action_name=action,
                running=None,
            )
        elif running is wanted:
            block = action_state.done(
                name,
                f"{name}: {'running' if running else 'stopped'}",
                action_name=action,
                running=running,
            )
        else:
            block = action_state.failed(
                name,
                f"{name}: command succeeded, but service {'did not start' if wanted else 'is still running'}",
                action_name=action,
                running=running,
            )
        return 200, action_state.attach(payload, block)

    rc_name = "isc-dhcpd" if name == "dhcpd" else name
    r = run(["service", rc_name, action], timeout=15)
    output = r.stdout + r.stderr
    payload = {"output": output}

    if not r.ok and action != "status":
        block = action_state.failed(name, f"{name}: command failed", action_name=action)
        return 500, action_state.attach(payload, block)

    if action == "status":
        # A read, not a write: the outcome *is* the state, and `service` exits
        # non-zero to mean "stopped" rather than "the read failed".
        running = service_running(rc_name) if not output.strip() else (
            False if "is not running" in output else True if "is running" in output else None
        )
        payload["running"] = running
        if running is None:
            block = action_state.unknown(name, f"{name}: state not readable", action_name=action)
        else:
            block = action_state.done(
                name,
                f"{name}: {'running' if running else 'stopped'}",
                action_name=action,
                running=running,
            )
        return 200, action_state.attach(payload, block)

    if action in {"enable", "disable"}:
        # `service <name> enable` writes rc.conf; confirming it means mapping a
        # service name onto its rcvar (isc-dhcpd -> dhcpd_enable), and that map
        # is exactly the kind of guess this module exists to refuse.
        block = action_state.unverified(
            name,
            f"{name}: {'enabled' if action == 'enable' else 'disabled'} in rc.conf, "
            "live service state unchanged",
            action_name=action,
        )
        return 200, action_state.attach(payload, block)

    running = service_running(rc_name)
    payload["running"] = running
    wanted = action in {"start", "restart"}
    if running is None:
        block = action_state.unverified(
            name,
            f"{name}: command succeeded, service state could not be read",
            action_name=action,
            running=None,
        )
    elif running is wanted:
        block = action_state.done(
            name,
            f"{name}: {'running' if running else 'stopped'}",
            action_name=action,
            running=running,
        )
    else:
        block = action_state.failed(
            name,
            f"{name}: command succeeded, but service {'did not start' if wanted else 'is still running'}",
            action_name=action,
            running=running,
        )
    return 200, action_state.attach(payload, block)


ALLOWED_RC_CONF_KEYS = frozenset({
    "hostname", "defaultrouter", "ipv6_defaultrouter", "gateway_enable", "ipv6_gateway_enable",
    "pf_enable", "pflog_enable", "unbound_enable", "dhcpd_enable", "dhcpd_ifaces",
    "mpd_enable", "mpd_flags", "ntpd_enable", "ntpd_sync_on_start", "sshd_enable",
    "nginx_enable", "smartd_enable", "nut_enable", "nut_upslog_enable", "nut_upsmon_enable",
    "gatebsd_enable", "gatebsd_failover_enable", "gatebsd_reverse_ssh_enable",
    "gatewayctl_apply_enable", "ru_bypass_enable", "amnezia_enable",
    "cloned_interfaces", "autobridge_interfaces",
})
_RC_CONF_IFACE_KEY_RE = re.compile(r"^(?:ifconfig|vlans|create_args|autobridge)_[A-Za-z0-9_]{1,31}$")
_RC_CONF_VALUE_UNSAFE = "\x00\r\n$`\\\"';|&<>"


def rcconf() -> tuple[int, dict[str, Any]]:
    """Read rc.conf as key/value (redacting secrets)."""
    from ..adapters import parse_key_value_file
    data = parse_key_value_file(str(paths.RC_CONF))
    return 200, {"rcconf": data}


def rcconf_set(key_value: object, value_value: object) -> tuple[int, dict[str, Any]]:
    """Safely update one rc.conf assignment under an inter-process lock."""
    from .. import backup
    from ..fsutil import exclusive_lock

    if not isinstance(key_value, str) or (
        key_value not in ALLOWED_RC_CONF_KEYS and _RC_CONF_IFACE_KEY_RE.fullmatch(key_value) is None
    ):
        return 400, {"error": "invalid rc.conf key"}
    if (
        not isinstance(value_value, str)
        or len(value_value) > 4096
        or any(ch in value_value for ch in _RC_CONF_VALUE_UNSAFE)
    ):
        return 400, {"error": "invalid rc.conf value"}

    key = key_value
    value = value_value
    rc_conf = paths.RC_CONF
    lock_path = rc_conf.with_suffix(rc_conf.suffix + ".gatebsd.lock")
    try:
        with exclusive_lock(lock_path):
            if rc_conf.is_symlink() or not rc_conf.is_file():
                return 409, {"error": "refusing unsafe rc.conf"}
            original = rc_conf.read_text(encoding="utf-8", errors="strict")
            lines = original.splitlines()
            assignment = re.compile(rf"^\s*{re.escape(key)}\s*=")
            escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
            replacement = f'{key}="{escaped}"'
            output: list[str] = []
            replaced = False
            for line in lines:
                if assignment.match(line):
                    if not replaced and value:
                        output.append(replacement)
                    replaced = True
                else:
                    output.append(line)
            if not replaced and value:
                output.append(replacement)
            new_content = "\n".join(output).rstrip("\n") + "\n"
            if new_content == original:
                return 200, {"ok": True, "key": key, "value": value, "changed": False}
            backup_meta = backup.backup_files([rc_conf], reason="rcconf-edit")
            atomic_write_text(rc_conf, new_content, preserve_metadata=True)
            return 200, {"ok": True, "key": key, "value": value, "changed": True, "backup": backup_meta}
    except (OSError, UnicodeError) as exc:
        return 500, {"error": f"failed to update rc.conf: {exc}"}
