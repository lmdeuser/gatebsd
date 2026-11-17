"""gatebsd_ui.api — URL dispatcher for gatebsd (FreeBSD edition)."""
from __future__ import annotations

import fcntl
import ipaddress
import os
import re
import stat
from pathlib import Path
from typing import Any

from . import action_state, adapters, adblock, backup, diagnostics, discovery, failover as failover_probe, routing, ru_table, storage, tls, vpn_policy, writers
from .adapters import RU_TABLE
from .adapters.helpers import VPN_IF, _safe_config_text
from .command import run
from .auth import authorized_system_user, valid_password_text, valid_username, verify_system_password
from .fsutil import atomic_write_bytes, exclusive_lock

MIN_BYPASS_PREFIX_LEN = int(os.environ.get("GATEBSD_RU_MIN_PREFIX_LEN", "8"))
if not (1 <= MIN_BYPASS_PREFIX_LEN <= 32):
    MIN_BYPASS_PREFIX_LEN = 8


def _normalize_pf_values(value: object) -> tuple[list[str] | None, str | None]:
    if not isinstance(value, list) or not 1 <= len(value) <= 4096:
        return None, "values must be a list containing 1-4096 networks"
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            return None, "values must contain only strings"
        candidate = item.strip()
        if not candidate or any(ch in candidate for ch in "\x00\r\n\t "):
            return None, f"invalid IPv4 network: {item!r}"
        try:
            network = ipaddress.ip_network(candidate, strict=True)
        except ValueError:
            return None, f"invalid IPv4 network: {candidate}"
        if network.version != 4:
            return None, f"IPv6 is not supported in this table: {candidate}"
        # 0.0.0.0/0 is the default route on FreeBSD. Accepting it here would let
        # a bypass entry hijack the default route and then delete it when the
        # table is cleared, leaving the site with no route out. The floor must
        # match MIN_PREFIX_LEN in sbin/ru-routes.sh, or an entry accepted by the
        # API would fail every subsequent route transaction.
        if network.prefixlen < MIN_BYPASS_PREFIX_LEN:
            return None, (
                f"prefix /{network.prefixlen} is too broad; "
                f"minimum is /{MIN_BYPASS_PREFIX_LEN}"
            )
        canonical = network.with_prefixlen
        if canonical not in seen:
            normalized.append(canonical)
            seen.add(canonical)
    return normalized, None


def _pf_table_entries(content: bytes) -> set[str]:
    entries: set[str] = set()
    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(b"#"):
            continue
        try:
            entries.add(stripped.decode("ascii"))
        except UnicodeDecodeError:
            # Preserve unknown bytes in the file but never match them to an API
            # supplied network value.
            continue
    return entries


def _pf_table_add(body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Atomically add validated IPv4 networks to the RU bypass table."""
    values, error = _normalize_pf_values(body.get("values"))
    if values is None:
        return 400, {"error": error}
    table_path = Path(str(RU_TABLE))
    lock_path = table_path.with_suffix(table_path.suffix + ".lock")
    try:
        with exclusive_lock(lock_path):
            try:
                metadata = table_path.lstat()
            except FileNotFoundError:
                metadata = None
            if metadata is not None and not stat.S_ISREG(metadata.st_mode):
                return 409, {"error": "refusing unsafe table path"}
            existing_content = ru_table.read_regular(table_path, missing_ok=True)
            existing = _pf_table_entries(existing_content)
            added = [value for value in values if value not in existing]
            if not added:
                # The panel used to toast `values.length` -- what the operator
                # typed, never what the table took. Re-entering five addresses
                # that were already there reported "5 entries processed".
                return 200, action_state.attach(
                    {"added": 0, "total": len(existing), "requested": len(values)},
                    action_state.done(
                        "ru_bypass",
                        f"added 0 of {len(values)}: all addresses already in table",
                        action_name="add",
                        added=0,
                        requested=len(values),
                    ),
                )
            if metadata is not None:
                backup.backup_files([table_path], reason="pf-table-add")
            separator = b"" if not existing_content or existing_content.endswith((b"\n", b"\r")) else b"\n"
            new_content = existing_content + separator + b"".join(value.encode("ascii") + b"\n" for value in added)
            atomic_write_bytes(
                table_path,
                new_content,
                mode=0o640,
                preserve_metadata=metadata is not None,
            )
            payload = action_state.attach(
                {"added": len(added), "total": len(existing | set(added)), "requested": len(values)},
                action_state.done(
                    "ru_bypass",
                    f"added {len(added)} of {len(values)}, {len(existing | set(added))} in table",
                    action_name="add",
                    added=len(added),
                    requested=len(values),
                ),
            )
    except OSError as exc:
        return 500, {"error": f"failed to update table: {exc}"}
    vpn_policy.trigger_route_convergence()
    return 200, payload


def _pf_table_remove(body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Atomically remove validated IPv4 networks without rewriting other bytes."""
    values, error = _normalize_pf_values(body.get("values"))
    if values is None:
        return 400, {"error": error}
    wanted = set(values)
    table_path = Path(str(RU_TABLE))
    lock_path = table_path.with_suffix(table_path.suffix + ".lock")
    try:
        with exclusive_lock(lock_path):
            try:
                metadata = table_path.lstat()
            except FileNotFoundError:
                return 404, {"error": "table not found"}
            if not stat.S_ISREG(metadata.st_mode):
                return 409, {"error": "refusing unsafe table path"}
            content = ru_table.read_regular(table_path)
            kept: list[bytes] = []
            removed = 0
            for raw_line in content.splitlines(keepends=True):
                stripped = raw_line.strip()
                try:
                    value = stripped.decode("ascii")
                except UnicodeDecodeError:
                    value = ""
                if stripped and not stripped.startswith(b"#") and value in wanted:
                    removed += 1
                else:
                    kept.append(raw_line)
            if removed == 0:
                return 200, action_state.attach(
                    {"removed": 0, "requested": len(values)},
                    action_state.done(
                        "ru_bypass",
                        f"removed 0 of {len(values)}: none of these addresses in table",
                        action_name="remove",
                        removed=0,
                        requested=len(values),
                    ),
                )
            backup.backup_files([table_path], reason="pf-table-remove")
            atomic_write_bytes(table_path, b"".join(kept), preserve_metadata=True)
            payload = action_state.attach(
                {"removed": removed, "requested": len(values)},
                action_state.done(
                    "ru_bypass",
                    f"removed {removed} of {len(values)}",
                    action_name="remove",
                    removed=removed,
                    requested=len(values),
                ),
            )
    except OSError as exc:
        return 500, {"error": f"failed to update table: {exc}"}
    vpn_policy.trigger_route_convergence()
    return 200, payload


def _vpn_status() -> dict[str, Any]:
    """Real VPN status from gatewayctl."""
    from .command import run
    r = run(["/usr/local/sbin/gatewayctl", "status"], timeout=5)
    output = r.stdout
    # Two different facts, and they are not the same one twice. `active` is "the
    # interface is up"; `is_default` is "the tunnel carries the default route".
    # A tunnel can be up and bypassed -- that is the state the whole vpn_path
    # work exists for.
    #
    # And neither may be reported as False when the truth is that gatewayctl
    # could not be read. "Not measured" is not "off"; this project has paid for
    # that confusion four times. None means unknown, and the panel says so.
    if not output.strip():
        active: bool | None = None
        is_default: bool | None = None
    else:
        active = any(VPN_IF in line and "UP" in line for line in output.splitlines())
        default_iface = ""
        for line in output.splitlines():
            if "interface:" in line:
                default_iface = line.split("interface:")[-1].strip()
                break
        is_default = default_iface == VPN_IF
    return {
        "active": active,
        "interface": VPN_IF,
        "is_default": is_default,
        "output": output,
    }


def _vpn_profiles() -> dict[str, Any]:
    """List validated AWG profiles without exposing secrets."""
    return writers.awg_profiles()


def _secureboot_status() -> dict[str, Any]:
    """Report capability honestly; Linux MOK enrollment is not a FreeBSD feature."""
    return {
        "supported": False,
        "enabled": False,
        "enrolled": False,
        "message": "Secure Boot key enrollment is not managed by GateBSD on FreeBSD",
    }


def _internet_repair() -> tuple[int, dict[str, Any]]:
    """Run the serialized, dependency-aware one-click recovery workflow."""
    from .recovery import recover_internet
    return recover_internet()


def _amnezia_repo_status() -> dict[str, Any]:
    """Check if amnezia packages are installed."""
    from .command import run
    r = run(["pkg", "info", "amnezia-kmod"], timeout=3)
    installed = r.ok and "amnezia-kmod" in (r.stdout or "")
    # Get list of all amnezia packages
    r2 = run(["pkg", "info", "-x", "amnezia"], timeout=3)
    packages = r2.stdout.strip() if r2.ok else ""
    return {"installed": installed, "packages": packages}


def _ups_config() -> dict[str, Any]:
    """Read structured NUT configuration without returning credentials."""
    return writers.ups_config()


import base64
import binascii
import fcntl
import pty
import pwd
import queue
import select
import signal
import struct
import subprocess
import termios
import threading
import time

def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


_TERMINAL_IDLE_SECONDS = _bounded_env_int("GATEBSD_TERMINAL_IDLE_SECONDS", 900, 60, 86400)
_TERMINAL_MAX_INPUT = _bounded_env_int("GATEBSD_TERMINAL_MAX_INPUT", 64 * 1024, 1024, 1024 * 1024)
_TERMINAL_MAX_OUTPUT = _bounded_env_int("GATEBSD_TERMINAL_MAX_OUTPUT", 256 * 1024, 4096, 4 * 1024 * 1024)
_TERMINAL_MAX_SESSIONS = _bounded_env_int("GATEBSD_TERMINAL_MAX_SESSIONS", 8, 1, 64)


_TERMINAL_DEFAULT_ROWS = 24
_TERMINAL_DEFAULT_COLS = 80
# xterm.js will not propose anything larger, and an unbounded value from the
# browser reaches ioctl(2) as a struct field.
_TERMINAL_MAX_ROWS = 1000
_TERMINAL_MAX_COLS = 1000


class TerminalSession:
    """One PTY owned by one authenticated system-login session."""

    def __init__(self, username: str, argv: list[str] | None = None):
        self.username = username
        self.output_queue: queue.Queue[bytes] = queue.Queue(maxsize=256)
        self.alive = True
        self.last_activity = time.monotonic()
        self.returncode: int | None = None

        # Everything the child needs is built before the fork. Between fork and
        # exec only async-signal-safe work is allowed, and this server is
        # threaded: allocating or taking a lock in the child can deadlock it.
        #
        # argv is overridden only by the regression harness, which has to fork a
        # program it can interrogate: su(1) wants an account and a password
        # database, while what is under test is how the child is forked. No
        # request path reaches this argument.
        argv = list(argv) if argv else ["/usr/bin/su", "-l", username]
        env = {
            "PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": "/home/" + username if username != "root" else "/root",
        }

        # forkpty(3), not openpty(3) plus Popen. The previous form allocated a
        # pty and handed the slave to the child as its three standard streams,
        # which looks equivalent and is not: `start_new_session=True` calls
        # setsid(2), and a session leader created that way has *no* controlling
        # terminal. An inherited descriptor does not become one -- on FreeBSD
        # that takes TIOCSCTTY, which nothing here issued.
        #
        # So the shell could not tcsetpgrp() and said "can't set terminal
        # process group"; job control was off, ^C reached nobody, and top, vi
        # and less misbehaved. forkpty() goes through login_tty(3), which is
        # setsid() *and* TIOCSCTTY, in the child, in the right order.
        pid, master_fd = pty.fork()
        if pid == 0:
            try:
                os.execve(argv[0], argv, env)
            except BaseException:
                os._exit(126)
            os._exit(126)

        self.pid = pid
        self.master_fd = master_fd
        # A fresh pty is 0x0, and a terminal of no size is the other half of
        # why full-screen programs drew nonsense. The browser sends the real
        # size right after opening; this is what the shell sees until it does.
        self.set_window_size(_TERMINAL_DEFAULT_ROWS, _TERMINAL_DEFAULT_COLS)

        self.read_thread = threading.Thread(
            target=self._read_loop,
            daemon=True,
            name=f"gatebsd-terminal-{username}-{pid}",
        )
        self.read_thread.start()

    def set_window_size(self, rows: int, cols: int) -> None:
        rows = max(1, min(int(rows), _TERMINAL_MAX_ROWS))
        cols = max(1, min(int(cols), _TERMINAL_MAX_COLS))
        packed = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, packed)
        # The kernel raises SIGWINCH on the foreground process group of the
        # pty, so a running top or vi redraws itself. Only a session with a
        # controlling terminal has such a group, which is why this could not
        # have worked before the fix above.
        self.last_activity = time.monotonic()

    def _reap(self) -> int | None:
        """Collect the child's status without blocking, and remember it.

        Popen used to own this. waitpid(2) answers once per child, so the
        answer is cached: asking twice would raise ChildProcessError and be
        read as "still running".
        """
        if self.returncode is not None:
            return self.returncode
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.returncode = -1
            return self.returncode
        except OSError:
            return None
        if pid == 0:
            return None
        self.returncode = status
        return self.returncode

    def _read_loop(self) -> None:
        while self.alive:
            try:
                readable, _, _ = select.select([self.master_fd], [], [], 0.25)
                if not readable:
                    continue
                data = os.read(self.master_fd, 4096)
                if not data:
                    break
                self.last_activity = time.monotonic()
                try:
                    self.output_queue.put_nowait(data)
                except queue.Full:
                    try:
                        self.output_queue.get_nowait()
                    except queue.Empty:
                        pass
                    try:
                        self.output_queue.put_nowait(data)
                    except queue.Full:
                        pass
            except (OSError, ValueError):
                break
        self.alive = False

    def is_running(self) -> bool:
        return self.alive and self._reap() is None

    def is_idle(self) -> bool:
        return time.monotonic() - self.last_activity > _TERMINAL_IDLE_SECONDS

    def write(self, data: bytes) -> None:
        if not self.is_running():
            raise OSError("terminal session is not running")
        if len(data) > _TERMINAL_MAX_INPUT:
            raise ValueError("terminal input is too large")
        os.write(self.master_fd, data)
        self.last_activity = time.monotonic()

    def read(self, timeout: float = 1.0) -> bytes:
        chunks: list[bytes] = []
        total = 0
        try:
            first = self.output_queue.get(timeout=timeout)
            chunks.append(first)
            total += len(first)
        except queue.Empty:
            return b""
        while total < _TERMINAL_MAX_OUTPUT:
            try:
                chunk = self.output_queue.get_nowait()
            except queue.Empty:
                break
            remaining = _TERMINAL_MAX_OUTPUT - total
            chunks.append(chunk[:remaining])
            total += min(len(chunk), remaining)
        self.last_activity = time.monotonic()
        return b"".join(chunks)

    def _wait(self, timeout: float) -> bool:
        """Poll for the child to exit. True if it did."""
        deadline = time.monotonic() + timeout
        while True:
            if self._reap() is not None:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)

    def close(self) -> None:
        if not self.alive and self._reap() is not None:
            return
        self.alive = False
        # The child is a session leader, so its pid is its process group id --
        # that is what forkpty() arranged, and it is why signalling the group
        # reaches the shell and everything it started.
        for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(self.pid, sig)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            if self._wait(2):
                break
        try:
            os.close(self.master_fd)
        except OSError:
            pass
        if self.read_thread.is_alive():
            self.read_thread.join(timeout=1)


_TERM_LOCK = threading.RLock()
_TERM_SESSIONS: dict[str, TerminalSession] = {}


def _terminal_identity(query: dict[str, list[str]]) -> tuple[str | None, str | None]:
    auth_mode = (query.get("_auth_mode") or [""])[0]
    if auth_mode not in {"system", "sudo"}:
        return None, "terminal is available only for authenticated system accounts"
    username = (query.get("_user") or [""])[0]
    session_id = (query.get("_session") or [""])[0]
    if not valid_username(username) or not re.fullmatch(r"[0-9a-f]{64}", session_id):
        return None, "terminal requires an authenticated system account"
    try:
        pwd.getpwnam(username)
    except KeyError:
        return None, "authenticated user is not a local system account"
    return f"{username}:{session_id}", None


def _cleanup_terminal_sessions() -> None:
    stale: list[str] = []
    for key, session in _TERM_SESSIONS.items():
        if not session.is_running() or session.is_idle():
            stale.append(key)
    for key in stale:
        session = _TERM_SESSIONS.pop(key, None)
        if session is not None:
            session.close()


def _get_terminal_session(query: dict[str, list[str]]) -> tuple[TerminalSession | None, str | None]:
    identity, error = _terminal_identity(query)
    if identity is None:
        return None, error
    username = identity.split(":", 1)[0]
    with _TERM_LOCK:
        _cleanup_terminal_sessions()
        session = _TERM_SESSIONS.get(identity)
        if session is None or not session.is_running():
            if session is not None:
                session.close()
            if len(_TERM_SESSIONS) >= _TERMINAL_MAX_SESSIONS:
                return None, "terminal session limit reached"
            session = TerminalSession(username)
            _TERM_SESSIONS[identity] = session
        return session, None


def terminal_read(query: dict[str, list[str]]) -> tuple[int, dict[str, Any]]:
    try:
        session, error = _get_terminal_session(query)
        if session is None:
            return 403, {"error": error or "terminal unavailable"}
        data = session.read(timeout=1.0)
        return 200, {"data": base64.b64encode(data).decode("ascii")}
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return 500, {"error": f"terminal unavailable: {exc}"}


def terminal_write(query: dict[str, list[str]], data_b64: object) -> tuple[int, dict[str, Any]]:
    if not isinstance(data_b64, str):
        return 400, {"error": "terminal data must be base64 text"}
    try:
        data = base64.b64decode(data_b64, validate=True)
    except (ValueError, binascii.Error):
        return 400, {"error": "invalid terminal data"}
    if len(data) > _TERMINAL_MAX_INPUT:
        return 413, {"error": "terminal input is too large"}
    try:
        session, error = _get_terminal_session(query)
        if session is None:
            return 403, {"error": error or "terminal unavailable"}
        session.write(data)
        return 200, {"ok": True}
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return 500, {"error": f"terminal unavailable: {exc}"}


def terminal_resize(
    query: dict[str, list[str]], rows: object, cols: object
) -> tuple[int, dict[str, Any]]:
    """Carry the browser's window size down to the pty.

    /api/terminal/resize was already named in the agent's identity-bearing
    paths, and nothing implemented it: no handler here, no caller in app.js.
    The pty therefore stayed at the 0x0 a fresh one is born with, while the
    frontend's fit addon resized only the widget in the page. That is why full
    screen programs drew at the wrong size even once they had a real terminal.
    """
    try:
        want_rows = int(rows)
        want_cols = int(cols)
    except (TypeError, ValueError):
        return 400, {"error": "terminal size must be two integers"}
    if want_rows < 1 or want_cols < 1:
        return 400, {"error": "terminal size must be positive"}
    try:
        session, error = _get_terminal_session(query)
        if session is None:
            return 403, {"error": error or "terminal unavailable"}
        session.set_window_size(want_rows, want_cols)
        return 200, {"ok": True}
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return 500, {"error": f"terminal unavailable: {exc}"}


def terminal_close(query: dict[str, list[str]]) -> tuple[int, dict[str, Any]]:
    identity, error = _terminal_identity(query)
    if identity is None:
        return 403, {"error": error or "terminal unavailable"}
    with _TERM_LOCK:
        session = _TERM_SESSIONS.pop(identity, None)
    if session is not None:
        session.close()
    return 200, {"ok": True}


def _get_interface_gateway(iface: str) -> str | None:
    if not _valid_interface_name(iface):
        return None
    if iface.startswith("ng"):
        r = run(["ifconfig", iface])
        if r.ok:
            m = re.search(r"-->\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", r.stdout)
            if m:
                return m.group(1)
    
    lease_file = Path(f"/var/db/dhclient.leases.{iface}")
    content = _safe_config_text(lease_file, limit=1024 * 1024)
    matches = re.findall(r"option\s+routers\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3});", content)
    for candidate in reversed(matches):
        try:
            return str(ipaddress.IPv4Address(candidate))
        except ipaddress.AddressValueError:
            continue
    return None


_INTERFACE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,31}")
_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")


def _valid_interface_name(value: object) -> bool:
    return isinstance(value, str) and _INTERFACE_RE.fullmatch(value) is not None


def _wan_test(iface: str) -> tuple[int, dict[str, Any]]:
    if not _valid_interface_name(iface):
        return 400, {"error": "invalid interface"}
    if iface == failover_probe.WAN_IF:
        fib_key, default_fib = "PRIMARY_FIB", 1
    elif iface == failover_probe.BACKUP_IF:
        fib_key, default_fib = "BACKUP_FIB", 2
    else:
        return 400, {"error": "interface is not a configured WAN"}

    config = failover_probe._raw_key_values(failover_probe.paths.FAILOVER_CONF)
    fib = failover_probe._positive_int(config.get(fib_key), default_fib)
    timeout_s = max(1, failover_probe._positive_int(config.get("PING_TIMEOUT"), 2))
    targets = [item for item in config.get("CHECK_TARGETS", "1.1.1.1 8.8.8.8 9.9.9.9").split() if item]
    link = failover_probe._check_gateway(iface)
    try:
        gateway = str(ipaddress.IPv4Address(link.get("gateway") or ""))
    except ipaddress.AddressValueError:
        gateway = ""
    if not gateway:
        return 200, {
            "ok": False,
            "avg_ms": 0.0,
            "loss_pct": 100.0,
            "error": f"no gateway found for {iface}",
            "fib": fib,
        }

    ping = failover_probe._check_ping(fib, str(link.get("local_ip") or ""), targets, timeout_s)
    checks = {
        "internet_ping": ping,
        "tcp_443": failover_probe._check_tcp(fib=fib),
        "dns": failover_probe._check_dns(fib=fib),
        "https": failover_probe._check_https(fib=fib),
    }
    return 200, {
        "ok": all(checks[name]["ok"] for name in ("tcp_443", "dns", "https")),
        "avg_ms": ping.get("latency_ms") or 0.0,
        "loss_pct": 0.0 if ping["ok"] else 100.0,
        "gateway": gateway,
        "fib": fib,
        "checks": checks,
    }


def dispatch(path: str, query: dict[str, list[str]] | None = None,
             method: str = "GET",
             body: dict[str, Any] | None = None) -> tuple[int, dict | list]:
    query = query or {}

    # ── GET ──────────────────────────────────────────────────────────────────
    get_routes = {
        "/api/terminal/read":      lambda: terminal_read(query),
        "/api/overview":           adapters.overview,
        "/api/system":             adapters.system_info,
        "/api/memory":             adapters.memory_info,
        "/api/disks":              adapters.disks,
        "/api/interfaces":         adapters.interfaces,
        "/api/physical_ports":     adapters.physical_ports,
        "/api/wan":                adapters.wan_status,
        "/api/services":           adapters.services,
        "/api/services/all":       adapters.all_services,
        "/api/stats/traffic":      adapters.traffic_stats,
        "/api/health":             adapters.health,
        "/api/history":            storage.history,
        "/api/backups":            backup.list_backups,
        "/api/backups/diff":       lambda: backup.diff_backup(query.get("file", [""])[0]),
        "/api/logs":               lambda: adapters.logs(query),
        "/api/firewall":           adapters.firewall,
        "/api/firewall/detail":    adapters.firewall_detail,
        "/api/dhcp":               adapters.dhcpd,
        "/api/clients":            adapters.lan_clients,
        "/api/pppoe":              adapters.pppoe,
        "/api/modem":              adapters.modem,
        "/api/amnezia":            adapters.amnezia,
        "/api/ups":                adapters.ups,
        "/api/system/updates":     writers.pkg_updates,
        "/api/system/updates/log": writers.pkg_upgrade_log,
        "/api/pf/conf":            writers.pf_get_conf,
        "/api/pf/conf/pending":    writers.pf_pending_commit,
        "/api/port-forwards":      writers.port_forward_list,
        "/api/reverse-ssh":        writers.reverse_ssh_list,
        "/api/dhcp/conf":          writers.dhcpd_get_conf,
        "/api/dns/conf":           writers.unbound_get_conf,
        "/api/dns/split":          writers.dns_split_get,
        "/api/repo/sources":       writers.repo_sources,
        "/api/rcconf":             writers.rcconf,
        "/api/discovery":          adapters.discovery,
        "/api/import":             lambda: discovery.load(),
        "/api/split-tunnel":       routing.split_tunnel,
        "/api/diagnostics":        diagnostics.snapshot,
        "/api/failover":           adapters.failover_status,
        "/api/vpn/peers":          lambda: writers.awg_peer_list(query.get("name", ["awg0"])[0]),
        "/api/vpn":                _vpn_status,
        "/api/vpn/status":         _vpn_status,
        "/api/vpn/profiles":       _vpn_profiles,
        "/api/vpn/exceptions":     vpn_policy.status,
        "/api/adblock/status":      adblock.status,
        "/api/adblock/rules":       adblock.rules,
        "/api/tls/status":         tls.status,
        "/api/secureboot/status":  _secureboot_status,
        "/api/amnezia/repository/status": _amnezia_repo_status,
        "/api/ups/config":         _ups_config,
        "/api/zfs":              adapters.zfs_pools,
        "/api/disks/io":         adapters.disk_io,
        "/api/disks/smart":      lambda: adapters.smart_details(query.get("device", [""])[0]),
    }

    if method == "GET" and path in get_routes:
        result = get_routes[path]()
        if isinstance(result, tuple):
            return result
        return 200, result

    # ── POST ─────────────────────────────────────────────────────────────────
    if method == "POST":
        b = body or {}

        if path == "/api/internet/repair":
            return _internet_repair()

        # Auth — system login via /etc/master.passwd
        if path == "/api/auth/login":
            username = b.get("username", "")
            password = b.get("password", "")
            if verify_system_password(username, password) and authorized_system_user(username):
                return 200, {"authenticated": True, "username": username}
            return 401, {"authenticated": False}
        if path == "/api/auth/password":
            username = query.get("_user", [""])[0]
            current_password = b.get("current_password", "")
            password = b.get("password", "")
            if not valid_username(username):
                return 400, {"error": "invalid authenticated username"}
            if not isinstance(current_password, str) or not current_password or not verify_system_password(username, current_password):
                return 403, {"error": "current password is incorrect"}
            if not valid_password_text(password, minimum=8, maximum=1024):
                return 400, {"error": "password must be 8-1024 characters without NUL or newlines"}
            changed = run(["pw", "moduser", username, "-h", "0"], timeout=15, input=password + "\n")
            if changed.ok:
                return 200, {"ok": True}
            return 500, {
                "error": "failed to change system password",
                "detail": changed.stderr or changed.stdout or changed.error or "",
            }

        # System
        if path == "/api/system/upgrade":
            # Never run the upgrade inside the request: it fetches hundreds of
            # megabytes and then replaces packages, and one of those packages is
            # GateBSD itself, so a synchronous call kills the process serving
            # the request mid-transaction. The worker reports progress through
            # /api/system/updates/log.
            return writers.pkg_upgrade_start()

        # PF
        if path == "/api/pf/reload":
            return writers.pf_reload()
        if path == "/api/pf/conf":
            conf = b.get("conf", "")
            if not conf:
                return 400, {"error": "conf required"}
            # A ruleset that removes management access is refused unless the
            # caller explicitly accepts the risk, and any accepted change must
            # be confirmed through the new ruleset or it is reverted.
            allow_lockout = b.get("allow_lockout") is True
            require_confirmation = b.get("skip_confirmation") is not True
            return writers.pf_set_conf(
                conf,
                allow_lockout=allow_lockout,
                require_confirmation=require_confirmation,
            )
        if path == "/api/pf/conf/confirm":
            return writers.pf_confirm_conf()
        if path == "/api/port-forwards/save":
            return writers.port_forward_save(b)
        if path == "/api/port-forwards/delete":
            return writers.port_forward_delete(b.get("id"))
        if path == "/api/port-forwards/test":
            return writers.port_forward_test(b.get("id"))
        if path == "/api/reverse-ssh/save":
            return writers.reverse_ssh_save(b)
        if path == "/api/reverse-ssh/delete":
            return writers.reverse_ssh_delete(b.get("id"))

        # PPPoE / mpd5
        if path in {"/api/pppoe/restart", "/api/pppoe/reconnect"}:
            # The two lines that used to live here stamped `active="restarted"`
            # and `primary="restarted"` onto every 200. Literals, not state:
            # they were true about the call and unknown about the link, and the
            # panel printed them as a connected uplink. `mpd5_restart` now
            # measures the session and says which of the five states it is.
            return writers.mpd5_restart()

        # AmneziaWG / gatewayctl
        if path in {"/api/amnezia/apply", "/api/vpn/apply"}:
            return writers.gatewayctl("apply")
        if path in {"/api/amnezia/down", "/api/vpn/down"}:
            return writers.gatewayctl("down")
        if path in {"/api/amnezia/rollback", "/api/vpn/rollback"}:
            return writers.gatewayctl("rollback")
        if path == "/api/vpn/init/pf":
            return writers.gatewayctl("reload")
        if path == "/api/vpn/init/routes":
            return writers.gatewayctl("apply")
        if path == "/api/amnezia/status":
            return writers.gatewayctl("status")
        if path == "/api/amnezia/ru_bypass/update":
            return writers.ru_bypass_update()
        if path == "/api/amnezia/config":
            name = b.get("name", "")
            text = b.get("conf", "")
            if not name or not text:
                return 400, {"error": "name and conf required"}
            return writers.awg_set_config(name, text)
        if path == "/api/amnezia/activate":
            name = b.get("name", "")
            if not name:
                return 400, {"error": "name required"}
            return writers.awg_activate(name)
        if path == "/api/vpn/profile/switch":
            return writers.awg_activate(b.get("id", ""))
        if path == "/api/vpn/stop":
            return writers.awg_stop()
        if path == "/api/vpn/profile/upload":
            status, payload = writers.awg_set_config(b.get("name", ""), b.get("content", ""))
            if status == 200:
                profile_id = str(b.get("name", ""))
                payload["profile"] = {
                    "id": profile_id,
                    "name": profile_id,
                    "path": payload.get("path", ""),
                }
            return status, payload
        if path == "/api/vpn/profile/delete":
            return writers.awg_delete_profile(b.get("id", ""))
        if path == "/api/adblock/update":
            return adblock.update()
        if path == "/api/adblock/probe":
            return adblock.dns_probe(b.get("blocked"), b.get("control"), b.get("verdict"))
        if path == "/api/adblock/rules/add":
            return adblock.change_rule(b.get("value"), kind=b.get("kind"), add=True)
        if path == "/api/adblock/rules/remove":
            return adblock.change_rule(b.get("value"), kind=b.get("kind"), add=False)
        if path == "/api/tls/renew":
            return tls.renew()
        if path == "/api/amnezia/update-ru-ips":
            return writers.ru_bypass_update()
        if path == "/api/amnezia/diagnose":
            return writers.vpn_diagnose(b.get("mode"), b.get("target"))
        if path == "/api/dhcp/range":
            return writers.dhcp_range_set(b.get("start"), b.get("end"), b.get("lease"))
        if path == "/api/dns/upstreams":
            return writers.dns_upstreams_set(b.get("servers"))
        if path == "/api/dns/split":
            return writers.dns_split_set(b.get("domains"), b.get("upstreams"))
        if path == "/api/repo/sources":
            return writers.repo_sources_set(b)
        if path == "/api/repo/scan":
            return writers.repo_scan()
        if path == "/api/secureboot/enroll":
            return 409, {"error": "Secure Boot MOK enrollment is not supported on FreeBSD"}

        if path == "/api/vpn/exceptions/add":
            return vpn_policy.change(b.get("value"), add=True, direction=b.get("direction", "direct"))
        if path == "/api/vpn/exceptions/remove":
            return vpn_policy.change(b.get("value"), add=False)
        if path == "/api/vpn/exceptions/diagnose":
            return vpn_policy.diagnose(b.get("value"), direction=b.get("direction", "direct"))

        # VPN bypass table management (pf tables, replacing nft sets)
        if path == "/api/vpn/nft/plus":
            return _pf_table_add(b)
        if path == "/api/vpn/nft/minus":
            return _pf_table_remove(b)

        # VPN peer management
        if path == "/api/vpn/peers":
            name = b.get("name", "awg0")
            pub = b.get("public_key", "")
            ep = b.get("endpoint", "")
            ips = b.get("allowed_ips", "0.0.0.0/0")
            psk = b.get("preshared_key", "")
            if not pub:
                return 400, {"error": "public_key required"}
            return writers.awg_peer_add(name, pub, ep, ips, psk)
        if path == "/api/vpn/peers/remove":
            name = b.get("name", "awg0")
            pub = b.get("public_key", "")
            if not pub:
                return 400, {"error": "public_key required"}
            return writers.awg_peer_remove(name, pub)
        if path == "/api/vpn/key-rotate":
            name = b.get("name", "awg0")
            return writers.awg_key_rotate(name)

        # DHCP
        if path == "/api/dhcp/restart":
            return writers.dhcpd_restart()

        # DNS
        if path == "/api/dns/restart":
            return writers.unbound_restart()

        # UPS
        if path == "/api/ups/restart":
            return writers.nut_restart()

        # Generic service control
        if path in {"/api/service/control", "/api/services/manage"}:
            name = b.get("name", "") or b.get("unit", "")
            action = b.get("action", "")
            return writers.service_control(name, action)

        # Failover control
        if path == "/api/failover/mode":
            mode = b.get("mode", "")
            return writers.failover_mode(mode)
        if path == "/api/failover/switch":
            return writers.failover_switch(b.get("target", ""))

        # System power (reboot/poweroff)
        if path == "/api/system/power":
            action = b.get("action", "")
            if action not in ("reboot", "poweroff"):
                return 400, {"error": "action must be reboot or poweroff"}
            import threading
            def _power():
                import time as _time
                _time.sleep(2)
                run(["shutdown", "-r" if action == "reboot" else "-p", "now"], timeout=5)
            threading.Thread(target=_power, daemon=True).start()
            # `{"ok": True}` here was answered two seconds before `shutdown` is
            # even spawned, and it could not be anything else -- a box that has
            # rebooted cannot report that it did. That is not success, it is
            # `in_progress`, and the name now says so.
            return 200, action_state.attach(
                {"requested": action},
                action_state.in_progress(
                    action,
                    "reboot scheduled in 2 seconds"
                    if action == "reboot"
                    else "poweroff scheduled in 2 seconds",
                    action_name=action,
                ),
            )

        if path == "/api/discovery/scan":
            return writers.discovery_scan()
        if path == "/api/import/run":
            return writers.import_existing()
        if path == "/api/backups/create":
            return 200, backup.backup_known_configs(reason="manual-api")
        if path == "/api/diagnose/run":
            tool = str(b.get("tool", "ping"))
            target = str(b.get("target", ""))
            if tool == "traceroute":
                return writers.traceroute(target)
            if tool == "nslookup":
                return writers.nslookup(target)
            if tool == "ping":
                normalized = diagnostics.normalize_target(target)
                if normalized is None:
                    return 400, {"error": "invalid target"}
                r = run(["ping", "-c", "4", normalized], timeout=10)
                return 200, {"ok": r.ok, "output": r.stdout + r.stderr}
            return 400, {"error": "unsupported diagnostic tool"}

        if path == "/api/wan/test":
            iface = b.get("iface", "")
            return _wan_test(iface)

        # Diagnostics
        if path == "/api/diag/traceroute":
            target = b.get("target", "")
            if not target:
                return 400, {"error": "target required"}
            return writers.traceroute(target)
        if path == "/api/diag/nslookup":
            target = b.get("target", "")
            if not target:
                return 400, {"error": "target required"}
            return writers.nslookup(target)

        # Wake on LAN
        if path == "/api/wol":
            mac = b.get("mac", "")
            if not isinstance(mac, str) or _MAC_RE.fullmatch(mac) is None:
                return 400, {"error": "invalid MAC address"}
            mac = mac.lower()
            r = run(["ether-wake", mac], timeout=5)
            if not r.ok:
                # Try wakeonlan package
                r = run(["wakeonlan", mac], timeout=5)
            return (200 if r.ok else 500), {"ok": r.ok, "output": r.stdout + r.stderr}

        if path == "/api/dhcp/static/add":
            return writers.dhcp_static_add(b.get("mac"), b.get("ip"), b.get("hostname", ""))
        if path == "/api/dhcp/static/remove":
            return writers.dhcp_static_remove(b.get("mac"))

        # Backup management
        if path == "/api/backups/delete":
            return backup.delete_backup(b.get("name", "") or b.get("filename", ""))
        if path == "/api/backups/restore":
            return backup.restore_backup(b.get("name", "") or b.get("filename", ""))

        # rc.conf save
        if path == "/api/rcconf":
            return writers.rcconf_set(b.get("key"), b.get("value", ""))

        # System updates (pkg)
        if path == "/api/system/updates/check":
            return writers.pkg_updates(refresh=True)
        if path == "/api/system/updates/install":
            return writers.pkg_upgrade_start()

        # UPS
        if path == "/api/ups/command":
            cmd = str(b.get("command", ""))
            confirmation = str(b.get("confirmation", ""))
            if not cmd:
                return 400, {"error": "command required"}
            return writers.ups_command(cmd, confirmation)
        if path == "/api/ups/config":
            return writers.configure_ups(b)
        if path == "/api/terminal/write":
            return terminal_write(query, b.get("data", ""))
        if path == "/api/terminal/resize":
            return terminal_resize(query, b.get("rows"), b.get("cols"))
        if path == "/api/terminal/close":
            return terminal_close(query)

        # Disk SMART test
        if path == "/api/disks/smart/test":
            payload = adapters.smart_test(b.get("device", ""), b.get("type", "short"))
            return (200 if payload.get("ok") else 400), payload

        # Disk mount/unmount
        if path == "/api/disks/mount":
            payload = adapters.disk_mount(b.get("device", ""))
            return (200 if payload.get("ok") else 409), payload
        if path == "/api/disks/unmount":
            payload = adapters.disk_unmount(b.get("device", ""))
            return (200 if payload.get("ok") else 409), payload

    return 404, {"error": f"not found: {method} {path}"}
