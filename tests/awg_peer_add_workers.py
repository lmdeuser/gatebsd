"""Lightweight subprocess entrypoints for awg_peer_add tests.

Spawned workers import this module instead of the full 151-test unittest module.
"""
from __future__ import annotations

import fcntl
import json
import os
import select
import socket
import sys
from pathlib import Path

class _WorkerTerminal(Exception):
    """Sentinel exception: terminal message already sent from inner logic."""


# ── Module-level workers for spawn context ─────────────────

def _send_msg(out, msg: dict) -> None:
    """Send a JSON message terminated by newline to a file object."""
    data = json.dumps(msg, separators=(",", ":")) + "\n"
    out.write(data.encode())
    out.flush()


def _recv_msg(inp, timeout: float,
              stage: str | None = None) -> dict | None:
    """Receive a JSON message with timeout from a file object.

    If stage is given, only returns when the target stage is found.
    Uses select() on the underlying fd for reliable timeout.
    """
    import time as _time
    fd = inp.fileno()
    deadline = _time.monotonic() + timeout
    buf = b""
    eof = False
    while True:
        # Process buffered data first
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if line.strip():
                try:
                    msg = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if stage is None or msg.get("stage") == stage:
                    return msg
        if eof:
            break
        remaining = max(deadline - _time.monotonic(), 0)
        if remaining <= 0:
            break
        rlist, _, _ = select.select([fd], [], [], min(remaining, 1.0))
        if rlist:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                eof = True
            else:
                if not chunk:
                    eof = True
                else:
                    buf += chunk
    return None


def _wait_stage(sock: socket.socket, expected_stage: str, timeout: float,
                test_name: str, worker_pid: int | None) -> dict:
    """Wait for a specific stage message from worker. Fail test on timeout."""
    msg = _recv_msg(sock, timeout)
    if msg is None:
        raise TimeoutError(
            f"{test_name}: worker pid={worker_pid} "
            f"timed out waiting for stage '{expected_stage}'"
        )
    actual = msg.get("stage")
    if actual != expected_stage:
        raise AssertionError(
            f"{test_name}: worker pid={worker_pid} "
            f"sent stage '{actual}' but expected '{expected_stage}'; msg={msg}"
        )
    return msg


def _subprocess_worker_main() -> None:
    """Worker entry point: runs awg_peer_add controlled by parent over stdin/stdout.

    Env vars: CONF_DIR, CONF_NAME, PUBKEY,
              WORKER_EXIT_AFTER_RESULT (1 = exit(1)),
              WORKER_TRACEBACK_AFTER_RESULT (1 = write Traceback to stderr).
    Reads commands from stdin (line-delimited JSON), writes results to stdout.

    Exactly one terminal message is sent per invocation: result, error, or stopped.
    After sending a terminal message, the worker exits immediately.
    """
    conf_dir = os.environ["CONF_DIR"]
    conf_name = os.environ["CONF_NAME"]
    pubkey = os.environ["PUBKEY"]
    exit_after_result = os.environ.get("WORKER_EXIT_AFTER_RESULT", "0") == "1"
    traceback_after = os.environ.get("WORKER_TRACEBACK_AFTER_RESULT", "0") == "1"

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))

    inp = sys.stdin.buffer
    out = sys.stdout.buffer
    terminal_sent = False

    try:
        _subprocess_worker_impl(inp, out, conf_dir, conf_name, pubkey)
    except _WorkerTerminal:
        pass
    except Exception as e:
        if not terminal_sent:
            terminal_sent = True
            try:
                _send_msg(out, {"stage": "error", "detail": str(e)})
            except (OSError, ValueError):
                pass
    finally:
        try:
            out.flush()
        except (OSError, ValueError):
            pass
    if traceback_after:
        try:
            sys.stderr.write("Traceback: controlled mutation after result\n")
            sys.stderr.flush()
        except (OSError, ValueError):
            pass
    if exit_after_result:
        sys.exit(1)


def _subprocess_worker_impl(
    inp, out, conf_dir: str, conf_name: str, pubkey: str,
) -> None:
    """Core worker logic: controlled awg_peer_add over stdin/stdout IPC."""
    from unittest.mock import patch as _patch
    from gatebsd_ui.writers import vpn
    conf_path = Path(conf_dir) / f"{conf_name}.conf"
    original_flock = fcntl.flock
    _real_read_bytes = Path.read_bytes
    _real_chmod_os = os.chmod
    _real_replace = os.replace
    backup_count = 0
    write_count = 0
    chmod_count = 0
    exclusive_lock_count = 0

    def _wait_cmd(expected_cmd: str, timeout: float = 15.0) -> None:
        msg = _recv_msg(inp, timeout)
        if msg is None:
            raise TimeoutError(f"worker timed out waiting for cmd '{expected_cmd}'")
        if msg.get("cmd") != expected_cmd:
            raise AssertionError(
                f"worker got cmd '{msg.get('cmd')}' but expected '{expected_cmd}'"
            )

    def patched_flock(fd: int, operation: int) -> None:
        nonlocal exclusive_lock_count
        if operation & fcntl.LOCK_EX:
            exclusive_lock_count += 1
            lock_kind = "profile" if exclusive_lock_count == 1 else "config"
            _send_msg(out, {"stage": f"{lock_kind}_lock_attempted"})
            original_flock(fd, operation)  # may block
            _send_msg(out, {"stage": f"{lock_kind}_lock_acquired"})
        else:
            original_flock(fd, operation)

    def patched_read_bytes(self_path: Path, **kwargs: object) -> bytes:
        if self_path == conf_path:
            _send_msg(out, {"stage": "read_reached"})
            try:
                data = _real_read_bytes(self_path, **kwargs)
            except Exception as e:
                raise
            _send_msg(out, {"stage": "read_completed"})
            _wait_cmd("allow_after_read")
            return data
        return _real_read_bytes(self_path, **kwargs)

    def patched_backup(*args: object, **kwargs: object) -> dict:
        nonlocal backup_count
        backup_count += 1
        _send_msg(out, {"stage": "backup_reached"})
        _wait_cmd("allow_backup_continue")
        return {}

    def patched_chmod_os(path: object, mode: int, *args: object, **kwargs: object) -> None:
        nonlocal chmod_count
        if isinstance(path, (str, Path)) and str(path).endswith(".tmp"):
            chmod_count += 1
        _real_chmod_os(path, mode, *args, **kwargs)

    def patched_replace(src: object, dst: object, *args: object, **kwargs: object) -> None:
        nonlocal write_count
        write_count += 1
        _real_replace(src, dst, *args, **kwargs)

    try:
        with (
            _patch.object(vpn, "AMNEZIA_CONF_DIR", Path(conf_dir)),
            _patch.object(vpn.backup, "backup_files", side_effect=patched_backup),
            _patch.object(fcntl, "flock", patched_flock),
            _patch.object(Path, "read_bytes", patched_read_bytes),
            _patch("os.chmod", side_effect=patched_chmod_os),
            _patch("os.replace", side_effect=patched_replace),
        ):
            _send_msg(out, {"stage": "worker_started"})
            status, body = vpn.awg_peer_add(conf_name, pubkey)
            _send_msg(out, {
                "stage": "result",
                "status": status,
                "body": body,
                "backup_count": backup_count,
                "replace_count": write_count,
                "chmod_count": chmod_count,
            })
    except Exception as e:
        import traceback as _tb
        try:
            _send_msg(out, {
                "stage": "result",
                "status": -1,
                "body": {"error": str(e), "trace": _tb.format_exc()},
                "backup_count": backup_count,
                "replace_count": write_count,
                "chmod_count": chmod_count,
            })
        except (OSError, ValueError):
            pass
    raise _WorkerTerminal()


def _subprocess_external_lock_main() -> None:
    """External lock worker: holds LOCK_EX on conf.lock until told to release.

    Env vars: LOCK_PATH, SKIP_RELEASED (1 = skip sending released),
              LOCK_EXIT_AFTER_RELEASED (1 = exit(1) after released).
    Reads commands from stdin, writes results to stdout.
    Commands: release (release lock and exit), stop (exit immediately).
    """
    lock_path = os.environ["LOCK_PATH"]
    skip_released = os.environ.get("SKIP_RELEASED", "0") == "1"
    exit_after_released = os.environ.get("LOCK_EXIT_AFTER_RELEASED", "0") == "1"
    inp = sys.stdin.buffer
    out = sys.stdout.buffer
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            _send_msg(out, {"stage": "lock_acquired"})
            msg = _recv_msg(inp, 30.0)
            if msg is None:
                raise TimeoutError("external lock worker timed out")
            cmd = msg.get("cmd", "")
            if cmd == "stop":
                return
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)
        if cmd == "release" and not skip_released:
            _send_msg(out, {"stage": "released"})
    except Exception as e:
        try:
            _send_msg(out, {"stage": "error", "detail": str(e)})
        except (OSError, ValueError):
            pass
    finally:
        try:
            out.flush()
        except (OSError, ValueError):
            pass
    if exit_after_released:
        sys.exit(1)


def _stderr_flood_worker_main() -> None:
    """Worker that writes 1 MiB to stderr then sends a normal result.

    Proves that stderr via TemporaryFile does not block the worker.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))
    out = sys.stdout.buffer
    # Write 1 MiB to stderr (via fd, not Python's sys.stderr)
    stderr_fd = sys.stderr.fileno()
    chunk = b"X" * 4096
    target = 1024 * 1024  # 1 MiB
    written = 0
    while written < target:
        n = os.write(stderr_fd, chunk)
        written += n
    # Now send a normal result via stdout
    _send_msg(out, {"stage": "result", "status": 200, "body": {"ok": True}})


def _read_error_worker_main() -> None:
    """Worker where patched_read_bytes raises on controlled read.

    Env vars: CONF_DIR, CONF_NAME, PUBKEY, FAIL_READ (1 = fail).
    Exactly one terminal message must be sent.
    Exits with returncode 0 after sending terminal.
    """
    conf_dir = os.environ["CONF_DIR"]
    conf_name = os.environ["CONF_NAME"]
    pubkey = os.environ["PUBKEY"]
    fail_read = os.environ.get("FAIL_READ", "0") == "1"

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))

    out = sys.stdout.buffer

    from unittest.mock import patch as _patch
    from gatebsd_ui.writers import vpn
    conf_path = Path(conf_dir) / f"{conf_name}.conf"
    _real_read_bytes = Path.read_bytes

    def patched_read_bytes(self_path: Path, **kwargs: object) -> bytes:
        if self_path == conf_path and fail_read:
            _send_msg(out, {"stage": "read_reached"})
            raise OSError("controlled read error")
        return _real_read_bytes(self_path, **kwargs)

    try:
        with (
            _patch.object(vpn, "AMNEZIA_CONF_DIR", Path(conf_dir)),
            _patch.object(vpn.backup, "backup_files", return_value={}),
            _patch.object(Path, "read_bytes", patched_read_bytes),
        ):
            _send_msg(out, {"stage": "worker_started"})
            status, body = vpn.awg_peer_add(conf_name, pubkey)
            _send_msg(out, {
                "stage": "result",
                "status": status,
                "body": body,
            })
    except Exception as e:
        import traceback as _tb
        _send_msg(out, {
            "stage": "result",
            "status": -1,
            "body": {"error": str(e), "trace": _tb.format_exc()},
        })
    return
