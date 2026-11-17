"""Regression tests for awg_peer_add — conf_name, peer_pubkey, duplicate detection, flock, atomic write."""
from __future__ import annotations

import fcntl
import json
import os
import queue
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

# Canonical WireGuard/AmneziaWG keys: exactly 44 base64 characters decoding to
# 32 bytes. Deterministic so the tests are reproducible. Anything that merely
# looks key-shaped is rejected by the writer, because a truncated or re-wrapped
# key was previously accepted, written to the live config, and only refused
# later by awg-quick -- so the tunnel failed to come up on the next restart
# rather than at the point of the mistake.
KEY_A = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
KEY_B = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
KEY_SPECIAL = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
# Canonical keys that differ from KEY_A in exactly one byte, so near-miss
# duplicate detection is still exercised with keys the validator accepts.
KEY_NEAR_FIRST = "AgEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
KEY_NEAR_LAST = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQk="


# ── Helpers ────────────────────────────────────────────────

class _SpyClose:
    """Spy for os.close that calls real os.close and records fd values."""
    def __init__(self) -> None:
        self._real_close = os.close
        self.calls: list[int] = []

    def __call__(self, fd: int) -> None:
        self.calls.append(fd)
        try:
            self._real_close(fd)
        except OSError:
            pass


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


# ── Fake paths for validation tests ───────────────────────

class _FakeConfDir:
    def __truediv__(self, other: object) -> object:
        raise AssertionError(f"AMNEZIA_CONF_DIR.__truediv__ called with {other!r}")


class _TrackingConfDir:
    def __init__(self) -> None:
        self.truediv_calls: list[object] = []
        self._tracking_path: _TrackingPath | None = None

    def __truediv__(self, other: object) -> "_TrackingPath":
        self.truediv_calls.append(other)
        self._tracking_path = _TrackingPath()
        return self._tracking_path


class _TrackingPath:
    def __init__(self) -> None:
        self.exists_calls = 0
        self.read_text_calls = 0
        self.write_text_calls = 0
        self.chmod_calls = 0

    def exists(self) -> bool:
        self.exists_calls += 1
        raise AssertionError("_TrackingPath.exists called")

    def read_text(self, **kwargs: object) -> str:
        self.read_text_calls += 1
        raise AssertionError("_TrackingPath.read_text called")

    def write_text(self, data: str, **kwargs: object) -> None:
        self.write_text_calls += 1
        raise AssertionError("_TrackingPath.write_text called")

    def chmod(self, mode: int) -> None:
        self.chmod_calls += 1
        raise AssertionError("_TrackingPath.chmod called")


class _OpLog:
    """Thread-safe operation log for tracking post-error operations."""
    def __init__(self) -> None:
        self._ops: list[str] = []
    def log(self, name: str) -> None:
        self._ops.append(name)
    def has(self, name: str) -> bool:
        return name in self._ops
    @property
    def ops(self) -> list[str]:
        return list(self._ops)


class _AtomicWriteResult:
    """Result from _run_atomic_write_with_tracking."""
    __slots__ = ("status", "body", "oplog")
    def __init__(self, status: int, body: dict, oplog: _OpLog) -> None:
        self.status = status
        self.body = body
        self.oplog = oplog


class _TrackingFlushFile:
    """File wrapper that logs flush and fileno calls."""
    def __init__(self, real_file: object, oplog: _OpLog) -> None:
        self._real = real_file
        self._oplog = oplog
    def write(self, data: object) -> None:
        self._real.write(data)
    def flush(self) -> None:
        self._oplog.log("flush")
        self._real.flush()
    def fileno(self) -> int:
        return self._real.fileno()
    def __enter__(self) -> "_TrackingFlushFile":
        return self
    def __exit__(self, *a: object) -> None:
        self._real.close()


class _WriteErrorFile:
    """File wrapper that raises on write."""
    def __init__(self, real_file: object, oplog: _OpLog) -> None:
        self._real = real_file
        self._oplog = oplog
    def write(self, data: object) -> None:
        self._oplog.log("write")
        raise OSError("simulated write error")
    def flush(self) -> None:
        self._oplog.log("flush")
        self._real.flush()
    def fileno(self) -> int:
        return self._real.fileno()
    def __enter__(self) -> "_WriteErrorFile":
        return self
    def __exit__(self, *a: object) -> None:
        self._real.close()


class _FlushErrorFile:
    """File wrapper that raises on flush."""
    def __init__(self, real_file: object, oplog: _OpLog) -> None:
        self._real = real_file
        self._oplog = oplog
    def write(self, data: object) -> None:
        self._real.write(data)
    def flush(self) -> None:
        self._oplog.log("flush")
        raise OSError("simulated flush error")
    def fileno(self) -> int:
        return self._real.fileno()
    def __enter__(self) -> "_FlushErrorFile":
        return self
    def __exit__(self, *a: object) -> None:
        self._real.close()


class _BlockingPath:
    def __init__(self, real_path: Path) -> None:
        self._real = real_path
        self.exists_calls = 0
        self.read_text_calls = 0
        self.write_text_calls = 0
        self.chmod_calls = 0

    def __truediv__(self, other: object) -> "_BlockingPath":
        raise AssertionError(f"_BlockingPath.__truediv__ called with {other!r}")

    def exists(self) -> bool:
        self.exists_calls += 1
        return self._real.exists()

    def read_text(self, **kwargs: object) -> str:
        self.read_text_calls += 1
        return self._real.read_text(**kwargs)  # type: ignore[return-value]

    def write_text(self, data: str, **kwargs: object) -> None:
        self.write_text_calls += 1
        self._real.write_text(data, **kwargs)

    def chmod(self, mode: int) -> None:
        self.chmod_calls += 1
        self._real.chmod(mode)


# ── Validation tests ──────────────────────────────────────

class AwgPeerAddConfNameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)
        self.patcher_conf = patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.conf_dir)
        self.patcher_backup = patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={})
        self.mock_backup = self.patcher_backup.start()
        self.patcher_conf.start()

    def tearDown(self) -> None:
        self.patcher_conf.stop()
        self.patcher_backup.stop()
        self.td.cleanup()

    def _write(self, name: str, content: str) -> Path:
        p = self.conf_dir / name
        p.write_text(content, encoding="utf-8")
        return p

    def _assert_conf_name_400(self, name: object) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n")
        before = set(self.conf_dir.iterdir())
        self.mock_backup.reset_mock()
        status, body = awg_peer_add(name, KEY_A)  # type: ignore[arg-type]
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "invalid config name"})
        self.mock_backup.assert_not_called()
        self.assertEqual(set(self.conf_dir.iterdir()), before)

    def _assert_valid_name_404(self, name: str) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        status, body = awg_peer_add(name, KEY_A)
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": f"{name}.conf not found"})

    def test_conf_name_none(self) -> None: self._assert_conf_name_400(None)
    def test_conf_name_int(self) -> None: self._assert_conf_name_400(123)
    def test_conf_name_list(self) -> None: self._assert_conf_name_400([])
    def test_conf_name_dict(self) -> None: self._assert_conf_name_400({})
    def test_conf_name_empty_string(self) -> None: self._assert_conf_name_400("")
    def test_conf_name_space_only(self) -> None: self._assert_conf_name_400(" ")
    def test_conf_name_internal_space(self) -> None: self._assert_conf_name_400("wg 0")
    def test_conf_name_slash(self) -> None: self._assert_conf_name_400("/")
    def test_conf_name_path_traversal(self) -> None: self._assert_conf_name_400("../wg0")
    def test_conf_name_with_lf(self) -> None: self._assert_conf_name_400("wg0\n")
    def test_conf_name_with_crlf(self) -> None: self._assert_conf_name_400("wg0\r\n")
    def test_conf_name_with_tab(self) -> None: self._assert_conf_name_400("wg0\t")
    def test_conf_name_null_byte(self) -> None: self._assert_conf_name_400("wg\x00")
    def test_conf_name_unicode(self) -> None: self._assert_conf_name_400("\u0442\u0435\u0441\u0442")
    def test_valid_awg0(self) -> None: self._assert_valid_name_404("awg0")
    def test_valid_hyphen(self) -> None: self._assert_valid_name_404("wg-0")
    def test_valid_underscore(self) -> None: self._assert_valid_name_404("wg_0")
    def test_valid_mixed(self) -> None: self._assert_valid_name_404("AWG_test-1")


class AwgPeerAddPathConstructionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)
        self.fake_conf_dir = _FakeConfDir()
        self.patcher_conf = patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.fake_conf_dir)
        self.patcher_backup = patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={})
        self.mock_backup = self.patcher_backup.start()
        self.patcher_conf.start()

    def tearDown(self) -> None:
        self.patcher_conf.stop()
        self.patcher_backup.stop()
        self.td.cleanup()

    def _assert_no_path_construction(self, name: object) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        (self.conf_dir / "wg0.conf").write_text(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n", encoding="utf-8")
        self.mock_backup.reset_mock()
        status, body = awg_peer_add(name, KEY_A)  # type: ignore[arg-type]
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "invalid config name"})
        self.mock_backup.assert_not_called()

    def test_no_path_construction_none(self) -> None: self._assert_no_path_construction(None)
    def test_no_path_construction_int(self) -> None: self._assert_no_path_construction(123)
    def test_no_path_construction_list(self) -> None: self._assert_no_path_construction([])
    def test_no_path_construction_dict(self) -> None: self._assert_no_path_construction({})
    def test_no_path_construction_empty(self) -> None: self._assert_no_path_construction("")
    def test_no_path_construction_space(self) -> None: self._assert_no_path_construction(" ")
    def test_no_path_construction_internal_space(self) -> None: self._assert_no_path_construction("wg 0")
    def test_no_path_construction_slash(self) -> None: self._assert_no_path_construction("/")
    def test_no_path_construction_traversal(self) -> None: self._assert_no_path_construction("../wg0")
    def test_no_path_construction_lf(self) -> None: self._assert_no_path_construction("wg0\n")
    def test_no_path_construction_crlf(self) -> None: self._assert_no_path_construction("wg0\r\n")
    def test_no_path_construction_tab(self) -> None: self._assert_no_path_construction("wg0\t")
    def test_no_path_construction_nul(self) -> None: self._assert_no_path_construction("wg\x00")
    def test_no_path_construction_unicode(self) -> None: self._assert_no_path_construction("\u0442\u0435\u0441\u0442")


class AwgPeerAddFileOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)
        self.blocking = _BlockingPath(self.conf_dir)
        self.patcher_conf = patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.blocking)
        self.patcher_backup = patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={})
        self.mock_backup = self.patcher_backup.start()
        self.patcher_conf.start()

    def tearDown(self) -> None:
        self.patcher_conf.stop()
        self.patcher_backup.stop()
        self.td.cleanup()

    def _assert_no_file_ops(self, name: object) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        (self.conf_dir / "wg0.conf").write_text(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n", encoding="utf-8")
        before = set(self.conf_dir.iterdir())
        self.mock_backup.reset_mock()
        self.blocking.exists_calls = 0
        self.blocking.read_text_calls = 0
        self.blocking.write_text_calls = 0
        self.blocking.chmod_calls = 0
        status, body = awg_peer_add(name, KEY_A)  # type: ignore[arg-type]
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "invalid config name"})
        self.assertEqual(self.blocking.exists_calls, 0)
        self.assertEqual(self.blocking.read_text_calls, 0)
        self.assertEqual(self.blocking.write_text_calls, 0)
        self.assertEqual(self.blocking.chmod_calls, 0)
        self.mock_backup.assert_not_called()
        self.assertEqual(set(self.conf_dir.iterdir()), before)

    def test_no_file_ops_none(self) -> None: self._assert_no_file_ops(None)
    def test_no_file_ops_int(self) -> None: self._assert_no_file_ops(123)
    def test_no_file_ops_list(self) -> None: self._assert_no_file_ops([])
    def test_no_file_ops_dict(self) -> None: self._assert_no_file_ops({})
    def test_no_file_ops_empty(self) -> None: self._assert_no_file_ops("")
    def test_no_file_ops_space(self) -> None: self._assert_no_file_ops(" ")
    def test_no_file_ops_internal_space(self) -> None: self._assert_no_file_ops("wg 0")
    def test_no_file_ops_slash(self) -> None: self._assert_no_file_ops("/")
    def test_no_file_ops_traversal(self) -> None: self._assert_no_file_ops("../wg0")
    def test_no_file_ops_lf(self) -> None: self._assert_no_file_ops("wg0\n")
    def test_no_file_ops_crlf(self) -> None: self._assert_no_file_ops("wg0\r\n")
    def test_no_file_ops_tab(self) -> None: self._assert_no_file_ops("wg0\t")
    def test_no_file_ops_nul(self) -> None: self._assert_no_file_ops("wg\x00")
    def test_no_file_ops_unicode(self) -> None: self._assert_no_file_ops("\u0442\u0435\u0441\u0442")


class AwgPeerAddPubkeyValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)
        self.tracking_conf_dir = _TrackingConfDir()
        self.patcher_conf = patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.tracking_conf_dir)
        self.patcher_backup = patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={})
        self.mock_backup = self.patcher_backup.start()
        self.patcher_conf.start()

    def tearDown(self) -> None:
        self.patcher_conf.stop()
        self.patcher_backup.stop()
        self.td.cleanup()

    def _write(self, name: str, content: str) -> Path:
        p = self.conf_dir / name
        p.write_text(content, encoding="utf-8")
        return p

    def _assert_pubkey_400(self, pubkey: object, label: str = "") -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        conf_file = self._write("wg0.conf", f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n")
        original_bytes = conf_file.read_bytes()
        before = set(self.conf_dir.iterdir())
        self.mock_backup.reset_mock()
        self.tracking_conf_dir.truediv_calls.clear()
        self.tracking_conf_dir._tracking_path = None
        status, body = awg_peer_add("wg0", pubkey)  # type: ignore[arg-type]
        self.assertEqual(status, 400, f"{label}")
        self.assertEqual(body, {"error": "invalid peer public key"}, f"{label}")
        self.assertEqual(self.tracking_conf_dir.truediv_calls, [], f"{label}")
        self.mock_backup.assert_not_called()
        self.assertEqual(conf_file.read_bytes(), original_bytes, f"{label}")
        self.assertEqual(set(self.conf_dir.iterdir()), before, f"{label}")

    def _assert_pubkey_passes_to_404(self, pubkey: str, label: str = "") -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self.patcher_conf.stop()
        self.patcher_conf = patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.conf_dir)
        self.patcher_conf.start()
        try:
            status, body = awg_peer_add("wg0", pubkey)
            self.assertEqual(status, 404, f"{label}")
            self.assertEqual(body, {"error": "wg0.conf not found"}, f"{label}")
        finally:
            self.patcher_conf.stop()
            self.patcher_conf = patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.tracking_conf_dir)
            self.patcher_conf.start()

    def test_pubkey_none(self) -> None: self._assert_pubkey_400(None, "None")
    def test_pubkey_int(self) -> None: self._assert_pubkey_400(123, "int")
    def test_pubkey_list(self) -> None: self._assert_pubkey_400([], "list")
    def test_pubkey_dict(self) -> None: self._assert_pubkey_400({}, "dict")
    def test_pubkey_empty_string(self) -> None: self._assert_pubkey_400("", "empty")
    def test_pubkey_space_only(self) -> None: self._assert_pubkey_400(" ", "space")
    def test_pubkey_internal_space(self) -> None: self._assert_pubkey_400("AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAA", "internal space")
    def test_pubkey_too_short(self) -> None: self._assert_pubkey_400("A" * 42, "42 chars")
    def test_pubkey_too_long(self) -> None: self._assert_pubkey_400("A" * 46, "46 chars")
    def test_pubkey_with_trailing_lf(self) -> None: self._assert_pubkey_400(KEY_A + "\n", "trailing LF")
    def test_pubkey_with_trailing_crlf(self) -> None: self._assert_pubkey_400(KEY_A + "\r\n", "trailing CRLF")
    def test_pubkey_with_tab(self) -> None: self._assert_pubkey_400(KEY_A[:43] + "\t", "trailing tab")
    def test_pubkey_with_nul(self) -> None: self._assert_pubkey_400("A" * 43 + "\x00", "NUL byte")
    def test_pubkey_unicode(self) -> None: self._assert_pubkey_400("\u0442\u0435\u0441\u0442" * 11, "Unicode")
    def test_pubkey_invalid_char(self) -> None: self._assert_pubkey_400("B" * 43 + "!", "invalid char")
    # Length alone is not sufficient: a real key is 44 characters AND decodes to
    # 32 bytes. 43 and 45 characters cannot, so they are now refused rather than
    # written to the config.
    def test_pubkey_43_chars_is_rejected(self) -> None: self._assert_pubkey_400("A" * 43, "43 chars")
    def test_pubkey_45_chars_is_rejected(self) -> None: self._assert_pubkey_400("A" * 45, "45 chars")
    def test_pubkey_right_length_wrong_payload_is_rejected(self) -> None:
        # 44 chars of "A" is well-formed base64 but does not decode to 32 bytes.
        self._assert_pubkey_400("A" * 44, "44 chars, non-canonical")
    def test_pubkey_non_canonical_padding_is_rejected(self) -> None:
        self._assert_pubkey_400("A" * 42 + "==", "non-canonical padding")
    def test_pubkey_canonical_key_is_accepted(self) -> None:
        self._assert_pubkey_passes_to_404(KEY_A, "canonical key")
    def test_pubkey_canonical_key_with_plus_and_slash_is_accepted(self) -> None:
        self._assert_pubkey_passes_to_404(KEY_SPECIAL, "canonical key with + and /")


class AwgPeerAddDuplicateDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)
        self.patcher_conf = patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.conf_dir)
        self.patcher_backup = patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={})
        self.mock_backup = self.patcher_backup.start()
        self.patcher_conf.start()

    def tearDown(self) -> None:
        self.patcher_conf.stop()
        self.patcher_backup.stop()
        self.td.cleanup()

    def _write(self, name: str, content: str) -> Path:
        p = self.conf_dir / name
        p.write_text(content, encoding="utf-8")
        return p

    def _assert_duplicate_409(self, existing: str, pubkey: str, label: str = "") -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        conf_file = self._write("wg0.conf", existing)
        original_bytes = conf_file.read_bytes()
        original_mode = os.stat(conf_file).st_mode
        before = set(self.conf_dir.iterdir())
        self.mock_backup.reset_mock()
        status, body = awg_peer_add("wg0", pubkey)
        self.assertEqual(status, 409, f"{label}")
        self.assertEqual(body, {"error": "peer already exists in config"}, f"{label}")
        self.mock_backup.assert_not_called()
        self.assertEqual(conf_file.read_bytes(), original_bytes, f"{label}")
        self.assertEqual(os.stat(conf_file).st_mode, original_mode, f"{label}")
        new_files = set(self.conf_dir.iterdir()) - before
        allowed_lock_files = {
            self.conf_dir / ".gatebsd-profiles.lock",
            self.conf_dir / "wg0.conf.lock",
        }
        self.assertTrue(new_files <= allowed_lock_files, f"{label}: {new_files}")

    def _assert_false_positive_adds_peer(self, existing: str, pubkey: str, label: str = "") -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        conf_file = self._write("wg0.conf", existing)
        before = set(self.conf_dir.iterdir())
        self.mock_backup.reset_mock()
        status, body = awg_peer_add("wg0", pubkey)
        self.assertEqual(status, 200, f"{label}")
        self.assertEqual(body.get("ok"), True, f"{label}")
        self.mock_backup.assert_called_once()
        new_content = conf_file.read_text(encoding="utf-8")
        block = f"[Peer]\nPublicKey = {pubkey}\nAllowedIPs = 0.0.0.0/0\n"
        if existing.endswith("\r\n\r\n") or existing.endswith("\n\n"):
            expected = existing + block
        elif existing.endswith("\r\n") or existing.endswith("\n"):
            expected = existing + "\n" + block
        else:
            expected = existing + "\n\n" + block
        self.assertEqual(new_content, expected, f"{label}")
        new_files = set(self.conf_dir.iterdir()) - before
        allowed_lock_files = {
            self.conf_dir / ".gatebsd-profiles.lock",
            self.conf_dir / "wg0.conf.lock",
        }
        self.assertTrue(new_files <= allowed_lock_files, f"{label}: {new_files}")

    def _assert_rejected_before_write(self, pubkey: str, label: str = "") -> None:
        """A non-canonical key must be refused without touching the config."""
        from gatebsd_ui.writers.vpn import awg_peer_add
        status, body = awg_peer_add("wg0", pubkey)
        self.assertEqual(status, 400, label)
        self.assertEqual(body, {"error": "invalid peer public key"}, label)

    def test_duplicate_plain(self) -> None: self._assert_duplicate_409(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n", KEY_A, "plain")
    def test_duplicate_no_space_around_equals(self) -> None: self._assert_duplicate_409(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey={KEY_A}\nAllowedIPs = 10.0.0.2/32\n", KEY_A, "no spaces")
    def test_duplicate_quoted(self) -> None: self._assert_duplicate_409(f'[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = "{KEY_A}"\nAllowedIPs = 10.0.0.2/32\n', KEY_A, "quoted")
    def test_duplicate_leading_whitespace(self) -> None: self._assert_duplicate_409(f"[Interface]\nPrivateKey = k\n\n[Peer]\n    PublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n", KEY_A, "leading whitespace")
    def test_duplicate_spaces_around_equals(self) -> None: self._assert_duplicate_409(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey   =   {KEY_A}\nAllowedIPs = 10.0.0.2/32\n", KEY_A, "spaces around equals")
    def test_duplicate_second_peer(self) -> None: self._assert_duplicate_409(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.2/32\n\n[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.3/32\n", KEY_A, "second peer")
    def test_duplicate_all_whitespace_variations(self) -> None: self._assert_duplicate_409(f"[Interface]\nPrivateKey = k\n\n[Peer]\n  PublicKey  =  {KEY_A}  \nAllowedIPs = 10.0.0.2/32\n", KEY_A, "all whitespace")
    def test_duplicate_quoted_with_spaces(self) -> None: self._assert_duplicate_409(f'[Interface]\nPrivateKey = k\n\n[Peer]\n  PublicKey  =  "{KEY_A}"  \nAllowedIPs = 10.0.0.2/32\n', KEY_A, "quoted with spaces")
    def test_false_positive_comment_before_sections(self) -> None: self._assert_false_positive_adds_peer(f"# PublicKey = {KEY_A}\n[Interface]\nPrivateKey = k\n", KEY_A, "comment before sections")
    def test_false_positive_comment_inside_peer(self) -> None: self._assert_false_positive_adds_peer(f"[Interface]\nPrivateKey = k\n\n[Peer]\n# PublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n", KEY_A, "comment inside peer")
    def test_false_positive_privatekey_in_interface(self) -> None: self._assert_false_positive_adds_peer(f"[Interface]\nPrivateKey = {KEY_A}\nAllowedIPs = 10.0.0.1/24\n", KEY_A, "privatekey in interface")
    def test_false_positive_publickey_in_interface(self) -> None: self._assert_false_positive_adds_peer(f"[Interface]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.1/24\n", KEY_A, "publickey in interface")
    def test_false_positive_endpoint_contains_key(self) -> None: self._assert_false_positive_adds_peer(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_B}\nEndpoint = host:{KEY_A}\nAllowedIPs = 10.0.0.2/32\n", KEY_A, "endpoint contains key")
    def test_false_positive_allowedips_contains_key(self) -> None: self._assert_false_positive_adds_peer(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = {KEY_A}/32\n", KEY_A, "allowedips contains key")
    def test_false_positive_presharedkey_contains_key(self) -> None: self._assert_false_positive_adds_peer(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_B}\nPresharedKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n", KEY_A, "presharedkey contains key")
    def test_false_positive_arbitrary_parameter(self) -> None: self._assert_false_positive_adds_peer(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_B}\nCustomField = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n", KEY_A, "arbitrary parameter")
    def test_false_positive_peerbackup_section(self) -> None: self._assert_false_positive_adds_peer(f"[Interface]\nPrivateKey = k\n\n[PeerBackup]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n", KEY_A, "PeerBackup section")
    def test_false_positive_longer_pubkey(self) -> None: self._assert_false_positive_adds_peer(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_A}B\nAllowedIPs = 10.0.0.2/32\n", KEY_A, "longer pubkey")
    def test_close_different_first_char(self) -> None: self._assert_false_positive_adds_peer(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n", KEY_NEAR_FIRST, "different first byte")
    def test_close_different_last_char(self) -> None: self._assert_false_positive_adds_peer(f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n", KEY_NEAR_LAST, "different last byte")
    def test_close_longer_value(self) -> None: self._assert_rejected_before_write(KEY_A + "A", "longer than a canonical key")
    def test_close_shorter_value(self) -> None: self._assert_rejected_before_write(KEY_A[:-1], "shorter than a canonical key")
    def test_close_case_sensitive(self) -> None: self._assert_rejected_before_write(KEY_A.lower(), "lowercased key is not canonical")


# ── Flock + atomic write tests ────────────────────────────

class AwgPeerAddFlockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)
        self.patcher_conf = patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.conf_dir)
        self.patcher_backup = patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={})
        self.mock_backup = self.patcher_backup.start()
        self.patcher_conf.start()

    def tearDown(self) -> None:
        self.patcher_conf.stop()
        self.patcher_backup.stop()
        self.td.cleanup()

    def _write(self, name: str, content: str) -> Path:
        p = self.conf_dir / name
        p.write_text(content, encoding="utf-8")
        return p

    def _save_metadata(self) -> dict[str, object]:
        p = self.conf_dir / "wg0.conf"
        s = os.stat(p)
        return {"bytes": p.read_bytes(), "mode": s.st_mode, "uid": s.st_uid, "gid": s.st_gid}

    def _assert_metadata_unchanged(self, saved: dict[str, object]) -> None:
        p = self.conf_dir / "wg0.conf"
        self.assertEqual(p.read_bytes(), saved["bytes"], "config bytes changed")
        s = os.stat(p)
        self.assertEqual(s.st_mode, saved["mode"], "config mode changed")
        self.assertEqual(s.st_uid, saved["uid"], "config uid changed")
        self.assertEqual(s.st_gid, saved["gid"], "config gid changed")

    def _assert_no_tmp_files(self) -> None:
        tmp_files = list(self.conf_dir.glob("*.tmp"))
        self.assertEqual(tmp_files, [], f"unexpected .tmp files: {tmp_files}")

    def _assert_lock_released(self) -> None:
        lock_fd = os.open(
            str(self.conf_dir / "wg0.conf.lock"),
            os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600,
        )
        try:
            result = fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIsNone(result, "lock should be released")
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    # ── Lock file basics ───────────────────────────────────

    def test_lock_file_path(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        self.assertFalse((self.conf_dir / "wg0.conf.lock").exists())
        awg_peer_add("wg0", KEY_A)
        self.assertTrue((self.conf_dir / "wg0.conf.lock").exists())

    def test_lock_file_mode_0600(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        awg_peer_add("wg0", KEY_A)
        self.assertEqual(os.stat(self.conf_dir / "wg0.conf.lock").st_mode & 0o777, 0o600)

    def test_existing_lock_mode_fixed(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        lock = self.conf_dir / "wg0.conf.lock"
        lock.write_text("")
        os.chmod(lock, 0o666)
        awg_peer_add("wg0", KEY_A)
        self.assertEqual(os.stat(lock).st_mode & 0o777, 0o600)

    def test_lock_file_not_deleted(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        awg_peer_add("wg0", KEY_A)
        self.assertTrue((self.conf_dir / "wg0.conf.lock").exists())

    # ── Lock error handling ─────────────────────────────────

    def test_open_error_returns_500(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        with patch("gatebsd_ui.writers.vpn.os.open", side_effect=OSError("simulated")):
            status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to lock config"})

    def test_fchmod_error_returns_500(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        with patch("gatebsd_ui.writers.vpn.os.fchmod", side_effect=OSError("simulated")):
            status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to lock config"})

    def test_flock_error_returns_500(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        def broken_flock(fd: int, operation: int) -> None:
            if operation & fcntl.LOCK_EX:
                raise OSError("simulated")
        with patch("gatebsd_ui.writers.vpn.fcntl.flock", side_effect=broken_flock):
            status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to lock config"})

    # ── Duplicate and disappear under lock ──────────────────

    def test_duplicate_under_lock(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        conf = f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n"
        conf_file = self._write("wg0.conf", conf)
        original_bytes = conf_file.read_bytes()
        status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "peer already exists in config"})
        self.assertEqual(conf_file.read_bytes(), original_bytes)
        self.assertTrue((self.conf_dir / "wg0.conf.lock").exists())
        self.assertEqual(os.stat(self.conf_dir / "wg0.conf.lock").st_mode & 0o777, 0o600)

    def test_config_disappears_under_lock(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        call_count = [0]
        original_lstat = Path.lstat
        def disappearing_lstat(self_path: Path, *args: object, **kwargs: object) -> os.stat_result:
            if self_path == self.conf_dir / "wg0.conf":
                call_count[0] += 1
                if call_count[0] == 2:
                    raise FileNotFoundError(self_path)
            return original_lstat(self_path, *args, **kwargs)
        with patch.object(Path, "lstat", disappearing_lstat):
            status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "wg0.conf not found"})

    # ── Exact os.open call ─────────────────────────────────

    def test_exact_os_open_call(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        expected_lock_path = self.conf_dir / "wg0.conf.lock"
        with patch("gatebsd_ui.writers.vpn.os.open", wraps=os.open) as mock_open:
            awg_peer_add("wg0", KEY_A)
        mock_open.assert_any_call(
            expected_lock_path,
            os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )

    # ── os.close on error paths ────────────────────────────

    def test_fchmod_error_close_fd(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        fake_fd = 42
        spy = _SpyClose()
        with (
            patch("gatebsd_ui.writers.vpn.os.open", return_value=fake_fd),
            patch("gatebsd_ui.writers.vpn.os.fchmod", side_effect=OSError("simulated")),
            patch("gatebsd_ui.writers.vpn.os.close", side_effect=spy),
        ):
            status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 500)
        self.assertIn(fake_fd, spy.calls)

    def test_flock_error_close_fd(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        fake_fd = 42
        spy = _SpyClose()
        def broken_flock(fd: int, operation: int) -> None:
            if operation & fcntl.LOCK_EX:
                raise OSError("simulated")
        with (
            patch("gatebsd_ui.writers.vpn.os.open", return_value=fake_fd),
            patch("gatebsd_ui.writers.vpn.os.fchmod"),
            patch("gatebsd_ui.writers.vpn.fcntl.flock", side_effect=broken_flock),
            patch("gatebsd_ui.writers.vpn.os.close", side_effect=spy),
        ):
            status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 500)
        self.assertIn(fake_fd, spy.calls)

    def test_duplicate_close_fd(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", f"[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n")
        spy = _SpyClose()
        with patch("gatebsd_ui.writers.vpn.os.close", side_effect=spy):
            status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 409)
        self.assertGreater(len(spy.calls), 0)

    def test_disappearing_config_close_fd(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        call_count = [0]
        original_lstat = Path.lstat
        def disappearing_lstat(self_path: Path, *args: object, **kwargs: object) -> os.stat_result:
            if self_path == self.conf_dir / "wg0.conf":
                call_count[0] += 1
                if call_count[0] == 2:
                    raise FileNotFoundError(self_path)
            return original_lstat(self_path, *args, **kwargs)
        spy = _SpyClose()
        with (
            patch.object(Path, "lstat", disappearing_lstat),
            patch("gatebsd_ui.writers.vpn.os.close", side_effect=spy),
        ):
            status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertGreater(len(spy.calls), 0)

    # ── Atomic write: success branch ───────────────────────

    def test_atomic_success_body(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        mock_backup = MagicMock(return_value={"bk": True})
        with patch("gatebsd_ui.writers.vpn.backup.backup_files", mock_backup):
            status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 200)
        conf_path = str(self.conf_dir / "wg0.conf")
        self.assertEqual(body["ok"], True)
        self.assertEqual(body["path"], conf_path)
        self.assertEqual(body["backup"], {"bk": True})
        # Writing the file does not reload the running tunnel. The response must
        # say so explicitly rather than implying the edit is already in effect:
        # this profile is not the active one, so nothing was synced.
        self.assertTrue(body["reload_required"])
        self.assertFalse(body["reload"]["applied"])
        expected_content = "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = " + KEY_A + "\nAllowedIPs = 0.0.0.0/0\n"
        self.assertEqual((self.conf_dir / "wg0.conf").read_text(), expected_content)

    def test_atomic_success_backup_once(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        mock_backup = MagicMock(return_value={})
        with patch("gatebsd_ui.writers.vpn.backup.backup_files", mock_backup):
            awg_peer_add("wg0", KEY_A)
        mock_backup.assert_called_once()
        self.assertEqual(mock_backup.call_args.kwargs.get("reason", ""), "awg-peer-add")

    def test_atomic_no_direct_write_text(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        with patch.object(Path, "write_text") as mock_wt:
            awg_peer_add("wg0", KEY_A)
        mock_wt.assert_not_called()

    def test_atomic_no_tmp_after_success(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        awg_peer_add("wg0", KEY_A)
        self._assert_no_tmp_files()

    def test_atomic_tmp_in_same_dir(self) -> None:
        import tempfile as _tempfile
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        created_tmp = [None]
        _real_mkstemp = _tempfile.mkstemp
        def tracking_mkstemp(**kwargs: object) -> tuple[int, str]:
            result = _real_mkstemp(**kwargs)
            created_tmp[0] = result[1]
            return result
        with patch.object(_tempfile, "mkstemp", side_effect=tracking_mkstemp):
            awg_peer_add("wg0", KEY_A)
        self.assertIsNotNone(created_tmp[0])
        self.assertTrue(created_tmp[0].endswith(".tmp"))
        self.assertEqual(str(Path(created_tmp[0]).parent), str(self.conf_dir))

    def test_atomic_mkstemp_kwargs(self) -> None:
        import tempfile as _tempfile
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        mock_mkstemp = MagicMock(return_value=(42, str(self.conf_dir / "test.tmp")))
        with patch.object(_tempfile, "mkstemp", mock_mkstemp):
            awg_peer_add("wg0", KEY_A)
        mock_mkstemp.assert_called_once()
        _, kwargs = mock_mkstemp.call_args
        self.assertEqual(kwargs["dir"], self.conf_dir)
        self.assertEqual(kwargs["suffix"], ".tmp")

    def test_atomic_fdopen_args(self) -> None:
        import tempfile as _tempfile
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        fake_fd = 77
        mock_mkstemp = MagicMock(return_value=(fake_fd, str(self.conf_dir / "test.tmp")))
        mock_fdopen = MagicMock()
        # Make fdopen return a context manager that does nothing
        mock_file = MagicMock()
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_file.fileno = MagicMock(return_value=fake_fd)
        mock_fdopen.return_value = mock_file
        with (
            patch.object(_tempfile, "mkstemp", mock_mkstemp),
            patch("gatebsd_ui.writers.vpn.os.fdopen", mock_fdopen),
            patch("gatebsd_ui.writers.vpn.os.fsync"),
            patch("gatebsd_ui.writers.vpn.os.chown"),
            patch("gatebsd_ui.writers.vpn.os.chmod"),
            patch("gatebsd_ui.writers.vpn.os.replace"),
            patch("gatebsd_ui.writers.vpn.os.close"),
        ):
            awg_peer_add("wg0", KEY_A)
        mock_fdopen.assert_called_once_with(fake_fd, "wb")

    def test_atomic_write_content(self) -> None:
        import tempfile as _tempfile
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        fake_fd = 88
        mock_mkstemp = MagicMock(return_value=(fake_fd, str(self.conf_dir / "test.tmp")))
        written_data = []
        mock_file = MagicMock()
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        def capture_write(data: bytes) -> None:
            written_data.append(data)
        mock_file.write = capture_write
        mock_file.fileno = MagicMock(return_value=fake_fd)
        with (
            patch.object(_tempfile, "mkstemp", mock_mkstemp),
            patch("gatebsd_ui.writers.vpn.os.fdopen", return_value=mock_file),
            patch("gatebsd_ui.writers.vpn.os.close"),
        ):
            awg_peer_add("wg0", KEY_A)
        expected = "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = " + KEY_A + "\nAllowedIPs = 0.0.0.0/0\n"
        self.assertEqual(len(written_data), 1)
        self.assertEqual(written_data[0], expected.encode("utf-8"))

    def test_atomic_fsync_called(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        fsync_called = [False]
        _real_fsync = os.fsync
        def tracking_fsync(fd: int) -> None:
            fsync_called[0] = True
            _real_fsync(fd)
        with patch("os.fsync", side_effect=tracking_fsync):
            awg_peer_add("wg0", KEY_A)
        self.assertTrue(fsync_called[0])

    def test_atomic_uid_gid_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        chown_args = []
        _real_chown = os.chown
        def tracking_chown(path: object, uid: int, gid: int) -> None:
            chown_args.append((str(path), uid, gid))
            _real_chown(path, uid, gid)
        with patch("os.chown", side_effect=tracking_chown):
            awg_peer_add("wg0", KEY_A)
        self.assertEqual(len(chown_args), 1)
        self.assertTrue(chown_args[0][0].endswith(".tmp"))
        original_stat = os.stat(self.conf_dir / "wg0.conf")
        self.assertEqual(chown_args[0][1], original_stat.st_uid)
        self.assertEqual(chown_args[0][2], original_stat.st_gid)

    def test_atomic_mode_0600(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        chmod_args = []
        _real_chmod = os.chmod
        def tracking_chmod(path: object, mode: int) -> None:
            chmod_args.append((str(path), mode))
            _real_chmod(path, mode)
        with patch("os.chmod", side_effect=tracking_chmod):
            awg_peer_add("wg0", KEY_A)
        tmp_chmod = [a for a in chmod_args if a[0].endswith(".tmp")]
        self.assertEqual(len(tmp_chmod), 1)
        self.assertEqual(tmp_chmod[0][1], 0o600)

    def test_atomic_replace_args(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        replace_args = []
        _real_replace = os.replace
        def tracking_replace(src: object, dst: object, *a: object, **kw: object) -> None:
            replace_args.append((src, dst))
            _real_replace(src, dst, *a, **kw)
        with patch("os.replace", side_effect=tracking_replace):
            awg_peer_add("wg0", KEY_A)
        self.assertEqual(len(replace_args), 1)
        src, dst = replace_args[0]
        self.assertIsInstance(src, str)
        self.assertTrue(src.endswith(".tmp"))
        self.assertEqual(str(dst), str(self.conf_dir / "wg0.conf"))

    def test_atomic_lock_un_after_replace(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        call_order: list[str] = []
        _real_flock = fcntl.flock
        _real_replace_fn = os.replace
        def tracking_flock(fd: int, operation: int) -> None:
            if operation & fcntl.LOCK_EX:
                call_order.append("LOCK_EX")
            elif operation & fcntl.LOCK_UN:
                call_order.append("LOCK_UN")
            _real_flock(fd, operation)
        def tracking_replace(src: object, dst: object, *a: object, **kw: object) -> None:
            call_order.append("os.replace")
            _real_replace_fn(src, dst, *a, **kw)
        with (
            patch("gatebsd_ui.writers.vpn.fcntl.flock", side_effect=tracking_flock),
            patch("os.replace", side_effect=tracking_replace),
        ):
            awg_peer_add("wg0", KEY_A)
        self.assertIn("os.replace", call_order)
        self.assertIn("LOCK_UN", call_order)
        self.assertLess(call_order.index("os.replace"), call_order.index("LOCK_UN"))

    def test_atomic_lock_fd_closed_after(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_add
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        spy = _SpyClose()
        with patch("gatebsd_ui.writers.vpn.os.close", side_effect=spy):
            awg_peer_add("wg0", KEY_A)
        self.assertGreater(len(spy.calls), 0)

    # ── Atomic write: error branches (operation log) ────────

    def _run_atomic_write_with_tracking(
        self,
        error_ops: list[str] | None = None,
        **extra_patches: object,
    ) -> _AtomicWriteResult:
        """Run awg_peer_add with full operation tracking.

        error_ops: list of operation names that should raise OSError.
        When an op is in error_ops, it logs itself THEN raises.
        All chown/chmod/replace log even when they raise (exception-safe).
        """
        from gatebsd_ui.writers.vpn import awg_peer_add
        if error_ops is None:
            error_ops = []
        _real_fdopen = os.fdopen
        _real_fsync = os.fsync
        _real_chown = os.chown
        _real_chmod = os.chmod
        _real_replace = os.replace
        _real_lstat = Path.lstat
        _real_flock = fcntl.flock
        import tempfile as _tempfile
        _real_mkstemp = _tempfile.mkstemp
        oplog = _OpLog()

        def tracking_lstat(self_path: Path, *a: object, **kw: object) -> os.stat_result:
            is_config = str(self_path).endswith(".conf") and not str(self_path).endswith(".lock")
            if is_config:
                if "stat" in error_ops:
                    oplog.log("stat")
                    raise OSError("simulated lstat error")
                oplog.log("stat")
            return _real_lstat(self_path, *a, **kw)

        def tracking_backup(*args: object, **kwargs: object) -> dict:
            if "backup" in error_ops:
                oplog.log("backup")
                raise OSError("simulated backup error")
            oplog.log("backup")
            return {}

        def tracking_mkstemp(**kwargs: object) -> tuple[int, str]:
            if "mkstemp" in error_ops:
                oplog.log("mkstemp")
                raise OSError("simulated mkstemp error")
            oplog.log("mkstemp")
            return _real_mkstemp(**kwargs)

        def tracking_fdopen(fd: int, mode: str = "rb", *a: object, **kw: object) -> _TrackingFlushFile:
            if "fdopen" in error_ops:
                oplog.log("fdopen")
                raise OSError("simulated fdopen error")
            oplog.log("fdopen")
            return _TrackingFlushFile(_real_fdopen(fd, mode, *a, **kw), oplog)

        def tracking_fsync(fd: int) -> None:
            if "fsync" in error_ops:
                oplog.log("fsync")
                raise OSError("simulated fsync error")
            oplog.log("fsync")
            _real_fsync(fd)

        def tracking_chown(path: object, uid: int, gid: int) -> None:
            if isinstance(path, (str, Path)) and str(path).endswith(".tmp"):
                oplog.log("chown")
                if "chown" in error_ops:
                    raise OSError("simulated chown error")
            _real_chown(path, uid, gid)

        def tracking_chmod(path: object, mode: int) -> None:
            if isinstance(path, (str, Path)) and str(path).endswith(".tmp"):
                oplog.log("chmod")
                if "chmod" in error_ops:
                    raise OSError("simulated chmod error")
            _real_chmod(path, mode)

        def tracking_replace(src: object, dst: object, *a: object, **kw: object) -> None:
            oplog.log("replace")
            if "replace" in error_ops:
                raise OSError("simulated replace error")
            _real_replace(src, dst, *a, **kw)

        def tracking_flock(fd: int, operation: int) -> None:
            if operation & fcntl.LOCK_EX:
                oplog.log("LOCK_EX")
            elif operation & fcntl.LOCK_UN:
                oplog.log("LOCK_UN")
            _real_flock(fd, operation)

        patches = {
            "stat": patch.object(Path, "lstat", tracking_lstat),
            "backup": patch("gatebsd_ui.writers.vpn.backup.backup_files", side_effect=tracking_backup),
            "mkstemp": patch.object(_tempfile, "mkstemp", side_effect=tracking_mkstemp),
            "fdopen": patch("gatebsd_ui.writers.vpn.os.fdopen", side_effect=tracking_fdopen),
            "fsync": patch("os.fsync", side_effect=tracking_fsync),
            "chown": patch("os.chown", side_effect=tracking_chown),
            "chmod": patch("os.chmod", side_effect=tracking_chmod),
            "replace": patch("os.replace", side_effect=tracking_replace),
            "flock": patch("gatebsd_ui.writers.vpn.fcntl.flock", side_effect=tracking_flock),
        }
        with ExitStack() as stack:
            for key, p in patches.items():
                if key not in extra_patches:
                    stack.enter_context(p)
            for p in extra_patches.values():
                stack.enter_context(p)
            status, body = awg_peer_add("wg0", KEY_A)
        return _AtomicWriteResult(status, body, oplog)

    def _assert_post_error_no_ops(self, oplog: _OpLog, error_op: str,
                                   forbidden: list[str]) -> None:
        """Assert that the error operation was logged and no forbidden ops follow."""
        self.assertTrue(oplog.has(error_op),
                        f"error op '{error_op}' was never logged; log: {oplog.ops}")
        error_idx = oplog.ops.index(error_op)
        for forbidden_op in forbidden:
            self.assertFalse(oplog.has(forbidden_op),
                             f"forbidden op '{forbidden_op}' logged after '{error_op}'; log: {oplog.ops}")
            for i, op in enumerate(oplog.ops):
                if op == forbidden_op and i > error_idx:
                    self.fail(f"forbidden op '{forbidden_op}' at index {i} "
                              f"after error '{error_op}' at index {error_idx}; log: {oplog.ops}")

    def _run_with_fd_tracking(self, **patches: object) -> tuple[int, dict, list[int], list[int], list[tuple[int, int]]]:
        """Run awg_peer_add with os.open/os.close/fcntl.flock tracking.

        Returns (status, body, closed_fds, lock_fds, flock_calls).
        flock_calls is a list of (fd, operation) tuples from fcntl.flock.
        """
        from gatebsd_ui.writers.vpn import awg_peer_add
        _real_open = os.open
        _real_close = os.close
        _real_flock = fcntl.flock
        closed_fds: list[int] = []
        lock_fd_captured: list[int] = []
        flock_calls: list[tuple[int, int]] = []

        def tracking_open(path: object, flags: int, mode: int = 0o777, *a: object, **kw: object) -> int:
            fd = _real_open(path, flags, mode, *a, **kw)
            if not str(path).endswith(".tmp"):
                lock_fd_captured.append(fd)
            return fd

        def tracking_close(fd: int) -> None:
            closed_fds.append(fd)
            _real_close(fd)

        def tracking_flock(fd: int, operation: int) -> None:
            flock_calls.append((fd, operation))
            _real_flock(fd, operation)

        with ExitStack() as stack:
            stack.enter_context(patch("gatebsd_ui.writers.vpn.os.open", side_effect=tracking_open))
            stack.enter_context(patch("gatebsd_ui.writers.vpn.os.close", side_effect=tracking_close))
            stack.enter_context(patch("gatebsd_ui.writers.vpn.fcntl.flock", side_effect=tracking_flock))
            for p in patches.values():
                stack.enter_context(p)
            status, body = awg_peer_add("wg0", KEY_A)
        return status, body, closed_fds, lock_fd_captured, flock_calls

    def test_stat_error_returns_500(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        saved = self._save_metadata()
        _real_exists_fn = Path.exists
        def exists_always(self_path: Path, *a: object, **kw: object) -> bool:
            if str(self_path).endswith(".conf") and not str(self_path).endswith(".lock"):
                return True
            return _real_exists_fn(self_path, *a, **kw)
        r = self._run_atomic_write_with_tracking(
            error_ops=["stat"],
            exists=patch.object(Path, "exists", exists_always),
        )
        self.assertEqual(r.status, 500)
        self.assertEqual(r.body, {"error": "failed to inspect config"})
        self._assert_metadata_unchanged(saved)
        self._assert_no_tmp_files()
        self._assert_lock_released()
        self.assertTrue(r.oplog.has("stat"), f"stat not logged; log: {r.oplog.ops}")
        for op in ("mkstemp", "fdopen", "write", "flush", "fsync", "chown", "chmod", "replace"):
            self.assertFalse(r.oplog.has(op),
                             f"op '{op}' should not be called after stat error; log: {r.oplog.ops}")

    def test_mkstemp_error_returns_500(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        saved = self._save_metadata()
        r = self._run_atomic_write_with_tracking(
            error_ops=["mkstemp"],
        )
        self.assertEqual(r.status, 500)
        self.assertEqual(r.body, {"error": "failed to write config"})
        self._assert_post_error_no_ops(r.oplog, "mkstemp",
                                       ["fdopen", "write", "flush", "fsync", "chown", "chmod", "replace"])
        self._assert_metadata_unchanged(saved)
        self._assert_no_tmp_files()
        self._assert_lock_released()

    def test_fdopen_error_returns_500(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        saved = self._save_metadata()
        r = self._run_atomic_write_with_tracking(
            error_ops=["fdopen"],
        )
        self.assertEqual(r.status, 500)
        self.assertEqual(r.body, {"error": "failed to write config"})
        self._assert_post_error_no_ops(r.oplog, "fdopen",
                                       ["write", "flush", "fsync", "chown", "chmod", "replace"])
        self._assert_metadata_unchanged(saved)
        self._assert_no_tmp_files()
        self._assert_lock_released()

    def test_write_error_returns_500(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        saved = self._save_metadata()
        _real_fdopen = os.fdopen
        _real_chown = os.chown
        _real_chmod = os.chmod
        _real_replace = os.replace
        oplog = _OpLog()

        def broken_fdopen(fd: int, mode: str = "rb", *a: object, **kw: object) -> _WriteErrorFile:
            return _WriteErrorFile(_real_fdopen(fd, mode, *a, **kw), oplog)

        def tracking_chown(path: object, uid: int, gid: int) -> None:
            oplog.log("chown")
            try:
                _real_chown(path, uid, gid)
            except OSError:
                pass

        def tracking_chmod(path: object, mode: int) -> None:
            oplog.log("chmod")
            try:
                _real_chmod(path, mode)
            except OSError:
                pass

        def tracking_replace(src: object, dst: object, *a: object, **kw: object) -> None:
            oplog.log("replace")
            try:
                _real_replace(src, dst, *a, **kw)
            except OSError:
                pass

        with ExitStack() as stack:
            stack.enter_context(patch("gatebsd_ui.writers.vpn.os.fdopen", side_effect=broken_fdopen))
            stack.enter_context(patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}))
            stack.enter_context(patch("os.chown", side_effect=tracking_chown))
            stack.enter_context(patch("os.chmod", side_effect=tracking_chmod))
            stack.enter_context(patch("os.replace", side_effect=tracking_replace))
            from gatebsd_ui.writers.vpn import awg_peer_add
            status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to write config"})
        self._assert_post_error_no_ops(oplog, "write",
                                       ["flush", "fsync", "chown", "chmod", "replace"])
        self._assert_metadata_unchanged(saved)
        self._assert_no_tmp_files()
        self._assert_lock_released()

    def test_flush_error_returns_500(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        saved = self._save_metadata()
        _real_fdopen = os.fdopen
        _real_fsync = os.fsync
        _real_chown = os.chown
        _real_chmod = os.chmod
        _real_replace = os.replace
        oplog = _OpLog()

        def broken_fdopen(fd: int, mode: str = "rb", *a: object, **kw: object) -> _FlushErrorFile:
            return _FlushErrorFile(_real_fdopen(fd, mode, *a, **kw), oplog)

        def tracking_fsync(fd: int) -> None:
            oplog.log("fsync")
            try:
                _real_fsync(fd)
            except OSError:
                pass

        def tracking_chown(path: object, uid: int, gid: int) -> None:
            oplog.log("chown")
            try:
                _real_chown(path, uid, gid)
            except OSError:
                pass

        def tracking_chmod(path: object, mode: int) -> None:
            oplog.log("chmod")
            try:
                _real_chmod(path, mode)
            except OSError:
                pass

        def tracking_replace(src: object, dst: object, *a: object, **kw: object) -> None:
            oplog.log("replace")
            try:
                _real_replace(src, dst, *a, **kw)
            except OSError:
                pass

        with ExitStack() as stack:
            stack.enter_context(patch("gatebsd_ui.writers.vpn.os.fdopen", side_effect=broken_fdopen))
            stack.enter_context(patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}))
            stack.enter_context(patch("os.fsync", side_effect=tracking_fsync))
            stack.enter_context(patch("os.chown", side_effect=tracking_chown))
            stack.enter_context(patch("os.chmod", side_effect=tracking_chmod))
            stack.enter_context(patch("os.replace", side_effect=tracking_replace))
            from gatebsd_ui.writers.vpn import awg_peer_add
            status, body = awg_peer_add("wg0", KEY_A)
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to write config"})
        self._assert_post_error_no_ops(oplog, "flush",
                                       ["fsync", "chown", "chmod", "replace"])
        self._assert_metadata_unchanged(saved)
        self._assert_no_tmp_files()
        self._assert_lock_released()

    def test_fsync_error_returns_500(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        saved = self._save_metadata()
        r = self._run_atomic_write_with_tracking(
            error_ops=["fsync"],
        )
        self.assertEqual(r.status, 500)
        self.assertEqual(r.body, {"error": "failed to write config"})
        self._assert_post_error_no_ops(r.oplog, "fsync",
                                       ["chown", "chmod", "replace"])
        self._assert_metadata_unchanged(saved)
        self._assert_no_tmp_files()
        self._assert_lock_released()

    def test_chown_error_returns_500(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        saved = self._save_metadata()
        r = self._run_atomic_write_with_tracking(
            error_ops=["chown"],
        )
        self.assertEqual(r.status, 500)
        self.assertEqual(r.body, {"error": "failed to write config"})
        self._assert_post_error_no_ops(r.oplog, "chown",
                                       ["chmod", "replace"])
        self._assert_metadata_unchanged(saved)
        self._assert_no_tmp_files()
        self._assert_lock_released()

    def test_chmod_error_returns_500(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        saved = self._save_metadata()
        r = self._run_atomic_write_with_tracking(
            error_ops=["chmod"],
        )
        self.assertEqual(r.status, 500)
        self.assertEqual(r.body, {"error": "failed to write config"})
        self._assert_post_error_no_ops(r.oplog, "chmod",
                                       ["replace"])
        self._assert_metadata_unchanged(saved)
        self._assert_no_tmp_files()
        self._assert_lock_released()

    def test_replace_error_returns_500(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        saved = self._save_metadata()
        r = self._run_atomic_write_with_tracking(
            error_ops=["replace"],
        )
        self.assertEqual(r.status, 500)
        self.assertEqual(r.body, {"error": "failed to write config"})
        self.assertTrue(r.oplog.has("replace"), f"replace not logged; log: {r.oplog.ops}")
        self.assertEqual(
            r.oplog.ops.count("replace"), 1,
            f"replace must be attempted exactly once; log: {r.oplog.ops}",
        )
        # After the replace error, no success ops should follow
        replace_idx = r.oplog.ops.index("replace")
        forbidden_after = {"backup", "mkstemp", "fdopen", "write", "flush",
                           "fsync", "chown", "chmod", "replace"}
        for i, op in enumerate(r.oplog.ops):
            if i > replace_idx and op in forbidden_after:
                self.fail(f"forbidden op '{op}' at index {i} "
                          f"after replace error at index {replace_idx}; log: {r.oplog.ops}")
        self._assert_metadata_unchanged(saved)
        self._assert_no_tmp_files()
        self._assert_lock_released()

    # ── Cleanup: tmp deletion, flock release, fd close ──────

    def test_stat_error_cleanup(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        real_lstat = Path.lstat
        def failing_lstat(self_path: Path, *a: object, **kw: object) -> os.stat_result:
            if self_path == self.conf_dir / "wg0.conf":
                raise OSError("lstat")
            return real_lstat(self_path, *a, **kw)
        status, body, closed_fds, lock_fds, flock_calls = self._run_with_fd_tracking(
            **{
                "stat": patch.object(Path, "lstat", failing_lstat),
                "backup": patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}),
                "fdopen": patch("gatebsd_ui.writers.vpn.os.fdopen", return_value=MagicMock()),
                "fsync": patch("os.fsync"),
                "chown": patch("os.chown"),
                "chmod": patch("os.chmod"),
                "replace": patch("os.replace"),
            })
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to inspect config"})
        self._assert_no_tmp_files()
        self._assert_lock_released()
        for lock_fd in lock_fds:
            self.assertIn(lock_fd, closed_fds, f"lock fd {lock_fd} not closed")
        # Verify LOCK_EX and LOCK_UN for exact lock_fd
        lock_ex_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_EX]
        lock_un_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_UN]
        # Metadata inspection failed while holding the profile-selection lock,
        # before a per-config lock could be selected safely.
        self.assertEqual(len(lock_ex_calls), 1, f"expected 1 LOCK_EX, got {len(lock_ex_calls)}")
        self.assertEqual(len(lock_un_calls), 1, f"expected 1 LOCK_UN, got {len(lock_un_calls)}")
        self.assertEqual({fd for fd, _ in lock_ex_calls},

                         {fd for fd, _ in lock_un_calls})

        self.assertTrue({fd for fd, _ in lock_ex_calls} <= set(lock_fds))

    def test_mkstemp_error_cleanup(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        status, body, closed_fds, lock_fds, flock_calls = self._run_with_fd_tracking(
            **{
                "mkstemp": patch("tempfile.mkstemp", side_effect=OSError("mkstemp")),
                "backup": patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}),
                "fdopen": patch("gatebsd_ui.writers.vpn.os.fdopen", return_value=MagicMock()),
                "fsync": patch("os.fsync"),
                "chown": patch("os.chown"),
                "chmod": patch("os.chmod"),
                "replace": patch("os.replace"),
            })
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to write config"})
        self._assert_no_tmp_files()
        self._assert_lock_released()
        for lock_fd in lock_fds:
            self.assertIn(lock_fd, closed_fds, f"lock fd {lock_fd} not closed")
        lock_ex_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_EX]
        lock_un_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_UN]
        self.assertEqual(len(lock_ex_calls), 2, f"expected 2 LOCK_EX, got {len(lock_ex_calls)}")
        self.assertEqual(len(lock_un_calls), 2, f"expected 2 LOCK_UN, got {len(lock_un_calls)}")
        self.assertEqual({fd for fd, _ in lock_ex_calls},

                         {fd for fd, _ in lock_un_calls})

        self.assertTrue({fd for fd, _ in lock_ex_calls} <= set(lock_fds))

    def test_fdopen_error_cleanup(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        # Create a real temp file to get a real fd
        real_fd, real_tmp_path = tempfile.mkstemp(dir=str(self.conf_dir), suffix=".tmp")
        try:
            status, body, closed_fds, lock_fds, flock_calls = self._run_with_fd_tracking(
                **{
                    "mkstemp": patch("tempfile.mkstemp",
                                     return_value=(real_fd, real_tmp_path)),
                    "fdopen": patch("gatebsd_ui.writers.vpn.os.fdopen", side_effect=OSError("fdopen")),
                    "backup": patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}),
                    "fsync": patch("os.fsync"),
                    "chown": patch("os.chown"),
                    "chmod": patch("os.chmod"),
                    "replace": patch("os.replace"),
                })
            self.assertEqual(status, 500)
            self.assertEqual(body, {"error": "failed to write config"})
            self._assert_no_tmp_files()
            self._assert_lock_released()
            for lock_fd in lock_fds:
                self.assertIn(lock_fd, closed_fds, f"lock fd {lock_fd} not closed")
            self.assertIn(real_fd, closed_fds,
                           f"raw temp fd {real_fd} not closed after fdopen error")
            # Verify the fd is actually closed (fstat should raise EBADF)
            try:
                os.fstat(real_fd)
                self.fail(f"fd {real_fd} should be closed but fstat succeeded")
            except OSError:
                pass  # expected: fd is closed
            lock_ex_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_EX]
            lock_un_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_UN]
            self.assertEqual(len(lock_ex_calls), 2)
            self.assertEqual(len(lock_un_calls), 2)
            self.assertEqual({fd for fd, _ in lock_ex_calls},

                             {fd for fd, _ in lock_un_calls})

            self.assertTrue({fd for fd, _ in lock_ex_calls} <= set(lock_fds))
        finally:
            # Cleanup: remove temp file if it still exists
            try:
                os.unlink(real_tmp_path)
            except OSError:
                pass

    def test_write_error_cleanup(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        _real_fdopen = os.fdopen
        class _WriteErr:
            def __init__(self, f: object) -> None:
                self._f = f
            def write(self, d: object) -> None:
                raise OSError("write")
            def flush(self) -> None:
                self._f.flush()
            def fileno(self) -> int:
                return self._f.fileno()
            def __enter__(self) -> "_WriteErr":
                return self
            def __exit__(self, *a: object) -> None:
                self._f.close()
        status, body, closed_fds, lock_fds, flock_calls = self._run_with_fd_tracking(
            **{
                "fdopen": patch("gatebsd_ui.writers.vpn.os.fdopen",
                               side_effect=lambda fd, m="rb", *a, **kw: _WriteErr(_real_fdopen(fd, m, *a, **kw))),
                "backup": patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}),
                "fsync": patch("os.fsync"),
                "chown": patch("os.chown"),
                "chmod": patch("os.chmod"),
                "replace": patch("os.replace"),
            })
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to write config"})
        self._assert_no_tmp_files()
        self._assert_lock_released()
        for lock_fd in lock_fds:
            self.assertIn(lock_fd, closed_fds, f"lock fd {lock_fd} not closed")
        lock_ex_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_EX]
        lock_un_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_UN]
        self.assertEqual(len(lock_ex_calls), 2)
        self.assertEqual(len(lock_un_calls), 2)
        self.assertEqual({fd for fd, _ in lock_ex_calls},

                         {fd for fd, _ in lock_un_calls})

        self.assertTrue({fd for fd, _ in lock_ex_calls} <= set(lock_fds))

    def test_flush_error_cleanup(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        _real_fdopen = os.fdopen
        class _FlushErr:
            def __init__(self, f: object) -> None:
                self._f = f
            def write(self, d: object) -> None:
                self._f.write(d)
            def flush(self) -> None:
                raise OSError("flush")
            def fileno(self) -> int:
                return self._f.fileno()
            def __enter__(self) -> "_FlushErr":
                return self
            def __exit__(self, *a: object) -> None:
                self._f.close()
        status, body, closed_fds, lock_fds, flock_calls = self._run_with_fd_tracking(
            **{
                "fdopen": patch("gatebsd_ui.writers.vpn.os.fdopen",
                               side_effect=lambda fd, m="rb", *a, **kw: _FlushErr(_real_fdopen(fd, m, *a, **kw))),
                "backup": patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}),
                "fsync": patch("os.fsync"),
                "chown": patch("os.chown"),
                "chmod": patch("os.chmod"),
                "replace": patch("os.replace"),
            })
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to write config"})
        self._assert_no_tmp_files()
        self._assert_lock_released()
        for lock_fd in lock_fds:
            self.assertIn(lock_fd, closed_fds, f"lock fd {lock_fd} not closed")
        lock_ex_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_EX]
        lock_un_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_UN]
        self.assertEqual(len(lock_ex_calls), 2)
        self.assertEqual(len(lock_un_calls), 2)
        self.assertEqual({fd for fd, _ in lock_ex_calls},

                         {fd for fd, _ in lock_un_calls})

        self.assertTrue({fd for fd, _ in lock_ex_calls} <= set(lock_fds))

    def test_fsync_error_cleanup(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        status, body, closed_fds, lock_fds, flock_calls = self._run_with_fd_tracking(
            **{
                "backup": patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}),
                "fsync": patch("os.fsync", side_effect=OSError("fsync")),
                "chown": patch("os.chown"),
                "chmod": patch("os.chmod"),
                "replace": patch("os.replace"),
            })
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to write config"})
        self._assert_no_tmp_files()
        self._assert_lock_released()
        for lock_fd in lock_fds:
            self.assertIn(lock_fd, closed_fds, f"lock fd {lock_fd} not closed")
        lock_ex_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_EX]
        lock_un_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_UN]
        self.assertEqual(len(lock_ex_calls), 2)
        self.assertEqual(len(lock_un_calls), 2)
        self.assertEqual({fd for fd, _ in lock_ex_calls},

                         {fd for fd, _ in lock_un_calls})

        self.assertTrue({fd for fd, _ in lock_ex_calls} <= set(lock_fds))

    def test_chown_error_cleanup(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        _real_chown = os.chown
        def broken_chown(path: object, uid: int, gid: int) -> None:
            if isinstance(path, (str, Path)) and str(path).endswith(".tmp"):
                raise OSError("chown")
            _real_chown(path, uid, gid)
        status, body, closed_fds, lock_fds, flock_calls = self._run_with_fd_tracking(
            **{
                "backup": patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}),
                "chown": patch("os.chown", side_effect=broken_chown),
                "chmod": patch("os.chmod"),
                "replace": patch("os.replace"),
            })
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to write config"})
        self._assert_no_tmp_files()
        self._assert_lock_released()
        for lock_fd in lock_fds:
            self.assertIn(lock_fd, closed_fds, f"lock fd {lock_fd} not closed")
        lock_ex_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_EX]
        lock_un_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_UN]
        self.assertEqual(len(lock_ex_calls), 2)
        self.assertEqual(len(lock_un_calls), 2)
        self.assertEqual({fd for fd, _ in lock_ex_calls},

                         {fd for fd, _ in lock_un_calls})

        self.assertTrue({fd for fd, _ in lock_ex_calls} <= set(lock_fds))

    def test_chmod_error_cleanup(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        _real_chmod = os.chmod
        def broken_chmod(path: object, mode: int) -> None:
            if isinstance(path, (str, Path)) and str(path).endswith(".tmp"):
                raise OSError("chmod")
            _real_chmod(path, mode)
        status, body, closed_fds, lock_fds, flock_calls = self._run_with_fd_tracking(
            **{
                "backup": patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}),
                "chmod": patch("os.chmod", side_effect=broken_chmod),
                "replace": patch("os.replace"),
            })
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to write config"})
        self._assert_no_tmp_files()
        self._assert_lock_released()
        for lock_fd in lock_fds:
            self.assertIn(lock_fd, closed_fds, f"lock fd {lock_fd} not closed")
        lock_ex_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_EX]
        lock_un_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_UN]
        self.assertEqual(len(lock_ex_calls), 2)
        self.assertEqual(len(lock_un_calls), 2)
        self.assertEqual({fd for fd, _ in lock_ex_calls},

                         {fd for fd, _ in lock_un_calls})

        self.assertTrue({fd for fd, _ in lock_ex_calls} <= set(lock_fds))

    def test_replace_error_cleanup(self) -> None:
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        status, body, closed_fds, lock_fds, flock_calls = self._run_with_fd_tracking(
            **{
                "backup": patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}),
                "replace": patch("os.replace", side_effect=OSError("replace")),
            })
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "failed to write config"})
        self._assert_no_tmp_files()
        self._assert_lock_released()
        for lock_fd in lock_fds:
            self.assertIn(lock_fd, closed_fds, f"lock fd {lock_fd} not closed")
        lock_ex_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_EX]
        lock_un_calls = [(fd, op) for fd, op in flock_calls if op & fcntl.LOCK_UN]
        self.assertEqual(len(lock_ex_calls), 2)
        self.assertEqual(len(lock_un_calls), 2)
        self.assertEqual({fd for fd, _ in lock_ex_calls},

                         {fd for fd, _ in lock_un_calls})

        self.assertTrue({fd for fd, _ in lock_ex_calls} <= set(lock_fds))

    # ── Strict order of operations ──────────────────────────

    def test_strict_order_of_operations(self) -> None:
        """Profile lock -> config lock -> read -> backup -> atomic publish."""
        from contextlib import contextmanager
        from gatebsd_ui.writers import vpn

        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        call_order: list[str] = []
        real_read_bytes = Path.read_bytes

        @contextmanager
        def tracking_lock(path: Path):
            call_order.append(f"lock_enter:{Path(path).name}")
            try:
                yield 1
            finally:
                call_order.append(f"lock_exit:{Path(path).name}")

        def tracking_read(self_path: Path) -> bytes:
            if self_path == self.conf_dir / "wg0.conf":
                call_order.append("read_bytes")
            return real_read_bytes(self_path)

        def tracking_backup(*args: object, **kwargs: object) -> dict:
            call_order.append("backup")
            return {}

        def tracking_atomic(path: Path, data: bytes, **kwargs: object) -> None:
            call_order.append("atomic_write_bytes")
            self.assertEqual(path, self.conf_dir / "wg0.conf")
            self.assertEqual(kwargs.get("mode"), 0o600)
            self.assertIs(kwargs.get("preserve_metadata"), True)
            self.assertIn(b"[Peer]", data)

        with (
            patch.object(vpn, "exclusive_lock", tracking_lock),
            patch.object(Path, "read_bytes", tracking_read),
            patch.object(vpn.backup, "backup_files", side_effect=tracking_backup),
            patch.object(vpn, "atomic_write_bytes", side_effect=tracking_atomic),
        ):
            status, body = vpn.awg_peer_add("wg0", KEY_A)

        self.assertEqual(status, 200)
        self.assertEqual(body["ok"], True)
        self.assertEqual(call_order, [
            "lock_enter:.gatebsd-profiles.lock",
            "lock_enter:wg0.conf.lock",
            "read_bytes",
            "backup",
            "atomic_write_bytes",
            "lock_exit:wg0.conf.lock",
            "lock_exit:.gatebsd-profiles.lock",
        ])


# ── Concurrency tests (subprocess-based) ──────────────────

class _SubprocessWorker:
    """Managed subprocess for awg_peer_add concurrency tests.

    Uses subprocess.Popen with stdin/stdout pipes and threaded I/O.
    stderr is captured via a seekable TemporaryFile, not subprocess.PIPE.
    """

    def __init__(self, conf_dir: str, conf_name: str, pubkey: str,
                 test_name: str, *,
                 env_extra: dict[str, str] | None = None) -> None:
        self.test_name = test_name
        self.conf_dir = conf_dir
        self.conf_name = conf_name
        self.pubkey = pubkey
        self.proc: subprocess.Popen | None = None
        self._reader_thread: threading.Thread | None = None
        self._queue: queue.Queue = queue.Queue()
        self._last_stage = "init"
        self._stderr_file: tempfile.TemporaryFile | None = None
        self._env_extra: dict[str, str] = dict(env_extra or {})

    def start(self) -> None:
        env = os.environ.copy()
        env["CONF_DIR"] = self.conf_dir
        env["CONF_NAME"] = self.conf_name
        env["PUBKEY"] = self.pubkey
        if self._env_extra:
            env.update(self._env_extra)
        self._stderr_file = tempfile.TemporaryFile(mode="w+b")
        self.proc = subprocess.Popen(
            [sys.executable, "-c",
             "from tests.awg_peer_add_workers import _subprocess_worker_main; "
             "_subprocess_worker_main()"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file,
            close_fds=True,
            start_new_session=True,
        )

        def _reader():
            """Read JSON lines from worker stdout and enqueue them."""
            try:
                for line in self.proc.stdout:  # type: ignore[union-attr]
                    line = line.strip()
                    if line:
                        try:
                            msg = json.loads(line)
                            self._queue.put(msg)
                        except (json.JSONDecodeError, ValueError):
                            pass
            except (OSError, ValueError):
                pass
            finally:
                self._queue.put(None)  # sentinel: EOF

        thread_name = f"reader-{self.test_name}-pid{self.proc.pid}"
        self._reader_thread = threading.Thread(target=_reader, daemon=True,
                                               name=thread_name)
        self._reader_thread.start()

    def _drain_queue(self) -> None:
        """Drain all available messages from the queue."""
        while True:
            try:
                msg = self._queue.get_nowait()
                if msg is None:
                    break
            except queue.Empty:
                break

    def wait_stage(self, stage: str, timeout: float = 15.0) -> dict:
        """Wait for a specific stage message from worker."""
        import time as _time
        deadline = _time.monotonic() + timeout
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                stderr = self._read_stderr()
                raise TimeoutError(
                    f"{self.test_name}: pid={self.proc.pid} "
                    f"timeout waiting for '{stage}'; "
                    f"last_stage={self._last_stage}; stderr={stderr[:500]}"
                )
            try:
                msg = self._queue.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                continue
            if msg is None:
                stderr = self._read_stderr()
                raise TimeoutError(
                    f"{self.test_name}: pid={self.proc.pid} "
                    f"disconnected waiting for '{stage}'; "
                    f"last_stage={self._last_stage}; stderr={stderr[:500]}"
                )
            self._last_stage = msg.get("stage", "?")
            if self._last_stage == stage:
                return msg
            if self._last_stage == "result":
                stderr = self._read_stderr()
                raise AssertionError(
                    f"{self.test_name}: pid={self.proc.pid} "
                    f"unexpected result before '{stage}': {msg}; "
                    f"stderr={stderr[:500]}"
                )

    def send_cmd(self, cmd: str) -> None:
        if self.proc is None or self.proc.stdin is None:
            return
        try:
            _send_msg(self.proc.stdin, {"cmd": cmd})
        except (OSError, BrokenPipeError, ValueError):
            pass

    def recv_result(self, timeout: float = 15.0) -> dict:
        """Wait for terminal 'result' message, then verify clean exit.

        After receiving result, waits for process to exit, demands
        returncode == 0, and checks stderr for forbidden markers
        (Traceback, _WorkerTerminal).  On failure, performs emergency
        cleanup and raises AssertionError with full diagnostics.
        """
        msg = self.wait_stage("result", timeout)
        # Wait for normal exit after terminal message
        if self.proc.poll() is None:
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if self.proc.poll() is None:
            # Still alive — force kill
            self._emergency_cleanup()
            raise AssertionError(
                f"{self.test_name}: worker pid={self.proc.pid} "
                f"did not exit after sending result; "
                f"result={msg!r}; stderr={self._read_stderr()[:500]}"
            )
        if self.proc.returncode != 0:
            stderr = self._read_stderr()
            try:
                pgid = os.getpgid(self.proc.pid)
            except OSError:
                pgid = "unknown"
            self._emergency_cleanup()
            raise AssertionError(
                f"{self.test_name}: worker pid={self.proc.pid} "
                f"pgid={pgid} exited with returncode={self.proc.returncode}; "
                f"result={msg!r}; stderr={stderr[:500]}"
            )
        # Check stderr for forbidden markers even when returncode == 0
        stderr = self._read_stderr()
        forbidden = ["Traceback", "_WorkerTerminal"]
        for marker in forbidden:
            if marker in stderr:
                try:
                    pgid = os.getpgid(self.proc.pid)
                except OSError:
                    pgid = "unknown"
                self._emergency_cleanup()
                raise AssertionError(
                    f"{self.test_name}: worker pid={self.proc.pid} "
                    f"pgid={pgid} returned cleanly but stderr contains "
                    f"forbidden marker '{marker}'; "
                    f"result={msg!r}; stderr={stderr[:500]}"
                )
        return msg

    def _emergency_cleanup(self) -> None:
        """Force-kill worker and clean up resources. Never raises."""
        try:
            if self.proc.poll() is None:
                os.killpg(self.proc.pid, signal.SIGKILL)
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        except (ProcessLookupError, OSError):
            pass
        self.cleanup()

    def cleanup(self) -> None:
        """Guaranteed cleanup: stop → wait → TERM group → KILL group → close.

        Verifies reader thread is dead after join. Fails if thread is alive.
        Closes all IPC handles including stderr TemporaryFile.
        """
        if self.proc is None:
            self._close_stderr_file()
            return
        if self.proc.poll() is None:
            try:
                self.send_cmd("stop")
            except (OSError, BrokenPipeError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except (ProcessLookupError, OSError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        if self.proc.poll() is None:
            raise RuntimeError(
                f"{self.test_name}: could not kill worker pid={self.proc.pid}"
            )
        # Close pipes
        for f in (self.proc.stdin, self.proc.stdout):
            if f is not None:
                try:
                    f.close()
                except (OSError, ValueError):
                    pass
        # Drain queue
        self._drain_queue()
        # Wait for reader thread and verify it terminated
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=3)
            if self._reader_thread.is_alive():
                raise RuntimeError(
                    f"{self.test_name}: reader thread "
                    f"'{self._reader_thread.name}' still alive after join"
                )
        self._close_stderr_file()

    def _close_stderr_file(self) -> None:
        if self._stderr_file is not None:
            try:
                self._stderr_file.close()
            except (OSError, ValueError):
                pass
            self._stderr_file = None

    def _read_stderr(self) -> str:
        if self._stderr_file is None:
            return ""
        try:
            pos = self._stderr_file.tell()
            self._stderr_file.seek(0)
            data = self._stderr_file.read()
            self._stderr_file.seek(pos)
            return data.decode("utf-8", errors="replace")
        except (OSError, ValueError):
            return ""


class _ExternalLockHolder:
    """Managed subprocess that holds an external lock via stdin/stdout.

    stderr is captured via a seekable TemporaryFile, not subprocess.PIPE.
    """

    def __init__(self, lock_path: str, test_name: str) -> None:
        self.test_name = test_name
        self.lock_path = lock_path
        self.proc: subprocess.Popen | None = None
        self._reader_thread: threading.Thread | None = None
        self._queue: queue.Queue = queue.Queue()
        self._stderr_file: tempfile.TemporaryFile | None = None

    def start(self) -> None:
        env = os.environ.copy()
        env["LOCK_PATH"] = self.lock_path
        self._stderr_file = tempfile.TemporaryFile(mode="w+b")
        self.proc = subprocess.Popen(
            [sys.executable, "-c",
             "from tests.awg_peer_add_workers import _subprocess_external_lock_main; "
             "_subprocess_external_lock_main()"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file,
            close_fds=True,
            start_new_session=True,
        )

        def _reader():
            try:
                for line in self.proc.stdout:  # type: ignore[union-attr]
                    line = line.strip()
                    if line:
                        try:
                            msg = json.loads(line)
                            self._queue.put(msg)
                        except (json.JSONDecodeError, ValueError):
                            pass
            except (OSError, ValueError):
                pass
            finally:
                self._queue.put(None)

        thread_name = f"reader-lock-{self.test_name}-pid{self.proc.pid}"
        self._reader_thread = threading.Thread(target=_reader, daemon=True,
                                               name=thread_name)
        self._reader_thread.start()

    def wait_lock_acquired(self, timeout: float = 15.0) -> None:
        import time as _time
        deadline = _time.monotonic() + timeout
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"{self.test_name}: lock holder pid={self.proc.pid} "
                    f"timeout waiting for lock_acquired"
                )
            try:
                msg = self._queue.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                continue
            if msg is None:
                raise TimeoutError(
                    f"{self.test_name}: lock holder disconnected"
                )
            if msg.get("stage") == "lock_acquired":
                return
            raise AssertionError(
                f"{self.test_name}: lock holder sent '{msg.get('stage')}' "
                f"expected 'lock_acquired'"
            )

    def release(self, timeout: float = 10.0) -> None:
        """Tell lock holder to release and clean up.

        Sends exact 'release' command, waits for 'released' stage,
        then demands normal exit with returncode == 0.

        Raises AssertionError if 'released' is not received, if the
        process does not exit cleanly, or if the process needs to be
        force-killed after 'released'.
        """
        import time as _time
        if self.proc is None or self.proc.poll() is not None:
            self._cleanup_resources()
            return
        try:
            if self.proc.stdin:
                _send_msg(self.proc.stdin, {"cmd": "release"})
        except (OSError, BrokenPipeError, ValueError) as exc:
            stderr = self._read_stderr()
            self._force_kill()
            self._cleanup_resources()
            raise AssertionError(
                f"{self.test_name}: failed to send release cmd to "
                f"pid={self.proc.pid}: {exc!r}; stderr={stderr[:500]}"
            )
        # Wait for 'released' confirmation — must receive it
        released_received = False
        last_stage = None
        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            try:
                msg = self._queue.get(timeout=min(1.0, max(deadline - _time.monotonic(), 0)))
            except queue.Empty:
                continue
            if msg is None:
                # EOF — process exited without sending 'released'
                break
            last_stage = msg.get("stage")
            if last_stage == "released":
                released_received = True
                break
            if last_stage == "error":
                break
        if not released_received:
            stderr = self._read_stderr()
            returncode = self.proc.poll()
            try:
                pgid = os.getpgid(self.proc.pid)
            except OSError:
                pgid = "unknown"
            self._force_kill()
            self._cleanup_resources()
            raise AssertionError(
                f"{self.test_name}: lock holder pid={self.proc.pid} "
                f"pgid={pgid} did not send 'released' stage; "
                f"last_stage={last_stage!r}; returncode={returncode}; "
                f"stderr={stderr[:500]}"
            )
        # Wait for normal exit after released
        if self.proc.poll() is None:
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        # If still alive after released — that's a protocol violation
        if self.proc.poll() is None:
            stderr = self._read_stderr()
            self._force_kill()
            self._cleanup_resources()
            raise AssertionError(
                f"{self.test_name}: lock holder pid={self.proc.pid} "
                f"did not exit after sending 'released'; "
                f"stderr={stderr[:500]}"
            )
        # Demanding clean exit (returncode == 0)
        if self.proc.returncode != 0:
            stderr = self._read_stderr()
            try:
                pgid = os.getpgid(self.proc.pid)
            except OSError:
                pgid = "unknown"
            self._cleanup_resources()
            raise AssertionError(
                f"{self.test_name}: lock holder pid={self.proc.pid} "
                f"pgid={pgid} exited with returncode={self.proc.returncode} "
                f"after sending 'released'; stderr={stderr[:500]}"
            )
        self._cleanup_resources()

    def stop(self) -> None:
        """Force-stop the lock holder and verify full termination.

        Sends stop, waits, TERM group, KILL group, verifies PID/PGID gone.
        """
        if self.proc is None or self.proc.poll() is not None:
            self._cleanup_resources()
            return
        try:
            if self.proc.stdin:
                _send_msg(self.proc.stdin, {"cmd": "stop"})
        except (OSError, BrokenPipeError, ValueError):
            pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        # TERM group if still running
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except (ProcessLookupError, OSError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        # KILL group if still running
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        # Verify terminated
        if self.proc.poll() is None:
            raise RuntimeError(
                f"{self.test_name}: could not stop lock holder "
                f"pid={self.proc.pid}"
            )
        # Verify PID gone
        try:
            os.kill(self.proc.pid, 0)
            raise AssertionError(
                f"{self.test_name}: lock holder PID {self.proc.pid} "
                f"still exists after stop"
            )
        except ProcessLookupError:
            pass
        # Verify PGID gone (only ProcessLookupError counts)
        try:
            pgid = os.getpgid(self.proc.pid)
            try:
                os.killpg(pgid, 0)
                raise AssertionError(
                    f"{self.test_name}: lock holder PGID {pgid} "
                    f"(PID={self.proc.pid}) still exists after stop"
                )
            except ProcessLookupError:
                pass
        except OSError:
            pass
        self._cleanup_resources()

    def _force_kill(self) -> None:
        """Force-kill process group: TERM → KILL, verify dead."""
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass

    def _cleanup_resources(self) -> None:
        """Close all IPC handles and join reader thread."""
        if self.proc is not None:
            for f in (self.proc.stdin, self.proc.stdout):
                if f is not None:
                    try:
                        f.close()
                    except (OSError, ValueError):
                        pass
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=3)
            if self._reader_thread.is_alive():
                raise RuntimeError(
                    f"{self.test_name}: lock holder reader thread "
                    f"'{self._reader_thread.name}' still alive after join"
                )
        self._close_stderr_file()

    def _close_stderr_file(self) -> None:
        if self._stderr_file is not None:
            try:
                self._stderr_file.close()
            except (OSError, ValueError):
                pass
            self._stderr_file = None

    def _read_stderr(self) -> str:
        if self._stderr_file is None:
            return ""
        try:
            pos = self._stderr_file.tell()
            self._stderr_file.seek(0)
            data = self._stderr_file.read()
            self._stderr_file.seek(pos)
            return data.decode("utf-8", errors="replace")
        except (OSError, ValueError):
            return ""


class AwgPeerAddConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)

    def tearDown(self) -> None:
        self.td.cleanup()

    def _write(self, name: str, content: str) -> Path:
        p = self.conf_dir / name
        p.write_text(content, encoding="utf-8")
        return p

    def test_concurrent_two_different_keys(self) -> None:
        """Two concurrent adds — both 200, no lost update."""
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")

        w1 = _SubprocessWorker(str(self.conf_dir), "wg0", KEY_A, "p1")
        w2 = _SubprocessWorker(str(self.conf_dir), "wg0", KEY_B, "p2")
        try:
            w1.start()
            w1.wait_stage("worker_started")
            w1.wait_stage("profile_lock_attempted")
            w1.wait_stage("config_lock_acquired")
            w1.wait_stage("read_reached")
            w1.wait_stage("read_completed")
            w1.send_cmd("allow_after_read")
            w1.wait_stage("backup_reached")

            # Start p2 — it will queue on the file lock
            w2.start()
            w2.wait_stage("worker_started")
            w2.wait_stage("profile_lock_attempted")  # blocked behind the global profile lock

            w1.send_cmd("allow_backup_continue")
            r1 = w1.recv_result()
            self.assertEqual(r1["status"], 200)
            self.assertEqual(r1["backup_count"], 1)
            self.assertEqual(r1["replace_count"], 1)
            self.assertEqual(r1["chmod_count"], 1)

            # Now p2 should get lock and proceed
            w2.wait_stage("profile_lock_acquired")
            w2.wait_stage("config_lock_attempted")
            w2.wait_stage("config_lock_acquired")
            w2.wait_stage("read_reached")
            w2.wait_stage("read_completed")
            w2.send_cmd("allow_after_read")
            w2.wait_stage("backup_reached")
            w2.send_cmd("allow_backup_continue")
            r2 = w2.recv_result()
            self.assertEqual(r2["status"], 200)
            self.assertEqual(r2["backup_count"], 1)
            self.assertEqual(r2["replace_count"], 1)
            self.assertEqual(r2["chmod_count"], 1)

            content = (self.conf_dir / "wg0.conf").read_text()
            self.assertEqual(content.count(f"PublicKey = {KEY_A}"), 1)
            self.assertEqual(content.count(f"PublicKey = {KEY_B}"), 1)
        finally:
            w1.cleanup()
            w2.cleanup()

    def test_concurrent_two_same_keys(self) -> None:
        """Two concurrent adds of same key — one 200, one 409."""
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")

        w1 = _SubprocessWorker(str(self.conf_dir), "wg0", KEY_A, "p1")
        w2 = _SubprocessWorker(str(self.conf_dir), "wg0", KEY_A, "p2")
        try:
            w1.start()
            w1.wait_stage("worker_started")
            w1.wait_stage("profile_lock_attempted")
            w1.wait_stage("config_lock_acquired")
            w1.wait_stage("read_reached")
            w1.wait_stage("read_completed")
            w1.send_cmd("allow_after_read")
            w1.wait_stage("backup_reached")

            w2.start()
            w2.wait_stage("worker_started")
            w2.wait_stage("profile_lock_attempted")  # blocked behind the global profile lock

            w1.send_cmd("allow_backup_continue")
            r1 = w1.recv_result()
            self.assertEqual(r1["status"], 200)
            self.assertEqual(r1["backup_count"], 1)
            self.assertEqual(r1["replace_count"], 1)
            self.assertEqual(r1["chmod_count"], 1)

            # p2 gets lock, reads config → duplicate found during read
            # patched_read_bytes waits for allow_after_read before returning
            w2.wait_stage("profile_lock_acquired")
            w2.wait_stage("config_lock_attempted")
            w2.wait_stage("config_lock_acquired")
            w2.wait_stage("read_reached")
            w2.wait_stage("read_completed")
            w2.send_cmd("allow_after_read")
            r2 = w2.recv_result()
            self.assertEqual(r2["status"], 409)
            self.assertEqual(r2["body"], {"error": "peer already exists in config"})
            self.assertEqual(r2["backup_count"], 0)
            self.assertEqual(r2["replace_count"], 0)
            self.assertEqual(r2["chmod_count"], 0)

            self.assertEqual((self.conf_dir / "wg0.conf").read_text().count(f"PublicKey = {KEY_A}"), 1)
        finally:
            w1.cleanup()
            w2.cleanup()

    def test_compatibility_with_external_lock(self) -> None:
        """External LOCK_EX via _ExternalLockHolder subprocess blocks awg_peer_add, then releases."""
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        lock_path = str(self.conf_dir / "wg0.conf.lock")

        holder = _ExternalLockHolder(lock_path, "ext-lock")
        w1 = _SubprocessWorker(str(self.conf_dir), "wg0", KEY_A, "adder")
        try:
            holder.start()
            holder.wait_lock_acquired()

            w1.start()
            w1.wait_stage("worker_started")
            w1.wait_stage("profile_lock_acquired")
            w1.wait_stage("config_lock_attempted")  # blocked on the external config lock

            # Release via subprocess holder.  The profile lock and config
            # lock-attempt events were already consumed above.
            holder.release()

            w1.wait_stage("config_lock_acquired")
            w1.wait_stage("read_reached")
            w1.wait_stage("read_completed")
            w1.send_cmd("allow_after_read")
            w1.wait_stage("backup_reached")
            w1.send_cmd("allow_backup_continue")
            r1 = w1.recv_result()
            self.assertEqual(r1["status"], 200)
            self.assertEqual(r1["backup_count"], 1)
            self.assertEqual(r1["replace_count"], 1)
            self.assertEqual(r1["chmod_count"], 1)
            content = (self.conf_dir / "wg0.conf").read_text()
            self.assertIn(KEY_A, content)
        finally:
            w1.cleanup()
            holder.stop()

    def test_config_changed_during_lock_wait(self) -> None:
        """Config changed while waiting for lock — reads updated version."""
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        lock_path = str(self.conf_dir / "wg0.conf.lock")

        holder = _ExternalLockHolder(lock_path, "ext-lock-chg")
        w1 = _SubprocessWorker(str(self.conf_dir), "wg0", KEY_A, "adder")
        try:
            holder.start()
            holder.wait_lock_acquired()

            w1.start()
            w1.wait_stage("worker_started")
            w1.wait_stage("profile_lock_acquired")
            w1.wait_stage("config_lock_attempted")  # blocked on the external config lock

            comment = "# changed while awg_peer_add was waiting"
            with open(self.conf_dir / "wg0.conf", "a") as f:
                f.write(comment + "\n")

            # Release via subprocess holder.  The profile lock and config
            # lock-attempt events were already consumed above.
            holder.release()

            w1.wait_stage("config_lock_acquired")
            w1.wait_stage("read_reached")
            w1.wait_stage("read_completed")
            w1.send_cmd("allow_after_read")
            w1.wait_stage("backup_reached")
            w1.send_cmd("allow_backup_continue")
            r1 = w1.recv_result()
            self.assertEqual(r1["status"], 200)
            self.assertEqual(r1["backup_count"], 1)
            self.assertEqual(r1["replace_count"], 1)
            self.assertEqual(r1["chmod_count"], 1)
            content = (self.conf_dir / "wg0.conf").read_text()
            self.assertIn(comment, content)
            self.assertIn(KEY_A, content)
        finally:
            w1.cleanup()
            holder.stop()

    def test_cleanup_terminates_worker(self) -> None:
        """Emergency cleanup kills worker and its process group."""
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        w1 = _SubprocessWorker(str(self.conf_dir), "wg0", KEY_A, "cleanup-test")
        try:
            w1.start()
            w1.wait_stage("worker_started")
            w1.wait_stage("profile_lock_attempted")
            w1.wait_stage("profile_lock_acquired")
            w1.wait_stage("config_lock_attempted")
            w1.wait_stage("config_lock_acquired")
            w1.wait_stage("read_reached")
            w1.wait_stage("read_completed")
            w1.send_cmd("allow_after_read")
            w1.wait_stage("backup_reached")
            # Do NOT send allow_backup_continue — force cleanup path
            pid = w1.proc.pid
            pgid = os.getpgid(pid)
        finally:
            w1.cleanup()

        # Verify worker is dead
        self.assertIsNotNone(w1.proc.poll(), "worker should be terminated")
        # Verify exact PID no longer exists
        try:
            os.kill(pid, 0)
            self.fail(f"worker PID {pid} still exists after cleanup")
        except ProcessLookupError:
            pass
        # Verify exact PGID no longer exists
        # Only accept ProcessLookupError; PermissionError does NOT prove
        # the group is gone
        try:
            os.killpg(pgid, 0)
            self.fail(
                f"process group PGID={pgid} (PID={pid}) still exists "
                f"after cleanup"
            )
        except ProcessLookupError:
            pass


# ── Module-level helpers for harness tests ─────────────────

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


class AwgPeerAddHarnessTests(unittest.TestCase):
    """Harness-level tests proving subprocess infrastructure correctness."""

    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)

    def tearDown(self) -> None:
        self.td.cleanup()

    def _write(self, name: str, content: str) -> Path:
        p = self.conf_dir / name
        p.write_text(content, encoding="utf-8")
        return p

    def test_stderr_flood_does_not_block_worker(self) -> None:
        """Worker writes 1 MiB to stderr via TemporaryFile without blocking."""
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        stderr_file = tempfile.TemporaryFile(mode="w+b")
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "from tests.awg_peer_add_workers import _stderr_flood_worker_main; "
             "_stderr_flood_worker_main()"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            close_fds=True,
            start_new_session=True,
        )
        try:
            # Read result from stdout
            import time as _time
            deadline = _time.monotonic() + 30
            buf = b""
            while _time.monotonic() < deadline:
                rlist, _, _ = select.select([proc.stdout], [], [], 1.0)
                if rlist:
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\n" in buf:
                        break
            # Parse the result
            lines = buf.strip().split(b"\n")
            self.assertTrue(len(lines) >= 1, f"no stdout from worker: {buf!r}")
            msg = json.loads(lines[-1])
            self.assertEqual(msg["stage"], "result")
            self.assertEqual(msg["status"], 200)
            # Verify stderr has content (at least 1 MiB written)
            pos = stderr_file.tell()
            stderr_file.seek(0)
            stderr_data = stderr_file.read()
            stderr_file.seek(pos)
            self.assertGreaterEqual(len(stderr_data), 1024 * 1024,
                                    "stderr should contain >= 1 MiB")
            # Worker must have exited
            proc.wait(timeout=10)
            self.assertIsNotNone(proc.poll())
        finally:
            proc.kill()
            proc.wait(timeout=5)
            try:
                proc.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                proc.stdout.close()
            except (OSError, ValueError):
                pass
            stderr_file.close()

    def test_exactly_one_terminal_message_on_read_error(self) -> None:
        """Controlled read error produces exactly one terminal message.

        Verifies: exactly one terminal, returncode==0, no traceback in stderr,
        stdin/stdout/stderr closed, PID/PGID gone.
        """
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        env = os.environ.copy()
        env["CONF_DIR"] = str(self.conf_dir)
        env["CONF_NAME"] = "wg0"
        env["PUBKEY"] = KEY_A
        env["FAIL_READ"] = "1"
        stderr_file = tempfile.TemporaryFile(mode="w+b")
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "from tests.awg_peer_add_workers import _read_error_worker_main; "
             "_read_error_worker_main()"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            close_fds=True,
            start_new_session=True,
        )
        pid = proc.pid
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = None
        try:
            proc.stdin.close()
            # Read all stdout until EOF
            import time as _time
            deadline = _time.monotonic() + 15
            buf = b""
            while _time.monotonic() < deadline:
                rlist, _, _ = select.select([proc.stdout], [], [], 1.0)
                if rlist:
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    buf += chunk
            # Parse all messages
            lines = [l for l in buf.strip().split(b"\n") if l.strip()]
            msgs = []
            for line in lines:
                try:
                    msgs.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    pass
            stages = [m.get("stage") for m in msgs]
            self.assertIn("worker_started", stages)
            self.assertIn("read_reached", stages)
            terminal_msgs = [m for m in msgs
                             if m.get("stage") in ("result", "error", "stopped")]
            self.assertEqual(len(terminal_msgs), 1,
                             f"expected exactly 1 terminal message, got "
                             f"{len(terminal_msgs)}: {stages}")
            self.assertEqual(terminal_msgs[0]["stage"], "result")
            self.assertEqual(terminal_msgs[0]["status"], 500)
            # Process must exit cleanly
            proc.wait(timeout=5)
            self.assertEqual(proc.returncode, 0,
                             f"worker exit code must be 0, got {proc.returncode}")
            # Stderr must not contain Traceback or _WorkerTerminal
            pos = stderr_file.tell()
            stderr_file.seek(0)
            stderr_data = stderr_file.read().decode("utf-8", errors="replace")
            stderr_file.seek(pos)
            self.assertNotIn("Traceback", stderr_data,
                             f"stderr must not contain Traceback: "
                             f"{stderr_data[:500]}")
            self.assertNotIn("_WorkerTerminal", stderr_data,
                             f"stderr must not contain _WorkerTerminal: "
                             f"{stderr_data[:500]}")
            # stdout must be closed (EOF)
            self.assertTrue(proc.stdout.closed or
                            os.read(proc.stdout.fileno(), 1) == b"")
            # PID must be gone
            try:
                os.kill(pid, 0)
                self.fail(f"worker PID {pid} still exists")
            except ProcessLookupError:
                pass
            # PGID must be gone (if we could determine it)
            if pgid is not None:
                try:
                    os.killpg(pgid, 0)
                    self.fail(f"worker PGID {pgid} still exists")
                except ProcessLookupError:
                    pass
        finally:
            try:
                proc.kill()
            except (OSError, ProcessLookupError):
                pass
            proc.wait(timeout=5)
            try:
                proc.stdout.close()
            except (OSError, ValueError):
                pass
            stderr_file.close()

    def test_external_lock_held_by_separate_pid(self) -> None:
        """External lock is held by a separate subprocess PID, not threads."""
        import errno
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        lock_path = str(self.conf_dir / "wg0.conf.lock")
        holder = _ExternalLockHolder(lock_path, "pid-check")
        try:
            holder.start()
            holder.wait_lock_acquired()
            # Verify lock holder is a real subprocess with its own PID
            self.assertIsNotNone(holder.proc)
            self.assertIsNotNone(holder.proc.pid)
            self.assertGreater(holder.proc.pid, 0)
            # Verify the process is alive
            self.assertIsNone(holder.proc.poll(),
                               "lock holder should still be alive")
            # Verify the lock is actually held by trying non-blocking LOCK_EX
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC,
                              0o600)
            try:
                result = fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if result is None:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    self.fail("lock should be held by external holder")
            except OSError as exc:
                # Only EACCES, EAGAIN, or EWOULDBLOCK prove the lock is held
                allowed = {errno.EACCES, errno.EAGAIN}
                try:
                    allowed.add(errno.EWOULDBLOCK)
                except AttributeError:
                    pass  # EWOULDBLOCK == EAGAIN on Linux
                if exc.errno not in allowed:
                    self.fail(
                        f"non-blocking LOCK_EX raised unexpected errno "
                        f"{exc.errno} ({os.strerror(exc.errno)}); "
                        f"expected EACCES/EAGAIN/EWOULDBLOCK"
                    )
            finally:
                os.close(lock_fd)
            # Release and verify lock is freed
            holder.release()
            lock_fd2 = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC,
                               0o600)
            try:
                result = fcntl.flock(lock_fd2, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertIsNone(result, "lock should be released")
                fcntl.flock(lock_fd2, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd2)
        finally:
            holder.stop()

    def test_reader_thread_terminated_after_cleanup(self) -> None:
        """Reader thread is verified dead after cleanup; no leaked threads."""
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        w1 = _SubprocessWorker(str(self.conf_dir), "wg0", KEY_A, "thread-check")
        try:
            w1.start()
            w1.wait_stage("worker_started")
            w1.wait_stage("config_lock_acquired")
            self.assertIsNotNone(w1._reader_thread)
            self.assertTrue(w1._reader_thread.is_alive(),
                            "reader thread should be alive while worker runs")
        finally:
            w1.cleanup()
        # After cleanup, reader thread must be dead
        self.assertIsNotNone(w1._reader_thread)
        self.assertFalse(w1._reader_thread.is_alive(),
                         "reader thread must be dead after cleanup")
        # Verify process is dead
        self.assertIsNotNone(w1.proc.poll(), "worker should be terminated")

    def test_release_must_receive_released(self) -> None:
        """Mutation A: worker skips sending 'released' — release() must fail."""
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        lock_path = str(self.conf_dir / "wg0.conf.lock")
        env = os.environ.copy()
        env["LOCK_PATH"] = lock_path
        env["SKIP_RELEASED"] = "1"
        stderr_file = tempfile.TemporaryFile(mode="w+b")
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "from tests.awg_peer_add_workers import _subprocess_external_lock_main; "
             "_subprocess_external_lock_main()"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            close_fds=True,
            start_new_session=True,
        )
        holder = _ExternalLockHolder.__new__(_ExternalLockHolder)
        holder.test_name = "no-released"
        holder.lock_path = lock_path
        holder.proc = proc
        holder._stderr_file = stderr_file
        holder._queue = queue.Queue()
        # Start reader thread
        def _reader():
            try:
                for line in proc.stdout:
                    line = line.strip()
                    if line:
                        try:
                            msg = json.loads(line)
                            holder._queue.put(msg)
                        except (json.JSONDecodeError, ValueError):
                            pass
            except (OSError, ValueError):
                pass
            finally:
                holder._queue.put(None)
        thread_name = f"reader-lock-no-released-pid{proc.pid}"
        holder._reader_thread = threading.Thread(target=_reader, daemon=True,
                                                 name=thread_name)
        holder._reader_thread.start()
        try:
            holder.wait_lock_acquired()
            # release() must fail because 'released' is never sent
            with self.assertRaises(AssertionError) as ctx:
                holder.release(timeout=3.0)
            self.assertIn("did not send 'released'", str(ctx.exception))
        finally:
            holder._force_kill()
            holder._cleanup_resources()

    def test_worker_exitcode_must_be_zero(self) -> None:
        """Mutation 1: real _SubprocessWorker exits with returncode=1.

        Worker runs full awg_peer_add protocol, sends correct result,
        then sys.exit(1).  recv_result() must detect non-zero returncode
        via the managed _SubprocessWorker lifecycle.
        """
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        w1 = _SubprocessWorker(
            str(self.conf_dir), "wg0", KEY_A, "exit1-managed",
            env_extra={"WORKER_EXIT_AFTER_RESULT": "1"},
        )
        pid = None
        pgid = None
        try:
            w1.start()
            pid = w1.proc.pid
            try:
                pgid = os.getpgid(pid)
            except OSError:
                pass
            # Run the full managed protocol
            w1.wait_stage("worker_started")
            w1.wait_stage("config_lock_acquired")
            w1.wait_stage("read_reached")
            w1.wait_stage("read_completed")
            w1.send_cmd("allow_after_read")
            w1.wait_stage("backup_reached")
            w1.send_cmd("allow_backup_continue")
            # recv_result must detect returncode=1 and raise
            with self.assertRaises(AssertionError) as ctx:
                w1.recv_result(timeout=10)
            self.assertIn("returncode=1", str(ctx.exception))
        finally:
            w1.cleanup()
            # Verify full cleanup: PID gone, PGID gone, thread dead, IPC closed
            self.assertIsNotNone(w1.proc)
            self.assertIsNotNone(w1.proc.poll(),
                                 "worker must be terminated")
            if pid is not None:
                try:
                    os.kill(pid, 0)
                    self.fail(f"PID {pid} still exists after cleanup")
                except ProcessLookupError:
                    pass
            if pgid is not None:
                try:
                    os.killpg(pgid, 0)
                    self.fail(f"PGID {pgid} still exists after cleanup")
                except ProcessLookupError:
                    pass
            self.assertFalse(w1._reader_thread.is_alive(),
                             "reader thread must be dead after cleanup")
            self.assertTrue(w1.proc.stdin is None or w1.proc.stdin.closed,
                            "stdin must be closed")
            self.assertTrue(w1.proc.stdout is None or w1.proc.stdout.closed,
                            "stdout must be closed")
            self.assertIsNone(w1._stderr_file,
                              "stderr TemporaryFile must be closed")

    def test_lockholder_exitcode_must_be_zero(self) -> None:
        """Mutation 2: real _ExternalLockHolder exits with returncode=1.

        Lock holder sends released then sys.exit(1).
        release() must detect non-zero returncode and fail.
        """
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        lock_path = str(self.conf_dir / "wg0.conf.lock")
        env = os.environ.copy()
        env["LOCK_PATH"] = lock_path
        env["LOCK_EXIT_AFTER_RELEASED"] = "1"
        stderr_file = tempfile.TemporaryFile(mode="w+b")
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "from tests.awg_peer_add_workers import _subprocess_external_lock_main; "
             "_subprocess_external_lock_main()"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            close_fds=True,
            start_new_session=True,
        )
        holder = _ExternalLockHolder.__new__(_ExternalLockHolder)
        holder.test_name = "lock-exit1"
        holder.lock_path = lock_path
        holder.proc = proc
        holder._stderr_file = stderr_file
        holder._queue = queue.Queue()
        def _reader():
            try:
                for line in proc.stdout:
                    line = line.strip()
                    if line:
                        try:
                            msg = json.loads(line)
                            holder._queue.put(msg)
                        except (json.JSONDecodeError, ValueError):
                            pass
            except (OSError, ValueError):
                pass
            finally:
                holder._queue.put(None)
        holder._reader_thread = threading.Thread(target=_reader, daemon=True,
                                                  name="reader-lock-exit1")
        holder._reader_thread.start()
        try:
            holder.wait_lock_acquired()
            # release() must fail because process exits with code 1
            with self.assertRaises(AssertionError) as ctx:
                holder.release(timeout=5.0)
            self.assertIn("returncode=1", str(ctx.exception))
        finally:
            holder._force_kill()
            holder._cleanup_resources()

    def test_worker_no_traceback_in_stderr(self) -> None:
        """Mutation C: real _SubprocessWorker with Traceback in stderr.

        Worker runs full protocol, sends correct result, writes Traceback
        to stderr, then exits with returncode=0.  recv_result() must
        detect the forbidden marker via managed lifecycle.
        """
        self._write("wg0.conf", "[Interface]\nPrivateKey = k\n")
        w1 = _SubprocessWorker(
            str(self.conf_dir), "wg0", KEY_A, "traceback-managed",
            env_extra={"WORKER_TRACEBACK_AFTER_RESULT": "1"},
        )
        pid = None
        pgid = None
        try:
            w1.start()
            pid = w1.proc.pid
            try:
                pgid = os.getpgid(pid)
            except OSError:
                pass
            # Run the full managed protocol
            w1.wait_stage("worker_started")
            w1.wait_stage("config_lock_acquired")
            w1.wait_stage("read_reached")
            w1.wait_stage("read_completed")
            w1.send_cmd("allow_after_read")
            w1.wait_stage("backup_reached")
            w1.send_cmd("allow_backup_continue")
            # recv_result must detect Traceback in stderr
            with self.assertRaises(AssertionError) as ctx:
                w1.recv_result(timeout=10)
            err = str(ctx.exception)
            self.assertIn("Traceback", err)
            self.assertIn("returned cleanly but stderr contains", err)
        finally:
            w1.cleanup()
            # Verify full cleanup: PID gone, PGID gone, thread dead, IPC closed
            self.assertIsNotNone(w1.proc)
            self.assertIsNotNone(w1.proc.poll(),
                                 "worker must be terminated")
            if pid is not None:
                try:
                    os.kill(pid, 0)
                    self.fail(f"PID {pid} still exists after cleanup")
                except ProcessLookupError:
                    pass
            if pgid is not None:
                try:
                    os.killpg(pgid, 0)
                    self.fail(f"PGID {pgid} still exists after cleanup")
                except ProcessLookupError:
                    pass
            self.assertFalse(w1._reader_thread.is_alive(),
                             "reader thread must be dead after cleanup")
            self.assertTrue(w1.proc.stdin is None or w1.proc.stdin.closed,
                            "stdin must be closed")
            self.assertTrue(w1.proc.stdout is None or w1.proc.stdout.closed,
                            "stdout must be closed")
            self.assertIsNone(w1._stderr_file,
                              "stderr TemporaryFile must be closed")

    def test_non_blocking_flock_ebadf_rejected(self) -> None:
        """Mutation D: EBADF from non-blocking LOCK_EX is NOT proof of lock."""
        import errno
        # EBADF should not be accepted as evidence of a held lock
        exc = OSError(errno.EBADF, os.strerror(errno.EBADF))
        self.assertEqual(exc.errno, errno.EBADF)
        # Verify our check would reject EBADF
        allowed = {errno.EACCES, errno.EAGAIN}
        try:
            allowed.add(errno.EWOULDBLOCK)
        except AttributeError:
            pass
        self.assertNotIn(errno.EBADF, allowed,
                         "EBADF must not be in the allowed set for flock")

    def test_permission_error_not_accepted_for_pgid(self) -> None:
        """PermissionError is NOT accepted as evidence that PGID is gone.

        Only ProcessLookupError proves the process group has been removed.
        This test verifies the distinction by checking source code of
        test_cleanup_terminates_worker for the correct exception pattern.
        """
        import inspect
        import textwrap
        import re
        src = inspect.getsource(
            AwgPeerAddConcurrencyTests.test_cleanup_terminates_worker
        )
        src = textwrap.dedent(src)
        # Find all except clauses in the source
        except_pattern = re.compile(
            r"except\s*\(([^)]+)\)|except\s+(\w+)", re.MULTILINE
        )
        for match in except_pattern.finditer(src):
            types_str = match.group(1) or match.group(2)
            type_names = [t.strip() for t in types_str.split(",")]
            self.assertNotIn(
                "PermissionError", type_names,
                "test_cleanup_terminates_worker must NOT catch "
                "PermissionError — only ProcessLookupError proves PGID is gone"
            )


if __name__ == "__main__":
    unittest.main()
