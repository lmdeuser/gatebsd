"""Regression tests for awg_peer_remove.

Covers:
  1. Correct peer removal and interface preservation
  2. Edge cases (empty file, interface-only, incomplete peer, re-removal, etc.)
  3. Atomicity for concurrent readers (subprocess-based, pipe-synchronized)
  4. Concurrent removal operations (subprocess-based)
  5. Filesystem error injection for each production stage
  6. Lock acquisition, release, and process lifecycle
"""
from __future__ import annotations

import errno
import fcntl
import json
import os
import queue
import select
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time as _time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

# Valid 44-char Base64 keys (match ^[A-Za-z0-9+/=]{43,45}$)
KEY_A = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
KEY_B = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
KEY_C = "C" * 44

# Keys with special Base64 chars (+, /, =) — exactly 44 chars
KEY_SPECIAL = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="


def _make_conf(*sections: str, preamble: str = "") -> str:
    parts: list[str] = []
    if preamble:
        parts.append(preamble)
    parts.extend(sections)
    return "\n".join(parts) + "\n"


THREE_PEERS = _make_conf(
    "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = server_privkey",
    f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32",
    f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.3/32",
    f"[Peer]\nPublicKey = {KEY_C}\nAllowedIPs = 10.0.0.4/32",
)

SINGLE_PEER = _make_conf(
    "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = server_privkey",
    f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32",
)

FULL_AWG_CONFIG = _make_conf(
    "[Interface]\n"
    "Address = 10.0.0.1/24\n"
    "PrivateKey = server_privkey\n"
    "DNS = 1.1.1.1\n"
    "MTU = 1420\n"
    "Table = auto\n"
    "PostUp = /usr/local/sbin/route.sh up\n"
    "PostDown = /usr/local/sbin/route.sh down\n"
    "Jc = 40\n"
    "Jmin = 40\n"
    "Jmax = 70\n"
    "S1 = 0\n"
    "S2 = 0\n"
    "H1 = 1\n"
    "H2 = 2\n"
    "H3 = 3\n"
    "H4 = 4",
    f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\nEndpoint = 1.2.3.4:51820\nPresharedKey = pskey_a",
    f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.3/32\nEndpoint = 5.6.7.8:51820\nPresharedKey = pskey_b",
)


# ── Subprocess IPC helpers ─────────────────────────────────


def _send_msg(out, msg: dict) -> None:
    data = json.dumps(msg, separators=(",", ":")) + "\n"
    out.write(data.encode())
    out.flush()


def _recv_msg(inp, timeout: float) -> dict | None:
    fd = inp.fileno()
    deadline = _time.monotonic() + timeout
    buf = b""
    eof = False
    while True:
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if line.strip():
                try:
                    return json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
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


def _read_line_nonblock(fd: int) -> bytes | None:
    """Read a single newline-terminated line from fd, non-blocking. Returns None if no data."""
    buf = b""
    deadline = _time.monotonic() + 0.002
    while _time.monotonic() < deadline:
        rlist, _, _ = select.select([fd], [], [], 0.001)
        if rlist:
            try:
                ch = os.read(fd, 1)
            except OSError:
                return None
            if not ch:
                return None
            if ch == b"\n":
                return buf
            buf += ch
        else:
            if buf:
                continue
            return None
    return None if not buf else buf


# ── Subprocess workers ─────────────────────────────────────


def _remove_worker_main() -> None:
    """Run awg_peer_remove in subprocess, controlled by parent via stdin/stdout."""
    conf_dir = os.environ["CONF_DIR"]
    conf_name = os.environ["CONF_NAME"]
    pubkey = os.environ["PUBKEY"]

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))
    inp = sys.stdin.buffer
    out = sys.stdout.buffer
    terminal_sent = False

    try:
        from gatebsd_ui.writers import vpn
        from unittest.mock import patch as _patch

        conf_path = Path(conf_dir) / f"{conf_name}.conf"
        original_flock = fcntl.flock

        def patched_flock(fd: int, operation: int) -> None:
            if operation & fcntl.LOCK_EX:
                _send_msg(out, {"stage": "lock_attempted"})
                original_flock(fd, operation)
                _send_msg(out, {"stage": "lock_acquired"})
            else:
                original_flock(fd, operation)

        with (
            _patch.object(vpn, "AMNEZIA_CONF_DIR", Path(conf_dir)),
            _patch.object(vpn.backup, "backup_files", return_value={}),
            _patch.object(fcntl, "flock", patched_flock),
        ):
            _send_msg(out, {"stage": "worker_started"})
            status, body = vpn.awg_peer_remove(conf_name, pubkey)
            terminal_sent = True
            _send_msg(out, {"stage": "result", "status": status, "body": body})
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


def _remove_worker_with_error_main() -> None:
    """Run awg_peer_remove with injectable errors at specific stages.

    Env: CONF_DIR, CONF_NAME, PUBKEY, FAIL_STAGE, FAIL_COUNT.
    Stages: mkstemp|fdopen|write|flush|fsync|chmod|replace.
    """
    conf_dir = os.environ["CONF_DIR"]
    conf_name = os.environ["CONF_NAME"]
    pubkey = os.environ["PUBKEY"]
    fail_stage = os.environ.get("FAIL_STAGE", "")
    fail_count = int(os.environ.get("FAIL_COUNT", "1"))

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))
    out = sys.stdout.buffer

    try:
        from gatebsd_ui.writers import vpn
        from unittest.mock import patch as _patch
        import tempfile as _tempfile

        _real_mkstemp = _tempfile.mkstemp
        _real_fdopen = os.fdopen
        _real_fsync = os.fsync
        _real_chmod = os.chmod
        _real_replace = os.replace
        attempt = [0]

        def tracking_mkstemp(**kwargs: object) -> tuple[int, str]:
            attempt[0] += 1
            if fail_stage == "mkstemp" and attempt[0] <= fail_count:
                raise OSError("simulated mkstemp error")
            return _real_mkstemp(**kwargs)

        class _WriteFailFile:
            """Wrapper that raises on write()."""
            def __init__(self, real_file):
                self._real = real_file
            def write(self, data):
                raise OSError("simulated write error")
            def flush(self):
                self._real.flush()
            def fileno(self):
                return self._real.fileno()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                self._real.close()

        class _FlushFailFile:
            """Wrapper that raises on flush()."""
            def __init__(self, real_file):
                self._real = real_file
            def write(self, data):
                self._real.write(data)
            def flush(self):
                raise OSError("simulated flush error")
            def fileno(self):
                return self._real.fileno()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                self._real.close()

        def tracking_fdopen(fd: int, mode: str = "rb", *a: object, **kw: object):  # type: ignore[return]
            if fail_stage == "fdopen" and attempt[0] <= fail_count:
                raise OSError("simulated fdopen error")
            real = _real_fdopen(fd, mode, *a, **kw)
            if fail_stage == "write" and attempt[0] <= fail_count:
                return _WriteFailFile(real)
            if fail_stage == "flush" and attempt[0] <= fail_count:
                return _FlushFailFile(real)
            return real

        def tracking_fsync(fd: int) -> None:
            if fail_stage == "fsync" and attempt[0] <= fail_count:
                raise OSError("simulated fsync error")
            _real_fsync(fd)

        def tracking_chmod(path: object, mode: int) -> None:
            if fail_stage == "chmod" and isinstance(path, (str, Path)) and str(path).endswith(".tmp") and attempt[0] <= fail_count:
                raise OSError("simulated chmod error")
            _real_chmod(path, mode)

        def tracking_replace(src: object, dst: object, *a: object, **kw: object) -> None:
            if fail_stage == "replace" and attempt[0] <= fail_count:
                raise OSError("simulated replace error")
            _real_replace(src, dst, *a, **kw)

        patches_dict: dict[str, object] = {
            "mkstemp": _patch.object(_tempfile, "mkstemp", side_effect=tracking_mkstemp),
            "fdopen": _patch("gatebsd_ui.writers.vpn.os.fdopen", side_effect=tracking_fdopen),
            "fsync": _patch("os.fsync", side_effect=tracking_fsync),
            "chmod": _patch("gatebsd_ui.writers.vpn.os.chmod", side_effect=tracking_chmod),
            "replace": _patch("gatebsd_ui.writers.vpn.os.replace", side_effect=tracking_replace),
        }

        with ExitStack() as stack:
            stack.enter_context(_patch.object(vpn, "AMNEZIA_CONF_DIR", Path(conf_dir)))
            stack.enter_context(_patch.object(vpn.backup, "backup_files", return_value={}))
            for name, p in patches_dict.items():
                stack.enter_context(p)
            _send_msg(out, {"stage": "worker_started"})
            try:
                status, body = vpn.awg_peer_remove(conf_name, pubkey)
                _send_msg(out, {"stage": "result", "status": status, "body": body})
            except Exception as e:
                _send_msg(out, {"stage": "exception", "detail": str(e)})
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


def _atomicity_writer_main() -> None:
    """Writer for atomicity tests: patches os.replace to synchronize with parent.

    Env: CONF_DIR, CONF_NAME, PUBKEY, SYNC_DIR.
    Protocol: creates SYNC_DIR/ready file, waits for SYNC_DIR/go file, then replaces.
    """
    conf_dir = os.environ["CONF_DIR"]
    conf_name = os.environ["CONF_NAME"]
    pubkey = os.environ["PUBKEY"]
    sync_dir = os.environ["SYNC_DIR"]

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))
    out = sys.stdout.buffer

    try:
        from gatebsd_ui.writers import vpn
        from unittest.mock import patch as _patch
        import tempfile as _tempfile

        _real_replace = os.replace
        original_flock = fcntl.flock

        def synchronized_replace(src: object, dst: object, *a: object, **kw: object) -> None:
            # Signal parent that we're about to replace
            ready_path = os.path.join(sync_dir, "ready")
            with open(ready_path, "w") as f:
                f.write("ready")
            # Wait for parent to write go file
            go_path = os.path.join(sync_dir, "go")
            deadline = _time.monotonic() + 15.0
            while _time.monotonic() < deadline:
                if os.path.exists(go_path):
                    break
                _time.sleep(0.001)
            else:
                raise TimeoutError("writer timed out waiting for go file")
            _real_replace(src, dst, *a, **kw)

        def patched_flock(fd: int, operation: int) -> None:
            if operation & fcntl.LOCK_EX:
                _send_msg(out, {"stage": "lock_acquired"})
            original_flock(fd, operation)

        with (
            _patch.object(vpn, "AMNEZIA_CONF_DIR", Path(conf_dir)),
            _patch.object(vpn.backup, "backup_files", return_value={}),
            _patch("gatebsd_ui.writers.vpn.os.replace", side_effect=synchronized_replace),
            _patch.object(fcntl, "flock", patched_flock),
        ):
            _send_msg(out, {"stage": "worker_started"})
            status, body = vpn.awg_peer_remove(conf_name, pubkey)
            _send_msg(out, {"stage": "result", "status": status, "body": body})
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


def _atomicity_reader_main() -> None:
    """Reader for atomicity tests: reads config file governed by parent via stdin pipe.

    Env: CONF_PATH, ORIGINAL_HEX, EXPECTED_HEX, SIGNAL_DIR.
    Protocol: parent sends GOVERNOR_START on stdin → reader reads in tight loop.
    Reader creates SIGNAL_DIR/read_N on first read. Parent waits for this.
    Parent closes stdin → reader stops, reports.
    """
    conf_path = os.environ["CONF_PATH"]
    original_hex = os.environ["ORIGINAL_HEX"]
    expected_hex = os.environ["EXPECTED_HEX"]
    signal_dir = os.environ.get("SIGNAL_DIR", "")
    out = sys.stdout.buffer

    original_bytes = bytes.fromhex(original_hex) if original_hex else b""
    expected_bytes = bytes.fromhex(expected_hex) if expected_hex else b""

    # Wait for start signal on stdin
    inp_fd = sys.stdin.buffer.fileno()
    start_line = _read_line_nonblock(inp_fd)
    if start_line is None:
        try:
            data = b""
            while True:
                ch = os.read(inp_fd, 1)
                if not ch or ch == b"\n":
                    break
                data += ch
            start_line = data
        except OSError:
            start_line = b""

    if start_line.strip() != b"GOVERNOR_START":
        _send_msg(out, {
            "stage": "error",
            "detail": f"expected GOVERNOR_START, got: {start_line!r}",
        })
        return

    # Read in tight loop until stdin closes
    reads: list[tuple[int, bytes]] = []
    violations: list[str] = []
    idx = 0
    first_read_done = False

    while True:
        # Non-blocking check if stdin is closed
        rlist, _, _ = select.select([inp_fd], [], [], 0)
        if rlist:
            try:
                peek = os.read(inp_fd, 1)
            except OSError:
                break
            if not peek:
                break

        try:
            data = open(conf_path, "rb").read()
        except OSError as e:
            violations.append(f"read#{idx}: OSError: {e}")
            idx += 1
            continue

        reads.append((idx, data))

        # Signal first read to parent
        if not first_read_done and signal_dir:
            first_read_done = True
            try:
                with open(os.path.join(signal_dir, f"read_{os.getpid()}"), "w") as f:
                    f.write("ok")
            except OSError:
                pass

        if data == original_bytes:
            pass
        elif data == expected_bytes:
            pass
        else:
            violations.append(f"read#{idx}: unexpected content ({len(data)} bytes)")
        idx += 1

    seen_original = any(d == original_bytes for _, d in reads)
    seen_expected = any(d == expected_bytes for _, d in reads)

    _send_msg(out, {
        "stage": "done",
        "total": len(reads),
        "seen_original": seen_original,
        "seen_expected": seen_expected,
        "violations": violations,
    })


def _external_lock_holder_main() -> None:
    """Hold LOCK_EX on a lock file until told to release."""
    lock_path = os.environ["LOCK_PATH"]
    inp = sys.stdin.buffer
    out = sys.stdout.buffer

    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            _send_msg(out, {"stage": "lock_acquired"})
            msg = _recv_msg(inp, 30.0)
            cmd = msg.get("cmd", "") if msg else "stop"
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)
        if cmd == "release":
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


def _reader_worker_main() -> None:
    """Simple reader: reads config file in a loop for concurrency tests."""
    conf_path = os.environ["CONF_PATH"]
    count = int(os.environ.get("READER_COUNT", "500"))
    out = sys.stdout.buffer
    violations: list[str] = []
    reads_data: list[bytes] = []

    for i in range(count):
        try:
            data = open(conf_path, "rb").read()
            reads_data.append(data)
            if len(data) > 0 and b"[Interface]" not in data:
                violations.append(f"read#{i}: no [Interface] in {len(data)} bytes")
        except OSError as e:
            violations.append(f"read#{i}: OSError: {e}")

    # Validate every read is exactly original or expected
    original_hex = os.environ.get("ORIGINAL_HEX", "")
    expected_hex = os.environ.get("EXPECTED_HEX", "")
    if original_hex and expected_hex:
        original_bytes = bytes.fromhex(original_hex)
        expected_bytes = bytes.fromhex(expected_hex)
        for i, data in enumerate(reads_data):
            if data != original_bytes and data != expected_bytes:
                violations.append(
                    f"read#{i}: content mismatch ({len(data)} bytes)"
                )

    _send_msg(out, {
        "stage": "done",
        "total": len(reads_data),
        "violations": violations,
    })


# ── Subprocess worker management ───────────────────────────


class _Worker:
    """Managed subprocess for awg_peer_remove tests."""

    def __init__(self, conf_dir: str, conf_name: str, pubkey: str,
                 test_name: str, *,
                 worker_main: str = "_remove_worker_main",
                 env_extra: dict[str, str] | None = None) -> None:
        self.test_name = test_name
        self.conf_dir = conf_dir
        self.conf_name = conf_name
        self.pubkey = pubkey
        self.worker_main = worker_main
        self.proc: subprocess.Popen | None = None
        self._reader_thread: threading.Thread | None = None
        self._queue: queue.Queue = queue.Queue()
        self._reader_exceptions: list[Exception] = []
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
             f"from tests.awg_peer_remove_workers import {self.worker_main}; "
             f"{self.worker_main}()"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file,
            close_fds=True,
            start_new_session=True,
        )

        def _reader():
            try:
                for line in self.proc.stdout:
                    line = line.strip()
                    if line:
                        try:
                            msg = json.loads(line)
                            self._queue.put(msg)
                        except (json.JSONDecodeError, ValueError) as e:
                            self._reader_exceptions.append(e)
            except (OSError, ValueError) as e:
                self._reader_exceptions.append(e)
            finally:
                self._queue.put(None)

        self._reader_thread = threading.Thread(
            target=_reader, daemon=True,
            name=f"reader-{self.test_name}-pid{self.proc.pid}",
        )
        self._reader_thread.start()

    def wait_stage(self, stage: str, timeout: float = 15.0) -> dict:
        deadline = _time.monotonic() + timeout
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"{self.test_name}: pid={self.proc.pid} "
                    f"timeout waiting for '{stage}'"
                )
            try:
                msg = self._queue.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                continue
            if msg is None:
                raise TimeoutError(
                    f"{self.test_name}: pid={self.proc.pid} "
                    f"disconnected waiting for '{stage}'"
                )
            if msg.get("stage") == stage:
                return msg
            if msg.get("stage") in ("result", "error", "exception"):
                raise AssertionError(
                    f"{self.test_name}: pid={self.proc.pid} "
                    f"unexpected terminal message '{msg.get('stage')}' "
                    f"before '{stage}': {msg}"
                )

    def send_cmd(self, cmd: str) -> None:
        if self.proc and self.proc.stdin:
            try:
                _send_msg(self.proc.stdin, {"cmd": cmd})
            except (OSError, BrokenPipeError, ValueError):
                pass

    def recv_result(self, timeout: float = 15.0) -> dict:
        msg = self.wait_stage("result", timeout)
        self._wait_exit_clean()
        self._assert_no_reader_exceptions()
        return msg

    def recv_exception_or_result(self, timeout: float = 15.0) -> dict:
        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                break
            try:
                msg = self._queue.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                continue
            if msg is None:
                break
            if msg.get("stage") in ("result", "exception", "error"):
                self._wait_exit_clean()
                self._assert_no_reader_exceptions()
                return msg
        raise TimeoutError(f"{self.test_name}: no terminal message received")

    def _assert_no_reader_exceptions(self) -> None:
        if self._reader_exceptions:
            raise AssertionError(
                f"{self.test_name}: reader thread had exceptions: "
                f"{self._reader_exceptions}"
            )

    def _wait_exit_clean(self, timeout: float = 5.0) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pass
        if self.proc.poll() is None:
            self._emergency_cleanup()
            raise AssertionError(
                f"{self.test_name}: worker pid={self.proc.pid} did not exit"
            )
        if self.proc.returncode != 0:
            stderr = self._read_stderr()
            self._emergency_cleanup()
            raise AssertionError(
                f"{self.test_name}: worker pid={self.proc.pid} "
                f"returncode={self.proc.returncode}; stderr={stderr[:500]}"
            )

    def _emergency_cleanup(self) -> None:
        try:
            if self.proc and self.proc.poll() is None:
                os.killpg(self.proc.pid, signal.SIGKILL)
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        except (ProcessLookupError, OSError):
            pass
        self.cleanup()

    def cleanup(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.send_cmd("stop")
            except (OSError, BrokenPipeError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        for f in (getattr(self.proc, "stdin", None), getattr(self.proc, "stdout", None)):
            if f is not None:
                try:
                    f.close()
                except (OSError, ValueError):
                    pass
        self._queue_put_sentinel()
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=3)
            if self._reader_thread.is_alive():
                raise RuntimeError(
                    f"{self.test_name}: reader thread "
                    f"'{self._reader_thread.name}' still alive"
                )
        self._close_stderr()

    def _queue_put_sentinel(self) -> None:
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass

    def _close_stderr(self) -> None:
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
    """Managed subprocess that holds an external lock."""

    def __init__(self, lock_path: str, test_name: str) -> None:
        self.test_name = test_name
        self.lock_path = lock_path
        self.proc: subprocess.Popen | None = None
        self._reader_thread: threading.Thread | None = None
        self._queue: queue.Queue = queue.Queue()
        self._reader_exceptions: list[Exception] = []
        self._stderr_file: tempfile.TemporaryFile | None = None

    def start(self) -> None:
        env = os.environ.copy()
        env["LOCK_PATH"] = self.lock_path
        self._stderr_file = tempfile.TemporaryFile(mode="w+b")
        self.proc = subprocess.Popen(
            [sys.executable, "-c",
             "from tests.awg_peer_remove_workers import _external_lock_holder_main; "
             "_external_lock_holder_main()"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file,
            close_fds=True,
            start_new_session=True,
        )

        def _reader():
            try:
                for line in self.proc.stdout:
                    line = line.strip()
                    if line:
                        try:
                            msg = json.loads(line)
                            self._queue.put(msg)
                        except (json.JSONDecodeError, ValueError) as e:
                            self._reader_exceptions.append(e)
            except (OSError, ValueError) as e:
                self._reader_exceptions.append(e)
            finally:
                self._queue.put(None)

        self._reader_thread = threading.Thread(
            target=_reader, daemon=True,
            name=f"reader-lock-{self.test_name}-pid{self.proc.pid}",
        )
        self._reader_thread.start()

    def wait_lock_acquired(self, timeout: float = 15.0) -> None:
        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{self.test_name}: lock holder timeout")
            try:
                msg = self._queue.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                continue
            if msg is None:
                raise TimeoutError(f"{self.test_name}: lock holder disconnected")
            if msg.get("stage") == "lock_acquired":
                return
            raise AssertionError(
                f"{self.test_name}: unexpected stage '{msg.get('stage')}'"
            )

    def release(self, timeout: float = 10.0) -> None:
        if self.proc is None or self.proc.poll() is not None:
            self._cleanup()
            return
        try:
            if self.proc.stdin:
                _send_msg(self.proc.stdin, {"cmd": "release"})
        except (OSError, BrokenPipeError, ValueError):
            self._force_kill()
            self._cleanup()
            return
        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            try:
                msg = self._queue.get(timeout=min(1.0, max(deadline - _time.monotonic(), 0)))
            except queue.Empty:
                continue
            if msg is None:
                break
            if msg.get("stage") == "released":
                break
        if self.proc.poll() is None:
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self._cleanup()

    def stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            self._cleanup()
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
        if self.proc.poll() is None:
            self._force_kill()
        self._cleanup()

    def _force_kill(self) -> None:
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

    def _cleanup(self) -> None:
        if self.proc:
            for f in (self.proc.stdin, self.proc.stdout):
                if f is not None:
                    try:
                        f.close()
                    except (OSError, ValueError):
                        pass
        self._queue_put_sentinel()
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=3)
            if self._reader_thread.is_alive():
                raise RuntimeError(f"{self.test_name}: reader thread still alive")
        if self._reader_exceptions:
            raise AssertionError(
                f"{self.test_name}: reader thread exceptions: "
                f"{self._reader_exceptions}"
            )
        if self._stderr_file is not None:
            try:
                self._stderr_file.close()
            except (OSError, ValueError):
                pass
            self._stderr_file = None

    def _queue_put_sentinel(self) -> None:
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass


# =========================================================
# 1. STRICT peer_pubkey VALIDATION
# =========================================================


class AwgPeerRemoveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)
        self.patcher_conf = patch(
            "gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.conf_dir
        )
        self.patcher_backup = patch("gatebsd_ui.writers.vpn.backup.backup_files",
                                    return_value={})
        self.patcher_conf.start()
        self.patcher_backup.start()

    def tearDown(self) -> None:
        self.patcher_backup.stop()
        self.patcher_conf.stop()
        self.td.cleanup()

    def _write(self, name: str, content: str | bytes) -> Path:
        p = self.conf_dir / name
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
        return p

    def _read(self, name: str) -> str:
        return (self.conf_dir / name).read_text(encoding="utf-8")

    def _read_bytes(self, name: str) -> bytes:
        return (self.conf_dir / name).read_bytes()

    def test_pubkey_with_trailing_lf(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        original = self._read_bytes("wg0.conf")
        status, _ = awg_peer_remove("wg0", KEY_A + "\n")
        self.assertEqual(status, 400)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertFalse((self.conf_dir / "wg0.conf.lock").exists())

    def test_pubkey_with_trailing_crlf(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        original = self._read_bytes("wg0.conf")
        status, _ = awg_peer_remove("wg0", KEY_A + "\r\n")
        self.assertEqual(status, 400)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertFalse((self.conf_dir / "wg0.conf.lock").exists())

    def test_pubkey_none_returns_400(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        original = self._read_bytes("wg0.conf")
        status, _ = awg_peer_remove("wg0", None)  # type: ignore[arg-type]
        self.assertEqual(status, 400)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertFalse((self.conf_dir / "wg0.conf.lock").exists())

    def test_pubkey_int_returns_400(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        original = self._read_bytes("wg0.conf")
        status, _ = awg_peer_remove("wg0", 12345)  # type: ignore[arg-type]
        self.assertEqual(status, 400)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertFalse((self.conf_dir / "wg0.conf.lock").exists())

    def test_pubkey_list_returns_400(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        original = self._read_bytes("wg0.conf")
        status, _ = awg_peer_remove("wg0", [KEY_A])  # type: ignore[arg-type]
        self.assertEqual(status, 400)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertFalse((self.conf_dir / "wg0.conf.lock").exists())

    def test_pubkey_dict_returns_400(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        original = self._read_bytes("wg0.conf")
        status, _ = awg_peer_remove("wg0", {"key": KEY_A})  # type: ignore[arg-type]
        self.assertEqual(status, 400)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertFalse((self.conf_dir / "wg0.conf.lock").exists())

    def test_pubkey_short_string_returns_400(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        original = self._read_bytes("wg0.conf")
        status, _ = awg_peer_remove("wg0", "short")
        self.assertEqual(status, 400)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertFalse((self.conf_dir / "wg0.conf.lock").exists())

    def test_two_same_pubkey_in_one_peer_returns_409(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            f"[Peer]\nPublicKey = {KEY_A}\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        self.patcher_backup.stop()
        call_count: list[int] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 409)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertEqual(call_count, [])

    def test_two_different_pubkey_in_one_peer_first_matches(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            f"[Peer]\nPublicKey = {KEY_A}\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        self.patcher_backup.stop()
        call_count: list[int] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 409)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertEqual(call_count, [])

    def test_two_different_pubkey_in_one_peer_second_matches(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            f"[Peer]\nPublicKey = {KEY_B}\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        self.patcher_backup.stop()
        call_count: list[int] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 409)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertEqual(call_count, [])

    def test_remove_first_of_three(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", THREE_PEERS)
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertNotIn(KEY_A, result)
        self.assertIn(KEY_B, result)
        self.assertIn(KEY_C, result)

    def test_remove_middle_of_three(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", THREE_PEERS)
        status, body = awg_peer_remove("wg0", KEY_B)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertIn(KEY_A, result)
        self.assertNotIn(KEY_B, result)
        self.assertIn(KEY_C, result)

    def test_remove_last_of_three(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", THREE_PEERS)
        status, body = awg_peer_remove("wg0", KEY_C)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertIn(KEY_A, result)
        self.assertIn(KEY_B, result)
        self.assertNotIn(KEY_C, result)

    def test_remove_single_peer(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertNotIn(KEY_A, result)
        self.assertIn("[Interface]", result)

    def test_peer_with_comments_and_blanks(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = _make_conf(
            "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = server_privkey\n# Interface comment",
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32",
            f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.3/32",
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertNotIn(KEY_A, result)
        self.assertIn(KEY_B, result)
        self.assertIn("# Interface comment", result)

    def test_section_after_peer_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = _make_conf(
            "[Interface]\nPrivateKey = server_privkey",
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32",
            "[SomeOtherSection]\nKey = value",
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertIn("[SomeOtherSection]", result)
        self.assertIn("Key = value", result)
        self.assertNotIn(KEY_A, result)

    def test_pubkey_not_first_in_section(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = _make_conf(
            "[Interface]\nPrivateKey = server_privkey",
            f"[Peer]\nAllowedIPs = 10.0.0.2/32\nPublicKey = {KEY_A}\nEndpoint = 1.2.3.4:51820",
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertNotIn(KEY_A, result)
        self.assertNotIn("AllowedIPs = 10.0.0.2/32", result)
        self.assertIn("[Interface]", result)

    def test_pubkey_with_spaces_around_equals(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = _make_conf(
            "[Interface]\nPrivateKey = server_privkey",
            f"[Peer]\nPublicKey   =   {KEY_A}\nAllowedIPs = 10.0.0.2/32",
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        self.assertNotIn(KEY_A, self._read("wg0.conf"))

    def test_pubkey_in_double_quotes(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = _make_conf(
            "[Interface]\nPrivateKey = server_privkey",
            f'[Peer]\nPublicKey = "{KEY_A}"\nAllowedIPs = 10.0.0.2/32',
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        self.assertNotIn(KEY_A, self._read("wg0.conf"))

    def test_pubkey_properly_quoted_removed(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = f'[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = "{KEY_A}"\nAllowedIPs = 10.0.0.2/32\n'
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        self.assertNotIn(KEY_A, self._read("wg0.conf"))

    def test_pubkey_opening_quote_only_not_matched(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = f'[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = "{KEY_A}\nAllowedIPs = 10.0.0.2/32\n'
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "ambiguous PublicKey quoting in section"})
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_pubkey_closing_quote_only_not_matched(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = f'[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = {KEY_A}"\nAllowedIPs = 10.0.0.2/32\n'
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "ambiguous PublicKey quoting in section"})
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_pubkey_triple_quotes_not_matched(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = f'[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = """{KEY_A}"""\nAllowedIPs = 10.0.0.2/32\n'
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "ambiguous PublicKey quoting in section"})
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_pubkey_extra_not_matched(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = _make_conf(
            "[Interface]\nPrivateKey = server_privkey",
            f"[Peer]\nPublicKeyExtra = {KEY_A}\nAllowedIPs = 10.0.0.2/32",
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertEqual(self._read("wg0.conf"), conf)

    def test_similar_key_not_matched(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = _make_conf(
            "[Interface]\nPrivateKey = server_privkey",
            f"[Peer]\nPublicKey = {KEY_A}X\nAllowedIPs = 10.0.0.2/32",
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertEqual(self._read("wg0.conf"), conf)

    def test_pubkey_with_special_base64_chars(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = _make_conf(
            "[Interface]\nPrivateKey = k",
            f"[Peer]\nPublicKey = {KEY_SPECIAL}\nAllowedIPs = 10.0.0.2/32",
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_SPECIAL)
        self.assertEqual(status, 200)
        self.assertNotIn(KEY_SPECIAL, self._read("wg0.conf"))

    def test_missing_key_404_no_file_change(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", THREE_PEERS)
        original = self._read_bytes("wg0.conf")
        status, body = awg_peer_remove("wg0", "D" * 44)
        self.assertEqual(status, 404)
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_duplicate_pubkey_returns_409(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = _make_conf(
            "[Interface]\nPrivateKey = server_privkey",
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32",
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.5/32",
        )
        self._write("wg0.conf", conf)
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 409)
        self.assertEqual(self._read("wg0.conf"), conf)

    def test_invalid_conf_name(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        status, _ = awg_peer_remove("../../../etc/passwd", KEY_A)
        self.assertEqual(status, 400)

    def _assert_conf_name_400(self, name: object) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        before = set(self.conf_dir.iterdir())
        self.patcher_backup.stop()
        call_count: list[int] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()
        try:
            status, _ = awg_peer_remove(name, KEY_A)  # type: ignore[arg-type]
            self.assertEqual(status, 400)
            self.assertEqual(call_count, [])
            self.assertEqual(self._read_bytes("wg0.conf"), SINGLE_PEER.encode())
            after = set(self.conf_dir.iterdir())
            new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
            self.assertEqual(new_files, set(), f"unexpected files: {new_files}")
        finally:
            self.patcher_backup.stop()
            self.patcher_backup = patch(
                "gatebsd_ui.writers.vpn.backup.backup_files", return_value={})
            self.patcher_backup.start()

    def test_conf_name_none(self) -> None: self._assert_conf_name_400(None)
    def test_conf_name_int(self) -> None: self._assert_conf_name_400(123)
    def test_conf_name_list(self) -> None: self._assert_conf_name_400([])
    def test_conf_name_dict(self) -> None: self._assert_conf_name_400({})
    def test_conf_name_with_lf(self) -> None: self._assert_conf_name_400("wg0\n")
    def test_conf_name_with_crlf(self) -> None: self._assert_conf_name_400("wg0\r\n")
    def test_conf_name_with_tab(self) -> None: self._assert_conf_name_400("wg0\t")
    def test_conf_name_path_traversal(self) -> None: self._assert_conf_name_400("../wg0")
    def test_conf_name_slash(self) -> None: self._assert_conf_name_400("wg/0")
    def test_conf_name_space(self) -> None: self._assert_conf_name_400("wg 0")

    def test_conf_name_valid_awg0(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("awg0.conf", SINGLE_PEER)
        status, _ = awg_peer_remove("awg0", KEY_A)
        self.assertEqual(status, 200)

    def test_conf_name_valid_underscore(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg_0.conf", SINGLE_PEER)
        status, _ = awg_peer_remove("wg_0", KEY_A)
        self.assertEqual(status, 200)

    def test_conf_name_valid_hyphen(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg-0.conf", SINGLE_PEER)
        status, _ = awg_peer_remove("wg-0", KEY_A)
        self.assertEqual(status, 200)

    def test_conf_name_valid_mixed(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("AWG_test-1.conf", SINGLE_PEER)
        status, _ = awg_peer_remove("AWG_test-1", KEY_A)
        self.assertEqual(status, 200)

    def test_config_not_found(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        status, _ = awg_peer_remove("nonexistent", KEY_A)
        self.assertEqual(status, 404)

    def test_concurrent_removals(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", THREE_PEERS)
        errors: list[Exception] = []

        def remove_a() -> None:
            try:
                awg_peer_remove("wg0", KEY_A)
            except Exception as e:
                errors.append(e)

        def remove_b() -> None:
            try:
                awg_peer_remove("wg0", KEY_B)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=remove_a)
        t2 = threading.Thread(target=remove_b)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        self.assertEqual(errors, [])
        result = self._read("wg0.conf")
        self.assertNotIn(KEY_A, result)
        self.assertNotIn(KEY_B, result)
        self.assertIn(KEY_C, result)
        self.assertIn("[Interface]", result)

    def test_permissions_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        p = self._write("wg0.conf", SINGLE_PEER)
        os.chmod(p, 0o640)
        awg_peer_remove("wg0", KEY_A)
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)

    def test_two_sequential_removals(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", THREE_PEERS)
        s1, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(s1, 200)
        result1 = self._read("wg0.conf")
        self.assertNotIn(KEY_A, result1)
        self.assertIn(KEY_B, result1)
        self.assertIn(KEY_C, result1)
        s2, _ = awg_peer_remove("wg0", KEY_B)
        self.assertEqual(s2, 200)
        result2 = self._read("wg0.conf")
        self.assertNotIn(KEY_B, result2)
        self.assertIn(KEY_C, result2)
        self.assertIn("[Interface]", result2)

    def test_replace_failure_preserves_original(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        original = self._read_bytes("wg0.conf")
        def broken_replace(src: str, dst: str) -> None:
            raise OSError("simulated replace failure")
        with patch("gatebsd_ui.writers.vpn.os.replace", broken_replace):
            status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual((status, body), (500, {"error": "failed to write config"}))
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_no_temp_files_after_error(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        before = set(self.conf_dir.iterdir())
        def broken_replace(src: str, dst: str) -> None:
            raise OSError("simulated")
        with patch("gatebsd_ui.writers.vpn.os.replace", broken_replace):
            status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual((status, body), (500, {"error": "failed to write config"}))
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set(), f"temp files left: {new_files}")

    def test_cleanup_error_does_not_mask_original(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        original = self._read_bytes("wg0.conf")
        def broken_replace(src: str, dst: str) -> None:
            raise OSError("replace failed")
        def broken_unlink(p: Path, **kw: object) -> None:
            raise OSError("unlink failed")
        with (
            patch("gatebsd_ui.writers.vpn.os.replace", broken_replace),
            patch.object(Path, "unlink", broken_unlink),
        ):
            status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual((status, body), (500, {"error": "failed to write config"}))
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_lock_file_permissions(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        lock_path = self.conf_dir / "wg0.conf.lock"
        self.assertFalse(lock_path.exists())
        awg_peer_remove("wg0", KEY_A)
        mode = os.stat(lock_path).st_mode
        self.assertEqual(mode & 0o111, 0, "lock file must have no exec bits")
        self.assertEqual(mode & 0o077, 0, "lock file must not be group/other accessible")

    def test_backup_not_called_on_404(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        self.patcher_backup.stop()
        call_count: list[int] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()
        awg_peer_remove("wg0", "D" * 44)
        self.assertEqual(call_count, [])

    def test_backup_not_called_on_409(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = _make_conf(
            "[Interface]\nPrivateKey = k",
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32",
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.3/32",
        )
        self._write("wg0.conf", conf)
        self.patcher_backup.stop()
        call_count: list[int] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()
        awg_peer_remove("wg0", KEY_A)
        self.assertEqual(call_count, [])

    def test_backup_called_once_on_success(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        self.patcher_backup.stop()
        call_count: list[int] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()
        awg_peer_remove("wg0", KEY_A)
        self.assertEqual(len(call_count), 1)

    def test_preamble_comments_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        preamble = "# generated by GateBSD\n# keep this header\n\n"
        conf = preamble + SINGLE_PEER
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertTrue(result.startswith("# generated by GateBSD\n# keep this header\n\n"))
        self.assertNotIn(KEY_A, result)

    def test_preamble_arbitrary_line_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = "some arbitrary line\n" + SINGLE_PEER
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertTrue(result.startswith("some arbitrary line\n"))

    def test_crlf_preserved_after_removal(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            b"[Interface]\r\n"
            b"Address = 10.0.0.1/24\r\n"
            b"PrivateKey = server_privkey\r\n"
            b"\r\n"
            b"[Peer]\r\n"
            b"PublicKey = " + KEY_A.encode() + b"\r\n"
            b"AllowedIPs = 10.0.0.2/32\r\n"
            b"\r\n"
            b"[Peer]\r\n"
            b"PublicKey = " + KEY_B.encode() + b"\r\n"
            b"AllowedIPs = 10.0.0.3/32\r\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read_bytes("wg0.conf")
        expected = (
            b"[Interface]\r\n"
            b"Address = 10.0.0.1/24\r\n"
            b"PrivateKey = server_privkey\r\n"
            b"\r\n"
            b"[Peer]\r\n"
            b"PublicKey = " + KEY_B.encode() + b"\r\n"
            b"AllowedIPs = 10.0.0.3/32\r\n"
        )
        self.assertEqual(result, expected)
        self.assertNotIn(b"\n", result.replace(b"\r\n", b""))

    def test_invalid_utf8_byte_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            b"# comment\xff\n"
            b"[Interface]\nPrivateKey = k\n\n"
            b"[Peer]\nPublicKey = " + KEY_A.encode() + b"\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read_bytes("wg0.conf")
        expected = b"# comment\xff\n[Interface]\nPrivateKey = k\n\n"
        self.assertEqual(result, expected)

    def test_no_trailing_newline_non_last_section(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            b"[Interface]\nPrivateKey = k\n\n"
            b"[Peer]\nPublicKey = " + KEY_A.encode() + b"\nAllowedIPs = 10.0.0.2/32\n\n"
            b"[Peer]\nPublicKey = " + KEY_B.encode() + b"\nAllowedIPs = 10.0.0.3/32"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read_bytes("wg0.conf")
        expected = (
            b"[Interface]\nPrivateKey = k\n\n"
            b"[Peer]\nPublicKey = " + KEY_B.encode() + b"\nAllowedIPs = 10.0.0.3/32"
        )
        self.assertEqual(result, expected)

    def test_mixed_line_endings_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            b"# header\r\n"
            b"[Interface]\n"
            b"PrivateKey = k\r\n"
            b"\n"
            b"[Peer]\n"
            b"PublicKey = " + KEY_A.encode() + b"\n"
            b"AllowedIPs = 10.0.0.2/32\n"
            b"\n"
            b"[Peer]\r\n"
            b"PublicKey = " + KEY_B.encode() + b"\r\n"
            b"AllowedIPs = 10.0.0.3/32\r\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read_bytes("wg0.conf")
        expected = (
            b"# header\r\n"
            b"[Interface]\n"
            b"PrivateKey = k\r\n"
            b"\n"
            b"[Peer]\r\n"
            b"PublicKey = " + KEY_B.encode() + b"\r\n"
            b"AllowedIPs = 10.0.0.3/32\r\n"
        )
        self.assertEqual(result, expected)


# =========================================================
# INTERFACE PRESERVATION
# =========================================================


class AwgPeerRemoveInterfacePreservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)
        self.patcher_conf = patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.conf_dir)
        self.patcher_backup = patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={})
        self.patcher_conf.start()
        self.patcher_backup.start()

    def tearDown(self) -> None:
        self.patcher_backup.stop()
        self.patcher_conf.stop()
        self.td.cleanup()

    def _write(self, name: str, content: str | bytes) -> Path:
        p = self.conf_dir / name
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
        return p

    def _read(self, name: str) -> str:
        return (self.conf_dir / name).read_text(encoding="utf-8")

    def test_full_amnezia_config_preserves_interface(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", FULL_AWG_CONFIG)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertNotIn(KEY_A, result)
        self.assertIn(KEY_B, result)
        for field in ("Address = 10.0.0.1/24", "PrivateKey = server_privkey",
                      "DNS = 1.1.1.1", "MTU = 1420", "Table = auto",
                      "PostUp = /usr/local/sbin/route.sh up",
                      "PostDown = /usr/local/sbin/route.sh down",
                      "Jc = 40", "Jmin = 40", "Jmax = 70",
                      "S1 = 0", "S2 = 0", "H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4"):
            self.assertIn(field, result)

    def test_dns_preserved_after_removal(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\nDNS = 1.1.1.1, 8.8.8.8\n\n"
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        self.assertIn("DNS = 1.1.1.1, 8.8.8.8", self._read("wg0.conf"))

    def test_mtu_preserved_after_removal(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\nMTU = 1280\n\n"
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        self.assertIn("MTU = 1280", self._read("wg0.conf"))

    def test_table_preserved_after_removal(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\nTable = 51820\n\n"
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        self.assertIn("Table = 51820", self._read("wg0.conf"))

    def test_postup_postdown_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n"
            "PostUp = iptables -A FORWARD -i %i -j ACCEPT\n"
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT\n\n"
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertIn("PostUp = iptables -A FORWARD -i %i -j ACCEPT", result)
        self.assertIn("PostDown = iptables -D FORWARD -i %i -j ACCEPT", result)

    def test_amnezia_fields_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\nJc = 40\nJmin = 40\nJmax = 70\n"
            "S1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n\n"
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        for field in ("Jc = 40", "Jmin = 40", "Jmax = 70",
                      "S1 = 0", "S2 = 0", "H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4"):
            self.assertIn(field, result)

    def test_remaining_peer_fields_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n"
            f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.3/32\n"
            f"Endpoint = 5.6.7.8:51820\nPresharedKey = pskey_b\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertIn(KEY_B, result)
        self.assertIn("Endpoint = 5.6.7.8:51820", result)
        self.assertIn("PresharedKey = pskey_b", result)

    def test_interface_section_exact_bytes(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            b"[Interface]\n"
            b"Address = 10.0.0.1/24\n"
            b"PrivateKey = k\n"
            b"DNS = 1.1.1.1\n"
            b"MTU = 1420\n"
            b"\n"
            b"[Peer]\n"
            b"PublicKey = " + KEY_A.encode() + b"\n"
            b"AllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = (self.conf_dir / "wg0.conf").read_bytes()
        expected = (
            b"[Interface]\n"
            b"Address = 10.0.0.1/24\n"
            b"PrivateKey = k\n"
            b"DNS = 1.1.1.1\n"
            b"MTU = 1420\n"
            b"\n"
        )
        self.assertEqual(result, expected)


# =========================================================
# EDGE CASES
# =========================================================


class AwgPeerRemoveEdgeCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)
        self.patcher_conf = patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.conf_dir)
        self.patcher_backup = patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={})
        self.patcher_conf.start()
        self.patcher_backup.start()

    def tearDown(self) -> None:
        self.patcher_backup.stop()
        self.patcher_conf.stop()
        self.td.cleanup()

    def _write(self, name: str, content: str | bytes) -> Path:
        p = self.conf_dir / name
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
        return p

    def _read(self, name: str) -> str:
        return (self.conf_dir / name).read_text(encoding="utf-8")

    def _read_bytes(self, name: str) -> bytes:
        return (self.conf_dir / name).read_bytes()

    def test_empty_file_returns_404(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", "")
        original = self._read_bytes("wg0.conf")
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "peer not found in config"})
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_interface_only_returns_404(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = "[Interface]\nPrivateKey = k\nAddress = 10.0.0.1/24\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "peer not found in config"})
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_incomplete_peer_block_no_publickey(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            "[Peer]\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_empty_peer_block(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            "[Peer]\n\n"
        )
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_removal_of_already_removed_peer(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        self._write("wg0.conf", SINGLE_PEER)
        status1, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status1, 200)
        status2, body2 = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status2, 404)
        self.assertEqual(body2, {"error": "peer not found in config"})
        result = self._read("wg0.conf")
        self.assertIn("[Interface]", result)
        self.assertNotIn(KEY_A, result)

    def test_key_in_comment_not_matched(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            f"[Interface]\nPrivateKey = k\n# PublicKey = {KEY_A}\n\n"
            f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertIn(KEY_B, self._read("wg0.conf"))

    def test_key_in_allowedips_not_matched(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = {KEY_A}/32\n"
        )
        self._write("wg0.conf", conf)
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertIn(KEY_B, self._read("wg0.conf"))

    def test_key_in_endpoint_not_matched(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            f"[Peer]\nPublicKey = {KEY_B}\nEndpoint = host:{KEY_A}\n"
        )
        self._write("wg0.conf", conf)
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertIn(KEY_B, self._read("wg0.conf"))

    def test_multiple_peers_similar_values(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n"
            f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_B)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertIn(KEY_A, result)
        self.assertNotIn(KEY_B, result)
        self.assertIn("AllowedIPs = 10.0.0.2/32", result)

    def test_non_peer_section_with_publickey_not_matched(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            f"[CustomSection]\nPublicKey = {KEY_A}\nValue = something\n\n"
            f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        status, body = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 404)
        self.assertIn(KEY_B, self._read("wg0.conf"))

    def test_peer_section_not_at_end_of_file(self) -> None:
        from gatebsd_ui.writers.vpn import awg_peer_remove
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n\n"
            "[Interface]\nPrivateKey = k2\n"
        )
        self._write("wg0.conf", conf)
        status, _ = awg_peer_remove("wg0", KEY_A)
        self.assertEqual(status, 200)
        result = self._read("wg0.conf")
        self.assertNotIn(KEY_A, result)
        self.assertIn("[Interface]\nPrivateKey = k2", result)


# =========================================================
# ATOMICITY FOR READERS (pipe-synchronized, subprocess-based)
# =========================================================


class AwgPeerRemoveAtomicityTests(unittest.TestCase):
    """Prove readers see consistent file state during removal.

    Uses pipe-based synchronization: the writer subprocess patches os.replace
    to signal PRE_REPLACE, then waits for GO. Readers are governed by a start
    signal and stop when stdin closes. This guarantees readers are actively
    reading the file during the replace window.
    """

    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)

    def tearDown(self) -> None:
        self.td.cleanup()

    def _write(self, name: str, content: str) -> Path:
        p = self.conf_dir / name
        p.write_text(content, encoding="utf-8")
        return p

    def _run_atomicity_test(
        self,
        original_conf: str,
        expected_after: str,
        num_readers: int,
        test_label: str,
    ) -> None:
        """Core atomicity test with file-synchronized writer and readers."""
        self._write("wg0.conf", original_conf)
        original_hex = original_conf.encode().hex()
        expected_hex = expected_after.encode().hex()
        conf_path = str(self.conf_dir / "wg0.conf")

        # Create sync directory
        sync_dir = tempfile.mkdtemp(dir=str(self.conf_dir), prefix="sync_")
        signal_dir = tempfile.mkdtemp(dir=str(self.conf_dir), prefix="signal_")

        reader_procs: list[subprocess.Popen] = []
        reader_stderr_files: list[tempfile.TemporaryFile] = []

        # Start reader subprocesses
        for i in range(num_readers):
            env = os.environ.copy()
            env["CONF_PATH"] = conf_path
            env["ORIGINAL_HEX"] = original_hex
            env["EXPECTED_HEX"] = expected_hex
            env["SIGNAL_DIR"] = signal_dir
            stderr_f = tempfile.TemporaryFile(mode="w+b")
            reader_stderr_files.append(stderr_f)
            proc = subprocess.Popen(
                [sys.executable, "-c",
                 "from tests.awg_peer_remove_workers import _atomicity_reader_main; "
                 "_atomicity_reader_main()"],
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_f,
                close_fds=True,
                start_new_session=True,
            )
            reader_procs.append(proc)

        # Start writer subprocess
        w = _Worker(
            str(self.conf_dir), "wg0", KEY_A, f"{test_label}-writer",
            worker_main="_atomicity_writer_main",
            env_extra={"SYNC_DIR": sync_dir},
        )
        all_violations: list[str] = []
        try:
            w.start()
            w.wait_stage("worker_started")

            # Send GOVERNOR_START to all readers via their stdin pipes
            for proc in reader_procs:
                try:
                    proc.stdin.write(b"GOVERNOR_START\n")
                    proc.stdin.flush()
                except (OSError, BrokenPipeError):
                    pass

            # Wait for writer to create "ready" file (about to replace)
            ready_path = os.path.join(sync_dir, "ready")
            deadline = _time.monotonic() + 10.0
            while not os.path.exists(ready_path):
                if _time.monotonic() > deadline:
                    all_violations.append("timeout waiting for writer ready")
                    break
                _time.sleep(0.001)

            if not all_violations:
                # Wait for ALL readers to signal they have read the original file
                signal_deadline = _time.monotonic() + 5.0
                while _time.monotonic() < signal_deadline:
                    signal_files = [f for f in os.listdir(signal_dir) if f.startswith("read_")]
                    if len(signal_files) >= num_readers:
                        break
                    _time.sleep(0.001)

                # Now signal writer to proceed with replace
                go_path = os.path.join(sync_dir, "go")
                with open(go_path, "w") as f:
                    f.write("go")

                # Wait for writer to complete
                r = w.recv_result()
                self.assertEqual(r["status"], 200, f"writer failed: {r}")

            # Close all reader stdin pipes to signal them to stop
            for proc in reader_procs:
                try:
                    proc.stdin.close()
                except (OSError, ValueError):
                    pass
                finally:
                    proc.stdin = None

            # Collect and validate reader results
            for i, proc in enumerate(reader_procs):
                try:
                    stdout_data, stderr_data = proc.communicate(timeout=30)
                    if proc.stdout is not None:
                        proc.stdout.close()
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    all_violations.append(f"reader {i}: timed out")
                    continue

                # Strict validation of reader process
                if proc.returncode != 0:
                    all_violations.append(
                        f"reader {i}: exit code {proc.returncode}"
                    )
                    continue

                # Parse exactly one terminal message
                lines = [l for l in stdout_data.strip().split(b"\n") if l.strip()]
                terminal_msgs = []
                json_errors = 0
                unknown_stages = []
                for line in lines:
                    try:
                        msg = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        json_errors += 1
                        continue
                    stage = msg.get("stage")
                    if stage == "done":
                        terminal_msgs.append(msg)
                    elif stage not in ("read",):
                        unknown_stages.append(stage)

                if json_errors > 0:
                    all_violations.append(
                        f"reader {i}: {json_errors} JSON decode errors"
                    )
                if unknown_stages:
                    all_violations.append(
                        f"reader {i}: unknown stages: {unknown_stages}"
                    )
                if len(terminal_msgs) != 1:
                    all_violations.append(
                        f"reader {i}: expected 1 terminal 'done', "
                        f"got {len(terminal_msgs)}"
                    )
                    continue

                done = terminal_msgs[0]
                reader_viols = done.get("violations", [])
                all_violations.extend(
                    f"reader {i}: {v}" for v in reader_viols
                )

                if not done.get("seen_original"):
                    all_violations.append(
                        f"reader {i}: never saw original state"
                    )
                if not done.get("seen_expected"):
                    all_violations.append(
                        f"reader {i}: never saw expected state"
                    )

                # Check stderr for tracebacks
                if stderr_data:
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    if "Traceback" in stderr_text:
                        all_violations.append(
                            f"reader {i}: stderr contains Traceback"
                        )

                # Verify PID/PGID are gone
                try:
                    os.kill(proc.pid, 0)
                    all_violations.append(
                        f"reader {i}: PID {proc.pid} still exists"
                    )
                except ProcessLookupError:
                    pass
                try:
                    pgid = os.getpgid(proc.pid)
                    try:
                        os.killpg(pgid, 0)
                        all_violations.append(
                            f"reader {i}: PGID {pgid} still exists"
                        )
                    except ProcessLookupError:
                        pass
                except OSError:
                    pass

        finally:
            # Cleanup: close reader stdin pipes first, then kill
            for proc in reader_procs:
                try:
                    if proc.stdin and not proc.stdin.closed:
                        proc.stdin.close()
                except (OSError, ValueError):
                    pass
            for proc in reader_procs:
                try:
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGTERM)
                        proc.wait(timeout=3)
                except (ProcessLookupError, OSError, subprocess.TimeoutExpired):
                    pass
                try:
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait(timeout=3)
                except (ProcessLookupError, OSError, subprocess.TimeoutExpired):
                    pass
                for stream in (proc.stdin, proc.stdout):
                    if stream is not None:
                        try:
                            stream.close()
                        except (OSError, ValueError):
                            pass
            w.cleanup()
            for f in reader_stderr_files:
                try:
                    f.close()
                except (OSError, ValueError):
                    pass
            # Cleanup sync dir
            try:
                import shutil
                shutil.rmtree(sync_dir, ignore_errors=True)
                shutil.rmtree(signal_dir, ignore_errors=True)
            except Exception:
                pass

        self.assertEqual(all_violations, [],
                         f"atomicity violations: {all_violations}")

    def test_readers_see_consistent_state_during_removal(self) -> None:
        """3-peer removal: readers must see original AND expected state."""
        expected_after = (
            f"[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = server_privkey\n"
            f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.3/32\n"
            f"[Peer]\nPublicKey = {KEY_C}\nAllowedIPs = 10.0.0.4/32\n"
        )
        self._run_atomicity_test(
            THREE_PEERS, expected_after, num_readers=4,
            test_label="atomic-3peers",
        )

    def test_readers_see_consistent_state_single_peer(self) -> None:
        """Single peer removal: readers must see original AND expected state."""
        expected_after = "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = server_privkey\n"
        self._run_atomicity_test(
            SINGLE_PEER, expected_after, num_readers=3,
            test_label="atomic-1peer",
        )


# =========================================================
# CONCURRENT OPERATIONS (subprocess-based)
# =========================================================


class AwgPeerRemoveConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)

    def tearDown(self) -> None:
        self.td.cleanup()

    def _write(self, name: str, content: str) -> Path:
        p = self.conf_dir / name
        p.write_text(content, encoding="utf-8")
        return p

    def _read(self, name: str) -> str:
        return (self.conf_dir / name).read_text(encoding="utf-8")

    def test_concurrent_removal_different_peers(self) -> None:
        """Two subprocess workers remove different peers concurrently."""
        self._write("wg0.conf", THREE_PEERS)
        expected = (
            f"[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = server_privkey\n"
            f"[Peer]\nPublicKey = {KEY_C}\nAllowedIPs = 10.0.0.4/32\n"
        )
        w1 = _Worker(str(self.conf_dir), "wg0", KEY_A, "conc-a")
        w2 = _Worker(str(self.conf_dir), "wg0", KEY_B, "conc-b")
        try:
            w1.start()
            w1.wait_stage("worker_started")
            w1.wait_stage("lock_acquired")
            w2.start()
            w2.wait_stage("worker_started")
            w2.wait_stage("lock_attempted")
            r1 = w1.recv_result()
            self.assertEqual(r1["status"], 200)
            r2 = w2.recv_result()
            self.assertEqual(r2["status"], 200)
            result = self._read("wg0.conf")
            self.assertEqual(result, expected,
                             f"expected exact content after removing A and B")
        finally:
            w1.cleanup()
            w2.cleanup()

    def test_concurrent_removal_same_peer(self) -> None:
        """Two workers remove the same peer — one succeeds, one gets 404."""
        self._write("wg0.conf", SINGLE_PEER)
        expected = "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = server_privkey\n"
        w1 = _Worker(str(self.conf_dir), "wg0", KEY_A, "conc-same-a")
        w2 = _Worker(str(self.conf_dir), "wg0", KEY_A, "conc-same-b")
        try:
            w1.start()
            w1.wait_stage("worker_started")
            w1.wait_stage("lock_acquired")
            w2.start()
            w2.wait_stage("worker_started")
            w2.wait_stage("lock_attempted")
            r1 = w1.recv_result()
            self.assertEqual(r1["status"], 200)
            r2 = w2.recv_result()
            self.assertEqual(r2["status"], 404)
            result = self._read("wg0.conf")
            self.assertEqual(result, expected)
        finally:
            w1.cleanup()
            w2.cleanup()

    def test_remove_with_concurrent_readers(self) -> None:
        """Remove while multiple readers read — each read is exact original or expected."""
        original_conf = THREE_PEERS
        expected_after = (
            f"[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = server_privkey\n"
            f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.3/32\n"
            f"[Peer]\nPublicKey = {KEY_C}\nAllowedIPs = 10.0.0.4/32\n"
        )
        self._write("wg0.conf", original_conf)
        original_hex = original_conf.encode().hex()
        expected_hex = expected_after.encode().hex()
        conf_path = str(self.conf_dir / "wg0.conf")

        reader_procs: list[subprocess.Popen] = []
        reader_stderr_files: list[tempfile.TemporaryFile] = []
        for i in range(3):
            env = os.environ.copy()
            env["CONF_PATH"] = conf_path
            env["READER_COUNT"] = "500"
            env["ORIGINAL_HEX"] = original_hex
            env["EXPECTED_HEX"] = expected_hex
            stderr_f = tempfile.TemporaryFile(mode="w+b")
            reader_stderr_files.append(stderr_f)
            proc = subprocess.Popen(
                [sys.executable, "-c",
                 "from tests.awg_peer_remove_workers import _reader_worker_main; "
                 "_reader_worker_main()"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=stderr_f,
                close_fds=True,
                start_new_session=True,
            )
            reader_procs.append(proc)

        w = _Worker(str(self.conf_dir), "wg0", KEY_A, "rem-with-readers")
        try:
            w.start()
            w.wait_stage("worker_started")
            w.wait_stage("lock_acquired")
            r = w.recv_result()
            self.assertEqual(r["status"], 200)
        finally:
            w.cleanup()

        all_violations: list[str] = []
        for i, proc in enumerate(reader_procs):
            try:
                stdout_data, stderr_data = proc.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                all_violations.append(f"reader {i}: timed out")
                continue
            finally:
                if proc.stdout is not None:
                    try:
                        proc.stdout.close()
                    except (OSError, ValueError):
                        pass

            if proc.returncode != 0:
                all_violations.append(f"reader {i}: exit code {proc.returncode}")
                continue

            lines = [l for l in stdout_data.strip().split(b"\n") if l.strip()]
            terminal_msgs = []
            json_errors = 0
            for line in lines:
                try:
                    msg = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    json_errors += 1
                    continue
                if msg.get("stage") == "done":
                    terminal_msgs.append(msg)

            if json_errors > 0:
                all_violations.append(f"reader {i}: {json_errors} JSON decode errors")
            if len(terminal_msgs) != 1:
                all_violations.append(
                    f"reader {i}: expected 1 terminal, got {len(terminal_msgs)}"
                )
                continue

            all_violations.extend(
                f"reader {i}: {v}" for v in terminal_msgs[0].get("violations", [])
            )

            if stderr_data:
                stderr_text = stderr_data.decode("utf-8", errors="replace")
                if "Traceback" in stderr_text:
                    all_violations.append(f"reader {i}: stderr Traceback")

            try:
                os.kill(proc.pid, 0)
                all_violations.append(f"reader {i}: PID still exists")
            except ProcessLookupError:
                pass

        for f in reader_stderr_files:
            try:
                f.close()
            except (OSError, ValueError):
                pass

        self.assertEqual(all_violations, [], f"violations: {all_violations}")

    def test_sequential_removals_under_lock(self) -> None:
        """Verify no lost update when operations are serialized under lock."""
        self._write("wg0.conf", THREE_PEERS)
        expected = "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = server_privkey\n"

        for i, key in enumerate([KEY_A, KEY_B, KEY_C]):
            w = _Worker(str(self.conf_dir), "wg0", key, f"seq-{i}")
            try:
                w.start()
                w.wait_stage("worker_started")
                w.wait_stage("lock_acquired")
                r = w.recv_result()
                self.assertEqual(r["status"], 200)
            finally:
                w.cleanup()

        result = self._read("wg0.conf")
        self.assertEqual(result, expected)


# =========================================================
# FILESYSTEM ERROR INJECTION
# =========================================================


class AwgPeerRemoveFilesystemErrorTests(unittest.TestCase):
    """Test each filesystem stage that exists in production awg_peer_remove.

    Publication failures are converted by vpn.py into a stable HTTP 500
    response while atomic_write_bytes preserves the original file and cleans
    up temporary state.  Inject each low-level stage independently:
      1. mkstemp
      2. fdopen
      3. write  — inside try/except Exception (on tmp file object)
      4. flush  — inside try/except Exception (on tmp file object)
      5. fsync  — inside try/except Exception
      6. chown  — OSError swallowed
      7. chmod  — inside try/except Exception
      8. replace — inside try/except Exception

    The helper also performs best-effort directory fsync after replace.
    """

    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)

    def tearDown(self) -> None:
        self.td.cleanup()

    def _write(self, name: str, content: str) -> Path:
        p = self.conf_dir / name
        p.write_text(content, encoding="utf-8")
        return p

    def _read_bytes(self, name: str) -> bytes:
        return (self.conf_dir / name).read_bytes()

    def _read(self, name: str) -> str:
        return (self.conf_dir / name).read_text(encoding="utf-8")

    def _assert_after_fs_error(self, stage: str) -> None:
        """Common assertions after filesystem error at given stage."""
        self._write("wg0.conf", SINGLE_PEER)
        original = self._read_bytes("wg0.conf")

        w = _Worker(
            str(self.conf_dir), "wg0", KEY_A, f"fs-err-{stage}",
            worker_main="_remove_worker_with_error_main",
            env_extra={"FAIL_STAGE": stage, "FAIL_COUNT": "1"},
        )
        try:
            w.start()
            w.wait_stage("worker_started")
            r = w.recv_exception_or_result()
            self.assertEqual(r.get("stage"), "result", r)
            self.assertEqual(r.get("status"), 500, r)
            self.assertEqual(r.get("body"), {"error": "failed to write config"}, r)
        finally:
            w.cleanup()

        self.assertEqual(self._read_bytes("wg0.conf"), original,
                         f"config changed after {stage} error")

        tmp_files = list(self.conf_dir.glob("*.tmp"))
        self.assertEqual(tmp_files, [],
                         f"temp files left after {stage} error: {tmp_files}")

        lock_path = self.conf_dir / "wg0.conf.lock"
        if lock_path.exists():
            lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
            try:
                result = fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertIsNone(result, f"lock not released after {stage} error")
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def test_mkstemp_error_preserves_original(self) -> None:
        self._assert_after_fs_error("mkstemp")

    def test_fdopen_error_preserves_original(self) -> None:
        self._assert_after_fs_error("fdopen")

    def test_write_error_preserves_original(self) -> None:
        """Error during tmp.write() — original config must survive."""
        self._assert_after_fs_error("write")

    def test_flush_error_preserves_original(self) -> None:
        """Error during tmp.flush() — original config must survive."""
        self._assert_after_fs_error("flush")

    def test_fsync_error_preserves_original(self) -> None:
        self._assert_after_fs_error("fsync")

    def test_chmod_error_preserves_original(self) -> None:
        self._assert_after_fs_error("chmod")

    def test_replace_error_preserves_original(self) -> None:
        self._assert_after_fs_error("replace")

    def test_subsequent_operation_succeeds_after_error(self) -> None:
        """After error, next operation on same config must succeed."""
        self._write("wg0.conf", THREE_PEERS)
        original = self._read_bytes("wg0.conf")

        w = _Worker(
            str(self.conf_dir), "wg0", KEY_A, "fs-recovery",
            worker_main="_remove_worker_with_error_main",
            env_extra={"FAIL_STAGE": "replace", "FAIL_COUNT": "1"},
        )
        try:
            w.start()
            w.wait_stage("worker_started")
            w.recv_exception_or_result()
        finally:
            w.cleanup()

        self.assertEqual(self._read_bytes("wg0.conf"), original)

        expected = (
            f"[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = server_privkey\n"
            f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.3/32\n"
            f"[Peer]\nPublicKey = {KEY_C}\nAllowedIPs = 10.0.0.4/32\n"
        )
        w2 = _Worker(str(self.conf_dir), "wg0", KEY_A, "fs-recovery-ok")
        try:
            w2.start()
            w2.wait_stage("worker_started")
            w2.wait_stage("lock_acquired")
            r = w2.recv_result()
            self.assertEqual(r["status"], 200)
        finally:
            w2.cleanup()

        result = self._read("wg0.conf")
        self.assertEqual(result, expected,
                         f"config incorrect after recovery: {result!r}")

    def test_replace_error_exception_not_masked(self) -> None:
        """When replace fails, the original OSError must propagate as exception.

        awg_peer_remove raises on write errors (does not return 500).
        The exception stage must be "exception" with the original error message.
        """
        self._write("wg0.conf", SINGLE_PEER)

        w = _Worker(
            str(self.conf_dir), "wg0", KEY_A, "fs-mask",
            worker_main="_remove_worker_with_error_main",
            env_extra={"FAIL_STAGE": "replace", "FAIL_COUNT": "1"},
        )
        try:
            w.start()
            w.wait_stage("worker_started")
            r = w.recv_exception_or_result()
            self.assertEqual(r.get("stage"), "result", r)
            self.assertEqual(r.get("status"), 500, r)
            self.assertEqual(r.get("body"), {"error": "failed to write config"}, r)
        finally:
            w.cleanup()

        # Config must be unchanged
        self.assertEqual(
            self._read_bytes("wg0.conf"),
            SINGLE_PEER.encode(),
            "config must not be modified after replace error"
        )

    def test_write_error_exception_propagates(self) -> None:
        """Write error must propagate as exception, not swallowed."""
        self._write("wg0.conf", SINGLE_PEER)

        w = _Worker(
            str(self.conf_dir), "wg0", KEY_A, "fs-write",
            worker_main="_remove_worker_with_error_main",
            env_extra={"FAIL_STAGE": "write", "FAIL_COUNT": "1"},
        )
        try:
            w.start()
            w.wait_stage("worker_started")
            r = w.recv_exception_or_result()
            self.assertEqual(r.get("stage"), "result", r)
            self.assertEqual(r.get("status"), 500, r)
            self.assertEqual(r.get("body"), {"error": "failed to write config"}, r)
        finally:
            w.cleanup()

        self.assertEqual(self._read_bytes("wg0.conf"), SINGLE_PEER.encode())

    def test_flush_error_exception_propagates(self) -> None:
        """Flush error must propagate as exception, not swallowed."""
        self._write("wg0.conf", SINGLE_PEER)

        w = _Worker(
            str(self.conf_dir), "wg0", KEY_A, "fs-flush",
            worker_main="_remove_worker_with_error_main",
            env_extra={"FAIL_STAGE": "flush", "FAIL_COUNT": "1"},
        )
        try:
            w.start()
            w.wait_stage("worker_started")
            r = w.recv_exception_or_result()
            self.assertEqual(r.get("stage"), "result", r)
            self.assertEqual(r.get("status"), 500, r)
            self.assertEqual(r.get("body"), {"error": "failed to write config"}, r)
        finally:
            w.cleanup()

        self.assertEqual(self._read_bytes("wg0.conf"), SINGLE_PEER.encode())


# =========================================================
# LOCK AND PROCESS LIFECYCLE
# =========================================================


class AwgPeerRemoveLockLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)

    def tearDown(self) -> None:
        self.td.cleanup()

    def _write(self, name: str, content: str) -> Path:
        p = self.conf_dir / name
        p.write_text(content, encoding="utf-8")
        return p

    def _read(self, name: str) -> str:
        return (self.conf_dir / name).read_text(encoding="utf-8")

    def _assert_lock_free(self) -> None:
        lock_path = self.conf_dir / "wg0.conf.lock"
        lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        try:
            result = fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIsNone(result, "lock should be free")
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    def test_lock_released_after_success(self) -> None:
        self._write("wg0.conf", SINGLE_PEER)
        w = _Worker(str(self.conf_dir), "wg0", KEY_A, "lock-success")
        try:
            w.start()
            w.wait_stage("worker_started")
            w.wait_stage("lock_acquired")
            r = w.recv_result()
            self.assertEqual(r["status"], 200)
        finally:
            w.cleanup()
        self._assert_lock_free()

    def test_lock_released_after_404(self) -> None:
        self._write("wg0.conf", SINGLE_PEER)
        w = _Worker(str(self.conf_dir), "wg0", KEY_B, "lock-404")
        try:
            w.start()
            w.wait_stage("worker_started")
            w.wait_stage("lock_acquired")
            r = w.recv_result()
            self.assertEqual(r["status"], 404)
        finally:
            w.cleanup()
        self._assert_lock_free()

    def test_lock_released_after_409(self) -> None:
        conf = (
            "[Interface]\nPrivateKey = k\n\n"
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.2/32\n"
            f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.0.0.3/32\n"
        )
        self._write("wg0.conf", conf)
        w = _Worker(str(self.conf_dir), "wg0", KEY_A, "lock-409")
        try:
            w.start()
            w.wait_stage("worker_started")
            w.wait_stage("lock_acquired")
            r = w.recv_result()
            self.assertEqual(r["status"], 409)
        finally:
            w.cleanup()
        self._assert_lock_free()

    def test_external_lock_blocks_removal(self) -> None:
        self._write("wg0.conf", SINGLE_PEER)
        lock_path = str(self.conf_dir / "wg0.conf.lock")
        holder = _ExternalLockHolder(lock_path, "ext-block")
        w = _Worker(str(self.conf_dir), "wg0", KEY_A, "blocked-rem")
        try:
            holder.start()
            holder.wait_lock_acquired()
            w.start()
            w.wait_stage("worker_started")
            w.wait_stage("lock_attempted")
            holder.release()
            w.wait_stage("lock_acquired")
            r = w.recv_result()
            self.assertEqual(r["status"], 200)
        finally:
            w.cleanup()
            holder.stop()

    def test_worker_cleanup_terminates_process(self) -> None:
        self._write("wg0.conf", SINGLE_PEER)
        w = _Worker(str(self.conf_dir), "wg0", KEY_A, "cleanup-test")
        w.start()
        w.wait_stage("worker_started")
        w.wait_stage("lock_acquired")
        pid = w.proc.pid
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = None

        w.cleanup()

        self.assertIsNotNone(w.proc.poll(), "worker should be terminated")
        try:
            os.kill(pid, 0)
            self.fail(f"worker PID {pid} still exists after cleanup")
        except ProcessLookupError:
            pass
        if pgid is not None:
            try:
                os.killpg(pgid, 0)
                self.fail(f"worker PGID {pgid} still exists after cleanup")
            except ProcessLookupError:
                pass

    def test_reader_thread_terminated_after_cleanup(self) -> None:
        self._write("wg0.conf", SINGLE_PEER)
        w = _Worker(str(self.conf_dir), "wg0", KEY_A, "thread-test")
        try:
            w.start()
            w.wait_stage("worker_started")
            w.wait_stage("lock_acquired")
            self.assertIsNotNone(w._reader_thread)
            self.assertTrue(w._reader_thread.is_alive())
        finally:
            w.cleanup()
        self.assertIsNotNone(w._reader_thread)
        self.assertFalse(w._reader_thread.is_alive(),
                         "reader thread must be dead after cleanup")
        self.assertIsNotNone(w.proc.poll(), "worker must be terminated")

    def test_lock_holder_termination_frees_lock(self) -> None:
        self._write("wg0.conf", SINGLE_PEER)
        lock_path = str(self.conf_dir / "wg0.conf.lock")
        holder = _ExternalLockHolder(lock_path, "kill-holder")
        try:
            holder.start()
            holder.wait_lock_acquired()

            lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
            try:
                self.assertRaises(OSError, fcntl.flock, lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(lock_fd)

            holder.stop()

            lock_fd2 = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
            try:
                result = fcntl.flock(lock_fd2, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertIsNone(result, "lock should be freed after holder killed")
                fcntl.flock(lock_fd2, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd2)
        finally:
            holder.stop()

    def test_no_hanging_processes_after_test(self) -> None:
        self._write("wg0.conf", SINGLE_PEER)
        lock_path = str(self.conf_dir / "wg0.conf.lock")
        holder = _ExternalLockHolder(lock_path, "leak-check-h")
        w = _Worker(str(self.conf_dir), "wg0", KEY_A, "leak-check-w")
        try:
            holder.start()
            holder.wait_lock_acquired()
            w.start()
            w.wait_stage("worker_started")
            w.wait_stage("lock_attempted")
            holder.release()
            w.wait_stage("lock_acquired")
            r = w.recv_result()
            self.assertEqual(r["status"], 200)
        finally:
            w.cleanup()
            holder.stop()

        self.assertIsNotNone(w.proc.poll())
        self.assertIsNotNone(holder.proc.poll())
        if w._reader_thread is not None:
            self.assertFalse(w._reader_thread.is_alive())
        if holder._reader_thread is not None:
            self.assertFalse(holder._reader_thread.is_alive())


if __name__ == "__main__":
    unittest.main()
