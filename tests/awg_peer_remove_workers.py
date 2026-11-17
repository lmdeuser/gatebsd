"""Lightweight subprocess entrypoints for awg_peer_remove tests.

Kept separate from the large unittest module so spawned Python interpreters do
not import all 104 test cases before sending their first IPC event.
"""
from __future__ import annotations

import fcntl
import json
import os
import select
import sys
import time as _time
from contextlib import ExitStack
from pathlib import Path

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
