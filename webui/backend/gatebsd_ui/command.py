from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable

_SAFE_PATH = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"
_DEFAULT_MAX_OUTPUT = 2 * 1024 * 1024
_DEFAULT_MAX_INPUT = 64 * 1024


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    ok: bool
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "ok": self.ok,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
        }


def _safe_environment(overrides: dict[str, str] | None) -> dict[str, str]:
    environment = {
        "PATH": _SAFE_PATH,
        "HOME": "/root" if os.geteuid() == 0 else "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
    }
    if overrides:
        for key, value in overrides.items():
            if not isinstance(key, str) or not key or "=" in key or "\x00" in key:
                raise ValueError("invalid environment variable name")
            if not isinstance(value, str) or "\x00" in value:
                raise ValueError(f"invalid environment variable value for {key}")
            environment[key] = value
    return environment


def _group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the whole isolated process group, even if its leader exits first."""

    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        try:
            process.terminate()
        except OSError:
            return

    # Waiting only for the group leader is insufficient: a child can survive
    # after the leader exits. Give every member a short graceful window, then
    # enforce cleanup for the still-existing group.
    deadline = time.monotonic() + 0.25
    while time.monotonic() < deadline and _group_exists(pgid):
        time.sleep(0.01)

    if _group_exists(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            try:
                process.kill()
            except OSError:
                pass

    try:
        process.wait(timeout=0.5)
    except (subprocess.TimeoutExpired, ChildProcessError):
        pass


def _display_command(command: list[str], redact_args: Iterable[int] | None) -> list[str]:
    hidden = set(redact_args or ())
    return ["<redacted>" if index in hidden else item for index, item in enumerate(command)]


def run(
    command: list[str],
    timeout: float = 4.0,
    env: dict[str, str] | None = None,
    input: str | bytes | None = None,
    *,
    max_output: int = _DEFAULT_MAX_OUTPUT,
    max_input: int = _DEFAULT_MAX_INPUT,
    redact_args: Iterable[int] | None = None,
) -> CommandResult:
    """Run one argv-only command with bounded I/O and process-group cleanup."""
    display = _display_command(command, redact_args)
    if not command or any(not isinstance(item, str) or not item or "\x00" in item for item in command):
        return CommandResult(display, False, None, "", "", "invalid command arguments")
    if timeout <= 0 or max_output < 0 or max_input < 0:
        return CommandResult(display, False, None, "", "", "invalid command limits")

    if isinstance(input, str):
        stdin_payload = input.encode("utf-8")
    elif isinstance(input, bytes):
        stdin_payload = input
    elif input is None:
        stdin_payload = b""
    else:
        return CommandResult(display, False, None, "", "", "invalid command input")
    if len(stdin_payload) > max_input:
        return CommandResult(display, False, None, "", "", f"input exceeds {max_input} bytes")

    try:
        child_env = _safe_environment(env)
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            env=child_env,
        )
    except (FileNotFoundError, PermissionError, OSError, ValueError) as exc:
        return CommandResult(display, False, None, "", "", str(exc))

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    budget = {"remaining": max_output}
    budget_lock = threading.Lock()
    overflow = threading.Event()

    def reader(stream: Any, chunks: list[bytes]) -> None:
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                with budget_lock:
                    take = min(len(chunk), budget["remaining"])
                    if take:
                        chunks.append(chunk[:take])
                        budget["remaining"] -= take
                    if take < len(chunk) and not overflow.is_set():
                        overflow.set()
                        _terminate_group(process)
        except OSError:
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    assert process.stdout is not None and process.stderr is not None
    stdout_thread = threading.Thread(target=reader, args=(process.stdout, stdout_chunks), daemon=True)
    stderr_thread = threading.Thread(target=reader, args=(process.stderr, stderr_chunks), daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    stdin_thread: threading.Thread | None = None
    if input is not None and process.stdin is not None:
        def writer() -> None:
            try:
                assert process.stdin is not None
                process.stdin.write(stdin_payload)
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            finally:
                try:
                    assert process.stdin is not None
                    process.stdin.close()
                except OSError:
                    pass

        stdin_thread = threading.Thread(target=writer, daemon=True)
        stdin_thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_group(process)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass

    if stdin_thread is not None:
        stdin_thread.join(timeout=1)
    stdout_thread.join(timeout=1)
    stderr_thread.join(timeout=1)
    stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace").strip()
    stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace").strip()

    error: str | None = None
    if timed_out:
        error = f"timeout after {timeout}s"
    elif overflow.is_set():
        error = f"output exceeds {max_output} bytes"
    return CommandResult(
        command=display,
        ok=process.returncode == 0 and error is None,
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        error=error,
    )


def lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]
