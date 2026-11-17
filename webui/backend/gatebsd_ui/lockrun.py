"""Run one command while holding one or more GateBSD flock-compatible locks."""
from __future__ import annotations

import os
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path

from .fsutil import exclusive_lock


def _parse(argv: list[str]) -> tuple[list[Path], list[str]]:
    if not argv:
        raise ValueError("a lock path and command are required")
    if argv[0] != "--lock":
        lock_paths = [Path(argv[0])]
        command = argv[1:]
        if command[:1] == ["--"]:
            command = command[1:]
        if not command:
            raise ValueError("a command is required")
        return lock_paths, command

    lock_paths: list[Path] = []
    index = 0
    while index < len(argv) and argv[index] == "--lock":
        if index + 1 >= len(argv):
            raise ValueError("--lock requires a path")
        lock_paths.append(Path(argv[index + 1]))
        index += 2
    if index >= len(argv) or argv[index] != "--":
        raise ValueError("multiple-lock mode requires -- before the command")
    command = argv[index + 1:]
    if not lock_paths or not command:
        raise ValueError("at least one lock and a command are required")
    return sorted(set(lock_paths), key=lambda item: str(item)), command


def _command_environment() -> dict[str, str]:
    """Pass only runtime essentials and explicit GateBSD controls."""
    allowed = {"PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH"}
    return {
        key: value
        for key, value in os.environ.items()
        if key in allowed or key.startswith("GATEBSD_")
    }


def main() -> int:
    try:
        lock_paths, command = _parse(sys.argv[1:])
    except ValueError as exc:
        print(f"lockrun: {exc}", file=sys.stderr)
        return 2
    with ExitStack() as stack:
        for lock_path in lock_paths:
            stack.enter_context(exclusive_lock(lock_path))
        return subprocess.run(command, check=False, close_fds=True, env=_command_environment()).returncode


if __name__ == "__main__":
    raise SystemExit(main())
