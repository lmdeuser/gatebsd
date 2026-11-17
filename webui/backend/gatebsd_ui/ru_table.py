"""Atomic RU-prefix table publication shared by shell and Web API writers."""
from __future__ import annotations

import argparse
import hashlib
import os
import stat
from pathlib import Path

from .fsutil import atomic_write_bytes, exclusive_lock

MAX_TABLE_SIZE = 16 * 1024 * 1024


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: Path, *, missing_ok: bool = False) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        if missing_ok:
            return b""
        raise
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(f"refusing unsafe table file: {path}")
        if metadata.st_size > MAX_TABLE_SIZE:
            raise OSError(f"table file exceeds {MAX_TABLE_SIZE} bytes: {path}")
        payload = bytearray()
        while len(payload) <= MAX_TABLE_SIZE:
            chunk = os.read(fd, min(65536, MAX_TABLE_SIZE + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_TABLE_SIZE:
            raise OSError(f"table file grew beyond {MAX_TABLE_SIZE} bytes: {path}")
        after = os.fstat(fd)
        if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise OSError(f"table changed while being read: {path}")
        return bytes(payload)
    finally:
        os.close(fd)


def replace_table(destination: Path, candidate: Path, *, expected_sha256: str = "") -> tuple[str, str]:
    destination = Path(destination)
    candidate_data = read_regular(Path(candidate))
    if not candidate_data or len(candidate_data) > MAX_TABLE_SIZE:
        raise ValueError("candidate table must contain 1 byte to 16 MiB")
    lock_path = destination.with_suffix(destination.suffix + ".lock")
    with exclusive_lock(lock_path):
        previous = read_regular(destination, missing_ok=True)
        current_digest = digest(previous)
        if expected_sha256 and current_digest != expected_sha256:
            raise RuntimeError("table changed since the caller prepared its transaction")
        atomic_write_bytes(
            destination,
            candidate_data,
            mode=0o640,
            preserve_metadata=bool(previous),
        )
        return current_digest, digest(candidate_data)


def main() -> int:
    parser = argparse.ArgumentParser(description="publish a GateBSD RU prefix table")
    parser.add_argument("destination")
    parser.add_argument("candidate")
    parser.add_argument("--expected-sha256", default="")
    args = parser.parse_args()
    old_digest, new_digest = replace_table(
        Path(args.destination),
        Path(args.candidate),
        expected_sha256=args.expected_sha256,
    )
    print(f"old_sha256={old_digest}")
    print(f"new_sha256={new_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
