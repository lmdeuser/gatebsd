"""Small, dependency-free filesystem primitives used by GateBSD writers.

The helpers in this module keep file replacement on the same filesystem,
flush file data before publication, and avoid leaving half-written
configuration or secret files after failures.
"""
from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


def _ensure_safe_directory(directory: Path) -> None:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    metadata = directory.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError(f"refusing unsafe directory: {directory}")


def _fsync_directory(directory: Path) -> None:
    """Best-effort fsync of a directory after a rename/link change."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(directory, flags)
        os.fsync(fd)
    except OSError:
        # Some filesystems/platforms do not permit directory fsync.  The file
        # itself has already been fsynced, so do not turn that portability
        # limitation into a failed configuration change.
        pass
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def read_regular_bytes(path: Path, *, max_size: int = 16 * 1024 * 1024) -> tuple[bytes, os.stat_result]:
    """Read one stable regular file without following its final symlink."""
    if max_size < 0:
        raise ValueError("max_size must not be negative")
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError(f"refusing unsafe regular file: {path}")
        if before.st_size > max_size:
            raise OSError(f"regular file is too large: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, max_size + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_size:
                raise OSError(f"regular file grew beyond the size limit: {path}")
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
        ):
            raise OSError(f"regular file changed while being read: {path}")
        return b"".join(chunks), before
    finally:
        os.close(fd)


def read_regular_text(
    path: Path,
    *,
    max_size: int = 16 * 1024 * 1024,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> tuple[str, os.stat_result]:
    data, metadata = read_regular_bytes(path, max_size=max_size)
    return data.decode(encoding, errors=errors), metadata


def atomic_write_bytes(
    path: Path,
    data: bytes,
    *,
    mode: int | None = None,
    preserve_metadata: bool = True,
    uid: int | None = None,
    gid: int | None = None,
) -> None:
    """Atomically replace *path* with *data*.

    A temporary file is created in the destination directory, fsynced, given
    the requested ownership/mode, and then published with ``os.replace``.
    Existing uid/gid and permission bits are preserved by default when ``mode``
    is omitted.  An explicit ``mode`` overrides existing permission bits.  For a new
    file, ``mode`` is mandatory so callers cannot accidentally create a
    world-readable secret or configuration.
    """
    path = Path(path)
    _ensure_safe_directory(path.parent)

    existing = None
    try:
        link_metadata = path.lstat()
    except FileNotFoundError:
        link_metadata = None
    if link_metadata is not None:
        if stat.S_ISLNK(link_metadata.st_mode):
            raise OSError(f"refusing to replace symlink: {path}")
        if not stat.S_ISREG(link_metadata.st_mode):
            raise OSError(f"refusing to replace non-regular file: {path}")
        existing = link_metadata

    if existing is None and mode is None:
        raise ValueError("mode is required when creating a new file")

    # An explicit mode is authoritative even when ownership metadata is
    # preserved.  Secret/configuration writers use this to tighten an
    # accidentally permissive existing file without changing its owner.
    if mode is not None:
        target_mode = int(mode)
    elif existing is not None and preserve_metadata:
        target_mode = stat.S_IMODE(existing.st_mode)
    else:
        target_mode = 0o600

    fd = -1
    temp_name: str | None = None
    try:
        fd, temp_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        try:
            stream = os.fdopen(fd, "wb")
        except Exception:
            os.close(fd)
            fd = -1
            raise
        fd = -1
        temp_stat: os.stat_result | None = None
        with stream:
            stream.write(data)
            stream.flush()
            stream_fd = stream.fileno()
            if stream_fd >= 0:
                temp_stat = os.fstat(stream_fd)
            os.fsync(stream_fd)

        def _verify_temp_inode() -> None:
            if temp_stat is None:
                return
            current = os.lstat(temp_name)
            if (
                stat.S_ISLNK(current.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or (current.st_dev, current.st_ino) != (temp_stat.st_dev, temp_stat.st_ino)
            ):
                raise OSError(f"temporary file replaced or linked during atomic write: {temp_name}")

        _verify_temp_inode()
        if uid is not None or gid is not None:
            os.chown(temp_name, -1 if uid is None else uid, -1 if gid is None else gid)
        elif existing is not None and preserve_metadata:
            os.chown(temp_name, existing.st_uid, existing.st_gid)
        _verify_temp_inode()
        os.chmod(temp_name, target_mode)
        _verify_temp_inode()
        os.replace(temp_name, path)
        temp_name = None
        _fsync_directory(path.parent)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_name is not None:
            try:
                Path(temp_name).unlink(missing_ok=True)
            except OSError:
                pass


def atomic_write_text(
    path: Path,
    text: str,
    *,
    mode: int | None = None,
    preserve_metadata: bool = True,
    encoding: str = "utf-8",
    uid: int | None = None,
    gid: int | None = None,
) -> None:
    atomic_write_bytes(
        path,
        text.encode(encoding),
        mode=mode,
        preserve_metadata=preserve_metadata,
        uid=uid,
        gid=gid,
    )


def atomic_symlink(link_path: Path, target: Path) -> None:
    """Atomically replace *link_path* with a symlink to *target*."""
    link_path = Path(link_path)
    target = Path(target)
    _ensure_safe_directory(link_path.parent)
    temp_link = link_path.with_name(f".{link_path.name}.{os.getpid()}.{os.urandom(6).hex()}.tmp")
    try:
        os.symlink(str(target), str(temp_link))
        os.replace(temp_link, link_path)
        _fsync_directory(link_path.parent)
    finally:
        try:
            temp_link.unlink(missing_ok=True)
        except OSError:
            pass


@contextmanager
def exclusive_lock(lock_path: Path, mode: int = 0o600, *, nonblocking: bool = False) -> Iterator[int]:
    """Acquire an inter-process exclusive flock and always release/close it."""
    lock_path = Path(lock_path)
    _ensure_safe_directory(lock_path.parent)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, mode)
    locked = False
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(f"refusing unsafe lock file: {lock_path}")
        os.fchmod(fd, mode)
        operation = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
        fcntl.flock(fd, operation)
        locked = True
        yield fd
    finally:
        if locked:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            os.close(fd)
        except OSError:
            pass
