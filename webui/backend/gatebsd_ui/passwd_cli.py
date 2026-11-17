"""Command-line password hash writer for GateBSD local-password mode."""
from __future__ import annotations

import getpass
import grp
import hashlib
import os
import pwd
import secrets
from pathlib import Path

from .auth import valid_password_text
from .fsutil import atomic_write_text


def main() -> int:
    path = Path(os.environ.get("GATEBSD_AUTH_HASH_FILE", "/var/db/gatebsd/auth.hash"))
    first = getpass.getpass("New gatebsd password: ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        raise SystemExit("Passwords do not match")
    if not valid_password_text(first, minimum=8, maximum=1024):
        raise SystemExit("Password must be 8-1024 characters and contain no NUL or newlines")

    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", first.encode("utf-8"), salt.encode("ascii"), 200_000
    ).hex()
    uid = gid = None
    try:
        uid = pwd.getpwnam("gatebsd").pw_uid
        gid = grp.getgrnam("gatebsd").gr_gid
    except KeyError:
        pass
    atomic_write_text(
        path,
        f"{salt}:{digest}\n",
        mode=0o640,
        preserve_metadata=False,
        uid=uid,
        gid=gid,
    )
    print(f"Password hash written to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
