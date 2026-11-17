"""Password verification helpers that work across supported Python versions.

Python 3.13 removed :mod:`crypt`.  GateBSD therefore uses the module when it
exists and otherwise calls the platform crypt(3) implementation through
``ctypes`` with an explicit ABI.  The public helpers deliberately return only
a boolean so authentication failures never disclose account details.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import grp
import hmac
import os
import pwd
import re
import threading
from pathlib import Path

from .fsutil import read_regular_text

_USERNAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,31}")


def valid_username(value: object) -> bool:
    return isinstance(value, str) and _USERNAME_RE.fullmatch(value) is not None


_GROUP_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,31}")


def authorized_system_user(username: object, group_name: str | None = None) -> bool:
    """Return whether a local account may administer GateBSD.

    Root is always eligible. Other accounts must have the configured primary
    or supplementary administrative group, which defaults to FreeBSD wheel.
    """
    if not valid_username(username):
        return False
    group = (group_name or os.environ.get("GATEBSD_ADMIN_GROUP", "wheel")).strip()
    if _GROUP_RE.fullmatch(group) is None:
        return False
    try:
        account = pwd.getpwnam(username)
        if account.pw_uid == 0:
            return True
        admin = grp.getgrnam(group)
    except (KeyError, OSError):
        return False
    return account.pw_gid == admin.gr_gid or username in admin.gr_mem

def valid_password_text(value: object, *, minimum: int = 1, maximum: int = 4096) -> bool:
    return (
        isinstance(value, str)
        and minimum <= len(value) <= maximum
        and "\x00" not in value
        and "\n" not in value
        and "\r" not in value
    )
_CRYPT_LOCK = threading.Lock()

try:  # Python <= 3.12
    import crypt as _pycrypt
except ImportError:  # Python >= 3.13
    _pycrypt = None

_CRYPT_LIBRARY: ctypes.CDLL | None = None
_CRYPT_FUNCTION = None
if _pycrypt is None:
    candidates: list[str | None] = []
    for name in (ctypes.util.find_library("crypt"), "libcrypt.so.5", "libcrypt.so"):
        if name and name not in candidates:
            candidates.append(name)
    # On some BSD systems crypt(3) is exported by the process C library.
    candidates.append(None)
    for name in candidates:
        try:
            library = ctypes.CDLL(name)
            function = library.crypt
            function.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            function.restype = ctypes.c_char_p
        except (OSError, AttributeError):
            continue
        _CRYPT_LIBRARY = library  # keep the shared object alive
        _CRYPT_FUNCTION = function
        break


def verify_crypt(password: object, stored_hash: object) -> bool:
    """Return whether *password* matches a crypt(3) hash.

    Invalid input, unavailable platform support, and crypt errors are ordinary
    authentication failures rather than exceptions propagated to the API.
    """
    if not valid_password_text(password, maximum=4096) or not isinstance(stored_hash, str):
        return False
    if not stored_hash or "\x00" in stored_hash:
        return False
    if len(stored_hash) > 4096:
        return False

    try:
        with _CRYPT_LOCK:
            if _pycrypt is not None:
                calculated = _pycrypt.crypt(password, stored_hash)
            elif _CRYPT_FUNCTION is not None:
                raw = _CRYPT_FUNCTION(
                    password.encode("utf-8"),
                    stored_hash.encode("utf-8"),
                )
                calculated = raw.decode("utf-8") if raw is not None else None
            else:
                return False
    except (OSError, TypeError, ValueError, UnicodeError):
        return False

    return isinstance(calculated, str) and hmac.compare_digest(calculated, stored_hash)


def verify_system_password(
    username: object,
    password: object,
    passwd_path: Path = Path("/etc/master.passwd"),
) -> bool:
    """Verify a FreeBSD local account against ``master.passwd`` safely."""
    if not valid_username(username):
        return False
    if not valid_password_text(password, maximum=4096):
        return False

    try:
        text, _metadata = read_regular_text(Path(passwd_path), max_size=8 * 1024 * 1024, errors="strict")
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2 or parts[0] != username:
                continue
            stored_hash = parts[1]
            if not stored_hash or stored_hash.startswith(("*", "!")):
                return False
            return verify_crypt(password, stored_hash)
    except (OSError, UnicodeError):
        return False
    return False
