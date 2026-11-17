"""PF firewall operations with validation, atomic publication, and rollback."""
from __future__ import annotations

import json
import os
from contextlib import nullcontext
import re
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

from .. import backup
from ..adapters import PF_CONF
from ..adapters.helpers import LAN_IF
from ..command import run
from ..fsutil import atomic_write_text, exclusive_lock, read_regular_text

_MAX_PF_CONF = 2 * 1024 * 1024

# Pending-commit state for the confirm-or-revert workflow. Lives beside the
# other GateBSD runtime state so the every-minute recovery cron can find it.
PF_PENDING_PATH = Path(
    os.environ.get("GATEBSD_PF_PENDING", "/var/db/gatebsd-system/pf-pending-commit.json")
)
# How long an unconfirmed ruleset may stay live before it is reverted.
PF_CONFIRM_TIMEOUT = 120


def _lan_interface() -> str:
    return LAN_IF


def check_management_access(conf: str) -> tuple[bool, str]:
    """Whether a candidate ruleset still admits management traffic from the LAN.

    A syntactically valid ruleset can still be a total lockout: drop the rule
    that permits the LAN to reach the router itself and SSH, the web UI and DNS
    all stop answering, with recovery requiring physical console access. `pfctl
    -nf` cannot detect that, because nothing is wrong with the syntax.

    This is a deliberately conservative textual check against the source rather
    than the expanded ruleset: expanding requires loading into the kernel, and a
    heuristic that occasionally asks for an explicit override is much cheaper
    than a site visit. ``allow_lockout`` on the API lets an operator proceed.
    """
    lan = _lan_interface()
    # Macro assignments let the ruleset refer to the LAN by name.
    macros: dict[str, str] = {}
    for line in conf.splitlines():
        stripped = line.strip()
        match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"?([^"#]*)"?\s*(?:#.*)?', stripped)
        if match:
            macros[match.group(1)] = match.group(2).strip()

    lan_tokens = {lan}
    for name, value in macros.items():
        if value == lan:
            lan_tokens.add(f"${name}")
            lan_tokens.add(f"$({name})")
            lan_tokens.add("${" + name + "}")

    # A ruleset with no explicit block has a default-pass policy, so management
    # access cannot be lost. Note this is separately undesirable, but it is not
    # a lockout and is reported by the caller as a warning.
    has_block = False
    for line in conf.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if re.match(r"^block\b", stripped):
            has_block = True
            break
    if not has_block:
        return True, ""

    for line in conf.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped.startswith("pass"):
            continue
        if not re.search(r"\bin\b", stripped):
            continue
        if not any(token in stripped for token in lan_tokens):
            continue
        # The rule must be able to terminate at the router itself: either
        # explicitly "to (lan_if)"/"to lan_if", or "to any", or with no
        # destination restriction at all.
        if re.search(r"\bto\s+\(", stripped) or re.search(r"\bto\s+any\b", stripped):
            return True, ""
        if any(f"to {token}" in stripped for token in lan_tokens):
            return True, ""
        if not re.search(r"\bto\b", stripped):
            return True, ""

    return False, (
        f"no rule permits inbound traffic from the LAN ({lan}) to the router "
        "itself, so this ruleset would lock out SSH and the web UI"
    )


def _candidate_file(content: str, directory: Path) -> tuple[int, str]:
    fd, name = tempfile.mkstemp(dir=directory, prefix=".gatebsd-pf.", suffix=".conf")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            fd = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        return -1, name
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            Path(name).unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _remove_temp(name: str | None) -> None:
    if not name:
        return
    try:
        Path(name).unlink(missing_ok=True)
    except OSError:
        pass


def pf_reload() -> tuple[int, dict[str, Any]]:
    lock_path = PF_CONF.with_suffix(PF_CONF.suffix + ".gatebsd.lock")
    candidate: str | None = None
    try:
        with exclusive_lock(lock_path):
            content, _metadata = read_regular_text(PF_CONF, max_size=_MAX_PF_CONF, errors="strict")
            _fd, candidate = _candidate_file(content, PF_CONF.parent)
            checked = run(["pfctl", "-nf", candidate], timeout=10)
            if not checked.ok:
                return 400, {"error": "pf.conf syntax error", "detail": checked.stderr or checked.stdout}
            applied = run(["pfctl", "-f", candidate], timeout=15)
            return (200 if applied.ok else 500), {
                "ok": applied.ok,
                "detail": applied.stderr or applied.stdout or applied.error or "",
            }
    except (OSError, UnicodeError) as exc:
        return 500, {"error": f"failed to reload pf.conf: {exc}"}
    finally:
        _remove_temp(candidate)


def pf_get_conf() -> tuple[int, dict[str, Any]]:
    try:
        content, _metadata = read_regular_text(PF_CONF, max_size=_MAX_PF_CONF, errors="strict")
        return 200, {"conf": content, "path": str(PF_CONF)}
    except FileNotFoundError:
        return 404, {"error": "pf.conf not found"}
    except (OSError, UnicodeError) as exc:
        return 500, {"error": f"failed to read pf.conf: {exc}"}


def _write_pending(previous: str, reason: str) -> None:
    """Record the ruleset to restore if the new one is never confirmed."""
    PF_PENDING_PATH.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        PF_PENDING_PATH,
        json.dumps(
            {
                "deadline": int(time.time()) + PF_CONFIRM_TIMEOUT,
                "reason": reason,
                "previous": previous,
            },
            ensure_ascii=False,
        )
        + "\n",
        mode=0o600,
        preserve_metadata=PF_PENDING_PATH.exists(),
    )


def _clear_pending() -> None:
    try:
        PF_PENDING_PATH.unlink(missing_ok=True)
    except OSError:
        pass


def pf_pending_commit() -> tuple[int, dict[str, Any]]:
    """Report whether a ruleset is awaiting confirmation."""
    try:
        text, _metadata = read_regular_text(PF_PENDING_PATH, max_size=_MAX_PF_CONF * 2, errors="strict")
        record = json.loads(text)
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return 200, {"pending": False}
    deadline = record.get("deadline")
    if not isinstance(deadline, int):
        return 200, {"pending": False}
    return 200, {
        "pending": True,
        "deadline": deadline,
        "seconds_remaining": max(0, deadline - int(time.time())),
        "reason": record.get("reason", ""),
    }


def pf_confirm_conf() -> tuple[int, dict[str, Any]]:
    """Confirm the live ruleset, cancelling the pending automatic revert.

    Reaching this endpoint is itself the proof that management access survived:
    the request had to traverse the ruleset under test.
    """
    lock_path = PF_CONF.with_suffix(PF_CONF.suffix + ".gatebsd.lock")
    try:
        with exclusive_lock(lock_path):
            if not PF_PENDING_PATH.exists():
                return 200, {"ok": True, "pending": False}
            _clear_pending()
            return 200, {"ok": True, "confirmed": True}
    except OSError as exc:
        return 500, {"error": f"failed to confirm pf.conf: {exc}"}


def pf_revert_expired_commit() -> tuple[bool, dict[str, Any]]:
    """Restore the previous ruleset if an unconfirmed change has expired.

    Called from the every-minute recovery job. This is the half of the
    confirm-commit workflow that actually protects against lockout: if the new
    ruleset blocked management access, the operator cannot reach the confirm
    endpoint, and this restores the previous ruleset without them.
    """
    lock_path = PF_CONF.with_suffix(PF_CONF.suffix + ".gatebsd.lock")
    candidate: str | None = None
    try:
        with exclusive_lock(lock_path):
            try:
                text, _metadata = read_regular_text(
                    PF_PENDING_PATH, max_size=_MAX_PF_CONF * 2, errors="strict"
                )
                record = json.loads(text)
            except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
                return False, {"pending": False}

            deadline = record.get("deadline")
            previous = record.get("previous")
            if not isinstance(deadline, int) or not isinstance(previous, str):
                _clear_pending()
                return False, {"pending": False, "error": "malformed pending record"}
            if int(time.time()) < deadline:
                return False, {"pending": True, "seconds_remaining": deadline - int(time.time())}

            _fd, candidate = _candidate_file(previous, PF_CONF.parent)
            applied = run(["pfctl", "-f", candidate], timeout=15)
            published = False
            if applied.ok:
                try:
                    metadata = PF_CONF.stat()
                    atomic_write_text(
                        PF_CONF,
                        previous,
                        mode=stat.S_IMODE(metadata.st_mode),
                        preserve_metadata=True,
                    )
                    published = True
                except OSError:
                    published = False
            _clear_pending()
            return True, {
                "reverted": applied.ok,
                "published": published,
                "reason": record.get("reason", ""),
                "detail": applied.stderr or applied.stdout or applied.error or "",
            }
    except OSError as exc:
        return False, {"error": f"failed to revert pf.conf: {exc}"}
    finally:
        _remove_temp(candidate)


def pf_set_conf(conf: object, *, allow_lockout: bool = False,
                require_confirmation: bool = True, lock_held: bool = False) -> tuple[int, dict[str, Any]]:
    """Validate, apply, and atomically persist PF configuration.

    The live ruleset is applied from a candidate file first.  Publication to
    ``/etc/pf.conf`` preserves ownership/mode.  If publication fails after a
    successful ``pfctl -f``, the original ruleset is immediately re-applied so
    runtime and disk cannot silently diverge.

    Two protections exist because ``pfctl -nf`` only checks syntax:

    * an anti-lockout assertion refuses a ruleset with no path from the LAN to
      the router itself, unless ``allow_lockout`` is set;
    * confirm-commit records the outgoing ruleset and reverts to it unless
      ``pf_confirm_conf`` is called within ``PF_CONFIRM_TIMEOUT``. Since the
      confirmation must traverse the new ruleset, a change that breaks
      management access cannot be confirmed and is undone automatically.
    """
    if not isinstance(conf, str):
        return 400, {"error": "conf must be a string"}
    try:
        encoded = conf.encode("utf-8", errors="strict")
    except UnicodeError:
        return 400, {"error": "conf is not valid UTF-8"}
    if not encoded or len(encoded) > _MAX_PF_CONF or "\x00" in conf:
        return 400, {"error": "conf must be 1 byte to 2 MiB and contain no NUL"}
    if not conf.endswith("\n"):
        conf += "\n"

    reachable, lockout_reason = check_management_access(conf)
    if not reachable and not allow_lockout:
        return 409, {
            "error": "refusing a ruleset that would lock out management access",
            "detail": lockout_reason,
            "hint": "resubmit with allow_lockout=true to override",
        }

    lock_path = PF_CONF.with_suffix(PF_CONF.suffix + ".gatebsd.lock")
    candidate: str | None = None
    original_candidate: str | None = None
    lock_context = nullcontext() if lock_held else exclusive_lock(lock_path)
    try:
        with lock_context:
            original, metadata = read_regular_text(PF_CONF, max_size=_MAX_PF_CONF, errors="strict")
            if conf == original:
                return 200, {"ok": True, "changed": False}

            _fd, candidate = _candidate_file(conf, PF_CONF.parent)
            syntax = run(["pfctl", "-nf", candidate], timeout=10)
            if not syntax.ok:
                return 400, {"error": "syntax error", "detail": syntax.stderr or syntax.stdout or syntax.error or ""}

            backup_meta = backup.backup_files([PF_CONF], reason="pf-set-conf")
            applied = run(["pfctl", "-f", candidate], timeout=15)
            if not applied.ok:
                return 500, {
                    "error": "pfctl apply failed; existing disk configuration was not changed",
                    "detail": applied.stderr or applied.stdout or applied.error or "",
                    "rolled_back": True,
                    "backup": backup_meta,
                }

            try:
                atomic_write_text(
                    PF_CONF,
                    conf,
                    mode=stat.S_IMODE(metadata.st_mode),
                    preserve_metadata=True,
                )
            except OSError as publish_error:
                _fd, original_candidate = _candidate_file(original, PF_CONF.parent)
                rollback = run(["pfctl", "-f", original_candidate], timeout=15)
                _clear_pending()
                return 500, {
                    "error": f"failed to publish pf.conf: {publish_error}",
                    "rolled_back": rollback.ok,
                    "rollback_detail": rollback.stderr or rollback.stdout or rollback.error or "",
                    "backup": backup_meta,
                }

            response: dict[str, Any] = {"ok": True, "changed": True, "backup": backup_meta}
            if not reachable:
                response["lockout_override"] = lockout_reason
            if require_confirmation:
                try:
                    _write_pending(original, "pf-set-conf")
                    response["confirmation_required"] = True
                    response["confirm_within_seconds"] = PF_CONFIRM_TIMEOUT
                    response["confirm_endpoint"] = "/api/pf/conf/confirm"
                except OSError as pending_error:
                    # Failing to arm the revert must not be silent: the operator
                    # would believe they had a safety net that does not exist.
                    response["confirmation_required"] = False
                    response["confirmation_error"] = str(pending_error)
            else:
                _clear_pending()
            return 200, response
    except (OSError, UnicodeError) as exc:
        return 500, {"error": f"failed to update pf.conf: {exc}"}
    finally:
        _remove_temp(candidate)
        _remove_temp(original_candidate)
