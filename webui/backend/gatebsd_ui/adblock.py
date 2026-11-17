"""DNS-level advertising and tracker blocking for Unbound."""
from __future__ import annotations

import json
import os
import re
import stat
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from . import paths
from .command import run
from .fsutil import atomic_write_text, exclusive_lock, read_regular_text
from .resolver import display_host, normalize_domain, normalize_host

EXTRA_FILE = Path(os.environ.get("GATEBSD_ADBLOCK_EXTRA", "/usr/local/etc/gatebsd/adblock-extra"))
BLOCKLIST = Path(os.environ.get("GATEBSD_ADBLOCK_CONF", "/usr/local/etc/unbound/adblock.conf"))
UPDATE_SCRIPT = Path(os.environ.get("GATEBSD_ADBLOCK_UPDATE", "/usr/local/sbin/gatebsd-adblock-update.sh"))
LOG_FILE = Path(os.environ.get("GATEBSD_ADBLOCK_LOG", "/var/log/gatebsd-adblock.log"))
RUN_STATUS = Path(
    os.environ.get("GATEBSD_ADBLOCK_STATUS", "/var/db/gatebsd-system/adblock-status.json")
)
_INCLUDE_RE = re.compile(r'^\s*include:\s*["\']?([^"\'\s]+)["\']?\s*$', re.MULTILINE)
_TOTAL_RE = re.compile(r"^# Total:\s*(\d+)\s+domains\s*$", re.MULTILINE)
_GENERATED_RE = re.compile(r"^# Generated:\s*(.+?)\s*$", re.MULTILINE)
_VERDICT_RE = re.compile(r"^# Verdict:\s*(\S+)\s*$", re.MULTILINE)
_SOURCES_USED_RE = re.compile(r"^# Sources used:\s*(\d+)\s*$", re.MULTILINE)
_INTERFACE_RE = re.compile(r"^\s*interface:\s+([0-9.]+)\s*$", re.MULTILINE)

# Counters worth showing. unbound reports many; these are the ones that say
# something about whether the resolver is doing its job.
_STAT_KEYS = {
    "total.num.queries": "queries",
    "total.num.cachehits": "cache_hits",
    "total.num.queries_ip_ratelimited": "ratelimited",
    "num.answer.rcode.NXDOMAIN": "nxdomain",
    "num.answer.rcode.SERVFAIL": "servfail",
    "total.recursion.time.avg": "recursion_avg",
}


def resolver_stats() -> dict[str, Any]:
    """Live counters from unbound, or an empty answer with the reason why.

    Returns no invented numbers: a caller that cannot tell "zero" from "not
    measured" reports the first as if it were a finding.
    """
    result = run(
        ["unbound-control", "-c", str(paths.UNBOUND_CONF), "stats_noreset"],
        timeout=10,
    )
    if not result.ok:
        return {"available": False, "reason": (result.stderr or result.stdout).strip()[:200]}

    values: dict[str, float] = {}
    for line in result.stdout.splitlines():
        key, separator, raw = line.partition("=")
        if not separator or key.strip() not in _STAT_KEYS:
            continue
        try:
            values[_STAT_KEYS[key.strip()]] = float(raw.strip())
        except ValueError:
            continue
    if not values:
        return {"available": False, "reason": "unbound reported no counters"}

    queries = values.get("queries", 0.0)
    payload: dict[str, Any] = {"available": True}
    for name, value in values.items():
        payload[name] = int(value) if name != "recursion_avg" else round(value, 3)
    payload["cache_hit_percent"] = (
        round(values.get("cache_hits", 0.0) * 100.0 / queries, 1) if queries else 0.0
    )
    # extended-statistics is what produces the rcode breakdown. Its absence is
    # reported rather than papered over with zeroes.
    payload["extended"] = "nxdomain" in values
    return payload


def _read_text(path: Path, limit: int = 8 * 1024 * 1024) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(path, flags)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            return ""
        payload = bytearray()
        while len(payload) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > limit:
            return ""
        return bytes(payload).decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        return ""
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _read_head(path: Path, limit: int = 65536) -> str:
    """Read the first *limit* bytes, whatever the file's size.

    The blocklist carries everything the panel needs in a header a few hundred
    bytes long, and the body is megabytes of local-zone lines nobody parses.
    _read_text refuses a file larger than its cap and returns "" -- which the
    caller cannot tell apart from an empty blocklist, so the panel reported
    "filtering not working, 0 domains" on a resolver that was in fact blocking
    255881 names. Reading the head is both correct and cheap.
    """
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return ""
        return os.read(fd, limit).decode("utf-8", "replace")
    except OSError:
        return ""
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _count_zones(path: Path, limit: int = 256 * 1024 * 1024) -> int:
    """Count local-zone lines without holding the file in memory.

    Only used when the header is missing -- a blocklist written by an older
    version, or one truncated mid-write.
    """
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    count = 0
    tail = b""
    read = 0
    try:
        fd = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return 0
        while read < limit:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            read += len(chunk)
            buffer = tail + chunk
            count += buffer.count(b"local-zone:")
            tail = buffer[-16:]
        return count
    except OSError:
        return 0
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def status() -> dict[str, Any]:
    main_conf = _read_text(paths.UNBOUND_CONF, 2 * 1024 * 1024)
    block_text = _read_head(BLOCKLIST)
    includes = {Path(item).as_posix() for item in _INCLUDE_RE.findall(main_conf)}
    configured = BLOCKLIST.as_posix() in includes

    count = 0
    generated = ""
    verdict = ""
    sources_used = 0
    if block_text:
        total = _TOTAL_RE.search(block_text)
        if total:
            count = int(total.group(1))
        else:
            count = _count_zones(BLOCKLIST)
        generated_match = _GENERATED_RE.search(block_text)
        if generated_match:
            generated = generated_match.group(1)
        verdict_match = _VERDICT_RE.search(block_text)
        if verdict_match:
            verdict = verdict_match.group(1)
        elif "always_nxdomain" in block_text:
            # Written before the verdict was recorded in the header.
            verdict = "always_nxdomain"
        sources_match = _SOURCES_USED_RE.search(block_text)
        if sources_match:
            sources_used = int(sources_match.group(1))

    service = run(["service", "unbound", "onestatus"], timeout=5)
    anchor_writable = trust_anchor_writable()
    check = run(["unbound-checkconf", str(paths.UNBOUND_CONF)], timeout=10) if main_conf else None
    last_run = run_status()
    return {
        "enabled": configured and count > 0,
        "last_run": last_run,
        "last_success_at": last_run.get("last_success_at"),
        "configured": configured,
        "domains": count,
        "generated": generated,
        "verdict": verdict,
        "sources_used": sources_used,
        "stats": resolver_stats(),
        "blocklist": str(BLOCKLIST),
        "unbound_config": str(paths.UNBOUND_CONF),
        "unbound_running": service.ok,
        "trust_anchor_writable": anchor_writable,
        "config_valid": bool(check and check.ok),
        "update_available": UPDATE_SCRIPT.is_file() and os.access(UPDATE_SCRIPT, os.X_OK),
        "last_error": "" if check is None or check.ok else (check.stderr or check.stdout).strip(),
    }


def trust_anchor_writable(directory: Path | None = None,
                          account: str = "unbound") -> bool | None:
    """Can the resolver's own account maintain its DNSSEC trust anchor?

    It cannot, on the production router, and nothing said so. The port's rc
    script runs `unbound-anchor` as `unbound` inside every start; the anchor is
    written through a temporary file created *beside* it; and
    /usr/local/etc/unbound is root:wheel 0755. Measured 2026-08-07:

        fatal error: could not open autotrust file for writing,
        /usr/local/etc/unbound/root.key.21101-0-3053dc71: Permission denied

    rc.subr does not call that a failure, so the daemon starts and every reader
    above it says the service is fine. It is -- and the anchor is still not
    being maintained, which is a different sentence, and the box had nowhere to
    put it. Reporting it on a restart alone was not enough: the panel restarts
    services through /api/services/manage, so the operator would never have seen
    it. A condition of the box belongs where the box is described, the same
    place `config_valid` and the blocklist counts already live.

    Derived from ownership rather than by attempting a write: this runs on every
    status poll, and a status read that has side effects is not a read. `None`
    means the question could not be answered -- no such account, unreadable
    directory -- which is not the same as "no", and must not be drawn as one.
    """
    directory = directory if directory is not None else paths.UNBOUND_CONF.parent
    try:
        import pwd
        import grp
        entry = pwd.getpwnam(account)
        info = os.stat(directory)
    except (ImportError, KeyError, OSError):
        return None

    if info.st_mode & stat.S_IWOTH:
        return True
    if info.st_uid == entry.pw_uid:
        return bool(info.st_mode & stat.S_IWUSR)
    try:
        groups = {entry.pw_gid} | {
            g.gr_gid for g in grp.getgrall() if account in g.gr_mem
        }
    except OSError:  # pragma: no cover - depends on the host's group backend
        groups = {entry.pw_gid}
    if info.st_gid in groups:
        return bool(info.st_mode & stat.S_IWGRP)
    return False


def _moment(value: Any) -> str:
    try:
        return datetime.fromtimestamp(int(value)).strftime("%d.%m.%Y %H:%M")
    except (TypeError, ValueError, OSError, OverflowError):
        return "—"


def _run_warnings(state: dict[str, Any]) -> list[dict[str, str]]:
    """The line the customer reads, decided here rather than in JS.

    The backend owns the diagnosis so the panel renders this list without
    deriving a second verdict from the same facts.
    """
    if not state.get("available"):
        # Deliberately silent. A device whose updater has not reported since
        # this version arrived is not an incident -- cron rebuilds every six
        # hours -- and an alarm on every fresh install is how a warning card
        # becomes something nobody reads.
        return []

    used = state.get("sources_used")
    configured = state.get("sources_configured") or 0
    missing = used is not None and configured and used < configured
    when = _moment(state.get("checked_at"))

    if state.get("outcome") == "failed":
        if missing:
            detail = (
                f"{used} of {configured} sources available. Resolver is using the "
                "previous list — new names will not be added until sources recover."
            )
        else:
            detail = f"{state.get('reason') or 'reason not recorded'}. Resolver is using the previous list."
        return [{
            "time": when,
            "icon": "shield-off",
            "level": "error",
            "msg": f"Blocklist not updated: {detail}",
        }]

    if missing:
        # Only reachable on a device that had nothing published yet: there the
        # updater takes what it can get, because a partial list beats no
        # filtering at all. Said out loud all the same.
        return [{
            "time": when,
            "icon": "shield-alert",
            "level": "warn",
            "msg": (
                f"Blocklist built without some sources: {used} of {configured}. "
                "Some ad domains are missing."
            ),
        }]
    return []


def run_status() -> dict[str, Any]:
    """What the last blocklist rebuild did, from the record the updater leaves.

    The published blocklist cannot answer this. A run that refused to publish
    leaves the previous file in place, header and all, so reading the list
    alone reports six sources and a healthy date over a rebuild that failed.
    """
    state: dict[str, Any] = {
        "available": False,
        "error": None,
        "outcome": "",
        "checked_at": None,
        "last_success_at": None,
        "sources": [],
        "sources_configured": 0,
        "sources_used": None,
        "sources_skipped": [],
        "domains": None,
        "reason": "",
    }
    try:
        text, _metadata = read_regular_text(RUN_STATUS, max_size=64 * 1024, errors="strict")
    except FileNotFoundError:
        state["error"] = "blocklist updater has not reported yet"
        state["warnings"] = _run_warnings(state)
        return state
    except (OSError, UnicodeError, ValueError) as exc:
        state["error"] = f"state file unreadable: {exc}"
        state["warnings"] = _run_warnings(state)
        return state

    try:
        data = json.loads(text) if text.strip() else None
    except json.JSONDecodeError as exc:
        state["error"] = f"state file corrupted: {exc}"
        state["warnings"] = _run_warnings(state)
        return state
    if not isinstance(data, dict):
        state["error"] = "state file is not a JSON object"
        state["warnings"] = _run_warnings(state)
        return state

    def _int_or_none(value: Any) -> int | None:
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    state.update({
        "available": True,
        "outcome": str(data.get("outcome") or ""),
        "checked_at": _int_or_none(data.get("checked_at")),
        "last_success_at": _int_or_none(data.get("last_success_at")),
        "sources_configured": _int_or_none(data.get("sources_configured")) or 0,
        "sources_used": _int_or_none(data.get("sources_used")),
        "sources_skipped": str(data.get("sources_skipped") or "").split(),
        "domains": _int_or_none(data.get("domains")),
        "reason": str(data.get("reason") or ""),
    })
    if isinstance(data.get("sources"), list):
        state["sources"] = [
            {
                "url": str(source.get("url") or ""),
                "downloaded": _int_or_none(source.get("downloaded")) or 0,
                "parsed": _int_or_none(source.get("parsed")) or 0,
                "status": str(source.get("status") or "unknown"),
                "reason": str(source.get("reason") or ""),
            }
            for source in data["sources"] if isinstance(source, dict)
        ]
    state["warnings"] = _run_warnings(state)
    return state


def _resolver_address() -> str:
    match = _INTERFACE_RE.search(_read_text(paths.UNBOUND_CONF, 2 * 1024 * 1024))
    if match and match.group(1) != "0.0.0.0":
        return match.group(1)
    return "127.0.0.1"


def _dns_answer(name: str) -> dict[str, Any]:
    result = run(["drill", name, "A", f"@{_resolver_address()}"], timeout=5)
    answer: dict[str, Any] = {
        "name": name,
        "display_name": display_host(name),
        "ok": False,
        "rcode": "",
        "addresses": [],
        "error": "",
    }
    if not result.ok:
        answer["error"] = (result.stderr or result.stdout or result.error or "drill failed").strip()[:300]
        return answer
    match = re.search(r"\brcode:\s*([A-Z]+)", result.stdout)
    answer["rcode"] = match.group(1) if match else ""
    answer["addresses"] = list(dict.fromkeys(
        address for address in re.findall(r"\sIN\s+A\s+([0-9.]+)", result.stdout)
    ))
    return answer


def dns_probe(blocked: object, control: object, verdict: object) -> tuple[int, dict[str, Any]]:
    blocked_name = normalize_host(blocked)
    control_name = normalize_host(control)
    if blocked_name is None or control_name is None or verdict not in {
        "always_null", "always_nxdomain", "always_refuse"
    }:
        return 400, {"error": "valid blocked/control domains and blocklist verdict required"}
    blocked_answer = _dns_answer(blocked_name)
    control_answer = _dns_answer(control_name)
    if verdict == "always_null":
        blocked_answer["ok"] = (
            blocked_answer["rcode"] == "NOERROR"
            and bool(blocked_answer["addresses"])
            and set(blocked_answer["addresses"]) == {"0.0.0.0"}
        )
    elif verdict == "always_nxdomain":
        blocked_answer["ok"] = blocked_answer["rcode"] == "NXDOMAIN"
    else:
        blocked_answer["ok"] = blocked_answer["rcode"] == "REFUSED"
    control_answer["ok"] = (
        control_answer["rcode"] == "NOERROR"
        and any(address != "0.0.0.0" for address in control_answer["addresses"])
    )
    return 200, {
        "ok": blocked_answer["ok"] and control_answer["ok"],
        "checked_at": int(time.time()),
        "verdict": verdict,
        "blocked": blocked_answer,
        "control": control_answer,
    }


def _rule_domain(value: object) -> str:
    normalized = normalize_domain(value)
    if normalized is None:
        raise ValueError("valid domain required")
    return normalized


def _parse_rule(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("@@||") and stripped.endswith("^"):
        return "allow", _rule_domain(stripped[4:-1])
    if stripped.startswith("||") and stripped.endswith("^"):
        return "block", _rule_domain(stripped[2:-1])
    parts = stripped.split()
    if len(parts) == 2 and parts[0] in {"0.0.0.0", "127.0.0.1"}:
        return "block", _rule_domain(parts[1])
    return None


def _rule_lines(text: str) -> list[tuple[str, str, str]]:
    result = []
    for line in text.splitlines():
        try:
            parsed = _parse_rule(line)
        except ValueError:
            parsed = None
        if parsed is not None:
            result.append((parsed[0], parsed[1], line))
    return result


def rules() -> dict[str, Any]:
    try:
        text, _metadata = read_regular_text(EXTRA_FILE, max_size=1024 * 1024, errors="strict")
    except FileNotFoundError:
        text = ""
    return {
        "config": str(EXTRA_FILE),
        "entries": [
            {"kind": kind, "value": value, "display_value": display_host(value)}
            for kind, value, _line in _rule_lines(text)
        ],
    }


def change_rule(value: object, *, kind: object, add: bool) -> tuple[int, dict[str, Any]]:
    try:
        normalized = _rule_domain(value)
        if kind not in {"allow", "block"}:
            raise ValueError("kind must be allow or block")
    except ValueError as exc:
        return 400, {"error": str(exc)}
    try:
        with exclusive_lock(EXTRA_FILE.with_suffix(EXTRA_FILE.suffix + ".lock")):
            try:
                text, _metadata = read_regular_text(EXTRA_FILE, max_size=1024 * 1024, errors="strict")
            except FileNotFoundError:
                text = ""
            current = _rule_lines(text)
            exists = any(value == normalized for _kind, value, _line in current)
            if add and any(kind == current_kind and value == normalized for current_kind, value, _line in current):
                return 200, {"ok": True, "changed": False, **rules()}
            if not add and not exists:
                return 200, {"ok": True, "changed": False, **rules()}
            kept = [line for line in text.splitlines() if not any(
                value == normalized for _kind, value, rule_line in current if rule_line == line
            )]
            if add:
                kept.append(f"@@||{normalized}^" if kind == "allow" else f"0.0.0.0 {normalized}")
            new_text = "\n".join(kept) + ("\n" if kept else "")
            atomic_write_text(EXTRA_FILE, new_text, mode=0o600, preserve_metadata=bool(text))
        return 200, {"ok": True, "changed": True, **rules()}
    except (OSError, UnicodeError) as exc:
        return 500, {"error": str(exc)}


def update() -> tuple[int, dict[str, Any]]:
    if not UPDATE_SCRIPT.is_file() or not os.access(UPDATE_SCRIPT, os.X_OK):
        return 500, {"error": f"adblock updater is not executable: {UPDATE_SCRIPT}"}
    result = run([str(UPDATE_SCRIPT)], timeout=240)
    payload = status()
    payload["ok"] = result.ok and payload["enabled"] and payload["config_valid"]
    payload["output"] = (result.stdout + result.stderr).strip()
    if payload["ok"]:
        return 200, payload
    return 500, {"error": payload["output"] or payload["last_error"] or "adblock update failed", **payload}
