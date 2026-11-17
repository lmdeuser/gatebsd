"""Public TLS certificate status and guarded certificate renewal."""
from __future__ import annotations

import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .command import run
from .fsutil import read_regular_text

CERTIFICATE = Path(os.environ.get("GATEBSD_TLS_CERTIFICATE", "/usr/local/etc/ssl/letsencrypt/fullchain.pem"))
LOG_FILE = Path(os.environ.get("GATEBSD_TLS_LOG", "/var/log/gatebsd-ssl-renew.log"))
CRON_FILE = Path(os.environ.get("GATEBSD_TLS_CRON", "/usr/local/etc/cron.d/gatebsd-ssl-renew"))
RENEW_SCRIPT = Path(os.environ.get("GATEBSD_TLS_RENEW_SCRIPT", "/usr/local/sbin/gatebsd-renew-ssl"))


def _safe_output(value: object) -> str:
    text = str(value or "")
    return re.sub(r"(?i)(duckdns_token|token)=([^\s]+)", r"\1=***", text)[:2000]


def _log_time(line: str) -> int | None:
    try:
        return int(datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S").timestamp())
    except ValueError:
        return None


def _next_attempt(now: int) -> int | None:
    try:
        text, _metadata = read_regular_text(CRON_FILE, max_size=4096, errors="strict")
    except (OSError, UnicodeError, ValueError):
        return None
    match = re.search(r"(?m)^\s*(\d+)\s+(\d+)\s+\*\s+\*\s+\*\s+root\s+\S*gatebsd-renew-ssl\s*$", text)
    if not match:
        return None
    minute, hour = int(match.group(1)), int(match.group(2))
    current = datetime.fromtimestamp(now)
    candidate = current.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= current:
        candidate += timedelta(days=1)
    return int(candidate.timestamp())


def _renewal_history() -> tuple[int | None, dict[str, Any] | None]:
    last_success = None
    last_error = None
    try:
        text, _metadata = read_regular_text(LOG_FILE, max_size=64 * 1024, errors="strict")
    except (OSError, UnicodeError, ValueError):
        return None, None
    for line in text.splitlines():
        checked_at = _log_time(line)
        if checked_at is None:
            continue
        if "renewed and nginx reloaded" in line:
            last_success = checked_at
        if " ERROR: " in line:
            last_error = {
                "checked_at": checked_at,
                "message": _safe_output(line.split(" ERROR: ", 1)[1]),
            }
    return last_success, last_error


def status() -> dict[str, Any]:
    now = int(time.time())
    last_success, last_error = _renewal_history()
    payload: dict[str, Any] = {
        "available": False,
        "not_after": None,
        "days_remaining": None,
        "san": [],
        "last_success_at": last_success,
        "last_error": last_error,
        "next_attempt": _next_attempt(now),
    }
    result = run([
        "openssl", "x509", "-in", str(CERTIFICATE), "-noout", "-enddate", "-ext", "subjectAltName"
    ], timeout=10)
    if not result.ok:
        payload["error"] = _safe_output(result.stderr or result.stdout or result.error or "certificate is unreadable")
        return payload
    match = re.search(r"^notAfter=(.+)$", result.stdout, re.MULTILINE)
    if not match:
        payload["error"] = "certificate has no expiration date"
        return payload
    try:
        expires = datetime.strptime(match.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        payload["error"] = "certificate expiration date is invalid"
        return payload
    not_after = int(expires.timestamp())
    payload.update({
        "available": True,
        "not_after": not_after,
        "days_remaining": int((not_after - now) // 86400),
        "san": re.findall(r"DNS:([^,\s]+)", result.stdout),
    })
    return payload


def renew() -> tuple[int, dict[str, Any]]:
    if not RENEW_SCRIPT.is_file() or not os.access(RENEW_SCRIPT, os.X_OK):
        return 500, {"error": f"TLS renewal script is not executable: {RENEW_SCRIPT}"}
    result = run([str(RENEW_SCRIPT)], timeout=300)
    payload = status()
    output = _safe_output(result.stderr or result.stdout or result.error)
    payload["renewal"] = {
        "ok": result.ok,
        "output": output,
        "rolled_back": not result.ok and any(
            phrase in output.lower() for phrase in ("restored", "unchanged")
        ),
    }
    if result.ok:
        return 200, payload
    payload["error"] = output or "TLS renewal failed"
    return 500, payload
