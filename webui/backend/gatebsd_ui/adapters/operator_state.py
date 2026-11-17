"""What the backup operator told us, for the panel to show.

The SMS monitor writes /var/run/gatebsd/operator.json from cron; this reads it
and turns it into the one sentence a customer needs when the backup path is
down -- an air alert, an unpaid tariff, or an actual fault. Without this the
whole feature is a file nobody looks at.

Two rules run through everything below, both bought:

  * a file we could not read is never reported as a file that said nothing.
    `_safe_config_text` returns "" on any failure, and an empty string is
    indistinguishable from empty content -- that is precisely how the panel
    came to announce "filtering does not work, 0 domains" over a resolver that
    was blocking 255881 names. So this one reads the file itself and says
    which of the two happened;
  * a reading the monitor could not confirm is shown as unconfirmed. The
    monitor marks it `stale` and leaves `timestamp` on the last real reading,
    so the panel has to carry that through rather than present a week-old
    verdict as current.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .. import paths, sms
from ..fsutil import read_regular_text

LIMIT = 256 * 1024


def _read_json(path) -> tuple[dict | None, str | None]:
    """Return (data, error). Exactly one of them is None."""
    try:
        text, _metadata = read_regular_text(path, max_size=LIMIT, errors="strict")
    except FileNotFoundError:
        return None, "SMS monitor has not run yet"
    except (OSError, UnicodeError, ValueError) as exc:
        return None, f"state file unreadable: {exc}"
    try:
        data = json.loads(text) if text.strip() else None
    except json.JSONDecodeError as exc:
        return None, f"state file corrupted: {exc}"
    if not isinstance(data, dict):
        return None, "state file is not a JSON object"
    return data, None


def _watchdog_flags() -> dict[str, Any]:
    """Read backup and primary connectivity flags once from the watchdog state file.

    Two writers on one file is the failure this product keeps repeating, so
    the monitor was deliberately given a separate one. Reading both here is
    the reunion, and it belongs on the read side.
    """
    data, _error = _read_json(paths.FAILOVER_STATE)
    if not data:
        return {
            "backup_ok": False,
            "backup_ru_ok": False,
            "backup_fitted": True,
            "primary_ok": None,
            "primary_ru_ok": False,
        }
    primary_ok = data.get("primary_ok")
    return {
        "backup_ok": bool(data.get("backup_ok")),
        "backup_ru_ok": data.get("backup_ru_ok") is True,
        "backup_fitted": data.get("backup_fitted") is not False,
        "primary_ok": primary_ok if isinstance(primary_ok, bool) else None,
        "primary_ru_ok": data.get("primary_ru_ok") is True,
    }


def _backup_ok() -> bool:
    """The watchdog's own verdict, read from the watchdog's own file."""
    return bool(_watchdog_flags()["backup_ok"])


def _moment(value: Any) -> str:
    try:
        return datetime.fromtimestamp(int(value)).strftime("%d.%m.%Y %H:%M")
    except (TypeError, ValueError, OSError, OverflowError):
        return "—"


def _whitelist_warnings(state: dict[str, Any]) -> list[dict[str, str]]:
    """Surface RU domestic white-list mode warnings without contradicting SAYS_UP/SAYS_DOWN."""
    from ..failover import failover_warnings

    normalized = {
        "primary_ok": state.get("primary_ok"),
        "primary_ru_ok": state.get("primary_ru_ok"),
        "backup_ok": bool(state.get("backup_ok")),
        "backup_ru_ok": state.get("backup_ru_ok"),
        "backup_fitted": state.get("backup_fitted"),
    }
    return [
        {"time": "—", "icon": "shield-alert", "level": "warn", "msg": msg}
        for msg in failover_warnings(normalized)
    ]


def warnings(state: dict[str, Any]) -> list[dict[str, str]]:
    """The card the customer actually reads, decided here rather than in JS.

    There is no node on the machine that validates every push, so a rule
    written in app.js would ship without ever having been run -- the same
    shape as the tests that called `make` on a validator that had none. The
    panel renders this list and decides nothing.
    """
    if not state.get("available"):
        return [
            {
                "time": "—",
                "icon": "help-circle",
                "level": "warn",
                "msg": f"Backup carrier state unknown: {state.get('error') or 'no data'}",
            },
            *_whitelist_warnings(state),
        ]

    # Subscripted, not `.get`: a caller that forgot to measure the backup gets
    # a KeyError rather than a silent False, and False here is "backup unavailable".
    backup_ok = bool(state["backup_ok"])

    out: list[dict[str, str]] = []
    if state.get("stale"):
        # Said plainly, not implied by a date. The panel has already been
        # caught presenting a value it could not verify as a fact.
        out.append({
            "time": _moment(state.get("checked_at")),
            "icon": "wifi-off",
            "level": "warn",
            "msg": (
                f"Backup modem is unresponsive ({state.get('modem_error') or 'no link'}). "
                f"Showing last confirmed reading from {_moment(state.get('timestamp'))} "
                "— it may be stale."
            ),
        })
    if state.get("alert_active") and state.get("alert_kinds"):
        kinds = ", ".join(state["alert_kinds"])
        # Two different messages, because the alert and the outage are two
        # different facts. An alert is what the operator announced; the outage
        # is what the watchdog measured.
        if backup_ok:
            out.append({
                "time": "—",
                "icon": "siren",
                "level": "info",
                "msg": (
                    f"{kinds} active — carrier may throttle the backup link. "
                    "Backup is working currently."
                ),
            })
        else:
            out.append({
                "time": "—",
                "icon": "siren",
                "level": "warn",
                "msg": (
                    f"{kinds} active — carrier is throttling traffic. "
                    "Backup unavailable not due to hardware fault."
                ),
            })
    if state.get("alert_unknown"):
        out.append({
            "time": "—",
            "icon": "help-circle",
            "level": "warn",
            "msg": (
                "Alert was raised, all-clear not received — state unknown; "
                "cancellation SMS may have been missed."
            ),
        })
    if state.get("paid") is False:
        charge = f", next billing date {state['next_charge']}" if state.get("next_charge") else ""
        out.append({
            "time": "—",
            "icon": "credit-card",
            "level": "error",
            "msg": (
                f"Backup SIM plan is unpaid{charge} — human action required. "
                "Not a link failure."
            ),
        })
    if state.get("unknown_count"):
        out.append({
            "time": "—",
            "icon": "mail-question",
            "level": "warn",
            "msg": (
                f"Unparsed carrier messages ({state['unknown_count']}) — "
                "SMS template may have changed."
            ),
        })
    out.extend(_whitelist_warnings(state))
    return out


def operator() -> dict[str, Any]:
    # Read once, for both sentences. Two reads is two answers if the watchdog
    # rewrites the file between them, and the panel would again be showing a
    # diagnosis and a warning that disagree.
    flags = _watchdog_flags()
    backup_ok = bool(flags["backup_ok"])

    data, error = _read_json(paths.OPERATOR_STATE)
    if data is None:
        state = {"available": False, "error": error, "stale": True, **flags}
        state["warnings"] = warnings(state)
        return state

    alert_kinds = [str(k) for k in data.get("alert_kinds") or []]
    paid = data.get("operator_paid")
    seen = str(data.get("operator_seen") or "")
    state = {
        "available": True,
        "error": None,
        # Freshness is stated by the monitor, never inferred here from a date.
        "stale": bool(data.get("stale")),
        "timestamp": data.get("timestamp"),
        "checked_at": data.get("checked_at"),
        "modem_error": data.get("modem_error"),
        "alert_active": bool(data.get("alert_active")),
        "alert_unknown": bool(data.get("alert_unknown")),
        "alert_kinds": alert_kinds,
        "alert_text": data.get("alert_text") or "",
        "paid": paid if isinstance(paid, bool) else None,
        "state_text": data.get("operator_state_text") or "",
        "next_charge": data.get("next_charge"),
        # The stream never states a positive balance, so the panel never shows
        # one -- see OperatorState. Saying "0.00" over a funded SIM is a lie
        # the customer would act on.
        "unknown_count": int(data.get("unknown_count") or 0),
        # Published, not just used: the panel makes two statements about the
        # backup and this is the measurement both of them come from, so one
        # /api/overview response is enough to catch them disagreeing.
        **flags,
        "diagnosis": sms.explain(
            backup_ok=backup_ok,
            alert_active=bool(data.get("alert_active")),
            alert_kinds=alert_kinds,
            alert_unknown=bool(data.get("alert_unknown")),
            paid=paid if isinstance(paid, bool) else None,
            paid_since=seen[:10] or None,
        ),
    }
    state["warnings"] = warnings(state)
    return state
