"""Poll the backup dongle for SMS and publish what the operator told us.

Runs from cron as root. Everything it learns lands in its own state file:

    /var/run/gatebsd/operator.json

deliberately *not* in watchdog.json. The recurring failure in this product is
two writers on one file -- that is how adblock.conf was corrupted while unbound
carried on for eight days on the copy in its memory. The watchdog owns its
state; this owns its own; the panel and the watchdog read both.

There is no password on the modem. The lock is the Referer header: the goform
API answers with empty strings unless the request looks like it came from the
device's own page. Reading is safe; nothing here deletes a message, because the
device ships to a customer who will accumulate years of them (sec. 0.4).
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from . import sms
from .fsutil import atomic_write_text
from .paths import OPERATOR_STATE

MODEM = os.environ.get("GATEBSD_MODEM_HOST", "192.168.0.1")
TIMEOUT = float(os.environ.get("GATEBSD_MODEM_TIMEOUT", "10"))
COUNT = int(os.environ.get("GATEBSD_SMS_COUNT", "40"))
STATE_FILE = OPERATOR_STATE
# 2: the SMSC stamp is read with the offset it carries, so there is no
# estimated `modem_offset` any more, and freshness is stated (`stale`,
# `checked_at`) instead of being inferred from `timestamp`.
SCHEMA = 2

_QUERY = (
    "isTest=false&cmd=sms_data_total&page=0&data_per_page={count}"
    "&mem_store=1&tags=10&order_by=order+by+id+desc"
)


def _get(query: str) -> dict:
    url = f"http://{MODEM}/goform/goform_get_cmd_process?{query}"
    request = urllib.request.Request(url, headers={"Referer": f"http://{MODEM}/index.html"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8", "replace") or "{}")


def _parse_stamp(raw: str) -> datetime | None:
    """The stamp is `26,08,02,17,44,25,+12` -- the fields, then a UTC offset.

    The trailing field is quarter-hours, so `+12` is +03:00, and it belongs to
    the SMSC timestamp carried inside the message rather than to any clock in
    the dongle. That makes it exact: checked 2 August, `17:44:25 +03` against
    the router's own `20:44:20 +05` is one hour of real age. The earlier
    reading of this field as "the modem's idea of the timezone" is what made a
    reconciliation look necessary at all -- the message already says when it
    happened, in a frame it names.

    Without the field a message cannot be placed in time at all, so we return
    None and count it rather than assume a zone. An age computed in an invented
    frame is exactly how an alert would stay "active" for good.
    """
    parts = [p for p in raw.replace(",", " ").split() if p]
    if len(parts) < 7:
        return None
    try:
        year, month, day, hour, minute, second = (int(p) for p in parts[:6])
        quarters = int(parts[6])
    except ValueError:
        return None
    if abs(quarters) > 56:  # ±14:00, the widest offset any zone keeps
        return None
    try:
        return datetime(
            2000 + year, month, day, hour, minute, second,
            tzinfo=timezone(timedelta(minutes=15 * quarters)),
        )
    except ValueError:
        return None


def fetch_messages() -> tuple[list[sms.Message], int]:
    """Return the messages we could place in time, and how many we could not."""
    payload = _get(_QUERY.format(count=COUNT))
    messages = []
    unplaceable = 0
    for entry in payload.get("messages", []):
        stamp = _parse_stamp(entry.get("date", ""))
        if stamp is None:
            unplaceable += 1
            continue
        try:
            identifier = int(entry.get("id", "0"))
        except ValueError:
            unplaceable += 1
            continue
        messages.append(
            sms.Message(
                id=identifier,
                sender=entry.get("number", "?"),
                received=stamp,
                text=sms.decode_body(entry.get("content", "")),
            )
        )
    return messages, unplaceable


def delivery_lag(
    messages: list[sms.Message], previous: dict, now: datetime
) -> float | None:
    """Seconds between a message being stamped and this poll seeing it.

    Diagnostic only -- nothing decides anything on it. It is measured solely
    from a message that arrived *while we were watching*, which is the bound
    the old clock-offset estimate claimed and did not have: on the very first
    poll every message in the store counts as new, and the newest of them can
    be arbitrarily old. That is not a hypothetical. The router recorded a
    -9336 s "modem offset" on its first run, against two zones that really
    differ by -7200, because the newest message was already 36 minutes old when
    the monitor was installed. At a customer's site, where the store may hold
    nothing newer than last month, the same arithmetic would have placed the
    clock a month in the past and left any raised alert looking current for
    ever -- pausing the keep-alive of sec. 0.6 permanently.
    """
    seen = previous.get("seen_ids") or []
    if not seen:
        return None
    fresh = [m for m in messages if m.id > max(seen)]
    if not fresh:
        return None
    return (now - max(fresh, key=lambda m: m.id).received).total_seconds()


def build_state(
    messages: list[sms.Message],
    previous: dict,
    now_router: datetime,
    *,
    unplaceable: int = 0,
) -> dict:
    state = sms.summarize(messages, now=now_router)
    lag = delivery_lag(messages, previous, now_router)
    newest = max(messages, key=lambda m: m.id, default=None)

    alerts = {
        kind: {
            "active": alert.active and not alert.stale,
            "stale": alert.stale,
            "since": alert.since.isoformat(),
            "stated_time": alert.stated_time,
            "text": alert.text,
        }
        for kind, alert in state.alerts.items()
    }
    operator = state.operator
    return {
        "schema": SCHEMA,
        "timestamp": int(now_router.timestamp()),
        # False here, and True only in the branch that could not reach the
        # modem, so that a reader never has to infer freshness from a date.
        "stale": False,
        "stamp_tz_offset": (
            int(newest.received.utcoffset().total_seconds()) if newest else None
        ),
        "delivery_lag": round(lag) if lag is not None else None,
        "unplaceable_stamps": unplaceable,
        "alert_active": state.alert_active,
        "alert_unknown": state.alert_unknown,
        "alert_kinds": state.alert_kinds,
        "alert_text": next(
            (a.text for a in state.alerts.values() if a.active and not a.stale), ""
        ),
        "alerts": alerts,
        "operator_paid": operator.paid,
        "operator_state_text": operator.state_text,
        "operator_seen": operator.seen.isoformat() if operator.seen else None,
        "next_charge": operator.next_charge,
        "last_payment": operator.last_payment.isoformat() if operator.last_payment else None,
        "unknown_count": state.unknown_count,
        "unknown_sample": state.unknown_sample,
        "unknown_senders": state.unknown_senders,
        "seen_ids": sorted(m.id for m in messages),
        "messages_seen": len(messages),
    }


def read_previous() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def main(argv: list[str]) -> int:
    previous = read_previous()
    now = datetime.now().astimezone()
    try:
        messages, unplaceable = fetch_messages()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # The modem being unreachable is not a verdict about the operator. Keep
        # the last state, record that it went stale, and say so -- reporting
        # "no alert" because we could not ask is exactly the silent-signal
        # failure this whole feature exists to prevent.
        #
        # `timestamp` deliberately stays where it was: it dates the reading,
        # not the attempt. Moving it forward here would make a state we failed
        # to confirm look freshly confirmed, which is the same quiet lie the
        # panel told about the filter -- a failed read must never read as ok.
        state = dict(previous)
        state.setdefault("schema", SCHEMA)
        state.setdefault("timestamp", None)
        state["stale"] = True
        state["modem_error"] = str(exc)
        state["checked_at"] = int(now.timestamp())
        atomic_write_text(STATE_FILE, json.dumps(state, ensure_ascii=False, indent=1), mode=0o644)
        print(f"modem unreachable: {exc}", file=sys.stderr)
        return 1

    state = build_state(messages, previous, now, unplaceable=unplaceable)
    atomic_write_text(STATE_FILE, json.dumps(state, ensure_ascii=False, indent=1), mode=0o644)
    if "--verbose" in argv:
        print(json.dumps(state, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
