"""Read the backup operator's state out of the SMS the modem has collected.

The backup SIM is the device's second way out, and when it goes quiet the
watchdog can only say `backup_ok=false`. That is the same report whether the
operator is throttling everyone during an air alert, whether the tariff went
unpaid a month ago, or whether the hardware actually died. Three very different
situations, one indistinguishable symptom -- and we did in fact mistake an
unpaid tariff for normal behaviour for two weeks.

The operator tells us which one it is. It just does so over SMS.

Every rule below was bought with a real message; the corpus lives outside the
tree in <external-sms-corpus>. The ones that
look like paranoia are the ones that already cost us:

  * `Текущий баланс 0.00` meant trouble on 15 July and meant *success* on
    2 August, when the 300 roubles paid in went straight out to the tariff a
    second later. The state is carried by the verb, never by the number.
  * `Завтра ночью будет списана абонентская плата` contains "списана" -- the
    same word that confirms a successful charge. A substring match flips the
    device to "paid" on the strength of a warning that it is *about* to be.
  * `Внесена сумма 300.00 pуб.` writes "руб." with a Latin `p` (U+0070) while
    the message next to it uses Cyrillic `р` (U+0440). The operator mixes
    alphabets inside its own templates.
  * `отмена Ракетной опасности` cancels in the genitive; `снята Беспилотная
    опасность` cancels in the nominative. Matching whole phrases keeps the
    device in a missile alert forever.

This module is pure: it turns messages into a state. Talking to the modem is
sms_monitor's job, so that the tests can run the real parsing everywhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# An alert that never got its cancellation is not an alert that is still on.
# The two real ones lasted 5h35m and 1h12m; the cancel can also simply be lost,
# because the modem drops old messages once its store fills up (sec. 0.4). Past
# this age we report "unknown" rather than "active": a stuck alert would pause
# the keep-alive for good, which is a worse failure than admitting ignorance.
DEFAULT_ALERT_TTL = timedelta(hours=12)

# Latin characters that are visually identical to Cyrillic ones. Folded before
# any keyword match so that a template mixing alphabets still matches. Applied
# to a lowercased copy used only for matching -- the original text is what we
# ever show to a human.
_HOMOGLYPHS = str.maketrans({
    "a": "а", "b": "ь", "c": "с", "e": "е", "h": "н", "k": "к",
    "m": "м", "o": "о", "p": "р", "t": "т", "x": "х", "y": "у",
})

# Civil-defence alerts. Matched on the stem, because the noun declines and the
# verb that cancels it differs per type.
_ALERT_KINDS = (
    ("беспилотн", "UAV alert"),
    ("ракетн", "missile alert"),
    ("химическ", "chemical alert"),
)
_ALERT_RAISED = ("объявлен",)
_ALERT_CLEARED = ("снят", "отмена", "отменен", "отбой")

# The time an alert message states for itself ("В 14.55 снята ..."), which is
# not when it was delivered (15:05:16). We order by delivery id and show this.
_STATED_TIME = re.compile(r"\bв\s+(\d{1,2})[.:](\d{2})\b")

_NEXT_CHARGE = re.compile(
    r"дата\s+следующего\s+списания[^0-9]*(\d{2})\.(\d{2})\.(\d{4})"
)


def fold(text: str) -> str:
    """Lowercase, fold homoglyphs, collapse whitespace -- for matching only."""
    return " ".join(text.lower().translate(_HOMOGLYPHS).split())


def decode_body(body: str) -> str:
    """Message bodies arrive as UCS-2 big-endian hex; some already as text."""
    try:
        return bytes.fromhex(body).decode("utf-16-be")
    except (ValueError, UnicodeDecodeError):
        return body


@dataclass(frozen=True)
class Message:
    """One SMS as the modem reports it.

    `received` carries the offset the SMSC stamped it with (+03 on this
    operator, against the router's +05), so it is an absolute instant and ages
    are plain subtraction. sms_monitor does that parsing; whatever frame the
    caller works in, `now` in summarize() has to be in the same one.
    """

    id: int
    sender: str
    received: datetime
    text: str


# What a message turned out to be. "noise" and "unknown" are deliberately
# different: noise is recognised and discarded on purpose, unknown is a message
# we could not read. A device that ships to a customer for years will meet
# templates its author never saw, and silently ignoring them is how a signal
# stops updating without anyone noticing.
KIND_ALERT = "alert"
KIND_OPERATOR = "operator"
KIND_NOISE = "noise"
KIND_UNKNOWN = "unknown"


def classify(message: Message) -> str:
    text = fold(message.text)
    if _is_receipt(message.text):
        return KIND_NOISE
    if _alert_kind(text) and (_has(text, _ALERT_RAISED) or _has(text, _ALERT_CLEARED)):
        return KIND_ALERT
    if _operator_event(text)[0] is not None:
        return KIND_OPERATOR
    return KIND_UNKNOWN


def _has(folded: str, stems: tuple[str, ...]) -> bool:
    return any(stem in folded for stem in stems)


def _is_receipt(raw: str) -> bool:
    """The fiscal receipt carries a sum, a date and a time but no state.

    It has to be recognised rather than left to fall through as unknown: it
    arrives on every payment, and an unknown-message counter that ticks on
    every top-up is a counter nobody will read twice.
    """
    lowered = raw.lower()
    return "1-ofd.ru" in lowered or lowered.startswith("check ")


def _alert_kind(folded: str) -> str | None:
    for stem, name in _ALERT_KINDS:
        if stem in folded:
            return name
    if "опасност" in folded:
        return "other civil alert"
    return None


def _operator_event(folded: str) -> tuple[str | None, bool | None]:
    """Return (event, paid) for a billing message.

    `paid` is None for events that move money without moving the state.
    Order matters: the "about to be charged" warning contains the same verb as
    the confirmation of an actual charge.
    """
    if "будет списана" in folded:
        return "upcoming_charge", None
    if "недостаточно средств" in folded or "не оплачен" in folded:
        return "unpaid", False
    if "разблокирован" in folded or ("списана" in folded and "абонентск" in folded):
        return "charged", True
    if "внесена сумма" in folded:
        # Money arrived. Whether the tariff is now paid is a separate message:
        # on 2 August the first top-up was followed a second later by the
        # charge, and the second one stood alone because the tariff was already
        # paid and the money simply sits there until 2 September.
        return "payment", None
    return None, None


@dataclass
class AlertState:
    kind: str
    active: bool
    since: datetime
    text: str
    stated_time: str | None = None
    stale: bool = False


@dataclass
class OperatorState:
    """What we know about the account.

    There is deliberately no balance. The stream never states a positive one:
    the only figures that ever appear are the `Текущий баланс 0.00` inside a
    charge confirmation and an unsubstituted `%SUMM_AVAILABLE%` placeholder. On
    2 August the account had money on it and the SMS said 0.00 -- a balance
    field would have shown the customer a zero while their SIM was funded.
    """

    paid: bool | None = None
    state_text: str | None = None
    seen: datetime | None = None
    next_charge: str | None = None
    last_payment: datetime | None = None


@dataclass
class SmsState:
    alerts: dict[str, AlertState] = field(default_factory=dict)
    operator: OperatorState = field(default_factory=OperatorState)
    unknown_count: int = 0
    unknown_sample: str | None = None
    unknown_senders: list[str] = field(default_factory=list)

    @property
    def alert_active(self) -> bool:
        return any(a.active and not a.stale for a in self.alerts.values())

    @property
    def alert_kinds(self) -> list[str]:
        return sorted(k for k, a in self.alerts.items() if a.active and not a.stale)

    @property
    def alert_unknown(self) -> bool:
        """An alert we can neither confirm as over nor trust as current."""
        return any(a.active and a.stale for a in self.alerts.values())


def summarize(
    messages: list[Message],
    *,
    now: datetime,
    alert_ttl: timedelta = DEFAULT_ALERT_TTL,
) -> SmsState:
    """Fold the whole stream into one state.

    `now` is on the modem's clock, the same frame the messages are stamped in.

    The stream is folded oldest-first by delivery id, so the last meaningful
    message wins. Not by the time inside the text, and not by arrival order as
    the modem happens to list them: a payment produced three messages in 26
    seconds and the fiscal receipt came first.
    """
    state = SmsState()
    for message in sorted(messages, key=lambda m: m.id):
        kind = classify(message)
        if kind == KIND_NOISE:
            continue
        if kind == KIND_ALERT:
            _apply_alert(state, message)
        elif kind == KIND_OPERATOR:
            _apply_operator(state, message)
        else:
            state.unknown_count += 1
            state.unknown_sample = message.text[:200]
            if message.sender not in state.unknown_senders:
                state.unknown_senders.append(message.sender)

    for alert in state.alerts.values():
        alert.stale = alert.active and (now - alert.since) > alert_ttl
    return state


def _apply_alert(state: SmsState, message: Message) -> None:
    folded = fold(message.text)
    kind = _alert_kind(folded)
    if kind is None:
        return
    # Cleared wins when both appear: "отмена" and "объявлена" can share a
    # sentence, and an ambiguous message must not raise an alert.
    active = not _has(folded, _ALERT_CLEARED)
    stated = _STATED_TIME.search(folded)
    state.alerts[kind] = AlertState(
        kind=kind,
        active=active,
        since=message.received,
        text=message.text,
        stated_time=f"{stated.group(1)}:{stated.group(2)}" if stated else None,
    )


def _apply_operator(state: SmsState, message: Message) -> None:
    folded = fold(message.text)
    event, paid = _operator_event(folded)
    operator = state.operator

    charge = _NEXT_CHARGE.search(folded)
    if charge:
        # Taken as stated, never derived. The charge date moved from the 14th
        # to the 2nd of the month on 2 August; a date predicted from history
        # would have been wrong by twelve days.
        operator.next_charge = f"{charge.group(3)}-{charge.group(2)}-{charge.group(1)}"

    if event == "payment":
        operator.last_payment = message.received
        return
    if event == "upcoming_charge":
        return
    if paid is None:
        return
    operator.paid = paid
    operator.state_text = message.text
    operator.seen = message.received


def explain(
    *,
    backup_ok: bool,
    alert_active: bool,
    alert_kinds: list[str],
    alert_unknown: bool,
    paid: bool | None,
    paid_since: str | None,
) -> str:
    """Say why the backup path looks the way it does.

    This is the whole point of reading SMS: turning one `backup_ok=false` into
    the three different situations that produce it.

    Takes plain fields rather than an SmsState so that the panel can reach the
    same verdict from the published operator.json without reconstructing the
    parse. One implementation, two callers -- two copies of these sentences
    would drift, and the one the customer reads would be the stale one.
    """
    if backup_ok:
        if paid is False:
            return "backup is working, but plan is unpaid — carrier will throttle it"
        return "backup is ok"

    if alert_active:
        kinds = ", ".join(alert_kinds)
        return f"backup unavailable: {kinds} active, carrier is throttling traffic — not a fault"
    if paid is False:
        since = paid_since or "unknown"
        return f"backup restricted: plan unpaid since {since} — top up required, not a link fault"
    if alert_unknown:
        return "backup unavailable: alert active, all-clear not received — state unknown"
    return "backup unavailable, and carrier reported no cause — this is a fault"


def diagnose(state: SmsState, *, backup_ok: bool) -> str:
    return explain(
        backup_ok=backup_ok,
        alert_active=state.alert_active,
        alert_kinds=state.alert_kinds,
        alert_unknown=state.alert_unknown,
        paid=state.operator.paid,
        paid_since=(
            state.operator.seen.date().isoformat() if state.operator.seen else None
        ),
    )
