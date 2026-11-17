"""What actually happened when the customer pressed the button.

Every write endpoint in this project used to answer the same way: the exit code
of the wrapper it happened to run, dressed up as a result. The panel then
printed that as a green toast. Four separate lies came out of one button sweep
on 4 August, and all four have the same shape -- a report about the call, not
about the world:

    "unbound: undefined"     `doRestart` printed `r.active`; no such field
                             exists in the `service_control` reply at all
    "isc-dhcpd: restart"     `doServiceAction` fell back to the *name of the
                             action*, so the button echoed the request back
    "PPPoE: restarted"       a string literal in `api.py`, written before
                             `service mpd5 restart` had returned and long
                             before PPPoE had negotiated anything
    "5 entries processed"    the count the user typed in, while the backend
                             was answering `added: 0`

None of these can be fixed by picking a better field, because the field they
want does not exist yet: **the outcome of an action is not a boolean.** Five
states are real, and a button that cannot say them will keep guessing:

    done          the action ran and the world was checked afterwards
    failed        it did not happen
    unverified    the command returned success and nothing was checked, or the
                  check could not be made
    in_progress   started, and by design not finished when we answered
    unknown       we did not measure it

`unverified` is the state this codebase kept spending money on. `service mpd5
restart` returns before PPPoE has a session; `/api/system/power` answers before
`shutdown` has been spawned. Both are honest work -- they are simply not
`done`, and calling them `done` is how "the update broke it" gets reported two
weeks after the cause.

`succeeded` and `verified` are two fields on purpose, the same split as
`in_tunnel` / `expected` in `vpn_path`. They differ exactly where the old
booleans lied: an `unverified` action has `succeeded=True, verified=False`, and
a green toast over it is a claim we never checked.

`describe` is a pure function, so a test can hand it a state instead of mocking
a service manager, and `attach` keeps the wire shape in one place -- the panel
reads `payload["action"]` and decides nothing.
"""
from __future__ import annotations

from typing import Any

DONE = "done"
FAILED = "failed"
UNVERIFIED = "unverified"
IN_PROGRESS = "in_progress"
UNKNOWN = "unknown"

LABELS = {
    DONE: "done",
    FAILED: "failed",
    UNVERIFIED: "succeeded, result not verified",
    IN_PROGRESS: "in progress",
    UNKNOWN: "not measured",
}

# How the panel paints it. `unverified` is deliberately not green: the whole
# point of the state is that nobody looked.
TOAST_LEVELS = {
    DONE: "success",
    FAILED: "error",
    UNVERIFIED: "warning",
    IN_PROGRESS: "info",
    UNKNOWN: "warning",
}

_SUCCEEDED = {DONE: True, FAILED: False, UNVERIFIED: True, IN_PROGRESS: True, UNKNOWN: None}
_VERIFIED = {DONE: True, FAILED: True, UNVERIFIED: False, IN_PROGRESS: False, UNKNOWN: None}


def describe(state: str, *, target: str = "", detail: str = "", **extra: Any) -> dict[str, Any]:
    """Build the block the panel renders. `state` must be one of the five."""
    if state not in LABELS:
        raise ValueError(f"unknown action state: {state!r}")
    block: dict[str, Any] = {
        "state": state,
        "label": LABELS[state],
        "level": TOAST_LEVELS[state],
        "succeeded": _SUCCEEDED[state],
        "verified": _VERIFIED[state],
        "target": target,
        "detail": detail,
    }
    block.update(extra)
    return block


def done(target: str = "", detail: str = "", **extra: Any) -> dict[str, Any]:
    return describe(DONE, target=target, detail=detail, **extra)


def failed(target: str = "", detail: str = "", **extra: Any) -> dict[str, Any]:
    return describe(FAILED, target=target, detail=detail, **extra)


def unverified(target: str = "", detail: str = "", **extra: Any) -> dict[str, Any]:
    return describe(UNVERIFIED, target=target, detail=detail, **extra)


def in_progress(target: str = "", detail: str = "", **extra: Any) -> dict[str, Any]:
    return describe(IN_PROGRESS, target=target, detail=detail, **extra)


def unknown(target: str = "", detail: str = "", **extra: Any) -> dict[str, Any]:
    return describe(UNKNOWN, target=target, detail=detail, **extra)


def attach(payload: dict[str, Any], block: dict[str, Any]) -> dict[str, Any]:
    """Put the verdict on the wire, and make `ok` agree with it.

    `ok` predates this module and half the panel still reads it, so it is kept
    -- but it now means "the action succeeded", not "the wrapper exited 0".
    Those are the same number only when nobody checked, which is the case this
    module exists to name out loud. `succeeded is None` (`unknown`) must not
    become `ok: False`: "not measured" is not "failed", and a `False` there
    would be the same collapse in a new place.
    """
    payload["action"] = block
    succeeded = block["succeeded"]
    if succeeded is not None:
        payload["ok"] = succeeded
    return payload
