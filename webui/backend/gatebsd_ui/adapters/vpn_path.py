"""Where the traffic actually goes, and which VPN state that is.

The panel used to work this out itself, in one line of `app.js`:

    vpnUp = vpn_is_default || interface.state === "UP"

A disjunction. So "the tunnel is up but the traffic goes around it" was
indistinguishable from "the traffic is in the tunnel", the topology map drew
both green, and the warning card stayed silent through both. On the night of
4 August that silence covered two and a half hours of a household on bare WAN,
and the "Repair internet" button answered "the internet is working normally"
twice into it.

Five states are real, and they are told apart by three separate facts, never by
one boolean:

    in_path               the default route is the tunnel
    bypassed              the tunnel is up, the default route is something else
    disabled_by_operator  the operator's marker is present
    rolled_back           the watchdog took the tunnel out of the path itself
    down                  the tunnel interface is not up

and a sixth that is not a state of the VPN but of our knowledge:

    unknown               we could not measure it

`unknown` is not `down` and it is certainly not `in_path`. This project has
paid for that confusion four times already -- `sources_used`, the handshake
age, the operator's `stale`, an unreadable file against an empty one -- so a
fact we failed to read arrives here as ``None`` and leaves as ``unknown``.

Two fields carry the verdict, and they are deliberately not the same field:

    in_tunnel   is the traffic inside the tunnel right now
    expected    is the current state the one this box is configured to want

They differ exactly where the old boolean lied. A VPN the operator switched off
is `expected` (nobody needs an alarm about it) while `in_tunnel` is false, and
the panel still says out loud that the traffic is going direct.

`classify` is a pure function of measured facts, so a test can hand it a state
instead of mocking the function that reads one.
"""
from __future__ import annotations

import json
from typing import Any

from .. import paths
from ..command import run
from ..fsutil import read_regular_text
from .helpers import VPN_IF

IN_PATH = "in_path"
BYPASSED = "bypassed"
DISABLED_BY_OPERATOR = "disabled_by_operator"
ROLLED_BACK = "rolled_back"
DOWN = "down"
UNKNOWN = "unknown"

LABELS = {
    IN_PATH: "traffic routed via tunnel",
    BYPASSED: "tunnel up, traffic bypassing",
    DISABLED_BY_OPERATOR: "disabled by operator",
    ROLLED_BACK: "rolled back automatically",
    DOWN: "tunnel is down",
    UNKNOWN: "not measured",
}


def classify(
    *,
    interface_up: bool | None,
    default_iface: str | None,
    operator_disabled: bool | None,
    rolled_back: bool | None,
    vpn_iface: str = VPN_IF,
) -> dict[str, Any]:
    """Turn measured facts into one of the six states above.

    Every argument may be ``None``, meaning "we could not read this". Three of
    them are load-bearing: without the interface state, the default route, or
    the operator's marker there is no honest verdict to give, so the answer is
    `unknown` rather than a cheerful guess.
    """
    is_default: bool | None = None if default_iface is None else (default_iface == vpn_iface)

    facts: dict[str, Any] = {
        "interface_up": interface_up,
        "default_iface": default_iface,
        "is_default": is_default,
        "operator_disabled": operator_disabled,
        "rolled_back": rolled_back,
    }

    unmeasured = [name for name, value in (
        ("interface state", interface_up),
        ("default route", is_default),
        ("operator marker", operator_disabled),
    ) if value is None]

    if unmeasured:
        state = UNKNOWN
        in_tunnel: bool | None = None
        expected: bool | None = None
    elif is_default and interface_up:
        state = IN_PATH
        in_tunnel = True
        expected = True
    elif operator_disabled:
        # The operator's own decision outranks how the tunnel happens to look:
        # a marker over a live interface still means the traffic is not meant
        # to be in it, and the watchdog skips its whole VPN section regardless.
        state = DISABLED_BY_OPERATOR
        in_tunnel = False
        expected = True
    elif not interface_up:
        state = DOWN
        in_tunnel = False
        expected = False
    elif rolled_back:
        state = ROLLED_BACK
        in_tunnel = False
        expected = False
    else:
        state = BYPASSED
        in_tunnel = False
        expected = False

    result: dict[str, Any] = {
        "state": state,
        "label": LABELS[state],
        "in_tunnel": in_tunnel,
        "expected": expected,
        "vpn_iface": vpn_iface,
        "unmeasured": unmeasured,
        **facts,
    }
    result["warnings"] = _warnings(result)
    return result


def _warnings(state: dict[str, Any]) -> list[dict[str, str]]:
    """The sentences the customer reads. Composed here, not in `app.js`.

    There is no JS engine on the machine that validates every push, so a rule
    living in the frontend would ship having never been run once. The panel
    renders this list and decides nothing -- the same contract the blocklist
    and the backup operator already use.
    """
    name = state["state"]
    iface = state.get("default_iface") or "unknown interface"
    vpn_iface = state["vpn_iface"]

    if name == IN_PATH:
        return []

    if name == UNKNOWN:
        return [{
            "time": "—",
            "icon": "help-circle",
            "level": "warn",
            "msg": (
                "VPN state not measured: could not read — "
                + ", ".join(state["unmeasured"])
                + ". That does not mean everything is fine."
            ),
        }]

    if name == DISABLED_BY_OPERATOR:
        return [{
            "time": "—",
            "icon": "shield-off",
            "level": "warn",
            "msg": (
                f"VPN disabled: operator marker {paths.VPN_DISABLED} is set. "
                f"Traffic routes directly via {iface}; your external address is visible to the ISP."
            ),
        }]

    if name == ROLLED_BACK:
        return [{
            "time": "—",
            "icon": "shield-alert",
            "level": "error",
            "msg": (
                f"VPN rolled back automatically: watchdog returned traffic to {iface} after "
                "connectivity check failed. Tunnel is out of path."
            ),
        }]

    if name == BYPASSED:
        return [{
            "time": "—",
            "icon": "shield-alert",
            "level": "error",
            "msg": (
                f"Traffic is bypassing the VPN tunnel: default route goes via {iface}. "
                f"Interface {vpn_iface} is up but out of path — your external address "
                "is visible to the ISP."
            ),
        }]

    return [{
        "time": "—",
        "icon": "shield-off",
        "level": "error",
        "msg": f"VPN tunnel is down: interface {vpn_iface} is not UP.",
    }]


# ── Measurement ──────────────────────────────────────────────────────────────
# Each of these returns None when it could not find out, never a default.

def measure_interface_up(iface: str = VPN_IF) -> bool | None:
    result = run(["ifconfig", iface], timeout=3)
    if not result.ok:
        # `ifconfig` fails both for "no such interface" and for "could not
        # run ifconfig at all"; only the first is an answer.
        if "does not exist" in (result.stderr or "") or "not exist" in (result.stdout or ""):
            return False
        return None
    return "UP" in result.stdout


def measure_default_iface() -> str | None:
    result = run(["route", "-n", "get", "default"], timeout=3)
    if not result.ok:
        return None
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "interface:":
            return fields[1]
    return None


def measure_operator_disabled() -> bool | None:
    """Whether the operator's marker is there.

    ``Path.exists()`` is wrong here: it answers False both for "no marker" and
    for "the directory would not let me look", and those are the two states
    this module exists to keep apart.
    """
    try:
        paths.VPN_DISABLED.lstat()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return None


def measure_rolled_back() -> bool | None:
    try:
        text, _metadata = read_regular_text(paths.FAILOVER_STATE, max_size=256 * 1024, errors="strict")
        data = json.loads(text) if text.strip() else None
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or "vpn_rolled_back" not in data:
        return None
    return bool(data["vpn_rolled_back"])


def vpn_path_state() -> dict[str, Any]:
    """Measure, then classify. The two halves stay apart so tests can skip one.

    Named apart from the module on purpose: re-exported from
    ``adapters/__init__.py`` a function called ``vpn_path`` would shadow the
    submodule ``adapters.vpn_path``, and every importer would silently get the
    function instead.
    """
    return classify(
        interface_up=measure_interface_up(),
        default_iface=measure_default_iface(),
        operator_disabled=measure_operator_disabled(),
        rolled_back=measure_rolled_back(),
    )
