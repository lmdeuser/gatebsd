"""Aggregate overview combining multiple subsystems."""
from __future__ import annotations

from typing import Any

from ..adblock import run_status as adblock_run_status
from .system import system_info, memory_info
from .network import wan_status, lan_clients
from .vpn import amnezia
from .vpn_path import vpn_path_state
from .services import services
from .firewall import ups
from .operator_state import operator


def overview() -> dict[str, Any]:
    return {
        "system": system_info(),
        "memory": memory_info(),
        "wan": wan_status(),
        "amnezia": amnezia(),
        # Which of five states the tunnel is in, decided here. The panel
        # used to reduce it to one boolean with an OR, and "up but not in
        # the path" came out the same as "carrying the traffic".
        "vpn_path": vpn_path_state(),
        "services": services(),
        "ups": ups(),
        "operator": operator(),
        # Only the run record, never adblock.status(): that one shells out to
        # unbound-control and unbound-checkconf, and this payload is polled.
        # What belongs here is the one fact the blocklist itself cannot state
        # -- whether the last rebuild published anything.
        "adblock": adblock_run_status(),
        "clients": lan_clients(),
        "setup_done": True,
    }
