"""FreeBSD service status."""
from __future__ import annotations

from ..command import run
from .helpers import service_state, VPN_IF


def services() -> dict[str, str]:
    """FreeBSD service status for key daemons."""
    # gatewayctl_apply raises the VPN gateway; leaving it out of this list is
    # why the admin panel showed it as unknown and why the upgrade health gate
    # could report success with the tunnel out of the traffic path.
    names = ["mpd5", "pf", "unbound", "isc-dhcpd", "sshd", "ntpd",
             "nut", "nut_upsmon", "gatebsd_failover", "gatewayctl_apply",
             "amnezia", "gatebsd", "gatebsd_reverse_ssh", "smartd", "cron"]
    states = service_state(*names)
    # Map isc-dhcpd to dhcpd for frontend compatibility
    if "isc-dhcpd" in states:
        states["dhcpd"] = states.pop("isc-dhcpd")
    awg_r = run(["ifconfig", VPN_IF], timeout=2)
    vpn_state = "active" if awg_r.ok and "UP" in awg_r.stdout else "inactive"
    states[VPN_IF] = vpn_state
    states["awg0"] = vpn_state  # frontend compatibility
    return states


def all_services() -> list[dict[str, str]]:
    """List all rc.d services with status."""
    r = run(["service", "-e"], timeout=5)
    result = []
    for line in r.stdout.splitlines():
        name = line.strip().rsplit("/", 1)[-1]
        if not name:
            continue

        sr = run(["service", name, "status"], timeout=3)
        active = "active" if sr.ok else "inactive"

        lr = run(["service", name, "rcvar"], timeout=2)
        load = "loaded" if lr.ok else "missing"

        sub = ""
        if sr.ok and sr.stdout:
            sub = sr.stdout.strip().split("\n")[-1][:50]

        result.append({
            "unit": name,
            "active": active,
            "load": load,
            "sub": sub,
        })
    return result
