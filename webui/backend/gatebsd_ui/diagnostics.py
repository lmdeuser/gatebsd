"""Comprehensive system diagnostics snapshot."""
from __future__ import annotations

import re
from typing import Any

from . import failover, paths, routing
from .adapters import amnezia, dhcpd, firewall, pppoe, services, ups
from .adapters.helpers import WAN_IF, BACKUP_IF, VPN_IF, LAN_IF
from .command import lines, run
from .redact import redact_text


def _hardware_info() -> dict[str, Any]:
    """Collect hardware information: CPU, memory, disks, temperatures."""
    cpu_model = run(["sysctl", "-n", "hw.model"], timeout=3).stdout.strip()
    ncpu = run(["sysctl", "-n", "hw.ncpu"], timeout=2).stdout.strip()
    physmem = run(["sysctl", "-n", "hw.physmem"], timeout=2).stdout.strip()

    # CPU temperatures via coretemp
    temps = []
    try:
        n = int(ncpu or 0)
        for i in range(n):
            r = run(["sysctl", "-n", f"dev.cpu.{i}.temperature"], timeout=2)
            if r.ok:
                m = re.search(r"([\d.]+)", r.stdout)
                if m:
                    temps.append(float(m.group(1)))
    except (ValueError, TypeError):
        pass

    # Disk info
    disks_r = run(["sysctl", "-n", "kern.disks"], timeout=3)
    disk_list = disks_r.stdout.split() if disks_r.ok else []

    # Kernel modules
    kldstat = run(["kldstat"], timeout=3)
    modules = []
    if kldstat.ok:
        for line in kldstat.stdout.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 2:
                modules.append({"name": parts[1], "size": parts[2] if len(parts) > 2 else ""})

    return {
        "cpu": {"model": cpu_model, "cores": int(ncpu or 0), "temps_c": temps},
        "memory": {"physmem": int(physmem or 0)},
        "disks": disk_list,
        "kernel_modules": modules[:20],  # limit output
    }


def _network_info() -> dict[str, Any]:
    """Collect detailed network interface information."""
    interfaces = {}
    for iface in [WAN_IF, BACKUP_IF, LAN_IF, VPN_IF]:
        r = run(["ifconfig", iface], timeout=3)
        if r.ok:
            up = "UP" in r.stdout and "RUNNING" in r.stdout
            addrs = re.findall(r"inet\s+(\S+)", r.stdout)
            mtu_m = re.search(r"mtu\s+(\d+)", r.stdout)
            interfaces[iface] = {
                "up": up,
                "addresses": addrs,
                "mtu": int(mtu_m.group(1)) if mtu_m else None,
            }

    # ARP table
    arp = run(["arp", "-an"], timeout=3)
    arp_entries = len(lines(arp.stdout)) if arp.ok else 0

    # PF state count
    pf_states = run(["pfctl", "-s", "states"], timeout=3)
    state_count = len(lines(pf_states.stdout)) if pf_states.ok else 0

    return {
        "interfaces": interfaces,
        "arp_entries": arp_entries,
        "pf_states": state_count,
    }


def snapshot() -> dict[str, Any]:
    """Full system diagnostics snapshot with redacted secrets."""
    logs = run(["tail", "-n", "200", "/var/log/messages"], timeout=5)

    # System info
    hostname = run(["hostname"], timeout=2).stdout.strip()
    uptime = run(["uptime"], timeout=2).stdout.strip()
    freebsd_ver = run(["freebsd-version", "-ku"], timeout=2).stdout.strip()

    service_states = services()
    failover_status = failover.status()
    return {
        "system": {
            "hostname": hostname,
            "uptime": uptime,
            "freebsd_version": freebsd_ver,
        },
        "pf": firewall(),
        "routes": routing.route_table(),
        "pppoe": pppoe(),
        "dhcp": dhcpd(),
        "dns": {
            "config": str(paths.UNBOUND_CONF),
            "service": service_states.get("unbound"),
        },
        "awg": amnezia(),
        "split_tunnel": routing.split_tunnel(),
        "failover": failover_status,
        "watchdog": {
            "service": service_states.get("gatebsd_failover", "unknown"),
            "state": failover_status.get("state", {}),
        },
        "hardware": _hardware_info(),
        "network": _network_info(),
        "ups": ups(),
        "logs": redact_text(logs.stdout if logs.ok else logs.stderr),
    }
