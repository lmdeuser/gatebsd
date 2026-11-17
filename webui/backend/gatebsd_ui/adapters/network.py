"""Network interfaces, WAN status, traffic stats, LAN clients."""
from __future__ import annotations

import re
import threading
import time
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from ..command import lines, run
from .helpers import (
    _ifconfig_iface, LAN_IF, WAN_IF, BACKUP_IF, VPN_IF, LAN_NET, CHECK_IP,
)

# MAC OUI vendor prefix database (common devices)
_OUI_DB: dict[str, str] = {
    "30:96:10": "Huawei", "90:7a:be": "LG Electronics", "2e:9e:02": "Apple",
    "b0:dc:ef": "Intel", "68:1d:ef": "Apple", "10:90:fc": "Doogee",
    "2c:a7:ef": "OnePlus", "ac:c5:1b": "Pantum",
    "e0:51:d8": "TP-Link", "00:e0:4c": "Realtek", "84:47:09": "Intel",
    "6c:2b:59": "Apple", "f6:ac:0e": "Unknown", "30:65:ec": "Microsoft",
    "34:4b:50": "ZTE", "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi",
    "52:54:00": "QEMU/KVM", "08:00:27": "VirtualBox", "00:0c:29": "VMware",
    "00:50:56": "VMware", "00:15:5d": "Hyper-V", "44:38:39": "Cumulus",
    "aa:bb:cc": "Docker", "02:42:ac": "Docker", "00:16:3e": "Xen",
    "fe:ff:ff": "VMware", "00:05:69": "VMware", "00:1c:14": "VMware",
    "00:0d:3a": "Microsoft", "00:1d:d8": "Microsoft", "7c:1e:52": "Microsoft",
    "28:18:78": "Microsoft", "60:45:bd": "Microsoft", "b8:31:b5": "Microsoft",
    "3c:5a:b4": "Google", "f4:f5:d8": "Google", "54:60:09": "Google",
    "30:fd:38": "Google", "a4:77:33": "Google", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "d8:3a:dd": "Raspberry Pi", "28:cd:c1": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi", "00:1a:79": "Technicolor", "c0:05:02": "Actiontec",
    "40:b0:34": "ASUSTek", "10:bf:48": "ASUSTek", "04:d4:c4": "ASUSTek",
    "2c:4d:54": "ASUSTek", "08:60:6e": "ASUSTek", "74:d0:2b": "ASUSTek",
    "ac:9e:17": "ASUSTek", "04:92:26": "ASUSTek", "30:5a:3a": "ASUSTek",
    "24:4b:fe": "ASUSTek", "1c:87:2c": "ASUSTek", "04:d9:f5": "ASUSTek",
    "50:46:5d": "ASUSTek", "2c:fd:a1": "ASUSTek", "08:60:6e": "ASUSTek",
    "fc:c8:9a": "ASUSTek", "04:92:26": "ASUSTek", "74:d0:2b": "ASUSTek",
    "10:7b:44": "Samsung", "30:cd:a7": "Samsung", "f8:04:2e": "Samsung",
    "cc:07:ab": "Samsung", "84:25:db": "Samsung", "a0:82:1f": "Samsung",
    "e4:7c:f9": "Samsung", "b4:3a:28": "Samsung", "c0:97:27": "Samsung",
    "1c:62:b8": "Samsung", "5c:0a:5b": "Samsung", "94:35:0a": "Samsung",
    "a8:06:00": "Samsung", "c4:73:1e": "Samsung", "d0:22:be": "Samsung",
    "f0:08:f1": "Samsung", "24:4b:81": "Samsung", "e8:03:9a": "Samsung",
    "78:25:ad": "Samsung", "00:1e:58": "D-Link", "1c:5f:2b": "D-Link",
    "1c:7e:e5": "D-Link", "28:10:7b": "D-Link", "3c:1e:04": "D-Link",
    "40:9b:cd": "D-Link", "5c:d9:98": "D-Link", "78:32:1b": "D-Link",
    "84:c9:b2": "D-Link", "90:8d:78": "D-Link", "9c:d6:43": "D-Link",
    "b8:a3:86": "D-Link", "c0:a0:bb": "D-Link", "c8:be:19": "D-Link",
    "e0:1c:fc": "D-Link", "e4:6f:13": "D-Link", "f0:2d:59": "D-Link",
    "fc:75:16": "D-Link", "00:14:6c": "Netgear", "20:e5:2a": "Netgear",
    "28:c6:8e": "Netgear", "2c:b0:5d": "Netgear", "30:46:9a": "Netgear",
    "44:94:fc": "Netgear", "4c:60:de": "Netgear", "6c:b0:ce": "Netgear",
    "84:1b:5e": "Netgear", "8c:3b:ad": "Netgear", "9c:3d:cf": "Netgear",
    "a0:04:60": "Netgear", "a4:2b:8c": "Netgear", "b0:7f:b9": "Netgear",
    "b0:b9:8a": "Netgear", "c0:3f:0e": "Netgear", "c4:04:15": "Netgear",
    "cc:40:d0": "Netgear", "d0:21:f9": "Netgear", "dc:ef:09": "Netgear",
    "e0:46:9a": "Netgear", "e0:91:f5": "Netgear", "e4:f4:c6": "Netgear",
    "e8:fc:af": "Netgear", "f0:01:6c": "Netgear", "f8:73:94": "Netgear",
    "fc:fb:fb": "Netgear",
}

def _lookup_vendor(mac: str) -> str:
    """Lookup vendor from MAC OUI prefix."""
    if not mac:
        return ""
    prefix = mac.strip().lower()[:8]
    return _OUI_DB.get(prefix, "")

_nmap_lock = threading.Lock()
_nmap_cache: dict[str, Any] = {
    "timestamp": 0.0,
    "hosts": []  # list of dicts: {"ip": "...", "mac": "...", "latency_ms": ..., "vendor": "..."}
}


def physical_ports() -> dict[str, Any]:
    r = run(["ifconfig", "-l"], timeout=3)
    all_ifaces = r.stdout.split()
    physical = [i for i in all_ifaces if re.match(r"^(re|em|igb|bge|ix|ue|xl|dc)\d+$", i)]
    return {"ports": sorted(physical)}


def interfaces() -> dict[str, Any]:
    r = run(["ifconfig", "-a"], timeout=4)
    ifaces = []
    current: dict[str, Any] | None = None
    for line in r.stdout.splitlines():
        m = re.match(r"^(\S+):\s+flags=\S+<([^>]*)>", line)
        if m:
            if current:
                ifaces.append(current)
            current = {
                "name": m.group(1),
                "flags": m.group(2),
                "addresses": [],
            }
        elif current:
            im = re.search(r"inet\s+(\S+)", line)
            if im:
                current["addresses"].append(im.group(1))
    if current:
        ifaces.append(current)

    routes_r = run(["netstat", "-rn", "-f", "inet"], timeout=4)
    return {
        "interfaces": ifaces,
        "routes_v4": lines(routes_r.stdout),
    }


def wan_status() -> dict[str, Any]:
    wan  = _ifconfig_iface(WAN_IF)
    bak  = _ifconfig_iface(BACKUP_IF)
    vpn  = _ifconfig_iface(VPN_IF)

    default_r = run(["route", "-n", "get", "default"], timeout=3)
    active_iface = ""
    active_gw = ""
    for line in default_r.stdout.splitlines():
        if "interface:" in line:
            active_iface = line.split()[-1]
        if "gateway:" in line:
            active_gw = line.split()[-1]

    def ping_iface(iface: str) -> dict[str, Any]:
        if not iface:
            return {"ok": False, "error": "missing"}
        ifc = _ifconfig_iface(iface)
        addrs = ifc.get("addresses", [])
        src = addrs[0].split("/")[0] if addrs else ""

        # Determine target: PPPoE peer -> subnet gateway -> CHECK_IP
        target = CHECK_IP
        raw = ifc.get("raw", "")

        # 1. PPPoE peer (ng0: inet x.x.x.x --> y.y.y.y)
        m_peer = re.search(r"inet\s+\S+\s+-->\s+(\S+)", raw)
        if m_peer:
            target = m_peer.group(1)
        elif src:
            # 2. Subnet gateway: derive from netmask in raw ifconfig output
            try:
                m_mask = re.search(r"netmask\s+(0x[0-9a-fA-F]+)", raw)
                if m_mask:
                    mask_int = int(m_mask.group(1), 16)
                    # /24 (mask 0xffffff00) or narrower -> gateway .1
                    if mask_int >= 0xFFFFFF00:
                        octets = src.split(".")
                        if len(octets) == 4:
                            octets[3] = "1"
                            target = ".".join(octets)
            except (ValueError, IndexError):
                pass

        cmd = ["ping", "-c", "1", "-W", "2000", target]
        if src:
            cmd = ["ping", "-c", "1", "-W", "2000", "-S", src, target]
        r = run(cmd, timeout=4)
        latency = None
        m = re.search(r"time=([0-9.]+)", r.stdout)
        if m:
            latency = float(m.group(1))
        return {"ok": r.ok, "latency_ms": latency, "target": target}

    return {
        "active_iface": active_iface,
        "active_gw": active_gw,
        "wan":    wan,
        "backup": bak,
        "vpn":    vpn,
        "health": {
            "wan":    ping_iface(WAN_IF)   if wan["state"] != "missing"  else {"ok": False},
            "backup": ping_iface(BACKUP_IF) if bak["state"] != "missing"  else {"ok": False},
        },
        "sys": {
            "wan_if": WAN_IF, "backup_if": BACKUP_IF,
            "lan_if": LAN_IF, "vpn_if": VPN_IF,
            "lan_net": LAN_NET,
        },
    }


_traffic_lock = threading.Lock()
_traffic_previous: dict[str, tuple[float, int, int]] = {}


def iface_counters(iface: str) -> tuple[int, int]:
    """Return input/output bytes using the column names reported by FreeBSD."""
    r = run(["netstat", "-bnI", iface], timeout=3)
    header: list[str] = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == "Name":
            header = parts
            continue
        if not header or not parts or parts[0].rstrip("*") != iface:
            continue
        if "<Link#" not in line:
            continue
        try:
            return int(parts[header.index("Ibytes")]), int(parts[header.index("Obytes")])
        except (ValueError, IndexError):
            continue
    return 0, 0


def traffic_stats() -> dict[str, Any]:
    data: dict[str, Any] = {}
    now = time.monotonic()
    samples = {iface: iface_counters(iface) for iface in [WAN_IF, BACKUP_IF, LAN_IF, VPN_IF]}
    with _traffic_lock:
        for iface, (rx, tx) in samples.items():
            rx_rate = tx_rate = 0.0
            previous = _traffic_previous.get(iface)
            if previous:
                elapsed = now - previous[0]
                if elapsed > 0:
                    rx_rate = max(0, rx - previous[1]) / elapsed
                    tx_rate = max(0, tx - previous[2]) / elapsed
            _traffic_previous[iface] = (now, rx, tx)
            data[iface] = {
                "rx": rx, "tx": tx,
                "rx_rate": round(rx_rate, 2), "tx_rate": round(tx_rate, 2),
            }
    return {"interfaces": data}


def lan_clients() -> dict[str, Any]:
    from .firewall import dhcpd as _dhcpd
    global _nmap_cache

    clients: dict[str, dict[str, Any]] = {}

    def item(mac: str | None, ip: str | None = None) -> dict[str, Any]:
        key = (mac or "").lower() or (ip or "?").lower()
        c = clients.setdefault(key, {
            "ip": "", "mac": "", "hostname": "",
            "source": [], "state": "", "static": False,
        })
        if mac:
            c["mac"] = mac.lower()
        if ip:
            c["ip"] = ip
        return c

    data = _dhcpd()
    static_macs = {s["mac"].lower(): s for s in data.get("static", []) if s.get("mac")}

    # 1. Populate static DHCP hosts first
    for s in data.get("static", []):
        mac = s.get("mac")
        ip = s.get("ip")
        if mac or ip:
            e = item(mac, ip)
            e["static"] = True
            e["hostname"] = s.get("hostname", "")
            if "static" not in e["source"]:
                e["source"].append("static")

    # 2. Populate DHCP leases
    for lease in data["leases"]:
        e = item(lease.get("mac"), lease.get("ip"))
        e["hostname"] = lease.get("hostname", "")
        e["lease_expires"] = lease.get("expires", "")
        if "dhcp" not in e["source"]:
            e["source"].append("dhcp")

    # 3. Cached nmap subnet ping scan (30 seconds cache lifetime)
    with _nmap_lock:
        now = time.time()
        if now - _nmap_cache["timestamp"] > 30.0:
            hosts = []
            if LAN_NET:
                nmap_path = "nmap"
                for p in ["/usr/local/bin/nmap", "/usr/bin/nmap"]:
                    if Path(p).exists():
                        nmap_path = p
                        break
                # -sn: ping scan, -n: no DNS resolution, -T4: aggressive timing
                # --max-rtt-timeout 100ms --max-retries 1: optimize for LAN latency
                r = run([nmap_path, "-sn", "-n", "-T4", "--max-rtt-timeout", "100ms", "--max-retries", "1", "-oX", "-", LAN_NET], timeout=5)
                if r.ok and r.stdout:
                    try:
                        root = ET.fromstring(r.stdout)
                        for host in root.findall("host"):
                            status = host.find("status")
                            if status is not None and status.get("state") == "up":
                                ip_addr = None
                                mac_addr = None
                                latency_ms = None
                                for addr in host.findall("address"):
                                    if addr.get("addrtype") == "ipv4":
                                        ip_addr = addr.get("addr")
                                    elif addr.get("addrtype") == "mac":
                                        mac_addr = addr.get("addr")
                                # Extract latency from times element (srtt in microseconds)
                                times = host.find("times")
                                if times is not None:
                                    srtt = times.get("srtt")
                                    if srtt:
                                        latency_ms = round(int(srtt) / 1000, 1)
                                if ip_addr:
                                    vendor = _lookup_vendor(mac_addr) if mac_addr else ""
                                    hosts.append({"ip": ip_addr, "mac": mac_addr, "latency_ms": latency_ms, "vendor": vendor})
                    except Exception:
                        # Fallback to simple regex if XML parsing fails
                        for line in r.stdout.splitlines():
                            m = re.search(r"Nmap scan report for ([\d.]+)", line)
                            if m:
                                hosts.append({"ip": m.group(1), "mac": None, "latency_ms": None, "vendor": ""})
                _nmap_cache = {
                    "timestamp": now,
                    "hosts": hosts
                }

        cached_hosts = [dict(host) for host in _nmap_cache["hosts"]]

    for h in cached_hosts:
        e = item(h["mac"], h["ip"])
        e["state"] = "reachable"
        if h.get("latency_ms") is not None:
            e["latency_ms"] = h["latency_ms"]
        if h.get("vendor"):
            e["vendor"] = h["vendor"]
        if "nmap" not in e["source"]:
            e["source"].append("nmap")
    # 4. Parse system ARP table
    arp = run(["arp", "-an"], timeout=3)
    for line in arp.stdout.splitlines():
        m = re.match(r"\?\s+\(([\d.]+)\)\s+at\s+([0-9a-f:]+)\s+on\s+(\S+)", line)
        if m and m.group(3) == LAN_IF:
            e = item(m.group(2), m.group(1))
            e["state"] = "reachable"
            if "arp" not in e["source"]:
                e["source"].append("arp")

    # 5. Post-process list
    local_ips = set()
    r_if = run(["ifconfig", "-a"], timeout=3)
    if r_if.ok:
        for line in r_if.stdout.splitlines():
            im = re.search(r"inet\s+(\S+)", line)
            if im:
                local_ips.add(im.group(1).split("/")[0])

    rows = []
    for c in clients.values():
        if c.get("ip") in local_ips:
            continue
        rows.append(c)

    for r in rows:
        r["source"] = sorted(set(r["source"]))
        if r["mac"] in static_macs:
            r["static"] = True
            if not r["hostname"]:
                r["hostname"] = static_macs[r["mac"]].get("hostname", "")

        # Set normalized activity status
        if not r["state"]:
            if "arp" in r["source"] or "nmap" in r["source"] or "dhcp" in r["source"]:
                r["state"] = "active"
            else:
                r["state"] = "offline"

    rows.sort(key=lambda r: [int(x) if x.isdigit() else 999
                              for x in (r.get("ip") or "999.999.999.999").split(".")])
    return {"clients": rows, "count": len(rows)}
