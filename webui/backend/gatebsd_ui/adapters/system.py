"""System information: hostname, uptime, memory, disks, ZFS, SMART, I/O."""
from __future__ import annotations

import json
import os
import re
import stat
import socket
import threading
import time
from pathlib import Path
from typing import Any

from ..command import lines, run
from ..fsutil import read_regular_text


_cpu_lock = threading.Lock()
_cpu_previous: tuple[float, list[int]] | None = None


def _cpu_usage() -> float | None:
    global _cpu_previous
    raw = run(["sysctl", "-n", "kern.cp_time"], timeout=2).stdout.split()
    try:
        current = [int(value) for value in raw[:5]]
    except ValueError:
        return None
    if len(current) != 5:
        return None
    now = time.monotonic()
    with _cpu_lock:
        result = None
        if _cpu_previous:
            deltas = [max(0, value - old) for value, old in zip(current, _cpu_previous[1])]
            total = sum(deltas)
            if total:
                result = round(100 * (total - deltas[4]) / total, 1)
        _cpu_previous = (now, current)
    return result


def system_info() -> dict[str, Any]:
    hostname = socket.gethostname()
    uptime_seconds = None
    bt = run(["sysctl", "-n", "kern.boottime"], timeout=2)
    m = re.search(r"sec\s*=\s*(\d+)", bt.stdout)
    if m:
        uptime_seconds = time.time() - int(m.group(1))

    loadavg = run(["sysctl", "-n", "vm.loadavg"], timeout=2).stdout.strip()
    ver = run(["uname", "-r"], timeout=2).stdout.strip()
    arch = run(["uname", "-m"], timeout=2).stdout.strip()
    pkg_ver = run(["pkg", "query", "%v", "gatebsd"], timeout=3).stdout.strip()
    if not pkg_ver:
        try:
            version_path = Path(__file__).resolve().parents[4] / "VERSION"
            pkg_text, _metadata = read_regular_text(version_path, max_size=4096, errors="strict")
            pkg_ver = pkg_text.strip()
        except Exception:
            pass
    if not pkg_ver:
        pkg_ver = "dev"
    cpu_model = run(["sysctl", "-n", "hw.model"], timeout=2).stdout.strip()
    ncpu = run(["sysctl", "-n", "hw.ncpu"], timeout=2).stdout.strip()
    if ncpu:
        cpu_model = f"{cpu_model} ({ncpu} cores)"
    root_mount = run(["mount", "-p"], timeout=2)
    root_fs = ""
    for line in root_mount.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "/":
            root_fs = parts[2]
            break

    return {
        "hostname": hostname,
        "os": f"FreeBSD {ver}",
        "kernel": ver,
        "architecture": arch,
        "uptime_seconds": uptime_seconds,
        "loadavg": loadavg,
        "time": int(time.time()),
        "package_version": pkg_ver,
        "cpu_model": cpu_model,
        "cpu_pct": _cpu_usage(),
        "root_filesystem": root_fs,
    }


def memory_info() -> dict[str, Any]:
    physmem = int(run(["sysctl", "-n", "hw.physmem"], timeout=2).stdout.strip() or 0)
    usermem = int(run(["sysctl", "-n", "hw.usermem"], timeout=2).stdout.strip() or 0)
    vmstat = run(["vmstat", "-H"], timeout=3)
    swap_total = swap_used = 0
    for line in vmstat.stdout.splitlines():
        m = re.match(r"\s*(\d+)\s+(\d+)\s+(\d+)", line)
        if m and swap_total == 0:
            swap_total = int(m.group(1)) * 1024
            swap_used = int(m.group(2)) * 1024
    used = physmem - usermem
    return {
        "mem": {
            "total": physmem,
            "used": used,
            "free": usermem,
            "available": usermem,
        },
        "swap": {
            "total": swap_total,
            "used": swap_used,
            "free": max(0, swap_total - swap_used),
        },
    }


# ── Disks ────────────────────────────────────────────────────────────────────


def _build_mount_map() -> dict[str, tuple[str, str]]:
    """Parse mount -p → {device: (fstype, mountpoint)}."""
    mount_out = run(["mount", "-p"], timeout=3)
    mount_map: dict[str, tuple[str, str]] = {}
    for line in mount_out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            mount_map[parts[0]] = (parts[2], parts[1])
    return mount_map


def disks() -> dict[str, Any]:
    geom = run(["geom", "disk", "list"], timeout=5)
    df = run(["df", "-k"], timeout=3)
    mount_map = _build_mount_map()

    devs: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in geom.stdout.splitlines():
        line = line.strip()
        if line.startswith("Geom name:"):
            if current:
                devs.append(current)
            current = {"name": line.split(":", 1)[1].strip(), "smart": {}, "children": []}
        elif ":" in line and current:
            k, v = line.split(":", 1)
            current[k.strip().lower().replace(" ", "_")] = v.strip()
    if current:
        devs.append(current)

    for dev in devs:
        name = dev.get("name", "")
        if not name:
            continue
        dev["path"] = f"/dev/{name}"

        # fstype from mount table
        fstype, mpoint = mount_map.get(f"/dev/{name}", ("", ""))
        dev["fstype"] = fstype
        dev["mountpoints"] = [mpoint] if mpoint else []

        # partitions from gpart
        gp = run(["gpart", "show", "-p", name], timeout=3)
        for gline in gp.stdout.splitlines():
            gline = gline.strip()
            gm = re.match(r"^\s*\d+\s+\d+\s+(\S+)(?:\s+(\S+))?", gline)
            if gm:
                pname = gm.group(1)
                if pname == "-":
                    continue  # skip free space
                pfstype_raw = gm.group(2) or ""
                pfstype = pfstype_raw.rstrip(")")
                pfstype_m, pmpoint = mount_map.get(f"/dev/{pname}", (pfstype, ""))
                dev["children"].append({
                    "name": pname,
                    "fstype": pfstype or pfstype_m,
                    "mountpoints": [pmpoint] if pmpoint else [],
                })

        # SMART — smartctl may return exit code 1 for non-fatal warnings,
        # so check stdout for valid JSON rather than exit code.
        sr = run(["/usr/local/sbin/smartctl", "-a", "-j", f"/dev/{name}"], timeout=5)
        if sr.stdout:
            try:
                sd = json.loads(sr.stdout)
                dev["smart"] = {
                    "temp": sd.get("temperature", {}).get("current"),
                    "passed": sd.get("smart_status", {}).get("passed"),
                    "model": sd.get("model_name"),
                    "serial": sd.get("serial_number"),
                    "firmware": sd.get("firmware_version"),
                    "power_on_hours": sd.get("power_on_time", {}).get("hours"),
                }
            except json.JSONDecodeError:
                pass

    return {"blockdevices": devs, "df": lines(df.stdout)}


def smart_details(name: str) -> dict[str, Any]:
    """Full SMART data for one explicitly named existing character device."""
    device, error = _device_path(name)
    if device is None:
        return {"error": error or "invalid device name"}
    sr = run(["/usr/local/sbin/smartctl", "-a", "-j", device], timeout=10)
    if not sr.stdout:
        return {"error": "smartctl failed"}
    try:
        data = json.loads(sr.stdout)
    except json.JSONDecodeError:
        return {"error": "invalid JSON"}

    attrs = []
    for attr in data.get("ata_smart_attributes", {}).get("table", []):
        attrs.append({
            "id": attr.get("id"),
            "name": attr.get("name"),
            "value": attr.get("value"),
            "worst": attr.get("worst"),
            "thresh": attr.get("thresh"),
            "raw": attr.get("raw", {}).get("value"),
            "failed": attr.get("when_failed", ""),
        })

    return {
        "model": data.get("model_name"),
        "serial": data.get("serial_number"),
        "firmware": data.get("firmware_version"),
        "temp": data.get("temperature", {}).get("current"),
        "passed": data.get("smart_status", {}).get("passed"),
        "power_on_hours": data.get("power_on_time", {}).get("hours"),
        "sectors": data.get("user_capacity", {}).get("bytes"),
        "attributes": attrs,
    }


_DEVICE_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,31}")
_CRITICAL_MOUNTPOINTS = {"/", "/boot", "/boot/efi", "/usr", "/var"}


def _device_path(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or _DEVICE_NAME_RE.fullmatch(value) is None:
        return None, "invalid device name"
    path = Path("/dev") / value
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None, "device does not exist"
    except OSError as exc:
        return None, f"cannot inspect device: {exc}"
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISCHR(metadata.st_mode):
        return None, "device path is not a character device"
    return str(path), None


def _protected_device_paths() -> set[str]:
    protected: set[str] = set()
    mounts = run(["mount", "-p"], timeout=3)
    if mounts.ok:
        for line in mounts.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] in _CRITICAL_MOUNTPOINTS and parts[0].startswith("/dev/"):
                protected.add(parts[0])
    pools = run(["zpool", "status", "-P"], timeout=5)
    if pools.ok:
        for token in pools.stdout.split():
            if token.startswith("/dev/"):
                protected.add(token.rstrip("*"))
    return protected


def _same_disk(left: str, right: str) -> bool:
    def base(path: str) -> str:
        name = Path(path).name
        return re.sub(r"(?:p\d+|s\d+[a-h]?)$", "", name)
    return left == right or base(left) == base(right)


def smart_test(name: str, test_type: str = "short") -> dict[str, Any]:
    """Trigger a SMART self-test on one existing /dev character device."""
    device, error = _device_path(name)
    if device is None:
        return {"ok": False, "error": error or "invalid device name"}
    if test_type not in ("short", "long", "conveyance"):
        return {"ok": False, "error": "invalid test type"}
    r = run(["/usr/local/sbin/smartctl", "-t", test_type, device], timeout=10)
    return {"ok": r.ok, "output": r.stdout.strip(), "error": "" if r.ok else (r.stderr or r.error or "SMART test failed")}


# ── ZFS ──────────────────────────────────────────────────────────────────────


def zfs_pools() -> dict[str, Any]:
    """Return ZFS pool status and dataset usage."""
    status = run(["zpool", "status"], timeout=5)
    pools: list[dict[str, Any]] = []
    current_pool: dict[str, Any] | None = None
    for line in status.stdout.splitlines():
        line = line.strip()
        if line.startswith("pool:"):
            current_pool = {"name": line.split(":", 1)[1].strip(), "state": "", "vdevs": [], "errors": ""}
        elif line.startswith("state:") and current_pool:
            current_pool["state"] = line.split(":", 1)[1].strip()
        elif current_pool and line and not line.startswith(("pool", "state", "status", "action", "see", "config", "NAME", "errors", "---")):
            parts = line.split()
            if len(parts) >= 2:
                current_pool["vdevs"].append({"name": parts[0], "state": parts[1]})
        elif line.startswith("errors:") and current_pool:
            current_pool["errors"] = line.split(":", 1)[1].strip()
    if current_pool:
        pools.append(current_pool)

    zfs_list = run(["zfs", "list", "-H", "-o", "name,used,avail,refer,mountpoint,type"], timeout=5)
    datasets = []
    for line in zfs_list.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 6:
            datasets.append({
                "name": parts[0],
                "used": parts[1],
                "avail": parts[2],
                "refer": parts[3],
                "mountpoint": parts[4],
                "type": parts[5],
            })

    return {"pools": pools, "datasets": datasets}


# ── Disk I/O ─────────────────────────────────────────────────────────────────


def disk_io() -> dict[str, Any]:
    """Per-disk I/O stats from iostat."""
    r = run(["/usr/sbin/iostat", "-d", "-c", "1", "-w", "1"], timeout=5)
    devices = []
    lines = [l.rstrip() for l in r.stdout.splitlines() if l.strip()]
    # Format: line0=device names, line1=KB/t tps MB/s headers, line2=values
    if len(lines) < 3:
        return {"devices": devices}
    names = lines[0].split()
    vals = lines[2].split()
    # Each disk takes 4 fields: name kb_t tps mb_s
    for i in range(0, len(vals), 4):
        if i + 3 >= len(vals):
            break
        try:
            devices.append({
                "name": names[i // 4] if i // 4 < len(names) else f"disk{i//4}",
                "kb_per_t": float(vals[i]),
                "tps": int(vals[i + 1]),
                "mb_per_s": float(vals[i + 2]),
            })
        except (ValueError, IndexError):
            pass
    return {"devices": devices}


# ── Mount / Unmount ──────────────────────────────────────────────────────────


def disk_mount(device: str) -> dict[str, Any]:
    path, error = _device_path(device)
    if path is None:
        return {"ok": False, "error": error or "invalid device"}
    if any(_same_disk(path, protected) for protected in _protected_device_paths()):
        return {"ok": False, "error": "refusing to mount a system or active pool device"}
    mount_map = _build_mount_map()
    if path in mount_map:
        return {"ok": False, "error": f"device is already mounted at {mount_map[path][1]}"}
    r = run(["mount", path], timeout=10)
    return {"ok": r.ok, "output": r.stdout.strip(), "error": "" if r.ok else (r.stderr or r.error or "mount failed")}


def disk_unmount(device: str) -> dict[str, Any]:
    path, error = _device_path(device)
    if path is None:
        return {"ok": False, "error": error or "invalid device"}
    mount_map = _build_mount_map()
    mounted = mount_map.get(path)
    if mounted is None:
        return {"ok": False, "error": "device is not mounted"}
    if mounted[1] in _CRITICAL_MOUNTPOINTS or any(_same_disk(path, protected) for protected in _protected_device_paths()):
        return {"ok": False, "error": "refusing to unmount a system or active pool device"}
    r = run(["umount", path], timeout=10)
    return {"ok": r.ok, "output": r.stdout.strip(), "error": "" if r.ok else (r.stderr or r.error or "unmount failed")}
