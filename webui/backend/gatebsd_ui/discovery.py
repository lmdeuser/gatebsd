from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import time
from pathlib import Path
from typing import Any

from . import paths, routing
from .command import lines, run
from .fsutil import atomic_write_text, read_regular_bytes
from .redact import redact_text


def _file_summary(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(path, flags)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            return {"path": str(path), "exists": True, "error": "not a regular file"}
        sample_bytes = os.read(fd, min(20000, metadata.st_size))
        sample = redact_text(sample_bytes.decode("utf-8", errors="replace"))
        return {"path": str(path), "exists": True, "size": metadata.st_size,
                "mtime": int(metadata.st_mtime), "sample": sample}
    except FileNotFoundError:
        return {"path": str(path), "exists": False}
    except OSError as exc:
        return {"path": str(path), "exists": True, "error": str(exc)}
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def scan() -> dict[str, Any]:
    interfaces = run(["ifconfig", "-a"], timeout=5)
    services = run(["service", "-e"], timeout=5)
    pf_info = run(["pfctl", "-s", "info"], timeout=4)
    pf_nat = run(["pfctl", "-s", "nat"], timeout=4)
    pf_tables = run(["pfctl", "-s", "Tables"], timeout=4)
    awg = run(["awg", "show"], timeout=5)
    version = run(["freebsd-version", "-ku"], timeout=3)
    payload: dict[str, Any] = {
        "schema": 2,
        "generated_at": int(time.time()),
        "hostname": socket.gethostname(),
        "freebsd": version.stdout,
        "network_changes": False,
        "source_of_truth": "FreeBSD",
        "interfaces": interfaces.stdout,
        "services_enabled": lines(services.stdout),
        "routes": routing.route_table(),
        "pf": {"info": pf_info.stdout, "nat": lines(pf_nat.stdout), "tables": lines(pf_tables.stdout)},
        "awg": redact_text(awg.stdout if awg.ok else awg.stderr),
        "split_tunnel": routing.split_tunnel(),
        "configs": {name: _file_summary(path) for name, path in paths.CONFIG_FILES.items()},
    }
    return payload


def save_scan(path: Path | None = None) -> dict[str, Any]:
    target = path or paths.DISCOVERY_JSON
    payload = scan()
    atomic_write_text(
        target,
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        mode=0o600,
        preserve_metadata=target.exists(),
    )
    return {"path": str(target), "data": payload}


def load(path: Path | None = None) -> dict[str, Any]:
    target = path or paths.DISCOVERY_JSON
    try:
        raw, _metadata = read_regular_bytes(target, max_size=4 * 1024 * 1024)
        data = json.loads(raw.decode("utf-8", errors="strict"))
        return {"path": str(target), "data": data if isinstance(data, dict) else {}}
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"path": str(target), "data": {}}


def import_existing() -> dict[str, Any]:
    imported = save_scan(paths.IMPORT_JSON)
    return {"imported": True, **imported}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a GateBSD discovery snapshot")
    parser.add_argument("output", nargs="?", default=str(paths.DISCOVERY_JSON))
    args = parser.parse_args()
    target = Path(args.output)
    if not target.is_absolute():
        parser.error("output path must be absolute")
    result = save_scan(target)
    print(result["path"])


if __name__ == "__main__":
    main()
