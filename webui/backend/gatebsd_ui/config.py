"""Centralized GateBSD runtime configuration.

All paths and limits are overridable through GATEBSD_* environment variables.
"""
from __future__ import annotations

import os
from pathlib import Path


def env_int(name: str, default: int, minimum: int = 1, maximum: int | None = None) -> int:
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    value = max(value, minimum)
    return min(value, maximum) if maximum is not None else value


DB_DIR = Path(os.environ.get("GATEBSD_DB_DIR", "/var/db/gatebsd"))
RUN_DIR = Path(os.environ.get("GATEBSD_RUN_DIR", "/var/run/gatebsd"))
ETC_DIR = Path(os.environ.get("GATEBSD_ETC_DIR", "/usr/local/etc/gatebsd"))
AGENT_SOCKET = os.environ.get("GATEBSD_SOCKET", str(RUN_DIR / "agent.sock"))
SAMPLE_INTERVAL = env_int("GATEBSD_SAMPLE_INTERVAL", 60, 5, 86400)
AGENT_TIMEOUT = env_int("GATEBSD_AGENT_TIMEOUT", 180, 1, 900)
MAX_AGENT_REQUEST = env_int("GATEBSD_MAX_AGENT_REQUEST", 1024 * 1024, 4096, 16 * 1024 * 1024)
MAX_AGENT_RESPONSE = env_int("GATEBSD_MAX_AGENT_RESPONSE", 8 * 1024 * 1024, 4096, 64 * 1024 * 1024)
