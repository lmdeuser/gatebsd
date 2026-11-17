"""Detached package-maintenance entry point."""
from __future__ import annotations

from .writers.system import pkg_upgrade


def main() -> int:
    status, _payload = pkg_upgrade()
    return 0 if status == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
