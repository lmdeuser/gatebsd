"""Runtime package-integrity checks for the GateBSD Python backend.

The package builder compares every Python source path in the source tree with
its staged counterpart.  This module supplies the second half of that check:
it imports every installed GateBSD module and enforces the critical split-out
module set that must never disappear from a package.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterable


# These are the eleven critical modules introduced by the backend split.  The
# verifier also imports every other module it discovers, so this list is a
# minimum compatibility contract rather than a complete package manifest.
CRITICAL_SPLIT_MODULES: tuple[str, ...] = (
    "gatebsd_ui.adblock",
    "gatebsd_ui.auth",
    "gatebsd_ui.fsutil",
    "gatebsd_ui.lockrun",
    "gatebsd_ui.passwd_cli",
    "gatebsd_ui.pkg_maintenance",
    "gatebsd_ui.recovery",
    "gatebsd_ui.resolver",
    "gatebsd_ui.ru_table",
    "gatebsd_ui.writers.dhcp",
    "gatebsd_ui.writers.dns",
)


def discovered_modules() -> tuple[str, ...]:
    """Return every importable module shipped below :mod:`gatebsd_ui`."""

    package = importlib.import_module("gatebsd_ui")
    names = {"gatebsd_ui"}
    package_path = getattr(package, "__path__", None)
    if package_path is None:
        raise RuntimeError("gatebsd_ui is not an importable package")
    names.update(
        item.name
        for item in pkgutil.walk_packages(package_path, prefix="gatebsd_ui.")
    )
    return tuple(sorted(names))


def verify_runtime_modules(
    required: Iterable[str] = CRITICAL_SPLIT_MODULES,
) -> tuple[str, ...]:
    """Import all installed modules and reject a partial backend package."""

    modules = discovered_modules()
    installed = set(modules)
    missing = sorted(set(required) - installed)
    if missing:
        raise RuntimeError("missing required GateBSD modules: " + ", ".join(missing))

    failures: list[str] = []
    for name in modules:
        try:
            importlib.import_module(name)
        except Exception as exc:  # pragma: no cover - exercised by package smoke tests
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
    if failures:
        raise RuntimeError("GateBSD module import failures: " + "; ".join(failures))
    return modules


def main() -> int:
    modules = verify_runtime_modules()
    print(
        f"GateBSD Python backend verified: {len(modules)} modules, "
        f"{len(CRITICAL_SPLIT_MODULES)} critical split modules"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
