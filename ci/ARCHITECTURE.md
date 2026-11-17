# GateBSD Build and Verification Architecture

## Python

`ci/resolve-python.sh` selects a single versioned interpreter from `LOCALBASE/bin`, validates the supported version, required standard library modules, and `sqlite3`, and emits shell-safe package flavor metadata. The source tree does not pin a Python minor version.

`ci/build.sh` embeds the resolved binary into `/usr/local/libexec/gatebsd-python`; all packaged runtime entrypoints invoke this launcher. `ci/verify-python-tree.sh` checks exact source/stage Python file parity and imports the full backend; `gatebsd_ui.integrity` enforces the contract of `11` critical split modules.

## Package

The package builder extracts dependency versions and origins from the installed FreeBSD package database, builds a staging tree, strips Python bytecode caches, verifies no direct versioned Python invocations remain, and generates package manifests. Post-install executes fail-closed permission migration on existing root-owned configurations, separates privileged routing state into `/var/db/gatebsd-system`, and repeats the import smoke test before starting services.

## Upgrade Contract

`gatebsd-upgrade` verifies an immutable private copy of the input `.pkg` through both reader APIs (`pkg info -F` and `pkg query -F`), validates identity/origin/prefix/version and the `GATEBSD_UPGRADE_MIN_FREE_KIB` reserve (1 GiB default), writes rollback artifacts, installs missing dependencies, runs `pkg add -f`, restarts only previously active services, and runs a complete health gate before pruning old `upgrade-*` directories to `GATEBSD_UPGRADE_BACKUP_KEEP` (default `3`). On failure, package, configs, and database are restored.

## CI Boundary

Repository CI scripts provide infrastructure checks for the FreeBSD build environment and do not replace local unit/static analysis. Live PF, FIB routing, `rc.d`, package installation, ZFS, and hardware UPS checks require FreeBSD execution.
