# GateBSD Documentation

## Operations & Guides

- [User Guide](USER_GUIDE.md) — router traffic flows, subsystems, and administration.
- [Technical Specification](SPECIFICATION.md) — full architecture, data flow, and why the VPN channel stays fast, loop-free, and reliable.
- [Package Upgrade Runbook](ROUTER_UPGRADE.md) — pre-flight checks, `gatebsd-upgrade`, health gate, and rollback.
- [Package Repositories](PKG_REPOSITORY.md) — package sources, key pinning, and trust boundary.

## Architecture & Build

- [CI & Build Infrastructure](CI_INFRASTRUCTURE.md) — isolated FreeBSD build stand and pipeline topology.
- [Backup and Restore](../backup/README.md) — configuration snapshots and full ZFS boot-environment images.
- [Packaging](../pkg/README.md) — package metadata, upgrade contract, and stage checks.
- [CI Verification Boundary](../ci/ARCHITECTURE.md) — Python tree checks and FreeBSD runtime boundary.
