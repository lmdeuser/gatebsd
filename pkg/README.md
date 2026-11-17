# GateBSD Packaging

## Building

`ci/build.sh` invokes `ci/resolve-python.sh` to select the installed versioned Python interpreter without pinning a minor version in the source tree. The selected interpreter must support project syntax, required standard library modules, and `sqlite3`.

The builder generates `/usr/local/libexec/gatebsd-python`, package metadata, required dependency lists, `rc.d` scripts, and sample configurations. Runtime scripts must not call versioned Python binaries directly. Prior to `pkg create`, `ci/verify-python-tree.sh` requires exact `.py` parity between source and stage trees, runs `compileall` outside staging, and imports every module through the generated launcher.

## Local Package Verification

`gatebsd-upgrade` validates a private copy of the candidate package:

- regular non-symlink file, owned by `root`, no group/world write bits;
- size cap (`512 MiB` default) and SHA-256 stability before/after copying;
- cross-verification via both `pkg info -F` and `pkg query -F`;
- `name=gatebsd`, `origin=local/gatebsd`, `prefix=/usr/local`;
- safe version characters and valid dependency names.

These checks defend the local upgrade transaction against TOCTOU swaps and malformed archives; cryptographic origin trust comes from `pkg(8)` repository signatures.

## Upgrade and Rollback

Before running `pkg add -f`, `gatebsd-upgrade` archives:

1. the currently installed `gatebsd-*.pkg`;
2. allowlisted configuration files;
3. `/var/db/gatebsd/state.db` if present;
4. the list of services running prior to the upgrade.

Missing dependencies are installed before the GateBSD package; free space is checked against `GATEBSD_UPGRADE_MIN_FREE_KIB` (`1048576` KiB = 1 GiB default). After installation, only previously running services are restarted, followed by a health gate checking version, storage migration, services, and local HTTP/HTTPS endpoints. Old `/var/backups/gatebsd/upgrade-*` directories are pruned down to `GATEBSD_UPGRADE_BACKUP_KEEP` (`3` by default) while protecting the active transaction directory.

On error, the previous package, configuration files, and database are restored and the health gate is re-run against the old version. Newly added third-party dependencies are intentionally preserved during rollback.

## FreeBSD Verification

Actual `.pkg` builds, installation, `rc.d` startup, ownership checks, dependency resolution, and rollback must be verified on a FreeBSD system.
