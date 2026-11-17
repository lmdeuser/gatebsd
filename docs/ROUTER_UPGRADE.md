# Upgrading GateBSD on a Router

Status: Active operational runbook aligned with `sbin/gatebsd-upgrade`.
This document covers GateBSD package upgrades, not FreeBSD base OS upgrades or kernel module replacements, which require a separate maintenance plan and reboot.

## How the Installer Works

`/usr/local/sbin/gatebsd-upgrade` accepts a single absolute path to a root-owned `.pkg` file that is not writable by group or others. It verifies file stability and package metadata, reserves free space (`GATEBSD_UPGRADE_MIN_FREE_KIB`, default `1048576` KiB = 1 GiB on both runtime and backup filesystems), acquires upgrade and config writer locks, runs `gatebsd-config-guard`, and snapshots:

- the currently installed package archive;
- allowlisted configuration files;
- the SQLite state database;
- the list of services running prior to the upgrade.

After `pkg add -f`, only previously running services are restarted. A health gate verifies the installed version, storage schema migration, supervised services, and local HTTP/HTTPS endpoints. On any failure, the installer restores the previous package, configurations, and database, then repeats the health gate on the prior version. Rollback artifacts live in `/var/backups/gatebsd/upgrade-*`; after a successful health gate, at most `GATEBSD_UPGRADE_BACKUP_KEEP` (default `3`) recent `upgrade-*` directories are retained while protecting the current transaction directory.

Newly installed dependency packages are intentionally not removed on rollback because other packages on the host may share them. Local rollback does not replace an off-device configuration backup.

## 1. Preparation

Ensure a maintenance window and local console/recovery access before upgrading a production gateway. Do not start an upgrade while WAN/VPN links are unhealthy, configurations are broken, or disk space is exhausted.

Check current state as `root` (or via allowlisted `gatebsd-agentctl` subcommands `disk-usage`, `pkg-dry-run`, `be-destroy gatebsd-<name>`, and `image-backup-prune [0..3]`):

```sh
pkg query '%n-%v' gatebsd
pkg rquery -r gatebsd-releases '%n-%v' gatebsd
pkg upgrade -n
freebsd-version -ku
df -h / /var/tmp
```

Review `pkg upgrade -n` before proceeding; never replace inspection with a blind `pkg upgrade -y`. Create an off-device configuration backup via the Web UI.

If management TLS uses DuckDNS, verify `/usr/local/etc/gatebsd/duckdns.conf` is a root-owned regular file with mode `0600` containing `GATEBSD_TLS_DOMAIN` and `DuckDNS_Token` (see `duckdns.conf.sample`).

## 2. Fetching and Verifying the Candidate Package

Fetch the package from the signed release repository:

```sh
pkg fetch -r gatebsd-releases -o /var/tmp gatebsd
```

The `gatebsd-releases` repository places the package directly at `/var/tmp/gatebsd-<version>.pkg`. Calling `gatebsd-agentctl pkg-fetch` additionally prunes downloaded `gatebsd-*.pkg` caches in `/var/tmp` and `/var/tmp/All` down to the two newest files.

HTTP transport does not establish authenticity; trust comes from the repository signature and pinned public key documented in [PKG_REPOSITORY.md](PKG_REPOSITORY.md). Never install packages fetched from arbitrary URLs.

Verify name, version, and digest before installation:

```sh
pkg query -F /var/tmp/gatebsd-<version>.pkg '%n %v %o %p'
sha256 /var/tmp/gatebsd-<version>.pkg
```

## 3. Installation

Invoke the upgrader directly as `root` (or via `gatebsd-agentctl gatebsd-upgrade ...`) without holding an interactive stdout pipe open, as restarted daemons may inherit open file descriptors:

```sh
/usr/local/sbin/gatebsd-upgrade /var/tmp/gatebsd-<version>.pkg
```

Do not stop `cron` or restart services manually outside the installer transaction.

## 4. Verification

```sh
pkg query '%n-%v' gatebsd
service gatebsd onestatus
service gatebsd_failover onestatus
service nginx onestatus
service unbound onestatus
/usr/local/sbin/gatebsd-config-guard
cat /var/run/gatebsd/watchdog.json
```

Confirm user traffic flows from a LAN client and verify a fresh VPN handshake rather than relying solely on interface existence. If the health gate triggered a rollback, preserve the output and rollback directory before retrying.
