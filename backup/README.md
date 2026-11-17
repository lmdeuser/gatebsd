# GateBSD Backup and Restore

## Configuration Snapshots via Web API

Implementation: `webui/backend/gatebsd_ui/backup.py`.

- Root directory: `/var/backups/gatebsd`, mode `0700`.
- Snapshots are staged under a hidden directory and published atomically with a single `rename` only after all copies succeed.
- Only allowlisted GateBSD configuration paths are permitted.
- Per-file limit: 16 MiB; aggregate snapshot/restore limit: 64 MiB.
- Requires free space for the maximum snapshot size plus a 64 MiB reserve before writing.
- Retention: at most 10 snapshots and 512 MiB total; oldest snapshots are pruned while protecting the current copy.
- Reads open with `O_NOFOLLOW` and verify file metadata stability before/after reading.
- The sole allowed symlink exception is the active `awg0.conf` pointing to a regular `.conf` inside the managed Amnezia directory.
- Restore acquires the global mutation lock and the same writer locks held by PF/DHCP/DNS/AWG writers.
- Creates a safety backup before modifying live files, writes each file atomically, and rolls back partially applied changes before releasing locks on error.
- Snapshot diffs redact secrets and private keys.

## Full ZFS Boot-Environment Image

`sbin/gatebsd-backup.sh` exports a gzip-compressed ZFS stream of the active boot environment without stopping GateBSD. Before writing, it estimates stream size and enforces a 10 GiB free-space reserve. Pipeline exit status is verified via a private FIFO, followed by `gzip -t` and `zstreamdump`. The output file is published atomically; by default, only the single newest image is retained (`GATEBSD_IMAGE_BACKUP_KEEP=1`, sorted by mtime), and pruning to `0..3` copies is exposed via `gatebsd-agentctl image-backup-prune`.

`backup/gatebsd-restore.sh` is a destructive disaster-recovery helper. It verifies the gzip/ZFS stream, copies inputs to private staging, validates any optional config archive against path-traversal, symlinks, duplicates, and allowlist rules, and only then prompts for the target disk and explicit confirmation.

## Package Upgrade Rollback Artifacts

`sbin/gatebsd-upgrade` writes rollback artifacts under `/var/backups/gatebsd/upgrade-*`. Before unpacking, it checks `GATEBSD_UPGRADE_MIN_FREE_KIB` (`1048576` KiB = 1 GiB reserve on runtime and backup filesystems). After a passing health gate, at most `GATEBSD_UPGRADE_BACKUP_KEEP` (`3` by default) recent `upgrade-*` directories are kept while protecting the current transaction.
