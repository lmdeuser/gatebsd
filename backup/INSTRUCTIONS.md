# Backup Instructions

## Web UI Configuration Backup

Use the GateBSD Backups view to create, diff, restore, and delete configuration snapshots. Snapshots include only allowlisted configuration files, not disk images.

Restore automatically creates a safety backup and executes a compensating rollback on partial failure. Do not modify `/var/backups/gatebsd` manually during an operation.

## ZFS Image Backup

Run as `root` on FreeBSD:

```sh
/usr/local/sbin/gatebsd-backup.sh
```

Output path and source dataset are configured via `GATEBSD_IMAGE_BACKUP_DIR` and `GATEBSD_ROOT_DATASET`. The backup root must be a dedicated safe directory, and the source dataset must exist.

Before writing, the script estimates stream size via `zfs send -nvP` and requires an additional 10 GiB free reserve (configurable via `GATEBSD_IMAGE_BACKUP_MIN_FREE_KIB` in KiB). After verification succeeds, one latest image is retained by default (`GATEBSD_IMAGE_BACKUP_KEEP`, default `1`). Older images are pruned only after the new image is published and verified. Do not store local images inside the root ZFS dataset (`zroot/ROOT/default`), or subsequent `zfs send` streams will recursively include prior `.img.gz` files; after copying backups off-host, local images can be pruned with `gatebsd-agentctl image-backup-prune 0`.

## Disaster Restore

`backup/gatebsd-restore.sh` overwrites the target disk. Before running:

1. place the verified `.img.gz` on read-only or root-controlled media;
2. optionally prepare a configuration `.tar.gz` containing only supported paths;
3. boot into a compatible FreeBSD rescue environment;
4. set `BACKUP_FILE` and optionally `CONFIG_BACKUP_FILE`;
5. verify the target disk device name before typing `yes`.

The helper rejects unsafe device names, group/world-writable images, corrupted streams, and unsafe archive entries before performing any destructive step.
