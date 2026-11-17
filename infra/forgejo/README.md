# Local Forgejo

Forgejo runs on `stand-bsd` using the FreeBSD `forgejo15` package and SQLite.
This is appropriate for the small local installation and gives a consistent
ZFS snapshot containing repositories, Actions metadata and the database.

Public endpoints:

- Web and HTTPS Git: `https://git.example.lan/forgejo/`
- Forgejo SSH: `ssh://git@git.example.lan:2222/OWNER/REPOSITORY.git`

The application listens only on `127.0.0.1:3000`; nginx terminates TLS. Open
registration, federation, external avatars and public anonymous repository
views are disabled. Generated secrets and the administrator bootstrap password
are not stored in this directory.

The local CA certificate must be installed in the trust store of `ci-master`
and administrator workstations before credentials or runner tokens are sent to
Forgejo.

## Backup space controls

`backup.sh` estimates the logical dataset size with `zfs list -p -o refer` before
stopping Forgejo. It refuses to start unless the backup filesystem also retains
10 GiB of free space. Override the reserve with `FORGEJO_BACKUP_MIN_FREE_KIB`
for a deliberately sized test or installation.

Only the newest `FORGEJO_BACKUP_KEEP` (default `3`) Forgejo dumps, encrypted
secrets archives, checksums, and automatic `@backup-*` ZFS snapshots are
retained after a successful backup. `FORGEJO_BACKUP_ROOT`,
`FORGEJO_BACKUP_DATASET` and `FORGEJO_BACKUP_LOCK` have production defaults and
exist to make the real script testable without touching the service.
