# GateBSD

GateBSD is a closed-loop FreeBSD network gateway appliance with a split-privilege architecture: an unprivileged Web UI, a root-privileged local socket agent, and specialized writers and supervisors for PF, AmneziaWG, Unbound DNS, ISC DHCP, multi-WAN failover, backups, and transactional package upgrades.

Documentation index: [docs/README.md](docs/README.md) · [User Guide](docs/USER_GUIDE.md)

## Design Contract

GateBSD is built around dual-path delivery:

1. Bare-metal installation from an image and package repository bootstrap.
2. In-field upgrades via signed `.pkg` archives.

Both paths must converge on identical device state (file contents, ownership, and permissions) for any given `VERSION`.

Key structural invariants verified by the test suite:

- **One managed file, one writer**: Configuration and deployment targets have a single canonical writer (`tests/test_one_writer_per_managed_file.py`).
- **Dormant configuration defense**: `sbin/gatebsd-config-guard` runs native validators (`pfctl -nf`, `dhcpd -q -t -cf`, `unbound-checkconf`, `nginx -t -c`) before service restarts so broken files on disk cannot remain masked by valid in-memory state.
- **Defect-reintroduction testing**: Regression tests execute real scripts in sandboxed temporary roots and reintroduce historical defects to verify detection (`tests/test_ci_build_detach.py`, `tests/test_release_integrity.py`).
- **Source provenance**: `SOURCE_MANIFEST.sha256` binds every tracked file via SHA-256 and refuses unstaged edits (`scripts/build-source-manifest.sh`).

## Privilege Separation

- The Web UI runs under the dedicated unprivileged account `gatebsd` (`/usr/sbin/nologin`).
- The privileged agent listens on `/var/run/gatebsd/agent.sock` (`root:gatebsd`, mode `0660`) and enforces `AGENT_ALLOWED_GET` / `AGENT_ALLOWED_POST` route allowlists.
- By default the Web UI binds only to `127.0.0.1:8080` behind `nginx`.
- In `system` auth mode, login is restricted to `root` or members of `wheel` (configurable via `gatebsd_admin_group`). Unprivileged local users do not receive root API access.
- Authentication is mandatory and fails closed. Mutating POST endpoints require same-origin JSON requests; session tokens are HMAC-signed with epoch and persistent revocation support.
- SSH accepts public keys only (`AllowGroups wheel gatebsd-agent`). Legacy global `AllowUsers` directives in `/etc/ssh/sshd_config` are retired safely by `gatebsd-config-migrate` while preserving `Match` blocks.
- Automated maintenance uses `gatebsd-agent` without an arbitrary root shell: `sudo` permits only `/usr/local/sbin/gatebsd-agentctl` with allowlisted actions (`service-status`, `disk-usage`, inactive `be-destroy`, `image-backup-prune`, `pkg-fetch` cache pruning, and `gatebsd-upgrade`).

## Subsystems

### AmneziaWG & Split Tunneling

Peer operations (`peer add`, `peer remove`, `key rotate`) live in `webui/backend/gatebsd_ui/writers/vpn.py`. They invoke `awg`, validate keys and duplicates, acquire inter-process locks, create backups, and publish configurations atomically while preserving existing line endings, ownership, and file modes.

Persistent routing exceptions are stored in `/usr/local/etc/amnezia/direct-exceptions.conf` and `/usr/local/etc/amnezia/vpn_override.table` with IDNA/Punycode normalization and shared Cloudflare CDN IPv4 overlap warnings for `direct` rules. Scheduled route updates merge operator exceptions via `gatebsd_ui.vpn_policy merge`.

### PF, DHCP, and Unbound DNS

Writers validate candidate configurations with native FreeBSD tools, hold exclusive locks across the full read-modify-apply-publish cycle, stage writes on the destination filesystem with `O_NOFOLLOW` and `fsync`, and roll back on runtime failures. Firewall commits run a static LAN lockout check (`check_management_access`) and auto-revert after `PF_CONFIRM_TIMEOUT = 120` seconds if unconfirmed. Targeted split-DNS overrides reside in `/usr/local/etc/gatebsd/split-dns.conf`.

### Multi-WAN Failover, VPN, and Policy Routes

`gatebsd-watchdog.sh`, `gatewayctl`, `gatebsd-route-op`, and `ru-routes.sh` serialize route transitions on a shared route lock. Default route switches, VPN endpoint pinning, and policy route updates run as snapshot-and-rollback transactions; `gatebsd-route-op` caches the last resolved VPN endpoint IP in `/var/db/gatebsd-system/awg-endpoint.cache` for DNS-free cold starts. Large policy route tables load asynchronously under `daemon(8)` so boot and emergency failover are never blocked.

### Adblock & TLS

`gatebsd-adblock-update.sh` bounds payload size, parses host entries strictly, validates via `unbound-checkconf`, publishes atomically, and restores the previous working blocklist if reload fails.

`gatebsd-renew-ssl` checks TLS certificates within a 30-day renewal window using DNS-01 ACME (`acme.sh`), validates candidate hostname, expiry, and key match, and rolls back on `nginx` reload errors. Nginx caps request bodies at 1 MiB and rate-limits API traffic.

### Backups & Transactional Upgrades

1. **Configuration snapshots** (`webui/backend/gatebsd_ui/backup.py`): staged atomically under `/var/backups/gatebsd` (`0700`) with a 16 MiB per-file limit, 64 MiB aggregate limit, and bounded retention (`10` copies / `512 MiB`), redacting secrets in diffs.
2. **Full ZFS boot-environment images** (`sbin/gatebsd-backup.sh`): streams compressed ZFS snapshots without stopping routing, enforces a `10 GiB` reserve, verifies `gzip -t` and `zstreamdump`, and prunes to `GATEBSD_IMAGE_BACKUP_KEEP=1` by default. `backup/gatebsd-restore.sh` validates archives and streams before prompting for destructive disk operations.
3. **Package upgrades** (`sbin/gatebsd-upgrade`): copies root-owned `.pkg` files to private staging, checks SHA-256 stability, cross-checks metadata via both `pkg info -F` and `pkg query -F`, requires `GATEBSD_UPGRADE_MIN_FREE_KIB` (`1 GiB` reserve), snapshots rollback artifacts, restarts only previously active services, runs a full health gate, and rolls back package, config, and SQLite state on any failure.

## Zero-Dependency Runtime

- **Backend**: Python standard library only (`http.server`, `sqlite3`, `fcntl`, `socketserver`). No `pip` packages.
- **Frontend**: Static HTML, CSS, and vanilla JavaScript with vendored `xterm.js` and `lucide.min.js`. No Node/npm build pipeline.
- **Python resolution**: `ci/resolve-python.sh` detects the installed FreeBSD Python interpreter and emits `/usr/local/libexec/gatebsd-python`; `ci/verify-python-tree.sh` checks source-to-stage `.py` parity and `gatebsd_ui.integrity` verifies imports across all modules including the `11` critical split modules.

## Verification

Run the cross-platform syntax, integrity, and unit test checks locally:

```sh
PYTHONPATH=webui/backend python3 -m unittest discover -s tests -p "test_*.py"
```

Tests requiring live FreeBSD kernel features (`pf`, `setfib`, `rc.d`, `pkg`, `ZFS`) are automatically skipped on Linux and executed on the FreeBSD build stand.

## Limitations

- Full package builds, `rc.d` integration, ZFS image restore, UPS monitoring, and live `pf`/`setfib` routing require a FreeBSD environment.
- Local SHA-256 verification during `gatebsd-upgrade` protects against TOCTOU swaps; cryptographic origin trust depends on `pkg(8)` repository signing (`gatebsd-stand.pub`).
- Third-party dependency packages installed prior to an upgrade are not automatically removed during rollback because other packages may share them.
- GateBSD does not manage Secure Boot enrollment, EFI keys, firmware updates, or PXE boot.
