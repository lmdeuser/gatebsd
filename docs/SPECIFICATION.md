# GateBSD Technical Specification

This document describes how GateBSD works internally and why its routing, DNS, tunnel-management, and supervision layers together produce a stable, low-latency, leak-resistant VPN channel across the whole LAN.

All examples below use placeholder networks (`10.88.0.0/24`), sample interfaces (`re1`, `ng0`, `ue0`, `awg0`), and synthetic hosts (`vpn.example.invalid`, `mirror.example.lan`) corresponding to the repository defaults in [etc/amnezia/gateway.conf.sample](../etc/amnezia/gateway.conf.sample) and [etc/pf.conf.sample](../etc/pf.conf.sample).

---

## 1. System Topology and Privilege Boundaries

GateBSD turns a dedicated FreeBSD machine into a headless network gateway separating unprivileged presentation from privileged network mutation:

```text
LAN hosts (10.88.0.0/24 on re1)
   │
   ├── DNS (:53 TCP/UDP) ──▶ pf rdr ──▶ Unbound (10.88.0.1:53)
   │   (DoT :853 blocked; DoH canary NXDOMAIN)
   │
   └── IP traffic ──▶ pf filter / scrub / NAT ──▶ Kernel FIB 0
                                                    ├── Default route ──▶ awg0 (AmneziaWG VPN)
                                                    ├── Host pin /32  ──▶ Active WAN gw (VPN peer)
                                                    └── Bypass CIDRs  ──▶ Active WAN gw (ng0 / ue0)
```

- **Web UI (`gatebsd` user, `/usr/sbin/nologin`)**: Static HTML/CSS/vanilla JS behind `nginx`, served by a zero-dependency Python stdlib backend (`http.server`, `sqlite3`, `fcntl`, `socketserver`) bound to `127.0.0.1:8080`.
- **Privileged socket agent (`root`)**: Listens on `/var/run/gatebsd/agent.sock` (`root:gatebsd`, `0660`) and accepts only allowlisted routes (`AGENT_ALLOWED_GET`, `AGENT_ALLOWED_POST`).
- **System control plane (`root`)**: Shell supervisors and route transaction helpers ([sbin/gatewayctl](../sbin/gatewayctl), [sbin/gatebsd-route-op](../sbin/gatebsd-route-op), [sbin/gatebsd-watchdog.sh](../sbin/gatebsd-watchdog.sh), [sbin/ru-routes.sh](../sbin/ru-routes.sh)) serialized on shared `lockf(1)` locks.
- **Automation boundary (`gatebsd-agent`)**: Runs only allowlisted commands via `/usr/local/sbin/gatebsd-agentctl` without an interactive root shell.

---

## 2. How Each Subsystem Works

### 2.1 Logical Interfaces and Traffic Roles

| Role | Default Interface | Purpose |
|---|---|---|
| LAN | `re1` (`10.88.0.0/24`) | Client subnet served by ISC DHCP and Unbound DNS |
| Primary WAN | `ng0` (e.g., PPPoE via `mpd5`) | Primary external uplink |
| Backup WAN | `ue0` (e.g., USB LTE/4G modem) | Failover uplink when primary connectivity fails |
| VPN Tunnel | `awg0` (AmneziaWG) | Default gateway for non-bypass outbound traffic |

### 2.2 Tunnel Configuration and Profile Normalization

Tunnel profiles are managed by [webui/backend/gatebsd_ui/writers/vpn.py](../webui/backend/gatebsd_ui/writers/vpn.py) and tested before activation rather than accepted blindly:

- **Directive allowlisting**: Supports standard WireGuard plus AmneziaWG `1.5`, `2.0`, and `3.1` parameters (`Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4`, `I1`–`I5`, `ContentPaddingAddition`, `HeaderProtectionKey`, `RandomTailers`, `DisableCookies`, rekey timers). Unknown keys (which cause `awg-quick` to fail the entire file) and unsafe shell hooks (`PreUp`, `PostUp`, `PreDown`, `PostDown`, `SaveConfig`) are rejected.
- **Strict ASCII validation**: Integer fields check ASCII decimal digits (`isascii() and isdigit()`) rather than `str.isdigit()` so non-ASCII Unicode digits cannot pass Python checks and break C `strtoul()` parsers underneath.
- **Router-safe profile normalization (`_normalize_profile_text`)**: Imported client profiles assume a laptop, not a gateway. GateBSD deterministically rewrites three settings while leaving peer keys untouched:
  1. Forces `Table = off` so `awg-quick` never installs split `0.0.0.0/1` and `128.0.0.0/1` routes behind `gatewayctl`'s back.
  2. Strips upstream `DNS =` directives so `awg-quick` cannot invoke `resolvconf -x` to overwrite `/etc/resolv.conf` and bypass local Unbound.
  3. Inserts `MTU = 1280` when `MTU` is omitted (avoiding fragmentation/blackholing under AmneziaWG header padding).

### 2.3 Policy Routing and Targeted Split-DNS

- **Direct bypass tables ([sbin/ru-routes.sh](../sbin/ru-routes.sh), [sbin/ru-bypass-update.sh](../sbin/ru-bypass-update.sh))**: Regional CIDR feeds and operator overrides (`direct`, `vpn`, `default` in `/usr/local/etc/amnezia/direct-exceptions.conf` and `/usr/local/etc/amnezia/vpn_override.table`) install as kernel routes via the active WAN gateway in FIB 0, keeping the rest of the internet behind `awg0`.
- **Exception resolution and safety checks ([webui/backend/gatebsd_ui/vpn_policy.py](../webui/backend/gatebsd_ui/vpn_policy.py))**:
  - Domains are normalized to IDNA/Punycode across rule storage, `drill` resolution, and diagnostics.
  - IPv4 prefixes shorter than `/8` (`MIN_PREFIX_LEN=8`) are refused so a corrupted feed entry (including `0.0.0.0/0`, which represents the default route on FreeBSD) cannot hijack or wipe the default gateway.
  - Adding a `direct` domain whose IPv4 falls inside `CLOUDFLARE_IPV4_NETWORKS` triggers a warning because bypassing a shared CDN `/32` routes co-hosted domains outside VPN and can break TLS ECH sessions.
- **Unbound DNS and Split-DNS ([etc/unbound/unbound.conf.sample](../etc/unbound/unbound.conf.sample), [webui/backend/gatebsd_ui/writers/dns.py](../webui/backend/gatebsd_ui/writers/dns.py))**:
  - Root zone `"."` stays behind VPN upstreams.
  - Only explicit multi-label domains listed in `/usr/local/etc/gatebsd/split-dns.conf` forward to dedicated IPv4 resolvers; top-level and public suffix zones (`FORBIDDEN_SPLIT_ZONES`) are rejected.
  - Outbound LAN TCP/UDP `:53` queries are redirected to `10.88.0.1` via PF `rdr` (excluding `<local_nets>`), outbound DoT `:853` is dropped, and `use-application-dns.net` answers `NXDOMAIN` so browsers do not silently switch to external DoH and bypass routing or blocklists.

### 2.4 PF Firewall, Scrubbing, and Anti-Lockout

[etc/pf.conf.sample](../etc/pf.conf.sample) enforces packet normalization, NAT, and default-deny inbound filtering:

- `scrub in all`, `scrub on ng0 all max-mss 1240`, `scrub on awg0 all max-mss 1240`.
- `nat on` `$wan_if`, `$backup_if` (tagged `LAN_TO_BACKUP`), and `$vpn_if` (`awg0`), allowing seamless address translation whichever interface the kernel routing table picks.
- `block in all` with explicit LAN anti-lockout (`pass in quick on $lan_if from $lan_net to ($lan_if)`), WAN port-forward rules with mandatory source allowlists, and `check_management_access` static analysis + 120-second confirmation timer (`PF_CONFIRM_TIMEOUT = 120`) in [writers/firewall.py](../webui/backend/gatebsd_ui/writers/firewall.py).

### 2.5 Multi-FIB Failover and Unified Watchdog

[etc/sysctl.conf](../etc/sysctl.conf) configures `net.fibs=3`:

- **FIB 0**: Carries production LAN traffic (default via `awg0`, endpoint `/32` via active WAN, bypass prefixes via active WAN).
- **FIB 1 (`PRIMARY_FIB`) and FIB 2 (`BACKUP_FIB`)**: Populated on each watchdog tick from `ifconfig` / `dhclient` leases so `gatebsd-watchdog.sh` probes each physical link directly via `setfib` without disturbing or being fooled by the active VPN default route in FIB 0.

Each watchdog tick executes in strict dependency order ([sbin/gatebsd-watchdog.sh](../sbin/gatebsd-watchdog.sh)):

```text
measure_links -> select_underlay -> supervise_services -> judge_vpn -> complete_manual_request
```

---

## 3. Why This Architecture Provides a Good VPN Channel

Many router VPN setups fail under real traffic not because WireGuard encryption itself breaks, but because surrounding OS state drifts, MTU mismatches stall TCP streams, DNS leaks or caches stale failures, or health checks tear down working tunnels. GateBSD prevents those failure modes structurally:

### 3.1 Kernel Datapath Performance with Automatic Compatibility Fallback

- **Fast path by default**: AmneziaWG `1.5`, `2.0`, and `3.1` profiles run on the FreeBSD kernel module (`amnezia-kmod`) via `nvlist`, avoiding userspace packet-copy overhead.
- **No silent EINVAL drops**: Because `amnezia-kmod 3.1` rejects magic headers `H1..H4 <= 4` (`EINVAL`), `_magic_headers_rejected_by_kernel` detects low headers automatically and inserts `UserLand = true` (`amneziawg-go`) while surfacing engine and generation clearly in the profile view instead of letting tunnel startup silently fail.

### 3.2 Tuned Packet Framing (`MTU = 1280` + `max-mss 1240` + Deferred ISR)

- **Headroom for obfuscation overhead**: Over a PPPoE link (`ng0`, MTU `1492`), leaving the default `1420` WireGuard MTU leaves insufficient space for AmneziaWG `2.0` junk and header padding, causing fragmented UDP outer packets or silent large-packet drops. GateBSD sets `VPN_MTU="1280"` (applied explicitly via `ifconfig` and injected when omitted from imported configs) and clamps TCP SYN segments on both `ng0` and `awg0` via PF `max-mss 1240`.
- **Kernel buffer/latency tuning ([etc/sysctl.conf](../etc/sysctl.conf))**: `net.isr.dispatch=deferred`, `net.inet.tcp.delayed_ack=0`, `net.inet.tcp.sendspace=65536`, and `net.inet.udp.maxdgram=57344` keep throughput high and interactive latency low without stalling small packets.

### 3.3 Loop-Free Endpoint Pinning Across Failovers and Profile Switches

- **Breaking routing loops before switching default**: `gatewayctl cmd_apply` brings up `awg0`, installs a `/32` host route to the peer IP through the active WAN gateway (`route_endpoint_via_wan`), waits for a live peer handshake (`VPN_HANDSHAKE_WAIT`), switches default to `awg0`, and verifies real data-plane reachability (`check_net`) — rolling back automatically on any gate failure.
- **Persistent `/32` pin tracking (`endpoint_pin`)**: [sbin/gatebsd-route-op](../sbin/gatebsd-route-op) records the pinned peer IP in `/var/run/gatebsd/endpoint_pin` and performs profile switches in safe order (`install new pin -> persist record -> delete old pin`). Even if the previous profile's hostname stops resolving, its old host route is cleanly withdrawn rather than leaked permanently.
- **Underlay switch continuity (`switch_underlay`)**: When failover moves between `ng0` (PPPoE) and `ue0` (LTE), `gatebsd-route-op` re-pins the active VPN endpoint onto the new WAN gateway (preserving prior pin fallback if `ru_apply` fails) so encapsulated UDP follows the live carrier immediately without dropping the tunnel profile.
- **Cold-start resilience without DNS (`endpoint-dns-cache`)**: Successful endpoint resolutions are cached in `/var/db/gatebsd-system/endpoint-dns-cache`, enabling `gatewayctl` and `gatebsd-route-op` to route the peer IP even if upstream DNS is temporarily unreachable at boot.

### 3.4 DNS Integrity Without Circular Deadlocks

- **No self-inflicted DNS deadlock on tunnel rebuild**: By enforcing `Table = off` and stripping `DNS =` lines from AWG configs, local Unbound remains authoritative in `/etc/resolv.conf`. When switching profiles (`cmd_rebuild`), `gatewayctl` shifts default to the raw WAN *before* tearing down `awg0`, ensuring the router never destroys its own DNS path while resolving the next endpoint.
- **No client DNS leaks or stale outage caches**:
  - PF `rdr` on `:53` and blocking `:853` plus `use-application-dns.net` `NXDOMAIN` prevent client browsers from quietly escaping gateway DNS policy.
  - On route transitions, `gatebsd-route-op flush-resolver-negative` clears Unbound's negative cache immediately so domains that timed out during a brief drop do not stay stuck on cached `NXDOMAIN` for minutes afterward.
  - Unbound `prefetch: yes` and `serve-expired: yes` keep hot entries responsive across transient jitter.

### 3.5 Clean Split-Routing That Offloads Domestic Traffic Without Harming Boot or Failover

- **Line-rate direct paths**: Latency-sensitive domestic subnets and operator-selected services traverse the active WAN directly while international and tunneled traffic remain isolated inside `awg0`.
- **Non-blocking application**: Large route tables load asynchronously via `daemon(8)` (`service ru_bypass restart` / `schedule-clear`) rather than blocking boot or failover transitions; `ru-routes.sh` uses a compensating rollback snapshot if route convergence fails or times out.

### 3.6 Intelligent Supervision That Avoids False Tunnel Kills

- **Underlay-first tick prevents rollback storms**: Measuring physical links and picking the underlay *before* judging `awg0` ensures a dead PPPoE link never tricks the watchdog into spending 45 seconds rolling a healthy tunnel back onto a dead gateway (`awg0: loop detected` failure prevented).
- **ICMP + TCP/443 fallback probing**: Many cellular/LTE carriers drop public ICMP echo while allowing HTTPS (`443`). `gatebsd-watchdog.sh` falls back to TCP/`443` connect probes before marking an uplink dead, and uses `RU_CHECK_TARGETS` to distinguish carrier allowlist restrictions from a hard link outage.
- **Explicit `PATH` and sentinel safety**: `gatewayctl` and `gatebsd-watchdog.sh` export `/usr/local/bin` explicitly so `awg show` never fails with `ENOENT` under `cron(8)` or `rc.d(8)`, and empty `awg` output is never conflated with an expired handshake age.
- **Underlay settling grace & self-healing convergence**: After switching WANs, `VPN_NET_FAIL` resets while the peer re-handshakes (`underlay_settling`). If the tunnel is temporarily bypassed during an outage (`bypass-transient`), `/var/db/gatebsd/vpn_disabled` is left unset (reserved solely for explicit operator `down`/`bypass`), allowing `gatebsd-watchdog.sh` to automatically promote `awg0` back to the default route once the tunnel recovers — while `rc.d/gatewayctl_apply` daemonizes startup retries so slow PPPoE negotiation never delays `sshd` or Web UI availability at boot.

---

## 4. Transactional Reliability and Verification Model

- **Atomic writes & single-writer discipline**: Managed files (`pf.conf`, `unbound.conf`, `dhcpd.conf`, AWG profiles) are mutated under `lockf` / `fcntl.flock`, staged via `O_NOFOLLOW` + `fsync` on the destination filesystem, backed up before modification, and validated natively (`pfctl -nf`, `unbound-checkconf`, `dhcpd -q -t -cf`) before service reload.
- **Dormant defect prevention**: `sbin/gatebsd-config-guard` re-validates on-disk configs before restarts so an invalid edit cannot hide behind healthy in-memory daemon state until the next upgrade.
- **Transactional package upgrades**: [sbin/gatebsd-upgrade](../sbin/gatebsd-upgrade) copies root-owned `.pkg` files to private staging, checks SHA-256 stability, snapshots configs and SQLite DB, checks free space (`GATEBSD_UPGRADE_MIN_FREE_KIB`, `1 GiB` default), runs a post-install health gate, and rolls back package, configs, and DB automatically on any error. See [Package Upgrade Runbook](ROUTER_UPGRADE.md) and [Backup and Restore](../backup/README.md).
- **Provenance and defect-reintroduction tests**: [scripts/build-source-manifest.sh](../scripts/build-source-manifest.sh) binds every tracked file in `SOURCE_MANIFEST.sha256`. Regression suites (`tests/test_watchdog_wan_probe.py`, `tests/test_ci_build_detach.py`, `tests/test_one_writer_per_managed_file.py`, `tests/test_release_integrity.py`) run real scripts against simulated kernel/routing failures and reintroduce historical defects to verify tests actually catch them.

---

## 5. Known Trade-offs and Limitations

- **Double NAT by default on VPN**: `etc/pf.conf.sample` applies `nat on $vpn_if` so any LAN client works with standard server peers without server-side LAN subnet routes (which can be disabled when peering with a routed site-to-site peer).
- **Active TCP flows across WAN switches**: Shifting `default` between `ng0` and `ue0` changes the outer WAN NAT address; existing stateful connections drop and re-establish over the surviving path.
- **DNS-level adblock scope**: Unbound adblock cannot strip first-party ads served from primary content hostnames without breaking the site.
- **Platform boundary**: Runtime kernel operations (`pf`, `setfib`, `awg`, `mpd5`, ZFS boot environments) require FreeBSD; Linux test runs exercise cross-platform logic, mocked routing tables, and JS/Python contracts while skipping FreeBSD-only integration cases.
