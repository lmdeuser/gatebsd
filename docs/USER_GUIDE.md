# GateBSD User Guide and Architecture Overview

**GateBSD** is a FreeBSD-based network gateway designed to centralize routing, firewalling, VPN tunneling, DNS filtering, and multi-WAN failover for a home or small-office network.

## 1. Interfaces and Traffic Roles

GateBSD routes traffic across four primary logical interfaces:

1. **`LAN` (`re1`)**: Local network serving workstations, mobile devices, and access points via built-in DHCP and Unbound DNS.
2. **`WAN` (`ng0`)**: Primary internet uplink (e.g., PPPoE or direct Ethernet).
3. **`BACKUP` (`ue0`)**: Secondary internet uplink (e.g., USB LTE/4G modem or secondary ISP), used when primary connectivity fails.
4. **`VPN` (`awg0` / AmneziaWG)**: Encrypted tunnel interface for policy-routed traffic.

## 2. Failover and Watchdog (`gatebsd-watchdog.sh`)

GateBSD prioritizes maintaining internet reachability across uplink failures:

- **Probing**: By default, `gatebsd-watchdog.sh` probes the primary uplink every 10 seconds using ICMP and falls back to TCP/443 handshakes when carriers filter ICMP echo.
- **Modes**:
  - `observe`: Measures primary, backup, and VPN health without altering active routes.
  - `automatic`: Fails over to `BACKUP` after consecutive threshold failures and restores `PRIMARY` after stability thresholds and cooldowns pass.
  - `manual`: Prevents automatic transitions while permitting explicit `gatebsd-failoverctl primary|backup` switches.
- **Non-blocking policy tables**: Large routing tables load in a supervised background worker so table refreshes never block emergency WAN failover.
- **Secondary target probing**: If global probe targets (`CHECK_TARGETS`) fail, the watchdog also checks regional targets (`RU_CHECK_TARGETS`) and reports `primary_ru_ok` / `backup_ru_ok` separately.

Note that switching external uplinks changes the source NAT address and can drop existing stateful TCP connections.

## 3. Policy Routing and Exceptions

GateBSD separates direct traffic from tunneled traffic at the gateway:

- **Direct bypass table**: Selected networks route directly through the active WAN for full line rate and low latency; non-ASCII/IDNA domains are normalized to Punycode across configuration and diagnostics.
- **Tunneled traffic**: Remaining or explicitly overridden destinations route through `awg0`.
- **Shared CDN warnings**: Adding a `direct` domain exception whose IPv4 falls inside shared Cloudflare CDN pools triggers an explicit warning because routing that `/32` directly affects all co-hosted sites on the same address.

## 4. PF Firewall, Port Forwarding, and Remote Access

All LAN hosts sit behind FreeBSD's **PF** packet filter:

- **WAN -> LAN port forwards**: Forwards specific TCP/UDP ports with mandatory source IP/CIDR filtering (`0.0.0.0/0` requires explicit acknowledgment). Rules are checked via `pfctl -nf`, verified against a static LAN lockout heuristic, and require confirmation within 120 seconds or automatically revert.
- **Reverse SSH -> LAN**: Maintains an outbound SSH tunnel under the unprivileged `gatebsd-forward` user with strict host-key verification and `permitlisten` restrictions, independent of the active VPN profile.
- **Administrative boundary**: SSH enforces key-based login only. Automated actions run via `gatebsd-agent` and allowlisted `/usr/local/sbin/gatebsd-agentctl` without arbitrary root shell access. Nginx limits request bodies to 1 MiB and rate-limits API endpoints.

## 5. DNS Caching, Split-DNS, and Adblock (Unbound)

- **Caching and Split-DNS**: Unbound caches DNS responses locally and forwards selected domains from `/usr/local/etc/gatebsd/split-dns.conf` to dedicated upstream resolvers without altering the global forwarder.
- **DNS Adblock**: `gatebsd-adblock-update.sh` updates blocklists periodically, validates with `unbound-checkconf`, and rolls back on failure. DNS blocking cannot filter first-party ads served from the same domain as primary content.

## 6. Web Management UI

The local HTTPS dashboard (Nginx + stdlib Python backend) provides:

- Link status, throughput counters, and diagnostic tools;
- VPN profile management, peer CRUD, key rotation, and routing exceptions;
- User password changes and session management;
- Sensitive field blurring by default (click-to-reveal per value for screen-sharing safety; never a substitute for authentication).

## 7. Power Protection (UPS / NUT)

`gatebsd-ups-health.sh` monitors connected UPS devices via NUT and triggers an orderly FreeBSD/ZFS shutdown before battery exhaustion to prevent database or filesystem corruption.
