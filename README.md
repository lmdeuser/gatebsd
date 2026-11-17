# GateBSD

GateBSD is software for [FreeBSD](https://www.freebsd.org/) (a set of shell scripts, service configurations, and a Python web interface) that turns a FreeBSD computer with two network ports into an Internet [gateway](https://en.wikipedia.org/wiki/Default_gateway) for your [local area network (LAN)](https://en.wikipedia.org/wiki/Local_area_network).

You connect one network port to your ISP cable or modem ([WAN](https://en.wikipedia.org/wiki/Wide_area_network)) and the other port to your local switch or Wi-Fi access point. Once set up, devices on your LAN (laptops, phones, TVs) do not need local VPN apps: outbound traffic goes through the gateway's VPN tunnel by default, while regional IPs, chosen domains, and their DNS queries go directly over the ISP link via [split tunneling](https://en.wikipedia.org/wiki/Split_tunneling).

## What it does

- **Gateway VPN and bypass rules**: Connects to [WireGuard](https://www.wireguard.com/) or [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) servers and sends traffic through the tunnel by default, while routing a regional prefix table and your per-domain/IP exceptions straight out the WAN interface.
- **Local DNS, ad filtering, and Split-DNS**: Runs [Unbound](https://nlnetlabs.nl/projects/unbound/about/) for local [DNS](https://en.wikipedia.org/wiki/Domain_Name_System) resolution, blocks ad domains at the DNS layer, and forwards selected domains to direct resolvers ([split-horizon DNS](https://en.wikipedia.org/wiki/Split-horizon_DNS)) while keeping the rest of DNS behind the VPN.
- **Backup Internet failover**: Monitors the primary connection (Ethernet or [PPPoE](https://en.wikipedia.org/wiki/Point-to-Point_Protocol_over_Ethernet) via `mpd5`) and switches to a secondary link (such as a USB LTE modem) using separate FreeBSD routing tables ([setfib(1)](https://man.freebsd.org/cgi/man.cgi?query=setfib)), then switches back when the primary line recovers.
- **Firewall, NAT, and DHCP**: Manages FreeBSD's [PF](https://man.freebsd.org/cgi/man.cgi?query=pf) firewall, [NAT](https://en.wikipedia.org/wiki/Network_address_translation), WAN-to-LAN port forwarding, and [ISC DHCP](https://www.isc.org/dhcp/) from the browser.
- **Config checks and rollback**: Validates PF, Unbound, and DHCP files before reloading services, reverts firewall edits after 120 seconds if you do not confirm them in the UI, and snapshots configs before changes or package updates.
- **UPS shutdown**: Optionally monitors a battery backup with [NUT](https://networkupstools.org/) and shuts FreeBSD down before power runs out.

## Requirements

- An `amd64` computer or virtual machine running **FreeBSD** (tested on `15.1-RELEASE`) with at least two network interfaces (`WAN` and `LAN`), basic FreeBSD IP networking configured, and `root` access.
- FreeBSD packages (there are no `pip` or `npm` dependencies):

```sh
pkg install python312 py312-sqlite3 amnezia-kmod amnezia-tools amneziawg-go \
    unbound isc-dhcp44-server mpd5 nginx sudo acme.sh rsync ca_root_nss nut smartmontools
```

*(You can skip `mpd5`, `acme.sh`, or `nut` if you do not use PPPoE, automated TLS certificates, or a UPS.)*

## How to install and use

### 1. Install GateBSD onto your FreeBSD host

`gatebsd-install` keeps your existing FreeBSD network configuration untouched (`--existing` mode), backs up `/etc/pf.conf`, `rc.conf`, `unbound.conf`, and `dhcpd.conf` under `/var/backups/gatebsd/`, and enables the system services.

Run as `root`:

```sh
git clone https://github.com/lmdeuser/gatebsd.git
cd gatebsd
make install
/usr/local/sbin/gatebsd-install --existing --enable --start
```

If you are configuring `pf`, `unbound`, `nginx`, or `gateway.conf` for the first time, sample templates are included at [etc/pf.conf.sample](etc/pf.conf.sample), [etc/amnezia/gateway.conf.sample](etc/amnezia/gateway.conf.sample), [etc/unbound/unbound.conf.sample](etc/unbound/unbound.conf.sample), [etc/nginx/gatebsd.conf.sample](etc/nginx/gatebsd.conf.sample), and [etc/gatebsd/failover.conf.sample](etc/gatebsd/failover.conf.sample). When using the sample [nginx](https://nginx.org/) config, place a TLS certificate and key at `/usr/local/etc/gatebsd/tls/cert.pem` and `/usr/local/etc/gatebsd/tls/key.pem`.

### 2. Log in to the web panel

By default `nginx` serves HTTPS on port `443` and proxies to the Python backend (`127.0.0.1:8080`). Open `https://<your-gateway-lan-ip>/` in a browser and sign in with `root` or any account in the FreeBSD `wheel` group. To use a dedicated panel password instead of system login, adjust `gatebsd_auth_mode` in [etc/gatebsd.conf](etc/gatebsd.conf) and set a password with `/usr/local/sbin/gatebsd-passwd`.

### 3. Add a VPN config and set bypass rules

1. Open the **Amnezia VPN** tab and upload a `.conf` file for WireGuard or AmneziaWG. GateBSD sets `Table = off` and removes `DNS =` lines so its own route helper and `unbound` keep control over the default route and local DNS.
2. Start the tunnel. GateBSD uses the FreeBSD kernel module (`amnezia-kmod`) by default and automatically selects userspace (`amneziawg-go`) when obfuscation headers `H1..H4 <= 4` require it.
3. Open **Routing Policy** to route specific domains or IPv4 subnets directly over WAN (or force them through VPN). Open **Targeted Split-DNS** to forward specific domains to chosen direct DNS resolvers while leaving everything else on the VPN upstream.
4. Open **Failover** to verify primary and backup link checks in `observe` mode before switching to `automatic`.

## How the code is organized

- **No third-party libraries**: The web backend uses Python's standard library (`http.server`, `sqlite3`, `fcntl`), and the frontend is static HTML, CSS, and JavaScript.
- **Separated privileges**: The web UI runs as the unprivileged `gatebsd` user and sends allowlisted requests over `/var/run/gatebsd/agent.sock` to a root agent and root shell helpers (`sbin/gatewayctl`, `sbin/gatebsd-route-op`, `sbin/gatebsd-watchdog.sh`).
- **One writer per managed file**: Each system config has a single canonical writer (`tests/test_one_writer_per_managed_file.py`), and `SOURCE_MANIFEST.sha256` records SHA-256 digests of tracked files (`scripts/build-source-manifest.sh`).

Further reading:

- [User Guide](docs/USER_GUIDE.md) — subsystem overview, failover modes, port forwarding, and DNS behavior.
- [Technical Specification](docs/SPECIFICATION.md) — internal traffic flow, MTU/MSS sizing, anti-loop endpoint pinning, and watchdog details.
- [Package Upgrade Runbook](docs/ROUTER_UPGRADE.md) — `.pkg` upgrade workflow and rollback mechanics.
- [Documentation Index](docs/README.md)

## Running tests

Run the unit and sandbox test suite locally (Linux, macOS, or FreeBSD):

```sh
PYTHONPATH=webui/backend python3 -m unittest discover -s tests -p "test_*.py"
```

Tests that depend on live FreeBSD kernel tools (`pf`, `setfib`, `rc.d`, `pkg`, ZFS) skip automatically on Linux and run on the FreeBSD build host.

## Status and license

This is working personal software used on a live gateway, not a polished commercial product — it still contains bugs and rough edges. Test it on a spare machine or VM before using it as your primary network gateway.

Released under the [BSD 2-Clause License](LICENSE).
