"""Central path registry for GateBSD.

FreeBSD remains the source of truth. These paths describe where GateBSD reads
the existing gateway state and where it stores its own metadata.
"""
from __future__ import annotations

import os
from pathlib import Path


def env_path(name: str, default: str) -> Path:
    return Path(os.environ.get(name) or default)


DB_DIR = env_path("GATEBSD_DB_DIR", "/var/db/gatebsd")
RUN_DIR = env_path("GATEBSD_RUN_DIR", "/var/run/gatebsd")
ETC_DIR = env_path("GATEBSD_ETC_DIR", "/usr/local/etc/gatebsd")
BACKUP_DIR = env_path("GATEBSD_BACKUP_DIR", "/var/backups/gatebsd")

PF_CONF = env_path("GATEBSD_PF_CONF", "/etc/pf.conf")
RC_CONF = env_path("GATEBSD_RC_CONF", "/etc/rc.conf")
LOADER_CONF = env_path("GATEBSD_LOADER_CONF", "/boot/loader.conf")
SYSCTL_CONF = env_path("GATEBSD_SYSCTL_CONF", "/etc/sysctl.conf")
SSHD_CONF = env_path("GATEBSD_SSHD_CONF", "/etc/ssh/sshd_config")
SSHD_GATEBSD_CONF = env_path("GATEBSD_SSHD_GATEBSD_CONF", "/etc/ssh/sshd_config.d/gatebsd.conf")
SUDOERS_CONF = env_path("GATEBSD_SUDOERS_CONF", "/usr/local/etc/sudoers")
SUDOERS_AGENT_CONF = env_path("GATEBSD_SUDOERS_AGENT_CONF", "/usr/local/etc/sudoers.d/gatebsd-agent")

MPD_CONF = env_path("GATEBSD_MPD_CONF", "/usr/local/etc/mpd5/mpd.conf")
DHCPD_CONF = env_path("GATEBSD_DHCPD_CONF", "/usr/local/etc/dhcpd.conf")
DHCPD_LEASES = env_path("GATEBSD_DHCPD_LEASES", "/var/db/dhcpd/dhcpd.leases")
UNBOUND_CONF = env_path("GATEBSD_UNBOUND_CONF", "/usr/local/etc/unbound/unbound.conf")
SPLIT_DNS_CONF = env_path("GATEBSD_SPLIT_DNS_CONF", str(ETC_DIR / "split-dns.conf"))
UNBOUND_SPLIT_DNS_CONF = env_path("GATEBSD_UNBOUND_SPLIT_DNS_CONF", "/usr/local/etc/unbound/split-dns.conf")

NUT_DIR = env_path("GATEBSD_NUT_DIR", "/usr/local/etc/nut")
NUT_CONF = NUT_DIR / "nut.conf"
UPS_CONF = NUT_DIR / "ups.conf"
UPSD_CONF = NUT_DIR / "upsd.conf"
UPSD_USERS = NUT_DIR / "upsd.users"
UPSMON_CONF = NUT_DIR / "upsmon.conf"
NUT_CONFIG_LOCK = NUT_DIR / ".gatebsd-config.lock"

AMNEZIA_CONF_DIR = env_path("GATEBSD_AWG_CONF_DIR", "/usr/local/etc/amnezia")
AMNEZIA_CONFIG = env_path("GATEBSD_AWG_CONF", "/usr/local/etc/amnezia/awg0.conf")
GATEWAY_CONF = env_path("GATEBSD_GW_CONF", "/usr/local/etc/amnezia/gateway.conf")
RU_TABLE = env_path("GATEBSD_RU_TABLE", "/usr/local/etc/amnezia/ru_bypass.table")
VPN_OVERRIDE_TABLE = env_path("GATEBSD_VPN_OVERRIDE_TABLE", "/usr/local/etc/amnezia/vpn_override.table")
DIRECT_EXCEPTIONS = env_path("GATEBSD_DIRECT_EXCEPTIONS", "/usr/local/etc/amnezia/direct-exceptions.conf")

# The operator's "I turned the VPN off" marker. Everything that reads it must
# read the same file: gatewayctl and the watchdog take it from
# GATEBSD_VPN_DISABLED_FLAG, so the Python side honours that name too. Three
# hardcoded copies of this path is how a marker written by one tool became
# invisible to another.
VPN_DISABLED = env_path("GATEBSD_VPN_DISABLED_FLAG", str(DB_DIR / "vpn_disabled"))

DISCOVERY_JSON = env_path("GATEBSD_DISCOVERY", str(DB_DIR / "discovery.json"))
IMPORT_JSON = env_path("GATEBSD_IMPORT", str(DB_DIR / "import.json"))
FAILOVER_CONF = env_path("GATEBSD_FAILOVER_CONF", str(ETC_DIR / "failover.conf"))

# Which package source the panel selected, and the pkg config rendered from it.
# The renderer is gatebsd-repo-bootstrap and it is the only writer of the
# second file; the panel writes the first and runs the renderer.
REPO_SOURCES = env_path("GATEBSD_REPO_SOURCES", str(ETC_DIR / "repo-sources.conf"))
REPO_CONF = env_path("GATEBSD_REPO_CONF", "/usr/local/etc/pkg/repos/gatebsd.conf")
REPO_BOOTSTRAP = env_path("GATEBSD_REPO_BOOTSTRAP", "/usr/local/sbin/gatebsd-repo-bootstrap")
PKG_BIN = env_path("GATEBSD_PKG", "pkg")
FAILOVER_STATE = env_path("GATEBSD_FAILOVER_STATE", str(RUN_DIR / "watchdog.json"))
# The SMS monitor owns this one. Deliberately a second file: two writers on
# one file is how adblock.conf was corrupted while unbound ran on its memory.
OPERATOR_STATE = env_path("GATEBSD_OPERATOR_STATE", str(RUN_DIR / "operator.json"))
# gatebsd-ups-health.sh owns this read-only telemetry snapshot.
UPS_HEALTH_STATE = env_path("GATEBSD_UPS_HEALTH_STATE", str(RUN_DIR / "ups-health.state"))

CONFIG_FILES = {
    "pf": PF_CONF,
    "rc": RC_CONF,
    "loader": LOADER_CONF,
    "sysctl": SYSCTL_CONF,
    "sshd": SSHD_CONF,
    "sshd_gatebsd": SSHD_GATEBSD_CONF,
    "sudoers": SUDOERS_CONF,
    "sudoers_agent": SUDOERS_AGENT_CONF,
    "mpd5": MPD_CONF,
    "dhcpd": DHCPD_CONF,
    "unbound": UNBOUND_CONF,
    "split_dns": SPLIT_DNS_CONF,
    "unbound_split_dns": UNBOUND_SPLIT_DNS_CONF,
    "nut": NUT_CONF,
    "ups": UPS_CONF,
    "upsd": UPSD_CONF,
    "upsd_users": UPSD_USERS,
    "upsmon": UPSMON_CONF,
    "amnezia_gateway": GATEWAY_CONF,
    "amnezia_active": AMNEZIA_CONFIG,
    "ru_table": RU_TABLE,
    "vpn_override": VPN_OVERRIDE_TABLE,
    "direct_exceptions": DIRECT_EXCEPTIONS,
}
