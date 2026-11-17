"""writers package — re-exports all public functions for backward compatibility."""
from __future__ import annotations

# System
from .system import pkg_upgrade_log, pkg_updates, pkg_upgrade, pkg_upgrade_start, service_control, rcconf, rcconf_set, ALLOWED_SERVICES

# Firewall
from .firewall import (
    pf_reload,
    pf_get_conf,
    pf_set_conf,
    pf_confirm_conf,
    pf_pending_commit,
    pf_revert_expired_commit,
)
from .port_forward import (
    list_rules as port_forward_list,
    save_rule as port_forward_save,
    delete_rule as port_forward_delete,
    test_rule as port_forward_test,
    apply_gateway as port_forward_apply_gateway,
)
from .reverse_ssh import (
    list_config as reverse_ssh_list,
    save_config as reverse_ssh_save,
    delete_config as reverse_ssh_delete,
)

# VPN / Network services
from .vpn import (
    mpd5_restart, gatewayctl, awg_set_config, awg_activate, awg_stop, awg_delete_profile, awg_profiles, ru_bypass_update,
    awg_peer_list, awg_peer_add, awg_peer_remove, awg_key_rotate,
    dhcpd_get_conf, dhcpd_restart, unbound_get_conf, unbound_restart, nut_restart,
)

# Diagnostics
from .diagnostics import (
    traceroute,
    nslookup,
    discovery_scan,
    import_existing,
    failover_mode,
    failover_switch,
    vpn_diagnose,
)
from .ups import ups_config, ups_command, configure_ups
from .dhcp import static_add as dhcp_static_add, static_remove as dhcp_static_remove, range_set as dhcp_range_set
from .dns import (
    get_split_dns as dns_split_get,
    set_split_dns as dns_split_set,
    set_upstreams as dns_upstreams_set,
)
from .repo import read_sources as repo_sources, set_sources as repo_sources_set, scan as repo_scan

__all__ = [
    "pkg_upgrade_log", "pkg_updates", "pkg_upgrade", "pkg_upgrade_start",
    "service_control", "rcconf", "rcconf_set", "ALLOWED_SERVICES",
    "pf_reload", "pf_get_conf", "pf_set_conf",
    "pf_confirm_conf", "pf_pending_commit", "pf_revert_expired_commit",
    "port_forward_list", "port_forward_save", "port_forward_delete", "port_forward_test", "port_forward_apply_gateway",
    "reverse_ssh_list", "reverse_ssh_save", "reverse_ssh_delete",
    "mpd5_restart", "gatewayctl", "awg_set_config", "awg_activate", "awg_stop", "awg_delete_profile", "awg_profiles", "ru_bypass_update",
    "awg_peer_list", "awg_peer_add", "awg_peer_remove", "awg_key_rotate",
    "dhcpd_get_conf", "dhcpd_restart", "unbound_get_conf", "unbound_restart", "nut_restart",
    "traceroute", "nslookup", "discovery_scan", "import_existing", "failover_mode", "failover_switch", "vpn_diagnose",
    "ups_config", "ups_command", "configure_ups",
    "dhcp_static_add", "dhcp_static_remove", "dhcp_range_set", "dns_upstreams_set",
    "dns_split_get", "dns_split_set",
    "repo_sources", "repo_sources_set", "repo_scan",
]
