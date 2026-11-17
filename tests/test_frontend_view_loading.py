#!/usr/bin/env python3
"""Each view must keep successful measurements when one API read fails."""

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "webui" / "frontend" / "app.js"

NODE_PRELUDE = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync(process.argv[2], "utf8").split("\nboot().then")[0];
const elements = {
  content: {innerHTML: "", scrollTop: 0, style: {}, childNodes: []},
  notifBadge: {classList: {add() {}, remove() {}}},
  toasts: {appendChild() {}},
};
const sandbox = {
  console,
  document: {
    activeElement: null,
    addEventListener() {},
    createElement() { return {style: {}, remove() {}}; },
    getElementById(id) { return elements[id] || null; },
    querySelectorAll() { return []; },
  },
  window: {getSelection() { return {toString() { return ""; }}; }},
  localStorage: {getItem() { return null; }, setItem() {}},
  location: {host: "test"},
  setInterval() { return 1; },
  clearInterval() {},
  setTimeout() { return 1; },
  clearTimeout() {},
};
vm.createContext(sandbox);
vm.runInContext(source + `
;globalThis.__ui = {
  S, EP, RENDERERS, loadView,
  setApi(fn) { api = fn; },
};`, sandbox);
const ui = sandbox.__ui;
ui.S.view = "overview";
ui.S.loaded = false;
ui.S._lastHtml = "";
const good = {
  "/api/overview": {
    system: {hostname: "router-test", os: "FreeBSD 15", uptime_seconds: 60},
    services: {pf: "active", unbound: "active"},
    memory: {mem: {total: 100, available: 50}},
    vpn_path: {state: "in_tunnel", label: "verified", in_tunnel: true, expected: true, warnings: []},
    operator: {warnings: []}, adblock: {warnings: []}, ups: {},
  },
  "/api/wan": {
    active_iface: "ng0", sys: {wan_if: "ng0", lan_if: "igc0", lan_net: "192.0.2.1/24"},
    wan: {name: "ng0", state: "UP", addresses: ["198.51.100.2"]},
    backup: {name: "ue0", state: "DOWN", addresses: []}, health: {},
  },
  "/api/clients": {count: 1, clients: []},
  "/api/stats/traffic": {interfaces: {ng0: {rx_rate: 1000, tx_rate: 2000}}},
  "/api/amnezia": {interface: {name: "awg0", state: "UP", addresses: []}},
  "/api/health": {},
  "/api/logs?limit=20": {lines: ["Jan 01 router-test fresh log"]},
  "/api/interfaces": {interfaces: [{name: "ng0", addresses: ["198.51.100.2"]}], routes_v4: ["default 198.51.100.1"]},
  "/api/pppoe": {config: ["pppoe-test-config"]},
  "/api/modem": {modems: "modem-test"},
  "/api/physical_ports": {},
  "/api/rcconf": {},
  "/api/system": {hostname: "system-test", os: "FreeBSD 15", kernel: "test-kernel", uptime_seconds: 60, loadavg: "0.10"},
  "/api/tls/status": {
    available: true, not_after: 1800000000, days_remaining: 90,
    san: ["gateway.duckdns.org", "gateway.example"],
    last_success_at: 1700000000,
    last_error: {checked_at: 1700000100, message: "temporary ACME failure"},
    next_attempt: 1800000000,
  },
  "/api/memory": {mem: {total: 1000, available: 500}, swap: {used: 0, total: 0}},
  "/api/disks": {blockdevices: [{name: "ada0", size: "1T"}]},
  "/api/services": {unbound: "active"},
  "/api/zfs": {pools: [{name: "zroot", state: "ONLINE", vdevs: [], errors: "none"}], datasets: []},
  "/api/disks/io": {devices: [{name: "ada0", kb_per_t: 1, tps: 2, mb_per_s: 3}]},
  "/api/ups": {
    name: "ippon@localhost", ok: true, checked_at: 200, last_response_at: 200,
    last_check: {available: true, checked_at: 190, ok: true, errors: 0},
    data: {"ups.status": "OL", "battery.charge": "100", "input.voltage": "220", "ups.load": "10"},
    available_commands: [], warnings: [],
  },
  "/api/ups/config": {mode: "netserver", driver: "usbhid-ups", listeners: []},
  "/api/adblock/status": {
    enabled: true, configured: true, config_valid: true, unbound_running: true,
    domains: 80, generated: "2026-11-06 10:00 UTC", verdict: "always_null", sources_used: 1,
    last_success_at: 150,
    last_run: {
      available: true, outcome: "failed", checked_at: 200, last_success_at: 150,
      sources_skipped: ["https://b.invalid/hosts"],
      sources: [
        {url: "https://a.invalid/hosts", downloaded: 100, parsed: 80, status: "ok"},
        {url: "https://b.invalid/hosts", downloaded: 0, parsed: 0, status: "rejected", reason: "download_failed"},
      ],
      warnings: [],
    },
    stats: {available: false, reason: "not measured"},
  },
  "/api/adblock/rules": {
    config: "/test/adblock-extra",
    entries: [{kind: "block", value: "ads.example.com"}, {kind: "allow", value: "allowed.example"}],
  },
  "/api/dns/split": {
    config: "/test/split-dns.conf",
    unbound_config: "/test/unbound-split-dns.conf",
    configured: true,
    upstreams: ["77.88.8.8", "77.88.8.1"],
    default_upstreams: ["77.88.8.8", "77.88.8.1"],
    domains: [{value: "gosuslugi.ru", display_value: "gosuslugi.ru"}],
  },
  "/api/vpn/status": {active: true, is_default: true},
  "/api/vpn/profiles": {profiles: []},
  "/api/secureboot/status": {},
  "/api/vpn/exceptions": {
    config: "/test/direct.conf",
    entries: [
      {value: "agent-gw.kimi.com", direction: "direct", networks: ["203.0.113.156/32"], checked_at: 150, route: {interface: "ng0"}, error: ""},
      {value: "www.kimi.com", direction: "vpn", networks: ["203.0.113.8/32"], checked_at: 160, route: {interface: "awg0"}, error: ""},
      {value: "example.com", direction: "default", networks: ["203.0.113.9/32"], checked_at: 160, route: {interface: "ng0"}, error: ""},
    ],
  },
  "/api/failover": {state: {mode: "observe", state: "PRIMARY", primary_ok: true, backup_fitted: false}, config: {PRIMARY_IF: "ng0"}},
  "/api/discovery": {data: {detected: {}}},
  "/api/history": {events: [], devices: [], snapshot_counts: []},
  "/api/firewall": {state: "enabled", nat_rules: [], filter_rules: [], conf: ""},
  "/api/firewall/detail": {states: []},
  "/api/dhcp": {leases: [], static_hosts: [], upstreams: []},
  "/api/backups": {backups: [], dir: "/test/backups"},
  "/api/system/updates": {count: 0, missing: [], upgradable: []},
  "/api/services/all": [],
  "/api/repo/sources": {sources: []},
};
function respond(failures = {}, payloads = {}) {
  ui.setApi(async path => {
    if (failures[path]) throw new Error(failures[path]);
    const value = (payloads[path] || good[path]);
    ui.S.cache.set(path, value);
    return value;
  });
}
async function load(failures = {}, payloads = {}) {
  respond(failures, payloads);
  await ui.loadView(false);
  return elements.content.innerHTML;
}
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required to execute frontend tests")
class FrontendViewLoading(unittest.TestCase):
    def run_js(self, scenario):
        result = subprocess.run(
            ["node", "-", str(APP_JS)],
            input=NODE_PRELUDE + "(async () => {\n" + scenario + "\n})().catch(error => { console.error(error); process.exitCode = 1; });\n",
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_one_failed_endpoint_leaves_successful_blocks_visible(self):
        self.run_js(r"""
const html = await load({"/api/logs?limit=20": "log API unavailable"});
assert.match(html, /router-test/);
assert.match(html, /Service Status/);
assert.match(html, /log API unavailable/);
assert.match(html, /System Logs/);
assert.doesNotMatch(html, /Jan 01 router-test fresh log/);
""")

    def test_failed_measurement_is_not_a_healthy_or_stopped_system(self):
        self.run_js(r"""
const html = await load({"/api/overview": "overview API unavailable", "/api/wan": "wan API unavailable"});
assert.match(html, /not measured/i);
assert.doesNotMatch(html, /Internet works/);
assert.doesNotMatch(html, /Connectivity issues/);
assert.doesNotMatch(html, /No warnings/);
assert.doesNotMatch(html, />Stopped</);
""")

    def test_cached_data_is_marked_stale_when_refresh_fails(self):
        self.run_js(r"""
await load();
const html = await load({"/api/logs?limit=20": "refresh failed"});
assert.match(html, /fresh log/);
assert.match(html, /refresh failed/);
assert.match(html, /cached|previous/i);
assert.match(html, /router-test/);
""")

    def test_recovery_clears_the_local_error(self):
        self.run_js(r"""
await load({"/api/logs?limit=20": "temporary failure"});
const html = await load();
assert.match(html, /fresh log/);
assert.doesNotMatch(html, /temporary failure/);
assert.doesNotMatch(html, /State not measured/);
""")

    def test_wan_failed_modem_leaves_wan_and_pppoe_visible(self):
        self.run_js(r"""
ui.S.view = "wan";
const html = await load({"/api/modem": "modem API unavailable"});
assert.match(html, /ng0/);
assert.match(html, /pppoe-test-config/);
assert.match(html, /modem API unavailable/);
assert.match(html, /Uplink Checks/);
""")

    def test_wan_failed_measurement_is_not_inactive(self):
        self.run_js(r"""
ui.S.view = "wan";
const html = await load({"/api/wan": "wan API unavailable"});
assert.match(html, /not measured/i);
assert.match(html, /pppoe-test-config/);
assert.match(html, /198.51.100.2/);
assert.doesNotMatch(html, />inactive</);
""")

    def test_tls_status_shows_public_details_and_renew_button(self):
        self.run_js(r"""
ui.S.view = "system";
const html = await load();
assert.match(html, /TLS Certificate/);
assert.match(html, /gateway.duckdns.org/);
assert.match(html, /gateway.example/);
assert.match(html, /Last successful renewal/);
assert.match(html, /Last error/);
assert.match(html, /Next attempt/);
assert.match(html, /doTlsRenew/);
assert.doesNotMatch(html, /DuckDNS_Token/);
""")

    def test_tls_failure_is_local_to_its_card(self):
        self.run_js(r"""
ui.S.view = "system";
const html = await load({"/api/tls/status": "TLS API unavailable"});
assert.match(html, /TLS API unavailable/);
assert.match(html, /not measured/i);
assert.match(html, /system-test/);
assert.match(html, /ada0/);
""")

    def test_system_failed_services_leave_system_and_disks_visible(self):
        self.run_js(r"""
ui.S.view = "system";
const html = await load({"/api/services": "services API unavailable"});
assert.match(html, /system-test/);
assert.match(html, /ada0/);
assert.match(html, /zroot/);
assert.match(html, /services API unavailable/);
assert.doesNotMatch(html, /Service is stopped/);
""")

    def test_system_failed_zfs_is_local_to_its_section(self):
        self.run_js(r"""
ui.S.view = "system";
const html = await load({"/api/zfs": "zfs API unavailable"});
assert.match(html, /system-test/);
assert.match(html, /ada0/);
assert.match(html, /zfs API unavailable/);
assert.match(html, /ZFS/);
assert.match(html, /DNS resolver/);
""")

    def test_ups_failed_config_leaves_telemetry_visible(self):
        self.run_js(r"""
ui.S.view = "ups";
const html = await load({"/api/ups/config": "UPS config unavailable"});
assert.match(html, /ippon@localhost/);
assert.match(html, /UPS config unavailable/);
assert.match(html, /Online/);
assert.match(html, /Last UPS response/);
assert.match(html, /Last check/);
""")

    def test_ups_connection_loss_and_discharge_are_explicit(self):
        self.run_js(r"""
ui.S.view = "ups";
const loss = structuredClone(good["/api/ups"]);
loss.ok = false;
loss.error = "connection refused";
loss.last_response_at = 150;
loss.last_check = {available: true, checked_at: 190, ok: false, errors: 1};
loss.data["ups.status"] = "OB DISCHRG";
loss.data["battery.charge"] = "17";
loss.warnings = ["Low battery charge"];
const html = await load({}, {"/api/ups": loss});
assert.match(html, /Connection lost/);
assert.match(html, /On Battery/);
assert.match(html, /Discharging/);
assert.match(html, /Low battery charge/);
assert.match(html, /Last UPS response/);
""")

    def test_ups_calibration_is_named(self):
        self.run_js(r"""
ui.S.view = "ups";
const calibration = structuredClone(good["/api/ups"]);
calibration.data["ups.status"] = "CAL";
const html = await load({}, {"/api/ups": calibration});
assert.match(html, /Calibration/);
""")

    def test_ups_api_failure_is_not_a_measured_connection_loss(self):
        self.run_js(r"""
ui.S.view = "ups";
const html = await load({"/api/ups": "UPS API unavailable"});
assert.match(html, /UPS API unavailable/);
assert.match(html, /not measured/i);
assert.match(html, /usbhid-ups/);
assert.doesNotMatch(html, /Connection lost/);
""")

    def test_adblock_sources_and_last_success_are_visible(self):
        self.run_js(r"""
ui.S.view = "adblock";
const html = await load();
assert.match(html, /Blocklist Sources/);
assert.match(html, /https:\/\/a.invalid\/hosts/);
assert.match(html, /https:\/\/b.invalid\/hosts/);
assert.match(html, /download_failed/);
assert.match(html, /Last successful update/);
assert.match(html, /does not replace a browser adblocker/);
""")

    def test_adblock_rules_have_allow_block_editor(self):
        self.run_js(r"""
ui.S.view = "adblock";
const html = await load();
assert.match(html, /Allowlist &amp; Blocklist/);
assert.match(html, /ads.example.com/);
assert.match(html, /allowed.example/);
assert.match(html, /showAdblockRule/);
assert.match(html, /doAdblockRuleRemove/);
""")

    def test_adblock_api_failure_is_not_a_healthy_filter(self):
        self.run_js(r"""
ui.S.view = "adblock";
const html = await load({"/api/adblock/status": "adblock API unavailable"});
assert.match(html, /adblock API unavailable/);
assert.match(html, /not measured/i);
assert.doesNotMatch(html, /included","ok/);
assert.doesNotMatch(html, /running","ok/);
""")

    def test_vpn_policy_shows_direction_route_and_diagnose(self):
        self.run_js(r"""
ui.S.view = "amnezia";
const html = await load();
assert.match(html, /Routing Policy/);
assert.match(html, /via VPN/);
assert.match(html, /direct/);
assert.match(html, /default/);
assert.match(html, /ng0/);
assert.match(html, /awg0/);
assert.match(html, /doVpnExceptionDiagnose/);
""")

    def test_vpn_policy_failure_leaves_other_vpn_blocks_visible(self):
        self.run_js(r"""
ui.S.view = "amnezia";
const html = await load({"/api/vpn/exceptions": "policy API unavailable"});
assert.match(html, /policy API unavailable/);
assert.match(html, /not measured/i);
assert.match(html, /VPN Control/);
assert.match(html, /Network &amp; Service Diagnostics/);
""")

    def test_vpn_policy_renders_backend_warnings_for_shared_cdn(self):
        self.run_js(r"""
ui.S.view = "amnezia";
const html = await load({}, {"/api/vpn/exceptions": {
  config: "/test/direct.conf",
  warnings: [{code: "cloudflare_shared_cdn", level: "warn", value: "cf.example", msg: "cf.example: IP 104.21.10.20/32 belongs to shared Cloudflare CDN (TLS ECH)."}],
  entries: [
    {value: "cf.example", direction: "direct", networks: ["104.21.10.20/32"], checked_at: 170, route: {interface: "ng0"}, error: "", warnings: [{code: "cloudflare_shared_cdn", level: "warn", msg: "cf.example: IP 104.21.10.20/32 belongs to shared Cloudflare CDN (TLS ECH)."}]},
  ],
}});
assert.match(html, /belongs to shared Cloudflare CDN \(TLS ECH\)/);
assert.match(html, /Cloudflare CDN/);
""")

    def test_split_dns_renders_and_failure_is_local(self):
        self.run_js(r"""
ui.S.view = "adblock";
const html = await load();
assert.match(html, /Targeted Split-DNS/);
assert.match(html, /gosuslugi\.ru/);
assert.match(html, /77\.88\.8\.8/);
ui.S.view = "amnezia";
const vpnHtml = await load({"/api/dns/split": "split DNS API unavailable"});
assert.match(vpnHtml, /split DNS API unavailable/);
assert.match(vpnHtml, /VPN Control/);
assert.match(vpnHtml, /Routing Policy/);
""")

    def test_failover_failure_leaves_wan_and_history_visible(self):
        self.run_js(r"""
ui.S.view = "failover";
const html = await load({"/api/failover": "failover API unavailable"});
assert.match(html, /failover API unavailable/);
assert.match(html, /not measured/i);
assert.match(html, /Uplink Checks/);
assert.match(html, /WAN events/);
assert.doesNotMatch(html, />observe</);
""")

    def test_failover_shows_pending_request_and_direct_lte(self):
        self.run_js(r"""
ui.S.view = "failover";
const html = await load({}, {"/api/failover": {
  mode: "manual",
  state: {
    mode: "manual", state: "SWITCHING_TO_BACKUP", active_wan: "backup",
    request_id: "request-42", request_status: "pending", request_error: "",
    vpn_rolled_back: true, primary_ok: true, backup_ok: true, backup_fitted: true
  },
  config: {PRIMARY_IF: "ng0", BACKUP_IF: "ue0"}
}});
assert.match(html, /Monitor-only/);
assert.match(html, /request-42/);
assert.match(html, /pending/);
assert.match(html, /LTE direct/);
assert.doesNotMatch(html, /setFailoverMode\('automatic'\)/);
assert.doesNotMatch(html, />Monitor only</);
""")

    def test_lan_failed_dhcp_leaves_clients_and_interfaces_visible(self):
        self.run_js(r"""
ui.S.view = "lan";
const html = await load({"/api/dhcp": "DHCP API unavailable"});
assert.match(html, /DHCP API unavailable/);
assert.match(html, /not measured/i);
assert.match(html, /Clients/);
assert.match(html, /ng0/);
""")

    def test_firewall_detail_failure_does_not_zero_connections(self):
        self.run_js(r"""
ui.S.view = "firewall";
const html = await load({"/api/firewall/detail": "PF detail unavailable"});
assert.match(html, /PF detail unavailable/);
assert.match(html, /not measured/i);
assert.match(html, /Enabled/);
assert.doesNotMatch(html, /Active States<\/div><i[^>]*><\/i><\/div><div class="card-value">0/);
""")

    def test_history_failure_is_not_an_empty_history(self):
        self.run_js(r"""
ui.S.view = "history";
const html = await load({"/api/history": "history API unavailable"});
assert.match(html, /history API unavailable/);
assert.match(html, /not measured/i);
assert.doesNotMatch(html, /Recent Events<\/summary><div class="section-body"><p style="color:var\(--muted\)">No data/);
""")

    def test_backups_failure_is_not_an_empty_backup_list(self):
        self.run_js(r"""
ui.S.view = "backups";
const html = await load({"/api/backups": "backups API unavailable"});
assert.match(html, /backups API unavailable/);
assert.match(html, /not measured/i);
assert.doesNotMatch(html, /Snapshot History \(0\)/);
""")

    def test_admin_update_failure_is_not_no_updates(self):
        self.run_js(r"""
ui.S.view = "admin";
const html = await load({"/api/system/updates": "updates API unavailable"});
assert.match(html, /updates API unavailable/);
assert.match(html, /not measured/i);
assert.match(html, /Managed Services/);
assert.doesNotMatch(html, /no updates available/);
""")

    def test_logs_service_failure_is_not_an_empty_service_list(self):
        self.run_js(r"""
ui.S.view = "logs";
const html = await load({"/api/services/all": "service list unavailable"});
assert.match(html, /service list unavailable/);
assert.match(html, /not measured/i);
assert.match(html, /System Log/);
""")

    def test_failover_renders_ru_whitelist_warning_and_pill(self):
        self.run_js(r"""
ui.S.view = "failover";
const html = await load({}, {"/api/failover": {
  state: {
    mode: "automatic",
    state: "PRIMARY_DEGRADED",
    active_wan: "primary",
    primary_ok: false,
    primary_ru_ok: true,
    backup_fitted: true,
    backup_ok: false,
    backup_ru_ok: true
  },
  config: {PRIMARY_IF: "ng0", BACKUP_IF: "ue0"},
  warnings: ["Backup uplink is restricted (allowlist mode): only domestic hosts are reachable; international internet and external VPN are unavailable."]
}});
assert.match(html, /Backup uplink is restricted \(allowlist mode\)/);
assert.match(html, /domestic allowlist/);
""")

    def test_late_response_from_previous_view_is_discarded(self):
        self.run_js(r"""
let release;
ui.setApi(() => new Promise(resolve => { release = () => resolve(good["/api/overview"]); }));
const pending = ui.loadView(false);
ui.S.view = "system";
release();
await pending;
assert.equal(elements.content.innerHTML, "Loading…");
""")


if __name__ == "__main__":
    unittest.main()
