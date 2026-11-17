#!/usr/bin/env python3
"""Regression tests for M2, M3, and M4 WebUI and API hardening."""
from __future__ import annotations

import importlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "webui" / "backend"))

from gatebsd_ui import action_state, agent, api, storage  # noqa: E402
from gatebsd_ui.adapters import network as adapters_network  # noqa: E402
from gatebsd_ui.command import CommandResult  # noqa: E402
from gatebsd_ui.writers import diagnostics as writers_diagnostics  # noqa: E402
from gatebsd_ui.writers import system as writers_system  # noqa: E402
from gatebsd_ui.writers import vpn as writers_vpn  # noqa: E402

adapters_services_mod = importlib.import_module("gatebsd_ui.adapters.services")


APP_JS = ROOT / "webui" / "frontend" / "app.js"
STYLES_CSS = ROOT / "webui" / "frontend" / "styles.css"


def _ok(stdout: str = "", stderr: str = "", command: list[str] | None = None) -> CommandResult:
    return CommandResult(command=list(command or []), ok=True, returncode=0, stdout=stdout, stderr=stderr, error=None)


def _fail(returncode: int = 1, stdout: str = "", stderr: str = "failed", command: list[str] | None = None) -> CommandResult:
    return CommandResult(command=list(command or []), ok=False, returncode=returncode, stdout=stdout, stderr=stderr, error=stderr)


class M2ServiceControlTests(unittest.TestCase):
    def test_services_adapter_includes_gatebsd_reverse_ssh(self) -> None:
        captured: tuple[str, ...] = ()

        def fake_service_state(*names: str) -> dict[str, str]:
            nonlocal captured
            captured = names
            return {name: "active" for name in names}

        with patch.object(adapters_services_mod, "service_state", side_effect=fake_service_state):
            result = adapters_services_mod.services()
        self.assertIn("gatebsd_reverse_ssh", captured)
        self.assertEqual(result.get("gatebsd_reverse_ssh"), "active")

    def test_service_control_maps_dhcpd_to_isc_dhcpd(self) -> None:
        calls: list[list[str]] = []

        def fake_run(cmd: list[str], timeout: int = 5, **kwargs: object) -> CommandResult:
            calls.append(list(cmd))
            if cmd == ["service", "isc-dhcpd", "restart"]:
                return _ok("Starting dhcpd.\n")
            if cmd == ["service", "isc-dhcpd", "status"]:
                return _ok("dhcpd is running as pid 4242.\n")
            return _fail(1, stderr=f"unexpected command: {cmd}")

        with patch.object(writers_system, "run", side_effect=fake_run):
            status, payload = writers_system.service_control("dhcpd", "restart")
        self.assertEqual(status, 200)
        self.assertIs(payload["ok"], True)
        self.assertIs(payload["running"], True)
        self.assertEqual(payload["action"]["state"], action_state.DONE)
        self.assertEqual(calls[0], ["service", "isc-dhcpd", "restart"])
        self.assertIn(["service", "isc-dhcpd", "status"], calls)

    def test_service_control_manages_awg0_via_gatewayctl_and_ifconfig(self) -> None:
        self.assertIn("awg0", writers_system.ALLOWED_SERVICES)
        calls: list[tuple[list[str], int]] = []
        up_state = {"up": True}

        def fake_run(cmd: list[str], timeout: int = 5, **kwargs: object) -> CommandResult:
            calls.append((list(cmd), timeout))
            if cmd == ["/usr/local/sbin/gatewayctl", "apply"]:
                up_state["up"] = True
                return _ok("applied\n")
            if cmd == ["/usr/local/sbin/gatewayctl", "down"]:
                up_state["up"] = False
                return _ok("down\n")
            if cmd == ["ifconfig", "awg0"]:
                if up_state["up"]:
                    return _ok("awg0: flags=80d1<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST> metric 0 mtu 1360\n")
                return _fail(1, stderr="ifconfig: interface awg0 does not exist")
            if cmd == ["service", "amnezia", "enable"]:
                return _ok("amnezia enabled in /etc/rc.conf\n")
            return _fail(1, stderr=f"unexpected command: {cmd}")

        with patch.object(writers_system, "run", side_effect=fake_run):
            status, payload = writers_system.service_control("awg0", "restart")
            self.assertEqual(status, 200)
            self.assertIs(payload["ok"], True)
            self.assertIs(payload["running"], True)
            self.assertEqual(payload["action"]["state"], action_state.DONE)
            self.assertEqual(calls[0], (["/usr/local/sbin/gatewayctl", "apply"], 45))

            status, payload = writers_system.service_control("awg0", "stop")
            self.assertEqual(status, 200)
            self.assertIs(payload["ok"], True)
            self.assertIs(payload["running"], False)
            self.assertEqual(payload["action"]["state"], action_state.DONE)

            status, payload = writers_system.service_control("awg0", "enable")
            self.assertEqual(status, 200)
            self.assertEqual(payload["action"]["state"], action_state.UNVERIFIED)
            self.assertIs(payload["action"]["verified"], False)

            for action_name in ("start", "stop", "restart", "status", "enable"):
                _st, act_payload = writers_system.service_control("awg0", action_name)
                block = act_payload.get("action")
                self.assertIsInstance(block, dict, action_name)
                for field in ("state", "label", "level", "detail"):
                    self.assertTrue(block.get(field), f"awg0 {action_name}: missing {field}")

    def test_service_control_awg0_restart_down_is_failed(self) -> None:
        def fake_run(cmd: list[str], timeout: int = 5, **kwargs: object) -> CommandResult:
            if cmd == ["/usr/local/sbin/gatewayctl", "apply"]:
                return _ok("applied\n")
            if cmd == ["ifconfig", "awg0"]:
                return _ok("awg0: flags=8090<POINTOPOINT,NOARP,MULTICAST> metric 0 mtu 1360\n")
            return _fail(1)

        with patch.object(writers_system, "run", side_effect=fake_run):
            status, payload = writers_system.service_control("awg0", "restart")
        self.assertEqual(status, 200)
        self.assertIs(payload["ok"], False)
        self.assertIs(payload["running"], False)
        self.assertEqual(payload["action"]["state"], action_state.FAILED)


class M3WanStorageSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.prev_db = os.environ.get("GATEBSD_DB_PATH")
        os.environ["GATEBSD_DB_PATH"] = str(Path(self.tempdir.name) / "state.db")

    def tearDown(self) -> None:
        if self.prev_db is None:
            os.environ.pop("GATEBSD_DB_PATH", None)
        else:
            os.environ["GATEBSD_DB_PATH"] = self.prev_db
        self.tempdir.cleanup()

    def test_update_wan_accepts_live_wan_status_schema_and_detects_address_change(self) -> None:
        payload1 = {
            "wan": {"name": "ng0", "state": "UP", "addresses": ["198.51.100.2"]},
            "backup": {"name": "ue0", "state": "DOWN", "addresses": ["192.0.2.5"]},
            "health": {"wan": {"ok": True, "loss_pct": 0}, "backup": {"ok": False, "loss_pct": 100}},
            "active_iface": "ng0",
            "active_gw": "198.51.100.1",
            "sys_info": {"wan_if": "ng0", "backup_if": "ue0"},
        }
        storage.update_wan(payload1, ts=1000)
        snap = storage.latest_snapshot("wan")
        self.assertIsNotNone(snap)
        assert snap is not None
        self.assertEqual(snap["payload"]["active_iface"], "ng0")
        self.assertEqual(snap["payload"]["active_default"], "198.51.100.1")
        self.assertEqual(snap["payload"]["primary_addresses"], ["198.51.100.2"])
        self.assertEqual(snap["payload"]["secondary_addresses"], ["192.0.2.5"])

        payload2 = {
            **payload1,
            "wan": {"name": "ng0", "state": "UP", "addresses": ["198.51.100.99"]},
        }
        storage.update_wan(payload2, ts=1010)
        events = storage.history()["events"]
        kinds = [ev["kind"] for ev in events]
        self.assertIn("wan.address_change", kinds)

    def test_update_wan_keeps_legacy_primary_secondary_fallback(self) -> None:
        legacy = {
            "primary": {"name": "ng0", "state": "UP", "addresses": ["203.0.113.10"]},
            "secondary": {"name": "ue0", "state": "DOWN", "addresses": []},
            "health": {"primary": {"ok": True, "loss_pct": 0}, "secondary": {"ok": False, "loss_pct": 100}},
            "active_iface": "ng0",
            "active_default": "203.0.113.1",
        }
        storage.update_wan(legacy, ts=2000)
        snap = storage.latest_snapshot("wan")
        assert snap is not None
        self.assertEqual(snap["payload"]["active_default"], "203.0.113.1")
        self.assertEqual(snap["payload"]["primary_addresses"], ["203.0.113.10"])


class M4BackendTests(unittest.TestCase):
    def test_lookup_vendor_matches_lowercase_oui_db(self) -> None:
        self.assertEqual(adapters_network._lookup_vendor("30:96:10:aa:bb:cc"), "Huawei")
        self.assertEqual(adapters_network._lookup_vendor(" 6C:2B:59:11:22:33 "), "Apple")
        self.assertEqual(adapters_network._lookup_vendor(""), "")

    def test_awg_key_rotate_pushes_live_key_via_private_file_when_active(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            conf_dir = Path(td)
            active_profile = conf_dir / "main-vpn.conf"
            standby_profile = conf_dir / "standby.conf"
            awg0_link = conf_dir / "awg0.conf"
            active_profile.write_text("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", encoding="utf-8")
            os.chmod(active_profile, 0o600)
            standby_profile.write_text("[Interface]\nPrivateKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n", encoding="utf-8")
            os.chmod(standby_profile, 0o600)
            os.symlink(active_profile.name, awg0_link)

            new_priv = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
            new_pub = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
            observed_key_mode: list[int] = []
            observed_key_content: list[str] = []
            set_calls: list[list[str]] = []

            def fake_run(cmd: list[str], timeout: int = 5, **kwargs: object) -> CommandResult:
                if len(cmd) >= 2 and cmd[1] == "genkey":
                    return _ok(new_priv, command=cmd)
                if len(cmd) >= 2 and cmd[1] == "pubkey":
                    return _ok(new_pub, command=cmd)
                if cmd == ["ifconfig", "awg0"]:
                    return _ok("awg0: flags=80d1<UP,POINTOPOINT,RUNNING> mtu 1360\n")
                if len(cmd) >= 5 and cmd[1] == "set" and cmd[3] == "private-key":
                    set_calls.append(list(cmd))
                    key_path = Path(cmd[4])
                    observed_key_mode.append(stat.S_IMODE(key_path.stat().st_mode))
                    observed_key_content.append(key_path.read_text(encoding="utf-8"))
                    return _ok("")
                return _fail(1, stderr=f"unexpected cmd: {cmd}")

            with (
                patch.object(writers_vpn, "AMNEZIA_CONF_DIR", conf_dir),
                patch.object(writers_vpn, "AMNEZIA_CONFIG", awg0_link),
                patch.object(writers_vpn, "VPN_IF", "awg0"),
                patch.object(writers_vpn, "run", side_effect=fake_run),
                patch("gatebsd_ui.writers.vpn.backup.backup_files", return_value={}),
                patch("gatebsd_ui.writers.vpn.os.chown", lambda *a, **kw: None),
            ):
                status, payload = writers_vpn.awg_key_rotate("main-vpn")
                self.assertEqual(status, 200, payload)
                self.assertIs(payload["live_applied"], True)
                self.assertEqual(len(set_calls), 1)
                self.assertEqual(observed_key_mode, [0o600])
                self.assertEqual(observed_key_content, [new_priv + "\n"])
                self.assertFalse(Path(set_calls[0][4]).exists(), "temp private key file leaked")

                set_calls.clear()
                status_s, payload_s = writers_vpn.awg_key_rotate("standby")
                self.assertEqual(status_s, 200)
                self.assertIs(payload_s["live_applied"], False)
                self.assertEqual(set_calls, [])

    def test_agent_allowlist_and_failover_switch_endpoint(self) -> None:
        self.assertNotIn("/api/vpn/key-rotate", agent.AGENT_ALLOWED_GET)
        self.assertIn("/api/failover/switch", agent.AGENT_ALLOWED_POST)

        seen_cmds: list[list[str]] = []

        def fake_run(cmd: list[str], timeout: int = 5, **kwargs: object) -> CommandResult:
            seen_cmds.append(list(cmd))
            return _ok("switched\n")

        with patch.object(writers_diagnostics, "run", side_effect=fake_run):
            status, payload = api.dispatch(
                "/api/failover/switch",
                {},
                method="POST",
                body={"target": "backup"},
            )
            self.assertEqual(status, 200)
            self.assertIs(payload["ok"], True)
            self.assertEqual(payload["target"], "backup")
            self.assertEqual(seen_cmds, [["/usr/local/sbin/gatebsd-failoverctl", "backup"]])

            bad_status, _ = api.dispatch(
                "/api/failover/switch",
                {},
                method="POST",
                body={"target": "invalid"},
            )
            self.assertEqual(bad_status, 400)


NODE_TEST_PRELUDE = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync(process.argv[2], "utf8").split("\nboot().then")[0];

const fetchCalls = [];
const elements = {};
function makeEl(id) {
  if (!elements[id]) {
    elements[id] = {
      id,
      innerHTML: "",
      textContent: "",
      value: "",
      style: {},
      classList: { add() {}, remove() {}, toggle() {} },
      focus() {},
      remove() {},
    };
  }
  return elements[id];
}

const sandbox = {
  console,
  fetchCalls,
  elements,
  document: {
    activeElement: null,
    addEventListener() {},
    createElement() { return { className: "", style: {}, textContent: "", remove() {}, appendChild() {} }; },
    getElementById(id) { return makeEl(id); },
    querySelectorAll() { return []; },
  },
  window: { getSelection() { return { toString() { return ""; } }; } },
  localStorage: { getItem() { return null; }, setItem() {} },
  location: { host: "router.test" },
  setInterval() { return 1; },
  clearInterval() {},
  setTimeout(fn) { return 1; },
  clearTimeout() {},
};
vm.createContext(sandbox);
vm.runInContext(source + `
;globalThis.__ui = {
  S, api, post, esc, btn,
  jsArg: typeof jsArg === "function" ? jsArg : null,
  escJs: typeof escJs === "function" ? escJs : null,
  renderFirewall, renderFailover,
  showPfConfEdit: typeof showPfConfEdit === "function" ? showPfConfEdit : null,
  savePfConfEdit: typeof savePfConfEdit === "function" ? savePfConfEdit : null,
  switchFailoverWan: typeof switchFailoverWan === "function" ? switchFailoverWan : null,
  showDnsEdit,
};`, sandbox);
const ui = sandbox.__ui;
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required to execute frontend tests")
class M4FrontendTests(unittest.TestCase):
    def run_js(self, script: str) -> None:
        result = subprocess.run(
            ["node", "-", str(APP_JS)],
            input=NODE_TEST_PRELUDE + script,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)

    def test_styles_css_defines_toast_ok_and_warn_aliases(self) -> None:
        css = STYLES_CSS.read_text(encoding="utf-8")
        self.assertRegex(css, r"\.toast\.ok\b")
        self.assertRegex(css, r"\.toast\.warn\b")

    def test_app_js_onclick_handlers_use_escJs_and_no_ok_toast_type(self) -> None:
        js = APP_JS.read_text(encoding="utf-8")
        # Catch raw single-quoted template interpolations anywhere in app.js (e.g. onclick/btn).
        bad_interpolations = re.findall(r"[^\n]*'\$\{[^}]+\}[^\n]*", js)
        self.assertEqual(bad_interpolations, [], f"unsafe single-quoted interpolation: {bad_interpolations}")
        self.assertNotRegex(js, r'toast\([^;\n]+,\s*"ok"\s*\)')

    def test_app_js_escJs_and_view_fixes(self) -> None:
        self.run_js(r"""
assert.equal(typeof ui.jsArg, "function", "jsArg helper must exist");
assert.equal(typeof ui.escJs, "function", "escJs helper must exist");
const raw = `foo'bar"baz<tag>\nqux`;
const attrSnippet = ui.escJs(raw);
assert.ok(!attrSnippet.includes('"') && !attrSnippet.includes("<") && !attrSnippet.includes(">") && !attrSnippet.includes("\n"), attrSnippet);
const decoded = attrSnippet
  .replace(/&quot;/g, '"')
  .replace(/&#39;/g, "'")
  .replace(/&#x27;/g, "'")
  .replace(/&lt;/g, "<")
  .replace(/&gt;/g, ">")
  .replace(/&amp;/g, "&");
assert.equal(JSON.parse(decoded), raw);

// btn() already runs esc(onclick), so passing jsArg(...) must not double-escape &quot;
const btnHtml = ui.btn("Test", "play", "btn-ok", `fn(${ui.jsArg("a'b\"c")})`);
assert.ok(!btnHtml.includes("&amp;quot;"), "btn() must not double-escape onclick attribute: " + btnHtml);
assert.ok(btnHtml.includes("fn(&quot;a'b\\&quot;c&quot;)"), "unexpected btn onclick output: " + btnHtml);

// 1. renderFirewall: NAT card rendered even when filter_rules is empty, and PF edit opens showPfConfEdit()
const fwHtml = ui.renderFirewall({
  "/api/firewall": {
    state: "enabled",
    filter_rules: [],
    nat_rules: ["nat on ng0 from 10.88.0.0/24 to any -> (ng0)"],
    conf: "",
  },
  "/api/firewall/detail": { states: [] },
  "/api/port-forwards": { rules: [] },
  "/api/reverse-ssh": { rules: [] },
});
assert.ok(fwHtml.includes("NAT Rules"), "NAT card missing when filter_rules is empty");
assert.ok(fwHtml.includes("nat on ng0"), "NAT rule content missing");
assert.ok(fwHtml.includes("showPfConfEdit()"), "pf.conf button must invoke showPfConfEdit()");
assert.ok(!fwHtml.includes("switchView('firewall')"), "pf.conf button must not just reload view");
assert.equal(typeof ui.showPfConfEdit, "function");
assert.equal(typeof ui.savePfConfEdit, "function");

// 2. renderFailover: manual mode shows primary/backup switch buttons
const foHtml = ui.renderFailover({
  "/api/failover": {
    state: { mode: "manual", active_wan: "primary", primary_ok: true, backup_ok: true, vpn_ok: true },
    config: {},
  },
  "/api/discovery": { data: {} },
  "/api/history": { events: [] },
});
assert.ok(foHtml.includes("switchFailoverWan"), "manual mode must render switchFailoverWan buttons");
assert.equal(typeof ui.switchFailoverWan, "function");

// 3. showDnsEdit('') loads upstreams from /api/dhcp cache instead of pre-filling empty string
(async () => {
  ui.S.cache.set("/api/dhcp", { upstreams: ["1.1.1.1", "8.8.8.8"], ts: Date.now() });
  await ui.showDnsEdit("");
  const modalHtml = elements.modalBody ? elements.modalBody.innerHTML : "";
  assert.ok(modalHtml.includes("1.1.1.1") && modalHtml.includes("8.8.8.8"), "showDnsEdit('') should prefill cached upstreams: " + modalHtml);
})().catch(err => {
  console.error(err);
  process.exit(1);
});
""")


if __name__ == "__main__":
    unittest.main()
