#!/usr/bin/env python3
"""Sensitive UI values stay blurred until their own eye button is clicked."""

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
const sandbox = {
  console,
  document: {
    activeElement: null,
    addEventListener() {},
    createElement() { return {style: {}, remove() {}}; },
    getElementById() { return null; },
    querySelectorAll() { return []; },
  },
  window: {getSelection() { return {toString() { return ""; }}; }},
  localStorage: {getItem() { return null; }, setItem() {}},
  location: {host: "router.test"},
  setInterval() { return 1; },
  clearInterval() {},
  setTimeout() { return 1; },
  clearTimeout() {},
};
vm.createContext(sandbox);
vm.runInContext(source + `
;globalThis.__ui = {
  S, sensitive, sensitiveBlock, toggleSensitive, renderLan, renderNetwork, renderAdmin,
};`, sandbox);
const ui = sandbox.__ui;

function classList(initial = []) {
  const values = new Set(initial);
  return {
    toggle(name, force) {
      if (force) values.add(name); else values.delete(name);
      return force;
    },
    contains(name) { return values.has(name); },
  };
}

function eyeFixture(id) {
  const content = {
    inert: true,
    attributes: {"aria-hidden": "true"},
    removeAttribute(name) { delete this.attributes[name]; },
    setAttribute(name, value) { this.attributes[name] = String(value); },
  };
  const root = {
    classList: classList(["sensitive-value"]),
    querySelector(selector) {
      assert.equal(selector, ".sensitive-content");
      return content;
    },
  };
  const icon = {attributes: {"data-lucide": "eye"}, setAttribute(name, value) { this.attributes[name] = value; }};
  const button = {
    attributes: {},
    title: "",
    closest(selector) { assert.equal(selector, ".sensitive-value"); return root; },
    querySelector(selector) { assert.equal(selector, "[data-lucide]"); return icon; },
    setAttribute(name, value) { this.attributes[name] = String(value); },
  };
  return {id, content, root, icon, button};
}
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required to execute frontend tests")
class FrontendPrivacy(unittest.TestCase):
    def run_js(self, scenario):
        result = subprocess.run(
            ["node", "-", str(APP_JS)],
            input=NODE_PRELUDE + scenario,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_value_is_blurred_escaped_and_has_a_small_eye(self):
        self.run_js(r"""
const html = ui.sensitive('<img src=x onerror=alert(1)>', 'overview-wan');
assert.match(html, /class="sensitive-value"/);
assert.match(html, /class="sensitive-content" inert aria-hidden="true"/);
assert.match(html, /class="sensitive-toggle"/);
assert.match(html, /data-lucide="eye"/);
assert.match(html, /aria-pressed="false"/);
assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
assert.doesNotMatch(html, /<img src=x/);
""")

    def test_eye_toggles_one_value_and_render_keeps_it_open(self):
        self.run_js(r"""
const f = eyeFixture('client-ip-0');
ui.toggleSensitive(f.id, f.button);
assert.equal(f.root.classList.contains('revealed'), true);
assert.equal(f.content.inert, false);
assert.equal(f.content.attributes['aria-hidden'], undefined);
assert.equal(f.button.attributes['aria-pressed'], 'true');
assert.equal(f.icon.attributes['data-lucide'], 'eye-off');
let html = ui.sensitive('198.51.100.2', f.id);
assert.match(html, /sensitive-value revealed/);
assert.doesNotMatch(html, /sensitive-content" inert/);
assert.match(html, /data-lucide="eye-off"/);

ui.toggleSensitive(f.id, f.button);
assert.equal(f.root.classList.contains('revealed'), false);
assert.equal(f.content.inert, true);
assert.equal(f.content.attributes['aria-hidden'], 'true');
assert.equal(f.button.attributes['aria-pressed'], 'false');
html = ui.sensitive('198.51.100.2', f.id);
assert.doesNotMatch(html, /sensitive-value revealed/);
assert.match(html, /sensitive-content" inert/);
""")

    def test_raw_configuration_is_one_blurred_block(self):
        self.run_js(r"""
const html = ui.sensitiveBlock(['PrivateKey=<secret>', 'endpoint'], 'vpn-show');
assert.match(html, /sensitive-value sensitive-block/);
assert.match(html, /<pre>PrivateKey=&lt;secret&gt;\nendpoint<\/pre>/);
assert.match(html, /sensitive-content" inert/);
assert.match(html, /data-lucide="eye"/);
""")

    def test_lan_values_and_raw_configs_are_wired(self):
        self.run_js(r"""
const lan = ui.renderLan({
  '/api/clients': {clients: [{ip: '192.0.2.10', hostname: 'friend-phone', mac: 'aa:bb:cc:dd:ee:ff'}]},
  '/api/dhcp': {},
  '/api/interfaces': {interfaces: [{name: 'igc0', addresses: ['192.0.2.1/24']}]},
});
for (const id of ['lan-client-ip-0', 'lan-client-hostname-0', 'lan-client-mac-0', 'lan-interface-addresses']) {
  assert.match(lan, new RegExp(`data-sensitive-id="${id}"`), id);
}

const wan = ui.renderNetwork({
  '/api/interfaces': {},
  '/api/wan': {},
  '/api/pppoe': {config: ['PrivateKey=<secret>']},
});
assert.match(wan, /data-sensitive-id="wan-pppoe-config"/);
assert.match(wan, /PrivateKey=&lt;secret&gt;/);
""")

    def test_terminal_is_blurred_as_one_block(self):
        self.run_js(r"""
const html = ui.renderAdmin({
  '/api/system': {}, '/api/services': {}, '/api/services/all': [],
  '/api/backups': {}, '/api/system/updates': {}, '/api/repo/sources': {},
});
assert.match(html, /data-sensitive-id="admin-terminal"/);
assert.match(html, /id="termPlaceholder"/);
assert.match(html, /sensitive-value sensitive-block/);
""")


if __name__ == "__main__":
    unittest.main()
