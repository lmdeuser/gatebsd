from __future__ import annotations

import unittest
from contextlib import nullcontext
from unittest import mock

from gatebsd_ui.writers import port_forward


PF = '''wan_if="ng0"
lan_if="re1"
lan_net="10.88.0.0/24"
nat on $wan_if from $lan_net to any -> ($wan_if)
rdr on $lan_if proto { tcp udp } from $lan_net to ! <local_nets> port 53 -> ($lan_if)
pass in quick on $lan_if proto tcp from $lan_net to ($lan_if) port 3493 keep state
block in all
block in quick on $lan_if proto { tcp udp } from $lan_net to <doh> port 443
pass out quick keep state
pass in quick on $lan_if from $lan_net to ($lan_if) keep state
'''


def rule(**changes):
    value = {
        "id": "web",
        "enabled": True,
        "protocol": "tcp",
        "external_port": 443,
        "target_host": "10.88.0.155",
        "target_port": 8443,
        "sources": ["203.0.113.5/32", "198.51.100.0/24"],
    }
    value.update(changes)
    return value


class PortForwardValidationTests(unittest.TestCase):
    def test_source_allowlist_is_mandatory(self) -> None:
        for sources in ([], ["0.0.0.0/0"]):
            with self.subTest(sources=sources):
                with self.assertRaisesRegex(ValueError, "source"):
                    port_forward.validate_rule(rule(sources=sources))

    def test_any_source_requires_an_explicit_override(self) -> None:
        normalized = port_forward.validate_rule(rule(sources=["0.0.0.0/0"], allow_any_source=True))
        self.assertEqual(normalized["sources"], ["0.0.0.0/0"])

    def test_only_a_single_port_and_tcp_or_udp_are_accepted(self) -> None:
        for changes in ({"external_port": "443:444"}, {"target_port": 0}, {"protocol": "gre"}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    port_forward.validate_rule(rule(**changes))

    def test_target_must_belong_to_the_lan(self) -> None:
        with self.assertRaisesRegex(ValueError, "LAN"):
            port_forward.validate_rule(rule(target_host="8.8.8.8"))

    def test_sources_are_ipv4_networks_without_duplicates(self) -> None:
        normalized = port_forward.validate_rule(rule(sources=["203.0.113.5", "203.0.113.5/32"]))
        self.assertEqual(normalized["sources"], ["203.0.113.5/32"])


class PortForwardConfigTests(unittest.TestCase):
    def test_add_inserts_rdr_before_filters_and_pass_after_block(self) -> None:
        updated = port_forward.upsert_rule(PF, rule(), gateway="198.51.100.254")

        self.assertLess(updated.index("rdr on $wan_if"), updated.index("pass in quick on $lan_if proto tcp"))
        self.assertLess(updated.index("block in all"), updated.index("pass in quick on $wan_if"))
        self.assertIn('rdr on $wan_if proto tcp from { 203.0.113.5/32, 198.51.100.0/24 } to ($wan_if) port 443 -> 10.88.0.155 port 8443', updated)
        self.assertIn('pass in quick on $wan_if reply-to ($wan_if 198.51.100.254) proto tcp from { 203.0.113.5/32, 198.51.100.0/24 } to 10.88.0.155 port 8443 keep state', updated)
        self.assertEqual(port_forward.parse_rules(updated)[0]["id"], "web")

    def test_update_disable_and_delete_preserve_unmanaged_bytes(self) -> None:
        original = port_forward.upsert_rule(PF, rule(), gateway="198.51.100.254")
        disabled = port_forward.upsert_rule(original, rule(enabled=False), gateway="198.51.100.254")
        self.assertNotIn("rdr on $wan_if", disabled)
        self.assertNotIn("pass in quick on $wan_if", disabled)
        self.assertFalse(port_forward.parse_rules(disabled)[0]["enabled"])
        removed = port_forward.remove_rule(disabled, "web")
        self.assertEqual(removed, PF)

    def test_conflicting_external_endpoint_is_rejected(self) -> None:
        existing = port_forward.upsert_rule(PF, rule(), gateway="198.51.100.254")
        with self.assertRaisesRegex(ValueError, "already used"):
            port_forward.upsert_rule(existing, rule(id="other", target_port=443), gateway="198.51.100.254")

    def test_same_external_port_is_allowed_for_another_protocol(self) -> None:
        existing = port_forward.upsert_rule(PF, rule(), gateway="198.51.100.254")
        updated = port_forward.upsert_rule(existing, rule(id="dns", protocol="udp", external_port=53, target_port=53), gateway="198.51.100.254")
        self.assertEqual(len(port_forward.parse_rules(updated)), 2)

    def test_rule_ids_that_share_a_prefix_are_independent(self) -> None:
        existing = port_forward.upsert_rule(PF, rule(id="web-two", external_port=8443), gateway="198.51.100.254")
        existing = port_forward.upsert_rule(existing, rule(id="web"), gateway="198.51.100.254")
        remaining = port_forward.remove_rule(existing, "web")
        self.assertEqual([item["id"] for item in port_forward.parse_rules(remaining)], ["web-two"])

    def test_reconcile_changes_only_the_gateway(self) -> None:
        existing = port_forward.upsert_rule(PF, rule(), gateway="198.51.100.254")
        updated = port_forward.reconcile_gateway(existing, gateway="192.0.2.1")
        self.assertIn("reply-to ($wan_if 192.0.2.1)", updated)
        self.assertNotIn("198.51.100.254", updated)
        self.assertEqual(port_forward.reconcile_gateway(updated, gateway="192.0.2.1"), updated)

    def test_malformed_managed_block_is_not_rewritten(self) -> None:
        malformed = PF + "# GateBSD port-forward: begin id=broken\n"
        with self.assertRaisesRegex(ValueError, "managed block"):
            port_forward.parse_rules(malformed)


class PortForwardApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = mock.patch.object(port_forward, "exclusive_lock", return_value=nullcontext())
        self.lock.start()
        self.addCleanup(self.lock.stop)
        self.gateway = mock.patch.object(port_forward, "_current_wan_gateway", return_value="198.51.100.254")
        self.gateway.start()
        self.addCleanup(self.gateway.stop)

    def test_list_returns_rules_from_pf_conf(self) -> None:
        conf = port_forward.upsert_rule(PF, rule(), gateway="198.51.100.254")
        with mock.patch.object(port_forward, "_read_conf", return_value=conf):
            status, payload = port_forward.list_rules()
        self.assertEqual(status, 200)
        self.assertEqual(payload["rules"][0]["id"], "web")
        self.assertEqual(payload["lan_net"], "10.88.0.0/24")

    def test_save_uses_the_shared_pf_lock_and_confirmation(self) -> None:
        calls = []
        def apply(conf, **kwargs):
            calls.append((conf, kwargs))
            return 200, {"ok": True, "changed": True}
        with mock.patch.object(port_forward, "_read_conf", return_value=PF), mock.patch.object(port_forward, "pf_set_conf", side_effect=apply):
            status, _payload = port_forward.save_rule(rule())
        self.assertEqual(status, 200)
        self.assertIn("rdr on $wan_if", calls[0][0])
        self.assertEqual(calls[0][1]["lock_held"], True)
        self.assertNotEqual(calls[0][1].get("require_confirmation"), False)

    def test_delete_missing_rule_returns_404_without_applying(self) -> None:
        with mock.patch.object(port_forward, "_read_conf", return_value=PF), mock.patch.object(port_forward, "pf_set_conf") as apply:
            status, _payload = port_forward.delete_rule("missing")
        self.assertEqual(status, 404)
        apply.assert_not_called()

    def test_target_check_reports_the_actual_netcat_result(self) -> None:
        from types import SimpleNamespace

        conf = port_forward.upsert_rule(PF, rule(), gateway="198.51.100.254")
        result = SimpleNamespace(ok=True, stdout="", stderr="", error="")
        with mock.patch.object(port_forward, "_read_conf", return_value=conf), mock.patch.object(port_forward, "run", return_value=result) as command:
            status, payload = port_forward.test_rule("web")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["scope"], "lan-target")
        command.assert_called_once_with(["nc", "-z", "-w", "3", "10.88.0.155", "8443"], timeout=5)

    def test_gateway_reconcile_does_not_arm_lockout_rollback(self) -> None:
        conf = port_forward.upsert_rule(PF, rule(), gateway="198.51.100.254")
        calls = []
        def apply(candidate, **kwargs):
            calls.append((candidate, kwargs))
            return 200, {"ok": True}
        with mock.patch.object(port_forward, "_read_conf", return_value=conf), mock.patch.object(port_forward, "pf_set_conf", side_effect=apply):
            status, _payload = port_forward.apply_gateway("192.0.2.1")
        self.assertEqual(status, 200)
        self.assertIn("reply-to ($wan_if 192.0.2.1)", calls[0][0])
        self.assertEqual(calls[0][1]["require_confirmation"], False)
        self.assertEqual(calls[0][1]["lock_held"], True)


class PortForwardDeliveryTests(unittest.TestCase):
    def test_reconcile_wrapper_executes_the_real_entrypoint(self) -> None:
        import subprocess
        import tempfile
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            calls = work / "calls"
            launcher = work / "python"
            launcher.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" > '{calls}'\n", encoding="ascii")
            launcher.chmod(0o755)
            result = subprocess.run(
                ["sh", str(root / "sbin" / "gatebsd-port-forward"), "reconcile", "--gateway", "192.0.2.1"],
                capture_output=True,
                text=True,
                env={
                    "PATH": "/usr/bin:/bin",
                    "GATEBSD_PATH": "/usr/bin:/bin",
                    "GATEBSD_PYTHON_LAUNCHER": str(launcher),
                    "GATEBSD_BACKEND": str(root / "webui" / "backend"),
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(calls.read_text(encoding="ascii").strip(), "-m gatebsd_ui.writers.port_forward reconcile --gateway 192.0.2.1")

    def test_both_delivery_paths_install_the_helper(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        self.assertIn("gatebsd-port-forward", (root / "Makefile").read_text(encoding="utf-8"))
        self.assertIn("gatebsd-port-forward", (root / "ci" / "build.sh").read_text(encoding="utf-8"))


class PortForwardRouteTests(unittest.TestCase):
    def test_get_and_post_routes_are_wired(self) -> None:
        from gatebsd_ui import api

        with mock.patch.object(api.writers, "port_forward_list", return_value=(200, {"rules": []})):
            self.assertEqual(api.dispatch("/api/port-forwards")[0], 200)
        with mock.patch.object(api.writers, "port_forward_save", return_value=(200, {"ok": True})) as save:
            self.assertEqual(api.dispatch("/api/port-forwards/save", method="POST", body=rule())[0], 200)
            save.assert_called_once()
        with mock.patch.object(api.writers, "port_forward_delete", return_value=(200, {"ok": True})) as delete:
            self.assertEqual(api.dispatch("/api/port-forwards/delete", method="POST", body={"id": "web"})[0], 200)
            delete.assert_called_once_with("web")
        with mock.patch.object(api.writers, "port_forward_test", return_value=(200, {"ok": True})) as test:
            self.assertEqual(api.dispatch("/api/port-forwards/test", method="POST", body={"id": "web"})[0], 200)
            test.assert_called_once_with("web")

    def test_agent_allows_only_the_named_port_forward_endpoints(self) -> None:
        from gatebsd_ui import agent

        self.assertTrue(agent._agent_allowed("GET", "/api/port-forwards"))
        self.assertTrue(agent._agent_allowed("POST", "/api/port-forwards/save"))
        self.assertTrue(agent._agent_allowed("POST", "/api/port-forwards/delete"))
        self.assertTrue(agent._agent_allowed("POST", "/api/port-forwards/test"))
        self.assertFalse(agent._agent_allowed("POST", "/api/port-forwards"))


class PortForwardFrontendTests(unittest.TestCase):
    def test_firewall_view_contains_crud_test_and_confirmation_wiring(self) -> None:
        from pathlib import Path

        app = (Path(__file__).resolve().parents[1] / "webui" / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn('firewall: ["/api/firewall","/api/firewall/detail","/api/port-forwards","/api/reverse-ssh"]', app)
        for name in ("showPortForward", "savePortForward", "togglePortForward", "deletePortForward", "testPortForward"):
            self.assertIn(name, app)
        self.assertIn('Port Forwarding WAN → LAN', app)
        self.assertIn('/api/pf/conf/confirm', app)


if __name__ == "__main__":
    unittest.main()
