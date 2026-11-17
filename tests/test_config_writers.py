"""Regression tests for the PF, DNS and DHCP configuration writers.

These three modules had no test coverage at all, despite being the only code
paths that can rewrite the site's firewall, resolver and address assignment. The
defects they guard against are semantic rather than syntactic: every case below
produces a config that ``pfctl -nf`` / ``unbound-checkconf`` / ``dhcpd -t``
accepts and that then takes the site offline.
"""
from __future__ import annotations

import ipaddress
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from gatebsd_ui.command import CommandResult
from gatebsd_ui.writers import dhcp, dns, firewall


def ok_result(stdout: str = "") -> CommandResult:
    return CommandResult(
        command=["stub"], ok=True, returncode=0, stdout=stdout, stderr="", error=None
    )


def fail_result(stderr: str = "boom") -> CommandResult:
    return CommandResult(
        command=["stub"], ok=False, returncode=1, stdout="", stderr=stderr, error=None
    )


PF_SAFE = """wan_if="ng0"
lan_if="re1"
lan_net="10.88.0.0/24"
block in all
pass out quick keep state
pass in quick on $lan_if from $lan_net to ($lan_if) keep state
pass in quick on $lan_if from $lan_net to any keep state
"""

PF_LOCKOUT = """wan_if="ng0"
lan_if="re1"
lan_net="10.88.0.0/24"
block in all
pass out quick keep state
pass in quick on $lan_if from $lan_net to 10.9.9.9 keep state
"""

PF_COMMENTS_ONLY = "# every rule removed\n"


class PfAntiLockoutTests(unittest.TestCase):
    """A syntactically valid ruleset can still be a total lockout."""

    def test_ruleset_permitting_lan_to_router_is_accepted(self) -> None:
        reachable, reason = firewall.check_management_access(PF_SAFE)
        self.assertTrue(reachable, reason)

    def test_ruleset_without_a_path_to_the_router_is_rejected(self) -> None:
        # The LAN may talk to one specific host, but nothing may reach the
        # router itself: SSH and the web UI both stop answering.
        reachable, reason = firewall.check_management_access(PF_LOCKOUT)
        self.assertFalse(reachable)
        self.assertIn("lock out", reason)

    def test_default_pass_ruleset_is_not_treated_as_lockout(self) -> None:
        # No block rule means default-pass, which is undesirable for other
        # reasons but cannot lock anyone out.
        reachable, _reason = firewall.check_management_access(PF_COMMENTS_ONLY)
        self.assertTrue(reachable)

    def test_literal_interface_name_is_recognised_without_a_macro(self) -> None:
        conf = "block in all\npass in quick on re1 from 10.88.0.0/24 to (re1) keep state\n"
        with mock.patch.object(firewall, "_lan_interface", return_value="re1"):
            reachable, reason = firewall.check_management_access(conf)
        self.assertTrue(reachable, reason)

    def test_to_any_counts_as_reaching_the_router(self) -> None:
        conf = 'lan_if="re1"\nblock in all\npass in on $lan_if to any keep state\n'
        with mock.patch.object(firewall, "_lan_interface", return_value="re1"):
            reachable, reason = firewall.check_management_access(conf)
        self.assertTrue(reachable, reason)

    def test_commented_out_pass_rule_does_not_satisfy_the_check(self) -> None:
        conf = (
            'lan_if="re1"\n'
            "block in all\n"
            "# pass in quick on $lan_if from any to ($lan_if) keep state\n"
        )
        with mock.patch.object(firewall, "_lan_interface", return_value="re1"):
            reachable, _reason = firewall.check_management_access(conf)
        self.assertFalse(reachable)


class PfSetConfTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.pf_conf = root / "pf.conf"
        self.pf_conf.write_text(PF_SAFE, encoding="utf-8")
        self.pending = root / "pf-pending-commit.json"
        self._patches = [
            mock.patch.object(firewall, "PF_CONF", self.pf_conf),
            mock.patch.object(firewall, "PF_PENDING_PATH", self.pending),
            mock.patch.object(firewall.backup, "backup_files", return_value={"stub": True}),
            mock.patch.object(firewall, "_lan_interface", return_value="re1"),
        ]
        for patch in self._patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self._patches):
            patch.stop()
        self._tmp.cleanup()

    def test_lockout_ruleset_is_refused_and_disk_untouched(self) -> None:
        with mock.patch.object(firewall, "run", return_value=ok_result()) as runner:
            status, payload = firewall.pf_set_conf(PF_LOCKOUT)
        self.assertEqual(status, 409)
        self.assertIn("lock out", payload["error"])
        # Refused before pfctl was invoked at all.
        runner.assert_not_called()
        self.assertEqual(self.pf_conf.read_text(encoding="utf-8"), PF_SAFE)

    def test_lockout_ruleset_can_be_forced_with_explicit_override(self) -> None:
        with mock.patch.object(firewall, "run", return_value=ok_result()):
            status, payload = firewall.pf_set_conf(PF_LOCKOUT, allow_lockout=True)
        self.assertEqual(status, 200)
        self.assertIn("lockout_override", payload)
        self.assertEqual(self.pf_conf.read_text(encoding="utf-8"), PF_LOCKOUT)

    def test_accepted_change_arms_a_pending_revert(self) -> None:
        new = PF_SAFE + "pass in quick on $lan_if proto tcp to any port 8080 keep state\n"
        with mock.patch.object(firewall, "run", return_value=ok_result()):
            status, payload = firewall.pf_set_conf(new)
        self.assertEqual(status, 200)
        self.assertTrue(payload["confirmation_required"])
        record = json.loads(self.pending.read_text(encoding="utf-8"))
        # The *previous* ruleset is what a revert must restore.
        self.assertEqual(record["previous"], PF_SAFE)
        self.assertGreater(record["deadline"], int(time.time()))

    def test_confirmation_clears_the_pending_revert(self) -> None:
        new = PF_SAFE + "# confirmed change\n"
        with mock.patch.object(firewall, "run", return_value=ok_result()):
            firewall.pf_set_conf(new)
        self.assertTrue(self.pending.exists())
        status, payload = firewall.pf_confirm_conf()
        self.assertEqual(status, 200)
        self.assertTrue(payload["confirmed"])
        self.assertFalse(self.pending.exists())

    def test_unconfirmed_change_is_reverted_after_the_deadline(self) -> None:
        """The half of confirm-commit that actually prevents a lockout.

        If the new ruleset blocked management access the operator cannot reach
        the confirm endpoint, so the revert has to happen without them.
        """
        new = PF_SAFE + "# never confirmed\n"
        with mock.patch.object(firewall, "run", return_value=ok_result()):
            firewall.pf_set_conf(new)
        self.assertEqual(self.pf_conf.read_text(encoding="utf-8"), new)

        # Before the deadline: nothing happens.
        did_revert, detail = firewall.pf_revert_expired_commit()
        self.assertFalse(did_revert)
        self.assertTrue(detail["pending"])

        record = json.loads(self.pending.read_text(encoding="utf-8"))
        record["deadline"] = int(time.time()) - 1
        self.pending.write_text(json.dumps(record), encoding="utf-8")

        with mock.patch.object(firewall, "run", return_value=ok_result()):
            did_revert, detail = firewall.pf_revert_expired_commit()
        self.assertTrue(did_revert)
        self.assertTrue(detail["reverted"])
        self.assertEqual(self.pf_conf.read_text(encoding="utf-8"), PF_SAFE)
        self.assertFalse(self.pending.exists())

    def test_skip_confirmation_clears_any_stale_pending_record(self) -> None:
        self.pending.parent.mkdir(parents=True, exist_ok=True)
        self.pending.write_text(json.dumps({"deadline": 1, "previous": "x"}), encoding="utf-8")
        new = PF_SAFE + "# direct\n"
        with mock.patch.object(firewall, "run", return_value=ok_result()):
            status, payload = firewall.pf_set_conf(new, require_confirmation=False)
        self.assertEqual(status, 200)
        self.assertNotIn("confirmation_required", payload)
        self.assertFalse(self.pending.exists())

    def test_syntax_error_leaves_disk_and_pending_state_untouched(self) -> None:
        new = PF_SAFE + "# broken\n"
        with mock.patch.object(firewall, "run", return_value=fail_result("syntax")):
            status, _payload = firewall.pf_set_conf(new)
        self.assertEqual(status, 400)
        self.assertEqual(self.pf_conf.read_text(encoding="utf-8"), PF_SAFE)
        self.assertFalse(self.pending.exists())

    def test_no_temporary_candidate_files_are_left_behind(self) -> None:
        new = PF_SAFE + "# leak check\n"
        with mock.patch.object(firewall, "run", return_value=fail_result()):
            firewall.pf_set_conf(new)
        leftovers = list(self.pf_conf.parent.glob(".gatebsd-pf.*"))
        self.assertEqual(leftovers, [])


class VpnKeyValidationTests(unittest.TestCase):
    """Peer keys must be canonical, not merely key-shaped.

    The former check was a 43-45 character base64 character-class match, which
    accepted truncated and re-wrapped keys. Those were written to the live
    config and only rejected later by awg-quick, so the tunnel silently failed
    to come up on the next service restart rather than at the point of the
    mistake.
    """

    def test_canonical_key_is_accepted(self) -> None:
        from gatebsd_ui.writers.vpn import _is_valid_wg_key

        self.assertTrue(_is_valid_wg_key("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="))

    def test_wrong_length_and_non_canonical_payloads_are_rejected(self) -> None:
        from gatebsd_ui.writers.vpn import _is_valid_wg_key

        for candidate in (
            "A" * 43,           # cannot decode to 32 bytes
            "A" * 44,           # well-formed base64, wrong decoded length
            "A" * 45,
            "A" * 42 + "==",    # non-canonical padding
            "",
            None,
            12345,
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",  # padding stripped
        ):
            with self.subTest(candidate=candidate):
                self.assertFalse(_is_valid_wg_key(candidate))

    def test_peer_add_uses_the_strict_validator(self) -> None:
        # Guards against the add path reverting to the permissive regex while
        # the config-level validator stays strict, which is what allowed an
        # invalid key onto disk in the first place.
        from gatebsd_ui.writers import vpn

        source = Path(vpn.__file__).read_text(encoding="utf-8")
        add_start = source.index("def awg_peer_add(")
        add_body = source[add_start : source.index("\ndef ", add_start + 10)]
        self.assertIn("_is_valid_wg_key(peer_pubkey)", add_body)
        self.assertNotIn("_PUBKEY_VALID_RE", add_body)

    def test_peer_edits_report_whether_the_tunnel_was_reloaded(self) -> None:
        # Writing the file does not change the running interface, so a removed
        # peer keeps working and a new one cannot connect until the next
        # restart. The response must not imply the edit is live.
        from gatebsd_ui.writers import vpn

        source = Path(vpn.__file__).read_text(encoding="utf-8")
        for function in ("def awg_peer_add(", "def awg_peer_remove("):
            start = source.index(function)
            body = source[start : source.index("\ndef ", start + 10)]
            with self.subTest(function=function):
                self.assertIn("reload_required", body)
                self.assertIn("_sync_running_interface", body)


class DnsUpstreamValidationTests(unittest.TestCase):
    """unbound-checkconf accepts all of these; resolution still stops."""

    def setUp(self) -> None:
        # Report no local addresses unless a test says otherwise.
        self._patch = mock.patch.object(dns, "run", return_value=ok_result(""))
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()

    def test_routable_upstreams_are_accepted(self) -> None:
        servers, error = dns._normalize_servers(["1.1.1.1", "8.8.8.8"])
        self.assertIsNone(error)
        self.assertEqual(servers, ["1.1.1.1", "8.8.8.8"])

    def test_duplicates_are_collapsed(self) -> None:
        servers, error = dns._normalize_servers(["1.1.1.1", "1.1.1.1"])
        self.assertIsNone(error)
        self.assertEqual(servers, ["1.1.1.1"])

    def test_unusable_addresses_are_rejected(self) -> None:
        for candidate, expected in [
            ("0.0.0.0", "unspecified"),
            ("127.0.0.1", "loopback"),
            ("224.0.0.1", "multicast"),
            ("255.255.255.255", "broadcast"),
            ("169.254.1.1", "link-local"),
            ("240.0.0.1", "reserved"),
            ("::", "unspecified"),
            ("::1", "loopback"),
        ]:
            with self.subTest(candidate=candidate):
                servers, error = dns._normalize_servers([candidate])
                self.assertIsNone(servers, candidate)
                assert error is not None
                self.assertIn(expected, error)

    def test_router_own_address_is_rejected_to_avoid_a_resolution_loop(self) -> None:
        ifconfig = "re1: flags=8843\n\tinet 10.88.0.1 netmask 0xffffff00\n"
        with mock.patch.object(dns, "run", return_value=ok_result(ifconfig)):
            servers, error = dns._normalize_servers(["10.88.0.1"])
        self.assertIsNone(servers)
        assert error is not None
        self.assertIn("resolution loop", error)

    def test_local_address_check_fails_open_when_ifconfig_is_unavailable(self) -> None:
        # An unreadable ifconfig must not block a legitimate DNS change.
        with mock.patch.object(dns, "run", return_value=fail_result()):
            servers, error = dns._normalize_servers(["1.1.1.1"])
        self.assertIsNone(error)
        self.assertEqual(servers, ["1.1.1.1"])

    def test_empty_and_oversized_lists_are_rejected(self) -> None:
        self.assertIsNone(dns._normalize_servers([])[0])
        self.assertIsNone(dns._normalize_servers(["1.1.1.1"] * 9)[0])
        self.assertIsNone(dns._normalize_servers("1.1.1.1")[0])
        self.assertIsNone(dns._normalize_servers([b"1.1.1.1"])[0])


DHCPD_SAMPLE = """subnet 10.88.0.0 netmask 255.255.255.0 {
        option routers 10.88.0.1;
        option domain-name-servers 10.88.0.1;
        range 10.88.0.100 10.88.0.200;
}

host printer {
        hardware ethernet aa:bb:cc:dd:ee:ff;
        fixed-address 10.88.0.10;
}
"""


class DhcpRangeValidationTests(unittest.TestCase):
    """dhcpd -t accepts these ranges and then hands out conflicting addresses."""

    def _replace(self, start: str, end: str, text: str = DHCPD_SAMPLE):
        return dhcp._replace_range(
            text, ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
        )

    def test_valid_range_is_accepted(self) -> None:
        result, error = self._replace("10.88.0.100", "10.88.0.150")
        self.assertIsNone(error)
        assert result is not None
        self.assertIn("range 10.88.0.100 10.88.0.150;", result)

    def test_range_covering_the_advertised_gateway_is_rejected(self) -> None:
        # The router would hand out its own address: duplicate-address conflict
        # on the default gateway, and clients get a broken route and resolver.
        result, error = self._replace("10.88.0.1", "10.88.0.200")
        self.assertIsNone(result)
        assert error is not None
        self.assertIn("gateway", error)

    def test_range_covering_a_static_reservation_is_rejected(self) -> None:
        result, error = self._replace("10.88.0.5", "10.88.0.50")
        self.assertIsNone(result)
        assert error is not None
        self.assertIn("reserved", error)
        self.assertIn("printer", error)

    def test_commented_out_reservation_does_not_block_a_range(self) -> None:
        text = DHCPD_SAMPLE.replace(
            "        fixed-address 10.88.0.10;",
            "        # fixed-address 10.88.0.10;",
        )
        result, error = self._replace("10.88.0.5", "10.88.0.50", text)
        self.assertIsNone(error, error)
        self.assertIsNotNone(result)

    def test_inverted_and_edge_boundaries_are_rejected(self) -> None:
        self.assertIsNone(self._replace("10.88.0.200", "10.88.0.100")[0])
        self.assertIsNone(self._replace("10.88.0.0", "10.88.0.200")[0])
        self.assertIsNone(self._replace("10.88.0.100", "10.88.0.255")[0])

    def test_range_outside_every_subnet_is_rejected(self) -> None:
        result, error = self._replace("10.0.0.10", "10.0.0.20")
        self.assertIsNone(result)
        assert error is not None
        self.assertIn("exactly one configured subnet", error)


class DhcpStaticParsingTests(unittest.TestCase):
    """Brace accounting must not be confused by braces inside comments."""

    def test_reservations_are_paired_with_their_host(self) -> None:
        lines = DHCPD_SAMPLE.splitlines()
        found = dhcp._static_reservations(lines)
        self.assertIn((ipaddress.IPv4Address("10.88.0.10"), "printer"), found)

    def test_declared_routers_are_found_subnet_first(self) -> None:
        lines = DHCPD_SAMPLE.splitlines()
        routers = dhcp._declared_routers(lines, 0, len(lines))
        self.assertIn(ipaddress.IPv4Address("10.88.0.1"), routers)

    def test_comment_stripping_ignores_braces_in_comments(self) -> None:
        self.assertEqual(dhcp._strip_comment("value; # closing } brace"), "value; ")
        self.assertEqual(dhcp._strip_comment("# { opening brace"), "")

    def test_block_matches_mac_on_a_single_line_declaration(self) -> None:
        block = "host x { hardware ethernet aa:bb:cc:dd:ee:ff; fixed-address 10.0.0.5; }\n"
        self.assertTrue(dhcp._block_matches_mac(block, "aa:bb:cc:dd:ee:ff"))
        self.assertFalse(dhcp._block_matches_mac(block, "11:22:33:44:55:66"))

    def test_commented_mac_does_not_count_as_a_match(self) -> None:
        block = "host x {\n  # hardware ethernet aa:bb:cc:dd:ee:ff;\n}\n"
        self.assertFalse(dhcp._block_matches_mac(block, "aa:bb:cc:dd:ee:ff"))


class DhcpStaticRemoveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.conf = Path(self._tmp.name) / "dhcpd.conf"
        self._patches = [
            mock.patch.object(dhcp, "DHCPD_CONF", self.conf),
            mock.patch.object(dhcp.backup, "backup_files", return_value={"stub": True}),
        ]
        for patch in self._patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self._patches):
            patch.stop()
        self._tmp.cleanup()

    def test_host_with_a_brace_in_a_comment_is_still_removable(self) -> None:
        # A `}` inside a comment used to close the block early, leaving orphaned
        # directives at top level and a config that failed validation.
        self.conf.write_text(
            "host printer {\n"
            "        # note: replaced unit } spare in storage\n"
            "        hardware ethernet aa:bb:cc:dd:ee:ff;\n"
            "        fixed-address 10.88.0.10;\n"
            "}\n",
            encoding="utf-8",
        )
        with mock.patch.object(dhcp, "run", return_value=ok_result()):
            status, payload = dhcp.static_remove("aa:bb:cc:dd:ee:ff")
        self.assertEqual(status, 200, payload)
        remaining = self.conf.read_text(encoding="utf-8")
        self.assertNotIn("aa:bb:cc:dd:ee:ff", remaining)
        self.assertNotIn("fixed-address", remaining)

    def test_host_with_an_opening_brace_in_a_comment_is_found(self) -> None:
        # A `{` inside a comment used to leave the parser inside the block to
        # EOF, so an existing host reported as not found.
        self.conf.write_text(
            "host printer {\n"
            "        # see ticket {1234}\n"
            "        hardware ethernet aa:bb:cc:dd:ee:ff;\n"
            "}\n"
            "host other {\n"
            "        hardware ethernet 11:22:33:44:55:66;\n"
            "}\n",
            encoding="utf-8",
        )
        with mock.patch.object(dhcp, "run", return_value=ok_result()):
            status, payload = dhcp.static_remove("aa:bb:cc:dd:ee:ff")
        self.assertEqual(status, 200, payload)
        remaining = self.conf.read_text(encoding="utf-8")
        self.assertNotIn("aa:bb:cc:dd:ee:ff", remaining)
        self.assertIn("11:22:33:44:55:66", remaining)

    def test_single_line_host_declaration_is_removable(self) -> None:
        self.conf.write_text(
            "host printer { hardware ethernet aa:bb:cc:dd:ee:ff; fixed-address 10.88.0.10; }\n"
            "host other { hardware ethernet 11:22:33:44:55:66; }\n",
            encoding="utf-8",
        )
        with mock.patch.object(dhcp, "run", return_value=ok_result()):
            status, payload = dhcp.static_remove("aa:bb:cc:dd:ee:ff")
        self.assertEqual(status, 200, payload)
        remaining = self.conf.read_text(encoding="utf-8")
        self.assertNotIn("aa:bb:cc:dd:ee:ff", remaining)
        self.assertIn("11:22:33:44:55:66", remaining)

    def test_missing_mac_reports_not_found_and_changes_nothing(self) -> None:
        original = DHCPD_SAMPLE
        self.conf.write_text(original, encoding="utf-8")
        with mock.patch.object(dhcp, "run", return_value=ok_result()):
            status, _payload = dhcp.static_remove("99:99:99:99:99:99")
        self.assertEqual(status, 404)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), original)

    def test_validation_failure_does_not_publish(self) -> None:
        original = DHCPD_SAMPLE
        self.conf.write_text(original, encoding="utf-8")
        with mock.patch.object(dhcp, "run", return_value=fail_result("bad config")):
            status, _payload = dhcp.static_remove("aa:bb:cc:dd:ee:ff")
        self.assertEqual(status, 400)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
