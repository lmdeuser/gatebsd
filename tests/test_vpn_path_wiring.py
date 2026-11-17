#!/usr/bin/env python3
"""The VPN state has to travel: adapter -> /api/overview -> the repair button.

A test that reads the source proves nothing. The first wiring test written for
`adblock` in 2.9.55 passed on its own explanatory comment, which is the same
silhouette as a call sitting behind `if false`. So everything here *runs*: the
real `overview()`, the real `dispatch()` the agent uses, and the real
`recover_internet()`.

What is substituted is the environment, never the logic under test. Recovery's
three probes reach the actual internet, and a build host has none; the route,
the interface and the operator's marker -- the facts this change is about --
are supplied as a real stub binary and a real file on disk, and read by the
real code.
"""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))

from gatebsd_ui import adapters, command, recovery  # noqa: E402
from gatebsd_ui.adapters import vpn_path  # noqa: E402
from gatebsd_ui.api import dispatch  # noqa: E402


def _stub_bin(directory: Path, name: str, body: str) -> None:
    script = directory / name
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


class OverviewCarriesTheState(unittest.TestCase):
    def test_the_real_overview_payload_has_vpn_path(self):
        payload = adapters.overview()
        self.assertIn("vpn_path", payload, "overview() does not carry the VPN state at all")
        state = payload["vpn_path"]
        self.assertIn(state["state"], set(vpn_path.LABELS))
        self.assertIsInstance(state["warnings"], list)

    def test_a_host_that_cannot_be_measured_says_so(self):
        """A build host has no `route -n get default`; that must not read green."""
        payload = adapters.overview()
        state = payload["vpn_path"]
        if state["state"] != vpn_path.UNKNOWN:
            self.skipTest("this host can actually measure its default route")
        self.assertIsNot(state["expected"], True)
        self.assertTrue(state["warnings"], "an unmeasured VPN produced no warning")

    def test_the_agent_route_serves_the_same_state(self):
        status, payload = dispatch("/api/overview", {}, method="GET")
        self.assertEqual(status, 200)
        self.assertIn("vpn_path", payload)


class TheRepairButtonNamesThePath(unittest.TestCase):
    """The 4 August lie, executed rather than described.

    With the operator's marker present and the default route on bare WAN, the
    button used to answer "Internet is working normally" -- and did, twice, over
    a household that had been outside the tunnel for two and a half hours.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

        # `command.run` deliberately ignores the caller's PATH and imposes its
        # own, so the stub machine has to be handed to it there. Everything
        # inside recovery -- `_iface_up`, `_default_interface`, `classify`, the
        # message -- is the real code reading a real (stubbed) machine.
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.set_default_iface("ng0")
        _stub_bin(self.bin, "ifconfig", 'echo "awg0: flags=10080c1<UP,RUNNING> metric 0 mtu 1280"')
        _stub_bin(self.bin, "ping", "exit 0")
        _stub_bin(self.bin, "fetch", "exit 0")
        _stub_bin(self.bin, "service", "exit 0")
        self._saved_path = command._SAFE_PATH
        command._SAFE_PATH = f"{self.bin}:{self._saved_path}"
        self.addCleanup(setattr, command, "_SAFE_PATH", self._saved_path)

        self.marker = self.root / "vpn_disabled"
        self._saved_marker = vpn_path.paths.VPN_DISABLED
        vpn_path.paths.VPN_DISABLED = self.marker
        self.addCleanup(setattr, vpn_path.paths, "VPN_DISABLED", self._saved_marker)

        self._saved_state = vpn_path.paths.FAILOVER_STATE
        vpn_path.paths.FAILOVER_STATE = self.root / "watchdog.json"
        self.addCleanup(setattr, vpn_path.paths, "FAILOVER_STATE", self._saved_state)
        vpn_path.paths.FAILOVER_STATE.write_text(json.dumps({"vpn_rolled_back": False}))

        # The one probe that cannot be stubbed through PATH: it invokes the
        # packaged interpreter by absolute path, which no build host has.
        healthy = type("R", (), {"ok": True, "stdout": "", "stderr": "",
                                 "error": None, "returncode": 0})()
        saved_dns = recovery._dns
        recovery._dns = lambda: healthy
        self.addCleanup(setattr, recovery, "_dns", saved_dns)

        self._saved_report = recovery.REPORT_PATH
        recovery.REPORT_PATH = self.root / "last-recovery.json"
        self.addCleanup(setattr, recovery, "REPORT_PATH", self._saved_report)
        self._saved_lock = recovery.LOCK_PATH
        recovery.LOCK_PATH = self.root / "recovery.lock"
        self.addCleanup(setattr, recovery, "LOCK_PATH", self._saved_lock)

    def set_default_iface(self, iface):
        _stub_bin(self.bin, "route", f'echo "   interface: {iface}"')

    def test_marker_present_and_traffic_direct_is_not_reported_as_normal(self):
        self.marker.write_text("yes\n")
        status, report = recovery.recover_internet()
        self.assertEqual(status, 200)
        self.assertTrue(report["already_working"], "the health checks were made to pass")
        self.assertNotEqual(
            report["message"], "Internet is working normally",
            "the button still claims normality over traffic outside the tunnel")
        self.assertIn("not via VPN", report["message"])
        self.assertIn("ng0", report["message"])
        self.assertEqual(report["vpn"]["state"], vpn_path.DISABLED_BY_OPERATOR)

    def test_bypassed_without_a_marker_is_not_already_working(self):
        """No marker, tunnel up, default on ng0: recovery must not stand down."""
        state = vpn_path.classify(
            interface_up=True, default_iface="ng0",
            operator_disabled=vpn_path.measure_operator_disabled(),
            rolled_back=vpn_path.measure_rolled_back())
        self.assertEqual(state["state"], vpn_path.BYPASSED)
        self.assertIsNot(state["expected"], True)

    def test_the_tunnel_in_the_path_still_reports_normality(self):
        self.set_default_iface("awg0")
        status, report = recovery.recover_internet()
        self.assertEqual(status, 200)
        self.assertEqual(report["message"], "Internet is working normally")
        self.assertEqual(report["vpn"]["state"], vpn_path.IN_PATH)


class TheFrontendReadsTheBackendState(unittest.TestCase):
    """`app.js` must not recompute the verdict it is handed.

    This one does read the source, and says so: there is no JS engine on the
    validator, so the rule cannot be executed there. It is a guard against the
    disjunction coming back, not evidence that the panel works.
    """

    def setUp(self):
        self.app_js = (Path(__file__).resolve().parent.parent
                       / "webui" / "frontend" / "app.js").read_text()

    def test_the_disjunction_is_gone(self):
        self.assertNotIn('vpn.vpn_is_default||vpn.interface?.state==="UP"', self.app_js)
        self.assertNotIn('vpn.vpn_is_default || vpn.interface?.state === "UP"', self.app_js)

    def test_the_panel_takes_in_tunnel_from_the_payload(self):
        self.assertIn("vpnPathState.in_tunnel===true", self.app_js)

    def test_the_banner_never_greens_on_an_unmeasured_state(self):
        self.assertIn("vpnPathState.expected === true", self.app_js)

    def test_the_warnings_come_from_the_backend(self):
        self.assertIn("(vpnPathState.warnings||[]).forEach", self.app_js)
        self.assertNotIn('msg:"VPN tunnel is inactive"', self.app_js)

    def test_no_invented_uptimes_are_shown_to_the_customer(self):
        """Two cards carried a hardcoded "Online 01:32:05". That is a fiction."""
        self.assertNotIn("01:32:05", self.app_js)
        self.assertNotIn("01:32:07", self.app_js)


if __name__ == "__main__":
    unittest.main()
