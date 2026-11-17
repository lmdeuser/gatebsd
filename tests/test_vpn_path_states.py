#!/usr/bin/env python3
"""The five VPN states, and the sixth that means "we did not measure".

Why this exists at all. On the night of 4 August the box wrote its own
`vpn_disabled` marker, the default route sat on bare WAN for two and a half
hours, and the panel showed a green tunnel the whole time. Nothing was broken
in the reader: `app.js` computed

    vpnUp = vpn_is_default || interface.state === "UP"

and that OR is true in both "the traffic is in the tunnel" and "the tunnel is
up while the traffic goes around it". One boolean over two unrelated facts, so
the single state worth warning about was the state that could never warn. The
"Repair internet" button answered "the internet is working normally" twice into
it, for the same reason one layer down.

Each test below hands the classifier a state rather than mocking the function
that reads one -- a test on a mocked reader proves the reader was called, not
that the state was understood.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))

from gatebsd_ui.adapters import vpn_path  # noqa: E402


def classify(**overrides):
    """A healthy tunnel, with whichever fact the test wants to change."""
    facts = {
        "interface_up": True,
        "default_iface": "awg0",
        "operator_disabled": False,
        "rolled_back": False,
    }
    facts.update(overrides)
    return vpn_path.classify(**facts)


def messages(state):
    return " ".join(w["msg"] for w in state["warnings"])


class FiveStatesAreToldApart(unittest.TestCase):
    def test_traffic_in_the_tunnel_is_quiet(self):
        state = classify()
        self.assertEqual(state["state"], vpn_path.IN_PATH)
        self.assertIs(state["in_tunnel"], True)
        self.assertIs(state["expected"], True)
        self.assertEqual(state["warnings"], [])

    def test_up_but_bypassed_is_not_the_same_as_in_path(self):
        """The exact state of 4 August, and the one the old OR could not see."""
        state = classify(default_iface="ng0")
        self.assertEqual(state["state"], vpn_path.BYPASSED)
        self.assertIs(state["in_tunnel"], False)
        self.assertIs(state["expected"], False)
        self.assertIn("bypassing", messages(state))
        self.assertIn("ng0", messages(state))

    def test_the_old_disjunction_could_not_tell_those_two_apart(self):
        """Guards the shape of the defect, not just its symptom."""
        in_path = classify()
        bypassed = classify(default_iface="ng0")
        old_verdict = lambda s: bool(s["is_default"] or s["interface_up"])
        self.assertEqual(old_verdict(in_path), old_verdict(bypassed))
        self.assertNotEqual(in_path["state"], bypassed["state"])
        self.assertNotEqual(in_path["in_tunnel"], bypassed["in_tunnel"])

    def test_operator_switched_it_off(self):
        state = classify(default_iface="ng0", operator_disabled=True)
        self.assertEqual(state["state"], vpn_path.DISABLED_BY_OPERATOR)
        self.assertIs(state["in_tunnel"], False)
        # The operator's own choice: no alarm, but the panel still says it.
        self.assertIs(state["expected"], True)
        self.assertIn("VPN disabled", messages(state))

    def test_the_watchdog_rolled_it_back_itself(self):
        state = classify(default_iface="ng0", rolled_back=True)
        self.assertEqual(state["state"], vpn_path.ROLLED_BACK)
        self.assertIs(state["expected"], False)
        self.assertIn("rolled back", messages(state))

    def test_interface_never_came_up(self):
        state = classify(interface_up=False, default_iface="ng0")
        self.assertEqual(state["state"], vpn_path.DOWN)
        self.assertIs(state["expected"], False)
        self.assertIn("is down", messages(state))

    def test_operator_marker_outranks_a_live_interface(self):
        """A marker over an up-but-bypassed tunnel is still the operator's."""
        state = classify(default_iface="ng0", operator_disabled=True, rolled_back=True)
        self.assertEqual(state["state"], vpn_path.DISABLED_BY_OPERATOR)


class NotMeasuredIsNotFine(unittest.TestCase):
    """"unknown" is the state this project has paid for four times already."""

    def test_unreadable_route_is_not_a_working_tunnel(self):
        state = classify(default_iface=None)
        self.assertEqual(state["state"], vpn_path.UNKNOWN)
        self.assertIsNone(state["in_tunnel"])
        self.assertIsNone(state["expected"])
        self.assertIn("not measured", messages(state))

    def test_unreadable_interface_is_not_a_working_tunnel(self):
        self.assertEqual(classify(interface_up=None)["state"], vpn_path.UNKNOWN)

    def test_unreadable_marker_is_not_an_absent_marker(self):
        self.assertEqual(classify(operator_disabled=None)["state"], vpn_path.UNKNOWN)

    def test_unknown_never_reads_as_expected(self):
        """The banner tests `expected === true`; None must not pass it."""
        for missing in ("interface_up", "default_iface", "operator_disabled"):
            with self.subTest(missing=missing):
                self.assertIsNot(classify(**{missing: None})["expected"], True)

    def test_an_unreadable_rollback_flag_still_yields_a_verdict(self):
        """Only three facts are load-bearing; this one may be missing."""
        state = classify(default_iface="ng0", rolled_back=None)
        self.assertEqual(state["state"], vpn_path.BYPASSED)


class TheMarkerIsReadWithoutGuessing(unittest.TestCase):
    """`Path.exists()` answers False for "no marker" and for "cannot look"."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.marker = Path(self.tmp.name) / "vpn_disabled"
        self._saved = vpn_path.paths.VPN_DISABLED
        vpn_path.paths.VPN_DISABLED = self.marker
        self.addCleanup(setattr, vpn_path.paths, "VPN_DISABLED", self._saved)

    def test_absent_marker(self):
        self.assertIs(vpn_path.measure_operator_disabled(), False)

    def test_present_marker(self):
        self.marker.write_text("no\n")
        self.assertIs(vpn_path.measure_operator_disabled(), True)

    def test_a_path_we_cannot_walk_is_reported_as_unknown(self):
        """The root-proof half of the same question.

        The permission case below is the realistic one and it is skipped under
        root -- which is exactly how the harness runs, so on its own it would
        guard nothing. A parent that is a regular file gives ENOTDIR to every
        uid alive, and `Path.exists()` swallows that into a cheerful False just
        the same.
        """
        blocker = Path(self.tmp.name) / "not-a-directory"
        blocker.write_text("")
        vpn_path.paths.VPN_DISABLED = blocker / "vpn_disabled"
        self.assertFalse(vpn_path.paths.VPN_DISABLED.exists(),
                         "Path.exists() is supposed to be the wrong answer here")
        self.assertIsNone(vpn_path.measure_operator_disabled())

    @unittest.skipIf(os.geteuid() == 0, "root traverses a 0000 directory anyway")
    def test_unreadable_directory_is_reported_as_unknown(self):
        closed = Path(self.tmp.name) / "closed"
        closed.mkdir()
        vpn_path.paths.VPN_DISABLED = closed / "vpn_disabled"
        closed.chmod(0o000)
        self.addCleanup(closed.chmod, 0o755)
        self.assertIsNone(vpn_path.measure_operator_disabled())


class TheMarkerPathIsOnePath(unittest.TestCase):
    """gatewayctl, the watchdog and Python must read the same file."""

    def test_python_honours_the_shell_environment_variable(self):
        from gatebsd_ui import paths as paths_module
        import importlib

        os.environ["GATEBSD_VPN_DISABLED_FLAG"] = "/tmp/gatebsd-test-marker"
        try:
            reloaded = importlib.reload(paths_module)
            self.assertEqual(str(reloaded.VPN_DISABLED), "/tmp/gatebsd-test-marker")
        finally:
            del os.environ["GATEBSD_VPN_DISABLED_FLAG"]
            importlib.reload(paths_module)

    def test_the_shell_side_uses_that_same_variable(self):
        root = Path(__file__).resolve().parent.parent
        for script in ("sbin/gatewayctl", "sbin/gatebsd-watchdog.sh"):
            with self.subTest(script=script):
                self.assertIn("GATEBSD_VPN_DISABLED_FLAG", (root / script).read_text())


if __name__ == "__main__":
    unittest.main()
