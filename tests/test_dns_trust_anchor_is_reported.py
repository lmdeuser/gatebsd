#!/usr/bin/env python3
"""The box must say that it cannot maintain its DNSSEC trust anchor.

The port's rc script runs `unbound-anchor` as the `unbound` account inside every
start. The anchor is written through a temporary file created beside it, and
/usr/local/etc/unbound is root:wheel 0755, so that account cannot create it.
Measured on the production router, 7 August:

    fatal error: could not open autotrust file for writing,
    /usr/local/etc/unbound/root.key.21101-0-3053dc71: Permission denied

rc.subr does not treat that as a failure. The daemon starts, every reader above
it reports a healthy service, and the anchor is quietly never maintained.

Reporting it from the restart alone was not enough, and that was the mistake
worth recording: the panel restarts services through /api/services/manage, which
goes to the generic service_control, so the route that carried the warning was
one no button calls. A condition of the box belongs where the box is described.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "webui" / "backend"))

from gatebsd_ui import adblock  # noqa: E402


def an_existing_account() -> str:
    """Any account that exists here; `unbound` need not, off the appliance."""
    import pwd
    for candidate in ("unbound", "nobody", "daemon"):
        try:
            pwd.getpwnam(candidate)
            return candidate
        except KeyError:
            continue
    return pwd.getpwuid(os.getuid()).pw_name


class TheAnchorDirectoryIsJudgedByOwnership(unittest.TestCase):
    """Derived from stat, not by attempting a write.

    This runs on every status poll, and a read with side effects is not a read.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name) / "unbound"
        self.dir.mkdir()
        self.account = an_existing_account()

    def test_a_directory_the_account_cannot_write_is_reported_as_such(self):
        """The production shape: owned by someone else, not group writable."""
        if os.geteuid() != 0:
            self.skipTest("changing owner requires root")
        import pwd
        os.chown(self.dir, 0, 0)
        self.dir.chmod(0o755)
        if pwd.getpwnam(self.account).pw_uid == 0:
            self.skipTest("the account under test is root, which writes anywhere")
        self.assertIs(adblock.trust_anchor_writable(self.dir, self.account), False)

    def test_a_directory_the_account_owns_is_reported_writable(self):
        if os.geteuid() != 0:
            self.skipTest("changing owner requires root")
        import pwd
        os.chown(self.dir, pwd.getpwnam(self.account).pw_uid, 0)
        self.dir.chmod(0o755)
        self.assertIs(adblock.trust_anchor_writable(self.dir, self.account), True)

    def test_an_unanswerable_question_is_not_answered_no(self):
        """`None` is "not measured". Drawing it as "no" is the old collapse."""
        self.assertIsNone(
            adblock.trust_anchor_writable(self.dir / "does-not-exist", self.account))
        self.assertIsNone(
            adblock.trust_anchor_writable(self.dir, "no-such-account-here"))

    def test_the_status_the_panel_reads_carries_the_fact(self):
        """Executed through the real status builder, not asserted about a name.

        The fix that reported this only from the restart route was invisible
        precisely because nobody checked which reply the panel actually reads.
        """
        status = adblock.status()
        self.assertIn("trust_anchor_writable", status)
        self.assertIn(status["trust_anchor_writable"], (True, False, None))


class ThePanelDrawsTheThreeStates(unittest.TestCase):
    """The frontend has no test runner on the machine that ships it.

    So the one thing asserted here is that all three states are handled and
    that `not measured` is not painted as a fault -- the same rule action_state
    imposes on every other verdict in this panel.
    """

    def setUp(self) -> None:
        self.app = (Path(__file__).resolve().parents[1]
                    / "webui" / "frontend" / "app.js").read_text(encoding="utf-8")

    def test_all_three_states_are_drawn(self):
        self.assertIn("trust_anchor_writable===false", self.app)
        self.assertIn("trust_anchor_writable===true", self.app)

    def test_not_measured_is_not_painted_as_a_fault(self):
        line = next(l for l in self.app.splitlines()
                    if "DNSSEC trust anchor" in l)
        after = line.split("trust_anchor_writable===true")[1]
        self.assertIn('"not measured","warn"', after,
                      "an unmeasured anchor must not be drawn as broken or fine")


if __name__ == "__main__":
    unittest.main()
