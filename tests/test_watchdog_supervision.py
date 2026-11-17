"""Functional regression tests for what happens when the watchdog dies.

The defect these exist for was seen on 31 July: the daemon a package upgrade had
just started was gone within a minute and left nothing behind to say so. Its
TERM trap had not run, so the state file still described the *previous* stop;
syslog held no record; the pidfile was stale. The router ran without failover
and the only way to find out was to ask ``service`` -- which nobody does until
something else has already gone wrong.

Two properties are required of an exit nobody asked for: it is written down, and
it is undone. The first is tested here by running the real daemon. The second
belongs to rc.d -- daemon(8) supervision -- and is covered by the contract tests
in ``test_rc_boot.py`` and by the boot rehearsal on the rig.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

# The suite is run with `unittest discover -s tests`, which puts this directory
# on the path; the insert keeps the sibling import working when a single module
# is run by name instead.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_watchdog_failover import WATCHDOG, WatchdogHarness  # noqa: E402

UNEXPECTED = "watchdog exited unexpectedly"


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
class WatchdogExitTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = WatchdogHarness(Path(self._tmp.name))
        # ensure_root_dir requires a root-owned run directory; skip when not root.
        if os.getuid() != 0:
            self.skipTest("watchdog requires a root-owned run directory")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _build(self, iterations: int) -> None:
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=10,
            iterations=iterations,
        )

    def test_an_exit_nobody_asked_for_is_written_to_the_log(self) -> None:
        """The loop ends because a command failed under `set -e`.

        That is exactly the shape of the silent death: no signal, no trap, no
        state written -- previously no trace at all.
        """
        self._build(iterations=1)

        self.harness.run_watchdog()

        log = self.harness.log.read_text(encoding="utf-8")
        self.assertIn(UNEXPECTED, log)
        self.assertIn("supervisor should restart it", log)

    def test_a_stop_that_was_asked_for_is_not_reported_as_a_death(self) -> None:
        """A TERM must leave the ordinary stop record and nothing alarming.

        Without the distinction the log would cry wolf on every reboot and
        every package upgrade, and the line that matters would stop meaning
        anything.
        """
        self._build(iterations=10_000)
        env = self.harness.environment()
        out = (self.harness.root / "stdout.log").open("wb")
        try:
            proc = subprocess.Popen(
                ["sh", str(WATCHDOG)],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=out,
                start_new_session=True,
            )
            deadline = time.monotonic() + 15
            while not self.harness.state_file.exists():
                if time.monotonic() > deadline:
                    self.fail("the watchdog never wrote its state file")
                time.sleep(0.05)
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                self.fail("the watchdog did not stop when asked")
        finally:
            out.close()

        state = json.loads(self.harness.state_file.read_text(encoding="utf-8"))
        self.assertEqual(state["state"], "STOPPED", state)
        self.assertEqual(state["reason"], "stopped", state)
        self.assertNotIn(UNEXPECTED, self.harness.log.read_text(encoding="utf-8"))
