"""Functional regression tests for restarting a crashed service from the tick.

The defect these exist for was seen live on 31 July: the watchdog process was
alive and ``service gatebsd_failover status`` said "running", but no tick had
happened for six minutes and the state file was never written. ``ps`` showed the
main process in ``wait`` and its child in ``piperd``, and the last line in the
log was awg-quick's own ``[+] Backgrounding route monitor``.

``check_service`` read the output of ``service <name> start`` through
``cmd | while read``. awg-quick backgrounds a route monitor which inherits the
write end of that pipe and never closes it, so the reader waits for an EOF that
cannot arrive. Outward appearance: a healthy daemon. Reality: failover dead
until a human restarts it.

The tests therefore run the real daemon against a ``service`` stub that behaves
the way awg-quick does -- prints, leaves a child holding the inherited
descriptor, and returns -- and assert that the tick *finishes*. The
reintroduction test runs a copy of the watchdog with the pipe put back, so the
defect is executed rather than described.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# The suite is run with `unittest discover -s tests`, which puts this directory
# on the path; the insert keeps the sibling import working when a single module
# is run by name instead.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_watchdog_failover import WATCHDOG, WatchdogHarness  # noqa: E402

# The stubbed route monitor outlives the start by this much. It only has to
# exceed the run timeout below: the point is that the descriptor is still held
# when the watchdog is expected to have moved on.
MONITOR_HOLD_SECONDS = 20
RUN_TIMEOUT_SECONDS = 6

# The line awg-quick prints just before it detaches the monitor. Asserting on it
# proves the output was captured rather than dropped on the floor.
MONITOR_LINE = "[+] Backgrounding route monitor"


class ServiceRestartHarness(WatchdogHarness):
    """Adds a service stub that backgrounds a descriptor-holding child."""

    def crashed_service(self, name: str) -> None:
        """Make ``name`` report DOWN, then start like awg-quick does.

        ``/bin/sleep`` is called by absolute path on purpose: ``sleep`` on PATH
        is the stub that bounds the daemon loop, and calling it here would eat
        an iteration.
        """
        started = self.root / f"{name}.started"
        self._write(
            "service",
            f"""#!/bin/sh
printf 'service %s\\n' "$*" >> {self.calls}
if [ "$1" = {name} ]; then
  case "$2" in
    status)
      [ -f {started} ] || exit 1
      ;;
    start)
      echo "[#] awg-quick up awg0"
      echo "{MONITOR_LINE}"
      : > {started}
      /bin/sleep {MONITOR_HOLD_SECONDS} &
      ;;
  esac
fi
exit 0
""",
        )

    def reintroduce(self, pattern: str, replacement: str) -> Path:
        """Return a copy of the watchdog with the fix edited back out.

        A copy, and not an assertion about the source, because an earlier
        generation of these tests read the text and passed happily with the call
        under test sitting behind ``if false``.
        """
        source = WATCHDOG.read_text(encoding="utf-8")
        patched, count = re.subn(pattern, replacement, source)
        if count == 0:
            raise AssertionError(f"reintroduction pattern never matched: {pattern!r}")
        script = self.root / "watchdog-defective.sh"
        script.write_text(patched, encoding="utf-8")
        script.chmod(0o755)
        return script

    def run_supervised(self, *, script: Path | None = None) -> bool:
        """Run one tick with a deadline. True if the daemon finished in time.

        Output goes to files rather than pipes, and the daemon gets its own
        process group. Both are needed for the defective run: its blocked reader
        is a *child* of the watchdog, so killing the watchdog alone would leave
        the reader holding this end of a pipe and the test would hang in exactly
        the way the daemon does.
        """
        env = self.environment()
        out = (self.root / "stdout.log").open("wb")
        err = (self.root / "stderr.log").open("wb")
        try:
            proc = subprocess.Popen(
                ["sh", str(script or WATCHDOG)],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
            try:
                proc.wait(timeout=RUN_TIMEOUT_SECONDS)
                return True
            except subprocess.TimeoutExpired:
                return False
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
        finally:
            out.close()
            err.close()

    def log_text(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
class ServiceRestartTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = ServiceRestartHarness(Path(self._tmp.name))
        # ensure_root_dir requires a root-owned run directory; skip when not root.
        if os.getuid() != 0:
            self.skipTest("watchdog requires a root-owned run directory")
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=10,
            # Two, not one: check_service sleeps once between the start and the
            # status re-check, and the loop-bounding stub counts that call too.
            iterations=2,
        )
        self.harness.crashed_service("amnezia")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_tick_survives_a_service_that_backgrounds_a_child(self) -> None:
        self.assertTrue(
            self.harness.run_supervised(),
            "the tick did not finish: the daemon is waiting on a descriptor "
            "its restarted service left open",
        )

        calls = self.harness.call_log()
        self.assertIn("service amnezia start", calls)
        # check_service unbound runs after check_service amnezia. Seeing it is
        # proof the tick got past the restart rather than merely exiting.
        self.assertIn("service unbound status", calls)

        log = self.harness.log_text()
        self.assertIn(MONITOR_LINE, log)
        self.assertIn("OK: amnezia restarted successfully", log)

        state = json.loads(self.harness.state_file.read_text(encoding="utf-8"))
        self.assertEqual(state["state"], "PRIMARY", state)

    def test_reintroducing_the_pipe_hangs_the_tick(self) -> None:
        """The defect itself, executed.

        With the output read through a pipe, the backgrounded child keeps the
        write end open and the daemon never reaches the end of the tick.
        """
        script = self.harness.reintroduce(
            r'    run_logged service "\$name" start \|\| true\n',
            '    service "$name" start 2>&1 | while IFS= read -r _line; '
            'do log "  $_line"; done\n',
        )

        self.assertFalse(
            self.harness.run_supervised(script=script),
            "the reintroduced pipe did not hang the tick; the test no longer "
            "covers the defect it was written for",
        )

        # It got as far as starting the service and then stopped: no state was
        # written, and the check that follows the restart never ran.
        log = self.harness.log_text()
        self.assertIn(MONITOR_LINE, log)
        self.assertNotIn("service unbound status", self.harness.call_log())
        self.assertFalse(self.harness.state_file.exists())
