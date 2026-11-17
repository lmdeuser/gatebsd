"""Failover mode changes must not destroy the selected underlay."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_vpn_autostart import GatewayctlHarness  # noqa: E402
from test_watchdog_failover import WATCHDOG, WatchdogHarness  # noqa: E402

FAILOVERCTL = ROOT / "sbin" / "gatebsd-failoverctl"

STAT_STUB = r"""#!/bin/sh
if /usr/bin/stat -f '%u' / >/dev/null 2>&1; then
  exec /usr/bin/stat "$@"
fi
if [ "$1" = -f ]; then
  format=$2
  shift 2
  case "$format" in
    '%u') exec /usr/bin/stat -c '%u' "$@" ;;
    '%Lp') exec /usr/bin/stat -c '%a' "$@" ;;
    '%z') exec /usr/bin/stat -c '%s' "$@" ;;
    *) exit 2 ;;
  esac
fi
exec /usr/bin/stat "$@"
"""


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class ModeChangeDoesNotRestartWatchdog(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("failoverctl requires root")
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.run = self.root / "run"
        self.run.mkdir(mode=0o750)
        self.conf = self.root / "failover.conf"
        self.conf.write_text('FAILOVER_MODE="manual"\n', encoding="ascii")
        self.conf.chmod(0o600)
        self.calls = self.root / "calls.log"
        for name, body in {
            "stat": STAT_STUB,
            "service": f"#!/bin/sh\nprintf 'service %s\\n' \"$*\" >> {self.calls}\nexit 0\n",
            "logger": "#!/bin/sh\nexit 0\n",
            "sleep": "#!/bin/sh\nexit 1\n",
        }.items():
            path = self.bin / name
            path.write_text(body, encoding="ascii")
            path.chmod(0o755)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_ctl(self, action: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "GATEBSD_PATH": f"{self.bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "GATEBSD_FAILOVER_CONF": str(self.conf),
            "GATEBSD_FAILOVER_STATE": str(self.run / "watchdog.json"),
            "GATEBSD_MANUAL_WAN_FILE": str(self.run / "manual-wan"),
            "GATEBSD_FAILOVERCTL_LOCK": str(self.run / "failoverctl.lock"),
            "GATEBSD_FAILOVERCTL_LOCK_HELD": "1",
            "HOME": str(self.root),
            "LANG": "C",
        }
        return subprocess.run(
            ["sh", str(FAILOVERCTL), action],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_automatic_changes_only_the_policy(self) -> None:
        result = self.run_ctl("automatic")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('FAILOVER_MODE="automatic"', self.conf.read_text())
        calls = self.calls.read_text() if self.calls.exists() else ""
        self.assertNotIn("gatebsd_failover restart", calls)

    def test_manual_request_is_accepted_as_pending(self) -> None:
        result = self.run_ctl("backup")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pending request_id=", result.stdout)
        request = (self.run / "manual-wan").read_text(encoding="ascii").split()
        self.assertEqual(request[0], "backup")
        self.assertIn(request[1], result.stdout)


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class WatchdogRestoresTheSavedUnderlay(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("watchdog requires a root-owned run directory")
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = WatchdogHarness(Path(self._tmp.name))
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=5,
            iterations=1,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_backup_survives_a_watchdog_restart(self) -> None:
        self.harness.state_file.write_text(
            json.dumps({"active_wan": "backup", "last_switch": 123}), encoding="ascii"
        )
        result = self.harness.run_watchdog(failover_mode="manual")
        self.assertEqual(result.returncode, 1, "the bounded test loop must end normally")
        self.assertEqual(self.harness.state()["active_wan"], "backup")

    def test_corrupt_state_does_not_become_a_primary_route_decision(self) -> None:
        self.harness.state_file.write_text('{"active_wan":"primary', encoding="ascii")
        result = self.harness.run_watchdog()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            self.harness.state_file.read_text(encoding="ascii"),
            '{"active_wan":"primary',
            "a corrupt state must not be replaced with a newly invented primary state",
        )

    def test_idle_schema8_state_survives_a_watchdog_restart(self) -> None:
        first = self.harness.run_watchdog(failover_mode="manual")
        self.assertEqual(first.returncode, 1, first.stderr)
        self.assertEqual(self.harness.state()["request_status"], "")

        (self.harness.root / "sleep.count").unlink(missing_ok=True)
        second = self.harness.run_watchdog(failover_mode="manual")
        self.assertEqual(second.returncode, 1, second.stderr)


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class ManualRequestTerminalState(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("watchdog requires a root-owned run directory")
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = WatchdogHarness(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_request(self, *, route_op_fails: bool = False) -> dict:
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=5,
            iterations=1,
            route_op_fails=route_op_fails,
        )
        (self.harness.root / "ru.table").write_text("", encoding="ascii")
        (self.harness.run / "manual-wan").write_text(
            "backup request-42\n", encoding="ascii"
        )
        self.harness.run_watchdog(failover_mode="manual")
        return self.harness.state()

    def test_success_is_recorded_with_the_request_id(self) -> None:
        state = self.run_request()
        self.assertEqual(state["active_wan"], "backup")
        self.assertEqual(state["request_id"], "request-42")
        self.assertEqual(state["request_status"], "succeeded")
        self.assertEqual(state["request_error"], "")

    def test_failure_is_terminal_and_explained(self) -> None:
        state = self.run_request(route_op_fails=True)
        self.assertEqual(state["active_wan"], "primary")
        self.assertEqual(state["request_id"], "request-42")
        self.assertEqual(state["request_status"], "failed")
        self.assertNotEqual(state["request_error"], "")

    def test_pending_waits_for_ru_convergence_and_survives_restart(self) -> None:
        self.harness.build(
            primary_up=True, backup_up=True, vpn_up=True, vpn_is_default=True,
            handshake_age=5, iterations=1,
        )
        self.harness._write(
            "ru-routes.sh",
            "#!/bin/sh\n[ \"$1\" != check ] || exit 1\nexit 0\n",
        )
        (self.harness.root / "ru.table").write_text("", encoding="ascii")
        (self.harness.run / "manual-wan").write_text(
            "backup request-slow\n", encoding="ascii"
        )
        self.harness.run_watchdog(failover_mode="manual")
        state = self.harness.state()
        self.assertEqual(state["request_status"], "pending")
        self.assertEqual(state["request_id"], "request-slow")

        self.harness._write("ru-routes.sh", "#!/bin/sh\nexit 0\n")
        self.harness.run_watchdog(failover_mode="manual")
        state = self.harness.state()
        self.assertEqual(state["request_status"], "succeeded")
        self.assertEqual(state["request_id"], "request-slow")

    def test_ru_convergence_timeout_is_a_real_failure(self) -> None:
        self.harness.build(
            primary_up=True, backup_up=True, vpn_up=True, vpn_is_default=True,
            handshake_age=5, iterations=1,
        )
        self.harness._write(
            "ru-routes.sh",
            "#!/bin/sh\n[ \"$1\" != check ] || exit 1\nexit 0\n",
        )
        (self.harness.root / "ru.table").write_text("", encoding="ascii")
        (self.harness.run / "manual-wan").write_text(
            "backup request-timeout\n", encoding="ascii"
        )
        self.harness.run_watchdog(
            failover_mode="manual", extra_env={"REQUEST_TIMEOUT": "0"}
        )
        state = self.harness.state()
        self.assertEqual(state["request_status"], "failed")
        self.assertIn("timed out", state["request_error"])


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class VpnRollbackUsesTheSelectedUnderlay(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("watchdog requires a root-owned run directory")
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = WatchdogHarness(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_backup_direct_fallback_does_not_revert_to_primary(self) -> None:
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=6000,
            iterations=1,
        )
        self.harness.state_file.write_text(
            json.dumps({"active_wan": "backup", "last_switch": 123}), encoding="ascii"
        )
        self.harness.run_watchdog(failover_mode="manual")
        state = self.harness.state()
        self.assertEqual(state["active_wan"], "backup")
        self.assertTrue(state["vpn_rolled_back"])
        self.assertIn("vpn-rollback 198.51.100.1 awg0", self.harness.call_log())


class GatewayctlRejectsCorruptState(GatewayctlHarness):
    def test_corrupt_state_is_not_reported_as_primary(self) -> None:
        state = self.run_dir / "watchdog.json"
        state.write_text('{"active_wan":"primary', encoding="ascii")
        result = self.run_ctl("status")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("active : primary", result.stdout)


if __name__ == "__main__":
    unittest.main()
