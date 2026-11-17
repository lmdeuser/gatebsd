"""The CI dispatcher's mirror status must report, not decide.

`ci-mirror-status` used to run a health check. Both checkers write
/tank/mirror/status/health-ready-ok and health-ready.txt, so asking for the
status set it -- and a stale generation of the checker, scheduled by a leftover
cron file at 05:15, is how the release-blocking verdict came back once already
after it had been fixed.

It could not have worked in any case. Over SSH the dispatcher runs as
ci_deployer, uid 1002 group operator; the checkers are 0750 root:wheel and the
status directory is root:www 0755. No execute, no write. The published files
are 0644, so reading them is precisely what that account can do.

Every test RUNS infra/freebsd-ci/mirror-status-report.sh.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "infra" / "freebsd-ci" / "mirror-status-report.sh"
MANIFEST = ROOT / "infra" / "freebsd-ci" / "deployment.manifest"
DISPATCH = ROOT / "ci" / "host" / "gatebsd-ci-dispatch"


def stamp(age_seconds: int) -> str:
    moment = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


class MirrorStatusReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.status = Path(self._tmp.name) / "status"
        self.status.mkdir()

    def publish(self, verdict: str, age_seconds: int = 60, detail: bool = True) -> None:
        (self.status / "health-ready.txt").write_text(f"{verdict}\n", encoding="utf-8")
        if detail:
            (self.status / "health-detail.txt").write_text(
                "nginx=OK\nzfs=OK\n"
                f"freebsd_15_amd64_sync=OK\nchecked_utc={stamp(age_seconds)}\n",
                encoding="utf-8",
            )

    def run_report(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": "/usr/bin:/bin",
            "GATEBSD_PATH": "/usr/bin:/bin",
            "MIRROR_STATUS_DIR": str(self.status),
            "LANG": "C",
        }
        env.update(overrides)
        return subprocess.run(
            ["sh", str(REPORT)], capture_output=True, text=True, check=False, env=env
        )

    def test_a_fresh_ready_flag_reports_ready_and_succeeds(self) -> None:
        self.publish("READY")
        result = self.run_report()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("verdict=READY", result.stdout)
        self.assertIn("nginx=OK", result.stdout)

    def test_a_not_ready_flag_fails(self) -> None:
        self.publish("NOT_READY")
        result = self.run_report()
        self.assertEqual(result.returncode, 1)
        self.assertIn("verdict=NOT_READY", result.stdout)

    def test_it_writes_nothing(self) -> None:
        """A status query that changes the status is the defect being fixed."""
        self.publish("READY")
        before = {p.name: p.read_bytes() for p in self.status.iterdir()}
        self.run_report()
        after = {p.name: p.read_bytes() for p in self.status.iterdir()}
        self.assertEqual(before, after, "the report modified the status directory")
        self.assertFalse(
            (self.status / "health-ready-ok").exists(),
            "the report created the flag the checker owns",
        )

    def test_a_stale_flag_is_not_reported_as_ready(self) -> None:
        """READY from a week ago is not a verdict about now."""
        self.publish("READY", age_seconds=7 * 24 * 3600)
        result = self.run_report()
        self.assertEqual(result.returncode, 1)
        self.assertIn("STALE", result.stderr)
        self.assertIn("age_seconds=", result.stdout)

    def test_the_staleness_window_is_adjustable(self) -> None:
        self.publish("READY", age_seconds=4 * 3600)
        self.assertEqual(self.run_report().returncode, 1)
        self.assertEqual(self.run_report(MIRROR_STATUS_MAX_AGE="86400").returncode, 0)

    def test_a_missing_status_directory_is_reported_not_guessed(self) -> None:
        result = self.run_report()
        self.assertEqual(result.returncode, 2)
        self.assertIn("No published mirror status", result.stderr)

    def test_a_missing_detail_file_does_not_crash_the_report(self) -> None:
        """awk and sed on a missing file exit non-zero; under set -e that kills
        the script on the assignment, and the code below never runs."""
        self.publish("READY", detail=False)
        result = self.run_report()
        self.assertIn("detail=UNAVAILABLE", result.stdout)
        self.assertIn("age_seconds=UNKNOWN", result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_dispatcher_runs_the_reporter_and_no_checker(self) -> None:
        text = DISPATCH.read_text(encoding="utf-8")
        code = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertIn("/usr/local/sbin/mirror-status-report", code)
        self.assertNotIn("mirror-health-check", code)

    def test_the_reporter_is_executable_by_the_account_that_runs_it(self) -> None:
        """ci_deployer is in group operator, not wheel: 0750 root:wheel denies it."""
        for line in MANIFEST.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            source, target, mode, owner, group = line.split()
            if target.endswith("mirror-status-report"):
                self.assertEqual(mode, "0755", "the dispatcher could not exec it otherwise")
                break
        else:
            self.fail("mirror-status-report is not in the deployment manifest")

    def test_it_is_executable_in_the_working_tree(self) -> None:
        self.assertTrue(os.access(REPORT, os.X_OK), REPORT.name)


if __name__ == "__main__":
    unittest.main()
