"""The version gate must let a manual publish repair a missing release."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".forgejo" / "workflows" / "ci.yml"


class VersionGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.root / "VERSION").write_text("2.9.126\n", encoding="ascii")
        source = WORKFLOW.read_text(encoding="utf-8")
        start = source.index('before="${{ github.event.before }}"')
        end = source.index("      - name: Validate scripts and Python")
        self.decision = source[start:end]
        (self.root / "calls").write_text("", encoding="ascii")
        for name in ("git", "curl"):
            path = self.bin / name
            path.write_text(
                f"#!/bin/sh\nprintf '{name} %s\\n' \"$*\" >> {self.root / 'calls'}\n"
                + ("exit 0\n" if name == "git" else "exit 22\n"),
                encoding="ascii",
            )
            path.chmod(0o755)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_gate(self, event: str) -> subprocess.CompletedProcess[str]:
        before = "" if event == "workflow_dispatch" else "abcdef123456"
        script = (
            "set -euo pipefail\n"
            f"cd {self.root}\n"
            f"GITHUB_OUTPUT={self.root / 'output'}\n"
            "GITHUB_SHA=4798b60d1db708d3883c6e1431164b5b694d483f\n"
            + self.decision.replace("${{ github.event_name }}", event).replace(
                "${{ github.event.before }}", before
            )
        )
        return subprocess.run(
            ["bash", "-eu", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": f"{self.bin}:/usr/bin:/bin"},
        )

    def test_manual_dispatch_allows_repairing_the_missing_release(self) -> None:
        result = self.run_gate("workflow_dispatch")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("moved=true", (self.root / "output").read_text())
        self.assertNotIn("curl", (self.root / "calls").read_text())

    def test_push_with_an_unpublished_version_still_fails(self) -> None:
        result = self.run_gate("push")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NOT published", result.stderr)


if __name__ == "__main__":
    unittest.main()
