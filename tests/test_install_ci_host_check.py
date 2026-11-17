"""`install-ci-host.sh --check` must fail when the machine is behind the repository.

Releases 2.9.64 and 2.9.65 both died in the pipeline on

    Required package is not installed or lacks metadata: amneziawg-go
    GateBSD package was not produced.

Both times the repository was already correct: 366620d had added amneziawg-go to
the build jail's install list. What was stale was the machine -- the stand kept
running the previous copy of prepare-gatebsd-build-jail.sh, because stand
scripts are installed by install-ci-host.sh and never update themselves from
git. Two runs burned on a fix that was sitting in the tree the whole time.

`--check` is the question nobody was asking before a push: is this machine at
this commit? These tests run the script for real against a scratch manifest and
scratch targets. Reading its source would not do -- the version of this
project's wiring test that read the text passed happily with the call sitting
behind `if false`.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALLER = REPO / "infra" / "freebsd-ci" / "install-ci-host.sh"


class InstallCiHostCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.source_dir = self.root / "repo" / "ci" / "host"
        self.source_dir.mkdir(parents=True)
        self.live_dir = self.root / "live"
        self.live_dir.mkdir()
        self.source = self.source_dir / "prepared.sh"
        self.source.write_text("#!/bin/sh\necho current\n", encoding="utf-8")
        self.target = self.live_dir / "prepared.sh"

        self.manifest = self.root / "deployment.manifest"
        self.manifest.write_text(
            f"# scratch manifest\nci/host/prepared.sh  {self.target}  0750 root wheel\n",
            encoding="utf-8",
        )
        self.scan = self.root / "deployment.scan"
        self.scan.write_text("", encoding="utf-8")
        self.addCleanup(self.td.cleanup)

    def run_check(self) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update({
            "GATEBSD_REPO_DIR": str(self.root / "repo"),
            "GATEBSD_DEPLOY_MANIFEST": str(self.manifest),
            # A path that does not exist, so the package pass is skipped: this
            # test is about files, and `pkg` does not exist off FreeBSD anyway.
            "GATEBSD_DEPLOY_PACKAGES": str(self.root / "no-such-packages.list"),
            "GATEBSD_DEPLOY_SCAN": str(self.scan),
            "GATEBSD_PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        })
        return subprocess.run(
            ["sh", str(INSTALLER), "--check"],
            env=env, capture_output=True, text=True, timeout=60,
        )

    def test_a_machine_that_matches_passes(self) -> None:
        self.target.write_text(self.source.read_text(encoding="utf-8"), encoding="utf-8")
        self.target.chmod(0o750)
        result = self.run_check()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("matches the repository", result.stdout)

    def test_a_stale_file_fails_and_is_named(self) -> None:
        self.target.write_text("#!/bin/sh\necho previous generation\n", encoding="utf-8")
        result = self.run_check()
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("not at this commit", result.stdout)
        self.assertIn(str(self.target), result.stdout)

    def test_a_missing_file_fails_too(self) -> None:
        # The stand had the file, so this is the weaker case -- but a target that
        # was never installed is exactly as unbuildable.
        self.assertFalse(self.target.exists())
        result = self.run_check()
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn(str(self.target), result.stdout)

    def test_dry_run_still_reports_without_failing(self) -> None:
        # --check must not change what --dry-run does; the installer is called
        # with --dry-run by hand all the time, and a new non-zero exit there
        # would break every one of those habits.
        self.target.write_text("#!/bin/sh\necho previous generation\n", encoding="utf-8")
        env = dict(os.environ)
        env.update({
            "GATEBSD_REPO_DIR": str(self.root / "repo"),
            "GATEBSD_DEPLOY_MANIFEST": str(self.manifest),
            "GATEBSD_DEPLOY_PACKAGES": str(self.root / "no-such-packages.list"),
            "GATEBSD_DEPLOY_SCAN": str(self.scan),
            "GATEBSD_PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        })
        result = subprocess.run(
            ["sh", str(INSTALLER), "--dry-run"],
            env=env, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("would install", result.stdout)


if __name__ == "__main__":
    unittest.main()
