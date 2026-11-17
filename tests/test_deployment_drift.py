"""Tests for the deployment manifest, its installer and its drift verifier.

The stand is the closed development loop the product depends on, and until now
its host-side components were copied there by hand. That produced, on the live
machine: four generations of the mirror health check in /usr/local/sbin with a
cron file naming two of them, fifteen dated leftovers beside working scripts,
and `mirror-sync-git` registered by two cron files so it runs twice
concurrently every night -- the same duplicate-registration defect that
corrupted unbound's configuration on the production router.

None of that was detectable, because nothing compared the machine to the
repository. These tests cover the thing that now does.
"""
from __future__ import annotations

import grp
import os
import pwd
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra" / "freebsd-ci"
MANIFEST = INFRA / "deployment.manifest"
VERIFY = INFRA / "verify-deployment.sh"
INSTALL = INFRA / "install-ci-host.sh"
RETIRE = INFRA / "retire-leftovers.sh"
LEFTOVERS = INFRA / "leftovers.sh"
MIRROR_INSTALL = INFRA / "install-mirror-maintenance.sh"


def manifest_rows() -> list[list[str]]:
    rows = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            rows.append(line.split())
    return rows


class ManifestTests(unittest.TestCase):
    def test_every_manifest_source_exists_in_the_repository(self) -> None:
        for source, target, *_ in manifest_rows():
            self.assertTrue(
                (ROOT / source).is_file(), f"{source} is listed for {target} but is not in the tree"
            )

    def test_every_row_is_complete(self) -> None:
        for row in manifest_rows():
            self.assertEqual(len(row), 5, row)
            source, target, mode, owner, group = row
            self.assertFalse(source.startswith("/"), source)
            self.assertTrue(target.startswith("/"), target)
            self.assertRegex(mode, r"^0[0-7]{3}$", target)

    def test_no_target_is_claimed_twice(self) -> None:
        targets = [row[1] for row in manifest_rows()]
        self.assertEqual(sorted(targets), sorted(set(targets)))

    def test_no_managed_script_calls_a_generation_of_a_managed_file(self) -> None:
        """The dispatcher called /usr/local/sbin/mirror-health-check-v2.

        That name has no source here, so what it checked could not be reviewed,
        and it predates the fix that stopped a running nightly sync from
        counting as a broken mirror. Naming it also kept it alive as a
        dependency: it is why /usr/local/sbin held five generations of one
        check, and why retiring them needed a reference guard first.

        A managed script must call the managed name, not a generation of it.
        """
        targets = {row[1] for row in manifest_rows()}
        reference = re.compile(r"/usr/local/(?:sbin|libexec)/[A-Za-z0-9._-]+")
        for source, *_ in manifest_rows():
            text = (ROOT / source).read_text(encoding="utf-8", errors="replace")
            for token in reference.findall(text):
                token = token.rstrip(".")
                if token in targets:
                    continue
                for managed in targets:
                    self.assertFalse(
                        token.startswith(managed + "-v") or token.startswith(managed + "."),
                        f"{source} calls {token}, a generation of the managed {managed}",
                    )

    def test_the_dispatcher_is_not_group_writable(self) -> None:
        """It is the CI trust boundary: it decides what a build request may run."""
        for source, target, mode, _owner, _group in manifest_rows():
            if target.endswith("gatebsd-ci-dispatch"):
                self.assertIn(mode, ("0550", "0500"), "the dispatcher must not be writable")
                break
        else:
            self.fail("the CI dispatcher is not in the manifest")

    def test_forgejo_backup_and_cron_are_in_manifest_and_newsyslog(self) -> None:
        rows = {(row[0], row[1]): tuple(row[2:]) for row in manifest_rows()}
        self.assertEqual(
            rows.get(("infra/forgejo/backup.sh", "/usr/local/sbin/gatebsd-forgejo-backup")),
            ("0550", "root", "wheel"),
        )
        self.assertEqual(
            rows.get(("infra/forgejo/forgejo-backup.cron", "/usr/local/etc/cron.d/forgejo-backup")),
            ("0644", "root", "wheel"),
        )
        newsyslog = (INFRA / "newsyslog-gatebsd-stand.conf").read_text(encoding="utf-8")
        self.assertIn("/var/log/forgejo-backup.log", newsyslog)


class VerifierTests(unittest.TestCase):
    """Drives the verifier against a synthetic tree, so every verdict is real."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = self.root / "repo"
        self.sbin = self.root / "usr/local/sbin"
        self.cron = self.root / "cron.d"
        for path in (self.repo / "infra/freebsd-ci", self.sbin, self.cron):
            path.mkdir(parents=True)
        (self.repo / "infra/freebsd-ci/thing.sh").write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        self.manifest = self.root / "deployment.manifest"
        self.manifest.write_text(
            f"infra/freebsd-ci/thing.sh {self.sbin}/thing 0750 root wheel\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def deploy(self, content: str = "#!/bin/sh\ntrue\n", mode: int = 0o750) -> Path:
        target = self.sbin / "thing"
        target.write_text(content, encoding="utf-8")
        target.chmod(mode)
        return target

    def run_verify(self, extra_env: dict | None = None) -> subprocess.CompletedProcess[str]:
        # Default: point the package check and the directory scan at files that
        # are not there, so every test written before either existed keeps
        # testing what it tested. An absent list is not a finding -- it is a
        # stand that declares no dependencies and no scanned directories. The
        # scan one also keeps this suite off the real /usr/local: the shipped
        # deployment.scan names absolute paths on the stand, and a synthetic
        # tree has no business walking them.
        env = {
                "GATEBSD_DEPLOY_PACKAGES": str(self.root / "no-such-packages.list"),
                "GATEBSD_DEPLOY_SCAN": str(self.root / "no-such-deployment.scan"),
                "PATH": "/usr/bin:/bin",
                "GATEBSD_PATH": "/usr/bin:/bin",
                "GATEBSD_REPO_DIR": str(self.repo),
                "GATEBSD_DEPLOY_MANIFEST": str(self.manifest),
                "GATEBSD_CRON_DIRS": str(self.cron),
                "GATEBSD_MANAGED_PREFIX": str(self.sbin),
                "HOME": str(self.root),
                "LANG": "C",
        }
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["sh", str(VERIFY)],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    def _with_pkg_stub(self, installed: list[str]) -> dict:
        """A pkg(8) that knows exactly which packages exist.

        The verifier runs on FreeBSD and asks pkg; this suite does not. Stubbing
        the tool keeps the verifier's own logic under test instead of skipping
        the check everywhere it cannot run for real.
        """
        binroot = self.root / "stubbin"
        binroot.mkdir(exist_ok=True)
        stub = binroot / "pkg"
        cases = "\n".join(f"      {name}) exit 0 ;;" for name in installed)
        stub.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = info ] && [ "$2" = -e ]; then\n'
            '  case "$3" in\n'
            f"{cases}\n"
            "      *) exit 1 ;;\n"
            "  esac\n"
            "fi\n"
            "exit 0\n",
            encoding="ascii",
        )
        stub.chmod(0o755)
        # Both, and not just PATH: the verifier sets its own PATH from
        # GATEBSD_PATH, so a stub that only lands in PATH is never seen.
        return {
            "PATH": f"{binroot}:/usr/bin:/bin",
            "GATEBSD_PATH": f"{binroot}:/usr/bin:/bin",
        }

    def test_a_required_package_that_is_absent_is_reported(self) -> None:
        """The drift nothing could see, because nothing declared it.

        smartmontools was missing from a host that keeps the mirror, Forgejo
        and every release on one mechanical disk. Its health could not be read
        and the machine reported nothing wrong, because nothing was looking.
        """
        self.deploy()
        packages = self.root / "packages.list"
        packages.write_text(
            "# comment\nsmartmontools   why it is needed\nrsync   also needed\n",
            encoding="utf-8",
        )
        env = {"GATEBSD_DEPLOY_PACKAGES": str(packages)}
        env.update(self._with_pkg_stub(["rsync"]))
        result = self.run_verify(extra_env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("PACKAGE MISSING", result.stdout)
        self.assertIn("smartmontools", result.stdout)
        self.assertNotIn("rsync is required", result.stdout)

    def test_all_required_packages_present_is_clean(self) -> None:
        self.deploy()
        packages = self.root / "packages.list"
        packages.write_text("smartmontools   why\n", encoding="utf-8")
        env = {"GATEBSD_DEPLOY_PACKAGES": str(packages)}
        env.update(self._with_pkg_stub(["smartmontools"]))
        result = self.run_verify(extra_env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No drift", result.stdout)

    def test_a_matching_deployment_is_clean(self) -> None:
        self.deploy()
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No drift", result.stdout)

    def test_changed_content_is_reported(self) -> None:
        self.deploy(content="#!/bin/sh\nfalse\n")
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("DRIFTED", result.stdout)

    def test_a_missing_deployment_is_reported(self) -> None:
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("NOT DEPLOYED", result.stdout)

    def test_a_wrong_mode_is_reported(self) -> None:
        self.deploy(mode=0o777)
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("WRONG MODE", result.stdout)

    def test_a_leftover_beside_a_managed_file_is_reported(self) -> None:
        """`mirror-health-check-v2` next to `mirror-health-check`, in miniature."""
        self.deploy()
        (self.sbin / "thing.before-review-20260730").write_text("old\n", encoding="utf-8")
        (self.sbin / "thing-v2").write_text("older\n", encoding="utf-8")
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("thing.before-review-20260730", result.stdout)
        self.assertIn("thing-v2", result.stdout)

    def test_a_command_scheduled_by_two_cron_files_is_reported(self) -> None:
        """The defect that took DNS down on the router, found before it fires."""
        self.deploy()
        (self.cron / "jobs").write_text(f"15 3 * * * root {self.sbin}/thing\n", encoding="utf-8")
        # cron parses dotted names too, which is the whole point.
        (self.cron / "jobs.before-fix-20260721").write_text(
            f"15 3 * * * root {self.sbin}/thing\n", encoding="utf-8"
        )
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("SCHEDULED TWICE", result.stdout)

    def test_a_scheduled_command_with_no_source_is_reported(self) -> None:
        self.deploy()
        (self.cron / "jobs").write_text(
            f"15 3 * * * root {self.sbin}/thing\n15 4 * * * root {self.sbin}/mystery\n",
            encoding="utf-8",
        )
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("UNMANAGED", result.stdout)
        self.assertIn("mystery", result.stdout)

    def test_a_single_registration_is_not_reported_as_duplicate(self) -> None:
        self.deploy()
        (self.cron / "jobs").write_text(f"15 3 * * * root {self.sbin}/thing\n", encoding="utf-8")
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_an_unreadable_file_is_not_reported_as_drifted(self) -> None:
        """The CI dispatcher is mode 0550 on purpose; it is the trust boundary.

        Reporting "differs" when the real problem is "could not read it" trains
        an operator to disbelieve the verifier, which costs more than the drift.
        """
        target = self.deploy()
        target.chmod(0o000)
        try:
            result = self.run_verify()
        finally:
            target.chmod(0o750)
        if os.geteuid() == 0:
            self.skipTest("root can read anything, so this verdict cannot be observed")
        self.assertEqual(result.returncode, 1)
        self.assertIn("CANNOT VERIFY", result.stdout)
        self.assertNotIn("DRIFTED", result.stdout)

    def test_base_system_cron_entries_are_not_reported_as_unmanaged(self) -> None:
        """FreeBSD schedules atrun and newsyslog; those are never ours to own."""
        self.deploy()
        (self.cron / "jobs").write_text(
            f"15 3 * * * root {self.sbin}/thing\n*/5 * * * * root /usr/libexec/atrun\n",
            encoding="utf-8",
        )
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("atrun", result.stdout)

    def test_a_commented_out_cron_line_is_not_a_registration(self) -> None:
        self.deploy()
        (self.cron / "jobs").write_text(f"15 3 * * * root {self.sbin}/thing\n", encoding="utf-8")
        (self.cron / "jobs.disabled").write_text(
            f"# 15 3 * * * root {self.sbin}/thing\n", encoding="utf-8"
        )
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout)


class InstallerTests(unittest.TestCase):
    def test_the_installer_and_verifier_read_the_same_manifest(self) -> None:
        """Two files that disagree about where something lives is the bug itself."""
        for script in (INSTALL, VERIFY):
            text = script.read_text(encoding="utf-8")
            self.assertIn("GATEBSD_DEPLOY_MANIFEST", text)
            self.assertIn("deployment.manifest", text)

    def test_the_installer_does_not_leave_dated_copies_beside_live_files(self) -> None:
        """Keeping the old copy next to the new one is how the mess was made."""
        text = INSTALL.read_text(encoding="utf-8")
        code = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )
        for habit in (".before-", ".bak", "date -u", "cp -p"):
            self.assertNotIn(habit, code, f"the installer must not create {habit} copies")

    def test_dry_run_changes_nothing_and_needs_no_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            (repo / "infra/freebsd-ci").mkdir(parents=True)
            (repo / "infra/freebsd-ci/thing.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            target_dir = root / "sbin"
            manifest = root / "m"
            manifest.write_text(
                f"infra/freebsd-ci/thing.sh {target_dir}/thing 0750 root wheel\n", encoding="utf-8"
            )
            result = subprocess.run(
                ["sh", str(INSTALL), "--dry-run"],
                capture_output=True,
                text=True,
                check=False,
                env={
                    "PATH": "/usr/bin:/bin",
                    "GATEBSD_PATH": "/usr/bin:/bin",
                    "GATEBSD_REPO_DIR": str(repo),
                    "GATEBSD_DEPLOY_MANIFEST": str(manifest),
                    "HOME": str(root),
                    "LANG": "C",
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("would install", result.stdout)
            self.assertFalse(target_dir.exists(), "a dry run must not create anything")

    def test_both_scripts_are_executable(self) -> None:
        for script in (INSTALL, VERIFY):
            self.assertTrue(os.access(script, os.X_OK), script.name)


class RetirementTests(unittest.TestCase):
    """Drives retire-leftovers.sh against a synthetic tree.

    Reporting leftovers was never the hard part -- the verifier has listed
    fourteen of them for days. The step that did not happen is moving them, and
    it did not happen because a person had to do it. Every test here RUNS the
    script; none of them read it.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.repo = self.root / "repo"
        self.sbin = self.root / "usr/local/sbin"
        self.cron = self.root / "usr/local/etc/cron.d"
        self.backups = self.root / "backups"
        for path in (self.repo / "infra/freebsd-ci", self.sbin, self.cron):
            path.mkdir(parents=True)
        (self.repo / "infra/freebsd-ci/thing.sh").write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        self.manifest = self.root / "deployment.manifest"
        self.manifest.write_text(
            f"infra/freebsd-ci/thing.sh {self.sbin}/thing 0750 root wheel\n", encoding="utf-8"
        )
        self.target = self.sbin / "thing"
        self.target.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        self.target.chmod(0o750)

    def env(self) -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin",
            "GATEBSD_PATH": "/usr/bin:/bin",
            "GATEBSD_REPO_DIR": str(self.repo),
            "GATEBSD_DEPLOY_MANIFEST": str(self.manifest),
            "GATEBSD_LEFTOVER_BACKUP_ROOT": str(self.backups),
            "GATEBSD_CRON_DIRS": str(self.cron),
            "GATEBSD_MANAGED_PREFIX": str(self.sbin),
            "GATEBSD_DEPLOY_PACKAGES": str(self.root / "no-such-packages.list"),
            "GATEBSD_DEPLOY_SCAN": str(self.root / "no-such-deployment.scan"),
            "HOME": str(self.root),
            "LANG": "C",
        }

    def run_retire(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(RETIRE), *args],
            capture_output=True, text=True, check=False, env=self.env(),
        )

    def run_verify(self) -> subprocess.CompletedProcess[str]:
        # As in VerifierTests: this suite is about files, not dependencies, so
        # it declares none rather than inheriting the repository's real list.
        return subprocess.run(
            ["sh", str(VERIFY)],
            capture_output=True, text=True, check=False, env=self.env(),
        )

    def retired_copies(self) -> list[Path]:
        return sorted(p for p in self.backups.rglob("*") if p.is_file())

    def test_a_leftover_is_moved_out_of_the_live_directory(self) -> None:
        leftover = self.sbin / "thing.before-review-20260730"
        leftover.write_text("an older generation\n", encoding="utf-8")

        result = self.run_retire()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(leftover.exists(), "the leftover is still in the live directory")
        self.assertTrue(self.target.exists(), "the managed file must not be touched")
        copies = self.retired_copies()
        self.assertEqual(len(copies), 1, copies)
        self.assertEqual(copies[0].name, "thing.before-review-20260730")
        self.assertEqual(copies[0].read_text(encoding="utf-8"), "an older generation\n")

    def test_a_dotted_leftover_is_retired_too(self) -> None:
        """cron(8) and rcorder(8) read dotted names; a dot hides nothing from them."""
        for name in (".thing", ".thing.before-fix-20260721"):
            (self.sbin / name).write_text("hidden\n", encoding="utf-8")

        result = self.run_retire()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.sbin / ".thing").exists())
        self.assertFalse((self.sbin / ".thing.before-fix-20260721").exists())
        self.assertEqual(len(self.retired_copies()), 2)

    def test_an_unrelated_file_sharing_a_prefix_is_left_alone(self) -> None:
        """`thingamajig` is not a generation of `thing`; carrying it off is a bug."""
        bystander = self.sbin / "thingamajig"
        bystander.write_text("a different program\n", encoding="utf-8")

        result = self.run_retire()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(bystander.exists(), "an unrelated neighbour was retired")
        self.assertFalse(self.backups.exists())

    def test_a_dry_run_moves_nothing(self) -> None:
        leftover = self.sbin / "thing-v2"
        leftover.write_text("older\n", encoding="utf-8")

        result = self.run_retire("--dry-run")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("would retire", result.stdout)
        self.assertIn("thing-v2", result.stdout)
        self.assertTrue(leftover.exists(), "a dry run must not move anything")
        self.assertFalse(self.backups.exists(), "a dry run must not create the backup tree")

    def test_a_clean_directory_leaves_no_empty_backup_behind(self) -> None:
        """Otherwise the retirement becomes the next thing that needs cleaning."""
        result = self.run_retire()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No leftovers", result.stdout)
        self.assertFalse(self.backups.exists())

    def test_the_verifier_reports_nothing_after_the_retirer_has_run(self) -> None:
        """The two tools must judge by one rule, so this runs both in sequence.

        A retirer with a narrower rule than the verifier leaves exactly what the
        verifier keeps reporting; a wider one carries off a legitimate file.
        Reading both scripts cannot catch either -- running them can.
        """
        for name in ("thing.bak", "thing-v2", ".thing", "thing.before-x-20260101"):
            (self.sbin / name).write_text("older\n", encoding="utf-8")

        before = self.run_verify()
        self.assertEqual(before.returncode, 1)
        self.assertIn("LEFTOVER", before.stdout)

        retire = self.run_retire()
        self.assertEqual(retire.returncode, 0, retire.stdout + retire.stderr)

        after = self.run_verify()
        self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
        self.assertNotIn("LEFTOVER", after.stdout)
        self.assertEqual(len(self.retired_copies()), 4)

    def test_a_cron_leftover_is_retired(self) -> None:
        """The dangerous class: cron reads every file, so an old copy still runs.

        `freebsd-local-repo.before-mirror-fix-20260721-223439` was found beside
        the live crontab on the stand, scheduling an unmanaged
        mirror-health-check-v2 that wrote the working checker's readiness flag.
        """
        (self.repo / "infra/freebsd-ci/jobs.cron").write_text("# jobs\n", encoding="utf-8")
        with self.manifest.open("a", encoding="utf-8") as handle:
            handle.write(f"infra/freebsd-ci/jobs.cron {self.cron}/jobs 0644 root wheel\n")
        (self.cron / "jobs").write_text("# jobs\n", encoding="utf-8")
        stale = self.cron / "jobs.before-mirror-fix-20260721-223439"
        stale.write_text(f"15 5 * * * root {self.sbin}/thing-v2\n", encoding="utf-8")

        result = self.run_retire()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(stale.exists(), "an old crontab is a second live schedule")
        self.assertTrue((self.cron / "jobs").exists())

    def test_a_leftover_something_still_calls_is_kept_and_named(self) -> None:
        """`mirror-health-check-v2` was not an older generation of anything.

        It looked like one, and the CI dispatcher ran it for ci-mirror-status.
        Retiring by name alone would have broken that operation the first time
        this script ran on the stand.
        """
        called = self.sbin / "thing-v2"
        called.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        self.target.write_text(
            f"#!/bin/sh\nexec {self.sbin}/thing-v2 --light\n", encoding="utf-8"
        )
        orphan = self.sbin / "thing.bak"
        orphan.write_text("genuinely nobody's\n", encoding="utf-8")

        result = self.run_retire()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(called.exists(), "a file the managed script calls was carried off")
        self.assertIn("still referenced, kept", result.stderr)
        self.assertIn("thing-v2", result.stderr)
        self.assertFalse(orphan.exists(), "the genuine leftover should still have gone")

    def test_a_leftover_a_cron_file_still_schedules_is_kept(self) -> None:
        scheduled = self.sbin / "thing-v2"
        scheduled.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        (self.cron / "jobs").write_text(
            f"15 5 * * * root {self.sbin}/thing-v2\n", encoding="utf-8"
        )

        result = self.run_retire()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(scheduled.exists())
        self.assertIn("still referenced, kept", result.stderr)

    def test_the_retirer_moves_rather_than_copies(self) -> None:
        """A copy beside the live file is not a backup; it is a second live file."""
        leftover = self.sbin / "thing.bak"
        leftover.write_text("older\n", encoding="utf-8")

        self.run_retire()

        self.assertEqual(
            [p.name for p in self.sbin.iterdir()], ["thing"],
            "the live directory must hold only the managed file afterwards",
        )

    def test_it_refuses_to_overwrite_an_already_retired_copy(self) -> None:
        leftover = self.sbin / "thing.bak"
        leftover.write_text("older\n", encoding="utf-8")
        collision = self.backups / f"retired-{'0' * 16}Z"
        (collision / str(self.sbin).lstrip("/")).mkdir(parents=True)
        # Force the collision by pre-creating what this run would write.
        result = self.run_retire("--dry-run")
        destination = Path(
            [line for line in result.stdout.splitlines() if "would retire" in line][0]
            .split("->")[1].strip()
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("already there\n", encoding="utf-8")

        second = self.run_retire()

        if second.returncode == 0:
            self.skipTest("the run crossed a second boundary, so the names did not collide")
        self.assertEqual(second.returncode, 2)
        self.assertIn("refusing to overwrite", second.stderr)
        self.assertTrue(leftover.exists(), "the leftover must stay put when the move is refused")


class RetirementWiringTests(unittest.TestCase):
    """The installers must actually call the retirer.

    A test that greps the installer for the call passes just as happily with
    that call sitting behind `if false`, which is how a previous wiring test
    here missed a defect. These run the installers.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.repo = self.root / "repo"
        (self.repo / "infra/freebsd-ci").mkdir(parents=True)
        (self.repo / "infra/freebsd-ci/thing.sh").write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        self.sbin = self.root / "usr/local/sbin"
        self.sbin.mkdir(parents=True)
        self.backups = self.root / "backups"
        self.manifest = self.root / "deployment.manifest"
        self.manifest.write_text(
            f"infra/freebsd-ci/thing.sh {self.sbin}/thing 0750 root wheel\n", encoding="utf-8"
        )
        self.leftover = self.sbin / "thing.before-review-20260730"
        self.leftover.write_text("an older generation\n", encoding="utf-8")

    def env(self) -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "GATEBSD_PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "GATEBSD_REPO_DIR": str(self.repo),
            "GATEBSD_DEPLOY_MANIFEST": str(self.manifest),
            "GATEBSD_LEFTOVER_BACKUP_ROOT": str(self.backups),
            "HOME": str(self.root),
            "LANG": "C",
        }

    def test_the_host_installer_reaches_the_retirer_on_a_dry_run(self) -> None:
        result = subprocess.run(
            ["sh", str(INSTALL), "--dry-run"],
            capture_output=True, text=True, check=False, env=self.env(),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Checked before the message: a dry run that reports correctly and moves
        # the file anyway is the worse failure, so it must be the one named.
        self.assertTrue(self.leftover.exists(), "a dry run must not move anything")
        self.assertFalse(self.backups.exists(), "a dry run must not create the backup tree")
        self.assertIn("would retire", result.stdout)
        self.assertIn("thing.before-review-20260730", result.stdout)

    @unittest.skipUnless(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        "installing with the manifest's owner and group needs root",
    )
    def test_the_host_installer_retires_for_real(self) -> None:
        result = subprocess.run(
            ["sh", str(INSTALL)],
            capture_output=True, text=True, check=False, env=self.env(),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.sbin / "thing").is_file(), "the managed file was not installed")
        self.assertFalse(self.leftover.exists(), "the leftover survived a real install")
        moved = sorted(p for p in self.backups.rglob("*") if p.is_file())
        self.assertEqual(len(moved), 1, moved)
        self.assertEqual(moved[0].read_text(encoding="utf-8"), "an older generation\n")


class MirrorMaintenanceInstallerTests(unittest.TestCase):
    """The mirror installer names its targets itself instead of reading the
    manifest. That is tolerable only while the two agree, so this checks."""

    def installed_rows(self) -> list[tuple[str, str, str]]:
        rows = []
        for line in MIRROR_INSTALL.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line.startswith("install ") or " -m " not in line:
                continue
            fields = line.split()
            mode = fields[fields.index("-m") + 1]
            source = fields[-2].split("/")[-1].strip('"')
            rows.append((source, fields[-1], mode))
        return rows

    def test_every_path_it_installs_is_claimed_by_the_manifest(self) -> None:
        manifest = {target: (source, mode) for source, target, mode, *_ in manifest_rows()}
        for source, target, mode in self.installed_rows():
            self.assertIn(
                target, manifest,
                f"{target} is installed by the mirror installer but is not in the manifest, "
                "so neither the verifier nor the retirer knows about it",
            )
            manifest_source, manifest_mode = manifest[target]
            self.assertTrue(
                manifest_source.endswith(source),
                f"{target} comes from {source} here and {manifest_source} in the manifest",
            )
            self.assertEqual(
                manifest_mode.lstrip("0") or "0", mode.lstrip("0") or "0",
                f"{target} is installed {mode} here and {manifest_mode} in the manifest",
            )

    def test_the_crontab_is_in_the_manifest(self) -> None:
        """Until it was, nothing compared the deployed schedule to the repository."""
        targets = [row[1] for row in manifest_rows()]
        self.assertIn("/usr/local/etc/cron.d/freebsd-local-repo", targets)

    def test_the_retirer_and_the_shared_rule_are_shipped_beside_it(self) -> None:
        self.assertTrue(RETIRE.is_file())
        self.assertTrue(LEFTOVERS.is_file())
        self.assertTrue(os.access(RETIRE, os.X_OK), RETIRE.name)



class DriftOnlyMode(unittest.TestCase):
    """--drift-only, and why it is a mode rather than the default.

    By default a declared gap IS a finding, and that is not an oversight:
    mirror-sync-git was reported on every run since the manifest existed, and
    that report is the only reason anyone remembered it had no source -- the
    script that turned out to be filling the disk. tests/
    test_files_nothing_accounts_for.py pins that behaviour and it stays.

    But a pipeline gate asks a narrower question -- has the stand diverged from
    the commit being built -- and the stand carries two long-standing deliberate
    gaps in the nginx site files. A check that is red for ever on those cannot
    answer it: a gate that can never go green guards nothing. Hence one caller,
    one flag, and the default untouched.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = self.root / "repo"
        self.sbin = self.root / "usr/local/sbin"
        for path in (self.repo / "infra/freebsd-ci", self.sbin, self.root / "cron.d"):
            path.mkdir(parents=True)
        (self.repo / "infra/freebsd-ci/thing.sh").write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        self.manifest = self.root / "deployment.manifest"
        self.manifest.write_text(
            f"infra/freebsd-ci/thing.sh {self.sbin}/thing 0750 root wheel\n", encoding="utf-8"
        )
        target = self.sbin / "thing"
        target.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        target.chmod(0o750)
        # A second file in the scanned directory, declared as a gap.
        self.stray = self.sbin / "assembled-by-an-installer"
        self.stray.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        self.stray.chmod(0o755)
        self.scan = self.root / "deployment.scan"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_verify(self, drift_only: bool = True) -> subprocess.CompletedProcess[str]:
        argv = ["sh", str(VERIFY)] + (["--drift-only"] if drift_only else [])
        return subprocess.run(
            argv,
            capture_output=True, text=True, check=False,
            env={
                "GATEBSD_DEPLOY_PACKAGES": str(self.root / "no-such-packages.list"),
                "GATEBSD_DEPLOY_SCAN": str(self.scan),
                "PATH": "/usr/bin:/bin",
                "GATEBSD_PATH": "/usr/bin:/bin",
                "GATEBSD_REPO_DIR": str(self.repo),
                "GATEBSD_DEPLOY_MANIFEST": str(self.manifest),
                "GATEBSD_CRON_DIRS": str(self.root / "cron.d"),
                "GATEBSD_MANAGED_PREFIX": str(self.sbin),
                "HOME": str(self.root),
                "LANG": "C",
            },
        )

    def test_by_default_a_declared_gap_still_fails(self) -> None:
        """The default is what the other suite pins; this only checks it survived."""
        self.scan.write_text(
            f"scan   {self.sbin}\ngap    {self.stray}\n", encoding="utf-8"
        )
        result = self.run_verify(drift_only=False)
        self.assertEqual(1, result.returncode, result.stdout)

    def test_an_undeclared_stray_is_drift(self) -> None:
        """The control: without the declaration the same file fails either way."""
        self.scan.write_text(f"scan   {self.sbin}\n", encoding="utf-8")
        result = self.run_verify()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("UNACCOUNTED", result.stdout)

    def test_declaring_it_a_gap_clears_the_verdict(self) -> None:
        self.scan.write_text(
            f"scan   {self.sbin}\ngap    {self.stray}\n", encoding="utf-8"
        )
        result = self.run_verify()
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("No drift", result.stdout)

    def test_a_declared_gap_is_still_printed(self) -> None:
        self.scan.write_text(
            f"scan   {self.sbin}\ngap    {self.stray}\n", encoding="utf-8"
        )
        result = self.run_verify()
        self.assertIn("KNOWN GAP", result.stdout)
        self.assertIn(str(self.stray), result.stdout)

    def test_the_clean_verdict_says_how_many_gaps_it_passed_over(self) -> None:
        """Silence about them would be the same as forgetting them."""
        self.scan.write_text(
            f"scan   {self.sbin}\ngap    {self.stray}\n", encoding="utf-8"
        )
        result = self.run_verify()
        self.assertIn("1 declared gap", result.stdout)




class PrivilegedHelpersAreAllowed(unittest.TestCase):
    """A dispatcher verb that sudo will refuse is a verb that does not exist.

    Release 2.9.90 failed on this. gatebsd-ci-verify-deployment had a manifest
    row, a verb in gatebsd-ci-dispatch and a step in the workflow -- and no line
    in ci_deployer.sudoers. `sudo -n` refused it, the validate job went red, and
    nothing in the tree said which of the four places had been missed.
    """

    def setUp(self) -> None:
        self.dispatch = (ROOT / "ci" / "host" / "gatebsd-ci-dispatch").read_text(encoding="utf-8")
        self.sudoers = (ROOT / "ci" / "host" / "ci_deployer.sudoers").read_text(encoding="utf-8")

    def sudo_targets(self) -> set[str]:
        """Absolute paths the dispatcher hands to `sudo -n`."""
        return set(re.findall(r"sudo -n (/\S+)", self.dispatch))

    def permitted(self) -> set[str]:
        return set(re.findall(r"NOPASSWD:\s*(/\S+)", self.sudoers))

    def test_the_dispatcher_asks_for_something(self) -> None:
        """A walk that finds nothing passes for ever."""
        self.assertTrue(self.sudo_targets(), "no `sudo -n` call found in the dispatcher")

    def test_every_helper_the_dispatcher_runs_is_permitted(self) -> None:
        missing = self.sudo_targets() - self.permitted()
        self.assertEqual(set(), missing, f"not named in ci_deployer.sudoers: {sorted(missing)}")

    def test_nothing_is_permitted_that_the_dispatcher_never_runs(self) -> None:
        """The other direction: a permission nobody uses is a permission to lose."""
        stray = self.permitted() - self.sudo_targets()
        self.assertEqual(set(), stray, f"permitted but never invoked: {sorted(stray)}")


class StandContourHardeningH4Tests(unittest.TestCase):
    def test_verifier_detects_wrong_owner_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            sbin = root / "usr/local/sbin"
            (repo / "infra/freebsd-ci").mkdir(parents=True)
            sbin.mkdir(parents=True)
            src = repo / "infra/freebsd-ci/thing.sh"
            src.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
            target = sbin / "thing"
            target.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
            target.chmod(0o750)
            manifest = root / "deployment.manifest"
            manifest.write_text(
                f"infra/freebsd-ci/thing.sh {target} 0750 nonexistent_owner nonexistent_group\n",
                encoding="utf-8",
            )
            env = {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "GATEBSD_PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "GATEBSD_REPO_DIR": str(repo),
                "GATEBSD_DEPLOY_MANIFEST": str(manifest),
                "GATEBSD_DEPLOY_PACKAGES": str(root / "no-packages"),
                "GATEBSD_DEPLOY_SCAN": str(root / "no-scan"),
                "GATEBSD_CRON_DIRS": str(root / "no-cron"),
                "GATEBSD_VERIFY_OWNERSHIP": "1",
                "HOME": str(root),
                "LANG": "C",
            }
            res = subprocess.run(["sh", str(VERIFY)], capture_output=True, text=True, env=env, check=False)
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertIn("WRONG OWNER", res.stdout)

            owner = pwd.getpwuid(os.geteuid()).pw_name
            group = grp.getgrgid(os.getegid()).gr_name
            manifest.write_text(
                f"infra/freebsd-ci/thing.sh {target} 0750 {owner} {group}\n",
                encoding="utf-8",
            )
            res_ok = subprocess.run(["sh", str(VERIFY)], capture_output=True, text=True, env=env, check=False)
            self.assertEqual(res_ok.returncode, 0, res_ok.stdout + res_ok.stderr)
            self.assertIn("No drift", res_ok.stdout)

    def test_installer_check_detects_mode_drift_when_content_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            sbin = root / "usr/local/sbin"
            (repo / "infra/freebsd-ci").mkdir(parents=True)
            sbin.mkdir(parents=True)
            src = repo / "infra/freebsd-ci/thing.sh"
            src.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
            target = sbin / "thing"
            target.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
            target.chmod(0o644)
            manifest = root / "deployment.manifest"
            manifest.write_text(
                f"infra/freebsd-ci/thing.sh {target} 0750 root wheel\n",
                encoding="utf-8",
            )
            env = {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "GATEBSD_PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "GATEBSD_REPO_DIR": str(repo),
                "GATEBSD_DEPLOY_MANIFEST": str(manifest),
                "GATEBSD_DEPLOY_PACKAGES": str(root / "no-packages"),
                "GATEBSD_DEPLOY_SCAN": str(root / "no-scan"),
                "GATEBSD_VERIFY_OWNERSHIP": "0",
                "HOME": str(root),
                "LANG": "C",
            }
            stale_res = subprocess.run(["sh", str(INSTALL), "--check"], capture_output=True, text=True, env=env, check=False)
            self.assertEqual(stale_res.returncode, 1, stale_res.stdout + stale_res.stderr)
            self.assertIn("would install", stale_res.stdout)

            target.chmod(0o750)
            ok_res = subprocess.run(["sh", str(INSTALL), "--check"], capture_output=True, text=True, env=env, check=False)
            self.assertEqual(ok_res.returncode, 0, ok_res.stdout + ok_res.stderr)
            self.assertIn("This machine matches the repository.", ok_res.stdout)

    def test_mirror_sync_git_accepts_stand_bsd_and_n100_bsd_only(self) -> None:
        mirror_script = INFRA / "mirror-sync-git.sh"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stub_bin = root / "bin"
            stub_bin.mkdir()
            (stub_bin / "id").write_text("#!/bin/sh\necho 0\n", encoding="ascii")
            (stub_bin / "mkdir").write_text("#!/bin/sh\nexit 42\n", encoding="ascii")
            (stub_bin / "tee").write_text("#!/bin/sh\ncat >/dev/null\n", encoding="ascii")
            for name in ("id", "mkdir", "tee"):
                (stub_bin / name).chmod(0o755)

            known_hosts = root / "known_hosts"
            known_hosts.write_text("git.freebsd.org ssh-ed25519 AAAA\n", encoding="ascii")

            for host, expected_rc in (("stand-bsd", 42), ("n100-BSD", 42), ("other-host", 78)):
                (stub_bin / "hostname").write_text(f"#!/bin/sh\necho {host}\n", encoding="ascii")
                (stub_bin / "hostname").chmod(0o755)
                res = subprocess.run(
                    ["sh", str(mirror_script)],
                    capture_output=True,
                    text=True,
                    env={
                        "PATH": f"{stub_bin}:/usr/bin:/bin",
                        "MIRROR_SYNC_GIT_PATH": f"{stub_bin}:/usr/bin:/bin",
                        "KNOWN_HOSTS": str(known_hosts),
                        "HOME": str(root),
                        "LANG": "C",
                    },
                    check=False,
                )
                self.assertEqual(res.returncode, expected_rc, f"{host}: rc={res.returncode} err={res.stderr}")

    def test_forgejo_backup_encrypts_secrets_with_passphrase_and_warns_without(self) -> None:
        backup_script = ROOT / "infra" / "forgejo" / "backup.sh"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stub_bin = root / "bin"
            stub_bin.mkdir()
            backup_root = root / "backups"
            backup_root.mkdir(mode=0o750)
            secret_src = root / "secret_dir"
            secret_src.mkdir()
            (secret_src / "app.ini").write_text("SECRET_KEY = test123\n", encoding="utf-8")
            passfile = root / "backup-passphrase"
            passfile.write_text("very-strong-passphrase\n", encoding="utf-8")
            passfile.chmod(0o600)

            (stub_bin / "id").write_text("#!/bin/sh\necho 0\n", encoding="ascii")
            (stub_bin / "lockf").write_text('#!/bin/sh\nshift 3\nexec "$@"\n', encoding="ascii")
            (stub_bin / "df").write_text("#!/bin/sh\necho 'Filesystem 1024-blocks Used Available Capacity Mounted on'\necho 'tank 100000000 1000 99999000 1% /'\n", encoding="ascii")
            (stub_bin / "zfs").write_text('#!/bin/sh\nif [ "$1" = list ] && [ "$2" = -H ] && [ "$3" = -p ]; then echo 1024; fi\nexit 0\n', encoding="ascii")
            (stub_bin / "service").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            (stub_bin / "chown").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            (stub_bin / "su").write_text(
                '#!/bin/sh\n'
                'cmd="$*"\n'
                'dump=$(printf "%s" "$cmd" | sed -n "s/.*--file \x27\\([^\x27]*\\)\x27.*/\\1/p")\n'
                'printf "fake-dump" > "$dump"\n',
                encoding="ascii",
            )
            for p in stub_bin.iterdir():
                p.chmod(0o755)

            env = {
                "PATH": f"{stub_bin}:/usr/bin:/bin",
                "HOME": str(root),
                "LANG": "C",
                "FORGEJO_BACKUP_ROOT": str(backup_root),
                "FORGEJO_BACKUP_LOCK": str(root / "backup.lock"),
                "FORGEJO_SECRETS_PASSPHRASE_FILE": str(passfile),
                "FORGEJO_SECRETS_PATHS": str(secret_src),
            }
            res = subprocess.run(["sh", str(backup_script)], capture_output=True, text=True, env=env, check=False)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            enc_files = sorted(backup_root.glob("stand-secrets-*.tar.enc"))
            self.assertEqual(len(enc_files), 1, list(backup_root.iterdir()))
            enc_file = enc_files[0]
            self.assertTrue(Path(str(enc_file) + ".sha256").is_file())
            decrypted_tar = root / "decrypted.tar"
            dec = subprocess.run(
                [
                    "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "600000",
                    "-pass", f"file:{passfile}", "-in", str(enc_file), "-out", str(decrypted_tar),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(dec.returncode, 0, dec.stderr)
            listing = subprocess.run(["tar", "-tf", str(decrypted_tar)], capture_output=True, text=True, check=True)
            self.assertIn("app.ini", listing.stdout)

            # Without passphrase file: warn cleanly without aborting Forgejo dump.
            passfile.unlink()
            res_warn = subprocess.run(["sh", str(backup_script)], capture_output=True, text=True, env=env, check=False)
            self.assertEqual(res_warn.returncode, 0, res_warn.stdout + res_warn.stderr)
            self.assertIn("passphrase", res_warn.stderr.lower())

    def test_forgejo_backup_stages_dump_when_backup_root_preexists_root_owned(self) -> None:
        backup_script = ROOT / "infra" / "forgejo" / "backup.sh"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stub_bin = root / "bin"
            stub_bin.mkdir()
            backup_root = root / "backups"
            backup_root.mkdir(mode=0o755)
            for idx in ("1", "2", "3"):
                for suffix in ("tar.zst", "tar.enc"):
                    prefix = "forgejo" if suffix == "tar.zst" else "stand-secrets"
                    item = backup_root / f"{prefix}-20200101T00000{idx}Z.{suffix}"
                    item.write_text(f"recent-{idx}\n", encoding="utf-8")
                    (backup_root / f"{item.name}.sha256").write_text("deadbeef\n", encoding="utf-8")
            passfile = root / "backup-passphrase"
            passfile.write_text("very-strong-passphrase\n", encoding="utf-8")
            passfile.chmod(0o600)
            secret_src = root / "secret_dir"
            secret_src.mkdir()
            (secret_src / "app.ini").write_text("SECRET_KEY = test123\n", encoding="utf-8")

            manual_dir = backup_root / "20260829T184817Z"
            manual_dir.mkdir(mode=0o700)
            manual_archive = manual_dir / "forgejo-data-config.tar.gz"
            manual_archive.write_text("manual-archive\n", encoding="utf-8")
            old_mtime = time.time() - (30 * 86400)
            os.utime(manual_archive, (old_mtime, old_mtime))

            chown_log = root / "chown.log"
            (stub_bin / "id").write_text("#!/bin/sh\necho 0\n", encoding="ascii")
            (stub_bin / "lockf").write_text('#!/bin/sh\nshift 3\nexec "$@"\n', encoding="ascii")
            (stub_bin / "df").write_text(
                "#!/bin/sh\necho 'Filesystem 1024-blocks Used Available Capacity Mounted on'\necho 'tank 100000000 1000 99999000 1% /'\n",
                encoding="ascii",
            )
            (stub_bin / "zfs").write_text(
                '#!/bin/sh\nif [ "$1" = list ] && [ "$2" = -H ] && [ "$3" = -p ]; then echo 1024; fi\nexit 0\n',
                encoding="ascii",
            )
            (stub_bin / "service").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            (stub_bin / "chown").write_text(
                f'#!/bin/sh\nprintf "%s %s\\n" "$1" "$2" >> "{chown_log}"\n',
                encoding="ascii",
            )
            (stub_bin / "su").write_text(
                '#!/bin/sh\n'
                'cmd="$*"\n'
                'dump=$(printf "%s" "$cmd" | sed -n "s/.*--file \x27\\([^\x27]*\\)\x27.*/\\1/p")\n'
                'stage_dir=$(dirname "$dump")\n'
                f'if [ "$stage_dir" = "{backup_root}" ] || ! grep -Fqx "git:git $stage_dir" "{chown_log}"; then\n'
                '  echo "Failed to open $dump: permission denied" >&2\n'
                '  exit 1\n'
                'fi\n'
                'printf "fake-dump" > "$dump"\n',
                encoding="ascii",
            )
            for p in stub_bin.iterdir():
                p.chmod(0o755)

            env = {
                "PATH": f"{stub_bin}:/usr/bin:/bin",
                "HOME": str(root),
                "LANG": "C",
                "FORGEJO_BACKUP_ROOT": str(backup_root),
                "FORGEJO_BACKUP_LOCK": str(root / "backup.lock"),
                "FORGEJO_SECRETS_PASSPHRASE_FILE": str(passfile),
                "FORGEJO_SECRETS_PATHS": str(secret_src),
            }
            res = subprocess.run(["sh", str(backup_script)], capture_output=True, text=True, env=env, check=False)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            chown_entries = chown_log.read_text(encoding="utf-8").splitlines()
            self.assertIn(f"root:git {backup_root}", chown_entries)

            dumps = sorted(backup_root.glob("forgejo-*.tar.zst"))
            secrets = sorted(backup_root.glob("stand-secrets-*.tar.enc"))
            self.assertEqual(len(dumps), 3, dumps)
            self.assertEqual(len(secrets), 3, secrets)
            self.assertFalse((backup_root / "forgejo-20200101T000001Z.tar.zst").exists())
            self.assertFalse((backup_root / "forgejo-20200101T000001Z.tar.zst.sha256").exists())
            self.assertFalse((backup_root / "stand-secrets-20200101T000001Z.tar.enc").exists())
            self.assertFalse((backup_root / "stand-secrets-20200101T000001Z.tar.enc.sha256").exists())
            self.assertTrue(Path(str(dumps[-1]) + ".sha256").is_file())
            self.assertFalse(list(backup_root.glob(".forgejo-dump.*")))
            self.assertTrue(manual_archive.is_file())

    def test_forgejo_nginx_and_deploy_use_shared_n100_tls_dir(self) -> None:
        nginx_conf = (ROOT / "infra" / "forgejo" / "nginx-forgejo.conf.sample").read_text(encoding="utf-8")
        self.assertIn("/usr/local/etc/ssl/n100-tls/server.crt", nginx_conf)
        self.assertIn("/usr/local/etc/ssl/n100-tls/server.key", nginx_conf)
        self.assertNotIn("/usr/local/etc/ssl/home-forge", nginx_conf)

        deploy = (ROOT / "infra" / "forgejo" / "deploy.sh").read_text(encoding="utf-8")
        self.assertIn("/usr/local/etc/ssl/n100-tls", deploy)
        self.assertIn("server.crt", deploy)
        self.assertIn("server.key", deploy)
        self.assertNotIn("/tmp/", deploy)
        self.assertNotRegex(
            deploy,
            re.compile(r'^install -d -o root -g wheel -m 0700 "\$SECRET_DIR" "\$TLS_DIR"', re.MULTILINE),
        )


if __name__ == "__main__":
    unittest.main()
