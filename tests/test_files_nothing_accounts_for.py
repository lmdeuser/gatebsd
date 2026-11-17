"""A file nothing accounts for is now reported, not found by listing a directory.

verify-deployment.sh could see four kinds of drift, and every one of them
started from something that NAMES a file: a manifest row, a managed name, a
cron line. A file nothing names was a file nothing checked.

That is not a gap anyone reasoned their way to. /usr/local/sbin/configure-
freebsd-mirror was found on 6 August 2026 by listing the directory by hand. It
was a July copy of ci/host/configure_freebsd_mirror.sh, still carrying the
set_conf() awk writer of /usr/local/etc/poudriere.conf that 1ea48bd had removed
from the repository -- a second writer of a managed file, sitting in root's
PATH under a name that invites running it. No manifest claimed it. No cron file
scheduled it. It had been there for three weeks and the verifier had been run
repeatedly in that time.

Four more were beside it: configure-n100-console-samba, repair-n100-boot,
n100-tls-renew and two -v2 generations of mirror-sync-git.

Every test here RUNS verify-deployment.sh or retire-leftovers.sh against a
synthetic tree. None of them reads a script for the presence of a string: the
defect being reintroduced is a file appearing in a directory, and the only
honest proof that the tool notices is the tool noticing.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra" / "freebsd-ci"
MANIFEST = INFRA / "deployment.manifest"
SCAN = INFRA / "deployment.scan"
VERIFY = INFRA / "verify-deployment.sh"
RETIRE = INFRA / "retire-leftovers.sh"


def scan_rows() -> list[list[str]]:
    rows = []
    for line in SCAN.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            rows.append(line.split())
    return rows


def manifest_targets() -> list[str]:
    targets = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            targets.append(line.split()[1])
    return targets


def write_stub(directory: Path, name: str, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/bin/sh\n" + body, encoding="ascii")
    path.chmod(0o755)
    return path


def pkg_stub(directory: Path, owned: tuple[str, ...] = ()) -> Path:
    """A `pkg` that answers `which -q` for exactly the paths given.

    Linux has no pkg(8) at all, so without this the ownership rule is
    unreachable and every exemption below would go untested -- which is the
    failure mode where a test passes because the branch it covers never ran.
    """
    cases = "".join(f"    {path}) exit 0 ;;\n" for path in owned)
    return write_stub(
        directory,
        "pkg",
        'if [ "$1" = which ]; then\n'
        "  shift\n"
        "  while [ $# -gt 0 ]; do\n"
        '    case "$1" in -*|--) shift ;; *) break ;; esac\n'
        "  done\n"
        '  case "$1" in\n'
        f"{cases}"
        "    *) exit 1 ;;\n"
        "  esac\n"
        "fi\n"
        "exit 1\n",
    )


class ScanDeclarationTests(unittest.TestCase):
    """The declaration itself, before anything reads it."""

    def test_every_row_uses_a_known_keyword(self) -> None:
        for row in scan_rows():
            self.assertIn(row[0], ("scan", "state", "gap"), row)
            self.assertGreaterEqual(len(row), 2, row)

    def test_every_path_is_absolute(self) -> None:
        # The verifier compares these against find(1) output, which is absolute
        # because the root it is given is. A relative path here would match
        # nothing and the row would be silently inert.
        for row in scan_rows():
            self.assertTrue(row[1].startswith("/"), row)

    def test_the_three_directories_that_have_burned_us_are_scanned(self) -> None:
        roots = [row[1] for row in scan_rows() if row[0] == "scan"]
        for expected in ("/usr/local/sbin", "/usr/local/libexec", "/usr/local/etc"):
            self.assertIn(expected, roots)

    def test_every_state_and_gap_lies_under_a_scanned_root(self) -> None:
        """An exemption for something never scanned is a comment, not a rule.

        It also rots silently: the day the root it was meant for is renamed,
        the exemption keeps looking deliberate and stops doing anything.
        """
        roots = [row[1] for row in scan_rows() if row[0] == "scan"]
        for row in scan_rows():
            if row[0] == "scan":
                continue
            self.assertTrue(
                any(row[1] == r or row[1].startswith(r + "/") for r in roots),
                f"{row[1]} is exempted from a directory nothing scans",
            )

    def test_no_gap_is_also_a_manifest_row(self) -> None:
        """A file cannot be both managed and knowingly unmanaged."""
        targets = set(manifest_targets())
        for row in scan_rows():
            if row[0] == "gap":
                self.assertNotIn(row[1], targets, row[1])

    def test_the_gap_that_started_all_of_this_is_closed(self) -> None:
        """mirror-sync-git was the declared gap this file was written around.

        It was declared rather than imported because nobody had re-derived its
        8.6 KB of staging-and-atomic-publish logic, and a fiction in the
        repository is worse than an admitted hole. That held until 27 August
        2026, when the unread script turned out to keep every previous copy of
        every mirrored repository forever -- 104 of them, 180 GB -- filled the
        pool and stopped the release mirror for four days.

        The gap is what made that invisible, so this now pins the opposite: the
        file is managed, and no longer declared as a hole. Should it ever go
        back to being a gap, both halves have to move together.
        """
        gaps = [row[1] for row in scan_rows() if row[0] == "gap"]
        self.assertNotIn("/usr/local/sbin/mirror-sync-git", gaps)
        self.assertIn("/usr/local/sbin/mirror-sync-git", set(manifest_targets()))


class VerifierSeesUnaccountedFilesTests(unittest.TestCase):
    """Drives verify-deployment.sh against a synthetic /usr/local."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.repo = self.root / "repo"
        self.sbin = self.root / "usr/local/sbin"
        self.etc = self.root / "usr/local/etc"
        self.cron = self.root / "cron.d"
        self.stubs = self.root / "stubbin"
        self.backups = self.root / "backups"
        for path in (self.repo / "infra/freebsd-ci", self.sbin, self.etc, self.cron):
            path.mkdir(parents=True)

        (self.repo / "infra/freebsd-ci/thing.sh").write_text(
            "#!/bin/sh\ntrue\n", encoding="utf-8"
        )
        self.managed = self.sbin / "thing"
        self.managed.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        self.managed.chmod(0o750)

        self.manifest = self.root / "deployment.manifest"
        self.manifest.write_text(
            f"infra/freebsd-ci/thing.sh {self.managed} 0750 root wheel\n", encoding="utf-8"
        )
        self.scan = self.root / "deployment.scan"
        self.write_scan()
        pkg_stub(self.stubs)

    def write_scan(self, extra: str = "") -> None:
        self.scan.write_text(f"scan {self.sbin}\nscan {self.etc}\n{extra}", encoding="utf-8")

    def env(self, **extra: str) -> dict[str, str]:
        searchpath = f"{self.stubs}:/usr/bin:/bin"
        env = {
            "PATH": searchpath,
            "GATEBSD_PATH": searchpath,
            "GATEBSD_REPO_DIR": str(self.repo),
            "GATEBSD_DEPLOY_MANIFEST": str(self.manifest),
            "GATEBSD_DEPLOY_SCAN": str(self.scan),
            "GATEBSD_DEPLOY_PACKAGES": str(self.root / "no-such-packages.list"),
            "GATEBSD_LEFTOVER_BACKUP_ROOT": str(self.backups),
            "GATEBSD_CRON_DIRS": str(self.cron),
            "GATEBSD_MANAGED_PREFIX": str(self.sbin),
            "HOME": str(self.root),
            "LANG": "C",
        }
        env.update(extra)
        return env

    def verify(self, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(VERIFY)], capture_output=True, text=True, check=False, env=self.env(**extra)
        )

    def retire(self, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(RETIRE), *args],
            capture_output=True,
            text=True,
            check=False,
            env=self.env(**extra),
        )

    def test_the_harness_is_clean_before_the_defect_is_put_back(self) -> None:
        """Everything below is worthless if this is not true first."""
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No drift", result.stdout)

    def test_a_hand_installed_script_in_a_scanned_directory_is_reported(self) -> None:
        """The defect, put back exactly as it was found.

        A copy of a repository script, dropped into a PATH directory, claimed
        by no manifest row and scheduled by no cron file. This is what sat at
        /usr/local/sbin/configure-freebsd-mirror for three weeks.
        """
        stray = self.sbin / "configure-freebsd-mirror"
        stray.write_text("#!/bin/sh\nset_conf() { :; }\n", encoding="utf-8")
        stray.chmod(0o750)

        result = self.verify()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("UNACCOUNTED", result.stdout)
        self.assertIn(str(stray), result.stdout)

    def test_removing_it_makes_the_verifier_clean_again(self) -> None:
        """The other half of the reintroduction: the finding must go away.

        A check that reports the same thing whatever the machine looks like
        would pass this file's first test just as happily.
        """
        stray = self.sbin / "configure-freebsd-mirror"
        stray.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        self.assertEqual(self.verify().returncode, 1)

        stray.unlink()
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_stray_below_a_scanned_directory_is_reported_too(self) -> None:
        """rc.d and cron.d are subdirectories, and are where this hurts most.

        rcorder(8) and cron(8) each read every file in their directory whatever
        it is called, so a stray there is not clutter -- it is a second live
        configuration.
        """
        (self.etc / "rc.d").mkdir()
        stray = self.etc / "rc.d/gatebsd_agent.orig"
        stray.write_text("# PROVIDE: gatebsd_agent\n", encoding="utf-8")

        result = self.verify()

        self.assertIn("UNACCOUNTED", result.stdout)
        self.assertIn(str(stray), result.stdout)

    def test_a_managed_file_is_not_reported(self) -> None:
        result = self.verify()
        self.assertNotIn("UNACCOUNTED", result.stdout)
        self.assertIn(str(self.managed), result.stdout)

    def test_a_file_pkg_owns_is_not_reported(self) -> None:
        theirs = self.sbin / "nginx"
        theirs.write_text("binary\n", encoding="utf-8")

        self.assertIn("UNACCOUNTED", self.verify().stdout)

        pkg_stub(self.stubs, (str(theirs),))
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_file_whose_port_copy_pkg_owns_is_not_reported(self) -> None:
        """The four names a FreeBSD port uses for configuration it does not install.

        The port ships the copy and lets the first install put the live file in
        place, so the live file belongs to no package while the port plainly
        accounts for it. Without this rule /usr/local/etc reports two hundred
        findings and the dozen that are ours are lost in them -- and a verifier
        nobody can read is one nobody runs.
        """
        for suffix in (".sample", "-dist", ".dist", ".default"):
            with self.subTest(suffix=suffix):
                live = self.etc / "some-port.conf"
                live.write_text("live\n", encoding="utf-8")
                pkg_stub(self.stubs)
                self.assertIn(
                    "UNACCOUNTED", self.verify().stdout, f"{suffix}: unowned file not reported"
                )

                pkg_stub(self.stubs, (f"{live}{suffix}",))
                result = self.verify()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                live.unlink()

    def test_a_declared_gap_is_reported_as_a_decision_not_a_surprise(self) -> None:
        gap = self.sbin / "mirror-sync-git"
        gap.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        self.write_scan(extra=f"gap {gap}\n")

        result = self.verify()

        self.assertIn("KNOWN GAP", result.stdout)
        self.assertIn(str(gap), result.stdout)
        self.assertNotIn("UNACCOUNTED", result.stdout)

    def test_a_declared_gap_is_still_a_finding(self) -> None:
        """Naming it says "this was decided", not "stop mentioning it".

        mirror-sync-git has been reported on every run since the manifest
        existed, and that is the only reason anyone still remembers it has no
        source. A gap that stops being printed stops being remembered.
        """
        gap = self.sbin / "mirror-sync-git"
        gap.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        self.write_scan(extra=f"gap {gap}\n")

        self.assertEqual(self.verify().returncode, 1)

    def test_runtime_state_is_skipped(self) -> None:
        state = self.etc / "step/ca/db"
        state.mkdir(parents=True)
        (state / "MANIFEST").write_text("badger\n", encoding="utf-8")

        self.assertIn("UNACCOUNTED", self.verify().stdout)

        self.write_scan(extra=f"state {self.etc / 'step'}\n")
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_state_exemption_does_not_excuse_a_name_that_merely_starts_with_it(self) -> None:
        """`state /usr/local/etc/ssl` must not cover `.../sslmirror.conf`.

        A prefix match on the string would, and the file it waved through would
        be exactly the kind nobody is watching. The same class of mistake as
        judging a leftover by its name.
        """
        (self.etc / "ssl").mkdir()
        (self.etc / "ssl/server.key").write_text("key\n", encoding="utf-8")
        neighbour = self.etc / "sslmirror.conf"
        neighbour.write_text("conf\n", encoding="utf-8")

        self.write_scan(extra=f"state {self.etc / 'ssl'}\n")
        result = self.verify()

        self.assertIn(str(neighbour), result.stdout)
        self.assertNotIn("server.key", result.stdout)

    def test_a_leftover_beside_a_gap_is_a_leftover_not_a_stranger(self) -> None:
        """The payoff for declaring gaps at all.

        mirror-sync-git-v2 and mirror-sync-git-v2.bak2 sat in /usr/local/sbin
        since July. The leftover sweep never looked at them for one reason: no
        manifest row named the file they were copies of. Twenty-two dated
        copies of nginx's mirror site file were invisible for the same reason.
        """
        gap = self.sbin / "mirror-sync-git"
        gap.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        stale = self.sbin / "mirror-sync-git-v2"
        stale.write_text("#!/bin/sh\nold\n", encoding="utf-8")
        self.write_scan(extra=f"gap {gap}\n")

        result = self.verify()

        self.assertIn(f"LEFTOVER          {stale}", result.stdout)

    def test_a_leftover_is_not_also_reported_as_unaccounted(self) -> None:
        """One file, one verdict. Two would make the count meaningless."""
        gap = self.sbin / "mirror-sync-git"
        gap.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        stale = self.sbin / "mirror-sync-git-v2"
        stale.write_text("#!/bin/sh\nold\n", encoding="utf-8")
        self.write_scan(extra=f"gap {gap}\n")

        verdicts = [
            line
            for line in self.verify().stdout.splitlines()
            if str(stale) in line and line.split()[0] in ("LEFTOVER", "UNACCOUNTED", "KNOWN")
        ]
        self.assertEqual(len(verdicts), 1, verdicts)

    def test_the_retirer_carries_off_what_the_verifier_calls_a_leftover(self) -> None:
        """Both tools must judge the same set, or neither is worth running.

        A retirer with the narrower anchor set leaves behind precisely what the
        verifier keeps reporting, and the operator learns to ignore the report.
        That is the archetype this project keeps paying for: the same name,
        different rules in different tools.
        """
        gap = self.sbin / "mirror-sync-git"
        gap.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        stale = self.sbin / "mirror-sync-git-v2"
        stale.write_text("#!/bin/sh\nold\n", encoding="utf-8")
        self.write_scan(extra=f"gap {gap}\n")

        result = self.retire()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(stale.exists(), result.stdout)
        self.assertTrue(gap.exists(), "the gap itself is not a leftover of itself")
        retired = list(self.backups.rglob("mirror-sync-git-v2"))
        self.assertEqual(len(retired), 1, result.stdout)

    def test_the_retirer_leaves_a_gap_alone_when_no_scan_file_is_given(self) -> None:
        """An absent declaration must narrow the anchor set, never widen it."""
        gap = self.sbin / "mirror-sync-git"
        gap.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        stale = self.sbin / "mirror-sync-git-v2"
        stale.write_text("#!/bin/sh\nold\n", encoding="utf-8")

        result = self.retire(GATEBSD_DEPLOY_SCAN=str(self.root / "no-such.scan"))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(stale.exists())

    def test_an_absent_scan_declaration_is_not_a_finding(self) -> None:
        """A stand that declares no scanned directories declares nothing wrong.

        Same contract as packages.list: the file's absence means the check does
        not apply, not that the check failed.
        """
        stray = self.sbin / "configure-freebsd-mirror"
        stray.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")

        result = self.verify(GATEBSD_DEPLOY_SCAN=str(self.root / "no-such.scan"))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class TheStandsOwnDeclarationTests(unittest.TestCase):
    """The real files, not a synthetic tree."""

    def test_the_adopted_files_have_sources_in_the_repository(self) -> None:
        # nginx_after_libvirt was adopted here until 14 August 2026 and is gone
        # with libvirt: the stand is a virtual machine now, it runs no libvirtd,
        # and nginx no longer binds a bridge address to wait for.
        adopted = {
            "/usr/local/etc/rc.d/stand_network_ready",
            "/usr/local/etc/sudoers.d/ci_deployer",
            "/usr/local/etc/pkg/repos/FreeBSD.conf",
        }
        rows = {}
        for line in MANIFEST.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                parts = line.split()
                rows[parts[1]] = parts[0]
        for target in adopted:
            self.assertIn(target, rows, f"{target} was adopted but has no manifest row")
            self.assertTrue((ROOT / rows[target]).is_file(), rows[target])

    def test_the_rc_scripts_still_carry_the_lines_rcorder_reads(self) -> None:
        """Half of what these files do is a comment block.

        rcorder(8) reads the PROVIDE/REQUIRE header, not the code. Lose the
        PROVIDE line and the file is inert while still looking deployed --
        which is why it is asserted rather than assumed.
        """
        for name, provide in (
            ("rc.d-stand_network_ready", "stand_network_ready"),
        ):
            text = (INFRA / name).read_text(encoding="utf-8")
            self.assertIn(f"# PROVIDE: {provide}", text, name)
            self.assertIn("run_rc_command", text, name)

    def test_the_sudo_rule_grants_exactly_one_command(self) -> None:
        """It is the CI trust boundary, and it is in the manifest now so that a
        line appearing in it is drift rather than a discovery."""
        text = (ROOT / "ci/host/ci_deployer.sudoers").read_text(encoding="utf-8")
        grants = [line for line in text.splitlines() if "NOPASSWD" in line]
        self.assertEqual(len(grants), 1, grants)
        self.assertIn("/usr/local/libexec/gatebsd-ci-build", grants[0])
        self.assertNotIn("ALL", grants[0].split("NOPASSWD:", 1)[1])

    def test_both_tools_read_the_same_declaration(self) -> None:
        for script in (VERIFY, RETIRE):
            self.assertIn("GATEBSD_DEPLOY_SCAN", script.read_text(encoding="utf-8"), script.name)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
