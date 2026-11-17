"""The device has to be told where its packages come from, by the tree.

The pkg repository config and the stand's public key decide whether a unit
takes packages from this project or from upstream quarterly. They lived only
on the production router, typed in by hand on 30 July: not in this tree, not
in any package, not published anywhere. A unit rebuilt from an
image would have reported the same version and carried different packages,
which is the one promise the dual delivery path makes.

These tests RUN gatebsd-repo-bootstrap against a throwaway prefix. Reading it
would prove nothing -- the wiring test that read a script's text passed happily
with the call sitting behind `if false`, and this script's whole job is a side
effect on the filesystem.
"""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "sbin" / "gatebsd-repo-bootstrap"
CANONICAL_CONF = ROOT / "etc" / "pkg" / "repos" / "gatebsd.conf"
CANONICAL_KEY = ROOT / "etc" / "pkg" / "keys" / "gatebsd-stand.pub"

# A device pointed at upstream is the defect itself, so it is what the drift
# cases reintroduce.
UPSTREAM = "FreeBSD-ports: { enabled: yes }\n"


def _run(*args: str, prefix: Path, backups: Path | None = None):
    environment = dict(os.environ)
    if backups is not None:
        environment["GATEBSD_REPO_BACKUP_ROOT"] = str(backups)
    return subprocess.run(
        [str(BOOTSTRAP), "--prefix", str(prefix), *args],
        capture_output=True,
        text=True,
        env=environment,
    )


class BootstrapPointsADeviceAtTheStand(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.prefix = Path(self._tmp.name) / "local"
        self.backups = Path(self._tmp.name) / "backups"
        self.conf = self.prefix / "etc" / "pkg" / "repos" / "gatebsd.conf"
        self.key = self.prefix / "etc" / "pkg" / "keys" / "gatebsd-stand.pub"

    def _bootstrap(self, *args: str):
        return _run(*args, prefix=self.prefix, backups=self.backups)

    def _overwrite(self, path: Path, text: str) -> None:
        path.chmod(0o644)
        path.write_text(text, encoding="utf-8")

    def test_a_bare_device_gets_both_files_with_the_release_content(self) -> None:
        result = self._bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.conf.read_text(encoding="utf-8"),
            CANONICAL_CONF.read_text(encoding="utf-8"),
        )
        self.assertEqual(
            self.key.read_text(encoding="ascii"),
            CANONICAL_KEY.read_text(encoding="ascii"),
        )
        self.assertEqual(stat.S_IMODE(self.conf.stat().st_mode), 0o644)
        # The trust anchor is world-readable and nobody's to rewrite.
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o444)

    def test_the_config_never_lands_before_the_key_it_names(self) -> None:
        """pkg fails every repository operation if the pubkey is not there.

        On a bare device that operation is the one being bootstrapped, so the
        order is load-bearing rather than cosmetic.
        """
        result = self._bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        written = [
            line.split()[1]
            for line in result.stdout.splitlines()
            if line.startswith("wrote")
        ]
        self.assertEqual(written, [str(self.key), str(self.conf)])

    def test_running_it_twice_changes_nothing(self) -> None:
        self.assertEqual(self._bootstrap().returncode, 0)
        again = self._bootstrap()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertNotIn("wrote", again.stdout)
        self.assertEqual(again.stdout.count("ok"), 2)

    def test_check_reports_a_device_that_drifted_back_to_upstream(self) -> None:
        self.assertEqual(self._bootstrap().returncode, 0)
        self._overwrite(self.conf, UPSTREAM)

        drifted = self._bootstrap("--check")
        self.assertEqual(drifted.returncode, 1, drifted.stdout)
        self.assertIn("DRIFT", drifted.stdout)
        # --check reports; it must not quietly repair what it was asked about.
        self.assertEqual(self.conf.read_text(encoding="utf-8"), UPSTREAM)

    def test_a_drifted_device_converges_and_the_old_copy_is_kept(self) -> None:
        self.assertEqual(self._bootstrap().returncode, 0)
        self._overwrite(self.conf, UPSTREAM)

        repaired = self._bootstrap()
        self.assertEqual(repaired.returncode, 0, repaired.stderr)
        self.assertEqual(
            self.conf.read_text(encoding="utf-8"),
            CANONICAL_CONF.read_text(encoding="utf-8"),
        )
        self.assertEqual(self._bootstrap("--check").returncode, 0)

        kept = list(self.backups.rglob("gatebsd.conf"))
        self.assertEqual(len(kept), 1, "the replaced config was not kept")
        self.assertEqual(kept[0].read_text(encoding="utf-8"), UPSTREAM)

    def test_a_replaced_trust_key_is_rewritten_despite_its_read_only_mode(self) -> None:
        """0444 is the installed mode, so replacing it writes over a read-only file."""
        self.assertEqual(self._bootstrap().returncode, 0)
        self._overwrite(self.key, "-----BEGIN PUBLIC KEY-----\nnope\n")

        repaired = self._bootstrap()
        self.assertEqual(repaired.returncode, 0, repaired.stderr)
        self.assertEqual(
            self.key.read_text(encoding="ascii"),
            CANONICAL_KEY.read_text(encoding="ascii"),
        )
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o444)

    def test_right_content_with_the_wrong_mode_is_still_drift(self) -> None:
        """Found on the rehearsal rig: the key byte-identical and 0644.

        A comparison that stops at the bytes calls that device converged. On
        the trust anchor the mode is the half that decides what the device
        will accept as a signed package.
        """
        self.assertEqual(self._bootstrap().returncode, 0)
        self.key.chmod(0o664)

        drifted = self._bootstrap("--check")
        self.assertEqual(drifted.returncode, 1, drifted.stdout)
        self.assertIn("mode 664, expected 444", drifted.stdout)
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o664)

        repaired = self._bootstrap()
        self.assertEqual(repaired.returncode, 0, repaired.stderr)
        self.assertIn("chmod", repaired.stdout)
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o444)
        self.assertEqual(
            self.key.read_text(encoding="ascii"),
            CANONICAL_KEY.read_text(encoding="ascii"),
        )

    def test_a_mode_fix_does_not_pass_through_the_backup_path(self) -> None:
        """Nothing was replaced, so there is nothing to keep."""
        self.assertEqual(self._bootstrap().returncode, 0)
        self.conf.chmod(0o600)
        self.assertEqual(self._bootstrap().returncode, 0)
        self.assertFalse(self.backups.exists(), "a chmod left a pointless backup")

    def test_it_refuses_a_symlinked_destination(self) -> None:
        elsewhere = Path(self._tmp.name) / "elsewhere"
        elsewhere.mkdir()
        self.conf.parent.mkdir(parents=True)
        self.conf.symlink_to(elsewhere / "gatebsd.conf")

        result = self._bootstrap()
        self.assertNotEqual(result.returncode, 0, "symlinked destination accepted")
        self.assertFalse((elsewhere / "gatebsd.conf").exists())

    def test_it_reports_drift_against_the_prefix_it_was_given(self) -> None:
        """A prefix that already holds a stale config is not a bare device."""
        self.conf.parent.mkdir(parents=True)
        self.conf.write_text(UPSTREAM, encoding="utf-8")
        result = self._bootstrap("--check")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("missing", result.stdout)  # the key
        self.assertIn("differs", result.stdout)  # the config


class InstalledCopyDoesNotCompareTheDestinationWithItself(unittest.TestCase):
    """Once installed, ../etc/pkg relative to sbin/ *is* the destination.

    Left unguarded, an installed --check would compare the deployed files
    against themselves and pass on any device, however far it had drifted --
    the same nothing as a test that reads a script instead of running it.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.prefix = Path(self._tmp.name) / "local"
        (self.prefix / "sbin").mkdir(parents=True)
        self.installed = self.prefix / "sbin" / "gatebsd-repo-bootstrap"
        self.installed.write_bytes(BOOTSTRAP.read_bytes())
        self.installed.chmod(0o755)
        self.share = self.prefix / "share" / "gatebsd" / "etc" / "pkg"

    def _stage_canonical(self) -> None:
        (self.share / "repos").mkdir(parents=True)
        (self.share / "keys").mkdir(parents=True)
        (self.share / "repos" / "gatebsd.conf").write_bytes(CANONICAL_CONF.read_bytes())
        (self.share / "keys" / "gatebsd-stand.pub").write_bytes(CANONICAL_KEY.read_bytes())

    def _run_installed(self, *args: str):
        return subprocess.run(
            [str(self.installed), "--prefix", str(self.prefix), *args],
            capture_output=True,
            text=True,
        )

    def test_the_installed_script_uses_the_packaged_canonical_copy(self) -> None:
        self._stage_canonical()
        self.assertEqual(self._run_installed().returncode, 0)

        deployed = self.prefix / "etc" / "pkg" / "repos" / "gatebsd.conf"
        deployed.chmod(0o644)
        deployed.write_text(UPSTREAM, encoding="utf-8")
        drifted = self._run_installed("--check")
        self.assertEqual(drifted.returncode, 1, drifted.stdout)

    def test_without_the_packaged_copy_it_refuses_instead_of_passing(self) -> None:
        deployed = self.prefix / "etc" / "pkg" / "repos" / "gatebsd.conf"
        deployed.parent.mkdir(parents=True)
        deployed.write_text(UPSTREAM, encoding="utf-8")
        (self.prefix / "etc" / "pkg" / "keys").mkdir()
        (self.prefix / "etc" / "pkg" / "keys" / "gatebsd-stand.pub").write_text(
            "not the stand key\n", encoding="ascii"
        )

        result = self._run_installed("--check")
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertNotIn("matches", result.stdout)


class ThePackageCarriesWhatTheBootstrapNeeds(unittest.TestCase):
    """Staged is not packaged, and unstaged is not deliverable.

    Both halves have gone wrong here before: a file reached the staging tree
    and the manifest generator dropped it, and a script existed in sbin/ and
    was never added to the build's install loop. So these run build.sh's own
    statements rather than trusting that they say what they appear to say.
    """

    def setUp(self) -> None:
        self.build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")

    def _statements(self, needle: str) -> list[str]:
        return [
            line.strip()
            for line in self.build.splitlines()
            if needle in line and not line.strip().startswith("#")
        ]

    def test_build_stages_the_repository_config_and_the_trust_key(self) -> None:
        statements = [
            line
            for line in self._statements("share/gatebsd/etc/pkg/")
            if line.startswith("install -m")
        ]
        self.assertTrue(statements, "build.sh no longer stages the repository files")

        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            for relative in ("repos", "keys"):
                (stage / "usr/local/share/gatebsd/etc/pkg" / relative).mkdir(
                    parents=True
                )
            script = "\n".join(
                ["set -eu", f'STAGE="{stage}"', f'REPO_DIR="{ROOT}"'] + statements
            )
            result = subprocess.run(
                ["/bin/sh", "-c", script], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            staged = stage / "usr/local/share/gatebsd/etc/pkg"
            self.assertEqual(
                (staged / "repos" / "gatebsd.conf").read_bytes(),
                CANONICAL_CONF.read_bytes(),
            )
            self.assertEqual(
                (staged / "keys" / "gatebsd-stand.pub").read_bytes(),
                CANONICAL_KEY.read_bytes(),
            )

    def test_build_stages_the_bootstrap_itself(self) -> None:
        start = self.build.index("for file in gatewayctl ")
        end = self.build.index("done", start) + len("done")
        loop = self.build[start:end]

        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            (stage / "usr/local/sbin").mkdir(parents=True)
            result = subprocess.run(
                ["/bin/sh", "-c", f'set -eu\nSTAGE="{stage}"\nREPO_DIR="{ROOT}"\n{loop}'],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            staged = stage / "usr/local/sbin" / "gatebsd-repo-bootstrap"
            self.assertTrue(staged.is_file(), "the package would not carry the bootstrap")
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o755)

    def test_the_generated_file_list_carries_the_repository_files(self) -> None:
        start = self.build.index("FILES_LIST=$(cd ")
        end = self.build.index("done)", start) + len("done)")
        generator = self.build[start:end]

        expected = (
            "usr/local/share/gatebsd/etc/pkg/repos/gatebsd.conf",
            "usr/local/share/gatebsd/etc/pkg/keys/gatebsd-stand.pub",
            "usr/local/sbin/gatebsd-repo-bootstrap",
        )
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            for relative in expected:
                path = stage / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x", encoding="utf-8")

            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    f'set -eu\nSTAGE="{stage}"\n{generator}\nprintf "%s\\n" "$FILES_LIST"',
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            listed = result.stdout
            for relative in expected:
                self.assertIn(f"/{relative}:", listed)
            self.assertIn("/usr/local/sbin/gatebsd-repo-bootstrap: \"0755\"", listed)

    def test_post_install_runs_the_bootstrap(self) -> None:
        opening = "post-install: <<EOS"
        start = self.build.index(opening) + len(opening)
        end = self.build.index("\nEOS", start)
        post_install = self.build[start:end]
        calls = [
            line.strip()
            for line in post_install.splitlines()
            if line.strip() == "/usr/local/sbin/gatebsd-repo-bootstrap"
        ]
        self.assertEqual(len(calls), 1, "post-install does not converge the repo config")


if __name__ == "__main__":
    unittest.main()
