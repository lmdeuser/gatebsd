"""Installing a package that changes the additions must change the resolver.

The defect: `pkg add` writes the new `etc/gatebsd/adblock-extra` onto the
device, but nothing rebuilds the generated `/usr/local/etc/unbound/adblock.conf`
from it. The resolver keeps serving the previous build until the six-hourly
cron fires. Seen on the production router twice -- with 2.9.45 and again with
2.9.47 -- where the new names were on disk and absent from the resolver, and
both times the list only appeared after a hand-run of the updater. A customer
sees a product that visibly did not change and has no way to know why; this is
the house archetype, "the file changed and the thing living off it did not
notice", with the generator standing in for the daemon.

Two halves, and the second is the one that has failed before:

* the updater learns to answer "nothing to do" cheaply, so putting it on the
  upgrade path does not cost a 19 MB download on every release; and
* the upgrade path actually calls it. That test *runs* `gatebsd-upgrade` and
  watches for the call -- an earlier wiring test in this project passed happily
  with the call sitting behind `if false`, because it read the source instead.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from test_adblock_update import AdblockHarness

ROOT = Path(__file__).resolve().parents[1]
UPGRADE = ROOT / "sbin" / "gatebsd-upgrade"


class OnlyRebuildWhenTheInputsChanged(AdblockHarness):
    """`--if-changed` is the cheap answer that makes the wiring affordable."""

    def setUp(self) -> None:
        super().setUp()
        self.stamp = self.root / "adblock-inputs"
        self.extra = self.root / "adblock-extra"
        self.extra.write_text("0.0.0.0 first.example.com\n", encoding="ascii")

    def _env(self) -> dict[str, str]:
        return {
            "GATEBSD_ADBLOCK_STAMP": str(self.stamp),
            "GATEBSD_ADBLOCK_EXTRA": str(self.extra),
        }

    def _fetch_count(self) -> int:
        """How many times the fake `fetch` was asked for a source."""
        return len(self.check_log.read_text(encoding="utf-8").splitlines())

    def test_a_successful_run_records_what_it_built_from(self) -> None:
        result = self._run(include_style="quoted", extra_env=self._env())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.stamp.is_file(), "no record of the inputs was written")
        recorded = self.stamp.read_text(encoding="utf-8")
        self.assertIn("first.example.com", recorded)
        self.assertIn("https://example.invalid/hosts", recorded)

    def test_unchanged_inputs_are_not_rebuilt(self) -> None:
        first = self._run(include_style="quoted", extra_env=self._env())
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        published = self.blocklist.read_text(encoding="utf-8")
        before = self._fetch_count()

        second = self._run(
            include_style="quoted",
            extra_env=self._env(),
            args=["--if-changed"],
            previous_blocklist=published,
        )
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("unchanged", (second.stdout + second.stderr).lower())
        self.assertEqual(
            self._fetch_count(),
            before,
            "the skip still went out and downloaded the sources",
        )
        self.assertEqual(self.blocklist.read_text(encoding="utf-8"), published)

    def test_a_changed_additions_file_is_rebuilt(self) -> None:
        first = self._run(include_style="quoted", extra_env=self._env())
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        published = self.blocklist.read_text(encoding="utf-8")

        # Exactly what installing a new package does.
        self.extra.write_text(
            "0.0.0.0 first.example.com\n0.0.0.0 second.example.com\n",
            encoding="ascii",
        )
        result = self._run(
            include_style="quoted",
            extra_env=self._env(),
            args=["--if-changed"],
            previous_blocklist=published,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "second.example.com",
            self.blocklist.read_text(encoding="utf-8"),
            "the name the package brought never reached the resolver",
        )

    def test_a_changed_source_list_is_rebuilt(self) -> None:
        """Adding a feed changes the result too, and no extras file moved."""
        first = self._run(include_style="quoted", extra_env=self._env())
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        published = self.blocklist.read_text(encoding="utf-8")
        before = self._fetch_count()

        env = self._env()
        env["GATEBSD_ADBLOCK_URLS"] = (
            "https://example.invalid/hosts https://example.invalid/more"
        )
        result = self._run(
            include_style="quoted",
            extra_env=env,
            args=["--if-changed"],
            previous_blocklist=published,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertGreater(
            self._fetch_count(), before, "the new feed was never fetched"
        )

    def test_no_stamp_at_all_means_rebuild(self) -> None:
        """An upgrade from a version that never wrote one must not skip."""
        result = self._run(
            include_style="quoted", extra_env=self._env(), args=["--if-changed"]
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.stamp.is_file())
        self.assertIn(
            "creative.hpyrdr.com", self.blocklist.read_text(encoding="utf-8")
        )

    def test_a_failed_publish_leaves_no_stamp(self) -> None:
        """A stamp written ahead of the list would silence the next upgrade."""
        result = self._run(
            include_style="quoted",
            extra_env=self._env(),
            check_mode="fail_candidate",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            self.stamp.exists(),
            "a failed run claimed the published list matches these inputs",
        )


class TheUpgradeActuallyCallsIt(unittest.TestCase):
    """Run `gatebsd-upgrade` to the end and watch for the call.

    Everything before the interesting part is stubbed out: this is about the
    last few lines of the script, not about pkg.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "adblock-calls"
        self.package = self.root / "gatebsd.pkg"
        self.package.write_bytes(b"not really a package")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        path.chmod(0o755)

    def _updater(self, exit_code: int) -> Path:
        path = self.root / "gatebsd-adblock-update.sh"
        path.write_text(
            textwrap.dedent(
                f"""\
                #!/bin/sh
                printf 'args=%s lock_held=%s\\n' "$*" \\
                    "${{GATEBSD_ADBLOCK_LOCK_HELD:-unset}}" >> "$RECORD"
                exit {exit_code}
                """
            ),
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def _run_upgrade(self, updater: Path) -> subprocess.CompletedProcess[str]:
        # `gatebsd-upgrade` does a great deal before the line under test. All of
        # it is stubbed; the point is to reach the end of a successful run.
        self._write("stat", """
            #!/bin/sh
            if [ "$1" = -f ]; then
              format=$2; shift 2
              case "$format" in
                '%u') exec /usr/bin/stat -c '%u' "$@" ;;
                '%Lp') exec /usr/bin/stat -c '%a' "$@" ;;
                '%z') exec /usr/bin/stat -c '%s' "$@" ;;
                *) exit 2 ;;
              esac
            fi
            exec /usr/bin/stat "$@"
            """)
        self._write("sha256", """
            #!/bin/sh
            echo deadbeef
            """)
        # Enough of pkg(8) to walk the script from end to end: the candidate is
        # 9.9.9, what is installed is 9.9.8 until `pkg add` runs, and the
        # rollback package is produced where the script looks for it.
        self._write("pkg", """
            #!/bin/sh
            state="$FAKE_PKG_STATE"
            installed=9.9.8
            [ ! -f "$state" ] || installed=$(cat "$state")
            case "${1:-}" in
              info)
                [ "${2:-}" = -F ] || exit 0
                exit 0
                ;;
              query)
                shift
                if [ "${1:-}" = -e ]; then exit 1; fi
                if [ "${1:-}" = -F ]; then
                  file=$2; format=$3
                  version=9.9.9
                  case "$file" in *"/gatebsd-9.9.8.pkg") version=9.9.8 ;; esac
                  case "$format" in
                    '%n') echo gatebsd ;;
                    '%v') echo "$version" ;;
                    '%o') echo local/gatebsd ;;
                    '%p') echo /usr/local ;;
                    '%dn') : ;;
                    *) : ;;
                  esac
                  exit 0
                fi
                case "${1:-}" in
                  '%v') echo "$installed" ;;
                  *) : ;;
                esac
                ;;
              create)
                [ "${2:-}" = -o ] || exit 1
                : > "$3/gatebsd-${installed}.pkg"
                ;;
              add)
                echo 9.9.9 > "$state"
                ;;
              *) exit 0 ;;
            esac
            exit 0
            """)
        self._write("service", "#!/bin/sh\nexit 0\n")
        self._write("pfctl", "#!/bin/sh\nexit 1\n")
        self._write("fetch", "#!/bin/sh\nexit 0\n")
        self._write("logger", "#!/bin/sh\nexit 0\n")
        # A launcher that satisfies both the health gate's storage check and
        # the `-x` test, without importing anything.
        launcher = self.root / "python-launcher"
        launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        launcher.chmod(0o755)

        path = f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin"
        env = {
            "PATH": path,
            "GATEBSD_PATH": path,
            "HOME": str(self.root),
            "LANG": "C",
            "RECORD": str(self.calls),
            "FAKE_PKG_STATE": str(self.root / "installed-version"),
            "GATEBSD_UPGRADE_LOCK": str(self.root / "run" / "upgrade.lock"),
            "GATEBSD_UPGRADE_LOCK_HELD": "1",
            "GATEBSD_UPGRADE_CONFIG_LOCKS_HELD": "1",
            "GATEBSD_UPGRADE_BACKUP_ROOT": str(self.root / "backups"),
            "GATEBSD_PYTHON_LAUNCHER": str(launcher),
            "GATEBSD_BACKEND": str(self.root / "backend"),
            "GATEBSD_UPGRADE_PF_CONF": str(self.root / "pf.conf"),
            "GATEBSD_UPGRADE_GATEWAYCTL": str(self.bin / "service"),
            "GATEBSD_ADBLOCK_UPDATE": str(updater),
        }
        return subprocess.run(
            ["sh", str(UPGRADE), str(self.package)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def _recorded(self) -> str:
        return self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""

    @unittest.skipUnless(os.geteuid() == 0, "gatebsd-upgrade requires root")
    def test_a_completed_upgrade_converges_the_blocklist(self) -> None:
        result = self._run_upgrade(self._updater(0))
        self.assertIn(
            "passed health gate",
            result.stdout,
            f"the run never got that far: {result.stdout}\n{result.stderr}",
        )
        recorded = self._recorded()
        self.assertIn("--if-changed", recorded, "the updater was never called")
        self.assertIn(
            "lock_held=1",
            recorded,
            "called without declaring the config lock; it would hang on a lock "
            "its own parent holds",
        )

    @unittest.skipUnless(os.geteuid() == 0, "gatebsd-upgrade requires root")
    def test_a_failing_rebuild_does_not_fail_the_upgrade(self) -> None:
        """The version is healthy. Cron retries. Say so and move on."""
        result = self._run_upgrade(self._updater(1))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("passed health gate", result.stdout)
        self.assertIn("WARNING", result.stderr)
        self.assertIn("--if-changed", self._recorded())


if __name__ == "__main__":
    unittest.main()
