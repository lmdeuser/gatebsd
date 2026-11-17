#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UPDATE_SCRIPT = ROOT / "sbin" / "gatebsd-adblock-update.sh"


class AdblockHarness(unittest.TestCase):
    """Fixtures and stubs for running the real updater. No tests of its own.

    Split out so other modules can drive the same script without inheriting
    this file's test methods and running them a second time.
    """

    HOSTS_DATA = textwrap.dedent(
        """\
        # representative hosts input
        0.0.0.0 creative.hpyrdr.com
        0.0.0.0 0.0.0.0.creative.hpyrdr.com
        127.0.0.1 tracker.example.com
        0.0.0.0 127.0.0.1.0.0.0.0.nested.example.com
        0.0.0.0 localhost
        0.0.0.0 bad..example.com
        0.0.0.0 -invalid.example.com
        """
    )
    OLD_BLOCKLIST = textwrap.dedent(
        """\
        # previous working blocklist
        server:
            local-zone: "old.example." always_nxdomain
        """
    )

    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary_directory.name)
        self.config_dir = self.root / "unbound"
        self.config_dir.mkdir()
        self.tmp_dir = self.root / "tmp"
        self.tmp_dir.mkdir()
        self.fakebin = self.root / "bin"
        self.fakebin.mkdir()

        self.unbound_conf = self.config_dir / "unbound.conf"
        self.blocklist = self.config_dir / "adblock.conf"
        self.hosts = self.root / "hosts"
        self.hosts.write_text(self.HOSTS_DATA, encoding="ascii")
        self.log_file = self.root / "gatebsd-adblock.log"
        self.service_log = self.root / "service.log"
        self.check_log = self.root / "check.log"
        self.candidate_marker = self.root / "candidate.path"
        self.status_file = self.root / "adblock-status.json"

        self._write_fake_commands()

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def _write_executable(self, name: str, content: str) -> None:
        path = self.fakebin / name
        path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
        path.chmod(0o755)

    def _write_fake_commands(self) -> None:
        self._write_executable(
            "fetch",
            """\
            #!/bin/sh
            set -eu
            output=
            url=
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    -q) shift ;;
                    -T) shift 2 ;;
                    -o) output=$2; shift 2 ;;
                    *) url=$1; shift ;;
                esac
            done
            [ -n "$output" ]
            if [ -n "${FAKE_FETCH_FAIL:-}" ]; then
                for pattern in $FAKE_FETCH_FAIL; do
                    case "$url" in *"$pattern"*) exit 1 ;; esac
                done
            fi
            cp "$FAKE_HOSTS" "$output"
            """,
        )
        self._write_executable(
            "stat",
            """\
            #!/bin/sh
            set -eu
            [ "$1" = -f ]
            case "$2" in
                %z)
                    if /usr/bin/stat -f '%z' "$3" >/dev/null 2>&1; then
                        exec /usr/bin/stat -f '%z' "$3"
                    fi
                    exec /usr/bin/stat -c %s "$3"
                    ;;
                %Lp)
                    if /usr/bin/stat -f '%Lp' "$3" >/dev/null 2>&1; then
                        exec /usr/bin/stat -f '%Lp' "$3"
                    fi
                    exec /usr/bin/stat -c %a "$3"
                    ;;
                *) exit 2 ;;
            esac
            """,
        )
        self._write_executable(
            "service",
            """\
            #!/bin/sh
            set -eu
            action=${2:-}
            printf '%s\n' "$action" >> "$FAKE_SERVICE_LOG"
            count=$(wc -l < "$FAKE_SERVICE_LOG" | tr -d '[:space:]')
            case "${FAKE_SERVICE_MODE:-success}" in
                success) exit 0 ;;
                restart_success)
                    [ "$action" = restart ] && exit 0
                    exit 1
                    ;;
                rollback_success)
                    [ "$count" -ge 3 ] && exit 0
                    exit 1
                    ;;
                always_fail) exit 1 ;;
                *) exit 2 ;;
            esac
            """,
        )
        self._write_executable(
            "unbound-checkconf",
            r'''
            #!/usr/bin/env python3
            from __future__ import annotations

            import os
            import re
            import sys
            from pathlib import Path

            path = Path(sys.argv[-1])
            text = path.read_text(encoding="utf-8")
            with Path(os.environ["FAKE_CHECK_LOG"]).open("a", encoding="utf-8") as log:
                log.write(f"{path}\n")

            # The updater validates the generated standalone blocklist first.
            if "local-zone:" in text and "include:" not in text:
                raise SystemExit(0)

            includes: list[str] = []
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if line.startswith("#") or not line.startswith("include:"):
                    continue
                value = line.split(":", 1)[1].strip()
                value = re.sub(r"\s+#.*$", "", value).strip()
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    value = value[1:-1]
                includes.append(value)

            candidates = [
                Path(value)
                for value in includes
                if Path(value).name.startswith(".adblock.conf.")
            ]
            if len(candidates) != 1:
                raise SystemExit(20)
            candidate = candidates[0]
            if candidate == Path(os.environ["FAKE_FINAL_BLOCKLIST"]):
                raise SystemExit(21)
            if not candidate.is_file():
                raise SystemExit(22)
            candidate_text = candidate.read_text(encoding="utf-8")
            # The verdict is configuration, not a constant. This used to be
            # hardcoded to always_nxdomain, so changing what a blocked name
            # answers with failed here rather than anywhere meaningful.
            verdict = os.environ.get("FAKE_EXPECT_VERDICT", "always_null")
            if f'local-zone: "creative.hpyrdr.com." {verdict}' not in candidate_text:
                raise SystemExit(23)
            Path(os.environ["FAKE_CANDIDATE_MARKER"]).write_text(
                str(candidate), encoding="utf-8"
            )
            if os.environ.get("FAKE_CHECK_MODE") == "fail_candidate":
                raise SystemExit(24)
            raise SystemExit(0)
            ''',
        )

    def _configure(self, include_style: str, *, blocklist_exists: bool = True) -> None:
        if include_style == "quoted":
            include = f'include: "{self.blocklist}"\n'
        elif include_style == "unquoted":
            include = f"include: {self.blocklist}\n"
        elif include_style == "missing":
            include = ""
        elif include_style == "duplicate":
            include = (
                f'include: "{self.blocklist}"\n'
                f"include: {self.blocklist}\n"
            )
        else:
            raise ValueError(include_style)

        self.unbound_conf.write_text(
            "server:\n    username: unbound\n" + include,
            encoding="utf-8",
        )
        self.unbound_conf.chmod(0o640)
        if blocklist_exists:
            self.blocklist.write_text(self.OLD_BLOCKLIST, encoding="utf-8")
            self.blocklist.chmod(0o644)

    def _run(
        self,
        *,
        include_style: str,
        service_mode: str = "success",
        check_mode: str = "success",
        blocklist_exists: bool = True,
        hosts_data: str | None = None,
        extra_env: dict[str, str] | None = None,
        previous_blocklist: str | None = None,
        args: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self._configure(include_style, blocklist_exists=blocklist_exists)
        # _configure republishes OLD_BLOCKLIST every run, so a test about what
        # is already on the device has to say so after it, not before.
        if previous_blocklist is not None:
            self.blocklist.write_text(previous_blocklist, encoding="utf-8")
            self.blocklist.chmod(0o644)
        if hosts_data is not None:
            self.hosts.write_text(hosts_data, encoding="ascii")
        env = os.environ.copy()
        env.update(
            {
                "GATEBSD_ADBLOCK_LOCK_HELD": "1",
                "GATEBSD_PATH": (
                    f"{self.fakebin}:{Path(sys.executable).resolve().parent}:"
                    "/usr/local/bin:/usr/bin:/bin"
                ),
                "GATEBSD_ADBLOCK_URL": "https://example.invalid/hosts",
                "GATEBSD_UNBOUND_CONF": str(self.unbound_conf),
                "GATEBSD_ADBLOCK_CONF": str(self.blocklist),
                "GATEBSD_ADBLOCK_LOG": str(self.log_file),
                "GATEBSD_ADBLOCK_MIN_DOMAINS": "1",
                "GATEBSD_ADBLOCK_MAX_BYTES": "1048576",
                "TMPDIR": str(self.tmp_dir),
                # The scratch tmpfs is off for the whole suite by default.
                # Not for speed: without this, a suite run as root on a real
                # FreeBSD machine would mount a filesystem on that machine
                # while pretending to be a unit test. The tests that care
                # about the tmpfs turn it back on for themselves.
                "GATEBSD_ADBLOCK_NO_TMPFS": "1",
                # Same reasoning as the tmpfs switch above: the production
                # default writes into /var/db/gatebsd-system, and a suite run
                # as root on a real device would leave a stamp there claiming
                # the live blocklist was built from the fixture's inputs.
                "GATEBSD_ADBLOCK_STAMP": str(self.root / "adblock-inputs"),
                # And the run record, for the same reason.
                "GATEBSD_ADBLOCK_STATUS": str(self.status_file),
                "FAKE_HOSTS": str(self.hosts),
                "FAKE_SERVICE_LOG": str(self.service_log),
                "FAKE_SERVICE_MODE": service_mode,
                "FAKE_CHECK_LOG": str(self.check_log),
                "FAKE_CHECK_MODE": check_mode,
                "FAKE_FINAL_BLOCKLIST": str(self.blocklist),
                "FAKE_CANDIDATE_MARKER": str(self.candidate_marker),
                "LC_ALL": "C",
            }
        )
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["sh", str(UPDATE_SCRIPT), *(args or [])],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def _published(self, sources: int, zones: int = 4) -> str:
        """A previously published blocklist, with the header the guard reads.

        OLD_BLOCKLIST deliberately has no `# Sources used:` line -- it stands
        for a file written before that header existed. A test about the source
        guard has to publish one that does, or it passes for the wrong reason.
        """
        return (
            "# GateBSD Ad Blocker\n"
            f"# Sources used: {sources}\n"
            "server:\n"
            + "".join(
                f'    local-zone: "host{n}.example.com." always_null\n'
                for n in range(zones)
            )
        )

    def _status(self) -> dict:
        return json.loads(self.status_file.read_text(encoding="utf-8"))

    def _assert_no_temporary_files(self) -> None:
        self.assertEqual(list(self.config_dir.glob(".adblock.conf.*")), [])
        self.assertEqual(list(self.config_dir.glob(".unbound.conf.*")), [])
        self.assertEqual(list(self.tmp_dir.glob("gatebsd-adblock.*")), [])

    def _assert_new_blocklist(self) -> None:
        text = self.blocklist.read_text(encoding="utf-8")
        self.assertIn(
            'local-zone: "creative.hpyrdr.com." always_null', text
        )
        self.assertIn('local-zone: "tracker.example.com." always_null', text)
        self.assertIn('local-zone: "nested.example.com." always_null', text)
        self.assertEqual(text.count('local-zone: "creative.hpyrdr.com."'), 1)
        self.assertNotIn('local-zone: "0.0.0.0.', text)
        self.assertNotIn('local-zone: "127.0.0.1.', text)
        self.assertNotIn("old.example", text)
        self.assertEqual(stat.S_IMODE(self.unbound_conf.stat().st_mode), 0o640)

    def _assert_candidate_was_checked(self) -> None:
        candidate = Path(self.candidate_marker.read_text(encoding="utf-8"))
        self.assertEqual(candidate.parent, self.config_dir)
        self.assertTrue(candidate.name.startswith(".adblock.conf."))
        self.assertNotEqual(candidate, self.blocklist)


class AdblockUpdateIntegrationTests(AdblockHarness):
    # ------------------------------------------------- what a blocked name answers
    def test_the_default_verdict_is_an_address_not_nxdomain(self) -> None:
        """NXDOMAIN reads as a broken resolver, and clients act on that.

        They retry, and some fall back to a resolver of their own -- so the
        verdict was pushing traffic around the blocklist that issued it.
        always_null answers 0.0.0.0 and the connection fails at once, locally.
        """
        result = self._run(include_style="quoted")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        text = self.blocklist.read_text(encoding="utf-8")
        self.assertIn("always_null", text)
        self.assertNotIn("always_nxdomain", text)
        self.assertIn("# Verdict: always_null", text)

    def test_the_verdict_is_configurable(self) -> None:
        result = self._run(
            include_style="quoted",
            extra_env={
                "GATEBSD_ADBLOCK_VERDICT": "always_nxdomain",
                "FAKE_EXPECT_VERDICT": "always_nxdomain",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        text = self.blocklist.read_text(encoding="utf-8")
        self.assertIn('local-zone: "creative.hpyrdr.com." always_nxdomain', text)
        self.assertIn("# Verdict: always_nxdomain", text)

    def test_an_unknown_verdict_is_refused_before_anything_is_downloaded(self) -> None:
        result = self._run(
            include_style="quoted",
            extra_env={"GATEBSD_ADBLOCK_VERDICT": "always_transmogrify"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.blocklist.read_text(encoding="utf-8"), self.OLD_BLOCKLIST)

    # ------------------------------------------------------------ several sources
    def test_a_dropped_source_no_longer_quietly_publishes_a_smaller_list(self) -> None:
        """A missing feed is a failed download, not a quiet day at the authors.

        On 4 August one of six sources failed, the run published 307943 domains
        instead of 384499, and the router served that all night. The domain
        shrink guard passed it: 80% is well above its 50% floor. Only the
        number of SOURCES says what actually happened.
        """
        published = self._published(sources=2)
        result = self._run(
            include_style="quoted",
            previous_blocklist=published,
            extra_env={
                "GATEBSD_ADBLOCK_URLS": (
                    "https://example.invalid/hosts https://dead.invalid/hosts"
                ),
                "FAKE_FETCH_FAIL": "dead.invalid",
            },
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("only 1 of 2 sources downloaded", result.stdout)
        self.assertEqual(self.blocklist.read_text(encoding="utf-8"), published)

    def test_the_refusal_is_recorded_where_the_blocklist_cannot_say_it(self) -> None:
        """The list left on disk is the previous run's, and it reads healthy.

        Its header still states two sources and a date. That file is exactly
        what the panel used to read, which is why a refused rebuild has to
        leave a record of its own.
        """
        published = self._published(sources=2)
        self._run(
            include_style="quoted",
            previous_blocklist=published,
            extra_env={
                "GATEBSD_ADBLOCK_URLS": (
                    "https://example.invalid/hosts https://dead.invalid/hosts"
                ),
                "FAKE_FETCH_FAIL": "dead.invalid",
            },
        )
        self.assertIn("# Sources used: 2", self.blocklist.read_text(encoding="utf-8"))
        status = self._status()
        self.assertEqual(status["outcome"], "failed")
        self.assertEqual(status["sources_configured"], 2)
        self.assertEqual(status["sources_used"], 1)
        self.assertIn("https://dead.invalid/hosts", status["sources_skipped"])

    def test_a_dead_source_still_publishes_when_nothing_is_published_yet(self) -> None:
        """On a freshly flashed device a partial list beats no filtering."""
        result = self._run(
            include_style="quoted",
            blocklist_exists=False,
            extra_env={
                "GATEBSD_ADBLOCK_URLS": (
                    "https://example.invalid/hosts https://dead.invalid/hosts"
                ),
                "FAKE_FETCH_FAIL": "dead.invalid",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self._assert_new_blocklist()
        self.assertIn("skipping source", result.stdout)
        self.assertEqual(self._status()["sources_used"], 1)

    def test_retiring_a_source_is_not_the_same_as_losing_one(self) -> None:
        """Taking a dead feed out of the configuration must still publish.

        Otherwise the only cure for a permanently dead source would be a fight
        with this guard, and the list would stay frozen -- including the names
        we add to adblock-extra ourselves.
        """
        result = self._run(
            include_style="quoted",
            previous_blocklist=self._published(sources=2),
            extra_env={"GATEBSD_ADBLOCK_URLS": "https://example.invalid/hosts"},
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self._assert_new_blocklist()
        self.assertIn("# Sources used: 1", self.blocklist.read_text(encoding="utf-8"))

    def test_a_newly_added_source_that_fails_does_not_freeze_the_list(self) -> None:
        """The bar is what is live, not what is configured.

        Hagezi Pro was added to a list of five. Had it failed on its first
        night, a guard counting the configured six would have refused every
        rebuild from then on -- the list frozen at five sources by the very
        change meant to grow it. Five was what was published; five still is.
        """
        result = self._run(
            include_style="quoted",
            previous_blocklist=self._published(sources=1),
            extra_env={
                "GATEBSD_ADBLOCK_URLS": (
                    "https://example.invalid/hosts https://dead.invalid/hosts"
                ),
                "FAKE_FETCH_FAIL": "dead.invalid",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("# Sources used: 1", self.blocklist.read_text(encoding="utf-8"))

    def test_a_list_published_before_the_header_existed_does_not_block_the_update(self) -> None:
        """No header, nothing to compare against: publish once, guard after.

        The next run has a header of its own and the guard engages by itself.
        Pinned so the degradation stays a documented one run, not forever.
        """
        result = self._run(
            include_style="quoted",
            previous_blocklist=self.OLD_BLOCKLIST,
            extra_env={
                "GATEBSD_ADBLOCK_URLS": (
                    "https://example.invalid/hosts https://dead.invalid/hosts"
                ),
                "FAKE_FETCH_FAIL": "dead.invalid",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("# Sources used: 1", self.blocklist.read_text(encoding="utf-8"))

    def test_every_source_failing_preserves_the_published_list(self) -> None:
        result = self._run(
            include_style="quoted",
            extra_env={
                "GATEBSD_ADBLOCK_URLS": "https://dead.invalid/hosts",
                "FAKE_FETCH_FAIL": "dead.invalid",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.blocklist.read_text(encoding="utf-8"), self.OLD_BLOCKLIST)

    # ------------------------------------------------------------- shrink guard
    def test_a_list_that_collapsed_does_not_replace_a_healthy_one(self) -> None:
        """A source can answer 200 with a truncated body and pass every check.

        Size and syntax are both fine; only the comparison with what is already
        published notices that the filter just lost most of its domains.
        """
        published = "server:\n" + "".join(
            f'    local-zone: "host{n}.example.com." always_null\n' for n in range(100)
        )
        result = self._run(
            include_style="quoted",
            hosts_data="0.0.0.0 creative.hpyrdr.com\n",
            previous_blocklist=published,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("refusing to replace", result.stdout)
        self.assertEqual(self.blocklist.read_text(encoding="utf-8"), published)

    def test_growth_is_never_blocked_by_the_shrink_guard(self) -> None:
        published = 'server:\n    local-zone: "one.example.com." always_null\n'
        big = "0.0.0.0 creative.hpyrdr.com\n" + "".join(
            f"0.0.0.0 host{n}.example.com\n" for n in range(50)
        )
        result = self._run(
            include_style="quoted", hosts_data=big, previous_blocklist=published
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("host49.example.com", self.blocklist.read_text(encoding="utf-8"))

    def test_quoted_include_validates_candidate_and_publishes(self) -> None:
        result = self._run(include_style="quoted")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self._assert_new_blocklist()
        self._assert_candidate_was_checked()
        self.assertIn(f'include: "{self.blocklist}"', self.unbound_conf.read_text())
        self.assertEqual(self.service_log.read_text().splitlines(), ["reload"])
        self._assert_no_temporary_files()

    def test_unquoted_include_validates_candidate_and_publishes(self) -> None:
        result = self._run(include_style="unquoted")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self._assert_new_blocklist()
        self._assert_candidate_was_checked()
        self.assertIn(f"include: {self.blocklist}", self.unbound_conf.read_text())
        self.assertEqual(self.service_log.read_text().splitlines(), ["reload"])
        self._assert_no_temporary_files()

    def test_missing_include_is_added_and_validated(self) -> None:
        result = self._run(include_style="missing", blocklist_exists=False)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self._assert_new_blocklist()
        self._assert_candidate_was_checked()
        self.assertIn(f'include: "{self.blocklist}"', self.unbound_conf.read_text())
        self._assert_no_temporary_files()

    def test_candidate_validation_failure_preserves_previous_files(self) -> None:
        result = self._run(include_style="unquoted", check_mode="fail_candidate")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.blocklist.read_text(), self.OLD_BLOCKLIST)
        self.assertIn(f"include: {self.blocklist}", self.unbound_conf.read_text())
        self.assertFalse(self.service_log.exists())
        self._assert_candidate_was_checked()
        self._assert_no_temporary_files()

    def test_reload_failure_with_successful_restart_keeps_new_files(self) -> None:
        result = self._run(include_style="quoted", service_mode="restart_success")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self._assert_new_blocklist()
        self.assertEqual(
            self.service_log.read_text().splitlines(), ["reload", "restart"]
        )
        self._assert_no_temporary_files()

    def test_reload_and_restart_failure_rolls_back_exact_previous_files(self) -> None:
        self._configure("unquoted")
        old_conf = self.unbound_conf.read_bytes()
        old_blocklist = self.blocklist.read_bytes()
        result = self._run(
            include_style="unquoted", service_mode="rollback_success"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.unbound_conf.read_bytes(), old_conf)
        self.assertEqual(self.blocklist.read_bytes(), old_blocklist)
        self.assertEqual(
            self.service_log.read_text().splitlines(),
            ["reload", "restart", "reload"],
        )
        self.assertIn("previous configuration restored", result.stdout)
        self._assert_no_temporary_files()

    def test_failed_first_activation_restores_absent_blocklist(self) -> None:
        self._configure("missing", blocklist_exists=False)
        old_conf = self.unbound_conf.read_bytes()
        result = self._run(
            include_style="missing",
            blocklist_exists=False,
            service_mode="rollback_success",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.unbound_conf.read_bytes(), old_conf)
        self.assertFalse(self.blocklist.exists())
        self.assertEqual(
            self.service_log.read_text().splitlines(),
            ["reload", "restart", "reload"],
        )
        self.assertIn("previous configuration restored", result.stdout)
        self._assert_no_temporary_files()

    def test_duplicate_matching_includes_are_rejected_without_publication(self) -> None:
        result = self._run(include_style="duplicate")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.blocklist.read_text(), self.OLD_BLOCKLIST)
        self.assertIn("unambiguous candidate", result.stdout)
        self.assertFalse(self.service_log.exists())
        self._assert_no_temporary_files()

    def test_too_small_parsed_list_preserves_previous_files(self) -> None:
        result = self._run(
            include_style="quoted",
            hosts_data="0.0.0.0 localhost\n0.0.0.0 bad..example\n",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.blocklist.read_text(), self.OLD_BLOCKLIST)
        self.assertFalse(self.service_log.exists())
        self._assert_no_temporary_files()

    # ------------------------------------------------- scratch space in RAM

    def test_an_unmountable_scratch_does_not_stop_the_update(self) -> None:
        """The tmpfs is an optimisation and must never become a failure mode.

        It saves writes, nothing else -- the run is CPU-bound. So every way it
        can fail (no tmpfs support, no memory, a directory that cannot be
        created, not running as root) has to end in an ordinary run on disk,
        not in a device whose blocklist quietly stopped updating.

        The path below cannot be created on any of the machines this suite
        runs on, so the mount is attempted and fails for real. Asserting on
        the log line rather than only on the exit code is deliberate: a run
        that fell back silently and a run that used the tmpfs both exit 0, and
        those are not the same thing to anyone reading the log later.
        """
        result = self._run(
            include_style="quoted",
            extra_env={
                "GATEBSD_ADBLOCK_NO_TMPFS": "",
                "GATEBSD_ADBLOCK_TMPFS": "/proc/self/mem/cannot/be/a/directory",
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Scratch on disk", result.stdout)
        self.assertNotIn("Scratch in RAM", result.stdout)
        self._assert_new_blocklist()
        self._assert_no_temporary_files()


class TheRunRecordTests(AdblockHarness):
    """The record the panel reads. The blocklist itself cannot answer any of
    these questions, because a run that publishes nothing does not touch it."""

    def test_a_successful_run_records_what_it_published(self) -> None:
        result = self._run(include_style="quoted")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        status = self._status()
        self.assertEqual(status["outcome"], "published")
        self.assertEqual(status["sources_configured"], 1)
        self.assertEqual(status["sources_used"], 1)
        self.assertEqual(status["sources_skipped"], "")
        self.assertEqual(status["domains"], 3)
        self.assertGreater(status["checked_at"], 0)

    def test_per_source_download_and_parse_counts_are_recorded(self) -> None:
        result = self._run(include_style="quoted")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        status = self._status()
        self.assertEqual(status["last_success_at"], status["checked_at"])
        self.assertEqual(len(status["sources"]), 1)
        source = status["sources"][0]
        self.assertEqual(source["url"], "https://example.invalid/hosts")
        self.assertEqual(source["downloaded"], len(self.HOSTS_DATA.splitlines()))
        self.assertEqual(source["parsed"], 4)
        self.assertEqual(source["status"], "ok")

    def test_a_failed_run_preserves_the_last_success_and_names_rejected_source(self) -> None:
        self._run(include_style="quoted")
        first = self._status()
        result = self._run(
            include_style="quoted",
            previous_blocklist=self._published(sources=2),
            extra_env={
                "GATEBSD_ADBLOCK_URLS": "https://example.invalid/hosts https://dead.invalid/hosts",
                "FAKE_FETCH_FAIL": "dead.invalid",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        status = self._status()
        self.assertEqual(status["last_success_at"], first["last_success_at"])
        rejected = next(source for source in status["sources"] if source["url"] == "https://dead.invalid/hosts")
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["downloaded"], 0)
        self.assertEqual(rejected["parsed"], 0)
        self.assertEqual(rejected["reason"], "download_failed")

    def test_a_failure_before_any_download_reports_unknown_not_zero(self) -> None:
        """`sources_used: 0` would read as "every feed is down".

        Nothing was fetched here at all -- the verdict is refused before the
        first request. Same rule as the watchdog refusing to report an unknown
        handshake age as 0: null says "not measured", 0 says something false.
        """
        result = self._run(
            include_style="quoted",
            extra_env={"GATEBSD_ADBLOCK_VERDICT": "always_transmogrify"},
        )
        self.assertNotEqual(result.returncode, 0)
        status = self._status()
        self.assertEqual(status["outcome"], "failed")
        self.assertIsNone(status["sources_used"])
        self.assertIsNone(status["domains"])

    def test_a_reason_with_quotes_still_parses_as_json(self) -> None:
        """The reason is a message, and messages carry whatever they carry.

        An unescaped quote here would not merely garble one field: the whole
        record stops being JSON, and the panel loses the warning at exactly
        the moment it has something to say.
        """
        result = self._run(
            include_style="quoted",
            extra_env={"GATEBSD_ADBLOCK_VERDICT": 'always_"quoted"\\broken'},
        )
        self.assertNotEqual(result.returncode, 0)
        status = self._status()
        self.assertEqual(status["outcome"], "failed")
        self.assertIn('always_"quoted"\\broken', status["reason"])

    def test_the_record_is_replaced_whole_or_not_at_all(self) -> None:
        published = self._published(sources=2)
        self._run(include_style="quoted")
        first = self._status()
        self._run(
            include_style="quoted",
            previous_blocklist=published,
            extra_env={
                "GATEBSD_ADBLOCK_URLS": (
                    "https://example.invalid/hosts https://dead.invalid/hosts"
                ),
                "FAKE_FETCH_FAIL": "dead.invalid",
            },
        )
        second = self._status()
        self.assertEqual(first["outcome"], "published")
        self.assertEqual(second["outcome"], "failed")
        self.assertEqual(list(self.root.glob(".adblock-status.*")), [])

    def test_an_unwritable_record_does_not_fail_the_update(self) -> None:
        """A record we cannot write must not take down what it describes."""
        result = self._run(
            include_style="quoted",
            extra_env={
                "GATEBSD_ADBLOCK_STATUS": "/proc/self/mem/nowhere/adblock-status.json",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self._assert_new_blocklist()


if __name__ == "__main__":
    unittest.main()
