"""Browsers must not be able to walk away from this device's resolver.

The defect these exist for: ``use-application-dns.net`` resolved normally on the
production router (35.190.14.201), which is Firefox's documented signal that it
may switch itself to DNS-over-HTTPS. Every client that did so stopped asking
Unbound, so the 96766-domain blocklist, and every other DNS policy here, simply
did not apply to it.

Both delivery paths are covered here. A fresh device gets the directive from the
sample; a device already in the field never sees the sample -- the installer
preserves network configuration and the package only drops the sample in when
there is no ``unbound.conf`` at all -- and is served by the migration instead.

Every test runs ``sbin/gatebsd-config-migrate``; none of them reads its source.
"""
from __future__ import annotations

import fcntl
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "sbin" / "gatebsd-config-migrate"
SAMPLE = ROOT / "etc" / "unbound" / "unbound.conf.sample"
BACKEND = ROOT / "webui" / "backend"

CANARY = "use-application-dns.net"
BASE_CONF = """server:
    username: unbound
    interface: 10.88.0.1
    qname-minimisation: yes

forward-zone:
    name: "."
    forward-addr: 1.1.1.1
"""


class DnsCanarySampleTests(unittest.TestCase):
    """The fresh-install half: the sample a new device is built from."""

    def test_sample_answers_the_canary_with_nxdomain(self) -> None:
        text = SAMPLE.read_text(encoding="utf-8")
        self.assertIn(f'local-zone: "{CANARY}" always_nxdomain', text)


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class DnsCanaryMigrationTests(unittest.TestCase):
    """The in-field half: a device that already has an unbound.conf."""

    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("the migration runs as root and chowns files")
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.etc = self.root / "etc"
        self.etc.mkdir()
        self.conf = self.etc / "unbound.conf"
        self.conf.write_text(BASE_CONF, encoding="utf-8")
        self.conf.chmod(0o644)
        self.lock = Path(f"{self.conf}.gatebsd.lock")

        # `stat -f` is BSD; the container has GNU coreutils. The script only
        # asks for the owner and the permission bits.
        self._stub(
            "stat",
            """
            if [ "$1" = -f ]; then
              format=$2; shift 2
              case "$format" in
                '%u') exec /usr/bin/stat -c '%u' "$@" ;;
                '%Lp') exec /usr/bin/stat -c '%a' "$@" ;;
              esac
            fi
            exec /usr/bin/stat "$@"
            """,
        )
        self._stub("pw", "exit 1")
        self.checkconf_log = self.root / "checkconf.log"
        self.service_log = self.root / "service.log"
        self.set_checkconf(accepts=True)
        self.set_service(running=False, reload_ok=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + textwrap.dedent(body).strip() + "\n", encoding="utf-8")
        path.chmod(0o755)

    def set_checkconf(self, *, accepts: bool) -> None:
        self._stub(
            "unbound-checkconf",
            f"""
            printf '%s\\n' "$1" >> {self.checkconf_log}
            exit {0 if accepts else 1}
            """,
        )

    def set_service(self, *, running: bool, reload_ok: bool) -> None:
        self._stub(
            "service",
            f"""
            printf '%s\\n' "$*" >> {self.service_log}
            case "$2" in
              onestatus) exit {0 if running else 1} ;;
              reload|restart) exit {0 if reload_ok else 1} ;;
            esac
            exit 0
            """,
        )

    def environment(self, **overrides: str) -> dict[str, str]:
        missing = self.root / "absent"
        env = {
            "PATH": os.environ["PATH"],
            "GATEBSD_PATH": f"{self.bin}:{os.environ['PATH']}",
            "GATEBSD_UNBOUND_CONF": str(self.conf),
            "GATEBSD_PYTHON_LAUNCHER": sys.executable,
            "GATEBSD_BACKEND": str(BACKEND),
            # Keep the unrelated migrations out of the way: every one of these
            # returns immediately when its path does not exist.
            "GATEBSD_MAIN_CONF": str(missing / "gatebsd.conf"),
            "GATEBSD_FAILOVER_CONF": str(missing / "failover.conf"),
            "GATEBSD_GATEWAY_CONF": str(missing / "gateway.conf"),
            "GATEBSD_LEGACY_RU_STATE": str(missing / "ru-routes.applied"),
            "RU_STATE_FILE": str(missing / "system" / "ru-routes.applied"),
            "GATEBSD_DB_DIR": str(missing / "db"),
        }
        env.update(overrides)
        return env

    def run_migrate(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(MIGRATE)],
            env=self.environment(**overrides),
            capture_output=True,
            text=True,
            timeout=60,
        )

    def canary_lines(self) -> list[str]:
        return [
            line.strip()
            for line in self.conf.read_text(encoding="utf-8").splitlines()
            if CANARY in line and not line.strip().startswith("#")
        ]

    # -- the defect itself -------------------------------------------------

    def test_device_in_the_field_stops_answering_the_canary(self) -> None:
        result = self.run_migrate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.canary_lines(),
            [f'local-zone: "{CANARY}" always_nxdomain'],
        )
        # The forwarders and everything else the customer configured survive.
        self.assertIn("forward-addr: 1.1.1.1", self.conf.read_text(encoding="utf-8"))

    def test_running_twice_does_not_duplicate_the_directive(self) -> None:
        self.run_migrate()
        first = self.conf.read_text(encoding="utf-8")
        result = self.run_migrate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), first)
        self.assertEqual(len(self.canary_lines()), 1)

    def test_hand_written_directive_is_recognised(self) -> None:
        """Unquoted, trailing dot, indented -- all the same directive.

        The claim is that the canary step adds nothing, not that the file is
        untouched: other migrations legitimately edit the same unbound.conf,
        and asserting byte equality made this test fail for one of them while
        saying nothing about the canary.
        """
        self.conf.write_text(
            BASE_CONF + f"    local-zone: {CANARY}. always_nxdomain\n", encoding="utf-8"
        )
        before = self.conf.read_text(encoding="utf-8")
        self.run_migrate()
        after = self.conf.read_text(encoding="utf-8")
        self.assertEqual(len(self.canary_lines()), 1)
        self.assertTrue(after.startswith(before), after)

    def test_commented_out_directive_does_not_count(self) -> None:
        self.conf.write_text(
            BASE_CONF + f'#    local-zone: "{CANARY}" always_nxdomain\n', encoding="utf-8"
        )
        self.run_migrate()
        self.assertEqual(len(self.canary_lines()), 1)

    # -- refusing to break a working resolver ------------------------------

    def test_rejected_candidate_leaves_the_configuration_untouched(self) -> None:
        self.set_checkconf(accepts=False)
        before = self.conf.read_text(encoding="utf-8")
        result = self.run_migrate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), before)
        self.assertIn("rejected", result.stderr)
        # The candidate was validated, not the live file.
        checked = self.checkconf_log.read_text(encoding="utf-8").split()
        self.assertTrue(checked and checked[0] != str(self.conf), checked)

    def test_stale_temporary_files_are_not_left_behind(self) -> None:
        self.set_checkconf(accepts=False)
        self.run_migrate()
        leftovers = [entry.name for entry in self.etc.iterdir() if entry.name.startswith(".unbound.conf.")]
        self.assertEqual(leftovers, [])

    def test_resolver_that_refuses_to_reload_is_rolled_back(self) -> None:
        self.set_service(running=True, reload_ok=False)
        before = self.conf.read_text(encoding="utf-8")
        result = self.run_migrate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), before)
        self.assertIn("restoring previous configuration", result.stderr)

    def test_running_resolver_is_reloaded(self) -> None:
        self.set_service(running=True, reload_ok=True)
        self.run_migrate()
        self.assertIn("unbound reload", self.service_log.read_text(encoding="utf-8"))

    def test_stopped_resolver_is_not_started(self) -> None:
        self.set_service(running=False, reload_ok=True)
        self.run_migrate()
        actions = self.service_log.read_text(encoding="utf-8")
        self.assertNotIn("unbound reload", actions)
        self.assertNotIn("unbound restart", actions)
        self.assertEqual(len(self.canary_lines()), 1)

    def test_symlinked_configuration_is_refused(self) -> None:
        target = self.etc / "elsewhere.conf"
        target.write_text(BASE_CONF, encoding="utf-8")
        self.conf.unlink()
        self.conf.symlink_to(target)
        result = self.run_migrate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_text(encoding="utf-8"), BASE_CONF)
        self.assertIn("refusing unsafe Unbound configuration", result.stderr)

    def test_permissions_are_preserved(self) -> None:
        self.conf.chmod(0o640)
        self.run_migrate()
        self.assertEqual(self.conf.stat().st_mode & 0o777, 0o640)

    # -- the lock, which is what corrupted the blocklist once already ------

    def test_writing_waits_for_the_unbound_lock(self) -> None:
        """A second writer must not be able to interleave with this one."""
        handle = os.open(self.lock, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX)
            with subprocess.Popen(
                ["sh", str(MIGRATE)],
                env=self.environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ) as process:
                try:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        process.wait(timeout=5)
                    self.assertEqual(self.canary_lines(), [], "wrote without holding the lock")
                finally:
                    fcntl.flock(handle, fcntl.LOCK_UN)
                process.wait(timeout=30)
        finally:
            os.close(handle)
        self.assertEqual(len(self.canary_lines()), 1)

    def test_upgrade_holding_the_lock_does_not_deadlock(self) -> None:
        """gatebsd-upgrade holds every config lock for its whole run.

        Taking this lock again from inside it would hang the upgrade, which is
        the delivery mechanism itself.
        """
        handle = os.open(self.lock, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX)
            started = time.monotonic()
            result = subprocess.run(
                ["sh", str(MIGRATE)],
                env=self.environment(GATEBSD_UPGRADE_CONFIG_LOCKS_HELD="1"),
                capture_output=True,
                text=True,
                timeout=30,
            )
            elapsed = time.monotonic() - started
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            os.close(handle)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(elapsed, 20)
        self.assertEqual(len(self.canary_lines()), 1)


if __name__ == "__main__":
    unittest.main()
