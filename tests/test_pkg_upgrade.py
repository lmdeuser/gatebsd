"""Regression tests for the system package-upgrade guarantees.

``/api/system/updates/install`` used to run ``pkg upgrade -y`` with no package
snapshot, no configuration backup, no free-space check, no health gate and no
rollback -- on the machine that is the site's only internet uplink, with no
out-of-band access. A single bad upgrade of mpd5, unbound or the AmneziaWG
kernel module took the site offline with nothing to revert to.

The guarantees asserted here:

* preflight refuses to start when the root filesystem cannot hold the
  transaction;
* the configuration tree is snapshotted first;
* a ZFS boot environment is created, and the upgrade is refused outright if one
  cannot be;
* a post-upgrade health gate restarts what pkg(8) replaced and then verifies it;
* the install window is serialised against the watchdog's route transactions,
  while the download is not, so WAN failover is never denied for the length of a
  383 MiB download;
* a failed health gate reports the boot environment to activate and does *not*
  reboot the router by itself.

Behaviour that could not be asserted from the laptop was verified on the FreeBSD
15.1 stand: ``bectl check`` exit status, ``bectl create``/``list -H`` output, the
``"383 MiB to be downloaded."`` line format, and that FreeBSD ``lockf(1)`` and
Python ``flock`` contend for the same lock.
"""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gatebsd_ui.command import CommandResult
from gatebsd_ui.writers import system


def result(ok: bool = True, stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult(
        command=["stub"],
        ok=ok,
        returncode=0 if ok else 1,
        stdout=stdout,
        stderr=stderr,
        error=None,
    )


PLAN_OUTPUT = """Checking for upgrades (197 candidates): done
Installed packages to be UPGRADED:
\tFreeBSD-audit: 15.1 -> 15.1p2 [FreeBSD-base]

Number of packages to be upgraded: 54

383 MiB to be downloaded.
"""

NOTHING_TO_DO = """Checking integrity... done (0 conflicting)
Your packages are up to date.
"""


class DownloadSizeParsingTests(unittest.TestCase):
    """Verified against real `pkg upgrade -n -U` output on FreeBSD 15.1."""

    def test_mebibyte_plan_is_parsed(self) -> None:
        self.assertEqual(system._download_bytes(PLAN_OUTPUT), 383 * 1024**2)

    def test_plan_with_nothing_to_download_is_zero(self) -> None:
        self.assertEqual(system._download_bytes(NOTHING_TO_DO), 0)

    def test_every_unit_pkg_emits_is_understood(self) -> None:
        for text, expected in (
            ("512 B to be downloaded.", 512),
            ("64 KiB to be downloaded.", 64 * 1024),
            ("1.5 GiB to be downloaded.", int(1.5 * 1024**3)),
        ):
            with self.subTest(text=text):
                self.assertEqual(system._download_bytes(text), expected)

    def test_unparseable_size_does_not_raise(self) -> None:
        self.assertEqual(system._download_bytes("?? MiB to be downloaded."), 0)


class DiskPreflightTests(unittest.TestCase):
    def test_insufficient_space_is_refused(self) -> None:
        # 383 MiB download plus the 2 GiB headroom against 100 MiB free.
        with mock.patch.object(system, "_free_bytes", return_value=100 * 1024**2):
            error = system._disk_preflight(PLAN_OUTPUT)
        self.assertIsNotNone(error)
        self.assertIn("insufficient free space", error or "")

    def test_ample_space_passes(self) -> None:
        with mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3):
            self.assertIsNone(system._disk_preflight(PLAN_OUTPUT))

    def test_headroom_is_required_even_with_no_download(self) -> None:
        with mock.patch.object(system, "_free_bytes", return_value=64 * 1024**2):
            self.assertIsNotNone(system._disk_preflight(NOTHING_TO_DO))

    def test_unreadable_filesystem_does_not_block_the_upgrade(self) -> None:
        with mock.patch.object(system, "_free_bytes", return_value=None):
            self.assertIsNone(system._disk_preflight(PLAN_OUTPUT))


class BootEnvironmentTests(unittest.TestCase):
    def setUp(self) -> None:
        # Creation is logged and recorded in the state file; redirect both.
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self._patches = [
            mock.patch.object(system, "_UPDATE_LOG", root / "upgrade.log"),
            mock.patch.object(system, "_UPDATE_STATE", root / "state.json"),
        ]
        for patch in self._patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self._patches):
            patch.stop()
        self._tmp.cleanup()

    def test_created_environment_must_appear_in_the_listing(self) -> None:
        created: dict[str, str] = {}

        def fake_run(command: list[str], **_kwargs: object) -> CommandResult:
            if command[:2] == ["bectl", "create"]:
                created["name"] = command[2]
                return result(True)
            if command[:2] == ["bectl", "list"]:
                return result(True, stdout=f"default\tNR\t/\t8.06G\t2026-07-13 21:38\n"
                                          f"{created['name']}\t-\t-\t8K\t2026-07-30 04:01")
            return result(True)

        with mock.patch.object(system, "run", side_effect=fake_run):
            name, error = system._create_boot_environment()
        self.assertIsNone(error)
        self.assertTrue((name or "").startswith("gatebsd-preupgrade-"))

    def test_a_silent_creation_failure_is_detected(self) -> None:
        # `bectl create` exiting 0 without producing an environment must not be
        # mistaken for a usable rollback point.
        def fake_run(command: list[str], **_kwargs: object) -> CommandResult:
            if command[:2] == ["bectl", "list"]:
                return result(True, stdout="default\tNR\t/\t8.06G\t2026-07-13 21:38")
            return result(True)

        with mock.patch.object(system, "run", side_effect=fake_run):
            name, error = system._create_boot_environment()
        self.assertIsNone(name)
        self.assertIn("was not created", error or "")

    def test_creation_error_is_reported_with_detail(self) -> None:
        def fake_run(command: list[str], **_kwargs: object) -> CommandResult:
            if command[:2] == ["bectl", "create"]:
                return result(False, stderr="dataset busy")
            return result(True)

        with mock.patch.object(system, "run", side_effect=fake_run):
            name, error = system._create_boot_environment()
        self.assertIsNone(name)
        self.assertIn("dataset busy", error or "")

    def test_generated_name_is_a_safe_bectl_operand(self) -> None:
        with mock.patch.object(system, "run", return_value=result(True, stdout="")):
            system._create_boot_environment()
        # The name is generated from a UTC timestamp; assert the pattern that
        # gates it rather than the clock.
        self.assertIsNotNone(
            system._BE_NAME_RE.fullmatch(system._BE_NAME_PREFIX + "20260730-040100")
        )
        for unsafe in ("name with space", "name;rm -rf /", "-leading-dash", ""):
            with self.subTest(name=unsafe):
                self.assertIsNone(system._BE_NAME_RE.fullmatch(unsafe))


class PostUpgradeHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        # The health gate logs its restarts; keep that out of /var/log.
        self._tmp = tempfile.TemporaryDirectory()
        self._patch = mock.patch.object(
            system, "_UPDATE_LOG", Path(self._tmp.name) / "upgrade.log"
        )
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_services_stopped_by_the_upgrade_are_restarted_before_judging(self) -> None:
        # pkg(8) does not restart what it replaces, so an unstarted unbound is
        # expected rather than a failure.
        calls: list[list[str]] = []

        def fake_run(command: list[str], **_kwargs: object) -> CommandResult:
            calls.append(command)
            if command[:1] == ["service"] and command[2] == "onestatus":
                return result(command[1] != "unbound")
            return result(True)

        with mock.patch.object(system, "run", side_effect=fake_run):
            failures = system._post_upgrade_health()
        self.assertEqual(failures, [])
        self.assertIn(["service", "unbound", "restart"], calls)

    def test_a_service_that_cannot_be_restarted_is_a_failure(self) -> None:
        def fake_run(command: list[str], **_kwargs: object) -> CommandResult:
            if command[:1] == ["service"] and command[1] == "mpd5":
                return result(False)
            return result(True)

        with mock.patch.object(system, "run", side_effect=fake_run):
            failures = system._post_upgrade_health()
        self.assertIn("mpd5", failures)

    def test_a_service_the_guard_condemned_is_not_restarted_into_its_config(self) -> None:
        """Reporting a failure is not the same as acting on it.

        The guard parses without loading and says unbound cannot start from its
        file. Restarting it anyway is a corruption from days ago turning into an
        outage at upgrade time -- the sequence the guard exists to break, and
        the customer would read it as "the update broke DNS".
        """
        calls: list[list[str]] = []

        def fake_run(command: list[str], **_kwargs: object) -> CommandResult:
            calls.append(command)
            if command == [str(system._CONFIG_GUARD)]:
                return CommandResult(
                    command=command,
                    ok=False,
                    returncode=2,
                    stdout=(
                        "CRITICAL: /usr/local/etc/unbound/unbound.conf does not validate\n"
                        "UNSTARTABLE: unbound\n"
                    ),
                    stderr="",
                    error=None,
                )
            if command[:1] == ["service"] and command[2] == "onestatus":
                return result(False)
            return result(True)

        with mock.patch.object(system, "run", side_effect=fake_run):
            failures = system._post_upgrade_health()

        self.assertNotIn(["service", "unbound", "restart"], calls)
        self.assertNotIn(["service", "unbound", "start"], calls)
        self.assertIn("unbound", failures)
        self.assertIn("configuration", failures)
        # Holding back the condemned service must not hold back the rest: the
        # box would be down for a reason unrelated to the broken file.
        self.assertIn(["service", "nginx", "restart"], calls)

    def test_a_guard_that_names_nothing_holds_nothing_back(self) -> None:
        """A parser that stops matching must not silently stop every restart."""
        calls: list[list[str]] = []

        def fake_run(command: list[str], **_kwargs: object) -> CommandResult:
            calls.append(command)
            if command == [str(system._CONFIG_GUARD)]:
                return CommandResult(
                    command=command, ok=False, returncode=2,
                    stdout="something went wrong\n", stderr="", error=None,
                )
            if command[:1] == ["service"] and command[2] == "onestatus":
                return result(False)
            return result(True)

        with mock.patch.object(system, "run", side_effect=fake_run):
            failures = system._post_upgrade_health()

        self.assertIn(["service", "unbound", "restart"], calls)
        self.assertIn("configuration", failures)

    def test_a_broken_pf_ruleset_is_a_failure(self) -> None:
        def fake_run(command: list[str], **_kwargs: object) -> CommandResult:
            if command[:2] == ["pfctl", "-nf"]:
                return result(False)
            return result(True)

        with mock.patch.object(system, "run", side_effect=fake_run):
            self.assertIn("pf ruleset", system._post_upgrade_health())

    def test_a_missing_default_route_is_a_failure(self) -> None:
        def fake_run(command: list[str], **_kwargs: object) -> CommandResult:
            if command[:2] == ["route", "-n"]:
                return result(False)
            return result(True)

        with mock.patch.object(system, "run", side_effect=fake_run):
            self.assertIn("default route", system._post_upgrade_health())

    def test_pf_is_not_checked_when_it_is_not_enabled(self) -> None:
        def fake_run(command: list[str], **_kwargs: object) -> CommandResult:
            if command[:2] == ["pfctl", "-s"]:
                return result(False)
            if command[:2] == ["pfctl", "-nf"]:
                raise AssertionError("must not validate a ruleset while pf is disabled")
            return result(True)

        with mock.patch.object(system, "run", side_effect=fake_run):
            self.assertEqual(system._post_upgrade_health(), [])


class UpgradeSequenceTests(unittest.TestCase):
    """Drives the whole upgrade with pkg, bectl and service stubbed."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.gateway_lock = root / "gatewayctl.lock"
        self._patches = [
            mock.patch.object(system, "_UPDATE_LOG", root / "upgrade.log"),
            mock.patch.object(system, "_UPDATE_STATE", root / "state.json"),
            mock.patch.object(system, "_UPDATE_LOCK", root / "pkg-update.lock"),
            mock.patch.object(system, "_GATEWAY_LOCK", self.gateway_lock),
            mock.patch.object(system, "_read_required_packages", return_value=["nginx"]),
            mock.patch.object(system, "_missing_packages", return_value=[]),
        ]
        for patch in self._patches:
            patch.start()
        self.commands: list[list[str]] = []
        self.backup_calls: list[str] = []

    def tearDown(self) -> None:
        for patch in reversed(self._patches):
            patch.stop()
        self._tmp.cleanup()

    def fake_run(
        self,
        *,
        bectl_supported: bool = True,
        bectl_create_ok: bool = True,
        upgrade_ok: bool = True,
        healthy: bool = True,
    ):
        def runner(command: list[str], **_kwargs: object) -> CommandResult:
            self.commands.append(command)
            if command[:2] == ["bectl", "check"]:
                return result(bectl_supported)
            if command[:2] == ["bectl", "create"]:
                return result(bectl_create_ok)
            if command[:2] == ["bectl", "list"]:
                if not bectl_create_ok:
                    return result(True, stdout="default\tNR\t/\t8G\t2026")
                name = next(c[2] for c in self.commands if c[:2] == ["bectl", "create"])
                return result(True, stdout=f"{name}\t-\t-\t8K\t2026")
            if command[:3] == ["pkg", "upgrade", "-n"]:
                return result(True, stdout=PLAN_OUTPUT)
            if command[:2] == ["pkg", "upgrade"]:
                return result(upgrade_ok)
            if command[:1] == ["service"] and command[2] == "onestatus":
                # `healthy` describes the state *after* the upgrade. Before it,
                # every service is up -- otherwise the health gate has nothing
                # to judge, since it only judges what was running beforehand.
                if not any(c[:3] == ["pkg", "upgrade", "-y"] and "-F" not in c for c in self.commands):
                    return result(True)
                return result(healthy)
            if command[:1] == ["service"]:
                return result(healthy)
            return result(True)

        return runner

    def patched_backup(self, *, fails: bool = False):
        from gatebsd_ui import backup as backup_module

        def snapshot(reason: str) -> dict[str, str]:
            self.backup_calls.append(reason)
            if fails:
                raise OSError("backup volume is read-only")
            return {"dir": "/var/backups/gatebsd/stub"}

        return mock.patch.object(backup_module, "backup_known_configs", side_effect=snapshot)

    def test_successful_upgrade_snapshots_config_and_boot_environment(self) -> None:
        with mock.patch.object(system, "run", side_effect=self.fake_run()), self.patched_backup():
            with mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3):
                status, payload = system.pkg_upgrade()
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["boot_environment"].startswith("gatebsd-preupgrade-"))
        self.assertEqual(self.backup_calls, ["pkg-upgrade"])

    def test_pkg_self_upgrade_refreshes_schema_and_resumes_the_transaction(self) -> None:
        """pkg 2.8.4 exited zero after upgrading only itself on the router."""
        installs = 0

        def runner(command: list[str], **kwargs: object) -> CommandResult:
            nonlocal installs
            if command == ["pkg", "upgrade", "-y", "-U"]:
                installs += 1
                self.commands.append(command)
                if installs == 1:
                    return result(
                        True,
                        stderr=(
                            "pkg: need to re-create repo gatebsd-releases to upgrade schema version\n"
                            "pkg: Repository gatebsd-releases cannot be opened. 'pkg update' required\n"
                        ),
                    )
                return result(True)
            return self.fake_run()(command, **kwargs)

        with (
            mock.patch.object(system, "run", side_effect=runner),
            self.patched_backup(),
            mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
        ):
            status, payload = system.pkg_upgrade()

        self.assertEqual(status, 200, payload)
        self.assertEqual(installs, 2)
        first = self.commands.index(["pkg", "upgrade", "-y", "-U"])
        self.assertEqual(self.commands[first + 1], ["pkg", "update"])
        self.assertEqual(self.commands[first + 2], ["pkg", "upgrade", "-y", "-U"])

    def test_the_config_snapshot_precedes_the_upgrade(self) -> None:
        order: list[str] = []

        def runner(command: list[str], **kwargs: object) -> CommandResult:
            if command[:2] == ["pkg", "upgrade"] and "-n" not in command:
                order.append("upgrade")
            return self.fake_run()(command, **kwargs)

        from gatebsd_ui import backup as backup_module

        with (
            mock.patch.object(system, "run", side_effect=runner),
            mock.patch.object(
                backup_module,
                "backup_known_configs",
                side_effect=lambda reason: (order.append("backup") or {"dir": "/stub"}),
            ),
            mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
        ):
            system.pkg_upgrade()
        self.assertEqual(order[0], "backup", order)

    def test_missing_boot_environment_support_refuses_the_upgrade(self) -> None:
        with (
            mock.patch.object(system, "run", side_effect=self.fake_run(bectl_supported=False)),
            self.patched_backup(),
            mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
        ):
            status, payload = system.pkg_upgrade()
        self.assertEqual(status, 500)
        self.assertIn("could not be rolled back", payload["error"])
        # Nothing may have been installed.
        self.assertNotIn(["pkg", "upgrade", "-y", "-U"], self.commands)

    def test_failed_boot_environment_creation_refuses_the_upgrade(self) -> None:
        with (
            mock.patch.object(system, "run", side_effect=self.fake_run(bectl_create_ok=False)),
            self.patched_backup(),
            mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
        ):
            status, payload = system.pkg_upgrade()
        self.assertEqual(status, 500)
        self.assertNotIn(["pkg", "upgrade", "-y", "-U"], self.commands)

    def test_insufficient_disk_space_refuses_before_any_snapshot(self) -> None:
        with (
            mock.patch.object(system, "run", side_effect=self.fake_run()),
            self.patched_backup(),
            mock.patch.object(system, "_free_bytes", return_value=10 * 1024**2),
        ):
            status, payload = system.pkg_upgrade()
        self.assertEqual(status, 500)
        self.assertIn("insufficient free space", payload["error"])
        self.assertEqual(self.backup_calls, [])
        self.assertNotIn(["bectl", "create"], [c[:2] for c in self.commands])

    def test_failed_health_gate_reports_the_rollback_without_rebooting(self) -> None:
        with (
            mock.patch.object(system, "run", side_effect=self.fake_run(healthy=False)),
            self.patched_backup(),
            mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
        ):
            status, payload = system.pkg_upgrade()
        self.assertEqual(status, 500)
        self.assertIn("health check failed", payload["error"])
        self.assertIn("bectl activate", payload["rollback_command"])
        self.assertTrue(payload["reboot_required"])
        # The router is the site's only uplink: rebooting it is an operator
        # decision, never an automatic consequence of a failed upgrade.
        for command in self.commands:
            self.assertNotIn(command[:1], (["reboot"], ["shutdown"]))

    def test_install_window_is_serialised_against_route_transactions(self) -> None:
        # Hold the gateway lock the way gatewayctl and the watchdog do; the
        # upgrade must refuse rather than interleave with a route transaction.
        self.gateway_lock.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.gateway_lock, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with (
                mock.patch.object(system, "run", side_effect=self.fake_run()),
                self.patched_backup(),
                mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
            ):
                status, payload = system.pkg_upgrade()
        finally:
            os.close(fd)
        self.assertEqual(status, 500)
        self.assertIn("routing transaction", payload["error"])
        self.assertNotIn(["pkg", "upgrade", "-y", "-U"], self.commands)

    def test_download_happens_without_holding_the_routing_lock(self) -> None:
        """Failover must not be denied for the length of a 383 MiB download."""
        held_during_fetch: list[bool] = []

        def runner(command: list[str], **kwargs: object) -> CommandResult:
            if command[:2] == ["pkg", "upgrade"] and "-F" in command:
                probe = os.open(self.gateway_lock, os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(probe, fcntl.LOCK_UN)
                    held_during_fetch.append(False)
                except BlockingIOError:
                    held_during_fetch.append(True)
                finally:
                    os.close(probe)
            return self.fake_run()(command, **kwargs)

        with (
            mock.patch.object(system, "run", side_effect=runner),
            self.patched_backup(),
            mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
        ):
            system.pkg_upgrade()
        self.assertEqual(held_during_fetch, [False], "the fetch must not hold the routing lock")

    def test_a_second_concurrent_upgrade_is_rejected(self) -> None:
        lock_path = system._UPDATE_LOCK
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with mock.patch.object(system, "run", side_effect=self.fake_run()):
                status, payload = system.pkg_upgrade()
        finally:
            os.close(fd)
        self.assertEqual(status, 409)
        self.assertIn("already running", payload["error"])

    def test_state_file_records_the_rollback_target(self) -> None:
        with (
            mock.patch.object(system, "run", side_effect=self.fake_run(healthy=False)),
            self.patched_backup(),
            mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
        ):
            system.pkg_upgrade()
        state = json.loads(system._UPDATE_STATE.read_text(encoding="utf-8"))
        self.assertEqual(state["phase"], "unhealthy")
        self.assertTrue(str(state["boot_environment"]).startswith("gatebsd-preupgrade-"))

    def test_the_failover_watchdog_is_restarted_after_the_upgrade(self) -> None:
        """The package stops gatebsd_failover and never starts it again.

        ``ci/build.sh`` gives the package a pre-deinstall that runs
        ``service gatebsd_failover stop`` alongside ``service gatebsd stop``,
        and the post-install script starts neither. When the health gate did not
        cover gatebsd_failover the endpoint returned 200 while automatic WAN
        failover stayed off on the site's only uplink until the five-minute
        healthcheck cron happened to notice.
        """
        stopped = {"gatebsd", "gatebsd_failover"}

        def runner(command: list[str], **kwargs: object) -> CommandResult:
            if command[:1] == ["service"] and command[2] == "onestatus":
                # Up beforehand; stopped by the package's pre-deinstall.
                if command[1] in stopped and ["pkg", "upgrade", "-y", "-U"] in self.commands:
                    self.commands.append(command)
                    return result(False)
            if command[:1] == ["service"] and command[2] in {"restart", "start"}:
                stopped.discard(command[1])
            return self.fake_run()(command, **kwargs)

        with (
            mock.patch.object(system, "run", side_effect=runner),
            self.patched_backup(),
            mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
        ):
            status, payload = system.pkg_upgrade()

        self.assertEqual(status, 200, payload)
        restarted = {c[1] for c in self.commands if c[:1] == ["service"] and c[2] in {"restart", "start"}}
        self.assertIn("gatebsd_failover", restarted)
        self.assertIn("gatebsd", restarted)

    def test_a_service_that_was_already_down_is_not_reported_as_a_failure(self) -> None:
        """`service restart` honours the rcvar, so a disabled unbound cannot start.

        Judging it would turn "the operator runs their own resolver" into a
        failed upgrade complete with a reboot recommendation.
        """

        def runner(command: list[str], **kwargs: object) -> CommandResult:
            if command[:1] == ["service"] and command[1] == "unbound":
                self.commands.append(command)
                return result(False)
            return self.fake_run()(command, **kwargs)

        with (
            mock.patch.object(system, "run", side_effect=runner),
            self.patched_backup(),
            mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
        ):
            status, payload = system.pkg_upgrade()

        self.assertEqual(status, 200, payload)
        self.assertNotIn(
            ["service", "unbound", "restart"],
            [c for c in self.commands if c[:1] == ["service"]],
        )

    def test_a_failure_after_the_snapshot_still_reports_the_rollback_target(self) -> None:
        """The boot environment matters most when the upgrade itself failed."""
        with (
            mock.patch.object(system, "run", side_effect=self.fake_run(upgrade_ok=False)),
            self.patched_backup(),
            mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
        ):
            status, payload = system.pkg_upgrade()

        self.assertEqual(status, 500)
        self.assertTrue(payload["boot_environment"].startswith("gatebsd-preupgrade-"))
        self.assertIn("bectl activate", payload["rollback_command"])
        state = json.loads(system._UPDATE_STATE.read_text(encoding="utf-8"))
        self.assertEqual(state["phase"], "failed")
        self.assertEqual(state["boot_environment"], payload["boot_environment"])

    def test_superseded_boot_environments_are_removed_after_a_healthy_upgrade(self) -> None:
        """Each attempt clones the root dataset; nothing used to reclaim them."""
        old = [f"gatebsd-preupgrade-2026070{n}-000000" for n in range(1, 6)]

        def runner(command: list[str], **kwargs: object) -> CommandResult:
            if command[:2] == ["bectl", "list"]:
                self.commands.append(command)
                created = [c[2] for c in self.commands if c[:2] == ["bectl", "create"]]
                rows = ["default\tNR\t/\t8.06G\t2026-07-13 21:38"]
                destroyed = {c[3] for c in self.commands if c[:2] == ["bectl", "destroy"]}
                rows += [f"{n}\t-\t-\t8K\t2026" for n in old + created if n not in destroyed]
                return result(True, stdout="\n".join(rows))
            return self.fake_run()(command, **kwargs)

        with (
            mock.patch.object(system, "run", side_effect=runner),
            self.patched_backup(),
            mock.patch.object(system, "_free_bytes", return_value=200 * 1024**3),
        ):
            status, payload = system.pkg_upgrade()

        self.assertEqual(status, 200, payload)
        destroyed = [c[3] for c in self.commands if c[:2] == ["bectl", "destroy"]]
        # Six environments exist, three are kept, and the three oldest go.
        self.assertEqual(destroyed, old[:3])
        self.assertNotIn(payload["boot_environment"], destroyed)


class BootEnvironmentPruneTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._patch = mock.patch.object(system, "_UPDATE_LOG", Path(self._tmp.name) / "upgrade.log")
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_the_active_and_next_boot_environments_are_never_destroyed(self) -> None:
        listing = "\n".join(
            [
                "gatebsd-preupgrade-20260701-000000\tN\t/\t8G\t2026",
                "gatebsd-preupgrade-20260702-000000\tR\t-\t8K\t2026",
                "gatebsd-preupgrade-20260703-000000\t-\t-\t8K\t2026",
                "default\t-\t-\t8G\t2026",
            ]
        )
        commands: list[list[str]] = []

        def runner(command: list[str], **_kwargs: object) -> CommandResult:
            commands.append(command)
            if command[:2] == ["bectl", "list"]:
                return result(True, stdout=listing)
            return result(True)

        with mock.patch.object(system, "run", side_effect=runner):
            system._prune_boot_environments(keep=0)

        destroyed = [c[3] for c in commands if c[:2] == ["bectl", "destroy"]]
        self.assertEqual(destroyed, ["gatebsd-preupgrade-20260703-000000"])

    def test_unrelated_boot_environments_are_left_alone(self) -> None:
        listing = "operator-before-freebsd-15\t-\t-\t8G\t2026\ndefault\tNR\t/\t8G\t2026"
        commands: list[list[str]] = []

        def runner(command: list[str], **_kwargs: object) -> CommandResult:
            commands.append(command)
            if command[:2] == ["bectl", "list"]:
                return result(True, stdout=listing)
            return result(True)

        with mock.patch.object(system, "run", side_effect=runner):
            system._prune_boot_environments(keep=0)

        self.assertEqual([c for c in commands if c[:2] == ["bectl", "destroy"]], [])


if __name__ == "__main__":
    unittest.main()
