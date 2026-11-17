from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from gatebsd_ui import integrity


ROOT = Path(__file__).resolve().parents[1]


class ReleaseIntegrityTests(unittest.TestCase):
    def test_source_manifest_matches_every_tracked_source_file(self) -> None:
        manifest_path = ROOT / "SOURCE_MANIFEST.sha256"
        entries: dict[str, str] = {}
        for line in manifest_path.read_text(encoding="ascii").splitlines():
            digest, separator, relative = line.partition("  ")
            self.assertEqual(separator, "  ", line)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            relative = relative.removeprefix("./")
            self.assertNotIn(relative, entries)
            entries[relative] = digest

        tracked = set(
            subprocess.run(
                ["git", "ls-files"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()
        )
        tracked.discard("SOURCE_MANIFEST.sha256")
        self.assertEqual(set(entries), tracked)

        for relative, expected in entries.items():
            actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, relative)

    def test_all_runtime_modules_import_and_critical_contract_has_eleven(self) -> None:
        self.assertEqual(len(integrity.CRITICAL_SPLIT_MODULES), 11)
        modules = integrity.verify_runtime_modules()
        self.assertTrue(set(integrity.CRITICAL_SPLIT_MODULES).issubset(modules))
        self.assertIn("gatebsd_ui.server", modules)
        self.assertIn("gatebsd_ui.writers.vpn", modules)

    def test_python_tree_verifier_accepts_complete_tree_and_rejects_omission(self) -> None:
        script = ROOT / "ci" / "verify-python-tree.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            staged = root / "staged"
            shutil.copytree(
                ROOT / "webui" / "backend",
                source,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            shutil.copytree(source, staged)
            env = os.environ.copy()
            env["TMPDIR"] = str(root)
            complete = subprocess.run(
                ["sh", str(script), str(source), str(staged), sys.executable],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(complete.returncode, 0, complete.stderr)
            (staged / "gatebsd_ui" / "auth.py").unlink()
            incomplete = subprocess.run(
                ["sh", str(script), str(source), str(staged), sys.executable],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(incomplete.returncode, 0)
            self.assertIn("incomplete", incomplete.stderr)

    def test_release_scripts_are_executable_in_working_tree(self) -> None:
        required = {
            "backup/gatebsd-restore.sh",
            "backup/make-backup.sh",
            "ci/build.sh",
            "ci/resolve-python.sh",
            "ci/test.sh",
            "ci/verify-python-tree.sh",
            "deploy/build_pkg.sh",
            "libexec/gatebsd-python.in",
            "rc.d/gatebsd",
            "rc.d/gatebsd_failover",
            "rc.d/gatebsd_lock_cleanup",
            "rc.d/gatewayctl_apply",
            "rc.d/ru_bypass",
            "sbin/gatebsd-config-migrate",
            "sbin/gatebsd-lock-cleanup",
            "sbin/ru-routes.sh",
            "scripts/build-source-archive.sh",
        }
        for relative in required:
            mode = (ROOT / relative).stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR, relative)

        for top_level in ("sbin", "rc.d", "ci", "deploy"):
            for path in (ROOT / top_level).rglob("*"):
                if not path.is_file():
                    continue
                with path.open("rb") as handle:
                    first_line = handle.readline()
                if first_line.startswith(b"#!"):
                    self.assertTrue(os.access(path, os.X_OK), str(path.relative_to(ROOT)))

        index = subprocess.run(
            ["git", "ls-files", "-s"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        for line in index.splitlines():
            mode, _hash, _stage, relative = line.split(maxsplit=3)
            if mode == "100755":
                self.assertTrue(os.access(ROOT / relative, os.X_OK), relative)

    def test_package_build_verifies_tree_and_postinstall_imports(self) -> None:
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        self.assertIn("verify-python-tree.sh", build)
        self.assertIn("-m gatebsd_ui.integrity", build)
        self.assertIn("gatebsd-config-migrate", build)
        self.assertIn("gatebsd_lock_cleanup", build)
        self.assertIn("safe_dir /var/db/gatebsd-system root wheel 0750", build)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("VARDB_SYSTEM= /var/db/gatebsd-system", makefile)
        self.assertIn("install -d -o root -g wheel -m 0750 ${VARDB_SYSTEM}", makefile)

    def test_post_install_removes_duplicate_cron_entries(self) -> None:
        """cron(8) parses every file in cron.d, so a leftover doubles the job.

        Observed on the production router: `gatebsd-adblock.pkgsave`, left
        beside the live `gatebsd-adblock`, made two adblock updaters run at
        04:00 on the same Wednesday. Both wrote the generated blocklist
        directly, the writes interleaved, and the result was a config unbound
        refuses to parse -- so the resolver would not have come back from any
        restart, including the one an upgrade performs.

        This is the opposite of the sudoers `@includedir` behaviour, which
        skips names containing a dot; assuming the two agree is what let the
        leftover sit there unnoticed.
        """
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        self.assertIn("prune_cron_leftovers", build)

        function = build.split("prune_cron_leftovers() {", 1)[1].split("\n}", 1)[0]
        # Only files this package owns may be removed; a bare wildcard in the
        # code would delete another port's cron entry.
        code = "\n".join(
            line for line in function.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertNotIn("*", code)
        for base in (
            "gatebsd-healthcheck",
            "gatebsd-adblock",
            "gatebsd-ups-health",
            "gatebsd-ups-test",
            "gatebsd-ssl-renew",
            "ru-bypass",
        ):
            self.assertIn(base, function)
        for suffix in ("pkgsave", "bak", "disabled"):
            self.assertIn(suffix, function)

    def test_the_cron_pruner_removes_leftovers_and_spares_everything_else(self) -> None:
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        # The manifest is emitted through a quoted heredoc, so the shell escapes
        # are literal in the source; undo them to run the function directly.
        function = "prune_cron_leftovers() {" + build.split("prune_cron_leftovers() {", 1)[1].split(
            "\n}", 1
        )[0] + "\n}"
        function = function.replace("\\$", "$").replace("\\`", "`")

        with tempfile.TemporaryDirectory() as tmp:
            cron_dir = Path(tmp) / "usr/local/etc/cron.d"
            cron_dir.mkdir(parents=True)
            removed = ["gatebsd-adblock.pkgsave", "gatebsd-healthcheck.bak", "ru-bypass.old"]
            kept = [
                "gatebsd-adblock",          # the live entry
                "gatebsd-healthcheck",
                "ru-bypass",                # the package-owned live entry
                "some-other-port.pkgsave",  # not ours to delete
            ]
            for name in removed + kept:
                (cron_dir / name).write_text("0 4 * * 3 root /bin/true\n", encoding="utf-8")

            script = function.replace("/usr/local/etc/cron.d", str(cron_dir))
            result = subprocess.run(
                ["sh", "-c", f"set -eu\n{script}\nprune_cron_leftovers"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            survivors = sorted(p.name for p in cron_dir.iterdir())
            self.assertEqual(survivors, sorted(kept))

    def test_post_install_retires_only_the_exact_legacy_system_cron_job(self) -> None:
        """Reintroduce the live defect and run the package migration against it."""
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        function = "retire_legacy_ru_crontab() {" + build.split(
            "retire_legacy_ru_crontab() {", 1
        )[1].split("\n}", 1)[0] + "\n}"
        function = function.replace("\\$", "$").replace("\\`", "`")

        with tempfile.TemporaryDirectory() as tmp:
            crontab = Path(tmp) / "crontab"
            legacy = "0 3 * * * root /usr/local/sbin/ru-bypass-update.sh >> /var/log/ru-bypass.log 2>&1"
            preserved = [
                "# " + legacy,
                "5 3 * * * root /usr/local/sbin/ru-bypass-update.sh >> /var/log/ru-bypass.log 2>&1",
                "0 3 * * * root /usr/local/sbin/ru-bypass-update.sh --operator-override",
                "0 3 * * * root /usr/local/sbin/another-job",
            ]
            crontab.write_text("SHELL=/bin/sh\n" + legacy + "\n" + "\n".join(preserved) + "\n", encoding="utf-8")
            crontab.chmod(0o644)

            script = function.replace("_crontab=/etc/crontab", f"_crontab={crontab}")
            if sys.platform != "freebsd":
                script = script.replace("stat -f '%u'", "stat -c '%u'")
                script = script.replace("stat -f '%Lp'", "stat -c '%a'")
            result = subprocess.run(
                ["sh", "-c", f"set -eu\n{script}\nretire_legacy_ru_crontab"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            migrated = crontab.read_text(encoding="utf-8")
            self.assertNotIn("\n" + legacy + "\n", migrated)
            for line in preserved:
                self.assertIn(line, migrated)
            self.assertIn("package cron.d entry is authoritative", result.stderr)

            # The migration is idempotent and does not rewrite an already-clean file.
            before = crontab.stat().st_ino
            second = subprocess.run(
                ["sh", "-c", f"set -eu\n{script}\nretire_legacy_ru_crontab"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(crontab.stat().st_ino, before)

    def test_ru_update_schedule_is_owned_by_both_delivery_paths(self) -> None:
        cron = (ROOT / "etc" / "cron.d" / "ru-bypass").read_text(encoding="utf-8")
        command = "/usr/local/sbin/ru-bypass-update.sh >> /var/log/ru-bypass.log 2>&1"
        active = [line for line in cron.splitlines() if line and not line.startswith("#")]
        self.assertEqual(active, [f"0 3 * * * root {command}"])

        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        host_build = (ROOT / "ci" / "host" / "gatebsd-ci-build").read_text(encoding="utf-8")
        self.assertIn("etc/cron.d/ru-bypass ${PREFIX}/etc/cron.d/ru-bypass", makefile)
        self.assertIn("gatebsd-sms-monitor ru-bypass; do", build)
        self.assertIn("\nretire_legacy_ru_crontab\n", build)
        self.assertIn("legacy unowned RU update schedule", host_build)
        self.assertIn("pkg which -q /usr/local/etc/cron.d/ru-bypass", host_build)
        self.assertIn('! grep -Fq "/usr/local/sbin/ru-bypass-update.sh" /etc/crontab', host_build)

    def test_the_rc_quarantine_disarms_shadowing_copies_and_spares_the_rest(self) -> None:
        """rcorder(8) has no extension filter, so a leftover in rc.d really runs.

        Observed on the production router: a hand-made backup named
        ``gatebsd.before-python-flavor-fix-20260718-142222`` kept its
        ``PROVIDE: gatebsd`` and ran at every boot *ahead* of the package's own
        script. It started the UI under the pre-migration ``www`` identity; the
        real script then saw a UI already running and handed the agent socket to
        ``gatebsd``. The panel answered "agent unavailable" from boot onwards.

        This is the same trap as the duplicated cron entry, and the opposite of
        nginx's ``include conf.d/*.conf``, which really does need the suffix --
        which is why the orphaned nginx copies beside it were inert and this one
        was not. Whose glob sees the file has to be checked per tool.
        """
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        function = "quarantine_rc_leftovers() {" + build.split(
            "quarantine_rc_leftovers() {", 1
        )[1].split("\n}", 1)[0] + "\n}"
        function = function.replace("\\$", "$").replace("\\`", "`")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rc_dir = root / "usr/local/etc/rc.d"
            rc_dir.mkdir(parents=True)
            quarantine = root / "backups"

            moved = [
                "gatebsd.before-python-flavor-fix-20260718-142222",
                "gatebsd_failover.bak",
                "gatebsd-old",
            ]
            kept = [
                "gatebsd",              # the live scripts
                "gatebsd_failover",
                "gatebsd_firstboot",
                "gatebsd_lock_cleanup",
                "nginx",                # another port's script
                "unbound.sample",       # not ours to touch
            ]
            for name in moved + kept:
                (rc_dir / name).write_text("#!/bin/sh\n", encoding="ascii")

            # `pkg which -q` decides ownership; here nothing is owned by a package.
            fakebin = root / "bin"
            fakebin.mkdir()
            (fakebin / "pkg").write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
            (fakebin / "pkg").chmod(0o755)

            # The quarantine directory is created root:wheel on FreeBSD; this
            # test only cares about which files move, so make it plain mkdir.
            script = (
                function.replace("/usr/local/etc/rc.d", str(rc_dir))
                .replace("/var/backups/gatebsd-rc", str(quarantine))
                .replace('install -d -o root -g wheel -m 0750', 'mkdir -p')
            )
            result = subprocess.run(
                ["sh", "-c", f"set -eu\n{script}\nquarantine_rc_leftovers"],
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            self.assertEqual(sorted(p.name for p in rc_dir.iterdir()), sorted(kept))
            self.assertEqual(sorted(p.name for p in quarantine.iterdir()), sorted(moved))

    def test_the_upgrade_does_not_depend_on_the_package_starting_services(self) -> None:
        """An upgrade in the field must not need a human at the console -- but
        the package is not what can deliver that.

        This test used to require the opposite: ``pre-deinstall`` stops
        ``gatebsd``, ``gatebsd_failover`` and ``gatebsd_reverse_ssh`` so the
        files under them can be replaced, so ``post-install`` was made to start them again. It was then
        measured twice on the production router, both times finding the agent
        and the watchdog *down* after the upgrade -- and the reason turned out
        to be that a package cannot do this at all. Traced with DTrace on the
        rig: pkg acquires a reaper over the processes its scripts spawn and
        SIGKILLs every one of them when the script returns.

            pkg[61669] -> python3.12[61927] sig=9   the agent
            pkg[61669] -> sh[62030]         sig=9   the failover watchdog

        So the property is kept, and the mechanism moved outside pkg: the
        product's own ``gatebsd-upgrade`` restarts the services after pkg has
        returned, and ``gatebsd-healthcheck.sh`` repairs a device upgraded with
        a bare ``pkg upgrade`` from cron within a minute. Those are pinned in
        ``test_healthcheck.py``; what belongs here is that the package no longer
        pretends otherwise.
        """
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        stopped = {
            line.split()[1]
            for line in build.split("pre-deinstall: <<EOS", 1)[1].split("EOS", 1)[0].splitlines()
            if line.startswith("service ")
        }
        self.assertEqual(stopped, {"gatebsd", "gatebsd_failover", "gatebsd_reverse_ssh"})

        self.assertNotIn("start_managed_services", build)

        post_install = build.split("post-install: <<EOS", 1)[1].split("\nEOS", 1)[0]
        started = [
            line for line in post_install.splitlines()
            if re.search(r"\bservice\b.*\b(start|restart)\b", line)
            and not line.strip().startswith("#")
        ]
        self.assertEqual(started, [], started)

        # The two paths that do restore the services, so that removing either
        # one is a test failure rather than a discovery in the field.
        healthcheck = (ROOT / "sbin" / "gatebsd-healthcheck.sh").read_text(encoding="utf-8")
        self.assertIn("ensure_service gatebsd", healthcheck)
        self.assertIn("gatebsd_failover", healthcheck)
        upgrade = (ROOT / "sbin" / "gatebsd-upgrade").read_text(encoding="utf-8")
        self.assertIn("service gatebsd_failover restart", upgrade)

    def test_the_rc_quarantine_leaves_package_owned_files_alone(self) -> None:
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        function = "quarantine_rc_leftovers() {" + build.split(
            "quarantine_rc_leftovers() {", 1
        )[1].split("\n}", 1)[0] + "\n}"
        function = function.replace("\\$", "$").replace("\\`", "`")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rc_dir = root / "usr/local/etc/rc.d"
            rc_dir.mkdir(parents=True)
            # A name that matches the pattern but belongs to some other package:
            # removing it would break that port, so ownership is the deciding test.
            (rc_dir / "gatebsd.someport").write_text("#!/bin/sh\n", encoding="ascii")

            fakebin = root / "bin"
            fakebin.mkdir()
            (fakebin / "pkg").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            (fakebin / "pkg").chmod(0o755)

            script = (
                function.replace("/usr/local/etc/rc.d", str(rc_dir))
                .replace("/var/backups/gatebsd-rc", str(root / "backups"))
                .replace('install -d -o root -g wheel -m 0750', 'mkdir -p')
            )
            result = subprocess.run(
                ["sh", "-c", f"set -eu\n{script}\nquarantine_rc_leftovers"],
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((rc_dir / "gatebsd.someport").exists())

    def test_ru_bypass_stop_preserves_routes_and_clear_is_explicit(self) -> None:
        rc_script = (ROOT / "rc.d" / "ru_bypass").read_text(encoding="utf-8")
        stop_block = rc_script.split("ru_bypass_stop()", 1)[1].split("ru_bypass_clear()", 1)[0]
        self.assertNotIn("ru-routes.sh clear", stop_block)
        self.assertIn("active routes are preserved", stop_block)
        self.assertIn("/usr/sbin/daemon", rc_script)
        self.assertIn('-p "$pidfile"', rc_script)
        self.assertIn("GATEBSD_RU_APPLY_TIMEOUT", rc_script)
        route_script = (ROOT / "sbin" / "ru-routes.sh").read_text(encoding="utf-8")
        self.assertIn("lockf -T -k", route_script)
        self.assertIn("/var/db/gatebsd-system/ru-routes.applied", route_script)
        route_op = (ROOT / "sbin" / "gatebsd-route-op").read_text(encoding="utf-8")
        watchdog = (ROOT / "sbin" / "gatebsd-watchdog.sh").read_text(encoding="utf-8")
        self.assertIn("/var/db/gatebsd-system/ru-routes.applied", route_op)
        self.assertIn("/var/db/gatebsd-system/ru-routes.applied", watchdog)
        self.assertIn("install -d -o root -g gatebsd -m 0750", route_op)
        self.assertIn('extra_commands="clear check schedule-clear"', rc_script)
        clear_block = rc_script.split("ru_bypass_clear()", 1)[1].split("ru_bypass_status()", 1)[0]
        self.assertIn('"$RU_ROUTES_HELPER" clear', clear_block)

    def test_route_apply_noop_avoids_route_churn(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            table = root / "ru.table"
            state = root / "state"
            table.write_text("203.0.113.0/24\n", encoding="ascii")
            state.write_text("203.0.113.0/24\n", encoding="ascii")
            route_log = root / "route.log"
            fakebin = self._fake_commands(root, route_log, gateway="192.0.2.1")
            result = self._run_ru_routes(
                root,
                fakebin,
                table,
                state,
                route_log,
                timeout="30",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("already-active=1", result.stdout)
            commands = route_log.read_text(encoding="utf-8").splitlines()
            self.assertTrue(commands)
            self.assertTrue(all(" get " in f" {line} " for line in commands), commands)

    def test_route_timeout_rolls_back_partial_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            table = root / "ru.table"
            state = root / "state"
            table.write_text(
                "".join(f"10.{index // 256}.{index % 256}.0/24\n" for index in range(40)),
                encoding="ascii",
            )
            route_log = root / "route.log"
            fakebin = self._fake_commands(root, route_log, gateway="", advancing_clock=True)
            result = self._run_ru_routes(
                root,
                fakebin,
                table,
                state,
                route_log,
                timeout="30",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("timed out", result.stderr + result.stdout)
            commands = route_log.read_text(encoding="utf-8").splitlines()
            additions = [line for line in commands if line.startswith("add ")]
            deletions = [line for line in commands if line.startswith("delete ")]
            self.assertTrue(additions, commands)
            self.assertTrue(deletions, commands)
            self.assertLess(len(deletions), 40, "rollback touched routes that were never attempted")
            self.assertLessEqual(len(deletions), len(additions) + 1)
            self.assertFalse(state.exists())

    def test_config_permission_migration_repairs_modes_before_safe_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fakebin = root / "bin"
            fakebin.mkdir()
            (fakebin / "id").write_text("#!/bin/sh\necho 0\n", encoding="ascii")
            (fakebin / "stat").write_text(
                """#!/bin/sh
set -eu
format=$2
path=$3
case "$format" in
    %u) echo 0 ;;
    %Lp) /usr/bin/stat -c %a "$path" ;;
    *) exit 2 ;;
esac
""",
                encoding="ascii",
            )
            (fakebin / "chown").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            (fakebin / "chmod").write_text(
                '#!/bin/sh\nexec /bin/chmod "$@"\n', encoding="ascii"
            )
            for path in fakebin.iterdir():
                path.chmod(0o755)

            main = root / "gatebsd.conf"
            failover = root / "failover.conf"
            gateway = root / "gateway.conf"
            for config in (main, failover, gateway):
                config.write_text("KEY=value\n", encoding="ascii")
                config.chmod(0o666)

            env = {
                "PATH": f"{fakebin}:/usr/bin:/bin",
                "GATEBSD_PATH": f"{fakebin}:/usr/bin:/bin",
                "GATEBSD_MAIN_CONF": str(main),
                "GATEBSD_FAILOVER_CONF": str(failover),
                "GATEBSD_GATEWAY_CONF": str(gateway),
            }
            result = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-config-migrate")],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(stat.S_IMODE(main.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(failover.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(gateway.stat().st_mode), 0o600)


    def test_legacy_route_state_migrates_to_private_root_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fakebin = root / "bin"
            fakebin.mkdir()
            (fakebin / "id").write_text("#!/bin/sh\necho 0\n", encoding="ascii")
            (fakebin / "stat").write_text(
                """#!/bin/sh
set -eu
case "$2" in
    %u) echo 0 ;;
    %Lp) /usr/bin/stat -c %a "$3" ;;
    *) exit 2 ;;
esac
""",
                encoding="ascii",
            )
            (fakebin / "chown").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            (fakebin / "install").write_text(
                """#!/bin/sh
set -eu
if [ "${1:-}" = -d ]; then
    last=
    while [ "$#" -gt 0 ]; do last=$1; shift; done
    mkdir -p "$last"
    chmod 0750 "$last"
    exit 0
fi
mode=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -m) mode=$2; shift 2 ;;
        -o|-g) shift 2 ;;
        *) break ;;
    esac
done
cp "$1" "$2"
[ -z "$mode" ] || chmod "$mode" "$2"
""",
                encoding="ascii",
            )
            for path in fakebin.iterdir():
                path.chmod(0o755)

            legacy = root / "legacy" / "ru-routes.applied"
            legacy.parent.mkdir()
            legacy.write_text("203.0.113.0/24\n", encoding="ascii")
            legacy.chmod(0o640)
            current = root / "system" / "ru-routes.applied"
            env = {
                "PATH": f"{fakebin}:/usr/bin:/bin",
                "GATEBSD_PATH": f"{fakebin}:/usr/bin:/bin",
                "GATEBSD_MAIN_CONF": str(root / "missing-main.conf"),
                "GATEBSD_FAILOVER_CONF": str(root / "missing-failover.conf"),
                "GATEBSD_GATEWAY_CONF": str(root / "missing-gateway.conf"),
                "GATEBSD_LEGACY_RU_STATE": str(legacy),
                "RU_STATE_FILE": str(current),
            }
            result = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-config-migrate")],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(current.read_text(encoding="ascii"), legacy.read_text(encoding="ascii"))
            self.assertEqual(stat.S_IMODE(current.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(current.parent.stat().st_mode), 0o750)

    def test_config_permission_migration_rejects_untrusted_files(self) -> None:
        script = ROOT / "sbin" / "gatebsd-config-migrate"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real.conf"
            real.write_text("KEY=value\n", encoding="ascii")
            link = root / "gatebsd.conf"
            link.symlink_to(real)
            fakebin = root / "bin"
            fakebin.mkdir()
            fake_id = fakebin / "id"
            fake_id.write_text("#!/bin/sh\necho 0\n", encoding="ascii")
            fake_id.chmod(0o755)
            env = os.environ.copy()
            env.update(
                {
                    "GATEBSD_PATH": f"{fakebin}:/usr/bin:/bin",
                    "GATEBSD_MAIN_CONF": str(link),
                    "GATEBSD_FAILOVER_CONF": str(root / "missing-failover.conf"),
                    "GATEBSD_GATEWAY_CONF": str(root / "missing-gateway.conf"),
                }
            )
            result = subprocess.run(
                ["sh", str(script)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe configuration path", result.stderr)
            self.assertTrue(link.is_symlink())

    def test_boot_lock_cleanup_removes_only_known_unlocked_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            run_dir.mkdir(mode=0o750)
            (run_dir / "gatewayctl.lock").write_text("", encoding="ascii")
            (run_dir / "agent.pid").write_text("999999\n", encoding="ascii")
            untouched = run_dir / "unknown.lock"
            untouched.write_text("", encoding="ascii")
            for path in (run_dir / "gatewayctl.lock", run_dir / "agent.pid", untouched):
                path.chmod(0o600)

            fakebin = root / "bin"
            fakebin.mkdir()
            scripts = {
                "id": "#!/bin/sh\necho 0\n",
                "stat": """#!/bin/sh
set -eu
case "$2" in
    %u) echo 0 ;;
    %Lp) /usr/bin/stat -c %a "$3" ;;
    *) exit 2 ;;
esac
""",
                "ps": "#!/bin/sh\nexit 1\n",
                "kill": "#!/bin/sh\nexit 1\n",
                "logger": "#!/bin/sh\nexit 0\n",
                "install": """#!/bin/sh
set -eu
[ "${1:-}" = -d ] || exit 2
last=
while [ "$#" -gt 0 ]; do last=$1; shift; done
mkdir -p "$last"
chmod 0750 "$last"
""",
                "lockf": """#!/bin/sh
set -eu
[ "$1" = -t ]
shift 2
lock=$1
shift
exec "$@"
""",
            }
            for name, body in scripts.items():
                path = fakebin / name
                path.write_text(body, encoding="ascii")
                path.chmod(0o755)

            env = {
                "PATH": f"{fakebin}:/usr/bin:/bin",
                "GATEBSD_PATH": f"{fakebin}:/usr/bin:/bin",
                "GATEBSD_RUN_DIR": str(run_dir),
                "GATEBSD_ALLOW_TEST_RUN_DIR": "1",
            }
            result = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-lock-cleanup"), "--boot"],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((run_dir / "gatewayctl.lock").exists())
            self.assertFalse((run_dir / "agent.pid").exists())
            self.assertTrue(untouched.exists())

    def test_source_archive_is_reproducible_and_preserves_new_script_modes(self) -> None:
        import hashlib
        import zipfile

        script = ROOT / "scripts" / "build-source-archive.sh"
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.zip"
            second = Path(directory) / "second.zip"
            for output in (first, second):
                result = subprocess.run(
                    ["sh", str(script), str(output)],
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                hashlib.sha256(first.read_bytes()).digest(),
                hashlib.sha256(second.read_bytes()).digest(),
            )
            with zipfile.ZipFile(first) as archive:
                # The archive root is named after the checkout directory, which
                # is not "netgate" everywhere -- a CI runner checks out into its
                # own workspace path. Derive it instead of assuming it.
                archive_root = ROOT.name
                expected_executables = {
                    line.split(maxsplit=3)[3]
                    for line in subprocess.run(
                        ["git", "ls-files", "-s"],
                        cwd=ROOT,
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.splitlines()
                    if line.split(maxsplit=1)[0] == "100755"
                }
                expected_executables.update(
                    {
                        "ci/verify-python-tree.sh",
                        "rc.d/gatebsd_lock_cleanup",
                        "sbin/gatebsd-config-migrate",
                        "sbin/gatebsd-lock-cleanup",
                        "scripts/build-source-archive.sh",
                    }
                )
                for relative in expected_executables:
                    archived = f"{archive_root}/{relative}"
                    mode = (archive.getinfo(archived).external_attr >> 16) & 0o7777
                    self.assertTrue(mode & stat.S_IXUSR, relative)

    def test_source_archive_holds_the_tracked_set_and_nothing_else(self) -> None:
        """Built in a synthetic checkout, so the verdict is about the script.

        It used to walk the tree, which meant the archive was whatever happened
        to be lying in the working directory: every untracked file -- measured
        here once as .secrets/forgejo-api-token and an Amnezia subscription
        token -- plus the whole of .git. .gitignore had no say; os.walk does
        not read it. A build whose output depends on what else is in the
        directory cannot be called reproducible.
        """
        import subprocess as sp
        import zipfile

        script = ROOT / "scripts" / "build-source-archive.sh"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "checkout"
            (repo / "scripts").mkdir(parents=True)
            (repo / "src").mkdir()
            shutil.copy2(script, repo / "scripts" / "build-source-archive.sh")

            (repo / "README.md").write_text("source\n", encoding="utf-8")
            tool = repo / "src" / "thing.sh"
            tool.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
            tool.chmod(0o755)
            (repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")

            env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
            sp.run(["git", "init", "-q"], cwd=repo, check=True, env=env)
            sp.run(["git", "config", "user.email", "t@example.invalid"], cwd=repo, check=True)
            sp.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
            sp.run(["git", "add", "-A"], cwd=repo, check=True, env=env)
            sp.run(["git", "commit", "-qm", "source"], cwd=repo, check=True, env=env)

            # Everything below lands after the commit, so none of it is tracked.
            (repo / ".secrets").mkdir()
            (repo / ".secrets" / "api-token").write_text("SECRET\n", encoding="utf-8")
            (repo / "ignored.txt").write_text("ignored\n", encoding="utf-8")
            stray = repo / "stray.sh"
            stray.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
            stray.chmod(0o755)

            output = base / "out.zip"
            result = sp.run(
                ["sh", str(repo / "scripts" / "build-source-archive.sh"), str(output)],
                cwd=repo, check=False, capture_output=True, text=True, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            with zipfile.ZipFile(output) as archive:
                names = {
                    item.filename.split("/", 1)[1]
                    for item in archive.infolist()
                    if "/" in item.filename and not item.is_dir()
                }
            self.assertEqual(
                names,
                {".gitignore", "README.md", "scripts/build-source-archive.sh", "src/thing.sh"},
            )
            for absent in (".secrets/api-token", "ignored.txt", "stray.sh"):
                self.assertNotIn(absent, names)
            self.assertFalse(
                [name for name in names if name.startswith(".git/")],
                "the archive must not carry the repository's own history",
            )

    def test_source_archive_reports_a_tracked_file_missing_from_the_tree(self) -> None:
        """Silently shipping incomplete source is worse than refusing to ship."""
        import subprocess as sp

        script = ROOT / "scripts" / "build-source-archive.sh"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "checkout"
            (repo / "scripts").mkdir(parents=True)
            shutil.copy2(script, repo / "scripts" / "build-source-archive.sh")
            (repo / "README.md").write_text("source\n", encoding="utf-8")

            env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
            sp.run(["git", "init", "-q"], cwd=repo, check=True, env=env)
            sp.run(["git", "config", "user.email", "t@example.invalid"], cwd=repo, check=True)
            sp.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
            sp.run(["git", "add", "-A"], cwd=repo, check=True, env=env)
            sp.run(["git", "commit", "-qm", "source"], cwd=repo, check=True, env=env)
            (repo / "README.md").unlink()

            result = sp.run(
                ["sh", str(repo / "scripts" / "build-source-archive.sh"), str(base / "out.zip")],
                cwd=repo, check=False, capture_output=True, text=True, env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("absent from the working tree", result.stderr)

    @staticmethod
    def _fake_commands(
        root: Path,
        route_log: Path,
        *,
        gateway: str,
        advancing_clock: bool = False,
    ) -> Path:
        fakebin = root / "bin"
        fakebin.mkdir()
        (fakebin / "install").write_text(
            """#!/bin/sh
set -eu
if [ \"${1:-}\" = -d ]; then
    last=
    while [ \"$#\" -gt 0 ]; do last=$1; shift; done
    mkdir -p \"$last\"
    exit 0
fi
mode=
while [ \"$#\" -gt 0 ]; do
    case \"$1\" in
        -m) mode=$2; shift 2 ;;
        -o|-g) shift 2 ;;
        *) break ;;
    esac
done
cp \"$1\" \"$2\"
[ -z \"$mode\" ] || chmod \"$mode\" \"$2\"
""",
            encoding="ascii",
        )
        (fakebin / "logger").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        (fakebin / "stat").write_text(
            """#!/bin/sh
set -eu
case "$2" in
    %u) echo 0 ;;
    %Lp) /usr/bin/stat -c %a "$3" ;;
    *) exit 2 ;;
esac
""",
            encoding="ascii",
        )
        (fakebin / "ifconfig").write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
        (fakebin / "route").write_text(
            f"""#!/bin/sh
set -eu
printf '%s\\n' \"$*\" >> {route_log}
if [ \"${{1:-}}\" = -n ] && [ \"${{2:-}}\" = get ]; then
    {f"printf 'gateway: {gateway}\\n'" if gateway else ":"}
    exit 0
fi
[ \"${{1:-}}\" != change ] || exit 1
exit 0
""",
            encoding="ascii",
        )
        if advancing_clock:
            counter = root / "date.counter"
            (fakebin / "date").write_text(
                f"""#!/bin/sh
set -eu
n=0
[ ! -f {counter} ] || n=$(cat {counter})
n=$((n + 1))
printf '%s\\n' \"$n\" > {counter}
case \"$n\" in
    1) echo 100 ;;
    2) echo 101 ;;
    *) echo 131 ;;
esac
""",
                encoding="ascii",
            )
        for path in fakebin.iterdir():
            path.chmod(0o755)
        return fakebin

    @staticmethod
    def _run_ru_routes(
        root: Path,
        fakebin: Path,
        table: Path,
        state: Path,
        route_log: Path,
        *,
        timeout: str,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{fakebin}:/usr/bin:/bin",
            "GATEBSD_PATH": f"{fakebin}:/usr/bin:/bin",
            "GATEBSD_RU_ROUTE_LOCK_HELD": "1",
            "GATEBSD_GATEWAY_CONF": str(root / "missing.conf"),
            "RU_TABLE": str(table),
            "RU_STATE_FILE": str(state),
            "GATEBSD_WATCHDOG_STATE": str(root / "watchdog.json"),
            "GATEBSD_STATE_READER": str(ROOT / "sbin" / "gatebsd-state-value"),
            "GATEBSD_PYTHON_LAUNCHER": sys.executable,
            "GATEBSD_RU_ROUTE_LOCK": str(root / "route.lock"),
            "GATEBSD_ACTIVE_WAN_IF": "ng0",
            "GATEBSD_ACTIVE_WAN_GW": "192.0.2.1",
            "GATEBSD_RU_APPLY_TIMEOUT": timeout,
            "HOME": str(root),
            "LANG": "C",
        }
        route_log.touch()
        return subprocess.run(
            ["sh", str(ROOT / "sbin" / "ru-routes.sh"), "apply"],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )


class LogRotationTests(unittest.TestCase):
    """Every log this system writes must be rotated.

    ``gatebsd-recovery.log`` is appended to by cron every minute and had no
    newsyslog entry, so on a long-lived router it grows until /var is full --
    at which point the writers that keep the uplink up start failing on a
    filesystem they cannot write to.
    """

    _SEARCH_DIRS = ("sbin", "rc.d", "etc/cron.d", "webui/backend/gatebsd_ui", "libexec")
    # A log path can also be *read* -- gatebsd-collect gathers base-system logs
    # that FreeBSD's own newsyslog.conf already rotates. Only writes count here,
    # so the patterns below all describe an output destination.
    _WRITE_PATTERNS = (
        r">>?\s*[\"']?(/var/log/[A-Za-z0-9._-]+\.log)",       # shell redirection
        r"Path\(\s*[\"'](/var/log/[A-Za-z0-9._-]+\.log)[\"']", # Python log constant
        r":?=\s*[\"'](/var/log/[A-Za-z0-9._-]+\.log)[\"']",    # rc.d default value
    )

    def _written_logs(self) -> set[str]:
        import re

        patterns = [re.compile(p) for p in self._WRITE_PATTERNS]
        found: set[str] = set()
        for directory in self._SEARCH_DIRS:
            base = ROOT / directory
            if not base.is_dir():
                continue
            for path in base.rglob("*"):
                if not path.is_file() or "__pycache__" in path.parts:
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                for pattern in patterns:
                    found.update(pattern.findall(text))
        return found

    def _rotated_logs(self) -> set[str]:
        config = ROOT / "etc" / "newsyslog.conf.d" / "gatebsd.conf"
        rotated: set[str] = set()
        for line in config.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rotated.add(line.split()[0])
        return rotated

    def test_every_log_written_by_gatebsd_is_rotated(self) -> None:
        unrotated = sorted(self._written_logs() - self._rotated_logs())
        self.assertEqual(unrotated, [], f"no newsyslog entry for: {unrotated}")


class PackagingCompletenessM5Tests(unittest.TestCase):
    def test_m5_ci_build_includes_amneziawg_go_sms_cron_and_all_rc_leftovers(self) -> None:
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        req_pkgs = build.split('required-packages" <<EOF', 1)[1].split("EOF", 1)[0]
        self.assertIn("amneziawg-go", req_pkgs)

        cron_fn = build.split("prune_cron_leftovers() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("gatebsd-sms-monitor", cron_fn)

        rc_fn = build.split("quarantine_rc_leftovers() {", 1)[1].split("\n}", 1)[0]
        for rc_name in ("ru_bypass", "gatewayctl_apply", "gatebsd_reverse_ssh"):
            self.assertIn(rc_name, rc_fn)

    def test_m5_reverse_ssh_is_in_allowed_services(self) -> None:
        from gatebsd_ui.writers import system

        self.assertIn("gatebsd_reverse_ssh", system.ALLOWED_SERVICES)


if __name__ == "__main__":
    unittest.main()
