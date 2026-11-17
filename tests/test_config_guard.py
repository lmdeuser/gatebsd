"""Regression tests for the configuration guard.

The defect class this exists for was found on the production router. A running
daemon holds its configuration in memory, so a file corrupted underneath it
changes nothing until something restarts the service. Two cron-registered copies
of the adblock updater wrote ``adblock.conf`` concurrently; ``unbound-checkconf``
rejected the result; unbound kept serving for eight days from the list it had
already loaded. The next restart -- which is what an upgrade performs -- would
have taken DNS down, and it would have looked like the upgrade's fault.

The guarantees asserted here:

* every configuration with a native checker is validated;
* a configuration that validates is recorded as the known-good copy;
* a configuration that stops validating is restored from that copy;
* the rejected file is preserved rather than destroyed;
* a missing checker binary is not read as a broken configuration;
* the guard never restarts a service -- that decision belongs to its caller.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "sbin" / "gatebsd-config-guard"


class ConfigGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.good_dir = self.root / "known-good"
        self.unbound_conf = self.root / "unbound.conf"
        self.pf_conf = self.root / "pf.conf"
        self.log = self.root / "checker-calls.log"
        self.ups_enabled = self.root / "ups-enabled"

        # Stand in for unbound-checkconf: a file is valid unless it contains the
        # marker. Real checkers are not available on the build host, and the
        # guard's contract is about what it does with the verdict, not how the
        # verdict is reached.
        self._write_checker("unbound-checkconf")
        self._write_checker("pfctl", skip_args=2)
        for name in ("service", "unbound", "nginx"):
            self._forbid(name)
        self._write_sysrc()
        self.ups_bootstrap = self.bin / "gatebsd-ups-bootstrap"
        self.ups_bootstrap.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.ups_bootstrap.chmod(0o755)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_checker(self, name: str, skip_args: int = 0) -> None:
        target = self.bin / name
        target.write_text(
            "#!/bin/sh\n"
            f'shift {skip_args} 2>/dev/null || true\n'
            f'printf "%s %s\\n" "{name}" "$*" >> "{self.log}"\n'
            'for a in "$@"; do [ -f "$a" ] || continue; '
            'grep -q BROKEN "$a" && exit 1; done\n'
            "exit 0\n",
            encoding="utf-8",
        )
        target.chmod(0o755)

    def _forbid(self, name: str) -> None:
        """A guard that restarts anything is a guard that can cause an outage."""
        target = self.bin / name
        target.write_text(
            f'#!/bin/sh\nprintf "FORBIDDEN {name} %s\\n" "$*" >> "{self.log}"\nexit 0\n',
            encoding="utf-8",
        )
        target.chmod(0o755)

    def _write_sysrc(self) -> None:
        target = self.bin / "sysrc"
        target.write_text(
            f"#!/bin/sh\n[ -f '{self.ups_enabled}' ] && printf 'YES\\n' || printf 'NO\\n'\n",
            encoding="utf-8",
        )
        target.chmod(0o755)

    def run_guard(self) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "GATEBSD_PATH": f"{self.bin}:/usr/bin:/bin",
            "GATEBSD_KNOWN_GOOD_DIR": str(self.good_dir),
            "GATEBSD_PF_CONF": str(self.pf_conf),
            "GATEBSD_UNBOUND_CONF": str(self.unbound_conf),
            "GATEBSD_DHCPD_CONF": str(self.root / "absent-dhcpd.conf"),
            "GATEBSD_NGINX_CONF": str(self.root / "absent-nginx.conf"),
            "GATEBSD_UPS_BOOTSTRAP": str(self.ups_bootstrap),
            "HOME": str(self.root),
            "LANG": "C",
        }
        return subprocess.run(
            ["sh", str(GUARD)], capture_output=True, text=True, env=env, check=False
        )

    def _calls(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""

    def test_a_valid_configuration_is_recorded_as_known_good(self) -> None:
        self.unbound_conf.write_text("server:\n  verbosity: 1\n", encoding="utf-8")
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        saved = list(self.good_dir.glob("*unbound.conf"))
        self.assertEqual(len(saved), 1, [p.name for p in self.good_dir.iterdir()])
        self.assertEqual(saved[0].read_text(encoding="utf-8"), "server:\n  verbosity: 1\n")

    def test_a_configuration_that_stops_validating_is_restored(self) -> None:
        """This is the adblock corruption, reduced to its mechanism."""
        healthy = "server:\n  include: blocklist\n"
        self.unbound_conf.write_text(healthy, encoding="utf-8")
        self.assertEqual(self.run_guard().returncode, 0)

        # A second writer corrupts it, exactly as the duplicated cron job did.
        self.unbound_conf.write_text("server:\nBROKEN omain\n", encoding="utf-8")

        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.unbound_conf.read_text(encoding="utf-8"), healthy)

    def test_h5_snapshots_and_restores_unbound_and_nginx_companion_includes(self) -> None:
        unbound_dir = self.root / "unbound"
        unbound_dir.mkdir()
        self.unbound_conf = unbound_dir / "unbound.conf"
        adblock = unbound_dir / "adblock.conf"
        split_dns = unbound_dir / "split-dns.conf"
        healthy_unbound = f"server:\n  include: {adblock}\n  include: {split_dns}\n"
        healthy_adblock = 'server:\n  local-zone: "ads.example" static\n'
        healthy_split = 'forward-zone:\n  name: "ru"\n  forward-addr: 77.88.8.8\n'
        self.unbound_conf.write_text(healthy_unbound, encoding="utf-8")
        adblock.write_text(healthy_adblock, encoding="utf-8")
        split_dns.write_text(healthy_split, encoding="utf-8")

        # Extend unbound-checkconf stub so it follows include: directives just like real unbound-checkconf.
        (self.bin / "unbound-checkconf").write_text(
            "#!/bin/sh\n"
            'conf=$1\n'
            'grep -q BROKEN "$conf" && exit 1\n'
            'for inc in $(awk "/^[[:space:]]*include:/ {print \\$2}" "$conf"); do\n'
            '  [ -f "$inc" ] || continue\n'
            '  grep -q BROKEN "$inc" && exit 1\n'
            'done\n'
            'exit 0\n',
            encoding="utf-8",
        )
        (self.bin / "unbound-checkconf").chmod(0o755)

        self.assertEqual(self.run_guard().returncode, 0)
        self.assertEqual(len(list(self.good_dir.glob("*unbound.conf"))), 1)

        adblock.write_text("server:\n  BROKEN_INCLUDE\n", encoding="utf-8")
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(adblock.read_text(encoding="utf-8"), healthy_adblock)
        self.assertEqual(split_dns.read_text(encoding="utf-8"), healthy_split)

        # Verify nginx conf.d companion files are also snapshotted and restored.
        nginx_dir = self.root / "nginx"
        nginx_conf_d = nginx_dir / "conf.d"
        nginx_conf_d.mkdir(parents=True)
        nginx_conf = nginx_dir / "nginx.conf"
        site_conf = nginx_conf_d / "gatebsd.conf"
        nginx_conf.write_text(f"http {{ include {nginx_conf_d}/*.conf; }}\n", encoding="utf-8")
        site_conf.write_text("server { listen 80; }\n", encoding="utf-8")
        (self.bin / "nginx").write_text(
            "#!/bin/sh\n"
            '[ "$1" = -t ] || exit 0\n'
            'conf=$3\n'
            'grep -q BROKEN "$conf" && exit 1\n'
            f'for inc in "{nginx_conf_d}"/*.conf; do\n'
            '  [ -f "$inc" ] || continue\n'
            '  grep -q BROKEN "$inc" && exit 1\n'
            'done\n'
            'exit 0\n',
            encoding="utf-8",
        )
        (self.bin / "nginx").chmod(0o755)

        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "GATEBSD_PATH": f"{self.bin}:/usr/bin:/bin",
            "GATEBSD_KNOWN_GOOD_DIR": str(self.good_dir),
            "GATEBSD_PF_CONF": str(self.pf_conf),
            "GATEBSD_UNBOUND_CONF": str(self.unbound_conf),
            "GATEBSD_DHCPD_CONF": str(self.root / "absent-dhcpd.conf"),
            "GATEBSD_NGINX_CONF": str(nginx_conf),
            "GATEBSD_UPS_BOOTSTRAP": str(self.ups_bootstrap),
            "HOME": str(self.root),
            "LANG": "C",
        }
        res_snap = subprocess.run(["sh", str(GUARD)], env=env, capture_output=True, text=True, check=False)
        self.assertEqual(res_snap.returncode, 0, res_snap.stdout + res_snap.stderr)

        site_conf.write_text("server { BROKEN_NGINX }\n", encoding="utf-8")
        res_repair = subprocess.run(["sh", str(GUARD)], env=env, capture_output=True, text=True, check=False)
        self.assertEqual(res_repair.returncode, 1, res_repair.stdout + res_repair.stderr)
        self.assertEqual(site_conf.read_text(encoding="utf-8"), "server { listen 80; }\n")
        self.assertIn("REPAIRED", result.stdout)

    def test_the_rejected_configuration_is_kept_as_evidence(self) -> None:
        self.unbound_conf.write_text("server:\n  ok: 1\n", encoding="utf-8")
        self.run_guard()
        self.unbound_conf.write_text("server:\nBROKEN\n", encoding="utf-8")
        self.run_guard()

        rejected = list(self.good_dir.glob("*.rejected.*"))
        self.assertEqual(len(rejected), 1, [p.name for p in self.good_dir.iterdir()])
        self.assertIn("BROKEN", rejected[0].read_text(encoding="utf-8"))

    def test_a_broken_config_with_no_known_good_copy_is_reported_not_hidden(self) -> None:
        self.unbound_conf.write_text("server:\nBROKEN\n", encoding="utf-8")
        result = self.run_guard()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("manual repair required", result.stdout)
        # It must not be silently emptied or deleted to make the check pass.
        self.assertIn("BROKEN", self.unbound_conf.read_text(encoding="utf-8"))

    def test_a_missing_checker_is_not_a_broken_configuration(self) -> None:
        """An uninstalled service must not be reported as an unstartable one."""
        (self.bin / "unbound-checkconf").unlink()
        self.unbound_conf.write_text("anything at all\n", encoding="utf-8")
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_guard_never_restarts_a_service(self) -> None:
        self.unbound_conf.write_text("server:\n  ok: 1\n", encoding="utf-8")
        self.run_guard()
        self.unbound_conf.write_text("server:\nBROKEN\n", encoding="utf-8")
        self.run_guard()
        self.assertNotIn("FORBIDDEN", self._calls())

    def test_every_configured_file_is_checked(self) -> None:
        self.unbound_conf.write_text("server:\n  ok: 1\n", encoding="utf-8")
        self.pf_conf.write_text("block in all\n", encoding="utf-8")
        self.assertEqual(self.run_guard().returncode, 0)
        calls = self._calls()
        self.assertIn("unbound-checkconf", calls)
        self.assertIn("pfctl", calls)

    def test_enabled_nut_with_an_inconsistent_five_file_set_is_condemned(self) -> None:
        self.ups_enabled.touch()
        self.ups_bootstrap.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        result = self.run_guard()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("UNSTARTABLE: nut nut_upsmon", result.stdout)

    def test_disabled_nut_is_ignored_on_a_build_vm(self) -> None:
        self.ups_bootstrap.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("NUT configuration", result.stdout)

    def test_the_restored_file_keeps_the_live_permissions(self) -> None:
        self.unbound_conf.write_text("server:\n  ok: 1\n", encoding="utf-8")
        self.run_guard()
        self.unbound_conf.write_text("server:\nBROKEN\n", encoding="utf-8")
        self.unbound_conf.chmod(0o600)
        self.run_guard()
        self.assertEqual(self.unbound_conf.stat().st_mode & 0o777, 0o600)


class ConfigGuardWiringTests(unittest.TestCase):
    """The guard is worthless if nothing runs it."""

    def test_the_five_minute_healthcheck_runs_the_guard_before_restarting(self) -> None:
        """Asserted by running the script, not by reading it.

        A source-text assertion passes just as happily when the call sits behind
        `if false`, which is exactly the mistake this test was written to catch.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stub_bin = root / "bin"
            stub_bin.mkdir()
            calls = root / "calls.log"

            for name in ("service", "logger", "ps"):
                stub = stub_bin / name
                stub.write_text(
                    f'#!/bin/sh\nprintf "{name} %s\\n" "$*" >> "{calls}"\nexit 0\n',
                    encoding="utf-8",
                )
                stub.chmod(0o755)

            guard = root / "config-guard"
            guard.write_text(
                f'#!/bin/sh\nprintf "GUARD\\n" >> "{calls}"\nexit 0\n', encoding="utf-8"
            )
            guard.chmod(0o755)

            result = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-healthcheck.sh")],
                capture_output=True,
                text=True,
                check=False,
                env={
                    "PATH": f"{stub_bin}:/usr/bin:/bin",
                    "GATEBSD_PATH": f"{stub_bin}:/usr/bin:/bin",
                    "GATEBSD_CONFIG_GUARD": str(guard),
                    "GATEBSD_WATCHDOG_PIDFILE": str(root / "absent.pid"),
                    "HOME": str(root),
                    "LANG": "C",
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            log = calls.read_text(encoding="utf-8") if calls.exists() else ""
            self.assertIn("GUARD", log, "the healthcheck never ran the configuration guard")
            self.assertLess(
                log.index("GUARD"),
                log.index("service gatebsd"),
                "the guard must run before the healthcheck restarts anything",
            )

    def test_the_upgrade_health_gate_runs_the_guard(self) -> None:
        source = (
            ROOT / "webui" / "backend" / "gatebsd_ui" / "writers" / "system.py"
        ).read_text(encoding="utf-8")
        gate = source.split("def _post_upgrade_health", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("_CONFIG_GUARD", gate)
        self.assertLess(
            gate.index("_CONFIG_GUARD"),
            gate.index('"restart"'),
            "the guard must run before the gate restarts anything",
        )

    def test_the_guard_is_installed_by_both_the_makefile_and_the_package(self) -> None:
        self.assertIn(
            "gatebsd-config-guard", (ROOT / "Makefile").read_text(encoding="utf-8")
        )
        self.assertIn(
            "gatebsd-config-guard", (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        )
        self.assertTrue(os.access(GUARD, os.X_OK), "the guard must be executable")


if __name__ == "__main__":
    unittest.main()
