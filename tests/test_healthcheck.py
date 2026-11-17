"""Functional regression tests for the cron health check.

Why this carries the weight it does: a package cannot restart its own services.
pkg acquires a reaper over the processes its scripts spawn and SIGKILLs whatever
is still running when the script returns -- traced on the rig with DTrace after
it had twice left the production router without failover:

    pkg[61669] -> python3.12[61927] sig=9   the agent
    pkg[61669] -> sh[62030]         sig=9   the failover watchdog

Two paths therefore restore the services, and both live outside pkg: the
product's own ``gatebsd-upgrade``, which restarts them once pkg has returned,
and this script, which runs from cron every minute and is the only thing that
repairs a device upgraded with a bare ``pkg upgrade``. Its interval is the bound
on how long such a device has no WAN failover, so both the interval and the
services it covers are pinned here.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEALTHCHECK = ROOT / "sbin" / "gatebsd-healthcheck.sh"
CRON = ROOT / "etc" / "cron.d" / "gatebsd-healthcheck"
BUILD = ROOT / "ci" / "build.sh"


class HealthcheckHarness:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.calls = root / "calls.log"
        self.pidfile = root / "watchdog.pid"
        self.upsmon = root / "upsmon.conf"
        self.upsmon.write_text(
            "MONITOR ippon@localhost 1 upsmon-master secret primary\n", encoding="ascii"
        )
        self.ups_state = root / "ups-supervisor.failures"
        self.ups_enabled = root / "ups-enabled"
        self.ups_readable = root / "ups-readable"
        # Services report down unless their marker exists.
        self.up = root / "up"
        self.up.mkdir(exist_ok=True)
        self._write(
            "service",
            f"""#!/bin/sh
printf 'service %s\\n' "$*" >> {self.calls}
_name=$1
_verb=$2
case "$_verb" in
  onestatus|status) [ -f {self.up}/$_name ] && exit 0 || exit 1 ;;
  start|restart) : > {self.up}/$_name; exit 0 ;;
esac
exit 0
""",
        )
        self._write("logger", "#!/bin/sh\nexit 0\n")
        self._write("gatebsd-config-guard", "#!/bin/sh\nexit 0\n")
        self._write("gatebsd-ups-bootstrap", "#!/bin/sh\nexit 0\n")
        self._write(
            "sysrc",
            f"""#!/bin/sh
case "$*" in
  *nut_enable|*nut_upsmon_enable) [ -f {self.ups_enabled} ] && printf 'YES\n' || printf 'NO\n' ;;
  *) printf 'NO\n' ;;
esac
""",
        )
        self._write(
            "upsc",
            f"#!/bin/sh\n[ -f {self.ups_readable} ] || exit 1\nprintf 'OL\\n'\n",
        )
        for name in ("sed", "tr", "kill", "cat", "printf", "rm"):
            real = shutil.which(name)
            if real:
                (self.bin / name).symlink_to(real)
        # The check under test recognises the watchdog by its command line, so
        # `ps` is not optional here. The FreeBSD host that validates every push
        # has one; the container the suite also runs in does not, and without a
        # stand-in every test would silently exercise the "ps failed" path and
        # agree with itself.
        real_ps = shutil.which("ps")
        if real_ps:
            (self.bin / "ps").symlink_to(real_ps)
        else:
            self._write(
                "ps",
                """#!/bin/sh
# Enough of `ps -p PID -o command=` to answer the identity question.
_pid=
while [ "$#" -gt 0 ]; do
  case "$1" in -p) _pid=$2; shift 2 ;; *) shift ;; esac
done
[ -r "/proc/$_pid/cmdline" ] || exit 1
tr '\\0' ' ' < "/proc/$_pid/cmdline"
echo
""",
            )

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def service_up(self, name: str) -> None:
        (self.up / name).touch()

    def enable_ups(self, readable: bool = True) -> None:
        self.ups_enabled.touch()
        if readable:
            self.ups_readable.touch()

    def guard_condemns(self, *services: str) -> None:
        """Make the guard report configurations it could not repair.

        Status 2 with an ``UNSTARTABLE:`` line is the guard's real contract for
        "this will not parse"; the CRITICAL line above it is the noise a real
        run emits, kept so the parser is exercised against more than one line.
        """
        named = " ".join(services)
        self._write(
            "gatebsd-config-guard",
            "#!/bin/sh\n"
            "printf 'CRITICAL: /etc/example does not validate\\n'\n"
            f"printf 'UNSTARTABLE: {named}\\n'\n"
            "exit 2\n",
        )

    def start_fake_watchdog(self) -> subprocess.Popen:
        """A live process whose command line names the watchdog.

        The script accepts a pidfile only when ``ps`` shows the recorded PID
        running gatebsd-watchdog.sh, which is what stops it from signalling a
        recycled PID -- so a plausible test needs a real process with that name.
        """
        script = self.root / "gatebsd-watchdog.sh"
        # A loop, not a bare `sleep 60`: a shell execs the last command of a
        # script over itself, and the process would then be called "sleep" and
        # fail the very name check under test.
        script.write_text("#!/bin/sh\nwhile :; do sleep 1; done\n", encoding="ascii")
        script.chmod(0o755)
        proc = subprocess.Popen(["sh", str(script)])
        self.pidfile.write_text(f"{proc.pid}\n", encoding="ascii")
        return proc

    def run(self) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "GATEBSD_PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "GATEBSD_WATCHDOG_PIDFILE": str(self.pidfile),
            "GATEBSD_CONFIG_GUARD": str(self.bin / "gatebsd-config-guard"),
            "GATEBSD_UPS_BOOTSTRAP": str(self.bin / "gatebsd-ups-bootstrap"),
            "GATEBSD_UPSMON_CONF": str(self.upsmon),
            "GATEBSD_UPS_SUPERVISOR_STATE": str(self.ups_state),
            "HOME": str(self.root),
            "LANG": "C",
        }
        return subprocess.run(
            ["sh", str(HEALTHCHECK)],
            check=False, capture_output=True, text=True, env=env,
        )

    def call_log(self) -> str:
        return self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
class HealthcheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = HealthcheckHarness(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_it_restores_everything_a_package_upgrade_left_down(self) -> None:
        """The state a bare `pkg upgrade` leaves behind: nothing running."""
        self.harness.run()

        calls = self.harness.call_log()
        for service in ("gatebsd", "gatebsd_failover"):
            with self.subTest(service=service):
                self.assertRegex(calls, rf"service {service} (restart|start)")

    def test_a_healthy_device_is_left_alone(self) -> None:
        """It runs every minute, so doing nothing must really mean nothing."""
        self.harness.enable_ups()
        for name in ("gatebsd", "nginx", "nut", "nut_upsmon"):
            self.harness.service_up(name)
        proc = self.harness.start_fake_watchdog()
        try:
            self.harness.run()
        finally:
            proc.terminate()
            proc.wait()

        calls = self.harness.call_log()
        self.assertNotRegex(calls, r"service \w+ (restart|start)")

    def test_three_failed_telemetry_checks_trigger_one_bounded_nut_restart(self) -> None:
        self.harness.enable_ups(readable=False)
        for name in ("gatebsd", "nginx", "nut", "nut_upsmon"):
            self.harness.service_up(name)
        proc = self.harness.start_fake_watchdog()
        try:
            self.harness.run()
            self.harness.run()
            self.harness.run()
            self.harness.run()
        finally:
            proc.terminate()
            proc.wait()

        calls = self.harness.call_log()
        self.assertEqual(len(re.findall(r"service nut restart", calls)), 1, calls)

    def test_disabled_nut_is_not_started_on_a_machine_without_a_ups(self) -> None:
        for name in ("gatebsd", "nginx"):
            self.harness.service_up(name)
        proc = self.harness.start_fake_watchdog()
        try:
            self.harness.run()
        finally:
            proc.terminate()
            proc.wait()
        self.assertNotRegex(self.harness.call_log(), r"service nut(?:_upsmon)? (restart|start)")

    def test_it_does_not_restart_a_service_the_guard_condemned(self) -> None:
        """The supervisor must not deliver the outage the guard just prevented.

        The guard validates without loading and reports that nginx cannot start
        from its file. Restarting nginx anyway is how a config corrupted days
        ago becomes an outage now -- and this check runs every minute, so it
        would be the one that pulls the trigger.
        """
        self.harness.guard_condemns("nginx")
        proc = self.harness.start_fake_watchdog()
        try:
            self.harness.run()
        finally:
            proc.terminate()
            proc.wait()

        calls = self.harness.call_log()
        self.assertNotRegex(calls, r"service nginx (restart|start)")
        # Still supervised: holding back the condemned service must not turn
        # into holding back everything.
        self.assertRegex(calls, r"service gatebsd (restart|start)")

    def test_an_unrelated_broken_config_leaves_the_rest_supervised(self) -> None:
        """A broken dhcpd.conf is no reason to leave the uplink watchdog down."""
        self.harness.guard_condemns("dhcpd")

        self.harness.run()

        calls = self.harness.call_log()
        self.assertRegex(calls, r"service nginx (restart|start)")
        self.assertRegex(calls, r"service gatebsd_failover (restart|start)")

    def test_a_stale_pidfile_does_not_pass_for_a_running_watchdog(self) -> None:
        """A PID the kernel has recycled must not read as healthy.

        The router runs `security.bsd.see_other_uids=0` and this check runs as
        root from cron, so the only thing standing between a recycled PID and a
        watchdog that is never restarted is the command-name test.
        """
        self.harness.service_up("gatebsd")
        self.harness.service_up("nginx")
        proc = subprocess.Popen(["sleep", "60"])  # live, but not the watchdog
        self.harness.pidfile.write_text(f"{proc.pid}\n", encoding="ascii")
        try:
            self.harness.run()
        finally:
            proc.terminate()
            proc.wait()

        self.assertRegex(
            self.harness.call_log(), r"service gatebsd_failover (restart|start)"
        )


class HealthcheckDeliveryTests(unittest.TestCase):
    def test_the_check_runs_every_minute(self) -> None:
        # The interval is the bound on how long a device upgraded by hand has no
        # WAN failover, because nothing else can restore it.
        line = [
            line for line in CRON.read_text(encoding="utf-8").splitlines()
            if "gatebsd-healthcheck.sh" in line and not line.startswith("#")
        ]
        self.assertEqual(len(line), 1, line)
        self.assertRegex(line[0], r"^\*\s+\*\s+\*\s+\*\s+\*\s+root\s")

    def test_the_package_does_not_pretend_to_start_its_own_services(self) -> None:
        """pkg SIGKILLs whatever its scripts leave running.

        A start from post-install is not merely useless: it leaves stale
        pidfiles and a package that reports success while the device has no
        failover, which is exactly how this went unnoticed on the router.
        """
        text = BUILD.read_text(encoding="utf-8")
        start = text.index("post-install: <<EOS")
        body = text[start : text.index("\nEOS", start)]
        offending = [
            line for line in body.splitlines()
            if re.search(r'(?<!#)\bservice\s+"?\$?\w+"?\s+(start|restart)', line)
            and not line.strip().startswith("#")
        ]
        self.assertEqual(offending, [], offending)


if __name__ == "__main__":
    unittest.main()
