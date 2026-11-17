"""The UPS checks must not report success for not having checked.

On 2026-07-31 at 23:42 the link to the UPS died. The daily health check ran at
06:00 on two mornings and logged

    health target=ippon@localhost charge=unknown% voltage=unknownV status=unknown

raising nothing and exiting 0, because every one of its conditions is guarded
by "is this a number" and an empty string is not. The monthly battery test then
logged "SKIP: UPS is not on line power" -- untrue; it could not read the UPS at
all -- and also exited 0, which means that test had probably never run. On the
second morning the machine lost power, and nobody knew it had been unmonitored
for a day.

Neither script had a single behavioural test. These run them, against a fake
`upsc` that can be made to answer, to answer partially, or to say nothing.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEALTH = ROOT / "sbin" / "gatebsd-ups-health.sh"
TEST = ROOT / "sbin" / "gatebsd-ups-test.sh"
CRON = ROOT / "etc" / "cron.d" / "gatebsd-ups-test"

FAKE_LOGGER = """#!/bin/sh
while [ $# -gt 0 ]; do
    case "$1" in
        -t) shift 2 ;;
        --) shift; break ;;
        *) break ;;
    esac
done
printf '%s\\n' "$*"
"""

FAKE_UPSC = """#!/bin/sh
# $1 target, $2 variable. No data file means the UPS cannot be read at all.
[ -f "${UPSC_DATA:-}" ] || exit 1
if [ "$2" = ups.status ] && [ -f "${UPSC_STATUS_FILE:-}" ]; then
    cat "$UPSC_STATUS_FILE"
    exit 0
fi
value=$(grep "^$2: " "$UPSC_DATA" | sed 's/^[^:]*: //')
[ -n "$value" ] || exit 1
printf '%s\\n' "$value"
"""

FAKE_TRUE = "#!/bin/sh\nexit 0\n"
FAKE_SYSRC = "#!/bin/sh\nprintf 'YES\\n'\n"
FAKE_UPSCMD = """#!/bin/sh
printf '%s\n' "$*" >> "${UPSCMD_LOG:-/dev/null}"
if [ "${UPSCMD_NO_TRANSITION:-0}" != 1 ]; then
    case "$*" in
        *test.battery.start.quick*) printf 'CAL\n' > "$UPSC_STATUS_FILE" ;;
        *test.battery.stop*) printf 'OL\n' > "$UPSC_STATUS_FILE" ;;
    esac
fi
exit 0
"""

READABLE = """battery.charge: 100
battery.voltage: 27.2
ups.status: OL
ups.temperature: 25.0
ups.load: 0
"""


class UpsCheckBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, body in (
            ("logger", FAKE_LOGGER),
            ("upsc", FAKE_UPSC),
            ("service", FAKE_TRUE),
            ("sysrc", FAKE_SYSRC),
            ("upscmd", FAKE_UPSCMD),
            ("sleep", FAKE_TRUE),
        ):
            path = self.bin / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)

        self.upsmon = self.root / "upsmon.conf"
        self.upsmon.write_text(
            "MONITOR ippon@localhost 1 upsmon-master secret primary\n", encoding="utf-8"
        )
        self.users = self.root / "upsd.users"
        self.users.write_text("[upsmon-master]\n    upsmon primary\n", encoding="utf-8")
        self.data = self.root / "ups.data"
        self.status = self.root / "ups.status"

    def env(self, readable: str | None) -> dict[str, str]:
        if readable is None:
            data = str(self.root / "absent.data")
        else:
            self.data.write_text(readable, encoding="utf-8")
            data = str(self.data)
        return {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "GATEBSD_PATH": f"{self.bin}:/usr/bin:/bin",
            "UPSC_DATA": data,
            "UPSC_STATUS_FILE": str(self.status),
            "GATEBSD_UPSMON_CONF": str(self.upsmon),
            "GATEBSD_UPSD_USERS": str(self.users),
            "GATEBSD_UPS_HEALTH_STATE": str(self.root / "health.state"),
            "HOME": str(self.root),
            "LANG": "C",
        }


class HealthCheckTests(UpsCheckBase):
    def run_health(self, readable: str | None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(HEALTH)], capture_output=True, text=True, check=False,
            env=self.env(readable),
        )

    def test_an_unreadable_ups_is_an_alert_not_a_clean_run(self) -> None:
        """The defect itself: silence for a day while the link was dead."""
        result = self.run_health(None)
        self.assertIn("ALERT", result.stdout)
        self.assertIn("cannot read", result.stdout)
        self.assertNotEqual(result.returncode, 0, "an unreadable UPS must not exit 0")

    def test_a_readable_healthy_ups_raises_nothing(self) -> None:
        result = self.run_health(READABLE)
        self.assertNotIn("ALERT", result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("charge=100%", result.stdout)

    def health_state(self) -> dict[str, str]:
        result = {}
        for line in (self.root / "health.state").read_text(encoding="utf-8").splitlines():
            key, value = line.split("=", 1)
            result[key] = value
        return result

    def test_successful_check_publishes_its_result_and_response_time(self) -> None:
        result = self.run_health(READABLE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        state = self.health_state()
        self.assertEqual(state["ok"], "true")
        self.assertEqual(state["errors"], "0")
        self.assertTrue(state["checked_at"].isdigit())
        self.assertEqual(state["last_response_at"], state["checked_at"])
        self.assertEqual(state["status"], "OL")

    def test_failed_check_publishes_failure_without_a_new_response_time(self) -> None:
        result = self.run_health(None)
        self.assertNotEqual(result.returncode, 0)
        state = self.health_state()
        self.assertEqual(state["ok"], "false")
        self.assertEqual(state["last_response_at"], "")
        self.assertGreater(int(state["errors"]), 0)

    def test_failed_check_preserves_the_previous_response_time(self) -> None:
        self.run_health(READABLE)
        previous = self.health_state()["last_response_at"]
        self.run_health(None)
        self.assertEqual(self.health_state()["last_response_at"], previous)

    def test_an_unreadable_charge_is_an_alert_even_when_the_ups_answers(self) -> None:
        """battery.charge is the only low-battery criterion that works here.

        The driver mis-parses this model, so battery.runtime comes back as a
        word and every comparison against it is meaningless. Losing charge as
        well leaves nothing at all watching the battery.
        """
        partial = "ups.status: OL\nbattery.voltage: 27.2\nups.load: 0\n"
        result = self.run_health(partial)
        self.assertIn("ALERT", result.stdout)
        self.assertIn("charge is unreadable", result.stdout)
        self.assertNotEqual(result.returncode, 0)

    def test_a_low_battery_on_line_power_still_alerts(self) -> None:
        """The check that already worked must keep working."""
        low = READABLE.replace("battery.charge: 100", "battery.charge: 41")
        result = self.run_health(low)
        self.assertIn("ALERT", result.stdout)
        self.assertIn("41", result.stdout)
        self.assertNotEqual(result.returncode, 0)


class HealthScheduleTests(unittest.TestCase):
    def test_health_is_checked_every_five_minutes_not_once_a_day(self) -> None:
        cron = ROOT / "etc" / "cron.d" / "gatebsd-ups-health"
        active = [
            line.split() for line in cron.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0][:5], ["*/5", "*", "*", "*", "*"])
        self.assertEqual(active[0][5:], ["root", "/usr/local/sbin/gatebsd-ups-health.sh"])


class BatteryTestTests(UpsCheckBase):
    def run_test(self, readable: str | None) -> subprocess.CompletedProcess[str]:
        environment = self.env(readable)
        if readable is not None:
            status = next(
                (line.split(": ", 1)[1] for line in readable.splitlines() if line.startswith("ups.status: ")),
                "OL",
            )
            self.status.write_text(status + "\n", encoding="utf-8")
        environment["GATEBSD_UPS_TEST_LOCK_HELD"] = "1"
        environment["GATEBSD_UPS_TEST_DURATION"] = "10"
        environment["UPSCMD_LOG"] = str(self.root / "upscmd.log")
        return subprocess.run(
            ["sh", str(TEST)], capture_output=True, text=True, check=False, env=environment,
        )

    def test_an_accepted_command_without_a_real_state_transition_fails(self) -> None:
        environment = self.env(READABLE)
        self.status.write_text("OL\n", encoding="utf-8")
        environment.update({
            "GATEBSD_UPS_TEST_LOCK_HELD": "1",
            "GATEBSD_UPS_TEST_DURATION": "10",
            "UPSCMD_LOG": str(self.root / "upscmd.log"),
            "UPSCMD_NO_TRANSITION": "1",
        })
        result = subprocess.run(
            ["sh", str(TEST)], capture_output=True, text=True, check=False, env=environment,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("no CAL/OB/DISCHRG", result.stdout)

    def test_an_unreadable_ups_fails_instead_of_claiming_a_skip(self) -> None:
        """It used to say "UPS is not on line power" and exit 0. Both untrue."""
        result = self.run_test(None)
        self.assertIn("FAIL", result.stdout)
        self.assertIn("cannot read", result.stdout)
        self.assertIn("did not run", result.stdout)
        self.assertNotIn("not on line power", result.stdout)
        self.assertEqual(result.returncode, 1)

    def test_being_genuinely_on_battery_is_a_skip_and_says_so(self) -> None:
        on_battery = READABLE.replace("ups.status: OL", "ups.status: OB")
        result = self.run_test(on_battery)
        self.assertIn("SKIP", result.stdout)
        self.assertIn("OB", result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_low_but_readable_charge_is_a_skip(self) -> None:
        low = READABLE.replace("battery.charge: 100", "battery.charge: 30")
        result = self.run_test(low)
        self.assertIn("SKIP", result.stdout)
        self.assertIn("30", result.stdout)
        self.assertEqual(result.returncode, 0)

    def test_a_healthy_ups_actually_starts_the_battery_test(self) -> None:
        result = self.run_test(READABLE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("monthly UPS test completed", result.stdout)
        issued = (self.root / "upscmd.log").read_text(encoding="utf-8")
        self.assertIn("test.battery.start.quick", issued)
        self.assertIn("test.battery.stop", issued)

    def test_both_scripts_are_executable(self) -> None:
        for script in (HEALTH, TEST):
            self.assertTrue(os.access(script, os.X_OK), script.name)

    def test_monthly_test_is_opt_in_until_real_hardware_is_supervised(self) -> None:
        active = [line for line in CRON.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
        self.assertEqual(len(active), 1)
        self.assertIn("ups-autotest.enabled", active[0])
        self.assertIn("&& /usr/local/sbin/gatebsd-ups-test.sh", active[0])


if __name__ == "__main__":
    unittest.main()
