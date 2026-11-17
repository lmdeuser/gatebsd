"""Functional regression tests for the WAN failover state machine.

These drive the real ``sbin/gatebsd-watchdog.sh`` with stubbed system commands
rather than asserting on its source text, because the defects this file exists
to prevent are all behavioural: a state machine that stops failing over, or a
gateway helper that reports the wrong underlay.

The watchdog is a daemon, so the harness makes ``sleep`` exit non-zero to end
the loop after a bounded number of iterations.
"""
from __future__ import annotations

import grp
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT / "sbin" / "gatebsd-watchdog.sh"

PRIMARY_IF = "ng0"
BACKUP_IF = "ue0"
VPN_IF = "awg0"
PRIMARY_GW = "192.0.2.1"
BACKUP_GW = "198.51.100.1"


class WatchdogHarness:
    """Builds a stubbed environment and runs one or more watchdog iterations."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.run = root / "run"
        self.db = root / "db"
        self.log = root / "watchdog.log"
        self.calls = root / "calls.log"
        for path in (self.bin, self.run, self.db):
            path.mkdir(parents=True, exist_ok=True)
        self.run.chmod(0o750)
        self.state_file = self.run / "watchdog.json"

    # -- stub construction -------------------------------------------------
    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def build(
        self,
        *,
        primary_up: bool,
        backup_up: bool,
        vpn_up: bool,
        vpn_is_default: bool,
        handshake_age: int | None,
        iterations: int = 1,
        route_op_fails: bool = False,
        gatewayctl_succeeds: bool = True,
    ) -> None:
        """Create stubs describing one concrete network condition."""
        primary_inet = (
            f"\tinet 203.0.113.9 --> {PRIMARY_GW} netmask 0xffffffff"
            if primary_up
            else ""
        )
        backup_inet = "\tinet 198.51.100.50 netmask 0xffffff00" if backup_up else ""

        self._write(
            "ifconfig",
            f"""#!/bin/sh
iface=$1
case "$iface" in
  {PRIMARY_IF})
    [ -n "{primary_inet}" ] || exit 1
    echo "{PRIMARY_IF}: flags=88d1<UP,POINTOPOINT,RUNNING> mtu 1492"
    printf '%s\\n' "{primary_inet}"
    ;;
  {BACKUP_IF})
    [ -n "{backup_inet}" ] || exit 1
    echo "{BACKUP_IF}: flags=8843<UP,BROADCAST,RUNNING> mtu 1500"
    printf '%s\\n' "{backup_inet}"
    ;;
  {VPN_IF})
    {"echo '" + VPN_IF + ": flags=80c1<UP,RUNNING> mtu 1420'" if vpn_up else "exit 1"}
    ;;
  *) exit 1 ;;
esac
""",
        )

        # dhclient lease supplies the backup gateway.
        if backup_up:
            (self.db / f"dhclient.leases.{BACKUP_IF}").write_text(
                f"lease {{\n  option routers {BACKUP_GW};\n}}\n", encoding="ascii"
            )

        default_iface = VPN_IF if vpn_is_default else PRIMARY_IF
        default_gw = PRIMARY_GW if not vpn_is_default else ""
        self._write(
            "route",
            f"""#!/bin/sh
printf 'route %s\\n' "$*" >> {self.calls}
for arg in "$@"; do
  if [ "$arg" = default ]; then
    echo "   interface: {default_iface}"
    [ -z "{default_gw}" ] || echo "     gateway: {default_gw}"
    exit 0
  fi
done
echo "     gateway: {PRIMARY_GW}"
exit 0
""",
        )

        if handshake_age is None:
            awg_body = "exit 1\n"
        else:
            awg_body = (
                'now=$(date +%s)\n'
                f'printf "peerkey\\t$((now - {handshake_age}))\\n"\n'
            )
        self._write("awg", f"#!/bin/sh\n{awg_body}")

        # ping: reachability follows the interface state of the source address.
        self._write(
            "ping",
            f"""#!/bin/sh
src=
for arg in "$@"; do
  case "$prev" in -S) src=$arg ;; esac
  prev=$arg
done
case "$src" in
  203.0.113.9) {"exit 0" if primary_up else "exit 2"} ;;
  198.51.100.50) {"exit 0" if backup_up else "exit 2"} ;;
  *) {"exit 0" if (vpn_up and vpn_is_default) or primary_up or backup_up else "exit 2"} ;;
esac
""",
        )

        rc = 1 if route_op_fails else 0
        self._write(
            "gatebsd-route-op",
            f"""#!/bin/sh
printf 'route-op %s\\n' "$*" >> {self.calls}
exit {rc}
""",
        )
        self._write(
            "gatewayctl",
            f"""#!/bin/sh
printf 'gatewayctl %s\\n' "$*" >> {self.calls}
exit {0 if gatewayctl_succeeds else 1}
""",
        )
        self._write(
            "ru-routes.sh",
            f"""#!/bin/sh
printf 'ru-routes %s\\n' "$*" >> {self.calls}
exit 0
""",
        )
        self._write(
            "service",
            f"""#!/bin/sh
printf 'service %s\\n' "$*" >> {self.calls}
exit 0
""",
        )
        self._write("logger", "#!/bin/sh\nexit 0\n")
        self._write("setfib", '#!/bin/sh\nshift\nexec "$@"\n')
        self._write("sysctl", '#!/bin/sh\n[ "$2" = net.fibs ] || exit 1\necho 3\n')
        self._write("unbound-control-setup", "#!/bin/sh\nexit 0\n")
        # Bound the daemon loop: succeed for the requested number of iterations,
        # then fail so `set -e` terminates the script.
        counter = self.root / "sleep.count"
        self._write(
            "sleep",
            f"""#!/bin/sh
n=0
[ ! -f {counter} ] || n=$(cat {counter})
n=$((n + 1))
printf '%s\\n' "$n" > {counter}
[ "$n" -lt {iterations} ] || exit 1
exit 0
""",
        )
        # lockf: consume its own flags, drop the lock-file operand, then run the
        # child directly. The harness is single-process, so real locking would
        # only prevent the re-exec under test from happening at all.
        self._write(
            "lockf",
            """#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    -t) shift 2 ;;
    -k|-s|-n|-w) shift ;;
    -T) shift ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
# The next operand is the lock file; everything after it is the command.
shift
exec "$@"
""",
        )
        # The watchdog uses BSD `stat -f FORMAT`. Provide that interface so the
        # harness runs on a GNU-coreutils host too; the semantics under test are
        # the state machine's, not stat's.
        self._write(
            "stat",
            """#!/bin/sh
if /usr/bin/stat -f '%u' / >/dev/null 2>&1; then
  exec /usr/bin/stat "$@"
fi
if [ "$1" = -f ]; then
  format=$2
  shift 2
  case "$format" in
    '%u') exec /usr/bin/stat -c '%u' "$@" ;;
    '%Lp') exec /usr/bin/stat -c '%a' "$@" ;;
    *) exit 2 ;;
  esac
fi
exec /usr/bin/stat "$@"
""",
        )
        for name in (
            "install", "mktemp", "date", "cat", "awk", "sed", "cmp", "sort",
            "id", "ps", "kill", "grep", "rm", "chmod", "mv", "head", "tr", "df",
        ):
            real = shutil.which(name)
            if real:
                (self.bin / name).symlink_to(real)

    # -- execution ---------------------------------------------------------
    def environment(
        self,
        *,
        failover_mode: str = "automatic",
        extra_env: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Write the config and return the environment the daemon runs under.

        Separate from ``run_watchdog`` so a test that must supervise the process
        itself -- one asserting that the daemon does not hang, say -- can start
        it its own way without duplicating the stub wiring.
        """
        conf = self.root / "failover.conf"
        conf.write_text(
            "\n".join(
                [
                    f'PRIMARY_IF="{PRIMARY_IF}"',
                    f'BACKUP_IF="{BACKUP_IF}"',
                    f'VPN_IF="{VPN_IF}"',
                    f'FAILOVER_MODE="{failover_mode}"',
                    'FAIL_THRESHOLD="1"',
                    'RECOVERY_THRESHOLD="1"',
                    'MIN_BACKUP_HOLD="0"',
                    'SWITCH_COOLDOWN="0"',
                    'CHECK_INTERVAL="0"',
                    'PING_TIMEOUT="1"',
                    'VPN_HANDSHAKE_MAX="180"',
                    'VPN_RECOVERY_HANDSHAKE="90"',
                    'VPN_NET_FAIL_THRESHOLD="1"',
                    "",
                ]
            ),
            encoding="ascii",
        )
        conf.chmod(0o600)
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "GATEBSD_FAILOVER_CONF": str(conf),
            "GATEBSD_RUN_DIR": str(self.run),
            "GATEBSD_SERVICE_GROUP": grp.getgrgid(os.getgid()).gr_name,
            "GATEBSD_ALLOW_TEST_RUN_DIR": "1",
            "GATEBSD_WATCHDOG_STATE": str(self.state_file),
            "GATEBSD_VPN_DISABLED_FLAG": str(self.db / "vpn_disabled"),
            "GATEBSD_ROUTE_HELPER": str(self.bin / "gatebsd-route-op"),
            "GATEBSD_STATE_READER": str(ROOT / "sbin" / "gatebsd-state-value"),
            "GATEBSD_PYTHON_LAUNCHER": shutil.which("python3") or shutil.which("python3.12") or shutil.which("python3.11") or "python3",
            "GATEBSD_RU_ROUTES_HELPER": str(self.bin / "ru-routes.sh"),
            "GATEBSD_GATEWAY_HELPER": str(self.bin / "gatewayctl"),
            "GATEBSD_DHCLIENT_LEASE_DIR": str(self.db),
            "RU_TABLE": str(self.root / "ru.table"),
            "RU_STATE_FILE": str(self.db / "ru-routes.applied"),
            "EVENT_LOG": str(self.log),
            "HOME": str(self.root),
            "LANG": "C",
        }
        if extra_env:
            env.update(extra_env)
        return env

    def run_watchdog(
        self,
        *,
        failover_mode: str = "automatic",
        extra_env: dict[str, str] | None = None,
        script: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = self.environment(failover_mode=failover_mode, extra_env=extra_env)
        return subprocess.run(
            ["sh", str(script or WATCHDOG)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def state(self) -> dict:
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def call_log(self) -> str:
        return self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
class WatchdogFailoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = WatchdogHarness(Path(self._tmp.name))
        # ensure_root_dir requires a root-owned run directory; skip when not root.
        if os.getuid() != 0:
            self.skipTest("watchdog requires a root-owned run directory")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_vpn_outage_does_not_block_wan_failover(self) -> None:
        """The defect this test exists for.

        A stale VPN handshake used to set STATE=VPN_ROLLBACK, and the WAN
        failover section was skipped whenever STATE held that value. Leaving that
        state required a fresh handshake, which requires working WAN transit, so
        a VPN outage followed by a primary-WAN outage deadlocked: failover to a
        healthy backup never ran and the site stayed offline indefinitely.

        The rollback itself is no longer expected in this tick: the underlay has
        just moved, so the tunnel is inside its settling window and is not judged
        yet. That deferral is asserted to be a deferral, not a removal, by
        ``test_the_rollback_is_deferred_not_cancelled`` below and by
        ``tests/test_watchdog_underlay_first.py``.
        """
        self.harness.build(
            primary_up=False,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=6000,  # far beyond VPN_HANDSHAKE_MAX
            iterations=2,
        )
        self.harness.run_watchdog()
        state = self.harness.state()
        calls = self.harness.call_log()

        self.assertIn("switch-underlay", calls, "failover must still be attempted")
        self.assertEqual(state["active_wan"], "backup", state)

    def test_the_rollback_is_deferred_not_cancelled(self) -> None:
        """The same input, with the settling window switched off.

        VPN_SETTLE_AFTER_SWITCH=0 restores the old timing exactly: the tunnel is
        judged in the same tick that moved the ground under it. The rollback then
        happens, which is what says the window defers a verdict rather than
        abolishing it.
        """
        self.harness.build(
            primary_up=False,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=6000,
            iterations=2,
        )
        self.harness.run_watchdog(extra_env={"VPN_SETTLE_AFTER_SWITCH": "0"})
        state = self.harness.state()

        self.assertIn("vpn-rollback", self.harness.call_log())
        self.assertTrue(state["vpn_rolled_back"], state)

    def test_healthy_vpn_survives_awg_missing_from_path(self) -> None:
        """The defect this test exists for.

        rc.d and cron start the watchdog with PATH=/sbin:/bin:/usr/sbin:/usr/bin,
        which does not contain /usr/local/bin where awg is installed. `awg show`
        therefore failed with ENOENT, the error was swallowed by 2>/dev/null, and
        the empty output collapsed into the same 99999 sentinel used for "no
        handshake yet". That exceeds VPN_HANDSHAKE_MAX, so a healthy tunnel with a
        fresh handshake was rolled back to the bare WAN on every tick, taking the
        LAN bypass down with it.

        The stub is placed in a directory that is NOT on PATH, reproducing the
        production condition exactly: awg exists on disk but is unreachable.
        """
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=30,  # tunnel is healthy
            iterations=2,
        )
        # Move awg off PATH: installed, but not findable by a bare name.
        offpath = self.harness.root / "opt-bin"
        offpath.mkdir(exist_ok=True)
        (self.harness.bin / "awg").rename(offpath / "awg")

        self.harness.run_watchdog()
        state = self.harness.state()
        calls = self.harness.call_log()

        self.assertNotIn(
            "vpn-rollback",
            calls,
            "an unreadable handshake age must never roll back the VPN",
        )
        self.assertFalse(state["vpn_rolled_back"], state)

    def test_fresh_tunnel_without_handshake_is_not_rolled_back(self) -> None:
        """A tunnel that just came up has no handshake yet.

        awg reports 0 for a peer that has not completed a handshake. Treating that
        as a huge age rolled back tunnels 6 seconds after they were raised, before
        a handshake was physically possible.
        """
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=0,
            iterations=2,
        )
        self.harness._write("awg", "#!/bin/sh\nprintf 'peerkey\\t0\\n'\n")

        self.harness.run_watchdog()
        state = self.harness.state()

        self.assertNotIn("vpn-rollback", self.harness.call_log())
        self.assertFalse(state["vpn_rolled_back"], state)

    def test_genuinely_stale_handshake_still_rolls_back(self) -> None:
        """The guard must not disarm real rollback: a dead tunnel still fails."""
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=6000,
            iterations=2,
        )
        self.harness.run_watchdog()

        self.assertIn("vpn-rollback", self.harness.call_log())
        self.assertTrue(self.harness.state()["vpn_rolled_back"])

    def test_vpn_disabled_flag_does_not_block_wan_failover(self) -> None:
        (self.harness.db / "vpn_disabled").write_text("", encoding="ascii")
        self.harness.build(
            primary_up=False,
            backup_up=True,
            vpn_up=False,
            vpn_is_default=False,
            handshake_age=None,
            iterations=2,
        )
        self.harness.run_watchdog()
        state = self.harness.state()
        self.assertIn("switch-underlay", self.harness.call_log())
        self.assertEqual(state["active_wan"], "backup", state)

    def test_healthy_primary_is_not_switched_away(self) -> None:
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=5,
            iterations=2,
        )
        self.harness.run_watchdog()
        state = self.harness.state()
        self.assertEqual(state["active_wan"], "primary", state)
        self.assertNotIn("switch-underlay", self.harness.call_log())

    def test_both_links_down_reports_no_connectivity(self) -> None:
        self.harness.build(
            primary_up=False,
            backup_up=False,
            vpn_up=False,
            vpn_is_default=False,
            handshake_age=None,
            iterations=2,
        )
        self.harness.run_watchdog()
        state = self.harness.state()
        self.assertEqual(state["active_wan"], "primary", state)
        self.assertIn(state["state"], {"NO_CONNECTIVITY", "PRIMARY_DEGRADED"}, state)

    def test_state_file_is_written_atomically_and_parses(self) -> None:
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=True,
            vpn_is_default=True,
            handshake_age=5,
            iterations=1,
        )
        self.harness.run_watchdog()
        state = self.harness.state()
        for key in (
            "schema",
            "state",
            "active_wan",
            "vpn_ok",
            "vpn_rolled_back",
            "primary_ok",
            "backup_ok",
            "last_switch",
        ):
            self.assertIn(key, state)
        mode = stat.S_IMODE(self.harness.state_file.stat().st_mode)
        self.assertEqual(mode, 0o640)


class WatchdogSourceContractTests(unittest.TestCase):
    """Contract checks that do not need a root-owned run directory."""

    def setUp(self) -> None:
        self.source = WATCHDOG.read_text(encoding="utf-8")

    def test_failover_section_is_not_gated_on_vpn_state(self) -> None:
        # The specific regression: `if [ "$STATE" != "VPN_ROLLBACK" ]` wrapping
        # the WAN failover block.
        self.assertNotIn(
            'if [ "$STATE" != "VPN_ROLLBACK" ]',
            self.source,
            "WAN failover must not be gated on VPN rollback state; a VPN outage "
            "plus a primary-WAN outage would deadlock and never fail over",
        )

    def test_vpn_rollback_uses_dedicated_state_variable(self) -> None:
        self.assertIn("VPN_ROLLED_BACK=false", self.source)
        self.assertIn('if [ "$VPN_ROLLED_BACK" = true ]', self.source)

    def test_hup_is_trapped_so_log_rotation_cannot_kill_failover(self) -> None:
        # newsyslog signals the watchdog pidfile after rotating its log; the
        # shell default for SIGHUP is terminate.
        self.assertRegex(self.source, r"trap\s+'[^']*'\s+HUP")

    def test_gateway_helpers_do_not_propagate_failure_into_set_e(self) -> None:
        # FreeBSD /bin/sh aborts under `set -e` when a command substitution in an
        # assignment fails. These helpers are assigned from on the failover path,
        # where a missing gateway is the expected condition, so they must return 0
        # with empty output instead.
        for helper in ("pppoe_gw", "backup_gw"):
            start = self.source.index(f"{helper}() {{")
            body = self.source[start : self.source.index("\n}", start)]
            self.assertIn("return 0", body, helper)

    def test_underlay_selection_does_not_substitute_the_other_wan(self) -> None:
        # switch_underlay must read the gateway for the underlay it is switching
        # to, never a fallback, or recorded state desynchronises from the kernel.
        start = self.source.index("switch_underlay() {")
        body = self.source[start : self.source.index("\n}", start)]
        self.assertNotIn("usable_gateway", body)
        self.assertIn("gateway_for", body)


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
class VpnWantedButAbsentTests(unittest.TestCase):
    """After a reboot the watchdog must put the tunnel back without being asked.

    Observed on the production router on 2026-07-31: a power cycle, the boot-path
    ``gatewayctl apply`` lost the race against PPPoE and DNS, and from then on the
    LAN routed in clear. The watchdog was running the whole time and healthy --
    it simply had no branch for this. ``VPN_ROLLED_BACK`` starts out false on a
    fresh daemon, so the only recovery path there was could not fire, and the
    condition persisted for as long as the router stayed up.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = WatchdogHarness(Path(self._tmp.name))
        if os.getuid() != 0:
            self.skipTest("watchdog requires a root-owned run directory")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _boot_with_the_vpn_missing(self) -> None:
        """The state a lost boot race leaves behind: no marker, no tunnel."""
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=False,
            vpn_is_default=False,
            handshake_age=None,
            iterations=2,
        )
        self.assertFalse((self.harness.db / "vpn_disabled").exists())

    def test_the_watchdog_reapplies_the_gateway_by_itself(self) -> None:
        self._boot_with_the_vpn_missing()

        self.harness.run_watchdog()

        self.assertIn(
            "gatewayctl apply",
            self.harness.call_log(),
            "the VPN is wanted and is not in the default route; nothing else on "
            "the device will put it back",
        )

    def test_reintroduced_the_watchdog_waits_to_be_told(self) -> None:
        """The old shape: recover only from a rollback this daemon performed."""
        source = WATCHDOG.read_text(encoding="utf-8")
        marker = "            VPN_OK=false\n            _now=\"$(now)\"\n"
        self.assertIn(marker, source, "the convergence branch is no longer there")
        patched = Path(self._tmp.name) / "watchdog.patched.sh"
        patched.write_text(
            source.replace(
                '        else\n' + marker,
                '        elif [ "$VPN_ROLLED_BACK" = true ]; then\n' + marker,
            ),
            encoding="utf-8",
        )

        self._boot_with_the_vpn_missing()
        self.harness.run_watchdog(script=patched)

        self.assertNotIn(
            "gatewayctl apply",
            self.harness.call_log(),
            "the reintroduction did not reproduce the defect, so the test above "
            "is not measuring anything",
        )

    def test_the_retry_is_rate_limited(self) -> None:
        """Each attempt runs awg-quick and waits; it must not starve WAN checks."""
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=False,
            vpn_is_default=False,
            handshake_age=None,
            iterations=4,
        )

        self.harness.run_watchdog(extra_env={"VPN_RETRY_INTERVAL": "3600"})

        self.assertEqual(
            self.harness.call_log().count("gatewayctl apply"),
            1,
            "the interval was longer than the whole run, so exactly one attempt "
            "may have been made",
        )

    def test_an_operator_disabled_vpn_is_still_left_alone(self) -> None:
        """Convergence must not override the operator's own decision."""
        (self.harness.db / "vpn_disabled").write_text("", encoding="ascii")
        self.harness.build(
            primary_up=True,
            backup_up=True,
            vpn_up=False,
            vpn_is_default=False,
            handshake_age=None,
            iterations=2,
        )

        self.harness.run_watchdog()

        self.assertNotIn("gatewayctl apply", self.harness.call_log())

    def test_no_wan_gateway_defers_instead_of_retrying_into_nothing(self) -> None:
        self.harness.build(
            primary_up=False,
            backup_up=False,
            vpn_up=False,
            vpn_is_default=False,
            handshake_age=None,
            iterations=2,
        )

        self.harness.run_watchdog()

        self.assertNotIn("gatewayctl apply", self.harness.call_log())


if __name__ == "__main__":
    unittest.main()
