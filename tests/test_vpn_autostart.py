"""The tunnel must come back by itself, from any state the device booted into.

Three defects observed together on the production router on 2026-07-31, after an
ordinary power cycle:

* ``gatewayctl apply`` runs on the boot path while PPPoE is still dialling and
  unbound has not started, so ``awg-quick`` cannot resolve the peer endpoint. It
  spends about seventy seconds on its own retries and fails.
* ``rollback_apply`` recorded that failure by creating
  ``/var/db/gatebsd/vpn_disabled`` -- the marker that means *the operator turned
  the VPN off*. It survives a reboot, and every reader honours it: the watchdog
  skips its whole VPN section, the panel reports "VPN disabled by operator".
* The watchdog had no branch for "the VPN is wanted but is not in the default
  route" other than recovering from a rollback it had performed itself, so after
  a reboot -- where that flag starts out false -- nothing ever retried.

The three compose into: every boot that loses the race leaves the LAN routing in
clear until a human notices and runs ``gatewayctl apply`` by hand.

Every test here runs the real scripts. Each guard is paired with a
reintroduction that patches the defect back into a copy and asserts the old
behaviour returns, because a test that only reads the source passes just as
happily when the call it checks for sits behind ``if false``.
"""
from __future__ import annotations

import grp
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATEWAYCTL = ROOT / "sbin" / "gatewayctl"

STAT_STUB = """#!/bin/sh
if /usr/bin/stat -f '%u' / >/dev/null 2>&1; then
  exec /usr/bin/stat "$@"
fi
if [ "$1" = -f ]; then
  format=$2
  shift 2
  case "$format" in
    '%u') exec /usr/bin/stat -c '%u' "$@" ;;
    '%Lp') exec /usr/bin/stat -c '%a' "$@" ;;
    '%z') exec /usr/bin/stat -c '%s' "$@" ;;
    *) exit 2 ;;
  esac
fi
exec /usr/bin/stat "$@"
"""

LOCKF_STUB = """#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    -t) shift 2 ;;
    -k|-s|-n|-w|-T) shift ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
shift
exec "$@"
"""

WAN_IF = "ng0"
WAN_GW = "192.0.2.1"
VPN_IF = "awg0"


def a_non_root_group() -> str:
    """A real group on this host that is not root's."""
    for entry in grp.getgrall():
        if entry.gr_gid not in (0,):
            return entry.gr_name
    raise unittest.SkipTest("need a non-root group to observe re-owning")


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class GatewayctlHarness(unittest.TestCase):
    """Drives the real ``sbin/gatewayctl`` against stubbed system commands."""

    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("gatewayctl refuses to mutate routing as non-root")
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "calls.log"

        self.run_dir = self.root / "run"
        self.run_dir.mkdir(mode=0o750)
        self.db_dir = self.root / "db"
        self.db_dir.mkdir(mode=0o750)
        self.service_group = a_non_root_group()
        # Both directories start out as the package's post-install leaves them:
        # group-readable by the unprivileged service account that runs the UI.
        gid = grp.getgrnam(self.service_group).gr_gid
        os.chown(self.run_dir, 0, gid)
        os.chown(self.db_dir, 0, gid)

        self.flag = self.db_dir / "vpn_disabled"

        self.conf = self.root / "gateway.conf"
        self.conf.write_text(
            "\n".join(
                [
                    f'WAN_IF="{WAN_IF}"',
                    'BACKUP_IF="ue0"',
                    'LAN_IF="re1"',
                    f'VPN_IF="{VPN_IF}"',
                    'VPN_ENDPOINT_HOST="vpn.example.net"',
                    "",
                ]
            ),
            encoding="ascii",
        )
        os.chown(self.conf, 0, 0)
        self.conf.chmod(0o600)

        self._write("lockf", LOCKF_STUB)
        self._write("stat", STAT_STUB)
        self._write("logger", "#!/bin/sh\nexit 0\n")
        self._write("pfctl", "#!/bin/sh\nexit 0\n")
        self._write("ping", "#!/bin/sh\nexit 0\n")
        self._write("sleep", "#!/bin/sh\nexit 0\n")
        # The VPN interface does not exist yet; the WAN one is up with a peer,
        # which is what `pppoe_gw` parses the gateway out of.
        self._write(
            "ifconfig",
            f"""#!/bin/sh
printf 'ifconfig %s\\n' "$*" >> {self.calls}
case "$1" in
  {WAN_IF})
    echo "{WAN_IF}: flags=88d1<UP,POINTOPOINT,RUNNING> mtu 1492"
    echo "\tinet 203.0.113.9 --> {WAN_GW} netmask 0xffffffff"
    ;;
  *) exit 1 ;;
esac
""",
        )
        self._write(
            "route",
            f"""#!/bin/sh
printf 'route %s\\n' "$*" >> {self.calls}
echo "   interface: {WAN_IF}"
echo "     gateway: {WAN_GW}"
exit 0
""",
        )
        self._write("awg", "#!/bin/sh\nexit 1\n")
        self._write(
            "awg-quick",
            f"""#!/bin/sh
printf 'awg-quick %s\\n' "$*" >> {self.calls}
exit 0
""",
        )
        self.set_endpoint_resolvable(False)

        for name in (
            "install", "mktemp", "date", "cat", "awk", "sed", "id", "rm",
            "chmod", "mv", "head", "tr", "dirname", "grep", "printf", "env",
        ):
            real = shutil.which(name)
            if real:
                (self.bin / name).symlink_to(real)

        self.script = GATEWAYCTL

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def set_endpoint_resolvable(self, resolvable: bool) -> None:
        """Stub the route helper. ``endpoint-ip`` is the resolver gatewayctl uses."""
        answer = "echo 198.51.100.7" if resolvable else "exit 1"
        self._write(
            "gatebsd-route-op",
            f"""#!/bin/sh
printf 'route-op %s\\n' "$*" >> {self.calls}
case "$1" in
  endpoint-ip) {answer} ;;
  *) exit 0 ;;
esac
""",
        )

    def use_patched_copy(self, old: str, new: str) -> None:
        """Reintroduce a defect: run a copy of the script with ``old`` restored."""
        source = GATEWAYCTL.read_text(encoding="utf-8")
        self.assertIn(new, source, "the guard under test is no longer in the script")
        patched = self.root / "gatewayctl.patched"
        patched.write_text(source.replace(new, old), encoding="utf-8")
        patched.chmod(0o755)
        self.script = patched

    def run_ctl(self, action: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin",
            # gatewayctl fixes its own PATH on line one; this is the hook
            # that lets the stubs above be the commands it actually runs.
            "GATEBSD_PATH": f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.root),
            "LANG": "C",
            # Skip the re-exec through lockf: it runs `env -i PATH="$PATH"` and
            # the child immediately reassigns PATH from its own default, so the
            # stubs above are only in effect in the first process.
            "GATEBSD_GATEWAY_LOCK_HELD": "1",
            "GATEBSD_PF_LOCK_HELD": "1",
            "GATEBSD_GATEWAY_CONF": str(self.conf),
            "GATEBSD_GATEWAY_LOCK_FILE": str(self.run_dir / "gatewayctl.lock"),
            "GATEBSD_PF_LOCK_FILE": str(self.root / "pf.lock"),
            "GATEBSD_WATCHDOG_STATE": str(self.run_dir / "watchdog.json"),
            "GATEBSD_VPN_DISABLED_FLAG": str(self.flag),
            "GATEBSD_ROUTE_HELPER": str(self.bin / "gatebsd-route-op"),
            "GATEBSD_STATE_READER": str(ROOT / "sbin" / "gatebsd-state-value"),
            "GATEBSD_PYTHON_LAUNCHER": shutil.which("python3") or shutil.which("python3.12") or shutil.which("python3.11") or "python3",
            "VPN_ENDPOINT_WAIT": "0",
            "VPN_HANDSHAKE_WAIT": "1",
        }
        env.update(overrides)
        return subprocess.run(
            ["sh", str(self.script), action],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def call_log(self) -> str:
        return self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""


class PortForwardReconcile(GatewayctlHarness):
    def _install_helper(self) -> None:
        self._write(
            "gatebsd-port-forward",
            f"#!/bin/sh\nprintf 'port-forward %s\\n' \"$*\" >> {self.calls}\nexit 0\n",
        )
        self._write(
            "ifconfig",
            f"""#!/bin/sh
case "$1" in
  {WAN_IF})
    echo "{WAN_IF}: flags=88d1<UP,POINTOPOINT,RUNNING> mtu 1492"
    echo "\tinet 203.0.113.9 --> {WAN_GW} netmask 0xffffffff"
    ;;
  {VPN_IF})
    echo "{VPN_IF}: flags=88d1<UP,POINTOPOINT,RUNNING> mtu 1420"
    ;;
  *) exit 1 ;;
esac
""",
        )

    def test_apply_reconciles_the_current_wan_gateway(self) -> None:
        self._install_helper()
        self.set_endpoint_resolvable(True)

        self.run_ctl(
            "apply",
            GATEBSD_PORT_FORWARD_RECONCILE=str(self.bin / "gatebsd-port-forward"),
        )

        self.assertIn(f"port-forward reconcile --gateway {WAN_GW}", self.call_log())

    def test_removing_the_reconcile_call_restores_the_stale_gateway_defect(self) -> None:
        self._install_helper()
        self.set_endpoint_resolvable(True)
        self.use_patched_copy(
            old="",
            new='    reconcile_port_forwards || { rollback_apply "port-forward reconcile failed"; return 1; }\n',
        )

        self.run_ctl(
            "apply",
            GATEBSD_PORT_FORWARD_RECONCILE=str(self.bin / "gatebsd-port-forward"),
        )

        self.assertNotIn("port-forward reconcile", self.call_log())


class FailedApplyDoesNotLookLikeOperatorIntent(GatewayctlHarness):
    def test_a_failed_apply_leaves_the_disabled_marker_alone(self) -> None:
        result = self.run_ctl("apply")

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(
            self.flag.exists(),
            "a transient apply failure must not be recorded as 'the operator "
            "disabled the VPN' -- that marker survives the reboot and stops "
            "every retry there is",
        )

    def test_reintroduced_the_failed_apply_disables_the_vpn_for_good(self) -> None:
        self.use_patched_copy(
            old=(
                'default_via_wan || log "CRITICAL: failed to restore WAN default"\n'
                '    persist_vpn_disabled yes || log "CRITICAL: failed to persist disabled marker"'
            ),
            new='default_via_wan || log "CRITICAL: failed to restore WAN default"',
        )

        result = self.run_ctl("apply")

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue(
            self.flag.exists(),
            "the reintroduction did not reproduce the defect, so the guard "
            "above is not measuring anything",
        )

    def test_down_still_records_operator_intent(self) -> None:
        """Removing the marker from the failure path must not disarm `down`."""
        result = self.run_ctl("down")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(
            self.flag.exists(),
            "an explicit `gatewayctl down` is the operator turning the VPN off "
            "and must still be remembered across a reboot",
        )

    def test_the_shutdown_teardown_does_not_decide_the_next_boot(self) -> None:
        """`service gatewayctl_apply stop` also runs on the way to halt.

        Taking the `down` path there wrote the operator's marker on every clean
        shutdown, so the router came back up with the VPN already declared off
        and nothing on the device retried it.
        """
        result = self.run_ctl("teardown")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(
            self.flag.exists(),
            "halting the router says nothing about how it should route once it "
            "is back",
        )

    def test_the_rc_stop_path_uses_the_teardown_action(self) -> None:
        rc_script = (ROOT / "rc.d" / "gatewayctl_apply").read_text(encoding="utf-8")
        stop_block = rc_script.split("gatewayctl_apply_stop()", 1)[1].split(
            "gatewayctl_apply_status()", 1
        )[0]
        self.assertIn("gatewayctl teardown", stop_block)
        self.assertNotIn("gatewayctl down", stop_block)


class EndpointIsResolvedBeforeTheTunnelIsStarted(GatewayctlHarness):
    def test_awg_quick_is_not_called_while_the_endpoint_does_not_resolve(self) -> None:
        result = self.run_ctl("apply")

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn(
            "awg-quick up",
            self.call_log(),
            "awg-quick has no resolver timeout of its own: called too early it "
            "burns ~70s and leaves a half-created interface behind",
        )

    def test_reintroduced_awg_quick_is_called_into_an_unresolvable_endpoint(self) -> None:
        self.use_patched_copy(
            old="        log \"bringing up $VPN_IF\"",
            new=(
                "        endpoint_resolvable || {\n"
                "            log \"VPN endpoint ${VPN_ENDPOINT_HOST:-unset} does not resolve yet;"
                " not starting $VPN_IF\" >&2\n"
                "            return 1\n"
                "        }\n"
                "        log \"bringing up $VPN_IF\""
            ),
        )

        self.run_ctl("apply")

        self.assertIn(
            "awg-quick up",
            self.call_log(),
            "the reintroduction did not reproduce the defect",
        )

    def test_a_resolvable_endpoint_still_starts_the_tunnel(self) -> None:
        """The gate must not refuse anything that could have worked."""
        self.set_endpoint_resolvable(True)

        self.run_ctl("apply")

        self.assertIn("awg-quick up", self.call_log())


class RebuildKeepsDnsReachable(GatewayctlHarness):
    """A rebuild must not leave DNS routed to the interface it just destroyed."""

    def setUp(self) -> None:
        super().setUp()
        # Rebuild only tears down an interface that exists.  Keep both the WAN
        # and the currently active VPN visible to the real script.
        self._write(
            "ifconfig",
            f"""#!/bin/sh
printf 'ifconfig %s\\n' "$*" >> {self.calls}
case "$1" in
  {WAN_IF})
    echo "{WAN_IF}: flags=88d1<UP,POINTOPOINT,RUNNING> mtu 1492"
    echo "\tinet 203.0.113.9 --> {WAN_GW} netmask 0xffffffff"
    ;;
  {VPN_IF})
    echo "{VPN_IF}: flags=10080c1<UP,RUNNING,NOARP> mtu 1280"
    echo "\tinet 10.8.1.11 netmask 0xffffffff"
    ;;
  *) exit 1 ;;
esac
""",
        )

    def test_transient_wan_default_precedes_tunnel_teardown(self) -> None:
        self.set_endpoint_resolvable(True)

        self.run_ctl("rebuild")

        calls = self.call_log().splitlines()
        wan_default = next(i for i, line in enumerate(calls) if "route-op set-default-gw" in line)
        teardown = next(i for i, line in enumerate(calls) if "awg-quick down" in line)
        self.assertLess(wan_default, teardown, calls)

    def test_reintroduced_teardown_first_restores_the_dns_dead_end(self) -> None:
        self.set_endpoint_resolvable(True)
        self.use_patched_copy(
            old="",
            new=(
                '    default_via_wan || {\n'
                '        log "cannot establish a transient WAN default; leaving $VPN_IF intact" >&2\n'
                '        return 1\n'
                '    }\n'
            ),
        )

        self.run_ctl("rebuild")

        calls = self.call_log().splitlines()
        teardown = next(i for i, line in enumerate(calls) if "awg-quick down" in line)
        wan_default = next(i for i, line in enumerate(calls) if "route-op set-default-gw" in line)
        self.assertLess(teardown, wan_default, calls)


class SharedDirectoriesAreNotReOwned(GatewayctlHarness):
    """`/var/db/gatebsd` and `/var/run/gatebsd` belong to the whole product.

    ``install -d -o root -g wheel`` re-applies owner and group to a directory
    that already exists. Both of gatewayctl's calls pointed at directories the
    UI must reach as an unprivileged user, so every apply -- including the
    automatic one on the boot path -- locked the admin panel out with
    "agent unavailable" until someone put the group back by hand.
    """

    def test_apply_does_not_change_the_group_of_the_state_directory(self) -> None:
        before = self.db_dir.stat().st_gid

        self.run_ctl("down")  # `down` is the shortest path to persist_vpn_disabled

        self.assertTrue(self.flag.exists())
        self.assertEqual(
            self.db_dir.stat().st_gid,
            before,
            "the UI reads its own credentials from this directory as the "
            "service account; re-owning it to wheel locks it out",
        )

    def test_reintroduced_the_state_directory_is_re_owned_to_wheel(self) -> None:
        self.use_patched_copy(
            old='install -d -o root -g wheel -m 0750 "$_dir"',
            new='ensure_shared_dir "$_dir" gatebsd:gatebsd || return 1',
        )
        before = self.db_dir.stat().st_gid

        self.run_ctl("down")

        self.assertNotEqual(
            self.db_dir.stat().st_gid,
            before,
            "the reintroduction did not reproduce the defect",
        )


if __name__ == "__main__":
    unittest.main()


class EndpointWaitIsMeasuredInSeconds(GatewayctlHarness):
    """The endpoint budget must mean seconds, because it says seconds.

    It used to count iterations of the polling loop, and an iteration is not a
    second: it is one resolver call -- which can sit in a timeout of its own --
    plus the sleep. Measured on the production router 2026-07-31 with the budget
    set to 20, the real wait was 88 seconds. The name, the comment and the range
    check all said seconds; only the arithmetic disagreed, and the operator
    reading the setting had no way to see it.

    That mattered because of what came next: the boot-path apply gave up, and
    nothing retried until the watchdog's following tick. Halt 10:11:42, apply
    10:14:13, resolver gave up 10:15:41, tunnel in the path 10:17:37 -- six
    minutes with the LAN in the clear, none of it a failure.
    """

    def slow_unresolvable_endpoint(self, seconds: int) -> None:
        self._write(
            "gatebsd-route-op",
            f"""#!/bin/sh
printf 'route-op %s\\n' "$*" >> {self.calls}
case "$1" in
  endpoint-ip) /bin/sleep {seconds}; exit 1 ;;
  *) exit 0 ;;
esac
""",
        )

    def test_a_slow_resolver_does_not_multiply_the_budget(self) -> None:
        self.slow_unresolvable_endpoint(2)

        started = time.monotonic()
        result = self.run_ctl("apply", VPN_ENDPOINT_WAIT="3")
        elapsed = time.monotonic() - started

        self.assertNotEqual(result.returncode, 0, "an unresolvable endpoint must fail")
        # Counting iterations would spend 3 x (2s resolver + 1s sleep) here.
        self.assertLess(
            elapsed, 6.0,
            f"a 3-second budget took {elapsed:.1f}s: the loop is counting attempts, not seconds",
        )
        self.assertGreaterEqual(
            elapsed, 3.0,
            f"a 3-second budget gave up after {elapsed:.1f}s: it is not being honoured",
        )

    def test_the_wait_it_actually_spent_is_logged(self) -> None:
        """Six minutes were lost once because nobody could see this number."""
        self.slow_unresolvable_endpoint(1)
        result = self.run_ctl("apply", VPN_ENDPOINT_WAIT="2")
        self.assertIn("did not resolve within 2s", result.stdout + result.stderr)
        self.assertIn("waited", result.stdout + result.stderr)

    def test_a_zero_budget_still_asks_once(self) -> None:
        """Several callers mean "try, do not wait", and must keep getting that."""
        self.set_endpoint_resolvable(False)
        started = time.monotonic()
        self.run_ctl("apply", VPN_ENDPOINT_WAIT="0")
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 3.0, f"a zero budget waited {elapsed:.1f}s")
        self.assertIn("endpoint-ip", self.call_log())


class TheNextHopIsAFieldNotALineShape(GatewayctlHarness):
    """`inet ... -->` also describes the outer line of an encapsulating link.

    ``gif``, ``gre`` and point-to-point WWAN links print their tunnel endpoints
    one line above the address::

        tunnel inet 198.18.20.2 --> 198.18.20.9
            inet 203.0.113.9 --> 192.0.2.1 netmask 0xffffffff

    A pattern that only asks for the shape stops on the first of those, where
    the fourth field is the arrow. ``ng0`` prints no such line, which is why
    this never showed in the field; the rig showed it immediately, and 0.2
    plans a point-to-point backup on ``umb0``. Same defect in
    ``gatebsd-watchdog.sh`` and ``ru-routes.sh``; covered there too.
    """

    def use_encapsulating_wan(self) -> None:
        self._write(
            "ifconfig",
            f"""#!/bin/sh
printf 'ifconfig %s\\n' "$*" >> {self.calls}
case "$1" in
  {WAN_IF})
    echo "{WAN_IF}: flags=88d1<UP,POINTOPOINT,RUNNING> mtu 1492"
    echo "\ttunnel inet 198.18.20.2 --> 198.18.20.9"
    echo "\tinet 203.0.113.9 --> {WAN_GW} netmask 0xffffffff"
    ;;
  *) exit 1 ;;
esac
""",
        )

    def test_status_reports_the_next_hop_of_an_encapsulating_link(self) -> None:
        self.use_encapsulating_wan()
        result = self.run_ctl("status")
        self.assertIn(f"pppoe  : {WAN_GW}", result.stdout, result.stdout)

    def test_reintroducing_the_unanchored_parse_loses_the_next_hop(self) -> None:
        self.use_encapsulating_wan()
        self.use_patched_copy(
            old="""awk '/inet / && /-->/ { print $4; exit }'""",
            new="""awk '$1 == "inet" && $3 == "-->" { print $4; exit }'""",
        )
        result = self.run_ctl("status")
        self.assertIn("pppoe  : \n", result.stdout + "\n", result.stdout)
        self.assertNotIn(
            f"pppoe  : {WAN_GW}",
            result.stdout,
            "the defect did not reproduce: the gateway survived the tunnel line",
        )


class BootPathGetsItsOwnBudget(unittest.TestCase):
    """rc.d/gatewayctl_apply daemonises the work, so waiting there is free.

    Static, like the other rc.d checks: running an rc script needs /etc/rc.subr
    and the real service framework. The behaviour that can be run is covered
    above, against gatewayctl itself.
    """

    def setUp(self) -> None:
        self.text = (ROOT / "rc.d" / "gatewayctl_apply").read_text(encoding="utf-8")
        self.code = "\n".join(
            line for line in self.text.splitlines() if not line.lstrip().startswith("#")
        )

    def test_the_budget_reaches_the_worker(self) -> None:
        self.assertIn('VPN_ENDPOINT_WAIT="$gatewayctl_apply_endpoint_wait"', self.code)

    def test_the_boot_budget_is_long_enough_for_pppoe_to_dial(self) -> None:
        match = re.search(r': \$\{gatewayctl_apply_endpoint_wait:="(\d+)"\}', self.code)
        self.assertIsNotNone(match, "the boot path has no endpoint budget of its own")
        assert match is not None
        self.assertGreaterEqual(
            int(match.group(1)), 120,
            "the endpoint cannot resolve until the WAN is up; a short budget here "
            "is how the tunnel came up two minutes late",
        )

    def test_the_budget_is_validated_like_the_others(self) -> None:
        self.assertIn("gatewayctl_apply_endpoint_wait", self.code.split("_validate_timeouts")[1])


class TunnelUpOnTheWanHarness(GatewayctlHarness):
    """The observed state: WAN and tunnel both up, default route on the WAN."""

    def setUp(self) -> None:
        super().setUp()
        self._write(
            "ifconfig",
            f"""#!/bin/sh
printf 'ifconfig %s\\n' "$*" >> {self.calls}
case "$1" in
  {WAN_IF})
    echo "{WAN_IF}: flags=88d1<UP,POINTOPOINT,RUNNING> mtu 1492"
    echo "\tinet 203.0.113.9 --> {WAN_GW} netmask 0xffffffff"
    ;;
  {VPN_IF})
    echo "{VPN_IF}: flags=10080c1<UP,RUNNING,NOARP> mtu 1280"
    echo "\tinet 10.8.1.11 netmask 0xffffffff"
    ;;
  *) exit 1 ;;
esac
""",
        )


class AutomaticRecoveryIsNotTheOperator(TunnelUpOnTheWanHarness):
    """The emergency bypass must not outlive the minute that needed it.

    Observed on the production router on 2026-08-04. ``gatewayctl apply``
    reported ``OK - internet via awg0`` at 00:01:23; automatic recovery took its
    own health probe five seconds later, read the settling window as a broken
    tunnel, and escalated to ``gatewayctl bypass``. That wrote
    ``/var/db/gatebsd/vpn_disabled`` -- the marker that means *the operator
    turned the VPN off*.

    From then on nothing retried: the watchdog skips its whole VPN section while
    the marker is set, and ``recover_internet`` calls any default route
    "preferred" in the same condition, so ``/api/internet/repair`` answered
    "Internet is working normally" with the tunnel out of the path. The marker
    survived the 02:18 reboot. The household ran in the clear for two and a half
    hours, and the customer's own conclusion was that the router's VPN was
    broken.

    Recovery buys connectivity for the next minute. It is not a person, and it
    is not entitled to the marker.
    """

    def test_the_transient_bypass_leaves_the_marker_alone(self) -> None:
        result = self.run_ctl("bypass-transient")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(
            self.flag.exists(),
            "an automatic escalation must not be recorded as operator intent: "
            "the marker survives a reboot and stops every retry there is",
        )

    def test_an_operator_bypass_still_records_intent(self) -> None:
        """Splitting the verb must not disarm the one a human types."""
        result = self.run_ctl("bypass")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(
            self.flag.exists(),
            "`gatewayctl bypass` from an operator's hands is still a statement "
            "about how the router should route until told otherwise",
        )

    def test_reintroduced_the_transient_bypass_disables_the_vpn_for_good(self) -> None:
        self.use_patched_copy(
            old="if ! persist_vpn_disabled yes; then",
            new='if [ "$_record_intent" = yes ] && ! persist_vpn_disabled yes; then',
        )

        result = self.run_ctl("bypass-transient")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(
            self.flag.exists(),
            "the reintroduction did not reproduce the defect, so the guard "
            "above is not measuring anything",
        )


class RecoveryEscalatesWithoutDisablingTheVpn(TunnelUpOnTheWanHarness):
    """`recover_internet` decides the verb; the real gatewayctl executes it.

    Nothing here reads a source file for a string. Recovery walks its own
    branches against stubbed probes, and whichever verb it picks is run as the
    actual script, so the marker on disk afterwards is the same evidence the
    production router gave.
    """

    def _drive_recovery(self) -> tuple[dict, list[list[str]]]:
        import sys

        sys.path.insert(0, str(ROOT / "webui" / "backend"))
        try:
            from gatebsd_ui import recovery as recovery_mod
            from gatebsd_ui.command import CommandResult
        finally:
            sys.path.pop(0)

        seen: list[list[str]] = []

        def fake_run(command, timeout=None, env=None, **kwargs):
            seen.append(list(command))

            def done(ok: bool, out: str = "") -> CommandResult:
                return CommandResult(command=list(command), ok=ok,
                                     returncode=0 if ok else 1, stdout=out, stderr="")

            name = Path(command[0]).name
            if name == "gatewayctl":
                proc = self.run_ctl(command[1])
                return CommandResult(command=list(command), ok=proc.returncode == 0,
                                     returncode=proc.returncode, stdout=proc.stdout,
                                     stderr=proc.stderr)
            if name == "ifconfig":
                proc = subprocess.run([str(self.bin / "ifconfig"), *command[1:]],
                                      capture_output=True, text=True, check=False)
                return done(proc.returncode == 0, proc.stdout)
            if name == "route":
                # The default is on the WAN: this is the state recovery is
                # called in, and the state it must not make permanent.
                return done(True, f"   interface: {WAN_IF}\n     gateway: {WAN_GW}\n")
            if name == "ping":
                return done(True)
            if name == "fetch":
                # The probe that failed on the router, seconds after the route
                # moved. Everything else answers.
                return done(False)
            return done(True, "ok")

        originals = {
            "run": recovery_mod.run,
            "LOCK_PATH": recovery_mod.LOCK_PATH,
            "REPORT_PATH": recovery_mod.REPORT_PATH,
            "VPN_DISABLED": recovery_mod.VPN_DISABLED,
        }
        recovery_mod.run = fake_run
        recovery_mod.LOCK_PATH = self.run_dir / "internet-recovery.lock"
        recovery_mod.REPORT_PATH = self.root / "last-recovery.json"
        recovery_mod.VPN_DISABLED = self.flag
        try:
            _status, report = recovery_mod.recover_internet()
        finally:
            for key, value in originals.items():
                setattr(recovery_mod, key, value)
        return report, seen

    def test_the_emergency_exit_does_not_turn_the_vpn_off(self) -> None:
        report, seen = self._drive_recovery()

        verbs = [c[1] for c in seen if Path(c[0]).name == "gatewayctl"]
        self.assertIn("bypass-transient", verbs,
                      f"recovery never reached the emergency bypass: {report}")
        self.assertNotIn("bypass", verbs,
                         "the recording verb belongs to the operator, not to recovery")
        self.assertFalse(
            self.flag.exists(),
            "recovery disabled the VPN for good; the watchdog will now skip its "
            "whole VPN section and the panel will call the bare WAN healthy",
        )

    def test_reintroduced_the_escalation_leaves_the_vpn_off_for_good(self) -> None:
        """The 2026-08-04 incident, end to end."""
        self.use_patched_copy(
            old="if ! persist_vpn_disabled yes; then",
            new='if [ "$_record_intent" = yes ] && ! persist_vpn_disabled yes; then',
        )

        self._drive_recovery()

        self.assertTrue(
            self.flag.exists(),
            "the reintroduction did not reproduce the incident, so the guard "
            "above is not measuring anything",
        )
