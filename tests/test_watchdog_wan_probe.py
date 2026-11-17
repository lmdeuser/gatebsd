"""Functional regression tests for the per-link WAN health check.

The defect these exist for: ``PRIMARY_FIB``/``BACKUP_FIB`` selected routing
tables that nothing ever populated. mpd5 and dhclient install their routes into
FIB 0 only, so every ``setfib 1 ping`` left through a table containing nothing
but lo0. Both uplinks read as dead on a working line (243 consecutive failures
observed in the field), the site sat in PRIMARY_DEGRADED, and failover to the
backup could not run because it is gated on BACKUP_OK.

The harness therefore models routing tables rather than ping outcomes: ``route``
maintains one table per FIB with the kernel's own rules -- ``change`` fails when
the entry is absent, ``add`` fails when it is present, and installing a gateway
route fails with no on-link route to that next hop -- and ``ping``/``nc``
resolve their target through the table of the FIB they were run in. A watchdog
that does not populate a FIB gets "no route" from the probe, exactly as in
production.

Every test runs ``sbin/gatebsd-watchdog.sh``. The two reintroduction tests run a
*modified copy* of it, so the defect is re-created and executed rather than
asserted about the source text.
"""
from __future__ import annotations

import grp
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT / "sbin" / "gatebsd-watchdog.sh"

PRIMARY_IF = "ng0"
BACKUP_IF = "ue0"
VPN_IF = "awg0"
PRIMARY_SRC = "203.0.113.9"
PRIMARY_GW = "192.0.2.1"
BACKUP_SRC = "198.51.100.50"
BACKUP_GW = "198.51.100.1"
TARGETS = "203.0.113.101 203.0.113.102"

PRIMARY_FIB = 1
BACKUP_FIB = 2

# route(8) stub. One file per FIB, records of dest|gateway|interface.
ROUTE_STUB = r"""#!/bin/sh
FIB=${TESTFIB:-0}
TBL="$FIBDIR/fib$FIB"
[ -f "$TBL" ] || : > "$TBL"
printf 'route fib=%s %s\n' "$FIB" "$*" >> "$CALLS"

while [ $# -gt 0 ]; do
  case "$1" in -n|-q|-v|-d|-4|-6|-t) shift ;; *) break ;; esac
done
cmd=${1:-}; shift 2>/dev/null || true

lookup() { awk -F'|' -v d="$1" '$1==d {print $2 "|" $3; f=1} END{exit !f}' "$TBL"; }
drop() { awk -F'|' -v d="$1" '$1!=d' "$TBL" > "$TBL.new"; mv "$TBL.new" "$TBL"; }
upsert() {
  drop "$1"
  printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$TBL"
}

dest=; gw=; ifc=; mode=
while [ $# -gt 0 ]; do
  case "$1" in
    -host|-net) dest=$2; shift 2 ;;
    -iface|-interface) ifc=$2; mode=link; shift 2 ;;
    default) dest=default; shift ;;
    *) if [ -z "$dest" ]; then dest=$1; else gw=$1; fi; shift ;;
  esac
done

case "$cmd" in
  get)
    entry=$(lookup "$dest") || exit 1
    printf '    gateway: %s\n' "${entry%%|*}"
    printf '  interface: %s\n' "${entry##*|}"
    exit 0
    ;;
  add|change)
    if lookup "$dest" >/dev/null 2>&1; then exists=1; else exists=0; fi
    # The kernel refuses to change a route that is not there and to add one that
    # already is; the watchdog relies on that to stay idempotent.
    [ "$cmd" != change ] || [ "$exists" = 1 ] || exit 1
    [ "$cmd" != add ] || [ "$exists" = 0 ] || exit 1
    if [ "$mode" = link ]; then
      upsert "$dest" "$ifc" "$ifc"
      exit 0
    fi
    # A gateway route needs the next hop to be reachable on-link first. In a
    # fresh FIB it is not, which is why a bare `route add default <gw>` cannot
    # be the whole fix.
    nexthop=$(lookup "$gw") || exit 1
    upsert "$dest" "$gw" "${nexthop##*|}"
    exit 0
    ;;
  delete)
    lookup "$dest" >/dev/null 2>&1 || exit 1
    drop "$dest"
    exit 0
    ;;
esac
exit 0
"""

# Resolve a destination through the table of the current FIB, then consult the
# egress link's filtering policy. Shared by the ping and nc stubs.
PROBE_PRELUDE = r"""FIB=${TESTFIB:-0}
TBL="$FIBDIR/fib$FIB"
[ -f "$TBL" ] || : > "$TBL"
eval target=\${$#}
onlink=1
ifc=$(awk -F'|' -v d="$target" '$1==d {print $3; f=1} END{exit !f}' "$TBL") || {
  onlink=0
  ifc=$(awk -F'|' '$1=="default" {print $3; f=1} END{exit !f}' "$TBL") || exit 2
}
"""

PING_STUB = "#!/bin/sh\n" + PROBE_PRELUDE + r"""
printf 'ping fib=%s if=%s %s\n' "$FIB" "$ifc" "$target" >> "$CALLS"
if [ "$onlink" = 1 ]; then
  [ "$(cat "$FIBDIR/icmp_gw.$ifc" 2>/dev/null)" = 1 ] || exit 2
else
  [ "$(cat "$FIBDIR/icmp_net.$ifc" 2>/dev/null)" = 1 ] || exit 2
fi
exit 0
"""

NC_STUB = "#!/bin/sh\n" + PROBE_PRELUDE.replace(
    r"eval target=\${$#}", "eval port=\\${$#}\nshift $(($# - 2))\ntarget=$1"
) + r"""
printf 'nc fib=%s if=%s %s:%s\n' "$FIB" "$ifc" "$target" "$port" >> "$CALLS"
[ "$(cat "$FIBDIR/tcp_net.$ifc" 2>/dev/null)" = 1 ] || exit 1
exit 0
"""

LOCKF_STUB = r"""#!/bin/sh
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

STAT_STUB = r"""#!/bin/sh
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
"""


class ProbeHarness:
    """A watchdog environment whose routing tables are real state, not a mock."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.run = root / "run"
        self.db = root / "db"
        self.fibs = root / "fibs"
        self.log = root / "watchdog.log"
        self.calls = root / "calls.log"
        for path in (self.bin, self.run, self.db, self.fibs):
            path.mkdir(parents=True, exist_ok=True)
        self.run.chmod(0o750)
        self.state_file = self.run / "watchdog.json"
        self.script = WATCHDOG

    # -- construction ------------------------------------------------------
    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def fib_table(self, fib: int) -> dict[str, tuple[str, str]]:
        path = self.fibs / f"fib{fib}"
        if not path.exists():
            return {}
        table: dict[str, tuple[str, str]] = {}
        for line in path.read_text(encoding="ascii").splitlines():
            if not line:
                continue
            dest, gateway, iface = line.split("|")
            table[dest] = (gateway, iface)
        return table

    def _seed_fib(self, fib: int, rows: list[tuple[str, str, str]]) -> None:
        (self.fibs / f"fib{fib}").write_text(
            "".join(f"{d}|{g}|{i}\n" for d, g, i in rows), encoding="ascii"
        )

    def build(
        self,
        *,
        primary_up: bool = True,
        backup_up: bool = True,
        backup_fitted: bool = True,
        primary_icmp_net: bool = True,
        backup_icmp_net: bool = True,
        backup_tcp_net: bool = True,
        iterations: int = 2,
    ) -> None:
        # FIB 0: the live table. The default points at the VPN, which is the
        # whole reason a WAN check cannot simply use it.
        self._seed_fib(0, [("default", VPN_IF, VPN_IF)])
        # FIB 1 and FIB 2 start empty, exactly as the kernel leaves them.
        for fib in (PRIMARY_FIB, BACKUP_FIB):
            self._seed_fib(fib, [])

        # Link filtering policies. The backup carrier in the field answers on
        # its own gateway but drops echo to public addresses while forwarding
        # TCP -- the condition that keeps BACKUP_OK false under an ICMP-only
        # check.
        policies = {
            f"icmp_gw.{PRIMARY_IF}": primary_up,
            f"icmp_net.{PRIMARY_IF}": primary_up and primary_icmp_net,
            f"tcp_net.{PRIMARY_IF}": primary_up,
            f"icmp_gw.{BACKUP_IF}": backup_up,
            f"icmp_net.{BACKUP_IF}": backup_up and backup_icmp_net,
            f"tcp_net.{BACKUP_IF}": backup_up and backup_tcp_net,
            f"icmp_gw.{VPN_IF}": True,
            f"icmp_net.{VPN_IF}": True,
            f"tcp_net.{VPN_IF}": True,
        }
        for name, allowed in policies.items():
            (self.fibs / name).write_text("1" if allowed else "0", encoding="ascii")

        primary_inet = (
            f"\tinet {PRIMARY_SRC} --> {PRIMARY_GW} netmask 0xffffffff"
            if primary_up
            else ""
        )
        backup_inet = f"\tinet {BACKUP_SRC} netmask 0xffffff00" if backup_up else ""
        # "absent" and "present but down" are different facts and the stub
        # must be able to say either. ifconfig fails only for a missing NIC.
        backup_present = "yes" if backup_fitted else ""
        self._write(
            "ifconfig",
            f"""#!/bin/sh
case "$1" in
  {PRIMARY_IF})
    [ -n "{primary_inet}" ] || exit 1
    echo "{PRIMARY_IF}: flags=88d1<UP,POINTOPOINT,RUNNING> mtu 1492"
    printf '%s\\n' "{primary_inet}"
    ;;
  {BACKUP_IF})
    [ -n "{backup_present}" ] || exit 1
    echo "{BACKUP_IF}: flags=8843<UP,BROADCAST,RUNNING> mtu 1500"
    [ -z "{backup_inet}" ] || printf '%s\\n' "{backup_inet}"
    ;;
  {VPN_IF}) echo "{VPN_IF}: flags=80c1<UP,RUNNING> mtu 1420" ;;
  *) exit 1 ;;
esac
""",
        )
        if backup_up:
            (self.db / f"dhclient.leases.{BACKUP_IF}").write_text(
                f"lease {{\n  option routers {BACKUP_GW};\n}}\n", encoding="ascii"
            )

        self._write("route", ROUTE_STUB)
        self._write("ping", PING_STUB)
        self._write("nc", NC_STUB)
        self._write("setfib", '#!/bin/sh\nfib=$1\nshift\nTESTFIB=$fib exec "$@"\n')
        self._write("sysctl", '#!/bin/sh\n[ "$2" = net.fibs ] || exit 1\necho 3\n')
        self._write("awg", "#!/bin/sh\nnow=$(date +%s)\nprintf 'peerkey\\t%s\\n' \"$((now - 5))\"\n")
        for name in ("gatebsd-route-op", "gatewayctl", "ru-routes.sh", "service"):
            self._write(
                name,
                f'#!/bin/sh\nprintf \'{name} %s\\n\' "$*" >> "$CALLS"\nexit 0\n',
            )
        self._write("logger", "#!/bin/sh\nexit 0\n")
        self._write("unbound-control-setup", "#!/bin/sh\nexit 0\n")
        self._write("lockf", LOCKF_STUB)
        self._write("stat", STAT_STUB)
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
        for name in (
            "install", "mktemp", "date", "cat", "awk", "sed", "cmp", "sort",
            "id", "ps", "kill", "grep", "rm", "chmod", "mv", "head", "tr", "df",
        ):
            real = shutil.which(name)
            if real and not (self.bin / name).exists():
                (self.bin / name).symlink_to(real)

    # -- execution ---------------------------------------------------------
    def run_watchdog(self, *, tcp_port: str = "443", primary_fib: int = PRIMARY_FIB) -> subprocess.CompletedProcess[str]:
        conf = self.root / "failover.conf"
        conf.write_text(
            "\n".join(
                [
                    f'PRIMARY_IF="{PRIMARY_IF}"',
                    f'BACKUP_IF="{BACKUP_IF}"',
                    f'VPN_IF="{VPN_IF}"',
                    'FAILOVER_MODE="automatic"',
                    f'CHECK_TARGETS="{TARGETS}"',
                    f'CHECK_TCP_PORT="{tcp_port}"',
                    f'PRIMARY_FIB="{primary_fib}"',
                    f'BACKUP_FIB="{BACKUP_FIB}"',
                    'FAIL_THRESHOLD="1"',
                    'RECOVERY_THRESHOLD="1"',
                    'MIN_BACKUP_HOLD="0"',
                    'SWITCH_COOLDOWN="0"',
                    'CHECK_INTERVAL="0"',
                    'PING_TIMEOUT="1"',
                    'VPN_HANDSHAKE_MAX="180"',
                    'VPN_NET_FAIL_THRESHOLD="1"',
                    "",
                ]
            ),
            encoding="ascii",
        )
        conf.chmod(0o600)
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "FIBDIR": str(self.fibs),
            "CALLS": str(self.calls),
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
            "GATEBSD_DHCLIENT_LEASE_DIR": str(self.db),
            "RU_TABLE": str(self.root / "ru.table"),
            "RU_STATE_FILE": str(self.db / "ru-routes.applied"),
            "EVENT_LOG": str(self.log),
            "HOME": str(self.root),
            "LANG": "C",
        }
        return subprocess.run(
            ["sh", str(self.script)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def reintroduce(self, pattern: str, replacement: str) -> None:
        """Run a copy of the watchdog with the fix edited back out.

        The point of the copy is that the regression is *executed*: an earlier
        generation of these tests read the source text and passed happily with
        the call under test sitting behind `if false`.
        """
        source = WATCHDOG.read_text(encoding="utf-8")
        patched, count = re.subn(pattern, replacement, source)
        if count == 0:
            raise AssertionError(f"reintroduction pattern never matched: {pattern!r}")
        self.script = self.root / "watchdog-defective.sh"
        self.script.write_text(patched, encoding="utf-8")
        self.script.chmod(0o755)

    def state(self) -> dict:
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def call_log(self) -> str:
        return self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
class WanProbeFibTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = ProbeHarness(Path(self._tmp.name))
        if os.getuid() != 0:
            self.skipTest("watchdog requires a root-owned run directory")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # -- the fix -----------------------------------------------------------
    def test_link_check_populates_its_own_fib_and_sees_the_link(self) -> None:
        self.harness.build()
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertTrue(state["primary_ok"], state)
        self.assertEqual(state["primary_failures"], 0, state)
        self.assertEqual(state["state"], "PRIMARY", state)

        table = self.harness.fib_table(PRIMARY_FIB)
        self.assertIn("default", table, "the check must install its own default")
        self.assertEqual(table["default"], (PRIMARY_GW, PRIMARY_IF), table)
        self.assertIn(PRIMARY_GW, table, "the next hop needs an on-link route first")

    def test_probe_leaves_through_the_fib_it_was_told_to_use(self) -> None:
        """Not the system default: FIB 0 still points at the VPN throughout."""
        self.harness.build()
        self.harness.run_watchdog()

        for line in self.harness.call_log().splitlines():
            if line.startswith("ping fib=1"):
                self.assertIn(f"if={PRIMARY_IF}", line, line)
            if line.startswith("ping fib=2"):
                self.assertIn(f"if={BACKUP_IF}", line, line)
        self.assertEqual(self.harness.fib_table(0), {"default": (VPN_IF, VPN_IF)})

    def test_fib_zero_is_never_written_by_the_health_check(self) -> None:
        """A misconfigured FIB 0 must not turn the probe into a route change."""
        self.harness.build()
        self.harness.run_watchdog(primary_fib=0)

        self.assertEqual(
            self.harness.fib_table(0),
            {"default": (VPN_IF, VPN_IF)},
            "the live routing table must be left alone",
        )
        for line in self.harness.call_log().splitlines():
            if line.startswith("route fib=0"):
                self.assertRegex(line, r"route fib=0 -n get ", line)

    def test_default_is_withdrawn_when_the_link_goes_away(self) -> None:
        self.harness.build(primary_up=False)
        self.harness.run_watchdog()

        self.assertNotIn(
            "default",
            self.harness.fib_table(PRIMARY_FIB),
            "a stale default would answer for a link that is gone",
        )
        self.assertFalse(self.harness.state()["primary_ok"])

    # -- reintroduction ----------------------------------------------------
    def test_reintroducing_the_unpopulated_fib_breaks_the_check(self) -> None:
        """The defect itself: probe in a FIB nobody fills.

        This runs a copy of the watchdog with the convergence call removed from
        check_iface, which is precisely the state the script shipped in.
        """
        self.harness.build()
        self.harness.reintroduce(
            r'    sync_fib_default "\$iface" "\$fib" "\$gw" \|\| return 1\n',
            "",
        )
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertFalse(state["primary_ok"], state)
        self.assertFalse(state["backup_ok"], state)
        self.assertGreater(state["primary_failures"], 0, state)
        self.assertEqual(state["state"], "PRIMARY_DEGRADED", state)
        self.assertEqual(self.harness.fib_table(PRIMARY_FIB), {})

    def test_reintroducing_the_single_step_route_install_breaks_the_check(self) -> None:
        """Installing only the default is not enough in a fresh FIB.

        Without an on-link route to the next hop the kernel answers ENETUNREACH,
        so the shortcut fix -- one `route add default <gw>` -- leaves the table
        as empty as before.
        """
        self.harness.build()
        self.harness.reintroduce(
            r'    run_in_fib "\$_sf_fib" route change -host .*\n'
            r'        \|\| run_in_fib "\$_sf_fib" route add -host .*\n'
            r"        \|\| true\n",
            "",
        )
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertFalse(state["primary_ok"], state)
        self.assertNotIn("default", self.harness.fib_table(PRIMARY_FIB))


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
class BackupLinkIcmpFilterTests(unittest.TestCase):
    """The backup carrier forwards TCP but drops echo to public addresses."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = ProbeHarness(Path(self._tmp.name))
        if os.getuid() != 0:
            self.skipTest("watchdog requires a root-owned run directory")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_backup_behind_an_icmp_filter_is_still_healthy(self) -> None:
        self.harness.build(backup_icmp_net=False, backup_tcp_net=True)
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertTrue(state["backup_ok"], state)
        self.assertEqual(state["backup_failures"], 0, state)
        self.assertIn(f"nc fib={BACKUP_FIB}", self.harness.call_log())

    def test_failover_reaches_the_backup_when_only_tcp_answers(self) -> None:
        """What the field could never verify: an actual switch to ue0."""
        self.harness.build(primary_up=False, backup_icmp_net=False, iterations=3)
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertEqual(state["active_wan"], "backup", state)
        self.assertEqual(state["state"], "BACKUP", state)
        self.assertIn("switch-underlay", self.harness.call_log())

    def test_a_genuinely_dead_backup_is_still_dead(self) -> None:
        """The fallback must not turn every link into a healthy one.

        This also pins a crash the fallback work uncovered: with no primary and
        no DHCP lease for the backup, `backup_gw` ran awk on a file that does not
        exist. awk exits 2, `2>/dev/null` hides the message but not the status,
        and FreeBSD /bin/sh aborts the whole daemon on the assignment -- so the
        watchdog died silently and wrote no state at all, at the moment both
        links were down. The existing contract test could not see it: it reads
        the function's source for `return 0`, which is present and unreachable.
        """
        self.harness.build(primary_up=False, backup_up=False, iterations=3)
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertFalse(state["backup_ok"], state)
        self.assertFalse(state["primary_ok"], state)
        self.assertNotIn("switch-underlay", self.harness.call_log())

    # -- reintroduction ----------------------------------------------------
    def test_reintroducing_icmp_only_probing_hides_the_backup(self) -> None:
        """With the TCP fallback off, the usable backup reads as dead.

        This is the state the watchdog shipped in, and the reason failover to
        ue0 had never once been exercised: the automatic branch requires
        BACKUP_OK, which an echo-only probe can never set on this carrier.
        """
        self.harness.build(primary_up=False, backup_icmp_net=False, iterations=3)
        self.harness.run_watchdog(tcp_port="0")

        state = self.harness.state()
        self.assertFalse(state["backup_ok"], state)
        self.assertEqual(state["state"], "PRIMARY_DEGRADED", state)
        self.assertNotIn("switch-underlay", self.harness.call_log())


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
class AbsentBackupIsNotAFault(unittest.TestCase):
    """A device delivered with one uplink is a supported product.

    ``BACKUP_IF`` defaults to ue0, and on a machine that has no such interface
    every tick counted a failure for it. backup_failures climbed without bound
    and the panel showed the spare link permanently red with a five-figure
    error count. Nothing was wrong; nothing was fitted. An alarm that is always
    on is one nobody reads when it finally means something.

    "Absent" and "present but down" have to stay distinguishable, so both are
    tested here: a real backup that is failing must still be counted.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = ProbeHarness(Path(self._tmp.name))
        if os.getuid() != 0:
            self.skipTest("watchdog requires a root-owned run directory")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_a_missing_backup_interface_is_reported_as_not_fitted(self) -> None:
        self.harness.build(backup_fitted=False, iterations=4)
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertIs(state["backup_fitted"], False, state)
        self.assertIs(state["backup_ok"], False, state)
        self.assertEqual(
            state["backup_failures"], 0,
            "an interface that is not fitted cannot fail; the counter must stay truthful",
        )

    def test_a_fitted_backup_that_is_down_is_still_counted(self) -> None:
        """The counter has to keep meaning something for a real spare link."""
        self.harness.build(backup_fitted=True, backup_up=False, iterations=4)
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertIs(state["backup_fitted"], True, state)
        self.assertIs(state["backup_ok"], False, state)
        self.assertGreater(
            state["backup_failures"], 0,
            "a spare link that is fitted and dead is a fault and must be counted",
        )

    def test_the_absence_is_said_once_not_every_tick(self) -> None:
        self.harness.build(backup_fitted=False, iterations=4)
        self.harness.run_watchdog()

        text = self.harness.log.read_text(encoding="utf-8") if self.harness.log.exists() else ""
        self.assertEqual(
            text.count("no backup interface fitted"), 1,
            f"said {text.count('no backup interface fitted')} times across four ticks",
        )
