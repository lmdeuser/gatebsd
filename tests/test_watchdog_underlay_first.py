"""The tick judges the ground before it judges what is carried over it.

The defect these exist for was caught in production on 1 August. The primary
PPPoE died; the VPN section ran before the underlay section, read the internet
check failing through ``awg0``, and concluded the *tunnel* was broken. It spent
45 seconds rolling a healthy tunnel back to a WAN that no longer had a gateway,
the rollback failed for exactly that reason, and the underlay switch that
finally ran inherited a half-applied route set and failed too::

    09:32:39  fib 1: ng0 has no gateway; default withdrawn
    09:32:54  ALERT: internet check failed 3 times via awg0, rolling back
    09:33:39  ERROR: VPN rollback transaction failed
    09:35:26  route transaction failed while switching to backup; retained primary

Three separate facts are asserted here, each with the defect re-created and
*executed* rather than read out of the source: the section order, the settling
window that keeps the freshly moved underlay from being blamed on the tunnel,
and the refusal to hand out the gateway of a link that is no longer running.
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

# Link states the stub can express. "down_but_addressed" is the one that
# matters: `ifconfig ng0 down` leaves the address and its peer in place, so a
# gateway read out of that line looks alive and routes nowhere.
UP = "up"
DOWN_BUT_ADDRESSED = "down_but_addressed"
ABSENT = "absent"


class Harness:
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
        self.script = WATCHDOG

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def build(
        self,
        *,
        primary: str = UP,
        backup: str = UP,
        vpn_up: bool = True,
        handshake_age: int = 6000,
        iterations: int = 2,
        primary_encapsulated: bool = False,
        primary_reachable: bool = False,
    ) -> None:
        # An interface that is down keeps its flags line and its address; only
        # UP and RUNNING go away. That is the whole trap being modelled.
        def iface_case(name: str, state: str, inet: str, flags_up: str, above: str = "") -> str:
            if state == ABSENT:
                return f'  {name}) exit 1 ;;'
            flags = flags_up if state == UP else flags_up.replace("UP,", "").replace(",RUNNING", "")
            lines = ([above] if above else []) + [inet]
            body = "".join(f"    printf '%s\\n' \"{line}\"\n" for line in lines)
            return (
                f'  {name})\n'
                f'    echo "{name}: flags=8843<{flags}> mtu 1500"\n'
                f'{body}'
                f'    ;;'
            )

        self._write(
            "ifconfig",
            "#!/bin/sh\ncase \"$1\" in\n"
            + iface_case(
                PRIMARY_IF,
                primary,
                f"\tinet {PRIMARY_SRC} --> {PRIMARY_GW} netmask 0xffffffff",
                "UP,POINTOPOINT,RUNNING,SIMPLEX",
                # What an encapsulating point-to-point link prints above its
                # address. `ng0` has no such line; a gif, a gre or a p2p WWAN
                # does, and it matches "inet ... -->" one line too early.
                above=(
                    f"\ttunnel inet 198.18.20.2 --> 198.18.20.9"
                    if primary_encapsulated
                    else ""
                ),
            )
            + "\n"
            + iface_case(
                BACKUP_IF,
                backup,
                f"\tinet {BACKUP_SRC} netmask 0xffffff00",
                "UP,BROADCAST,RUNNING,SIMPLEX",
            )
            + "\n"
            + (
                f'  {VPN_IF}) echo "{VPN_IF}: flags=80c1<UP,RUNNING> mtu 1420" ;;\n'
                if vpn_up
                else f'  {VPN_IF}) exit 1 ;;\n'
            )
            + "  *) exit 1 ;;\nesac\n",
        )

        if backup != ABSENT:
            (self.db / f"dhclient.leases.{BACKUP_IF}").write_text(
                f"lease {{\n  option routers {BACKUP_GW};\n}}\n", encoding="ascii"
            )

        # The VPN holds the default route throughout, which is the condition
        # under which the tunnel gets judged at all.
        self._write(
            "route",
            f"""#!/bin/sh
printf 'route %s\\n' "$*" >> {self.calls}
for arg in "$@"; do
  if [ "$arg" = default ]; then
    echo "   interface: {VPN_IF}"
    exit 0
  fi
done
echo "     gateway: {PRIMARY_GW}"
exit 0
""",
        )
        self._write(
            "awg",
            "#!/bin/sh\nnow=$(date +%s)\n"
            f"printf 'peerkey\\t%s\\n' \"$((now - {handshake_age}))\"\n",
        )
        # Reachability follows the link the probe was sourced from. An unsourced
        # probe is the check through the tunnel, which fails here: that is the
        # second way the tunnel gets condemned for the underlay's outage.
        self._write(
            "ping",
            f"""#!/bin/sh
src=
for arg in "$@"; do
  case "$prev" in -S) src=$arg ;; esac
  prev=$arg
done
case "$src" in
  {PRIMARY_SRC}) exit {0 if primary_reachable else 2} ;;
  {BACKUP_SRC}) exit 0 ;;
  *) exit 2 ;;
esac
""",
        )
        self._write("nc", "#!/bin/sh\nexit 1\n")
        for name in ("gatebsd-route-op", "gatewayctl", "ru-routes.sh", "service"):
            self._write(
                name,
                f"#!/bin/sh\nprintf '{name} %s\\n' \"$*\" >> {self.calls}\nexit 0\n",
            )
        self._write("logger", "#!/bin/sh\nexit 0\n")
        self._write("setfib", '#!/bin/sh\nshift\nexec "$@"\n')
        self._write("sysctl", '#!/bin/sh\n[ "$2" = net.fibs ] || exit 1\necho 3\n')
        self._write("unbound-control-setup", "#!/bin/sh\nexit 0\n")
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
        self._write(
            "lockf",
            """#!/bin/sh
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
""",
        )
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
            if real and not (self.bin / name).exists():
                (self.bin / name).symlink_to(real)

    def run_watchdog(self, **extra_env: str) -> subprocess.CompletedProcess[str]:
        conf = self.root / "failover.conf"
        conf.write_text(
            "\n".join(
                [
                    f'PRIMARY_IF="{PRIMARY_IF}"',
                    f'BACKUP_IF="{BACKUP_IF}"',
                    f'VPN_IF="{VPN_IF}"',
                    'FAILOVER_MODE="automatic"',
                    'FAIL_THRESHOLD="1"',
                    'RECOVERY_THRESHOLD="1"',
                    'MIN_BACKUP_HOLD="0"',
                    'SWITCH_COOLDOWN="0"',
                    'CHECK_INTERVAL="0"',
                    'PING_TIMEOUT="1"',
                    'CHECK_TCP_PORT="0"',
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
        env.update(extra_env)
        return subprocess.run(
            ["sh", str(self.script)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def reintroduce(self, pattern: str, replacement: str) -> None:
        """Run a copy of the watchdog with the fix edited back out.

        The copy is the point: the regression is executed. An earlier generation
        of these tests read the source text and passed happily with the call
        under test sitting behind `if false`.

        Reads whatever the harness is currently set to run, so a defect that
        lived in more than one place can be put back in more than one call.
        """
        source = self.script.read_text(encoding="utf-8")
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

    def first_index(self, needle: str) -> int:
        for index, line in enumerate(self.call_log().splitlines()):
            if needle in line:
                return index
        return -1

    def event_log(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
class UnderlayBeforeTunnelTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = Harness(Path(self._tmp.name))
        if os.getuid() != 0:
            self.skipTest("watchdog requires a root-owned run directory")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # -- the fix -----------------------------------------------------------
    def test_the_underlay_moves_and_the_tunnel_is_not_condemned_for_it(self) -> None:
        """The 1 August condition, run end to end."""
        self.harness.build(primary=DOWN_BUT_ADDRESSED, backup=UP)
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertEqual(state["active_wan"], "backup", state)
        self.assertGreaterEqual(self.harness.first_index("switch-underlay"), 0)
        self.assertNotIn(
            "vpn-rollback",
            self.harness.call_log(),
            "the tunnel must not be rolled back for an outage of the ground under it",
        )
        self.assertIn("holding VPN judgement", self.harness.event_log())

    def test_the_settling_window_ends(self) -> None:
        """A tunnel that is still stale once the ground has settled is rolled back.

        The window defers a verdict; it must not abolish one. Expressed by
        setting the window to zero, which restores the old timing exactly.
        """
        self.harness.build(primary=DOWN_BUT_ADDRESSED, backup=UP)
        self.harness.run_watchdog(VPN_SETTLE_AFTER_SWITCH="0")

        self.assertIn("vpn-rollback", self.harness.call_log())
        self.assertTrue(self.harness.state()["vpn_rolled_back"])

    def test_a_link_that_is_no_longer_running_offers_no_gateway(self) -> None:
        """`ifconfig ng0 down` leaves the address behind; it is not a way out.

        With no backup fitted and the tunnel's own interface gone, the only
        candidate gateway is the dead primary's. Taking it would install a
        default route to a link with no carrier and report success.
        """
        self.harness.build(primary=DOWN_BUT_ADDRESSED, backup=ABSENT, vpn_up=False)
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertNotIn("vpn-rollback", self.harness.call_log())
        self.assertEqual(state["state"], "NO_CONNECTIVITY", state)
        self.assertIn("no WAN gateway available", self.harness.event_log())

    def test_a_primary_that_prints_a_tunnel_line_is_still_a_healthy_primary(self) -> None:
        """The next hop is a field of the address line, not any line shaped like one.

        An encapsulating point-to-point interface prints its outer addresses
        first::

            tunnel inet 198.18.20.2 --> 198.18.20.9
                inet 203.0.113.9 --> 192.0.2.1 netmask 0xffffffff

        and a pattern that only asks for "inet" and "-->" somewhere on the line
        stops on the first one, where the fourth field is the arrow. The link
        then has no gateway, for ever. `ng0` never showed this -- PPPoE prints no
        such line -- which is why it survived the field; the rig showed it at
        once, and 0.2 plans a point-to-point backup on `umb0`.
        """
        self.harness.build(
            primary=UP, primary_encapsulated=True, primary_reachable=True,
            backup=UP, handshake_age=30,
        )
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertTrue(state["primary_ok"], state)
        self.assertEqual(state["active_wan"], "primary", state)
        self.assertNotIn("switch-underlay", self.harness.call_log())

    # -- the defects, re-created and executed -------------------------------
    def test_reintroducing_the_unanchored_parse_loses_the_gateway_of_a_live_link(self) -> None:
        """With the old pattern the tunnel line answers first, and "-->" is not an address."""
        self.harness.build(
            primary=UP, primary_encapsulated=True, primary_reachable=True,
            backup=UP, handshake_age=30,
        )
        self.harness.reintroduce(
            re.escape("""    src="$(ifconfig "$iface" 2>/dev/null | awk '$1 == "inet" {print $2; exit}')\""""),
            """    src="$(ifconfig "$iface" 2>/dev/null | awk '/inet / {print $2; exit}')\"""",
        )
        self.harness.reintroduce(
            re.escape(
                """        gw="$(ifconfig "$iface" 2>/dev/null | awk '$1 == "inet" && $3 == "-->" {print $4; exit}')\""""
            ),
            """        gw="$(ifconfig "$iface" 2>/dev/null | awk '/inet.*-->/ {print $4; exit}')\"""",
        )
        self.harness.run_watchdog()

        state = self.harness.state()
        self.assertFalse(
            state["primary_ok"],
            "the defect did not reproduce: the primary kept its gateway",
        )
        self.assertEqual(state["active_wan"], "backup", state)

    def test_reintroducing_the_old_section_order_condemns_the_tunnel_first(self) -> None:
        self.harness.build(primary=DOWN_BUT_ADDRESSED, backup=UP)
        self.harness.reintroduce(
            r"    measure_links\n    select_underlay\n    supervise_services\n    judge_vpn\n",
            "    measure_links\n    judge_vpn\n    select_underlay\n    supervise_services\n",
        )
        self.harness.run_watchdog()

        rollback = self.harness.first_index("vpn-rollback")
        switch = self.harness.first_index("switch-underlay")
        self.assertGreaterEqual(rollback, 0, "the defect did not reproduce")
        self.assertGreaterEqual(switch, 0)
        self.assertLess(
            rollback,
            switch,
            "with the old order the tunnel is judged before the ground is chosen",
        )

    def test_reintroducing_the_missing_settling_window_condemns_the_tunnel(self) -> None:
        self.harness.build(primary=DOWN_BUT_ADDRESSED, backup=UP)
        self.harness.reintroduce(r"if underlay_settling; then", "if false; then")
        self.harness.run_watchdog()

        self.assertIn("vpn-rollback", self.harness.call_log())
        self.assertTrue(self.harness.state()["vpn_rolled_back"])

    def test_reintroducing_the_stale_gateway_installs_a_route_to_a_dead_link(self) -> None:
        self.harness.build(primary=DOWN_BUT_ADDRESSED, backup=ABSENT, vpn_up=False)
        self.harness.reintroduce(
            r'    iface_is_live "\$PRIMARY_IF" \|\| return 0\n', ""
        )
        self.harness.run_watchdog()

        self.assertIn(
            f"vpn-rollback {PRIMARY_GW}",
            self.harness.call_log(),
            "the defect did not reproduce: the dead link's gateway was not used",
        )
