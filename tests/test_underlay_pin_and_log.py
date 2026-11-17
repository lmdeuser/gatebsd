"""Two things that must follow the underlay when it moves: the pin, and the truth.

Both are the second half of the 1 August failure.

``gatebsd-route-op switch-underlay`` moved the VPN endpoint pin only while the
tunnel held the default route. On the path where it does not -- which is exactly
where a failover lands after a rollback -- the pin was left naming the link that
had just died. A host route to the tunnel's own peer via a dead gateway is worse
than no route at all: the outer packets are the one thing that must not follow
the link that failed, and ``awg0: loop detected`` filled the console at a hundred
lines a second while they tried.

``ru-routes.sh`` logged ``gateway=192.168.0.1 interface=ng0`` -- a pair that
cannot both be true. Routing was correct (prefixes are installed by gateway
alone); the message was not, and it cost real time to disbelieve during the
outage. The correction of ``WAN_IF`` lived inside a function called as
``GW=$(wan_gw)``, a command substitution, so it died with the subshell.

Every test here runs the real script. The reintroductions run a *copy* with the
fix edited back out, so the defect is executed rather than described.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROUTE_OP = ROOT / "sbin" / "gatebsd-route-op"
RU_ROUTES = ROOT / "sbin" / "ru-routes.sh"

PRIMARY_IF = "ng0"
BACKUP_IF = "ue0"
VPN_IF = "awg0"
PRIMARY_GW = "192.0.2.1"
BACKUP_GW = "198.51.100.1"
ENDPOINT = "203.0.113.77"

# route(8) over a table kept in a file: dest|gateway|interface. The kernel's own
# rules matter here -- `change` fails when the entry is absent and `add` fails
# when it is present -- because the helpers depend on that to stay idempotent.
ROUTE_STUB = r"""#!/bin/sh
TBL="$ROUTES"
[ -f "$TBL" ] || : > "$TBL"
printf 'route %s\n' "$*" >> "$CALLS"

while [ $# -gt 0 ]; do
  case "$1" in -n|-q|-v|-d|-4|-6) shift ;; *) break ;; esac
done
cmd=${1:-}; shift 2>/dev/null || true

lookup() { awk -F'|' -v d="$1" '$1==d {print $2 "|" $3; f=1} END{exit !f}' "$TBL"; }
drop() { awk -F'|' -v d="$1" '$1!=d' "$TBL" > "$TBL.new"; mv "$TBL.new" "$TBL"; }
upsert() { drop "$1"; printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$TBL"; }

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
    [ "$cmd" != change ] || [ "$exists" = 1 ] || exit 1
    [ "$cmd" != add ] || [ "$exists" = 0 ] || exit 1
    if [ "$mode" = link ]; then
      upsert "$dest" "$ifc" "$ifc"
      exit 0
    fi
    # A gateway route inherits the egress link of its next hop.
    if nexthop=$(lookup "$gw"); then
      upsert "$dest" "$gw" "${nexthop##*|}"
    else
      upsert "$dest" "$gw" "$gw"
    fi
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

# The helpers read ownership and mode with BSD `stat -f`, which a Linux
# container does not have. The semantics under test are the route logic's.
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


def write_stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(body, encoding="ascii")
    path.chmod(0o755)


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
class EndpointPinFollowsTheUnderlayTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        if os.getuid() != 0:
            self.skipTest("route-op refuses mutating actions to a non-root caller")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.routes = self.root / "routes"
        self.calls = self.root / "calls.log"
        self.script = ROUTE_OP

        write_stub(self.bin, "route", ROUTE_STUB)
        write_stub(self.bin, "stat", STAT_STUB)
        write_stub(self.bin, "ru-routes.sh", "#!/bin/sh\nprintf 'ru-routes %s\\n' \"$*\" >> \"$CALLS\"\nexit 0\n")
        write_stub(self.bin, "service", "#!/bin/sh\nprintf 'service %s\\n' \"$*\" >> \"$CALLS\"\nexit 0\n")
        self.conf = self.root / "gateway.conf"
        self.conf.write_text(
            f'VPN_IF="{VPN_IF}"\nVPN_ENDPOINT_HOST="{ENDPOINT}"\n', encoding="ascii"
        )
        self.conf.chmod(0o600)
        (self.root / "ru.table").write_text("", encoding="ascii")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def seed(self, rows: list[tuple[str, str, str]]) -> None:
        self.routes.write_text(
            "".join(f"{d}|{g}|{i}\n" for d, g, i in rows), encoding="ascii"
        )

    def table(self) -> dict[str, tuple[str, str]]:
        result: dict[str, tuple[str, str]] = {}
        for line in self.routes.read_text(encoding="ascii").splitlines():
            if line:
                dest, gateway, iface = line.split("|")
                result[dest] = (gateway, iface)
        return result

    def switch_to_backup(self) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "GATEBSD_ALLOW_TEST_PATH": "1",
            "GATEBSD_TEST_PATH_PREFIX": str(self.bin),
            "GATEBSD_GATEWAY_LOCK_HELD": "1",
            # Without this the lock path stays at its production default, and
            # route-op derives the endpoint-pin record from that directory --
            # so this test, run as root, would read and overwrite the live
            # /var/run/gatebsd/endpoint_pin of whatever machine it runs on.
            "GATEBSD_GATEWAY_LOCK_FILE": str(self.root / "gatewayctl.lock"),
            "GATEBSD_GATEWAY_CONF": str(self.conf),
            "GATEBSD_RU_ROUTES_HELPER": str(self.bin / "ru-routes.sh"),
            "RU_TABLE": str(self.root / "ru.table"),
            "RU_STATE_FILE": str(self.root / "ru-routes.applied"),
            "ROUTES": str(self.routes),
            "CALLS": str(self.calls),
            "HOME": str(self.root),
            "LANG": "C",
        }
        return subprocess.run(
            [
                "sh", str(self.script), "switch-underlay",
                BACKUP_IF, BACKUP_GW, PRIMARY_IF, PRIMARY_GW, VPN_IF,
            ],
            check=False, capture_output=True, text=True, env=env,
        )

    def reintroduce(self, pattern: str, replacement: str) -> None:
        source = ROUTE_OP.read_text(encoding="utf-8")
        patched, count = re.subn(pattern, replacement, source)
        if count == 0:
            raise AssertionError(f"reintroduction pattern never matched: {pattern!r}")
        self.script = self.root / "route-op-defective"
        self.script.write_text(patched, encoding="utf-8")
        self.script.chmod(0o755)

    # -- the fix -----------------------------------------------------------
    def test_the_pin_moves_even_when_the_tunnel_is_not_the_default(self) -> None:
        """The state a failover lands in after a VPN rollback."""
        self.seed(
            [
                ("default", PRIMARY_GW, PRIMARY_IF),
                (PRIMARY_GW, PRIMARY_GW, PRIMARY_IF),
                (BACKUP_GW, BACKUP_GW, BACKUP_IF),
                (ENDPOINT, PRIMARY_GW, PRIMARY_IF),
            ]
        )
        result = self.switch_to_backup()
        self.assertEqual(result.returncode, 0, result.stderr)

        table = self.table()
        self.assertEqual(table["default"][0], BACKUP_GW, table)
        self.assertEqual(
            table[ENDPOINT][0],
            BACKUP_GW,
            "the tunnel's endpoint must not stay pinned to the link that died",
        )

    def test_ru_work_is_scheduled_instead_of_blocking_the_underlay_switch(self) -> None:
        self.seed(
            [
                ("default", VPN_IF, VPN_IF),
                (PRIMARY_GW, PRIMARY_GW, PRIMARY_IF),
                (BACKUP_GW, BACKUP_GW, BACKUP_IF),
                (ENDPOINT, PRIMARY_GW, PRIMARY_IF),
            ]
        )
        result = self.switch_to_backup()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text()
        self.assertIn("service ru_bypass restart", calls)
        self.assertNotIn("ru-routes apply", calls)

    def test_no_pin_is_invented_for_a_tunnel_nobody_asked_for(self) -> None:
        """A device with the VPN switched off has no endpoint route, and gains none.

        Creating one here would mean resolving the endpoint -- a DNS lookup over
        a link chosen because the previous one just died.
        """
        self.seed(
            [
                ("default", PRIMARY_GW, PRIMARY_IF),
                (PRIMARY_GW, PRIMARY_GW, PRIMARY_IF),
                (BACKUP_GW, BACKUP_GW, BACKUP_IF),
            ]
        )
        result = self.switch_to_backup()
        self.assertEqual(result.returncode, 0, result.stderr)

        self.assertEqual(self.table()["default"][0], BACKUP_GW)
        self.assertNotIn(ENDPOINT, self.table())

    # -- the defect, re-created and executed -------------------------------
    def test_reintroducing_the_unmoved_pin_strands_it_on_the_dead_link(self) -> None:
        self.seed(
            [
                ("default", PRIMARY_GW, PRIMARY_IF),
                (PRIMARY_GW, PRIMARY_GW, PRIMARY_IF),
                (BACKUP_GW, BACKUP_GW, BACKUP_IF),
                (ENDPOINT, PRIMARY_GW, PRIMARY_IF),
            ]
        )
        self.reintroduce(
            r'        replace_default_gateway "\$_new_gateway" \|\| return 1\n'
            r'(?:.*\n)*?        return 0\n    fi\n',
            '        replace_default_gateway "$_new_gateway"\n        return\n    fi\n',
        )
        result = self.switch_to_backup()
        self.assertEqual(result.returncode, 0, result.stderr)

        table = self.table()
        self.assertEqual(table["default"][0], BACKUP_GW)
        self.assertEqual(
            table[ENDPOINT][0],
            PRIMARY_GW,
            "the defect did not reproduce: the pin moved anyway",
        )


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
class RuRoutesNamesTheActiveInterfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        if os.getuid() != 0:
            self.skipTest("ru-routes.sh requires root-owned state directories")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.routes = self.root / "routes"
        self.routes.write_text("", encoding="ascii")
        self.calls = self.root / "calls.log"
        self.script = RU_ROUTES

        write_stub(self.bin, "route", ROUTE_STUB)
        write_stub(self.bin, "stat", STAT_STUB)
        write_stub(self.bin, "logger", "#!/bin/sh\nexit 0\n")
        write_stub(self.bin, "lockf", f"#!/bin/sh\nprintf 'lockf %s\\n' \"$*\" >> {self.calls}\nexit 99\n")
        self.set_backup_gateway(None)

        (self.root / "ru.table").write_text("203.0.113.0/24\n", encoding="ascii")
        # The underlay in force, as the watchdog publishes it. Reading this is
        # the only reason ru-routes.sh has an opinion about the interface at all.
        (self.root / "watchdog.json").write_text(
            '{"schema":6,"state":"BACKUP","active_wan":"backup"}\n', encoding="ascii"
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def set_backup_gateway(self, gateway: str | None, *, encapsulated: bool = False) -> None:
        """Point ifconfig at a backup link that has a next hop, or has none.

        The peer is reported the way a point-to-point link reports it. The
        production fallback for an Ethernet backup reads dhclient's lease from a
        fixed /var/db path, which a test must not write to on the stand.

        ``encapsulated`` puts the outer ``tunnel inet`` line above the address,
        the way a gif or a point-to-point WWAN link prints it.
        """
        inet = (
            f"\tinet 198.51.100.50 --> {gateway} netmask 0xffffffff"
            if gateway
            else "\tinet 198.51.100.50 netmask 0xffffff00"
        )
        if encapsulated:
            inet = "\ttunnel inet 198.18.20.2 --> 198.18.20.9\\n" + inet
        write_stub(
            self.bin,
            "ifconfig",
            f"""#!/bin/sh
case "$1" in
  {BACKUP_IF})
    echo "{BACKUP_IF}: flags=8843<UP,BROADCAST,RUNNING> mtu 1500"
    printf '%b\\n' "{inet}"
    ;;
  {PRIMARY_IF})
    echo "{PRIMARY_IF}: flags=88d1<UP,POINTOPOINT,RUNNING> mtu 1492"
    printf '\\tinet 203.0.113.9 --> {PRIMARY_GW} netmask 0xffffffff\\n'
    ;;
  *) exit 1 ;;
esac
""",
        )

    def apply(self, *, outer_gateway_lock: bool = False) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "GATEBSD_PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "GATEBSD_RU_ROUTE_LOCK_HELD": "0" if outer_gateway_lock else "1",
            "GATEBSD_GATEWAY_LOCK_HELD": "1" if outer_gateway_lock else "0",
            "GATEBSD_GATEWAY_CONF": str(self.root / "missing.conf"),
            "GATEBSD_RU_ROUTE_LOCK": str(self.root / "gatewayctl.lock"),
            "GATEBSD_WATCHDOG_STATE": str(self.root / "watchdog.json"),
            "GATEBSD_STATE_READER": str(ROOT / "sbin" / "gatebsd-state-value"),
            "GATEBSD_PYTHON_LAUNCHER": shutil.which("python3") or shutil.which("python3.12") or shutil.which("python3.11") or "python3",
            "RU_TABLE": str(self.root / "ru.table"),
            "RU_STATE_FILE": str(self.root / "state" / "ru-routes.applied"),
            "ROUTES": str(self.routes),
            "CALLS": str(self.calls),
            "HOME": str(self.root),
            "LANG": "C",
        }
        return subprocess.run(
            ["sh", str(self.script), "apply"],
            check=False, capture_output=True, text=True, env=env,
        )

    def reintroduce(self, pattern: str | None = None, replacement: str | None = None) -> None:
        """Run a copy with a fix edited back out. Defaults to the subshell lookup."""
        if pattern is None:
            pattern = r"    resolve_wan \|\| true\n"
            replacement = '    GW=$(resolve_wan >/dev/null 2>&1; printf \'%s\' "${GW:-}")\n'
        source = RU_ROUTES.read_text(encoding="utf-8")
        patched, count = re.subn(pattern, replacement, source)
        if count == 0:
            raise AssertionError(f"reintroduction pattern never matched: {pattern!r}")
        self.script = self.root / "ru-routes-defective.sh"
        self.script.write_text(patched, encoding="utf-8")
        self.script.chmod(0o755)

    # -- the fix -----------------------------------------------------------
    def test_the_applied_line_names_the_interface_the_gateway_is_on(self) -> None:
        self.set_backup_gateway(BACKUP_GW)
        result = self.apply()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            f"applied=1 gateway={BACKUP_GW} interface={BACKUP_IF}",
            result.stdout,
            result.stdout,
        )

    def test_the_failure_message_names_the_interface_it_actually_looked_at(self) -> None:
        self.set_backup_gateway(None)
        result = self.apply()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"{BACKUP_IF} has no valid WAN gateway", result.stderr + result.stdout)

    def test_an_encapsulating_link_still_yields_its_next_hop(self) -> None:
        """A `tunnel inet` line above the address is not the address line.

        RU prefixes are installed by gateway alone, so a gateway lost to the
        wrong line means the whole RU table silently stops being applied.
        """
        self.set_backup_gateway(BACKUP_GW, encapsulated=True)
        result = self.apply()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"applied=1 gateway={BACKUP_GW} interface={BACKUP_IF}", result.stdout)

    def test_an_outer_gateway_transaction_does_not_acquire_a_second_lock(self) -> None:
        self.set_backup_gateway(BACKUP_GW)
        result = self.apply(outer_gateway_lock=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("lockf ", self.calls.read_text())

    def test_reintroducing_the_second_lock_fails_the_nested_transaction(self) -> None:
        self.reintroduce(
            re.escape('if [ "${GATEBSD_RU_ROUTE_LOCK_HELD:-0}" != 1 ] && [ "${GATEBSD_GATEWAY_LOCK_HELD:-0}" != 1 ]; then'),
            'if [ "${GATEBSD_RU_ROUTE_LOCK_HELD:-0}" != 1 ]; then',
        )
        self.set_backup_gateway(BACKUP_GW)
        result = self.apply(outer_gateway_lock=True)
        self.assertEqual(result.returncode, 99)
        self.assertIn("lockf ", self.calls.read_text())

    # -- the defect, re-created and executed -------------------------------
    def test_reintroducing_the_unanchored_parse_loses_the_next_hop(self) -> None:
        self.set_backup_gateway(BACKUP_GW, encapsulated=True)
        self.reintroduce(
            re.escape("""awk '$1 == "inet" && $3 == "-->" {print $4; exit}'"""),
            """awk '/inet / && /-->/ {print $4; exit}'""",
        )
        result = self.apply()
        self.assertNotEqual(
            result.returncode, 0,
            "the defect did not reproduce: the gateway survived the tunnel line",
        )
        self.assertIn(f"{BACKUP_IF} has no valid WAN gateway", result.stderr + result.stdout)

    def test_reintroducing_the_subshell_lookup_reports_the_wrong_interface(self) -> None:
        self.set_backup_gateway(BACKUP_GW)
        self.reintroduce()
        result = self.apply()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            f"applied=1 gateway={BACKUP_GW} interface={PRIMARY_IF}",
            result.stdout,
            "the defect did not reproduce: the interface was reported correctly",
        )
