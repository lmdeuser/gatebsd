"""TDD tests for WAN/LTE domestic RU white-list probing and status exposure."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gatebsd_ui import failover, paths

ROOT = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT / "sbin" / "gatebsd-watchdog.sh"
STATE_VALUE = ROOT / "sbin" / "gatebsd-state-value"

PRIMARY_IF = "ng0"
BACKUP_IF = "ue0"
VPN_IF = "awg0"
PRIMARY_SRC = "203.0.113.9"
PRIMARY_GW = "192.0.2.1"
BACKUP_SRC = "198.51.100.50"
BACKUP_GW = "198.51.100.1"
GLOBAL_TARGETS = "203.0.113.101 203.0.113.102"
RU_TARGETS = "77.88.8.8"
PRIMARY_FIB = 1
BACKUP_FIB = 2

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
    [ "$cmd" != change ] || [ "$exists" = 1 ] || exit 1
    [ "$cmd" != add ] || [ "$exists" = 0 ] || exit 1
    if [ "$mode" = link ]; then
      upsert "$dest" "$ifc" "$ifc"
      exit 0
    fi
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
elif [ "$target" = "77.88.8.8" ]; then
  [ "$(cat "$FIBDIR/icmp_ru.$ifc" 2>/dev/null)" = 1 ] || exit 2
else
  [ "$(cat "$FIBDIR/icmp_net.$ifc" 2>/dev/null)" = 1 ] || exit 2
fi
exit 0
"""

NC_STUB = "#!/bin/sh\n" + PROBE_PRELUDE.replace(
    r"eval target=\${$#}", "eval port=\\${$#}\nshift $(($# - 2))\ntarget=$1"
) + r"""
printf 'nc fib=%s if=%s %s:%s\n' "$FIB" "$ifc" "$target" "$port" >> "$CALLS"
if [ "$target" = "77.88.8.8" ]; then
  [ "$(cat "$FIBDIR/tcp_ru.$ifc" 2>/dev/null)" = 1 ] || exit 1
else
  [ "$(cat "$FIBDIR/tcp_net.$ifc" 2>/dev/null)" = 1 ] || exit 1
fi
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
if [ "$1" = -f ]; then
  format=$2
  shift 2
  case "$format" in
    '%u') printf '0\n'; exit 0 ;;
    '%Lp') exec /usr/bin/stat -c '%a' "$@" ;;
    *) exit 2 ;;
  esac
fi
exec /usr/bin/stat "$@"
"""

INSTALL_STUB = r"""#!/bin/sh
dir_mode=0
mode=0755
while [ "$#" -gt 0 ]; do
  case "$1" in
    -d) dir_mode=1; shift ;;
    -o|-g) shift 2 ;;
    -m) mode=$2; shift 2 ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
if [ "$dir_mode" = 1 ]; then
  for d in "$@"; do
    mkdir -p "$d" && chmod "$mode" "$d"
  done
  exit 0
fi
exec /usr/bin/install "$@"
"""


class RuProbeHarness:
    """Self-contained watchdog harness distinguishing global vs RU probes."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.run = root / "run"
        self.db = root / "db"
        self.fibs = root / "fibs"
        self.log = root / "watchdog.log"
        self.calls = root / "calls.log"
        for path in (self.root, self.bin, self.run, self.db, self.fibs):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o750)
        self.state_file = self.run / "watchdog.json"

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def _seed_fib(self, fib: int, rows: list[tuple[str, str, str]]) -> None:
        (self.fibs / f"fib{fib}").write_text(
            "".join(f"{d}|{g}|{i}\n" for d, g, i in rows), encoding="ascii"
        )

    def build(
        self,
        *,
        primary_up: bool = True,
        primary_gw_ok: bool = True,
        primary_global_ok: bool = True,
        primary_ru_ok: bool = True,
        backup_fitted: bool = True,
        backup_up: bool = True,
        backup_gw_ok: bool = True,
        backup_global_ok: bool = True,
        backup_ru_ok: bool = True,
        iterations: int = 1,
    ) -> None:
        self._seed_fib(0, [("default", VPN_IF, VPN_IF)])
        for fib in (PRIMARY_FIB, BACKUP_FIB):
            self._seed_fib(fib, [])

        policies = {
            f"icmp_gw.{PRIMARY_IF}": primary_up and primary_gw_ok,
            f"icmp_net.{PRIMARY_IF}": primary_up and primary_gw_ok and primary_global_ok,
            f"tcp_net.{PRIMARY_IF}": primary_up and primary_gw_ok and primary_global_ok,
            f"icmp_ru.{PRIMARY_IF}": primary_up and primary_ru_ok,
            f"tcp_ru.{PRIMARY_IF}": primary_up and primary_ru_ok,
            f"icmp_gw.{BACKUP_IF}": backup_up and backup_gw_ok,
            f"icmp_net.{BACKUP_IF}": backup_up and backup_gw_ok and backup_global_ok,
            f"tcp_net.{BACKUP_IF}": backup_up and backup_gw_ok and backup_global_ok,
            f"icmp_ru.{BACKUP_IF}": backup_up and backup_ru_ok,
            f"tcp_ru.{BACKUP_IF}": backup_up and backup_ru_ok,
            f"icmp_gw.{VPN_IF}": True,
            f"icmp_net.{VPN_IF}": True,
            f"tcp_net.{VPN_IF}": True,
        }
        for name, allowed in policies.items():
            (self.fibs / name).write_text("1" if allowed else "0", encoding="ascii")

        primary_inet = f"\tinet {PRIMARY_SRC} --> {PRIMARY_GW} netmask 0xffffffff" if primary_up else ""
        backup_inet = f"\tinet {BACKUP_SRC} netmask 0xffffff00" if backup_up else ""
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
        if backup_up and backup_fitted:
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
            self._write(name, f'#!/bin/sh\nprintf \'{name} %s\\n\' "$*" >> "$CALLS"\nexit 0\n')
        self._write("logger", "#!/bin/sh\nexit 0\n")
        self._write("unbound-control-setup", "#!/bin/sh\nexit 0\n")
        self._write("lockf", LOCKF_STUB)
        self._write("stat", STAT_STUB)
        self._write("install", INSTALL_STUB)
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
            "mktemp", "date", "cat", "awk", "sed", "cmp", "sort",
            "id", "ps", "kill", "grep", "rm", "chmod", "mv", "head", "tr", "df",
        ):
            real = shutil.which(name)
            if real and not (self.bin / name).exists():
                (self.bin / name).symlink_to(real)

    def run_watchdog(self, *, ru_targets: str = RU_TARGETS) -> subprocess.CompletedProcess[str]:
        conf = self.root / "failover.conf"
        conf.write_text(
            "\n".join(
                [
                    f'PRIMARY_IF="{PRIMARY_IF}"',
                    f'BACKUP_IF="{BACKUP_IF}"',
                    f'VPN_IF="{VPN_IF}"',
                    'FAILOVER_MODE="automatic"',
                    f'CHECK_TARGETS="{GLOBAL_TARGETS}"',
                    f'RU_CHECK_TARGETS="{ru_targets}"',
                    'CHECK_TCP_PORT="443"',
                    f'PRIMARY_FIB="{PRIMARY_FIB}"',
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
            "GATEBSD_SERVICE_GROUP": "wheel",
            "GATEBSD_ALLOW_TEST_RUN_DIR": "1",
            "GATEBSD_WATCHDOG_STATE": str(self.state_file),
            "GATEBSD_VPN_DISABLED_FLAG": str(self.db / "vpn_disabled"),
            "GATEBSD_ROUTE_HELPER": str(self.bin / "gatebsd-route-op"),
            "GATEBSD_STATE_READER": str(STATE_VALUE),
            "GATEBSD_PYTHON_LAUNCHER": shutil.which("python3") or "python3",
            "GATEBSD_RU_ROUTES_HELPER": str(self.bin / "ru-routes.sh"),
            "GATEBSD_DHCLIENT_LEASE_DIR": str(self.db),
            "RU_TABLE": str(self.root / "ru.table"),
            "RU_STATE_FILE": str(self.db / "ru-routes.applied"),
            "EVENT_LOG": str(self.log),
            "HOME": str(self.root),
            "LANG": "C",
        }
        return subprocess.run(
            ["sh", str(WATCHDOG)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=20,
        )

    def state(self) -> dict:
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def call_log(self) -> str:
        return self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""


class WatchdogRuWhitelistTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = RuProbeHarness(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_healthy_tick_skips_ru_probe_and_reports_ru_ok_true(self) -> None:
        self.harness.build()
        self.harness.run_watchdog()
        state = self.harness.state()
        self.assertEqual(state.get("schema"), 8)
        self.assertIs(state.get("primary_ok"), True)
        self.assertIs(state.get("primary_ru_ok"), True)
        self.assertIs(state.get("backup_ok"), True)
        self.assertIs(state.get("backup_ru_ok"), True)
        self.assertNotIn("77.88.8.8", self.harness.call_log())

    def test_whitelist_tick_keeps_ok_false_and_sets_ru_ok_true(self) -> None:
        self.harness.build(
            primary_gw_ok=True,
            primary_global_ok=False,
            primary_ru_ok=True,
            backup_gw_ok=True,
            backup_global_ok=False,
            backup_ru_ok=True,
        )
        self.harness.run_watchdog()
        state = self.harness.state()
        self.assertIs(state.get("primary_ok"), False)
        self.assertIs(state.get("primary_ru_ok"), True)
        self.assertIs(state.get("backup_ok"), False)
        self.assertIs(state.get("backup_ru_ok"), True)
        self.assertGreaterEqual(state.get("primary_failures", 0), 1)
        self.assertGreaterEqual(state.get("backup_failures", 0), 1)
        calls = self.harness.call_log()
        self.assertIn(f"ping fib={PRIMARY_FIB} if={PRIMARY_IF} 77.88.8.8", calls)
        self.assertIn(f"ping fib={BACKUP_FIB} if={BACKUP_IF} 77.88.8.8", calls)

    def test_total_outage_gateway_down_skips_ru_probe_and_sets_ru_ok_false(self) -> None:
        self.harness.build(
            primary_gw_ok=False,
            primary_global_ok=False,
            primary_ru_ok=True,
            backup_gw_ok=True,
            backup_global_ok=True,
        )
        self.harness.run_watchdog()
        state = self.harness.state()
        self.assertIs(state.get("primary_ok"), False)
        self.assertIs(state.get("primary_ru_ok"), False)
        self.assertNotIn(f"if={PRIMARY_IF} 77.88.8.8", self.harness.call_log())

    def test_total_outage_both_global_and_ru_fail_sets_ru_ok_false(self) -> None:
        self.harness.build(
            primary_gw_ok=True,
            primary_global_ok=False,
            primary_ru_ok=False,
            backup_gw_ok=True,
            backup_global_ok=False,
            backup_ru_ok=False,
        )
        self.harness.run_watchdog()
        state = self.harness.state()
        self.assertIs(state.get("primary_ok"), False)
        self.assertIs(state.get("primary_ru_ok"), False)
        self.assertIs(state.get("backup_ok"), False)
        self.assertIs(state.get("backup_ru_ok"), False)

    def test_unfitted_backup_sets_backup_ok_and_ru_ok_false(self) -> None:
        self.harness.build(backup_fitted=False, backup_up=False)
        self.harness.run_watchdog()
        state = self.harness.state()
        self.assertIs(state.get("backup_fitted"), False)
        self.assertIs(state.get("backup_ok"), False)
        self.assertIs(state.get("backup_ru_ok"), False)


class StateValueRuWhitelistTests(unittest.TestCase):
    def test_state_value_reads_ru_ok_booleans_and_rejects_non_bool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "watchdog.json"
            state_path.write_text(
                json.dumps({"primary_ru_ok": True, "backup_ru_ok": False}),
                encoding="utf-8",
            )
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "GATEBSD_PYTHON_LAUNCHER": shutil.which("python3") or "python3",
            }
            for key, expected in (("primary_ru_ok", "true"), ("backup_ru_ok", "false")):
                proc = subprocess.run(
                    ["sh", str(STATE_VALUE), str(state_path), key],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stdout.strip(), expected)

            state_path.write_text(json.dumps({"primary_ru_ok": 1}), encoding="utf-8")
            bad = subprocess.run(
                ["sh", str(STATE_VALUE), str(state_path), "primary_ru_ok"],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(bad.returncode, 2)


class FailoverBackendRuWhitelistTests(unittest.TestCase):
    def test_status_exposes_ru_flags_and_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "watchdog.json"
            conf_path = root / "failover.conf"
            conf_path.write_text('FAILOVER_MODE="automatic"\n', encoding="utf-8")
            state_path.write_text(
                json.dumps({
                    "primary_ok": False,
                    "primary_ru_ok": True,
                    "backup_fitted": True,
                    "backup_ok": False,
                    "backup_ru_ok": True,
                }),
                encoding="utf-8",
            )
            with patch.object(paths, "FAILOVER_STATE", state_path), patch.object(
                paths, "FAILOVER_CONF", conf_path
            ), patch.object(failover, "service_state", return_value={"gatebsd_failover": "active"}):
                data = failover.status(include_health=False)
            self.assertIs(data["primary_ru_ok"], True)
            self.assertIs(data["backup_ru_ok"], True)
            joined = "\n".join(data["warnings"])
            self.assertIn("Primary uplink is in domestic allowlist mode", joined)
            self.assertIn("Backup uplink is restricted (allowlist mode)", joined)

            state_path.write_text(
                json.dumps({
                    "primary_ok": True,
                    "primary_ru_ok": True,
                    "backup_fitted": False,
                    "backup_ok": False,
                    "backup_ru_ok": True,
                }),
                encoding="utf-8",
            )
            with patch.object(paths, "FAILOVER_STATE", state_path), patch.object(
                paths, "FAILOVER_CONF", conf_path
            ), patch.object(failover, "service_state", return_value={"gatebsd_failover": "active"}):
                unfitted = failover.status(include_health=False)
            self.assertEqual(unfitted["warnings"], [])

    def test_health_checks_probes_ru_only_when_global_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            conf_path = Path(tmp) / "failover.conf"
            conf_path.write_text(
                'CHECK_TARGETS="1.1.1.1"\nRU_CHECK_TARGETS="77.88.8.8"\nPRIMARY_FIB="1"\nBACKUP_FIB="2"\n',
                encoding="utf-8",
            )
            ping_calls: list[tuple[int, list[str]]] = []

            def fake_ping(fib: int, src: str, targets: list[str], timeout_s: int) -> dict:
                ping_calls.append((fib, list(targets)))
                # FIB 1 succeeds globally; FIB 2 fails global and succeeds RU
                if fib == 1:
                    return {"ok": True, "fib": fib, "targets": targets}
                if targets == ["77.88.8.8"]:
                    return {"ok": True, "fib": fib, "target": "77.88.8.8"}
                return {"ok": False, "fib": fib, "attempts": []}

            with patch.object(paths, "FAILOVER_CONF", conf_path), patch.object(
                failover, "_check_interface", return_value={"exists": True, "up": True, "has_ip": True, "addresses": []}
            ), patch.object(
                failover, "_check_gateway", return_value={"has_gw": True, "gateway": "192.0.2.1", "local_ip": "192.0.2.2"}
            ), patch.object(failover, "_check_ping", side_effect=fake_ping), patch.object(
                failover, "_check_pppoe_session", return_value={"running": True}
            ), patch.object(failover, "_check_awg_handshake", return_value={"exists": True}), patch.object(
                failover, "_check_dns", return_value={"ok": True}
            ), patch.object(failover, "_check_tcp", return_value={"ok": True}):
                checks = failover.health_checks()

            self.assertNotIn("ru_ping", checks["wan"])
            self.assertIn("ru_ping", checks["backup"])
            self.assertIs(checks["backup"]["ru_ping"]["ok"], True)
            self.assertEqual(
                ping_calls,
                [(1, ["1.1.1.1"]), (2, ["1.1.1.1"]), (2, ["77.88.8.8"])],
            )


class WatchdogHardeningM5Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = RuProbeHarness(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_m5_conf_parser_does_not_execute_shell_command_substitutions(self) -> None:
        self.harness.build(iterations=1)
        pwn_marker = self.harness.root / "pwned-by-failover-conf"
        res = self.harness.run_watchdog()
        self.assertEqual(res.returncode, 1)  # exit 1 from sleep stub stopping after 1 iteration
        # Now write malicious failover.conf with command substitution and verify marker is never created.
        conf = self.harness.root / "failover.conf"
        conf.write_text(
            f'FAILOVER_MODE="$(touch {pwn_marker})"\n'
            f'CHECK_INTERVAL="0"\n'
            f'PRIMARY_IF="{PRIMARY_IF}"\n'
            f'BACKUP_IF="{BACKUP_IF}"\n'
            f'VPN_IF="{VPN_IF}"\n',
            encoding="ascii",
        )
        conf.chmod(0o600)
        self.harness.build(iterations=1)
        # Re-run with the same malicious conf (run_watchdog rewrites conf, so invoke directly using env)
        env = {
            "PATH": f"{self.harness.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "FIBDIR": str(self.harness.fibs),
            "CALLS": str(self.harness.calls),
            "GATEBSD_FAILOVER_CONF": str(conf),
            "GATEBSD_RUN_DIR": str(self.harness.run),
            "GATEBSD_SERVICE_GROUP": "wheel",
            "GATEBSD_ALLOW_TEST_RUN_DIR": "1",
            "GATEBSD_WATCHDOG_STATE": str(self.harness.state_file),
            "GATEBSD_VPN_DISABLED_FLAG": str(self.harness.db / "vpn_disabled"),
            "GATEBSD_ROUTE_HELPER": str(self.harness.bin / "gatebsd-route-op"),
            "GATEBSD_STATE_READER": str(STATE_VALUE),
            "GATEBSD_PYTHON_LAUNCHER": shutil.which("python3") or "python3",
            "GATEBSD_RU_ROUTES_HELPER": str(self.harness.bin / "ru-routes.sh"),
            "GATEBSD_DHCLIENT_LEASE_DIR": str(self.harness.db),
            "RU_TABLE": str(self.harness.root / "ru.table"),
            "RU_STATE_FILE": str(self.harness.db / "ru-routes.applied"),
            "EVENT_LOG": str(self.harness.log),
            "HOME": str(self.harness.root),
            "LANG": "C",
        }
        subprocess.run(["sh", str(WATCHDOG)], env=env, capture_output=True, text=True, timeout=20)
        self.assertFalse(pwn_marker.exists(), "failover.conf command substitution executed!")

    def test_m5_vpn_disabled_on_backup_underlay_preserves_backup_state_and_null_age(self) -> None:
        self.harness.build(primary_up=False, primary_gw_ok=False, primary_global_ok=False, backup_up=True, iterations=1)
        (self.harness.db / "vpn_disabled").write_text("", encoding="ascii")
        # Trigger route-op return 0 and make default route initially point at VPN_IF (already seeded by build)
        self.harness.run_watchdog()
        state = self.harness.state()
        self.assertEqual(state["active_wan"], "backup")
        self.assertEqual(state["state"], "BACKUP")
        self.assertIsNone(state["vpn_handshake_age"])

    def test_state_value_accepts_empty_idle_request_status_and_rejects_unknown(self) -> None:
        state_path = self.harness.root / "state.json"
        env = {"PATH": "/usr/bin:/bin", "GATEBSD_PYTHON_LAUNCHER": sys.executable}

        state_path.write_text(json.dumps({"active_wan": "primary", "request_status": ""}), encoding="ascii")
        idle_res = subprocess.run(
            ["sh", str(STATE_VALUE), str(state_path), "request_status"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(idle_res.returncode, 0, idle_res.stderr)
        self.assertEqual(idle_res.stdout.strip(), "")

        state_path.write_text(json.dumps({"active_wan": "primary", "request_status": "bogus"}), encoding="ascii")
        bad_res = subprocess.run(
            ["sh", str(STATE_VALUE), str(state_path), "request_status"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(bad_res.returncode, 2)

    def test_watchdog_survives_restart_over_its_own_idle_state_file(self) -> None:
        self.harness.build(iterations=1)
        first = self.harness.run_watchdog()
        self.assertEqual(first.returncode, 1, first.stderr)
        self.assertEqual(self.harness.state()["request_status"], "")

        (self.harness.root / "sleep.count").unlink(missing_ok=True)
        second = self.harness.run_watchdog()
        self.assertEqual(second.returncode, 1, f"stderr={second.stderr}\nlog={self.harness.log.read_text() if self.harness.log.exists() else ''}")
        self.assertNotIn("watchdog exited unexpectedly (status 2)", self.harness.log.read_text(encoding="utf-8"))

    def test_safe_source_warns_unknown_keys_once_on_startup_not_every_tick(self) -> None:
        self.harness.build(iterations=3)
        conf = self.harness.root / "failover.conf"
        conf.write_text(
            "\n".join(
                [
                    f'PRIMARY_IF="{PRIMARY_IF}"',
                    f'BACKUP_IF="{BACKUP_IF}"',
                    f'VPN_IF="{VPN_IF}"',
                    'FAILOVER_MODE="automatic"',
                    f'CHECK_TARGETS="{GLOBAL_TARGETS}"',
                    f'RU_CHECK_TARGETS="{RU_TARGETS}"',
                    'CHECK_TCP_PORT="443"',
                    f'PRIMARY_FIB="{PRIMARY_FIB}"',
                    f'BACKUP_FIB="{BACKUP_FIB}"',
                    'FAIL_THRESHOLD="1"',
                    'RECOVERY_THRESHOLD="1"',
                    'MIN_BACKUP_HOLD="0"',
                    'SWITCH_COOLDOWN="0"',
                    'CHECK_INTERVAL="0"',
                    'PING_TIMEOUT="1"',
                    'VPN_HANDSHAKE_MAX="180"',
                    'VPN_NET_FAIL_THRESHOLD="1"',
                    'VPN_FAILURE_POLICY="open"',
                    'STATE_FILE="/tmp/x"',
                    'LOCK_FILE="/tmp/y"',
                    "",
                ]
            ),
            encoding="ascii",
        )
        conf.chmod(0o600)
        env = {
            "PATH": f"{self.harness.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "FIBDIR": str(self.harness.fibs),
            "CALLS": str(self.harness.calls),
            "GATEBSD_FAILOVER_CONF": str(conf),
            "GATEBSD_RUN_DIR": str(self.harness.run),
            "GATEBSD_SERVICE_GROUP": "wheel",
            "GATEBSD_ALLOW_TEST_RUN_DIR": "1",
            "GATEBSD_WATCHDOG_STATE": str(self.harness.state_file),
            "GATEBSD_VPN_DISABLED_FLAG": str(self.harness.db / "vpn_disabled"),
            "GATEBSD_ROUTE_HELPER": str(self.harness.bin / "gatebsd-route-op"),
            "GATEBSD_STATE_READER": str(STATE_VALUE),
            "GATEBSD_PYTHON_LAUNCHER": sys.executable,
            "GATEBSD_RU_ROUTES_HELPER": str(self.harness.bin / "ru-routes.sh"),
            "GATEBSD_DHCLIENT_LEASE_DIR": str(self.harness.db),
            "RU_TABLE": str(self.harness.root / "ru.table"),
            "RU_STATE_FILE": str(self.harness.db / "ru-routes.applied"),
            "EVENT_LOG": str(self.harness.log),
            "HOME": str(self.harness.root),
            "LANG": "C",
        }
        res = subprocess.run(["sh", str(WATCHDOG)], env=env, capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(res.returncode, 1, res.stderr)
        self.assertEqual(res.stderr.count("VPN_FAILURE_POLICY"), 1, res.stderr)


if __name__ == "__main__":
    unittest.main()
