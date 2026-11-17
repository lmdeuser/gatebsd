#!/usr/bin/env python3
"""The resolver's memory of failures must not outlive the path that caused them.

Measured on the production router on 6 August. The tunnel was out of the default
route from 06:14 to 08:28 while the peer's server was rebooted by its admins.
During those two hours unbound asked for google.com over a broken path, got
nothing, and cached the nothing.

At 08:28 the tunnel came back. The watchdog wrote PRIMARY, the panel went green,
`ya.ru` and `github.com` loaded -- and google.com stayed dead for another fifteen
minutes, until a hand-run `flush_zone google.com` returned it instantly:

    before flush: (empty)
    flush_zone google.com -> ok removed 15 rrsets, 28 messages
    after:        142.251.152.119

Every reader the customer has said the connection was fine, and it was. The one
component that had not been told the outage was over was the resolver, and
nothing in the box was responsible for telling it.

This is the archetype this project keeps paying for: a daemon holds state in
memory, the world underneath it changes, and nothing happens until something
restarts it. Here the wrong state is negative DNS answers and the trigger is a
route change -- so the flush belongs to the route change, in both directions and
on both paths (the tunnel moving in or out, and the carrier switching under it).

Everything below runs the real scripts against stubs for the machine. The
reintroductions edit the fix back out of a copy and assert the old behaviour
returns, because a test that reads the source passes just as happily when the
call it looks for sits behind `if false`.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Reuse the driver that already runs the real gatewayctl against stubs. Under
# `unittest discover` the tests directory is importable; under
# `python -m unittest tests.<module>` it is not, so say so outright.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_vpn_autostart import GatewayctlHarness, STAT_STUB  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ROUTE_OP = ROOT / "sbin" / "gatebsd-route-op"
WATCHDOG = ROOT / "sbin" / "gatebsd-watchdog.sh"

FLUSH = "flush-resolver-negative"


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class TheHelperActuallyFlushes(unittest.TestCase):
    """`gatebsd-route-op flush-resolver-negative`, executed."""

    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("route-op refuses privileged actions to a non-root caller")
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "calls.log"

        self._write("stat", STAT_STUB)
        self.set_control(exit_code=0)

        self.conf = self.root / "gateway.conf"
        self.conf.write_text('VPN_IF="awg0"\nVPN_ENDPOINT_HOST="vpn.example.net"\n', encoding="ascii")
        os.chown(self.conf, 0, 0)
        self.conf.chmod(0o600)

        self.lock_dir = self.root / "run"
        self.lock_dir.mkdir(mode=0o750)

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def set_control(self, *, exit_code: int) -> None:
        self._write(
            "unbound-control",
            f'#!/bin/sh\nprintf "unbound-control %s\\n" "$*" >> {self.calls}\nexit {exit_code}\n',
        )

    def run_op(self, *args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.root),
            "LANG": "C",
            "GATEBSD_GATEWAY_CONF": str(self.conf),
            "GATEBSD_GATEWAY_LOCK_FILE": str(self.lock_dir / "gatewayctl.lock"),
            "GATEBSD_UNBOUND_CONTROL": str(self.bin / "unbound-control"),
            "GATEBSD_UNBOUND_CONF": str(self.root / "unbound.conf"),
            # route-op imposes its own PATH; this is the sanctioned hook that
            # lets the stub `stat` above be the one it actually runs. Without
            # it every call dies on BSD `stat -f`, which Linux does not have.
            "GATEBSD_ALLOW_TEST_PATH": "1",
            "GATEBSD_TEST_PATH_PREFIX": str(self.bin),
        }
        env.update(overrides)
        return subprocess.run(
            ["sh", str(ROUTE_OP), *args],
            check=False, capture_output=True, text=True, env=env,
        )

    def recorded(self) -> str:
        return self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""

    def test_it_calls_flush_negative(self):
        result = self.run_op(FLUSH)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("flush_negative", self.recorded())

    def test_it_does_not_queue_behind_the_route_lock(self):
        """The flush is needed *during* a route change, so it must not wait for one.

        The watchdog does not run under the gateway lock. A flush that took it
        would fail with "already locked" at exactly the moment a route
        transaction is in flight -- the moment that makes the flush necessary.
        This points the lock at a directory route-op refuses, so any action that
        locks dies before doing its work.
        """
        hostile = self.root / "hostile"
        hostile.mkdir()
        os.chown(hostile, 0, 0)
        hostile.chmod(0o777)
        lock = str(hostile / "l.lock")

        # The control first: an action that does lock refuses this directory
        # outright, which is what makes the assertion below mean anything.
        locking = self.run_op("unpin-endpoint", GATEBSD_GATEWAY_LOCK_FILE=lock)
        self.assertNotEqual(locking.returncode, 0)
        self.assertIn("lock", locking.stderr,
                      "the locking action no longer stops at the lock")

        result = self.run_op(FLUSH, GATEBSD_GATEWAY_LOCK_FILE=lock)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("flush_negative", self.recorded())

    def test_a_refusing_resolver_is_reported_not_swallowed(self):
        self.set_control(exit_code=1)
        result = self.run_op(FLUSH)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resolver", result.stderr.lower())

    def test_a_box_without_unbound_control_still_routes(self):
        """No resolver to talk to is not a reason to fail a route change."""
        result = self.run_op(FLUSH, GATEBSD_UNBOUND_CONTROL=str(self.root / "no-such-binary"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.recorded(), "")

    def test_it_still_needs_root(self):
        """The control socket is root's, so this is not a public action.

        Dropping the lock requirement must not have dropped the root one with
        it -- they were the same flag until this change split them.
        """
        try:
            import pwd
            unprivileged = next(e for e in pwd.getpwall() if e.pw_uid not in (0,))
        except (ImportError, StopIteration):  # pragma: no cover - depends on the host
            self.skipTest("no unprivileged account on this host")
        readable = self.root / "gateway-readable.conf"
        readable.write_text(self.conf.read_text(encoding="ascii"), encoding="ascii")
        os.chown(readable, 0, 0)
        readable.chmod(0o644)
        os.chmod(self.root, 0o755)
        os.chmod(self.bin, 0o755)
        result = subprocess.run(
            ["sh", str(ROUTE_OP), FLUSH],
            check=False, capture_output=True, text=True,
            user=unprivileged.pw_uid, group=unprivileged.pw_gid,
            env={
                "PATH": f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/", "LANG": "C",
                # Readable by the caller, still root-owned and not writable:
                # otherwise the run dies on the config guard before it ever
                # reaches the root check this test is about.
                "GATEBSD_GATEWAY_CONF": str(readable),
                "GATEBSD_UNBOUND_CONTROL": str(self.bin / "unbound-control"),
                "GATEBSD_ALLOW_TEST_PATH": "1",
                "GATEBSD_TEST_PATH_PREFIX": str(self.bin),
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root required", result.stderr)


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class EveryPathChangeFlushes(GatewayctlHarness):
    """The real `gatewayctl`, driven through both directions of a path change."""

    def route_op_calls(self) -> str:
        return self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""

    def bypass_with_an_unwritable_marker(self) -> subprocess.CompletedProcess[str]:
        """Drive `bypass` down the branch that puts the default back on the tunnel.

        `apply` cannot be made to succeed in this harness: `apply_pf` reads
        `/etc/pf.conf` by an absolute path, and a test that created one would be
        writing to the firewall of whatever machine it runs on. `cmd_bypass`
        reaches `default_via_vpn` by another door -- when the marker cannot be
        written it puts the default route back where it found it -- so that is
        the door used here. Real function, real route change, no /etc.
        """
        blocker = self.root / "notadir"
        blocker.write_text("", encoding="ascii")
        return self.run_ctl(
            "bypass",
            GATEBSD_VPN_DISABLED_FLAG=str(blocker / "vpn_disabled"),
        )

    def test_moving_the_default_onto_the_tunnel_flushes(self):
        result = self.bypass_with_an_unwritable_marker()
        log = result.stdout + result.stderr
        self.assertIn("switching default -> ", log,
                      "this run never put the default back on the tunnel")
        self.assertGreaterEqual(
            self.route_op_calls().count(FLUSH), 2,
            "the default moved twice and the resolver was told about it once")

    def test_moving_the_default_back_to_wan_flushes(self):
        """`bypass` is the other direction, and it was equally stale on 6 August."""
        result = self.run_ctl("bypass")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(FLUSH, self.route_op_calls())

    def test_a_failed_apply_flushes_on_its_way_back(self):
        """Rollback restores the WAN default, so it changes the path too."""
        self.set_endpoint_resolvable(False)
        result = self.run_ctl("apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rolling back", result.stdout + result.stderr)
        self.assertIn(FLUSH, self.route_op_calls())

    def test_a_resolver_that_refuses_does_not_stop_the_route_change(self):
        """A flush is bookkeeping. Routing is the internet. They are not equal."""
        self._write(
            "gatebsd-route-op",
            f"""#!/bin/sh
printf 'route-op %s\\n' "$*" >> {self.calls}
case "$1" in
  endpoint-ip) echo 198.51.100.7 ;;
  {FLUSH}) exit 1 ;;
esac
exit 0
""",
        )
        result = self.run_ctl("bypass")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WARNING", result.stdout + result.stderr,
                      "a failed flush passed in silence")

    def test_reintroducing_the_defect_brings_the_silence_back(self):
        """Take the flush out of `default_via_wan` and watch the guard go red."""
        self.use_patched_copy(
            old='    route_op set-default-gw "$_gw"\n}',
            new='    route_op set-default-gw "$_gw" || return 1\n    flush_resolver\n}',
        )
        result = self.run_ctl("bypass")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(FLUSH, self.route_op_calls(),
                         "the reintroduction did not actually remove the call")


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class TheCarrierSwitchFlushesToo(unittest.TestCase):
    """A failover between primary and backup changes the path just as much.

    Not executed here -- `switch_underlay` needs the whole watchdog loop, which
    `test_watchdog_failover` already drives. This asserts only that the call
    exists next to the switch, and is named a text guard for that reason.
    """

    def test_switch_underlay_flushes(self):
        source = WATCHDOG.read_text(encoding="utf-8")
        body = source.split("switch_underlay() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn(FLUSH, body)


if __name__ == "__main__":
    unittest.main()
