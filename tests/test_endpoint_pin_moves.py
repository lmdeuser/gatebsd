#!/usr/bin/env python3
"""A switched profile must not leave its predecessor's endpoint pinned.

The pin is a /32 host route through the WAN. It exists so the tunnel's own
outer packets are not routed into the tunnel, and there must be exactly one of
them: one live endpoint, one pin.

Switching a profile broke that arithmetic. `awg_activate` writes the new
endpoint into gateway.conf *before* it rebuilds the tunnel, and the only thing
that could remove the old pin -- `unpin-endpoint` -- worked out which address to
remove by resolving VPN_ENDPOINT_HOST out of that same file. So at the moment
the old pin became garbage, the address of the old pin no longer existed
anywhere on the box. Nothing leaked a route once; it leaked one per switch,
permanently, and no command could name them afterwards.

That is invisible on a device that has carried one profile since it was built,
which is why it was: the production router has exactly one profile and exactly
one pin. It becomes the normal case the moment profiles start turning over --
and they do turn over, because the servers behind them die. Each dead server
leaves behind a permanent hole in the tunnel: one address that keeps being
routed around it, chosen by whoever used to own that address next.

The dead server also takes the repair with it. A retired profile whose endpoint
was a hostname cannot be unpinned by resolving that hostname again, because a
hostname belonging to a machine that no longer exists stops resolving. An
address that was remembered as an address is immune to that; a name is not.

So the pin is remembered, and pinning means *moving* the pin. Everything below
runs the real `gatebsd-route-op` against stubs and reads the route commands it
actually issued -- the reintroduction at the bottom edits the fix back out of a
copy and asserts the leak returns, because a test that reads the source passes
just as happily when the line it looks for sits behind `if false`.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_vpn_autostart import LOCKF_STUB, STAT_STUB  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ROUTE_OP = ROOT / "sbin" / "gatebsd-route-op"

OLD_ENDPOINT = "203.0.113.10"
NEW_ENDPOINT = "198.51.100.20"
WAN_GATEWAY = "192.0.2.1"
WAN_IF = "ng0"


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class ThePinMoves(unittest.TestCase):
    """`gatebsd-route-op pin-endpoint` / `unpin-endpoint`, executed."""

    script = ROUTE_OP

    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("route-op refuses mutating actions to a non-root caller")
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "route-calls.log"

        self._write("stat", STAT_STUB)
        # Linux has no lockf(1). This stub runs the command straight through,
        # which is fine here and only here: nothing below claims anything about
        # mutual exclusion -- the subject is which route commands get issued.
        # Questions about the lock itself are asked on the stand, with a real
        # lockf, by rehearse_gateway_lock.sh.
        self._write("lockf", LOCKF_STUB)
        # `route` is the whole observation. Recording the argument vector is the
        # only way to tell "the pin moved" from "a second pin appeared" -- the
        # two differ by one delete and by nothing else.
        self._write(
            "route",
            f'#!/bin/sh\nprintf "route %s\\n" "$*" >> {self.calls}\nexit 0\n',
        )
        self.set_resolver(OLD_ENDPOINT)

        self.conf = self.root / "gateway.conf"
        self.set_endpoint(OLD_ENDPOINT)

        self.lock_dir = self.root / "run"
        self.lock_dir.mkdir(mode=0o750)
        self.pin_record = self.lock_dir / "endpoint_pin"

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def set_endpoint(self, host: str) -> None:
        self.conf.write_text(
            f'VPN_IF="awg0"\nVPN_ENDPOINT_HOST="{host}"\n', encoding="ascii")
        os.chown(self.conf, 0, 0)
        self.conf.chmod(0o600)

    def set_resolver(self, answer: str | None) -> None:
        """Stand in for the box's resolver launcher.

        `None` is a hostname that has stopped resolving -- a dead provider, the
        case the record exists for.
        """
        if answer is None:
            self._write("resolver", "#!/bin/sh\nexit 1\n")
        else:
            self._write("resolver", f'#!/bin/sh\nprintf "{answer}\\n"\n')

    def run_op(self, *args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.root),
            "LANG": "C",
            "GATEBSD_GATEWAY_CONF": str(self.conf),
            "GATEBSD_GATEWAY_LOCK_FILE": str(self.lock_dir / "gatewayctl.lock"),
            "GATEBSD_PYTHON_LAUNCHER": str(self.bin / "resolver"),
            "GATEBSD_ALLOW_TEST_PATH": "1",
            "GATEBSD_TEST_PATH_PREFIX": str(self.bin),
            # Skip route-op's re-exec under lockf. It relaunches through
            # `env -i` with an explicit variable list that cannot carry the test
            # path hook, so past that point `stat -f` would be Linux's stat and
            # every safe_source check would fail on an answer it never got.
            # test_vpn_autostart drives the real gatewayctl the same way, and
            # for the same reason.
            "GATEBSD_GATEWAY_LOCK_HELD": "1",
        }
        env.update(overrides)
        return subprocess.run(
            ["sh", str(self.script), *args],
            check=False, capture_output=True, text=True, env=env,
        )

    def recorded(self) -> str:
        return self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""

    def forget_calls(self) -> None:
        self.calls.unlink(missing_ok=True)

    def pin(self) -> subprocess.CompletedProcess[str]:
        return self.run_op("pin-endpoint", WAN_IF, WAN_GATEWAY)

    def switch_profile_to(self, endpoint: str) -> None:
        """Exactly what activating another profile does to the box's state.

        `awg_activate` writes the new endpoint into gateway.conf and then has
        the tunnel rebuilt, and the rebuild pins. Nothing else about the switch
        touches routes, so this is the whole of it as route-op sees it.
        """
        self.set_endpoint(endpoint)
        self.set_resolver(endpoint)

    # ------------------------------------------------------------------
    def test_the_first_pin_is_recorded_as_an_address(self):
        result = self.pin()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"-host {OLD_ENDPOINT}", self.recorded())
        self.assertEqual(self.pin_record.read_text(encoding="ascii").strip(),
                         OLD_ENDPOINT)

    def test_switching_a_profile_removes_the_previous_pin(self):
        """The defect, stated as the arithmetic: one endpoint, one pin."""
        self.assertEqual(self.pin().returncode, 0)
        self.forget_calls()

        self.switch_profile_to(NEW_ENDPOINT)
        result = self.pin()
        self.assertEqual(result.returncode, 0, result.stderr)

        calls = self.recorded()
        self.assertIn(f"delete -host {OLD_ENDPOINT}", calls,
                      "the previous endpoint was left pinned: "
                      f"every profile switch leaks a route around the tunnel\n{calls}")
        self.assertIn(f"-host {NEW_ENDPOINT}", calls)
        self.assertEqual(self.pin_record.read_text(encoding="ascii").strip(),
                         NEW_ENDPOINT)

    def test_repinning_the_same_endpoint_deletes_nothing(self):
        """`cmd_apply` pins on every apply, and most applies change nothing.

        Deleting and re-adding the pin the tunnel is using would put a hole in
        the path on every watchdog-driven recovery, so "move the pin" has to
        mean "only when it moved".
        """
        self.assertEqual(self.pin().returncode, 0)
        self.forget_calls()
        self.assertEqual(self.pin().returncode, 0)
        self.assertNotIn("delete", self.recorded())

    def test_unpinning_uses_the_record_when_the_name_has_died(self):
        """The churn case: the server is gone, so its hostname is gone with it.

        Resolution cannot answer "what did we pin" here, and it is exactly when
        the answer is needed -- a retired profile is retired because its far end
        stopped existing.
        """
        self.set_endpoint("vpn.dead-provider.example")
        self.set_resolver(OLD_ENDPOINT)
        self.assertEqual(self.pin().returncode, 0)
        self.forget_calls()

        self.set_resolver(None)      # the name no longer resolves
        result = self.run_op("unpin-endpoint")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"delete -host {OLD_ENDPOINT}", self.recorded(),
                      "an endpoint whose hostname died can no longer be unpinned")
        self.assertFalse(self.pin_record.exists(),
                         "the record outlived the pin it describes")

    def test_a_missing_record_is_an_answer_not_an_error(self):
        """This script runs under `set -eu` and callers assign the result.

        A helper that reports "nothing is pinned" with a failing status kills
        the whole route transaction on the assignment -- the trap `awk` on a
        missing file has already sprung in this codebase.
        """
        self.assertFalse(self.pin_record.exists())
        result = self.run_op("unpin-endpoint")
        self.assertEqual(result.returncode, 0, result.stderr)

        result = self.pin()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_record_that_cannot_be_written_fails_the_pin(self):
        """Bookkeeping that silently gives up re-opens the leak it closes.

        The first version of this swallowed every error while writing the
        record and reported success anyway, on the reasoning that bookkeeping
        should never break routing. In this direction that reasoning is wrong:
        a table pinning B while the record still says A cannot name B at the
        next switch, so B leaks permanently -- the original defect, restored by
        a full filesystem and invisible to every test.

        Unwritable here means a directory that does not exist. Permissions
        would not do it: this suite runs as root, and root writes anywhere.
        """
        missing = self.root / "nowhere" / "gatewayctl.lock"
        result = self.run_op("pin-endpoint", WAN_IF, WAN_GATEWAY,
                             GATEBSD_GATEWAY_LOCK_FILE=str(missing))
        self.assertNotEqual(result.returncode, 0,
                            "an unrecordable pin reported success")
        self.assertIn(f"delete -host {OLD_ENDPOINT}", self.recorded(),
                      "the pin it could not record was left installed and unnamed")

    def test_the_new_pin_is_installed_before_the_old_one_is_withdrawn(self):
        """Order matters: the losing case must be a spare route, not none.

        Withdrawing first means a failed install leaves no pin at all, on a box
        whose tunnel needs one to reach its own peer.
        """
        self.assertEqual(self.pin().returncode, 0)
        self.forget_calls()
        self.switch_profile_to(NEW_ENDPOINT)
        self.assertEqual(self.pin().returncode, 0)

        calls = self.recorded().splitlines()
        added = next(i for i, line in enumerate(calls) if NEW_ENDPOINT in line)
        removed = next(i for i, line in enumerate(calls)
                       if f"delete -host {OLD_ENDPOINT}" in line)
        self.assertLess(added, removed,
                        f"the old pin was withdrawn first:\n{self.recorded()}")

    def test_a_corrupt_record_does_not_stop_the_pin(self):
        """Whatever is in that file, the box must still be able to route."""
        self.lock_dir.mkdir(exist_ok=True)
        self.pin_record.write_text("not-an-address\n", encoding="ascii")
        result = self.pin()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"-host {OLD_ENDPOINT}", self.recorded())
        self.assertNotIn("delete", self.recorded())


class ReintroducingTheLeak(ThePinMoves):
    """Edit the fix back out and the leak must come back.

    Without this the suite above proves only that the script runs: an assertion
    about a route command that is never issued in either version would pass in
    both. The one test that must invert is the arithmetic one.
    """

    def setUp(self) -> None:
        super().setUp()
        broken = self.root / "gatebsd-route-op.broken"
        text = ROUTE_OP.read_text(encoding="utf-8")
        needle = ('    [ -z "$_previous" ] || route delete -host "$_previous" '
                  '>/dev/null 2>&1 || true\n')
        self.assertIn(needle, text, "the line the reintroduction removes has moved")
        broken.write_text(text.replace(needle, "    :\n"), encoding="utf-8")
        os.chown(broken, 0, 0)
        broken.chmod(0o755)
        self.script = broken

    def test_switching_a_profile_removes_the_previous_pin(self):
        with self.assertRaises(AssertionError):
            super().test_switching_a_profile_removes_the_previous_pin()

    def test_the_first_pin_is_recorded_as_an_address(self):
        self.skipTest("unchanged by the reintroduction")

    def test_repinning_the_same_endpoint_deletes_nothing(self):
        self.skipTest("unchanged by the reintroduction")

    def test_unpinning_uses_the_record_when_the_name_has_died(self):
        self.skipTest("unchanged by the reintroduction")

    def test_a_missing_record_is_an_answer_not_an_error(self):
        self.skipTest("unchanged by the reintroduction")

    def test_a_corrupt_record_does_not_stop_the_pin(self):
        self.skipTest("unchanged by the reintroduction")

    def test_a_record_that_cannot_be_written_fails_the_pin(self):
        self.skipTest("unchanged by the reintroduction")

    def test_the_new_pin_is_installed_before_the_old_one_is_withdrawn(self):
        self.skipTest("unchanged by the reintroduction")


if __name__ == "__main__":
    unittest.main()
