#!/usr/bin/env python3
"""A route operation must not re-own the runtime directory it borrows.

`/var/run/gatebsd` does not belong to gatebsd-route-op. The agent's unix socket
lives in it and the web UI -- which runs as the unprivileged service account --
reaches that socket through the group bits.

`install -d -o root -g gatebsd -m 0750` does not mean "create if missing". It
re-applies owner, group and mode to a directory that already exists. gatewayctl
did this on every apply, including the automatic one on the boot path, and from
that moment the panel answered "agent unavailable" to every request until
somebody noticed days later. The repair there became `ensure_shared_dir`:
validate what is there, create only what is missing, never re-own.

That repair never reached route-op, where the same call sits on the path of
every single route operation -- every apply, every failover, every watchdog
recovery. It has been benign only because it happens to re-apply the ownership
the directory already had.

It stopped being invisible on a machine with no `gatebsd` group at all: a build
host, a rehearsal rig. There `install -d` does not quietly re-own a correct
directory, it fails outright, and with it every mutating route action -- which
is how this was found, while rehearsing an unrelated change on the stand.

The test runs the real script. The reintroduction puts the unconditional call
back and asserts the directory is re-owned, because an assertion about
ownership that never changes in either version would pass in both.
"""
from __future__ import annotations

import grp
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_vpn_autostart import LOCKF_STUB, STAT_STUB, a_non_root_group  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ROUTE_OP = ROOT / "sbin" / "gatebsd-route-op"


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class TheRuntimeDirectoryIsLeftAlone(unittest.TestCase):

    script = ROUTE_OP

    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("route-op refuses mutating actions to a non-root caller")
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self._write("stat", STAT_STUB)
        # Linux has no lockf(1), and route-op refuses before it reaches the
        # directory handling without one. Nothing here claims anything
        # about the lock itself.
        self._write("lockf", LOCKF_STUB)

        self.conf = self.root / "gateway.conf"
        self.conf.write_text('VPN_IF="awg0"\nVPN_ENDPOINT_HOST="203.0.113.10"\n',
                             encoding="ascii")
        os.chown(self.conf, 0, 0)
        self.conf.chmod(0o600)

        # A directory that is already correct by route-op's own rules: root
        # owned, not group or world writable. Its group stands in for the one
        # gatebsd-install gives it, and it is the thing that must survive.
        self.borrowed_group = a_non_root_group()
        self.lock_dir = self.root / "run"
        # 0700, not 0750: route-op accepts both (neither is group or world
        # writable), but the defective call re-applies exactly 0750 -- so a
        # directory that starts at 0750 makes the mode assertion below unable
        # to fail, which is what it did until codex pointed at it.
        self.lock_dir.mkdir(mode=0o700)
        os.chown(self.lock_dir, 0, grp.getgrnam(self.borrowed_group).gr_gid)

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def group_of_lock_dir(self) -> str:
        return grp.getgrgid(self.lock_dir.stat().st_gid).gr_name

    def run_op(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Deliberately WITHOUT GATEBSD_GATEWAY_LOCK_HELD.

        The directory handling lives in the branch that takes the lock, so a
        harness that skips that branch to keep its stubs would skip the subject
        of this test entirely. The call is allowed to fail after it re-execs --
        past that point PATH is route-op's own and `stat -f` is Linux's -- and
        nothing here asserts on its status. What is asserted happened before it.
        """
        env = {
            "PATH": f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.root),
            "LANG": "C",
            "GATEBSD_GATEWAY_CONF": str(self.conf),
            "GATEBSD_GATEWAY_LOCK_FILE": str(self.lock_dir / "gatewayctl.lock"),
            "GATEBSD_ALLOW_TEST_PATH": "1",
            "GATEBSD_TEST_PATH_PREFIX": str(self.bin),
        }
        return subprocess.run(
            ["sh", str(self.script), *args],
            check=False, capture_output=True, text=True, env=env,
        )

    def test_an_existing_directory_keeps_its_group(self):
        self.run_op("unpin-endpoint")
        self.assertEqual(self.group_of_lock_dir(), self.borrowed_group,
                         "a route operation re-owned the runtime directory it "
                         "shares with the agent socket")

    def test_an_existing_directory_keeps_its_mode(self):
        self.run_op("unpin-endpoint")
        self.assertEqual(self.lock_dir.stat().st_mode & 0o777, 0o700)

    def test_a_missing_directory_is_still_created(self):
        """Not re-owning must not turn into not creating."""
        fresh = self.root / "fresh"
        env_dir = fresh / "gatewayctl.lock"
        self.assertFalse(fresh.exists())
        result = subprocess.run(
            ["sh", str(self.script), "unpin-endpoint"],
            check=False, capture_output=True, text=True,
            env={
                "PATH": f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": str(self.root),
                "LANG": "C",
                "GATEBSD_GATEWAY_CONF": str(self.conf),
                "GATEBSD_GATEWAY_LOCK_FILE": str(env_dir),
                "GATEBSD_ALLOW_TEST_PATH": "1",
                "GATEBSD_TEST_PATH_PREFIX": str(self.bin),
            },
        )
        # `gatebsd` need not exist on the machine running the tests, and
        # without it `install -d` cannot succeed -- so the requirement is stated
        # as the two outcomes that are both correct, and neither of which is
        # "carried on as though the directory were there". Accepting the mere
        # mention of the words in stderr, as this did at first, let a silent
        # failure through.
        if fresh.is_dir():
            return
        self.assertNotEqual(result.returncode, 0,
                            "a missing runtime directory was not created and no "
                            "failure was reported")
        self.assertIn("cannot create route lock directory", result.stderr)

    def test_an_unsafe_directory_is_still_refused(self):
        """Dropping the re-own must not drop the validation with it."""
        hostile = self.root / "hostile"
        hostile.mkdir()
        os.chown(hostile, 0, 0)
        hostile.chmod(0o777)
        result = subprocess.run(
            ["sh", str(self.script), "unpin-endpoint"],
            check=False, capture_output=True, text=True,
            env={
                "PATH": f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": str(self.root),
                "LANG": "C",
                "GATEBSD_GATEWAY_CONF": str(self.conf),
                "GATEBSD_GATEWAY_LOCK_FILE": str(hostile / "l.lock"),
                "GATEBSD_ALLOW_TEST_PATH": "1",
                "GATEBSD_TEST_PATH_PREFIX": str(self.bin),
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("writable", result.stderr)


class ReintroducingTheReown(TheRuntimeDirectoryIsLeftAlone):
    """Put the unconditional install back and the directory must be re-owned."""

    def setUp(self) -> None:
        super().setUp()
        text = ROUTE_OP.read_text(encoding="utf-8")
        needle = (
            '    else\n'
            '        install -d -o root -g gatebsd -m 0750 "$_lock_dir" \\\n'
            '            || fail "cannot create route lock directory: $_lock_dir"\n'
            '    fi\n'
        )
        self.assertIn(needle, text, "the branch the reintroduction removes has moved")
        # `root` rather than `gatebsd` only so the re-owning is observable on a
        # machine that has no gatebsd group; the defect is the unconditional
        # call, not which group it names.
        broken_text = text.replace(
            needle, '    fi\n    install -d -o root -g root -m 0750 "$_lock_dir"\n')
        broken = self.root / "route-op.broken"
        broken.write_text(broken_text, encoding="utf-8")
        os.chown(broken, 0, 0)
        broken.chmod(0o755)
        self.script = broken

    def test_an_existing_directory_keeps_its_group(self):
        with self.assertRaises(AssertionError):
            super().test_an_existing_directory_keeps_its_group()

    def test_an_existing_directory_keeps_its_mode(self):
        with self.assertRaises(AssertionError):
            super().test_an_existing_directory_keeps_its_mode()

    def test_a_missing_directory_is_still_created(self):
        self.skipTest("unchanged by the reintroduction")

    def test_an_unsafe_directory_is_still_refused(self):
        self.skipTest("unchanged by the reintroduction")


if __name__ == "__main__":
    unittest.main()
