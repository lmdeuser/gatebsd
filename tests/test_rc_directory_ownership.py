"""The startup directory must not be writable by anyone but root.

Found on the production router: /usr/local/etc/rc.d was operator:operator and
group-writable, and the amnezia script inside it was owned the same way.
rcorder(8) reads that directory whole and init runs what it finds as root, so
an unprivileged account could drop a file there and own the machine at the next
boot. The same directory is where a hand-made backup that kept its PROVIDE:
line once ran ahead of the real script -- this is not a hypothetical corner.

The migration corrects only what is wrong. Re-owning a directory that is
already correct is how both shared runtime directories were broken before, and
a migration that rewrites good state every run trains everyone to ignore it. So
there are tests for leaving things alone, not only for fixing them.

Every test RUNS sbin/gatebsd-config-migrate.
"""
from __future__ import annotations

import os
import pwd
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "sbin" / "gatebsd-config-migrate"


def _a_non_root_uid() -> int | None:
    for name in ("nobody", "daemon", "bin"):
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            continue
        if entry.pw_uid != 0:
            return entry.pw_uid
    return None


NON_ROOT = _a_non_root_uid()


@unittest.skipUnless(
    hasattr(os, "geteuid") and os.geteuid() == 0 and NON_ROOT is not None,
    "chown needs root and a non-root account to hand things to",
)
class RcDirectoryOwnershipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)
        self.rc = self.dir / "rc.d"
        self.rc.mkdir()
        self.script = self.rc / "gatebsd"
        self.script.write_text("#!/bin/sh\n", encoding="utf-8")
        self.script.chmod(0o755)

    def _run(self) -> subprocess.CompletedProcess:
        environment = dict(os.environ)
        environment.update({
            "GATEBSD_RC_DIR": str(self.rc),
            # Everything else this script migrates is out of scope here.
            "GATEBSD_MAIN_CONF": str(self.dir / "absent-main.conf"),
            "GATEBSD_FAILOVER_CONF": str(self.dir / "absent-failover.conf"),
            "GATEBSD_GATEWAY_CONF": str(self.dir / "absent-gateway.conf"),
            "GATEBSD_UNBOUND_CONF": str(self.dir / "absent-unbound.conf"),
            "GATEBSD_PF_CONF": str(self.dir / "absent-pf.conf"),
            "GATEBSD_LEGACY_RU_STATE": str(self.dir / "absent-ru.state"),
            "RU_STATE_FILE": str(self.dir / "absent-ru-new.state"),
        })
        return subprocess.run(
            ["sh", str(MIGRATE)], env=environment,
            capture_output=True, text=True, timeout=60,
        )

    # ------------------------------------------------------------------ the hole
    def test_a_directory_owned_by_a_user_is_taken_back(self) -> None:
        os.chown(self.rc, NON_ROOT, NON_ROOT)
        result = self._run()
        self.assertEqual(self.rc.stat().st_uid, 0, result.stdout + result.stderr)

    def test_a_group_writable_directory_is_tightened(self) -> None:
        """Owned by root is not enough if the group can still write to it."""
        self.rc.chmod(0o775)
        self._run()
        self.assertEqual(self.rc.stat().st_mode & 0o777, 0o755)

    def test_a_script_owned_by_a_user_is_taken_back(self) -> None:
        """It runs as root at boot whoever owns it, so the file matters too."""
        os.chown(self.script, NON_ROOT, NON_ROOT)
        self._run()
        self.assertEqual(self.script.stat().st_uid, 0)

    # ------------------------------------------------------------------ restraint
    def test_a_correct_directory_is_left_exactly_as_it_is(self) -> None:
        """Rewriting good state every run is how the runtime dirs got broken."""
        self.rc.chmod(0o755)
        before = self.rc.stat()
        result = self._run()
        after = self.rc.stat()
        self.assertEqual((after.st_uid, after.st_gid, after.st_mode),
                         (before.st_uid, before.st_gid, before.st_mode))
        self.assertNotIn("corrected ownership", result.stdout)

    def test_a_symlink_inside_is_never_followed(self) -> None:
        """Otherwise a planted link redirects the chown at any file on the system."""
        target = self.dir / "outside"
        target.write_text("private\n", encoding="utf-8")
        os.chown(target, NON_ROOT, NON_ROOT)
        (self.rc / "planted").symlink_to(target)

        result = self._run()

        self.assertEqual(target.stat().st_uid, NON_ROOT, "the chown followed a symlink out of rc.d")
        self.assertIn("ignoring symlink", result.stderr)


if __name__ == "__main__":
    unittest.main()
