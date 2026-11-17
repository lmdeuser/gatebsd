"""The shared runtime directory must survive a failoverctl invocation.

The defect these exist for: ``gatebsd-failoverctl`` created the directory of its
lock file and of its manual-WAN request with
``install -d -o root -g wheel -m 0750``. That directory is
``/var/run/gatebsd`` -- not this tool's own, but the one holding the agent's
unix socket. The web UI runs as the unprivileged service account and needs the
group's traverse bit to reach that socket, so every non-status invocation --
switching WAN mode from the admin panel was enough -- locked the UI out. It then
answered 503 "agent unavailable" to every request, and the admin panel could not
be logged into at all until the group was put back by hand.

Both tests run the real script. The reintroduction test runs a copy with the
old ``install -d`` restored, and asserts the directory really does get re-owned,
so the guard is known to be measuring something.
"""
from __future__ import annotations

import grp
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAILOVERCTL = ROOT / "sbin" / "gatebsd-failoverctl"

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


def two_distinct_groups() -> tuple[str, str]:
    """Two real groups on this host, neither of them root."""
    names = [g.gr_name for g in grp.getgrall() if g.gr_gid not in (0,)]
    unique: list[str] = []
    for name in names:
        if name not in unique:
            unique.append(name)
        if len(unique) == 2:
            break
    if len(unique) < 2:
        raise unittest.SkipTest("need two non-root groups to observe re-owning")
    return unique[0], unique[1]


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class FailoverctlRuntimeDirTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("failoverctl requires root")
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.run_dir = self.root / "run"
        self.run_dir.mkdir(mode=0o750)

        self.owned_group, self.other_group = two_distinct_groups()
        # The directory starts out belonging to the service group, exactly as
        # the package's post-install leaves it.
        os.chown(self.run_dir, 0, grp.getgrnam(self.owned_group).gr_gid)

        self.conf = self.root / "failover.conf"
        self.conf.write_text('FAILOVER_MODE="automatic"\n', encoding="ascii")
        os.chown(self.conf, 0, 0)
        self.conf.chmod(0o600)

        self._write("lockf", LOCKF_STUB)
        self._write("stat", STAT_STUB)
        self._write("service", "#!/bin/sh\nexit 0\n")
        self._write("logger", "#!/bin/sh\nexit 0\n")
        # Ends the manual-switch wait loop immediately: `set -e` aborts on a
        # failing sleep, after the request has already been written.
        self._write("sleep", "#!/bin/sh\nexit 1\n")

        self.script = FAILOVERCTL

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def run_ctl(self, *args: str, hold_lock: bool = False) -> subprocess.CompletedProcess[str]:
        # `hold_lock` skips the re-exec through lockf. That matters for what a
        # test can observe: the re-exec runs `env -i PATH="$PATH" ...` and the
        # child then reassigns PATH from its own default, so the stubs here are
        # only in effect in the first process. Assertions about the lock
        # directory hold either way -- it is created before the re-exec.
        env = {
            "PATH": f"{self.bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "GATEBSD_PATH": f"{self.bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "GATEBSD_FAILOVER_CONF": str(self.conf),
            "GATEBSD_FAILOVER_STATE": str(self.run_dir / "watchdog.json"),
            "GATEBSD_MANUAL_WAN_FILE": str(self.run_dir / "manual-wan"),
            "GATEBSD_FAILOVERCTL_LOCK": str(self.run_dir / "failoverctl.lock"),
            "HOME": str(self.root),
            "LANG": "C",
        }
        if hold_lock:
            env["GATEBSD_FAILOVERCTL_LOCK_HELD"] = "1"
        return subprocess.run(
            ["sh", str(self.script), *args],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def group_of_run_dir(self) -> str:
        return grp.getgrgid(self.run_dir.stat().st_gid).gr_name

    def reintroduce(self, pattern: str, replacement: str) -> None:
        source = FAILOVERCTL.read_text(encoding="utf-8")
        patched, count = re.subn(pattern, replacement, source)
        if count == 0:
            raise AssertionError(f"reintroduction pattern never matched: {pattern!r}")
        self.script = self.root / "failoverctl-defective"
        self.script.write_text(patched, encoding="utf-8")
        self.script.chmod(0o755)

    # -- the fix -----------------------------------------------------------
    def test_setting_a_mode_leaves_the_runtime_directory_alone(self) -> None:
        self.run_ctl("observe")
        self.assertEqual(
            self.group_of_run_dir(),
            self.owned_group,
            "the agent socket's directory was re-owned; the web UI loses access",
        )

    def test_a_manual_wan_request_leaves_the_runtime_directory_alone(self) -> None:
        self.conf.write_text('FAILOVER_MODE="manual"\n', encoding="ascii")
        self.conf.chmod(0o600)

        self.run_ctl("backup", hold_lock=True)

        self.assertTrue(
            (self.run_dir / "manual-wan").exists(), "the request was never written"
        )
        self.assertEqual(self.group_of_run_dir(), self.owned_group)

    def test_a_missing_runtime_directory_is_still_created(self) -> None:
        """Guarding an existing directory must not stop it being made."""
        fresh = self.root / "fresh"
        env_dir = fresh / "failoverctl.lock"
        result = subprocess.run(
            ["sh", str(FAILOVERCTL), "observe"],
            check=False,
            capture_output=True,
            text=True,
            env={
                "PATH": f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin",
                "GATEBSD_PATH": f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin",
                "GATEBSD_FAILOVER_CONF": str(self.conf),
                "GATEBSD_FAILOVER_STATE": str(fresh / "watchdog.json"),
                "GATEBSD_MANUAL_WAN_FILE": str(fresh / "manual-wan"),
                "GATEBSD_FAILOVERCTL_LOCK": str(env_dir),
                "GATEBSD_SERVICE_GROUP": self.owned_group,
                "HOME": str(self.root),
                "LANG": "C",
            },
        )
        self.assertTrue(fresh.is_dir(), result.stderr)
        self.assertEqual(grp.getgrgid(fresh.stat().st_gid).gr_name, self.owned_group)

    # -- reintroduction ----------------------------------------------------
    def test_reintroducing_the_reowning_install_breaks_the_agent_socket(self) -> None:
        """Put the old `install -d -o root -g ...` back and watch it re-own."""
        self.reintroduce(
            r'    ensure_runtime_dir "\$\(dirname "\$LOCK_FILE"\)"\n',
            f'    install -d -o root -g {self.other_group} -m 0750 '
            f'"$(dirname "$LOCK_FILE")"\n',
        )
        self.run_ctl("observe")
        self.assertEqual(
            self.group_of_run_dir(),
            self.other_group,
            "the reintroduced defect did not re-own the directory; "
            "the guard would be measuring nothing",
        )


if __name__ == "__main__":
    unittest.main()
