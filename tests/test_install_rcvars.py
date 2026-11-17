"""`gatebsd-install --enable` must enable everything this package boots with.

The working router carries six rcvars; the installer set three. The other
three -- gatewayctl_apply_enable, ru_bypass_enable and the amnezia pair -- were
put there by hand, so a device rebuilt from the image would come up with no VPN
and no RU routes and look like a unit that had simply lost its tunnel. That is
the same family as the pkg repository config which also exists only on the live
machine: state the product depends on, living nowhere in the
tree.

This test RUNS the installer. The previous coverage of this script asserted on
its source text, which cannot tell an executed line from a commented-out one --
and the enable block is exactly the kind of thing that gets moved behind a
condition and silently stops running.

`amnezia_enable` is deliberately not asserted here: rc.d/gatewayctl_apply owns
bringing awg0 up ("mpd" and "amnezia" were not real providers, as its own
comment says), so whether the packaged amnezia service should also be enabled
is an open question rather than a settled one.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _stub_absolute_helpers() -> None:
    """Stand in for the helpers the installer calls by absolute path.

    GATEBSD_PATH cannot redirect these, so the container gets harmless stubs.
    """
    for name in ("gatebsd-config-migrate", "gatebsd-scan"):
        helper = Path("/usr/local/sbin") / name
        if helper.exists():
            continue
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        helper.chmod(0o755)

# Derived from the live router (`grep -Ei 'gatewayctl|gatebsd' /etc/rc.conf`),
# which is the only device known to boot correctly end to end.
EXPECTED = {
    "gatebsd_enable=YES",
    "gatebsd_failover_enable=YES",
    "nginx_enable=YES",
    "gatewayctl_apply_enable=YES",
    "ru_bypass_enable=YES",
}

# The installer writes to /var/db/gatebsd and /usr/local/etc/gatebsd with no way
# to redirect them, so running it for real is only safe in the disposable
# container harness -- never against someone's actual gateway.
_IN_CONTAINER = Path("/.dockerenv").exists()


@unittest.skipUnless(
    os.geteuid() == 0 and _IN_CONTAINER,
    "runs the real installer; needs the root-capable container harness",
)
class InstallEnablesEveryShippedService(unittest.TestCase):
    def _run_installer(self, workdir: Path) -> list[str]:
        stub_dir = workdir / "stub"
        stub_dir.mkdir()
        calls = workdir / "calls.txt"
        for name in ("sysrc", "service", "nginx", "make"):
            stub = stub_dir / name
            stub.write_text(
                f'#!/bin/sh\necho "{name} $*" >> "{calls}"\nexit 0\n', encoding="utf-8"
            )
            stub.chmod(0o755)
        _stub_absolute_helpers()

        environment = dict(os.environ)
        environment.update({
            # lockf is a FreeBSD tool; the harness is Linux, and the re-exec
            # under it is not what this test is about.
            "GATEBSD_INSTALL_LOCK_HELD": "1",
            "GATEBSD_PATH": f"{stub_dir}:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
            "GATEBSD_INSTALL_BACKUP_ROOT": str(workdir / "backups"),
        })
        result = subprocess.run(
            ["sh", str(ROOT / "sbin" / "gatebsd-install"), "--existing", "--enable"],
            capture_output=True, text=True, timeout=120, env=environment, cwd=str(ROOT),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        if not calls.exists():
            return []
        return [
            line.split(" ", 1)[1]
            for line in calls.read_text(encoding="utf-8").splitlines()
            if line.startswith("sysrc ")
        ]

    def test_every_shipped_service_is_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            enabled = set(self._run_installer(Path(td)))
        missing = EXPECTED - enabled
        self.assertFalse(
            missing,
            f"a device installed from the image would not start: {sorted(missing)}",
        )

    def test_nothing_is_enabled_without_the_flag(self) -> None:
        """--enable is opt-in; an import-only run must not touch rc.conf."""
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            stub_dir = workdir / "stub"
            stub_dir.mkdir()
            calls = workdir / "calls.txt"
            for name in ("sysrc", "service", "nginx", "make"):
                stub = stub_dir / name
                stub.write_text(
                    f'#!/bin/sh\necho "{name} $*" >> "{calls}"\nexit 0\n', encoding="utf-8"
                )
                stub.chmod(0o755)
            _stub_absolute_helpers()
            environment = dict(os.environ)
            environment.update({
                "GATEBSD_INSTALL_LOCK_HELD": "1",
                "GATEBSD_PATH": f"{stub_dir}:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
                "GATEBSD_INSTALL_BACKUP_ROOT": str(workdir / "backups"),
            })
            result = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-install"), "--existing"],
                capture_output=True, text=True, timeout=120, env=environment, cwd=str(ROOT),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
        self.assertNotIn("sysrc ", recorded)


if __name__ == "__main__":
    unittest.main()
