from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "sbin" / "gatebsd-config-migrate"
NEWSYSLOG = ROOT / "etc" / "newsyslog.conf.d" / "gatebsd.conf"


class LogPermissionContractTests(unittest.TestCase):
    def test_rotation_does_not_make_ui_and_recovery_logs_world_readable(self) -> None:
        entries = {}
        for line in NEWSYSLOG.read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if fields and not line.startswith("#"):
                entries[fields[0]] = fields
        for name in ("gatebsd-ui.log", "gatebsd-recovery.log"):
            self.assertEqual(entries[f"/var/log/{name}"][1], "600")


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "migration requires root")
class LogPermissionMigrationTests(unittest.TestCase):
    def test_existing_ui_and_recovery_logs_become_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            log_dir = root / "log"
            log_dir.mkdir()
            logs = (log_dir / "gatebsd-ui.log", log_dir / "gatebsd-recovery.log")
            for path in logs:
                path.write_text("test\n", encoding="ascii")
                path.chmod(0o644)
            for name, body in {
                "chown": "exit 0",
                "service": "exit 1",
                "su": "exit 0",
                "sysrc": "exit 0",
                "unbound-checkconf": "exit 0",
            }.items():
                stub = bin_dir / name
                stub.write_text(f"#!/bin/sh\n{body}\n", encoding="ascii")
                stub.chmod(0o755)
            unbound = root / "unbound.conf"
            unbound.write_text("server:\n    username: unbound\n", encoding="ascii")
            state = root / "state"
            state.mkdir()
            legacy = root / "legacy-root.key"
            legacy.write_text("test-anchor\n", encoding="ascii")
            env = dict(os.environ)
            env.update({
                "GATEBSD_PATH": f"{bin_dir}:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
                "GATEBSD_LOG_DIR": str(log_dir),
                "GATEBSD_UNBOUND_CONF": str(unbound),
                "GATEBSD_UNBOUND_STATE_DIR": str(state),
                "GATEBSD_UNBOUND_LEGACY_ANCHOR": str(legacy),
                "GATEBSD_MAIN_CONF": str(root / "absent-main.conf"),
                "GATEBSD_FAILOVER_CONF": str(root / "absent-failover.conf"),
                "GATEBSD_GATEWAY_CONF": str(root / "absent-gateway.conf"),
                "GATEBSD_PF_CONF": str(root / "absent-pf.conf"),
                "GATEBSD_NGINX_CONF": str(root / "absent-nginx.conf"),
                "GATEBSD_RC_DIR": str(root / "rc.d"),
                "GATEBSD_SSHD_CONF": str(root / "absent-sshd.conf"),
                "GATEBSD_SUDOERS_CONF": str(root / "absent-sudoers"),
                "GATEBSD_LEGACY_RU_STATE": str(root / "absent-ru.state"),
                "RU_STATE_FILE": str(root / "absent-ru-new.state"),
            })
            result = subprocess.run(
                ["sh", str(MIGRATE)], env=env, capture_output=True, text=True, timeout=60
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for path in logs:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path.name)


if __name__ == "__main__":
    unittest.main()
