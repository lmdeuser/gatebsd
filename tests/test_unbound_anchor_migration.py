from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "sbin" / "gatebsd-config-migrate"
SAMPLE = ROOT / "etc" / "unbound" / "unbound.conf.sample"


class UnboundAnchorContractTests(unittest.TestCase):
    def test_sample_uses_the_service_writable_state_directory(self) -> None:
        self.assertIn('auto-trust-anchor-file: "/state/root.key"', SAMPLE.read_text(encoding="utf-8"))

    def test_rc_helper_is_given_the_config_with_the_anchor_path(self) -> None:
        script = MIGRATE.read_text(encoding="utf-8")
        self.assertIn('unbound_anchorflags="-a /usr/local/etc/unbound/state/root.key"', script)
        self.assertNotIn('unbound_anchorflags="-a /usr/local/etc/unbound/state/root.key -C', script)


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "migration requires root")
class UnboundAnchorMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)
        self.conf = self.dir / "unbound.conf"
        self.conf.write_text("server:\n    username: unbound\n", encoding="utf-8")
        self.state = self.dir / "state"
        self.state.mkdir()
        self.legacy = self.dir / "legacy-root.key"
        self.legacy.write_text("test-anchor\n", encoding="ascii")
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.accepts = True

    def _stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="ascii")
        path.chmod(0o755)

    def _run(self) -> subprocess.CompletedProcess[str]:
        self._stub("unbound-checkconf", f"exit {0 if self.accepts else 1}")
        self._stub("service", "exit 1")
        self._stub("su", "exit 0")
        self._stub("sysrc", f"printf '%s\\n' \"$*\" >> '{self.dir / 'sysrc.log'}")
        env = dict(os.environ)
        env.update({
            "GATEBSD_PATH": f"{self.bin}:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
            "GATEBSD_UNBOUND_CONF": str(self.conf),
            "GATEBSD_UNBOUND_STATE_DIR": str(self.state),
            "GATEBSD_UNBOUND_LEGACY_ANCHOR": str(self.legacy),
            "GATEBSD_MAIN_CONF": str(self.dir / "absent-main.conf"),
            "GATEBSD_FAILOVER_CONF": str(self.dir / "absent-failover.conf"),
            "GATEBSD_GATEWAY_CONF": str(self.dir / "absent-gateway.conf"),
            "GATEBSD_PF_CONF": str(self.dir / "absent-pf.conf"),
            "GATEBSD_NGINX_CONF": str(self.dir / "absent-nginx.conf"),
            "GATEBSD_RC_DIR": str(self.dir / "rc.d"),
            "GATEBSD_SSHD_CONF": str(self.dir / "absent-sshd.conf"),
            "GATEBSD_SUDOERS_CONF": str(self.dir / "absent-sudoers"),
            "GATEBSD_LEGACY_RU_STATE": str(self.dir / "absent-ru.state"),
            "RU_STATE_FILE": str(self.dir / "absent-ru-new.state"),
        })
        return subprocess.run(["sh", str(MIGRATE)], env=env, capture_output=True, text=True, timeout=60)

    def test_anchor_is_moved_and_converges_without_duplicates(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        text = self.conf.read_text(encoding="utf-8")
        self.assertEqual(text.count('auto-trust-anchor-file: "/state/root.key"'), 1)
        self.assertEqual((self.state / "root.key").read_text(encoding="ascii"), "test-anchor\n")
        self.assertEqual((self.dir / "sysrc.log").read_text(encoding="ascii").count("unbound_anchorflags"), 2)

    def test_legacy_anchor_path_is_replaced(self) -> None:
        self.conf.write_text('server:\n    username: unbound\n    auto-trust-anchor-file: "/usr/local/etc/unbound/root.key"\n', encoding="utf-8")
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        text = self.conf.read_text(encoding="utf-8")
        self.assertNotIn("/usr/local/etc/unbound/root.key", text)
        self.assertIn('auto-trust-anchor-file: "/state/root.key"', text)

    def test_validation_failure_preserves_the_original(self) -> None:
        self.accepts = False
        original = self.conf.read_text(encoding="utf-8")
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
