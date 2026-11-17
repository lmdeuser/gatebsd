from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from gatebsd_ui import backup, paths

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "sbin" / "gatebsd-config-migrate"
DROP_IN = ROOT / "etc" / "ssh" / "sshd_config.d" / "gatebsd.conf"


class SshDropInContractTests(unittest.TestCase):
    def test_drop_in_requires_keys_and_disables_forwarding(self) -> None:
        values = {}
        for raw in DROP_IN.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, value = line.split(None, 1)
            values[key.lower()] = value
        self.assertEqual(values["authenticationmethods"], "publickey")
        self.assertEqual(values["passwordauthentication"], "no")
        self.assertEqual(values["kbdinteractiveauthentication"], "no")
        self.assertEqual(values["pubkeyauthentication"], "yes")
        self.assertEqual(values["permitrootlogin"], "no")
        self.assertEqual(values["allowagentforwarding"], "no")
        self.assertEqual(values["allowtcpforwarding"], "no")
        self.assertEqual(values["x11forwarding"], "no")

    def test_h5_drop_in_uses_wheel_and_agent_groups_without_personal_usernames(self) -> None:
        raw = DROP_IN.read_text(encoding="utf-8")
        values = {}
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key, value = stripped.split(None, 1)
            values[key.lower()] = value
        self.assertNotIn("operator", raw)
        self.assertNotIn("allowusers", values)
        self.assertEqual(values.get("allowgroups"), "wheel gatebsd-agent")

    def test_both_delivery_paths_install_the_drop_in(self) -> None:
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        for text in (build, makefile):
            self.assertIn("etc/ssh/sshd_config.d/gatebsd.conf", text)
            self.assertIn("gatebsd-config-migrate", text)

    def test_sudoers_migration_removes_only_unattended_wheel_access(self) -> None:
        script = MIGRATE.read_text(encoding="utf-8")
        self.assertIn('%wheel ALL=(ALL:ALL) NOPASSWD: ALL', script)
        self.assertIn("visudo -c -f", script)
        self.assertIn("migrate_sudoers_nopasswd", script)

    def test_restore_validates_ssh_and_sudoers(self) -> None:
        self.assertEqual(backup._restore_validator(paths.SSHD_CONF), ["sshd", "-t", "-f"])
        self.assertEqual(backup._restore_validator(paths.SUDOERS_CONF), ["visudo", "-c", "-f"])
        self.assertIn(paths.SSHD_GATEBSD_CONF, paths.CONFIG_FILES.values())
        self.assertIn(paths.SUDOERS_AGENT_CONF, paths.CONFIG_FILES.values())


class SshIncludeMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)
        self.main = self.dir / "sshd_config"
        self.main.write_text("Port 22\nPasswordAuthentication yes\n", encoding="utf-8")
        self.backups = self.dir / "backups"
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.sshd_log = self.dir / "sshd.log"
        self.service_log = self.dir / "service.log"
        self.sshd_running = False
        self._stub_sshd(accepts=True)
        self._stub_exec(
            "id",
            '#!/bin/sh\nif [ "${1:-}" = -u ]; then echo 0; exit 0; fi\nexec /usr/bin/id "$@"\n',
        )
        self._stub_exec(
            "stat",
            '#!/bin/sh\n'
            'if [ "${1:-}" = -c ] && [ "${2:-}" = "%u" ]; then echo 0; exit 0; fi\n'
            'if [ "${1:-}" = -f ] && [ "${2:-}" = "%u" ]; then echo 0; exit 0; fi\n'
            'exec /usr/bin/stat "$@"\n',
        )
        self._stub_exec(
            "install",
            '#!/bin/sh\n'
            'if [ "${1:-}" = -d ]; then\n'
            '  for _last; do :; done\n'
            '  mkdir -p -m 0700 "$_last"\n'
            '  exit $?\n'
            'fi\n'
            'exec /usr/bin/install "$@"\n',
        )
        self._write_service_stub()

    def _stub_exec(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def _write_service_stub(self) -> None:
        self._stub_exec(
            "service",
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >> "{self.service_log}"\n'
            'if [ "${1:-}" = sshd ] && [ "${2:-}" = onestatus ]; then\n'
            f'  exit {0 if self.sshd_running else 1}\n'
            'fi\n'
            'exit 0\n',
        )

    def _stub_sshd(self, *, accepts: bool) -> None:
        path = self.bin / "sshd"
        path.write_text(
            f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{self.sshd_log}'\nexit {0 if accepts else 1}\n",
            encoding="ascii",
        )
        path.chmod(0o755)

    def _run(self) -> subprocess.CompletedProcess[str]:
        self._write_service_stub()
        env = dict(os.environ)
        env.update({
            "GATEBSD_PATH": f"{self.bin}:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
            "GATEBSD_SSHD_CONF": str(self.main),
            "GATEBSD_SSHD_BACKUP_DIR": str(self.backups),
            "GATEBSD_SSHD_GATEBSD_CONF": str(DROP_IN),
            "GATEBSD_MAIN_CONF": str(self.dir / "absent-main.conf"),
            "GATEBSD_FAILOVER_CONF": str(self.dir / "absent-failover.conf"),
            "GATEBSD_GATEWAY_CONF": str(self.dir / "absent-gateway.conf"),
            "GATEBSD_SPLIT_DNS_CONF": str(self.dir / "absent-split-dns.conf"),
            "GATEBSD_UNBOUND_CONF": str(self.dir / "absent-unbound.conf"),
            "GATEBSD_PF_CONF": str(self.dir / "absent-pf.conf"),
            "GATEBSD_NGINX_CONF": str(self.dir / "absent-nginx.conf"),
            "GATEBSD_SUDOERS_CONF": str(self.dir / "absent-sudoers"),
            "GATEBSD_DB_DIR": str(self.dir / "absent-db"),
            "GATEBSD_LOG_DIR": str(self.dir / "absent-log"),
            "GATEBSD_RC_DIR": str(self.dir / "rc.d"),
            "GATEBSD_LEGACY_RU_STATE": str(self.dir / "absent-ru.state"),
            "RU_STATE_FILE": str(self.dir / "absent-ru-new.state"),
        })
        return subprocess.run(["sh", str(MIGRATE)], env=env, capture_output=True, text=True, timeout=60)

    def test_include_is_prepended_and_candidate_is_validated(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.main.read_text(encoding="utf-8").startswith("Include /etc/ssh/sshd_config.d/*.conf\n"))
        self.assertIn("-t -f", self.sshd_log.read_text(encoding="ascii"))
        self.assertEqual(len(list(self.backups.rglob("sshd_config"))), 1)

    def test_rejected_candidate_leaves_original_untouched(self) -> None:
        self._stub_sshd(accepts=False)
        original = self.main.read_text(encoding="utf-8")
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.main.read_text(encoding="utf-8"), original)
        self.assertIn("left unchanged", result.stderr)

    def test_existing_include_is_idempotent(self) -> None:
        self.main.write_text("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n", encoding="utf-8")
        original = self.main.read_text(encoding="utf-8")
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.main.read_text(encoding="utf-8"), original)
        self.assertFalse(self.backups.exists())

    def test_global_allowusers_is_retired_and_sshd_reloaded_preserving_match_blocks(self) -> None:
        original = (
            "Include /etc/ssh/sshd_config.d/*.conf\n"
            "Port 22\n"
            "AllowUsers legacyuser\n"
            "Match User backup_sync\n"
            "    AllowUsers backup_sync\n"
            "    AllowTcpForwarding no\n"
        )
        self.main.write_text(original, encoding="utf-8")
        self.sshd_running = True
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        updated = self.main.read_text(encoding="utf-8")
        self.assertNotIn("AllowUsers legacyuser", updated)
        self.assertIn("Include /etc/ssh/sshd_config.d/*.conf", updated)
        self.assertIn("Port 22", updated)
        self.assertIn("Match User backup_sync\n    AllowUsers backup_sync", updated)
        backups = list(self.backups.rglob("sshd_config"))
        self.assertEqual(len(backups), 1)
        self.assertIn("AllowUsers legacyuser", backups[0].read_text(encoding="utf-8"))
        self.assertIn("-t -f", self.sshd_log.read_text(encoding="ascii"))
        self.assertIn("sshd reload", self.service_log.read_text(encoding="ascii"))


if __name__ == "__main__":
    unittest.main()
