from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "sbin" / "gatebsd-agentctl"


class AgentctlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.calls = self.dir / "calls.log"
        self._stub("id", "#!/bin/sh\nif [ \"$1\" = -u ]; then echo 0; else exec /usr/bin/id \"$@\"; fi\n")

    def _stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        for name in ("service", "pfctl", "pkg", "gatebsd-upgrade", "gatebsd-firstboot", "freebsd-update", "nginx", "sshd", "unbound-checkconf", "bectl", "shutdown", "cat"):
            self._stub(name, f"#!/bin/sh\nprintf '{name} %s\\n' \"$*\" >> '{self.calls}'\n")
        env = dict(os.environ)
        env["GATEBSD_PATH"] = str(self.bin)
        env["PATH"] = str(self.bin)
        return subprocess.run([str(SCRIPT), *args], env=env, capture_output=True, text=True)

    def test_arbitrary_shell_and_sensitive_reads_are_denied(self) -> None:
        for args in (("sh",), ("read-file", "/etc/master.passwd"), ("service-status", "anything"), ("be-create", "gatebsd-../x")):
            with self.subTest(args=args):
                result = self._run(*args)
                self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_only_named_service_actions_are_executed(self) -> None:
        result = self._run("service-status", "nginx")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self._run("service-reload", "sshd")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text(encoding="ascii")
        self.assertIn("service nginx onestatus", calls)
        self.assertIn("service sshd reload", calls)

    def test_upgrade_uses_existing_transaction(self) -> None:
        result = self._run("gatebsd-upgrade", "/var/tmp/gatebsd-test.pkg")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("gatebsd-upgrade /var/tmp/gatebsd-test.pkg", self.calls.read_text(encoding="ascii"))

        result_all = self._run("gatebsd-upgrade", "/var/tmp/All/gatebsd-test.pkg")
        self.assertEqual(result_all.returncode, 0, result_all.stderr)
        self.assertIn("gatebsd-upgrade /var/tmp/All/gatebsd-test.pkg", self.calls.read_text(encoding="ascii"))

        bad_nested = self._run("gatebsd-upgrade", "/var/tmp/nested/gatebsd-test.pkg")
        self.assertNotEqual(bad_nested.returncode, 0)

    def test_pkg_fetch_uses_the_signed_release_repository(self) -> None:
        result = self._run("pkg-fetch")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text(encoding="ascii")
        self.assertIn("pkg update -r gatebsd-releases", calls)
        self.assertIn("pkg fetch -y -r gatebsd-releases -o /var/tmp gatebsd", calls)

    def test_identity_and_base_update_have_explicit_verbs(self) -> None:
        self.assertEqual(self._run("firstboot").returncode, 0)
        self.assertEqual(self._run("freebsd-update-fetch").returncode, 0)
        self.assertEqual(self._run("freebsd-update-install").returncode, 0)
        calls = self.calls.read_text(encoding="ascii")
        self.assertIn("gatebsd-firstboot", calls)
        self.assertIn("freebsd-update fetch --not-running-from-cron", calls)
        self.assertIn("freebsd-update install", calls)

    def test_security_package_update_has_a_fixed_package_set(self) -> None:
        result = self._run("pkg-security-updates")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "pkg install -y -f -r gatebsd-ports rsync p5-Authen-SASL python312 py312-sqlite3 amneziawg-go nginx",
            self.calls.read_text(encoding="ascii"),
        )

    def test_boot_environment_and_reboot_are_explicit_verbs(self) -> None:
        self.assertEqual(self._run("be-list").returncode, 0)
        self.assertEqual(self._run("be-create", "gatebsd-pre-security-test").returncode, 0)
        self.assertEqual(self._run("system-reboot").returncode, 0)
        calls = self.calls.read_text(encoding="ascii")
        self.assertIn("bectl list", calls)
        self.assertIn("bectl create gatebsd-pre-security-test", calls)
        self.assertIn("shutdown -r now", calls)

    def test_backup_fetch_streams_only_a_named_final_image(self) -> None:
        result = self._run("backup-fetch", "gatebsd-test.img.gz")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cat /var/backups/gatebsd-image/gatebsd-test.img.gz", self.calls.read_text(encoding="ascii"))
        self.assertNotEqual(self._run("backup-fetch", "../master.passwd").returncode, 0)

    def test_sudo_grant_is_single_helper_and_both_delivery_paths_install_it(self) -> None:
        sudoers = (ROOT / "etc" / "sudoers.d" / "gatebsd-agent").read_text(encoding="utf-8")
        self.assertIn("NOPASSWD: /usr/local/sbin/gatebsd-agentctl", sudoers)
        self.assertNotIn("NOPASSWD: ALL", sudoers)
        for relative in ("ci/build.sh", "Makefile"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("gatebsd-agentctl", text)
            self.assertIn("etc/sudoers.d/gatebsd-agent", text)
            self.assertIn("gatebsd-agent", text)

    def test_m5_allows_additional_managed_services_and_rejects_newlines_portably(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("$'\\n'", source)
        for svc in ("ru_bypass", "amnezia", "gatebsd_reverse_ssh", "smartd"):
            with self.subTest(service=svc):
                result = self._run("service-status", svc)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"service {svc} onestatus", self.calls.read_text(encoding="ascii"))
        # Newline inside stat-file path must be rejected under POSIX /bin/sh.
        self._stub("stat", "#!/bin/sh\necho 'stat should not run'\nexit 0\n")
        res = self._run("stat-file", "/etc/pf.conf\n/etc/master.passwd")
        self.assertNotEqual(res.returncode, 0)

    def test_disk_usage_be_destroy_and_image_prune_controls(self) -> None:
        for name in ("service", "pfctl", "pkg", "gatebsd-upgrade", "gatebsd-firstboot", "freebsd-update", "nginx", "sshd", "unbound-checkconf", "shutdown", "cat", "df", "du", "ls"):
            self._stub(name, f"#!/bin/sh\nprintf '{name} %s\\n' \"$*\" >> '{self.calls}'\n")
        self._stub(
            "bectl",
            "#!/bin/sh\n"
            f"printf 'bectl %s\\n' \"$*\" >> '{self.calls}'\n"
            'if [ "${1:-}" = list ] && [ "${2:-}" = -H ]; then\n'
            '  printf "default\\tNR\\t/\\t50G\\t2026-07-08\\n"\n'
            '  printf "gatebsd-active\\tR\\t/\\t10M\\t2026-11-01\\n"\n'
            '  printf "gatebsd-preupgrade-old\\t-\\t-\\t9M\\t2026-08-30\\n"\n'
            '  exit 0\n'
            "fi\n"
            "exit 0\n",
        )
        self._stub(
            "stat",
            "#!/bin/sh\n"
            'if /usr/bin/stat -f "%m %N" / >/dev/null 2>&1; then\n'
            '  exec /usr/bin/stat "$@"\n'
            "fi\n"
            'if [ "${1:-}" = -f ] && [ "${2:-}" = "%m %N" ]; then\n'
            "  shift 2\n"
            '  exec /usr/bin/stat -c "%Y %n" "$@"\n'
            "fi\n"
            'exec /usr/bin/stat "$@"\n',
        )

        img_dir = self.dir / "images"
        img_dir.mkdir()
        img1 = img_dir / "gatebsd-2.9.100-1.img.gz"
        img2 = img_dir / "gatebsd-2.9.110-2.img.gz"
        img3 = img_dir / "gatebsd-2.9.120-3.img.gz"
        for idx, path in enumerate((img1, img2, img3), start=1):
            path.write_bytes(b"img")
            os.utime(path, (1000 * idx, 1000 * idx))

        fetch_dir = self.dir / "pkg-fetch"
        all_dir = fetch_dir / "All"
        all_dir.mkdir(parents=True)
        p1 = all_dir / "gatebsd-2.9.130.pkg"
        p2 = all_dir / "gatebsd-2.9.131.pkg"
        p3 = all_dir / "gatebsd-2.9.132.pkg"
        t1 = fetch_dir / "gatebsd-2.9.130.pkg"
        t2 = fetch_dir / "gatebsd-2.9.131.pkg"
        t3 = fetch_dir / "gatebsd-2.9.132.pkg"
        for idx, path in enumerate((p1, p2, p3), start=1):
            path.write_bytes(b"pkg")
            os.utime(path, (1000 * idx, 1000 * idx))
        for idx, path in enumerate((t1, t2, t3), start=1):
            path.write_bytes(b"pkg")
            os.utime(path, (1000 * idx, 1000 * idx))

        env = dict(os.environ)
        env["GATEBSD_PATH"] = f"{self.bin}:/usr/bin:/bin"
        env["PATH"] = f"{self.bin}:/usr/bin:/bin"
        env["GATEBSD_IMAGE_BACKUP_DIR"] = str(img_dir)
        env["GATEBSD_PKG_FETCH_DIR"] = str(fetch_dir)

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run([str(SCRIPT), *args], env=env, capture_output=True, text=True)

        du_res = run("disk-usage")
        self.assertEqual(du_res.returncode, 0, du_res.stderr)

        for bad_be in ("default", "15.1-RELEASE", "gatebsd-../bad", "gatebsd-active", "gatebsd-missing"):
            self.assertNotEqual(run("be-destroy", bad_be).returncode, 0, bad_be)

        be_ok = run("be-destroy", "gatebsd-preupgrade-old")
        self.assertEqual(be_ok.returncode, 0, be_ok.stderr)
        self.assertIn("bectl destroy -o gatebsd-preupgrade-old", self.calls.read_text(encoding="ascii"))

        for bad_keep in ("-1", "99", "abc"):
            self.assertNotEqual(run("image-backup-prune", bad_keep).returncode, 0, bad_keep)

        prune_one = run("image-backup-prune")
        self.assertEqual(prune_one.returncode, 0, prune_one.stderr)
        self.assertFalse(img1.exists())
        self.assertFalse(img2.exists())
        self.assertTrue(img3.is_file())

        prune_zero = run("image-backup-prune", "0")
        self.assertEqual(prune_zero.returncode, 0, prune_zero.stderr)
        self.assertFalse(img3.exists())

        fetch_res = run("pkg-fetch")
        self.assertEqual(fetch_res.returncode, 0, fetch_res.stderr)
        self.assertFalse(p1.exists())
        self.assertTrue(p2.is_file())
        self.assertTrue(p3.is_file())
        self.assertFalse(t1.exists())
        self.assertTrue(t2.is_file())
        self.assertTrue(t3.is_file())


if __name__ == "__main__":
    unittest.main()
