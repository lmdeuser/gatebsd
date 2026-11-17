from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gatebsd_ui import agent, api, backup, paths
from gatebsd_ui.writers import dns

REPO_ROOT = Path(__file__).resolve().parents[1]


def _idna(domain: str) -> str:
    return domain.encode("idna").decode("ascii")


class SplitDnsWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.unbound_dir = root / "unbound"
        self.unbound_dir.mkdir()
        self.unbound_conf = self.unbound_dir / "unbound.conf"
        self.unbound_split_conf = self.unbound_dir / "split-dns.conf"
        self.split_conf = root / "split-dns.conf"
        self.backup_dir = root / "backups"
        self.unbound_conf.write_text(
            "server:\n"
            "    interface: 127.0.0.1\n\n"
            "forward-zone:\n"
            '    name: "."\n'
            "    forward-addr: 1.1.1.1\n"
            "    forward-addr: 9.9.9.9\n",
            encoding="utf-8",
        )
        self.patches = (
            patch.object(paths, "UNBOUND_CONF", self.unbound_conf),
            patch.object(paths, "UNBOUND_SPLIT_DNS_CONF", self.unbound_split_conf),
            patch.object(paths, "SPLIT_DNS_CONF", self.split_conf),
            patch.object(paths, "BACKUP_DIR", self.backup_dir),
            patch.object(dns.paths, "UNBOUND_CONF", self.unbound_conf),
            patch.object(dns.paths, "UNBOUND_SPLIT_DNS_CONF", self.unbound_split_conf),
            patch.object(dns.paths, "SPLIT_DNS_CONF", self.split_conf),
        )
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_set_and_get_split_dns_renders_punycode_and_preserves_root_forwarder(self) -> None:
        commands: list[list[str]] = []

        def fake_run(cmd, **_kw):
            commands.append(list(cmd))
            if cmd[0] == "ifconfig":
                return SimpleNamespace(ok=True, stdout="inet 127.0.0.1\ninet 192.168.1.1\n", stderr="", error=None)
            return SimpleNamespace(ok=True, stdout="", stderr="", error=None)

        with patch.object(dns, "run", side_effect=fake_run):
            status, body = dns.set_split_dns(["Пример.РФ", "portal.example.org"], None)

        self.assertEqual(status, 200, body)
        self.assertTrue(body["changed"])
        self.assertEqual(body["upstreams"], ["77.88.8.8", "77.88.8.1"])
        gos_ascii = _idna("пример.рф")
        self.assertEqual(
            body["domains"],
            [
                {"value": gos_ascii, "display_value": "пример.рф"},
                {"value": "portal.example.org", "display_value": "portal.example.org"},
            ],
        )

        unbound_text = self.unbound_conf.read_text(encoding="utf-8")
        self.assertIn(f'include: "{self.unbound_split_conf}"', unbound_text)
        self.assertEqual(dns.parse_forwarders(unbound_text), ["1.1.1.1", "9.9.9.9"])

        rendered = self.unbound_split_conf.read_text(encoding="utf-8")
        self.assertIn(f'    name: "{gos_ascii}."', rendered)
        self.assertIn('    name: "portal.example.org."', rendered)
        self.assertIn("    forward-addr: 77.88.8.8", rendered)
        self.assertIn("    forward-addr: 77.88.8.1", rendered)

        # Updating root VPN forwarders afterwards preserves the split-dns include.
        with patch.object(dns, "run", side_effect=fake_run):
            up_st, up_body = dns.set_upstreams(["1.0.0.1", "9.9.9.9"])
        self.assertEqual(up_st, 200, up_body)
        after_up = self.unbound_conf.read_text(encoding="utf-8")
        self.assertIn(f'include: "{self.unbound_split_conf}"', after_up)
        self.assertEqual(dns.parse_forwarders(after_up), ["1.0.0.1", "9.9.9.9"])

        fetched = dns.get_split_dns()
        self.assertTrue(fetched["configured"])
        self.assertEqual(fetched["domains"], body["domains"])

    def test_refuses_whole_tlds_and_shared_ru_second_level_zones(self) -> None:
        forbidden = [
            "ru",
            "su",
            "xn--p1ai",
            "рф",
            "com",
            "com.ru",
            "net.ru",
            "org.ru",
            "pp.ru",
            "msk.ru",
            "spb.ru",
            "gov.ru",
            "mil.ru",
            "edu.ru",
            "ac.ru",
            "int.ru",
        ]
        for zone in forbidden:
            with patch.object(dns, "run", return_value=SimpleNamespace(ok=True, stdout="", stderr="", error=None)):
                status, body = dns.set_split_dns([zone], ["77.88.8.8"])
            self.assertEqual(status, 400, f"expected 400 for {zone}, got {status}: {body}")

    def test_refuses_bad_upstreams_and_rolls_back_on_validation_or_reload_failure(self) -> None:
        with patch.object(dns, "run", return_value=SimpleNamespace(ok=True, stdout="", stderr="", error=None)):
            st_loop, _ = dns.set_split_dns(["gosuslugi.ru"], ["127.0.0.1"])
            self.assertEqual(st_loop, 400)
            st_unspec, _ = dns.set_split_dns(["gosuslugi.ru"], ["0.0.0.0"])
            self.assertEqual(st_unspec, 400)

        original_unbound = self.unbound_conf.read_text(encoding="utf-8")
        self.split_conf.write_text("upstreams 77.88.8.8\nold.ru\n", encoding="utf-8")
        self.unbound_split_conf.write_text("forward-zone:\n    name: \"old.ru.\"\n    forward-addr: 77.88.8.8\n", encoding="utf-8")

        def fail_checkconf(cmd, **_kw):
            if cmd[0] == "unbound-checkconf":
                return SimpleNamespace(ok=False, stdout="", stderr="syntax error", error="syntax error")
            return SimpleNamespace(ok=True, stdout="", stderr="", error=None)

        with patch.object(dns, "run", side_effect=fail_checkconf):
            st_check, body_check = dns.set_split_dns(["new.ru"], ["77.88.8.8"])
        self.assertEqual(st_check, 400, body_check)
        self.assertEqual(self.unbound_conf.read_text(encoding="utf-8"), original_unbound)
        self.assertIn("old.ru", self.split_conf.read_text(encoding="utf-8"))
        self.assertIn("old.ru", self.unbound_split_conf.read_text(encoding="utf-8"))

        def fail_reload(cmd, **_kw):
            if cmd == ["service", "unbound", "reload"]:
                return SimpleNamespace(ok=False, stdout="", stderr="reload failed", error="reload failed")
            if cmd == ["service", "unbound", "restart"]:
                fail_reload.restarts += 1
                return SimpleNamespace(ok=fail_reload.restarts > 1, stdout="", stderr="restart failed", error="restart failed")
            return SimpleNamespace(ok=True, stdout="", stderr="", error=None)

        fail_reload.restarts = 0
        with patch.object(dns, "run", side_effect=fail_reload):
            st_rel, body_rel = dns.set_split_dns(["new.ru"], ["77.88.8.8"])
        self.assertEqual(st_rel, 500, body_rel)
        self.assertTrue(body_rel.get("rolled_back"))
        self.assertEqual(self.unbound_conf.read_text(encoding="utf-8"), original_unbound)
        self.assertIn("old.ru", self.split_conf.read_text(encoding="utf-8"))
        self.assertIn("old.ru", self.unbound_split_conf.read_text(encoding="utf-8"))

    def test_honors_upgrade_lock_env_without_self_deadlock(self) -> None:
        lock_path = self.unbound_conf.with_suffix(".conf.gatebsd.lock")
        from gatebsd_ui.fsutil import exclusive_lock

        with exclusive_lock(lock_path):
            with patch.dict(os.environ, {"GATEBSD_UPGRADE_CONFIG_LOCKS_HELD": "1"}), patch.object(
                dns, "run", return_value=SimpleNamespace(ok=True, stdout="", stderr="", error=None)
            ):
                ok = dns.sync_split_dns(reload_service=False)
        self.assertTrue(ok)
        self.assertTrue(self.unbound_split_conf.is_file())
        self.assertIn(f'include: "{self.unbound_split_conf}"', self.unbound_conf.read_text(encoding="utf-8"))


class SplitDnsDeliveryAndContractTests(unittest.TestCase):
    def test_sample_delivery_backup_and_api_agent_contracts(self) -> None:
        sample = REPO_ROOT / "etc" / "gatebsd" / "split-dns.conf.sample"
        self.assertTrue(sample.is_file(), "missing etc/gatebsd/split-dns.conf.sample")
        parsed = dns.parse_split_dns(sample.read_text(encoding="utf-8"))
        self.assertEqual(parsed["domains"], [])
        self.assertEqual(parsed["upstreams"], ["77.88.8.8", "77.88.8.1"])

        self.assertIn("split_dns", paths.CONFIG_FILES)
        self.assertIn("unbound_split_dns", paths.CONFIG_FILES)
        self.assertEqual(
            backup._restore_lock_paths(paths.SPLIT_DNS_CONF),
            [paths.UNBOUND_CONF.with_suffix(".conf.gatebsd.lock")],
        )
        self.assertEqual(backup._restore_validator(paths.UNBOUND_SPLIT_DNS_CONF), ["unbound-checkconf"])

        for rel in ("Makefile", "ci/build.sh", "sbin/gatebsd-install"):
            self.assertIn("split-dns.conf.sample", (REPO_ROOT / rel).read_text(encoding="utf-8"), rel)
        self.assertIn("split-dns.conf", (REPO_ROOT / "sbin" / "gatebsd-upgrade").read_text(encoding="utf-8"))
        self.assertIn("migrate_split_dns", (REPO_ROOT / "sbin" / "gatebsd-config-migrate").read_text(encoding="utf-8"))

        self.assertTrue(agent._agent_allowed("GET", "/api/dns/split"))
        self.assertTrue(agent._agent_allowed("POST", "/api/dns/split"))
        api_text = (REPO_ROOT / "webui" / "backend" / "gatebsd_ui" / "api.py").read_text(encoding="utf-8")
        self.assertIn('"/api/dns/split"', api_text)


if __name__ == "__main__":
    unittest.main()
