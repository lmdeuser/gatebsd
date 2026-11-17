from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gatebsd_ui import adblock, paths, resolver, vpn_policy
from gatebsd_ui.writers import diagnostics

REPO_ROOT = Path(__file__).resolve().parents[1]
ADBLOCK_SCRIPT = REPO_ROOT / "sbin" / "gatebsd-adblock-update.sh"


def _idna(domain: str) -> str:
    return domain.encode("idna").decode("ascii")


class ResolverIdnaTests(unittest.TestCase):
    def test_normalize_host_encodes_cyrillic_and_folds_case(self) -> None:
        self.assertEqual(resolver.normalize_host("Пример.РФ."), _idna("пример.рф"))
        self.assertEqual(resolver.normalize_host("Почта.Пример.РФ"), _idna("почта.пример.рф"))
        self.assertEqual(resolver.normalize_host(_idna("домен.рф").upper()), _idna("домен.рф"))
        self.assertEqual(resolver.normalize_host("192.168.1.1"), "192.168.1.1")
        self.assertEqual(resolver.normalize_host("::1"), "::1")

    def test_normalize_host_rejects_invalid_inputs(self) -> None:
        for bad in ("", "-bad.ru", "bad host.ru", "a..b.ru", "https://пример.рф", "bad_label.рф"):
            self.assertIsNone(resolver.normalize_host(bad), bad)

    def test_normalize_domain_requires_valid_multilabel_domain(self) -> None:
        self.assertEqual(resolver.normalize_domain("Домен.РФ."), _idna("домен.рф"))
        for non_domain in ("192.168.1.1", "::1", "localhost", "тест", "10.0.0.0/24", "1.2.3.4"):
            self.assertIsNone(resolver.normalize_domain(non_domain), non_domain)

    def test_display_host_decodes_punycode_and_preserves_ascii_or_cidr(self) -> None:
        self.assertEqual(resolver.display_host(_idna("пример.рф")), "пример.рф")
        self.assertEqual(resolver.display_host("example.com"), "example.com")
        self.assertEqual(resolver.display_host("10.0.0.0/24"), "10.0.0.0/24")


class VpnPolicyIdnaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.config = root / "direct-exceptions.conf"
        self.table = root / "ru_bypass.table"
        self.config.write_text("", encoding="utf-8")
        self.table.write_text("1.1.1.0/24\n", encoding="ascii")
        self.yandex_ascii = _idna("домен.рф")
        self.patches = (
            patch.object(paths, "DIRECT_EXCEPTIONS", self.config),
            patch.object(paths, "RU_TABLE", self.table),
            patch.object(vpn_policy.paths, "DIRECT_EXCEPTIONS", self.config),
            patch.object(vpn_policy.paths, "RU_TABLE", self.table),
        )
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

        def fake_run(command, **_kwargs):
            if command[0] == "drill":
                if command[-2] == self.yandex_ascii:
                    return SimpleNamespace(ok=True, stdout="93.158.134.242\n", stderr="", error=None)
                return SimpleNamespace(ok=False, stdout="", stderr="not found", error="not found")
            if command[:3] == ["route", "-n", "get"]:
                return SimpleNamespace(ok=True, stdout="interface: igc0\ngateway: 10.0.0.1\n", stderr="", error=None)
            return SimpleNamespace(ok=True, stdout="", stderr="", error=None)

        self.runner = patch.object(vpn_policy, "run", side_effect=fake_run)
        self.runner.start()
        self.addCleanup(self.runner.stop)

    def test_change_status_and_diagnose_store_punycode_and_expose_display_value(self) -> None:
        status, body = vpn_policy.change("Домен.РФ", add=True, direction="direct")
        self.assertEqual(status, 200, body)
        self.assertTrue(body["changed"])
        self.assertEqual(self.config.read_text(encoding="utf-8"), f"{self.yandex_ascii}\n")
        self.assertIn("93.158.134.242/32", self.table.read_text(encoding="ascii"))
        entry = body["entries"][0]
        self.assertEqual(entry["value"], self.yandex_ascii)
        self.assertEqual(entry["display_value"], "домен.рф")

        dup_status, dup_body = vpn_policy.change(self.yandex_ascii, add=True, direction="direct")
        self.assertEqual(dup_status, 200, dup_body)
        self.assertFalse(dup_body["changed"])

        diag_status, diag_body = vpn_policy.diagnose("Домен.РФ", direction="direct")
        self.assertEqual(diag_status, 200, diag_body)
        self.assertEqual(diag_body["value"], self.yandex_ascii)
        self.assertEqual(diag_body["display_value"], "домен.рф")
        self.assertTrue(diag_body["ok"])

        rm_status, rm_body = vpn_policy.change("домен.рф", add=False)
        self.assertEqual(rm_status, 200, rm_body)
        self.assertTrue(rm_body["changed"])
        self.assertEqual(self.config.read_text(encoding="utf-8"), "")
        self.assertNotIn("93.158.134.242/32", self.table.read_text(encoding="ascii"))


class AdblockAndDiagnosticsIdnaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.extra = Path(self.tmp.name) / "adblock-extra"
        self.patch_extra = patch.object(adblock, "EXTRA_FILE", self.extra)
        self.patch_extra.start()
        self.addCleanup(self.patch_extra.stop)

    def test_adblock_rules_normalize_cyrillic_and_expose_display_value(self) -> None:
        reklama_ascii = _idna("реклама.рф")
        allow_ascii = _idna("исключение.рф")

        st1, body1 = adblock.change_rule("Реклама.РФ", kind="block", add=True)
        self.assertEqual(st1, 200, body1)
        st2, body2 = adblock.change_rule("Исключение.РФ", kind="allow", add=True)
        self.assertEqual(st2, 200, body2)

        text = self.extra.read_text(encoding="utf-8")
        self.assertIn(f"0.0.0.0 {reklama_ascii}", text)
        self.assertIn(f"@@||{allow_ascii}^", text)
        self.assertEqual(
            body2["entries"],
            [
                {"kind": "block", "value": reklama_ascii, "display_value": "реклама.рф"},
                {"kind": "allow", "value": allow_ascii, "display_value": "исключение.рф"},
            ],
        )

    def test_adblock_dns_probe_encodes_idn_before_calling_drill(self) -> None:
        reklama_ascii = _idna("реклама.рф")
        control_ascii = _idna("домен.рф")
        calls: list[list[str]] = []

        def fake_run(command, **_kwargs):
            calls.append(list(command))
            name = command[1]
            if name == reklama_ascii:
                return SimpleNamespace(ok=True, stdout=";; rcode: NOERROR\nreklama. 60 IN A 0.0.0.0\n", stderr="", error=None)
            if name == control_ascii:
                return SimpleNamespace(ok=True, stdout=";; rcode: NOERROR\nyandex. 60 IN A 93.158.134.242\n", stderr="", error=None)
            return SimpleNamespace(ok=False, stdout="", stderr="unexpected", error="unexpected")

        with patch.object(adblock, "run", side_effect=fake_run), patch.object(adblock, "_resolver_address", return_value="127.0.0.1"):
            status, body = adblock.dns_probe("реклама.рф", "домен.рф", "always_null")
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        self.assertEqual([cmd[1] for cmd in calls], [reklama_ascii, control_ascii])
        self.assertEqual(body["blocked"]["name"], reklama_ascii)
        self.assertEqual(body["blocked"]["display_name"], "реклама.рф")

    def test_diagnostics_vpn_diagnose_normalizes_cyrillic_domain(self) -> None:
        president_ascii = _idna("пример.рф")
        commands: list[list[str]] = []

        def fake_run(command, **_kwargs):
            commands.append(list(command))
            return SimpleNamespace(ok=True, returncode=0, stdout="ok", stderr="", error=None)

        with patch.object(diagnostics, "run", side_effect=fake_run):
            status, body = diagnostics.vpn_diagnose("curl", "Пример.РФ.")
        self.assertEqual(status, 200, body)
        self.assertEqual(commands[0], ["route", "-n", "get", president_ascii])
        self.assertEqual(commands[1], ["fetch", "-T", "10", "-qo", "/dev/null", f"https://{president_ascii}/"])

    def test_adblock_update_script_normalizes_idn_in_adblock_extra(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()

            source_payload = root / "feed.txt"
            source_payload.write_text("0.0.0.0 ads.example.com\n", encoding="utf-8")

            for name, content in {
                "fetch": f"#!/bin/sh\nout=''\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = '-o' ]; then out=$2; shift 2; continue; fi\n  shift\ndone\ncp '{source_payload}' \"$out\"\n",
                "stat": f"#!{sys.executable}\nimport os, sys\nif len(sys.argv) >= 4 and sys.argv[1] == '-f' and sys.argv[2] == '%z':\n    print(os.path.getsize(sys.argv[3]))\nelse:\n    os.execv('/usr/bin/stat', ['stat', *sys.argv[1:]])\n",
                "unbound-checkconf": "#!/bin/sh\nexit 0\n",
                "service": "#!/bin/sh\nexit 0\n",
            }.items():
                tool = bin_dir / name
                tool.write_text(content, encoding="utf-8")
                tool.chmod(tool.stat().st_mode | stat.S_IEXEC)

            extra = root / "adblock-extra"
            extra.write_text(
                "0.0.0.0 реклама.рф\n||трекер.рф^\n@@||исключение.рф^\n0.0.0.0 исключение.рф\n",
                encoding="utf-8",
            )
            unbound_conf = root / "unbound.conf"
            unbound_conf.write_text("server:\n", encoding="utf-8")
            blocklist = root / "adblock.conf"

            env = {
                "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": str(root),
                "LANG": "C.UTF-8",
                "GATEBSD_PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin",
                "GATEBSD_ADBLOCK_LOCK_HELD": "1",
                "GATEBSD_ADBLOCK_URLS": "http://mock.invalid/feed.txt",
                "GATEBSD_ADBLOCK_MIN_DOMAINS": "2",
                "GATEBSD_UNBOUND_CONF": str(unbound_conf),
                "GATEBSD_ADBLOCK_CONF": str(blocklist),
                "GATEBSD_ADBLOCK_EXTRA": str(extra),
                "GATEBSD_ADBLOCK_LOG": str(root / "adblock.log"),
                "GATEBSD_ADBLOCK_STAMP": str(root / "adblock-inputs"),
                "GATEBSD_ADBLOCK_STATUS": str(root / "adblock-status.json"),
                "GATEBSD_ADBLOCK_LOCK": str(root / "adblock.lock"),
                "GATEBSD_PYTHON_LAUNCHER": sys.executable,
                "GATEBSD_PYTHONPATH": str(REPO_ROOT / "webui" / "backend"),
            }
            proc = subprocess.run(
                ["sh", str(ADBLOCK_SCRIPT)],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            published = blocklist.read_text(encoding="utf-8")
            self.assertIn(f'local-zone: "{_idna("реклама.рф")}." always_null', published)
            self.assertIn(f'local-zone: "{_idna("трекер.рф")}." always_null', published)
            self.assertNotIn(_idna("исключение.рф"), published)
            self.assertIn('local-zone: "ads.example.com." always_null', published)


if __name__ == "__main__":
    unittest.main()
