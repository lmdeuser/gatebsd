from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gatebsd_ui import agent, paths
from gatebsd_ui import vpn_policy

ROOT = Path(__file__).resolve().parents[1]


class VpnPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.config = root / "direct.conf"
        self.table = root / "ru.table"
        self.table.write_text("1.1.1.0/24\n", encoding="ascii")
        self.addresses = {
            "agent-gw.kimi.com": "203.0.113.156",
            "kimi.com": "203.0.113.156",
        }
        self.directories = (
            patch.object(paths, "DIRECT_EXCEPTIONS", self.config),
            patch.object(paths, "RU_TABLE", self.table),
            patch.object(vpn_policy.paths, "DIRECT_EXCEPTIONS", self.config),
            patch.object(vpn_policy.paths, "RU_TABLE", self.table),
        )
        for item in self.directories:
            item.start()
            self.addCleanup(item.stop)
        self.config.write_text("agent-gw.kimi.com\n", encoding="utf-8")

        def resolve(command, **_kwargs):
            value = command[-2]
            return SimpleNamespace(ok=True, stdout=f"alias.example.\n{self.addresses.get(value, '')}\n", stderr="", error=None)

        self.resolver = patch.object(vpn_policy, "run", side_effect=resolve)
        self.resolver.start()
        self.addCleanup(self.resolver.stop)

    def test_merge_resolves_domain_and_preserves_existing_table(self) -> None:
        result = vpn_policy.merge_file()
        self.assertEqual(result["custom"], 1)
        self.assertEqual(self.table.read_text(encoding="ascii"), "1.1.1.0/24\n203.0.113.156/32\n")
        self.table.write_text("1.1.1.0/24\n2.2.2.0/24\n", encoding="ascii")
        vpn_policy.merge_file()
        self.assertEqual(
            self.table.read_text(encoding="ascii"),
            "1.1.1.0/24\n2.2.2.0/24\n203.0.113.156/32\n",
        )

    def test_add_then_remove_prunes_the_old_resolved_address(self) -> None:
        status, body = vpn_policy.change("10.0.0.0/24", add=True)
        self.assertEqual(status, 200, body)
        self.assertIn("10.0.0.0/24", self.table.read_text(encoding="ascii"))
        self.assertIn("agent-gw.kimi.com", self.config.read_text(encoding="utf-8"))
        status, body = vpn_policy.change("agent-gw.kimi.com", add=False)
        self.assertEqual(status, 200, body)
        text = self.table.read_text(encoding="ascii")
        self.assertNotIn("203.0.113.156/32", text)
        self.assertIn("10.0.0.0/24", text)

    def test_duplicate_add_is_a_noop(self) -> None:
        before = (self.config.read_bytes(), self.table.read_bytes())
        status, body = vpn_policy.change("agent-gw.kimi.com", add=True)
        self.assertEqual(status, 200)
        self.assertFalse(body["changed"])
        self.assertEqual((self.config.read_bytes(), self.table.read_bytes()), before)

    def test_failed_resolution_changes_neither_file(self) -> None:
        before = (self.config.read_bytes(), self.table.read_bytes())
        with patch.object(vpn_policy, "run", return_value=SimpleNamespace(ok=False, stdout="", stderr="", error="dns")):
            status, _body = vpn_policy.change("kimi.com", add=True)
        self.assertEqual(status, 500)
        self.assertEqual((self.config.read_bytes(), self.table.read_bytes()), before)

    def test_broad_and_invalid_values_are_rejected(self) -> None:
        for value in ("0.0.0.0/0", "::1/128", "bad_domain", "../etc"):
            status, _body = vpn_policy.change(value, add=True)
            self.assertEqual(status, 400, value)

    def test_comments_are_preserved_when_rules_change(self) -> None:
        self.config.write_text("# operator note\nagent-gw.kimi.com\n", encoding="utf-8")
        status, _body = vpn_policy.change("10.0.0.0/24", add=True)
        self.assertEqual(status, 200)
        self.assertIn("# operator note", self.config.read_text(encoding="utf-8"))
        status, _body = vpn_policy.change("agent-gw.kimi.com", add=False)
        self.assertEqual(status, 200)
        self.assertIn("# operator note", self.config.read_text(encoding="utf-8"))

    def test_real_update_script_merges_and_publishes_candidate(self) -> None:
        root = Path(self.tmp.name) / "update"
        root.mkdir()
        root.chmod(0o700)
        bin_dir = root / "bin"
        bin_dir.mkdir()

        def stub(name: str, body: str) -> None:
            path = bin_dir / name
            path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
            path.chmod(0o755)

        stub("fetch", "out=; while [ $# -gt 0 ]; do if [ \"$1\" = -o ]; then out=$2; shift 2; else shift; fi; done; printf '1.1.1.0/24\\n2.2.2.0/24\\n' > \"$out\"")
        stub("drill", "printf 'alias.example.\\n203.0.113.156\\n'")
        stub("ru-routes.sh", "printf '%s\\n' \"$*\" >> \"$CALLS\"")
        stub("sha256", "[ \"$1\" != -q ] || shift; sha256sum \"$1\" | awk '{print $1}'")
        stub("stat", """if [ \"$1\" = -f ]; then
  case \"$2\" in
    %u) printf '0\\n'; exit 0 ;;
    %Lp) if [ \"$(/usr/bin/uname -s)\" = FreeBSD ]; then exec /usr/bin/stat -f '%Lp' \"$3\"; else exec /usr/bin/stat -c '%a' \"$3\"; fi ;;
    %z) if [ \"$(/usr/bin/uname -s)\" = FreeBSD ]; then exec /usr/bin/stat -f '%z' \"$3\"; else exec /usr/bin/stat -c '%s' \"$3\"; fi ;;
  esac
fi
exec /usr/bin/stat \"$@\"""")
        gateway = root / "gateway.conf"
        gateway.write_text("", encoding="utf-8")
        gateway.chmod(0o600)
        table = root / "ru.table"
        table.write_text("1.1.1.0/24\n", encoding="ascii")
        calls = root / "calls"
        env = {
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "GATEBSD_PATH": f"{bin_dir}:/usr/bin:/bin",
            "GATEBSD_RU_UPDATE_LOCK_HELD": "1",
            "GATEBSD_GATEWAY_CONF": str(gateway),
            "GATEBSD_DIRECT_EXCEPTIONS": str(self.config),
            "GATEBSD_PYTHON_LAUNCHER": sys.executable,
            "GATEBSD_RU_ROUTES_HELPER": str(bin_dir / "ru-routes.sh"),
            "GATEBSD_DRILL": str(bin_dir / "drill"),
            "GATEBSD_BACKEND": str(ROOT / "webui" / "backend"),
            "RU_TABLE": str(table),
            "RU_TABLE_MIN_PREFIXES": "1",
            "RU_TABLE_MAX_BYTES": "100000",
            "TMPDIR": str(root),
            "HOME": str(root),
            "CALLS": str(calls),
        }
        result = subprocess.run(
            ["sh", str(ROOT / "sbin" / "ru-bypass-update.sh")],
            env=env, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("203.0.113.156/32", table.read_text(encoding="ascii"))
        self.assertIn("2.2.2.0/24", table.read_text(encoding="ascii"))
        self.assertIn("apply", calls.read_text(encoding="utf-8"))

    def test_resolver_uses_freebsd_drill_options(self) -> None:
        with patch.object(vpn_policy, "run", return_value=SimpleNamespace(ok=True, stdout="203.0.113.156\n", stderr="", error=None)) as resolver:
            self.assertEqual(vpn_policy._resolve("kimi.com"), ["203.0.113.156/32"])
        command = resolver.call_args.args[0]
        self.assertEqual(command[:2], [vpn_policy.DRILL, "-Q"])
        self.assertNotIn("+short", command)

    def test_shipped_kimi_exceptions_are_narrow(self) -> None:
        sample = (ROOT / "etc" / "amnezia" / "direct-exceptions.conf.sample").read_text(encoding="utf-8")
        self.assertIn("agent-gw.kimi.com", sample)
        self.assertIn("kimi.com", sample)
        self.assertNotIn("www.kimi.com", sample)
        self.assertNotIn("www.kimi.ai", sample)
        self.assertNotIn("api.kimi.com", sample)

    def test_update_script_and_agent_contract_are_wired(self) -> None:
        script = (ROOT / "sbin" / "ru-bypass-update.sh").read_text(encoding="utf-8")
        self.assertIn("-m gatebsd_ui.vpn_policy merge", script)
        self.assertTrue(agent._agent_allowed("GET", "/api/vpn/exceptions"))
        self.assertTrue(agent._agent_allowed("POST", "/api/vpn/exceptions/add"))
        self.assertTrue(agent._agent_allowed("POST", "/api/vpn/exceptions/remove"))
        app = (ROOT / "webui" / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn("/api/vpn/exceptions", app)
        self.assertIn("Routing Policy", app)
        self.assertIn("direct_exceptions", paths.CONFIG_FILES)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        for text in (makefile, build):
            self.assertIn("direct-exceptions.conf.sample", text)

    def test_cloudflare_direct_rule_emits_shared_cdn_warning(self) -> None:
        self.addresses["cdn.example"] = "104.21.10.20"
        with patch.object(
            vpn_policy,
            "run",
            side_effect=lambda cmd, **_kw: (
                SimpleNamespace(ok=True, stdout="104.21.10.20\n", stderr="", error=None)
                if cmd[0] == "drill" and cmd[-2] == "cdn.example"
                else SimpleNamespace(ok=True, stdout="interface: ng0\ngateway: 10.0.0.1\n", stderr="", error=None)
                if cmd[:3] == ["route", "-n", "get"]
                else SimpleNamespace(ok=True, stdout="203.0.113.156\n", stderr="", error=None)
                if cmd[0] == "drill" and cmd[-2] == "agent-gw.kimi.com"
                else SimpleNamespace(ok=True, stdout="", stderr="", error=None)
            ),
        ):
            st, body = vpn_policy.change("cdn.example", add=True, direction="direct")
            self.assertEqual(st, 200, body)
            self.assertTrue(body.get("warnings"), body)
            msg = body["warnings"][0]["msg"]
            self.assertIn("Cloudflare", msg)
            self.assertIn("ECH", msg)
            cf_entry = next(e for e in body["entries"] if e["value"] == "cdn.example")
            self.assertTrue(cf_entry.get("warnings"), cf_entry)
            kimi_entry = next(e for e in body["entries"] if e["value"] == "agent-gw.kimi.com")
            self.assertEqual(kimi_entry.get("warnings"), [])

            dst, dbody = vpn_policy.diagnose("cdn.example", direction="direct")
            self.assertEqual(dst, 200, dbody)
            self.assertTrue(dbody.get("warnings"), dbody)

            cidr_st, cidr_body = vpn_policy.change("104.16.0.0/24", add=True, direction="direct")
            self.assertEqual(cidr_st, 200, cidr_body)
            cidr_entry = next(e for e in cidr_body["entries"] if e["value"] == "104.16.0.0/24")
            self.assertTrue(cidr_entry.get("warnings"), cidr_entry)

            for safe_dir in ("vpn", "default"):
                vpn_st, vpn_body = vpn_policy.change("cdn.example", add=True, direction=safe_dir)
                self.assertEqual(vpn_st, 200, vpn_body)
                safe_entry = next(e for e in vpn_body["entries"] if e["value"] == "cdn.example")
                self.assertEqual(safe_entry.get("warnings"), [])
                _, safe_diag = vpn_policy.diagnose("cdn.example", direction=safe_dir)
                self.assertEqual(safe_diag.get("warnings"), [])


if __name__ == "__main__":
    unittest.main()



class VpnPolicyHardeningRedTests(unittest.TestCase):
    def test_h1_direct_exceptions_never_treated_as_awg_profile_or_key_rotate_target(self) -> None:
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from gatebsd_ui import adapters, backup, paths, writers

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            conf_dir = root / "amnezia"
            conf_dir.mkdir(parents=True)
            backup_dir = root / "backups"
            backup_dir.mkdir(parents=True)

            active_target = conf_dir / "main.conf"
            active_target.write_text(
                "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n"
                "[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nAllowedIPs = 0.0.0.0/0\n",
                encoding="utf-8",
            )
            os.chmod(active_target, 0o600)
            active_link = conf_dir / "awg0.conf"
            active_link.symlink_to(active_target)

            direct_exc = conf_dir / "direct-exceptions.conf"
            direct_exc.write_text("direct kimi.com\n", encoding="utf-8")
            os.chmod(direct_exc, 0o600)

            gateway_conf = conf_dir / "gateway.conf"
            gateway_conf.write_text("WAN_IF=ng0\n", encoding="utf-8")

            with (
                patch.object(paths, "AMNEZIA_CONF_DIR", conf_dir),
                patch.object(paths, "AMNEZIA_CONFIG", active_link),
                patch.object(paths, "DIRECT_EXCEPTIONS", direct_exc),
                patch.object(paths, "GATEWAY_CONF", gateway_conf),
                patch.object(paths, "BACKUP_DIR", backup_dir),
                patch.object(backup.paths, "AMNEZIA_CONF_DIR", conf_dir),
                patch.object(backup.paths, "AMNEZIA_CONFIG", active_link),
                patch.object(backup.paths, "BACKUP_DIR", backup_dir),
                patch.object(writers.vpn, "AMNEZIA_CONF_DIR", conf_dir),
                patch.object(writers.vpn, "AMNEZIA_CONFIG", active_link),
                patch.object(adapters.vpn, "AMNEZIA_CONF_DIR", conf_dir),
                patch.object(adapters.vpn, "AMNEZIA_CONFIG", active_link),
                patch.object(writers.vpn, "run", return_value=SimpleNamespace(ok=True, stdout="", stderr="", error=None)),
            ):
                listed_ids = [item["id"] for item in writers.awg_profiles()["profiles"]]
                self.assertEqual(listed_ids, ["main"])
                adapter_names = [item["name"] for item in adapters.vpn.amnezia()["config_files"]]
                self.assertEqual(adapter_names, ["main.conf"])

                for status_code, _body in (
                    writers.awg_set_config("direct-exceptions", active_target.read_text(encoding="utf-8")),
                    writers.awg_activate("direct-exceptions"),
                    writers.awg_delete_profile("direct-exceptions"),
                    writers.awg_key_rotate("direct-exceptions"),
                    writers.awg_key_rotate("gateway"),
                ):
                    self.assertEqual(status_code, 400)

                self.assertEqual(direct_exc.read_text(encoding="utf-8"), "direct kimi.com\n")
                self.assertEqual(gateway_conf.read_text(encoding="utf-8"), "WAN_IF=ng0\n")

    def test_m1_concurrent_ru_bypass_update_and_vpn_policy_change_do_not_drop_or_fail(self) -> None:
        import os
        import subprocess
        import sys
        import tempfile
        import threading
        import time
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch

        from gatebsd_ui import vpn_policy

        root_dir = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            zone_file = root / "zone.txt"
            zone_file.write_text("77.88.0.0/18\n185.15.56.0/22\n", encoding="utf-8")

            ru_table_path = root / "ru_bypass.table"
            ru_table_path.write_text("1.2.3.0/24\n", encoding="utf-8")
            direct_exc = root / "direct-exceptions.conf"
            direct_exc.write_text("198.51.100.10/32\n", encoding="utf-8")

            launcher = bin_dir / "gatebsd-python"
            launcher.write_text(f"#!/bin/sh\nexec {sys.executable} \"$@\"\n", encoding="utf-8")
            launcher.chmod(0o755)

            # Delayed fetch gives vpn_policy.change() time to race cleanly if lock split-brain exists.
            fetch_stub = bin_dir / "fetch"
            fetch_stub.write_text(
                f"#!/bin/sh\nout=''\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in -o) out=$2; shift 2 ;; *) shift ;; esac\ndone\ncp \"{zone_file}\" \"$out\"\n",
                encoding="utf-8",
            )
            fetch_stub.chmod(0o755)

            for name, body in (
                ("lockf", "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do\n  case \"$1\" in -t) shift 2 ;; -k|-s|-T) shift ;; *) break ;; esac\ndone\n[ \"$1\" = \"--\" ] && shift\nlock=\"$1\"; shift\nexec \"$@\"\n"),
                ("stat", "#!/bin/sh\nif [ \"$1\" = \"-f\" ]; then\n  case \"$2\" in\n    %u) echo 0; exit 0 ;;\n    %Lp) python3 -c \"import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:].zfill(3))\" \"$3\"; exit 0 ;;\n    %z) wc -c < \"$3\" | tr -d ' '; exit 0 ;;\n  esac\nfi\nexec /usr/bin/stat \"$@\"\n"),
                ("sha256", "#!/bin/sh\nsleep 0.3\nif [ \"$1\" = \"-q\" ]; then python3 -c \"import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())\" \"$2\"; exit 0; fi\n"),
                ("ru-routes.sh", "#!/bin/sh\nexit 0\n"),
                ("install", "#!/bin/sh\nexec /usr/bin/install -m 0750 -d \"${@##*[!/-]*}\" 2>/dev/null || /bin/mkdir -p \"${@: -1}\"\n"),
            ):
                stub = bin_dir / name
                stub.write_text(body, encoding="utf-8")
                stub.chmod(0o755)
            # Clean install stub that strips -o/-g on unprivileged Linux.
            (bin_dir / "install").write_text(
                "#!/bin/sh\nargs=''\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in -o|-g) shift 2 ;; *) args=\"$args \\\"$1\\\"\"; shift ;; esac\ndone\neval exec /usr/bin/install $args\n",
                encoding="utf-8",
            )
            (bin_dir / "install").chmod(0o755)

            env = {
                "PATH": f"{bin_dir}:/usr/bin:/bin",
                "HOME": str(root),
                "GATEBSD_PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_RU_UPDATE_LOCK_HELD": "1",
                "RU_TABLE": str(ru_table_path),
                "GATEBSD_DIRECT_EXCEPTIONS": str(direct_exc),
                "RU_TABLE_MIN_PREFIXES": "2",
                "GATEBSD_RU_UPDATE_LOCK": str(root / "ru-update.lock"),
                "GATEBSD_PYTHON_LAUNCHER": str(launcher),
                "GATEBSD_BACKEND": str(root_dir / "webui" / "backend"),
                "GATEBSD_RU_ROUTES_HELPER": str(bin_dir / "ru-routes.sh"),
            }

            proc = subprocess.Popen(
                ["sh", str(root_dir / "sbin" / "ru-bypass-update.sh")],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Concurrently run vpn_policy.change mid-update.
            time.sleep(0.15)
            with (
                patch.object(vpn_policy.paths, "DIRECT_EXCEPTIONS", direct_exc),
                patch.object(vpn_policy.paths, "RU_TABLE", ru_table_path),
                patch.object(
                    vpn_policy,
                    "run",
                    return_value=SimpleNamespace(ok=True, stdout="203.0.113.77\n", stderr="", error=None),
                ),
            ):
                status, body = vpn_policy.change("203.0.113.77/32", add=True, direction="direct")
                self.assertEqual(status, 200, body)

            stdout, stderr = proc.communicate(timeout=15)
            self.assertEqual(proc.returncode, 0, f"stdout={stdout}\nstderr={stderr}")

            final_lines = set(ru_table_path.read_text(encoding="utf-8").splitlines())
            self.assertIn("77.88.0.0/18", final_lines)
            self.assertIn("198.51.100.10/32", final_lines)
            self.assertIn("203.0.113.77/32", final_lines)
