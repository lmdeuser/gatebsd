#!/usr/bin/env python3
"""Direction-aware VPN policy editing and read-only path diagnosis."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "webui" / "backend"))

from gatebsd_ui import agent, api, paths, vpn_policy  # noqa: E402


class PolicyEditorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.config = root / "direct.conf"
        self.table = root / "ru.table"
        self.table.write_text("203.0.113.156/32\n203.0.113.8/32\n", encoding="ascii")
        self.config.write_text(
            "# keep this comment\nagent-gw.kimi.com\nvpn www.kimi.com\ndefault example.com\n",
            encoding="utf-8",
        )
        self.directories = (
            patch.object(paths, "DIRECT_EXCEPTIONS", self.config),
            patch.object(paths, "RU_TABLE", self.table),
            patch.object(vpn_policy.paths, "DIRECT_EXCEPTIONS", self.config),
            patch.object(vpn_policy.paths, "RU_TABLE", self.table),
        )
        for item in self.directories:
            item.start()
            self.addCleanup(item.stop)
        self.calls = []

    def fake_run(self, command, **_kwargs):
        self.calls.append(command)
        if command[:2] == [vpn_policy.DRILL, "-Q"]:
            addresses = {
                "agent-gw.kimi.com": "203.0.113.156",
                "www.kimi.com": "203.0.113.8",
                "example.com": "203.0.113.9",
            }
            return SimpleNamespace(ok=True, stdout=addresses[command[-2]] + "\n", stderr="", error=None)
        if command[:2] == ["route", "-n"]:
            return SimpleNamespace(ok=True, stdout="gateway: 192.0.2.1\ninterface: ng0\n", stderr="", error=None)
        if command[0] == "fetch":
            return SimpleNamespace(ok=True, stdout="", stderr="", error=None)
        raise AssertionError(command)

    def test_status_exposes_direction_resolution_route_and_time(self) -> None:
        with patch.object(vpn_policy, "run", self.fake_run):
            payload = vpn_policy.status()
        by_value = {entry["value"]: entry for entry in payload["entries"]}
        self.assertEqual(by_value["agent-gw.kimi.com"]["direction"], "direct")
        self.assertEqual(by_value["www.kimi.com"]["direction"], "vpn")
        self.assertEqual(by_value["example.com"]["direction"], "default")
        self.assertEqual(by_value["www.kimi.com"]["route"]["interface"], "ng0")
        self.assertIsInstance(by_value["www.kimi.com"]["checked_at"], int)

    def test_vpn_direction_is_pruned_from_direct_table_without_duplicates(self) -> None:
        with patch.object(vpn_policy, "run", self.fake_run):
            status, body = vpn_policy.change("www.kimi.com", add=True, direction="vpn")
        self.assertEqual(status, 200, body)
        self.assertFalse(body["changed"])
        with patch.object(vpn_policy, "run", self.fake_run):
            vpn_policy.merge_file()
        self.assertNotIn("203.0.113.8/32", self.table.read_text(encoding="ascii"))
        self.assertEqual(self.config.read_text(encoding="utf-8").count("www.kimi.com"), 1)

    def test_changing_direction_preserves_comment_and_moves_the_network(self) -> None:
        with patch.object(vpn_policy, "run", self.fake_run):
            status, _body = vpn_policy.change("www.kimi.com", add=True, direction="direct")
        self.assertEqual(status, 200)
        text = self.config.read_text(encoding="utf-8")
        self.assertIn("# keep this comment", text)
        self.assertIn("\nwww.kimi.com\n", text)
        self.assertNotIn("vpn www.kimi.com", text)
        self.assertIn("203.0.113.156/32", self.table.read_text(encoding="ascii"))

    def test_diagnose_runs_dns_route_and_https(self) -> None:
        with patch.object(vpn_policy, "run", self.fake_run):
            status, payload = vpn_policy.diagnose("www.kimi.com", direction="vpn")
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["dns"]["ok"])
        self.assertEqual(payload["route"]["interface"], "ng0")
        self.assertTrue(payload["https"]["ok"])
        self.assertIsInstance(payload["checked_at"], int)
        self.assertTrue(any(call[0] == "fetch" for call in self.calls))

    def test_cidr_diagnosis_marks_dns_and_https_not_applicable(self) -> None:
        with patch.object(vpn_policy, "run", self.fake_run):
            status, payload = vpn_policy.diagnose("203.0.113.0/24", direction="direct")
        self.assertEqual(status, 200, payload)
        self.assertFalse(payload["dns"]["applicable"])
        self.assertFalse(payload["https"]["applicable"])
        self.assertEqual(payload["route"]["interface"], "ng0")

    def test_dispatch_and_agent_allow_diagnosis(self) -> None:
        with patch.object(vpn_policy, "run", self.fake_run):
            status, payload = api.dispatch(
                "/api/vpn/exceptions/diagnose", {}, method="POST",
                body={"value": "www.kimi.com", "direction": "vpn"},
            )
        self.assertEqual(status, 200, payload)
        self.assertIn("route", payload)
        self.assertTrue(agent._agent_allowed("POST", "/api/vpn/exceptions/diagnose"))


if __name__ == "__main__":
    unittest.main()



class VpnPolicyOverrideAndConvergenceRedTests(unittest.TestCase):
    def test_h2_vpn_direction_writes_override_table_and_ru_routes_applies_and_clears(self) -> None:
        import os
        import subprocess
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch

        from gatebsd_ui import api, vpn_policy

        root_dir = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            config = root / "direct-exceptions.conf"
            table = root / "ru_bypass.table"
            override = root / "vpn_override.table"
            state = root / "ru-routes.applied"
            override_state = root / "vpn-override.applied"
            table.write_text("77.88.0.0/18\n77.88.8.8/32\n", encoding="utf-8")

            def fake_run(command, timeout=10):
                if command[:2] == [vpn_policy.DRILL, "-Q"]:
                    return SimpleNamespace(ok=True, stdout="77.88.8.8\n", stderr="", error=None)
                if command[:3] == ["route", "-n", "get"]:
                    return SimpleNamespace(ok=True, stdout="   interface: awg0\n", stderr="", error=None)
                return SimpleNamespace(ok=True, stdout="", stderr="", error=None)

            with (
                patch.object(vpn_policy.paths, "DIRECT_EXCEPTIONS", config),
                patch.object(vpn_policy.paths, "RU_TABLE", table),
                patch.object(vpn_policy.paths, "VPN_OVERRIDE_TABLE", override),
                patch.object(vpn_policy, "run", side_effect=fake_run) as run_mock,
                patch.dict(os.environ, {"GATEBSD_FORCE_ROUTE_CONVERGE": "1"}, clear=False),
            ):
                status, body = vpn_policy.change("dns.yandex.ru", add=True, direction="vpn")
                self.assertEqual(status, 200, body)
                self.assertEqual(table.read_text(encoding="utf-8"), "77.88.0.0/18\n")
                self.assertEqual(override.read_text(encoding="utf-8"), "77.88.8.8/32\n")
                self.assertTrue(
                    any(c.args[0] == ["service", "ru_bypass", "start"] for c in run_mock.call_args_list),
                    run_mock.call_args_list,
                )

                # Test ru-routes.sh apply + clear with vpn_override.table
                bin_dir = root / "bin"
                bin_dir.mkdir()
                calls = root / "calls.log"
                (bin_dir / "lockf").write_text(
                    "#!/bin/sh\nwhile [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do\n  case \"$1\" in -T|-k|-s) shift ;; -t) shift 2 ;; *) break ;; esac\ndone\n[ \"$1\" = \"--\" ] && shift\nshift\nexec \"$@\"\n",
                    encoding="utf-8",
                )
                (bin_dir / "lockf").chmod(0o755)
                (bin_dir / "install").write_text(
                    "#!/bin/sh\nargs=''\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in -o|-g) shift 2 ;; *) args=\"$args \\\"$1\\\"\"; shift ;; esac\ndone\neval exec /usr/bin/install $args\n",
                    encoding="utf-8",
                )
                (bin_dir / "install").chmod(0o755)
                (bin_dir / "stat").write_text(
                    "#!/bin/sh\nif [ \"$1\" = \"-f\" ]; then\n  case \"$2\" in\n    %u) echo 0; exit 0 ;;\n    %Lp) echo 600; exit 0 ;;\n  esac\nfi\nexec /usr/bin/stat \"$@\"\n",
                    encoding="utf-8",
                )
                (bin_dir / "stat").chmod(0o755)
                (bin_dir / "state-reader").write_text("#!/bin/sh\necho primary\n", encoding="utf-8")
                (bin_dir / "state-reader").chmod(0o755)
                (bin_dir / "route").write_text(
                    f"#!/bin/sh\necho \"route $*\" >> \"{calls}\"\nif [ \"$1\" = \"-n\" ] && [ \"$2\" = \"get\" ]; then\n  echo \"   gateway: 192.0.2.1\"\n  echo \"   interface: ng0\"\nfi\nexit 0\n",
                    encoding="utf-8",
                )
                (bin_dir / "route").chmod(0o755)

                ru_env = {
                    "PATH": f"{bin_dir}:/usr/bin:/bin",
                    "GATEBSD_PATH": f"{bin_dir}:/usr/bin:/bin",
                    "GATEBSD_GATEWAY_CONF": str(root / "gateway.conf"),
                    "RU_TABLE": str(table),
                    "RU_STATE_FILE": str(state),
                    "GATEBSD_VPN_OVERRIDE_TABLE": str(override),
                    "VPN_OVERRIDE_STATE_FILE": str(override_state),
                    "GATEBSD_RU_ROUTE_LOCK": str(root / "route.lock"),
                    "GATEBSD_STATE_READER": str(bin_dir / "state-reader"),
                    "GATEBSD_ACTIVE_WAN_IF": "ng0",
                    "GATEBSD_ACTIVE_WAN_GW": "192.0.2.1",
                }
                apply_proc = subprocess.run(
                    ["sh", str(root_dir / "sbin" / "ru-routes.sh"), "apply"],
                    env=ru_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(apply_proc.returncode, 0, apply_proc.stderr)
                recorded = calls.read_text(encoding="utf-8").splitlines()
                self.assertTrue(
                    any("-net 77.88.8.8/32" in line and "-interface awg0" in line for line in recorded),
                    recorded,
                )
                self.assertEqual(override_state.read_text(encoding="utf-8").strip(), "77.88.8.8/32")

                # Switch rule back to direct -> override cleared, table gets /32 again
                status2, _body2 = vpn_policy.change("dns.yandex.ru", add=True, direction="direct")
                self.assertEqual(status2, 200)
                self.assertEqual(override.read_text(encoding="utf-8"), "")

                calls.write_text("", encoding="utf-8")
                clear_proc = subprocess.run(
                    ["sh", str(root_dir / "sbin" / "ru-routes.sh"), "clear"],
                    env=ru_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(clear_proc.returncode, 0, clear_proc.stderr)
                clear_recorded = calls.read_text(encoding="utf-8").splitlines()
                self.assertTrue(any("delete -net 77.88.8.8/32" in line for line in clear_recorded), clear_recorded)
                self.assertFalse(override_state.exists())

    def test_h2_pf_table_add_and_remove_trigger_convergence_only_when_changed(self) -> None:
        import os
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch

        from gatebsd_ui import api, backup, paths, vpn_policy

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            table = root / "ru_bypass.table"
            table.write_text("10.0.0.0/24\n", encoding="utf-8")
            backup_dir = root / "backups"
            backup_dir.mkdir()

            def fake_run(command, timeout=10):
                if command[:3] == ["route", "-n", "get"]:
                    return SimpleNamespace(ok=True, stdout="   interface: awg0\n", stderr="", error=None)
                return SimpleNamespace(ok=True, stdout="", stderr="", error=None)

            with (
                patch.object(api, "RU_TABLE", table),
                patch.object(paths, "RU_TABLE", table),
                patch.object(backup.paths, "RU_TABLE", table),
                patch.object(backup.paths, "BACKUP_DIR", backup_dir),
                patch.object(vpn_policy, "run", side_effect=fake_run) as run_mock,
                patch.dict(os.environ, {"GATEBSD_FORCE_ROUTE_CONVERGE": "1"}, clear=False),
            ):
                # No-op add must NOT converge
                st_noop, _ = api._pf_table_add({"values": ["10.0.0.0/24"]})
                self.assertEqual(st_noop, 200)
                self.assertFalse(any(c.args[0][:2] == ["service", "ru_bypass"] for c in run_mock.call_args_list))

                # Actual add MUST converge
                st_add, _ = api._pf_table_add({"values": ["203.0.113.0/24"]})
                self.assertEqual(st_add, 200)
                self.assertEqual(
                    sum(1 for c in run_mock.call_args_list if c.args[0] == ["service", "ru_bypass", "start"]),
                    1,
                )

                # Actual remove MUST converge
                st_rm, _ = api._pf_table_remove({"values": ["203.0.113.0/24"]})
                self.assertEqual(st_rm, 200)
                self.assertEqual(
                    sum(1 for c in run_mock.call_args_list if c.args[0] == ["service", "ru_bypass", "start"]),
                    2,
                )
