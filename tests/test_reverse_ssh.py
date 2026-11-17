from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

from gatebsd_ui.writers import reverse_ssh


HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE9WJd5J7y5W6J8W2s3F4g5H6j7K8l9M0n1P2q3R4s5T"


def rule(**changes):
    value = {
        "id": "home-web",
        "enabled": True,
        "remote_host": "203.0.113.142",
        "remote_port": 22,
        "remote_user": "gatebsd-forward",
        "remote_bind_address": "127.0.0.1",
        "allow_public": False,
        "external_port": 443,
        "target_host": "10.88.0.155",
        "target_port": 8443,
        "host_key": HOST_KEY,
    }
    value.update(changes)
    return value


class ReverseSshValidationTests(unittest.TestCase):
    def test_loopback_bind_is_the_default_safe_mode(self) -> None:
        normalized = reverse_ssh.validate_rule(rule())
        self.assertEqual(normalized["remote_bind_address"], "127.0.0.1")
        self.assertEqual(
            reverse_ssh.known_hosts_line(normalized),
            f"203.0.113.142 {HOST_KEY}",
        )

    def test_non_default_ssh_port_is_bracketed_in_known_hosts(self) -> None:
        normalized = reverse_ssh.validate_rule(rule(remote_port=2222))
        self.assertEqual(
            reverse_ssh.known_hosts_line(normalized),
            f"[203.0.113.142]:2222 {HOST_KEY}",
        )

    def test_public_bind_requires_an_explicit_override(self) -> None:
        with self.assertRaisesRegex(ValueError, "public"):
            reverse_ssh.validate_rule(rule(remote_bind_address="0.0.0.0"))
        normalized = reverse_ssh.validate_rule(rule(remote_bind_address="0.0.0.0", allow_public=True))
        self.assertEqual(normalized["remote_bind_address"], "0.0.0.0")

    def test_root_and_unsafe_values_are_rejected(self) -> None:
        for changes in (
            {"remote_user": "root"},
            {"remote_host": "-oProxyCommand=bad"},
            {"remote_user": "bad user"},
            {"target_host": "8.8.8.8"},
            {"host_key": "ssh-rsa short"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    reverse_ssh.validate_rule(rule(**changes))

    def test_ssh_arguments_enforce_keys_forwarding_and_keepalive(self) -> None:
        args = reverse_ssh.ssh_arguments(rule(), "/keys/home-web", "/keys/known_hosts")
        joined = " ".join(args)
        self.assertIn("-R 127.0.0.1:443:10.88.0.155:8443", joined)
        self.assertIn("ExitOnForwardFailure=yes", joined)
        self.assertIn("StrictHostKeyChecking=yes", joined)
        self.assertIn("UserKnownHostsFile=/keys/known_hosts", joined)
        self.assertIn("IdentitiesOnly=yes", joined)
        self.assertIn("BatchMode=yes", joined)
        self.assertIn("ServerAliveInterval=30", joined)
        self.assertIn("ServerAliveCountMax=3", joined)
        self.assertNotIn("StrictHostKeyChecking=no", joined)
        self.assertNotIn("autossh", joined)
        self.assertTrue(args[-1].endswith("gatebsd-forward@203.0.113.142"))


class ReverseSshSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile
        from pathlib import Path

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = mock.patch.object(reverse_ssh, "RUN_DIR", Path(self.temp.name) / "run")
        self.run_dir.start()
        self.addCleanup(self.run_dir.stop)
        self.result = SimpleNamespace(ok=True, stdout="", stderr="", error="")
        self.paths = mock.patch.multiple(
            reverse_ssh,
            _identity=mock.DEFAULT,
            _known_hosts_path=mock.DEFAULT,
            _pid_running=mock.DEFAULT,
        )
        self.paths.start()
        self.addCleanup(self.paths.stop)
        reverse_ssh._identity.return_value = "/keys/home-web"
        reverse_ssh._known_hosts_path.return_value = "/keys/known_hosts"
        reverse_ssh._pid_running.return_value = False

    def test_start_launches_each_enabled_rule_as_unprivileged_daemon(self) -> None:
        with mock.patch.object(reverse_ssh, "_load_rules", return_value=[rule()]), mock.patch.object(reverse_ssh, "run", return_value=self.result) as command:
            payload = reverse_ssh.start()
        self.assertEqual(payload["started"], ["home-web"])
        args = command.call_args.args[0]
        self.assertEqual(args[:8], [
            "/usr/sbin/daemon", "-u", "gatebsd-forward", "-r", "-R", "5", "-P", args[7],
        ])
        self.assertIn("/usr/bin/ssh", args)
        self.assertIn("ExitOnForwardFailure=yes", " ".join(args))

    def test_start_without_rules_does_not_launch_daemon(self) -> None:
        with mock.patch.object(reverse_ssh, "_load_rules", return_value=[]), mock.patch.object(reverse_ssh, "run") as command:
            payload = reverse_ssh.start()
        self.assertEqual(payload["started"], [])
        command.assert_not_called()

    def test_stop_also_stops_rules_removed_from_config(self) -> None:
        reverse_ssh.RUN_DIR.mkdir(parents=True)
        pidfile = reverse_ssh.RUN_DIR / "deleted.supervisor.pid"
        pidfile.write_text("123\n", encoding="ascii")
        with mock.patch.object(reverse_ssh, "_load_rules", return_value=[]), mock.patch.object(reverse_ssh, "_pid_running", return_value=True), mock.patch.object(reverse_ssh, "run", return_value=self.result) as command:
            payload = reverse_ssh.stop()
        self.assertEqual(payload["stopped"], ["deleted"])
        command.assert_called_once_with(["kill", "-TERM", "123"], timeout=3)
        self.assertFalse(pidfile.exists())

    def test_duplicate_remote_endpoints_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "already used"):
            reverse_ssh.validate_rules([
                rule(),
                rule(id="other", target_host="10.88.0.159"),
            ])


class ReverseSshApiTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile
        from pathlib import Path

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.paths = mock.patch.multiple(
            reverse_ssh,
            CONFIG_PATH=root / "reverse-ssh.json",
            KEY_DIR=root / "keys",
            RUN_DIR=root / "run",
            LOG_FILE=root / "reverse.log",
        )
        self.paths.start()
        self.addCleanup(self.paths.stop)
        self.chown = mock.patch.object(reverse_ssh, "_chown_forward")
        self.chown.start()
        self.addCleanup(self.chown.stop)
        self.service_results = []

    def _run(self, command, **_kwargs):
        if command[:2] == ["ssh-keygen", "-t"]:
            identity = command[-1]
            from pathlib import Path
            Path(identity).write_text("PRIVATE", encoding="ascii")
            Path(identity + ".pub").write_text(HOST_KEY + " generated\n", encoding="ascii")
        if command[:2] == ["ssh-keygen", "-l"]:
            return SimpleNamespace(ok=True, stdout="256 SHA256:verified host (ED25519)", stderr="", error="")
        if command[:2] == ["service", "gatebsd_reverse_ssh"]:
            return self.service_results.pop(0) if self.service_results else SimpleNamespace(ok=True, stdout="", stderr="", error="")
        return SimpleNamespace(ok=True, stdout="", stderr="", error="")

    def test_save_generates_private_material_but_returns_only_public_key(self) -> None:
        with mock.patch.object(reverse_ssh, "run", side_effect=self._run), mock.patch.object(reverse_ssh, "_pid_running", return_value=False):
            status, payload = reverse_ssh.save_config(rule())
            listed_status, listed = reverse_ssh.list_config()
        self.assertEqual(status, 200)
        self.assertEqual(listed_status, 200)
        self.assertIn("public_key", payload)
        self.assertNotIn("PRIVATE", str(payload))
        self.assertIn('permitlisten="127.0.0.1:443"', payload["authorized_keys_hint"])
        self.assertEqual(listed["rules"][0]["host_key_fingerprint"], "SHA256:verified")
        self.assertEqual(reverse_ssh.CONFIG_PATH.stat().st_mode & 0o777, 0o600)
        known_hosts = reverse_ssh.KEY_DIR / "home-web.known_hosts"
        self.assertEqual(known_hosts.read_text(encoding="ascii"), f"203.0.113.142 {HOST_KEY}\n")

    def test_failed_restart_restores_the_previous_configuration(self) -> None:
        with mock.patch.object(reverse_ssh, "run", side_effect=self._run):
            self.assertEqual(reverse_ssh.save_config(rule())[0], 200)
        before = reverse_ssh.CONFIG_PATH.read_text(encoding="utf-8")
        self.service_results = [
            SimpleNamespace(ok=False, stdout="", stderr="start failed", error=""),
            SimpleNamespace(ok=True, stdout="", stderr="", error=""),
        ]
        with mock.patch.object(reverse_ssh, "run", side_effect=self._run):
            status, payload = reverse_ssh.save_config(rule(external_port=8443))
        self.assertEqual(status, 500)
        self.assertTrue(payload["rolled_back"])
        self.assertEqual(reverse_ssh.CONFIG_PATH.read_text(encoding="utf-8"), before)


class ReverseSshDeliveryTests(unittest.TestCase):
    def test_rc_script_and_both_delivery_paths_exist(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        rc = (root / "rc.d" / "gatebsd_reverse_ssh").read_text(encoding="utf-8")
        self.assertIn('start_cmd="/usr/local/sbin/gatebsd-reverse-ssh start"', rc)
        self.assertIn('stop_cmd="/usr/local/sbin/gatebsd-reverse-ssh stop"', rc)
        for path in (root / "Makefile", root / "ci" / "build.sh"):
            text = path.read_text(encoding="utf-8")
            self.assertIn("gatebsd-reverse-ssh", text)
            self.assertIn("gatebsd_reverse_ssh", text)
            self.assertIn("gatebsd-forward", text)


    def test_upgrade_install_and_log_rotation_cover_the_service(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        self.assertIn("gatebsd_reverse_ssh", (root / "sbin" / "gatebsd-upgrade").read_text(encoding="utf-8"))
        self.assertIn("gatebsd_reverse_ssh", (root / "sbin" / "gatebsd-install").read_text(encoding="utf-8"))
        rotation = (root / "etc" / "newsyslog.conf.d" / "gatebsd.conf").read_text(encoding="utf-8")
        self.assertIn("/var/log/gatebsd-reverse-ssh.log 600", rotation)


class ReverseSshRouteTests(unittest.TestCase):
    def test_api_and_agent_routes_are_wired(self) -> None:
        from gatebsd_ui import agent, api

        with mock.patch.object(api.writers, "reverse_ssh_list", return_value=(200, {"rules": []})):
            self.assertEqual(api.dispatch("/api/reverse-ssh")[0], 200)
        with mock.patch.object(api.writers, "reverse_ssh_save", return_value=(200, {"ok": True})):
            self.assertEqual(api.dispatch("/api/reverse-ssh/save", method="POST", body=rule())[0], 200)
        with mock.patch.object(api.writers, "reverse_ssh_delete", return_value=(200, {"ok": True})) as delete:
            self.assertEqual(api.dispatch("/api/reverse-ssh/delete", method="POST", body={"id": "home-web"})[0], 200)
            delete.assert_called_once_with("home-web")
        self.assertTrue(agent._agent_allowed("GET", "/api/reverse-ssh"))
        self.assertTrue(agent._agent_allowed("POST", "/api/reverse-ssh/save"))
        self.assertTrue(agent._agent_allowed("POST", "/api/reverse-ssh/delete"))

    def test_frontend_has_reverse_ssh_crud_and_public_key_view(self) -> None:
        from pathlib import Path

        app = (Path(__file__).resolve().parents[1] / "webui" / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn('"/api/reverse-ssh"', app)
        self.assertIn("Reverse SSH → LAN", app)
        for name in ("showReverseSsh", "saveReverseSsh", "deleteReverseSsh", "showReverseSshKey"):
            self.assertIn(name, app)


class ReverseSshLockingTests(unittest.TestCase):
    def test_m5_save_and_delete_serialize_on_config_lock(self) -> None:
        import contextlib
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "reverse-ssh.json"
            kdir = Path(tmp) / "keys"
            cfg.write_text('{"version": 1, "rules": []}\n', encoding="utf-8")
            locks_entered: list[Path] = []

            @contextlib.contextmanager
            def spy_lock(lock_path: Path, *args, **kwargs):
                locks_entered.append(Path(lock_path))
                yield 1

            def fake_run(command, **_kwargs):
                if command[:2] == ["ssh-keygen", "-t"]:
                    identity = Path(command[-1])
                    identity.write_text("PRIVATE", encoding="ascii")
                    Path(f"{identity}.pub").write_text(f"{HOST_KEY} generated\n", encoding="ascii")
                if command[:2] == ["ssh-keygen", "-l"]:
                    return SimpleNamespace(ok=True, stdout="256 SHA256:verified host (ED25519)", stderr="", error="")
                return SimpleNamespace(ok=True, stdout="", stderr="", error="")

            with (
                mock.patch.object(reverse_ssh, "CONFIG_PATH", cfg),
                mock.patch.object(reverse_ssh, "KEY_DIR", kdir),
                mock.patch.object(reverse_ssh, "_chown_forward"),
                mock.patch.object(reverse_ssh, "_pid_running", return_value=False),
                mock.patch.object(reverse_ssh, "exclusive_lock", side_effect=spy_lock),
                mock.patch.object(reverse_ssh, "run", side_effect=fake_run),
            ):
                status_save, payload_save = reverse_ssh.save_config(rule(enabled=False))
                self.assertEqual(status_save, 200, payload_save)
                status_del, payload_del = reverse_ssh.delete_config("home-web")
                self.assertEqual(status_del, 200, payload_del)

            expected_lock = cfg.with_suffix(".json.gatebsd.lock")
            self.assertEqual(locks_entered, [expected_lock, expected_lock])


if __name__ == "__main__":
    unittest.main()
