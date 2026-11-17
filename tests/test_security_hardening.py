from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from email.message import Message
from pathlib import Path
from unittest import mock

from gatebsd_ui import auth, backup, discovery, ru_table, server, storage
from gatebsd_ui.command import run
from gatebsd_ui.resolver import resolve_ipv4, resolve_ipv4_via_server
from gatebsd_ui.adapters.helpers import _check_target, _lan_network, _safe_config_text
from gatebsd_ui.adapters import system as system_adapter
from gatebsd_ui.fsutil import exclusive_lock
from gatebsd_ui.lockrun import _command_environment, _parse as parse_lockrun


class SecurityHardeningTests(unittest.TestCase):
    def test_exclusive_lock_nonblocking_reports_busy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "operation.lock"
            with exclusive_lock(lock_path):
                with self.assertRaises(BlockingIOError):
                    with exclusive_lock(lock_path, nonblocking=True):
                        self.fail("second lock unexpectedly succeeded")

    def test_safe_config_reader_rejects_symlink_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "regular.conf"
            regular.write_text("KEY=value\n", encoding="utf-8")
            link = root / "link.conf"
            link.symlink_to(regular)
            self.assertEqual(_safe_config_text(regular), "KEY=value\n")
            self.assertEqual(_safe_config_text(link), "")
            self.assertEqual(_safe_config_text(regular, limit=2), "")

    def test_discovery_summary_does_not_follow_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / "secret"
            secret.write_text("PrivateKey = do-not-read\n", encoding="utf-8")
            link = root / "config"
            link.symlink_to(secret)
            summary = discovery._file_summary(link)
            self.assertTrue(summary["exists"])
            self.assertIn("error", summary)
            self.assertNotIn("sample", summary)

    def test_ru_table_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "table"
            regular.write_bytes(b"1.1.1.0/24\n")
            link = root / "link"
            link.symlink_to(regular)
            with self.assertRaises(OSError):
                ru_table.read_regular(link)

    def test_ru_table_compare_and_swap_preserves_concurrent_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "ru.table"
            candidate = root / "candidate"
            destination.write_bytes(b"1.1.1.0/24\n")
            candidate.write_bytes(b"2.2.2.0/24\n")
            with self.assertRaises(RuntimeError):
                ru_table.replace_table(destination, candidate, expected_sha256="0" * 64)
            self.assertEqual(destination.read_bytes(), b"1.1.1.0/24\n")

    def test_ru_table_atomic_replace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "ru.table"
            candidate = root / "candidate"
            destination.write_bytes(b"1.1.1.0/24\n")
            candidate.write_bytes(b"2.2.2.0/24\n")
            old_digest, new_digest = ru_table.replace_table(
                destination,
                candidate,
                expected_sha256=ru_table.digest(destination.read_bytes()),
            )
            self.assertEqual(old_digest, ru_table.digest(b"1.1.1.0/24\n"))
            self.assertEqual(new_digest, ru_table.digest(b"2.2.2.0/24\n"))
            self.assertEqual(destination.read_bytes(), b"2.2.2.0/24\n")

    def test_system_authorization_requires_admin_group(self) -> None:
        account = SimpleNamespace(pw_uid=1001, pw_gid=1001)
        admin = SimpleNamespace(gr_gid=0, gr_mem=["alice"])
        with (
            mock.patch("gatebsd_ui.auth.pwd.getpwnam", return_value=account),
            mock.patch("gatebsd_ui.auth.grp.getgrnam", return_value=admin),
        ):
            self.assertTrue(auth.authorized_system_user("alice", "wheel"))
            self.assertFalse(auth.authorized_system_user("bob", "wheel"))

    def test_root_is_authorized_without_group_lookup(self) -> None:
        root = SimpleNamespace(pw_uid=0, pw_gid=0)
        with (
            mock.patch("gatebsd_ui.auth.pwd.getpwnam", return_value=root),
            mock.patch("gatebsd_ui.auth.grp.getgrnam") as group_lookup,
        ):
            self.assertTrue(auth.authorized_system_user("root", "wheel"))
            group_lookup.assert_not_called()

    def test_logout_revocation_invalidates_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(server, "SESSION_SECRET_FILE", root / "session.secret"),
                mock.patch.object(server, "SESSION_REVOCATION_FILE", root / "revoked.json"),
                mock.patch.object(server, "SESSION_EPOCH_FILE", root / "session.epoch"),
                mock.patch.dict(os.environ, {"GATEBSD_SESSION_SECRET": ""}, clear=False),
            ):
                server._REVOKED_MEMORY.clear()
                token = server.make_token("root")
                self.assertEqual(server.valid_token(token), (True, "root"))
                self.assertTrue(server.revoke_token(token))
                self.assertEqual(server.valid_token(token), (False, ""))

    def test_session_secret_rotation_invalidates_old_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(server, "SESSION_SECRET_FILE", root / "session.secret"),
                mock.patch.object(server, "SESSION_REVOCATION_FILE", root / "revoked.json"),
                mock.patch.object(server, "SESSION_EPOCH_FILE", root / "session.epoch"),
                mock.patch.dict(os.environ, {"GATEBSD_SESSION_SECRET": ""}, clear=False),
            ):
                server._REVOKED_MEMORY.clear()
                token = server.make_token("root")
                server._rotate_session_secret()
                self.assertEqual(server.valid_token(token), (False, ""))
                self.assertEqual(server.valid_token(server.make_token("root")), (True, "root"))

    def test_same_origin_and_json_contract(self) -> None:
        handler = object.__new__(server.GateBSDHandler)
        headers = Message()
        headers["Host"] = "router.example:8443"
        headers["Origin"] = "https://router.example:8443"
        headers["Content-Type"] = "application/json; charset=utf-8"
        handler.headers = headers
        self.assertTrue(handler.same_origin_request())
        self.assertTrue(handler.json_content_type())

        headers.replace_header("Origin", "https://evil.example")
        self.assertFalse(handler.same_origin_request())
        headers.replace_header("Content-Type", "text/plain")
        self.assertFalse(handler.json_content_type())

    def test_null_origin_is_rejected(self) -> None:
        handler = object.__new__(server.GateBSDHandler)
        headers = Message()
        headers["Host"] = "127.0.0.1:8080"
        headers["Origin"] = "null"
        handler.headers = headers
        self.assertFalse(handler.same_origin_request())

    def test_lockrun_environment_is_allowlisted(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/bin",
                "GATEBSD_KEEP": "yes",
                "UNSAFE_SENTINEL": "secret",
            },
            clear=True,
        ):
            environment = _command_environment()
        self.assertEqual(environment["PATH"], "/bin")
        self.assertEqual(environment["GATEBSD_KEEP"], "yes")
        self.assertNotIn("UNSAFE_SENTINEL", environment)

    def test_multilock_parser_sorts_locks(self) -> None:
        locks, command = parse_lockrun([
            "--lock", "/tmp/z.lock", "--lock", "/tmp/a.lock", "--", "true"
        ])
        self.assertEqual([str(item) for item in locks], ["/tmp/a.lock", "/tmp/z.lock"])
        self.assertEqual(command, ["true"])

    def test_python_resolver_selects_highest_usable_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            localbase = Path(directory)
            bindir = localbase / "bin"
            bindir.mkdir()
            (bindir / "python3.10").symlink_to(sys.executable)
            (bindir / "python3.13").symlink_to(sys.executable)
            script = Path(__file__).resolve().parents[1] / "ci" / "resolve-python.sh"
            result = subprocess.run(
                ["sh", str(script)],
                check=False,
                capture_output=True,
                text=True,
                env={"PATH": os.environ.get("PATH", ""), "LOCALBASE": str(localbase)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"PYTHON_CMD={bindir / 'python3.13'}", result.stdout)
            self.assertIn("PYTHON_FLAVOR=py313", result.stdout)

    def test_command_runner_uses_minimal_environment_and_redacts_arguments(self) -> None:
        with mock.patch.dict(os.environ, {"GATEBSD_UNSAFE_SENTINEL": "secret"}, clear=False):
            result = run(
                [sys.executable, "-c", "import os; print(os.environ.get('GATEBSD_UNSAFE_SENTINEL', 'missing'))", "secret"],
                timeout=5,
                redact_args={3},
            )
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.stdout, "missing")
        self.assertEqual(result.command[3], "<redacted>")

    def test_command_runner_enforces_output_limit(self) -> None:
        result = run(
            [sys.executable, "-c", "print('x' * 100000)"],
            timeout=5,
            max_output=1024,
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "output exceeds 1024 bytes")
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 1024)

    def test_command_timeout_kills_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "child.pid"
            result = run(
                ["sh", "-c", f"sleep 30 & echo $! > {pid_path}; wait"],
                timeout=0.2,
            )
            self.assertFalse(result.ok)
            self.assertIn("timeout", result.error or "")
            child_pid = int(pid_path.read_text(encoding="ascii").strip())
            for _ in range(20):
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                import time
                time.sleep(0.05)
            else:
                self.fail("timed-out subprocess child survived process-group cleanup")

    def test_network_limits_reject_wide_or_invalid_lan_ranges(self) -> None:
        self.assertEqual(_lan_network("10.0.0.0/8"), "10.88.0.0/24")
        self.assertEqual(_lan_network("10.0.0.7/24"), "10.0.0.0/24")
        self.assertEqual(_check_target("bad target"), "1.1.1.1")

    def test_ipv4_resolver_rejects_ipv6_literal_without_dns_query(self) -> None:
        self.assertEqual(resolve_ipv4("2001:db8::1"), [])
        self.assertEqual(resolve_ipv4_via_server("2001:db8::1", "1.1.1.1"), [])


    def test_loopback_bind_detection(self) -> None:
        self.assertTrue(server._is_loopback_bind("127.0.0.1"))
        self.assertTrue(server._is_loopback_bind("::1"))
        self.assertTrue(server._is_loopback_bind("localhost"))
        self.assertFalse(server._is_loopback_bind("0.0.0.0"))
        self.assertFalse(server._is_loopback_bind("192.0.2.10"))

    def test_authentication_cannot_be_disabled(self) -> None:
        # An unauthenticated mode previously existed and allowed forged identity
        # parameters to reach the root agent. It must not be reintroducible.
        self.assertTrue(server.auth_enabled())
        self.assertIn(server.AUTH_MODE, {"system", "sudo", "password"})
        source = (Path(server.__file__)).read_text(encoding="utf-8")
        self.assertNotIn('"off"', source)

    def test_trusted_identity_query_parameters_are_stripped(self) -> None:
        # These keys are how this process tells the privileged agent who the
        # caller is. A request that supplies them itself is claiming an identity
        # it has not proven, so they must never survive into dispatch.
        forged = {
            "_user": ["root"],
            "_session": ["a" * 64],
            "_auth_mode": ["system"],
            "_anything": ["x"],
            "legitimate": ["keep"],
        }
        stripped = server._strip_trusted_query(forged)
        self.assertEqual(stripped, {"legitimate": ["keep"]})

    def test_revoke_token_rejects_forged_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(server, "SESSION_SECRET_FILE", root / "session.secret"),
                mock.patch.object(server, "SESSION_REVOCATION_FILE", root / "revoked.json"),
                mock.patch.object(server, "SESSION_EPOCH_FILE", root / "session.epoch"),
                mock.patch.dict(os.environ, {"GATEBSD_SESSION_SECRET": ""}, clear=False),
            ):
                server._REVOKED_MEMORY.clear()
                epoch = server._session_epoch()
                forged = f"{2 ** 62}:{'b' * 24}:root:{epoch}:{'c' * 64}"
                self.assertEqual(server.valid_token(forged), (False, ""))
                self.assertFalse(server.revoke_token(forged))

    def test_revocation_flood_cannot_resurrect_a_revoked_token(self) -> None:
        # The registry is bounded. If unsigned tokens could enter it, an
        # attacker could evict genuine revocations by submitting entries with
        # far-future expirations, making a logged-out token valid again.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(server, "SESSION_SECRET_FILE", root / "session.secret"),
                mock.patch.object(server, "SESSION_REVOCATION_FILE", root / "revoked.json"),
                mock.patch.object(server, "SESSION_EPOCH_FILE", root / "session.epoch"),
                mock.patch.dict(os.environ, {"GATEBSD_SESSION_SECRET": ""}, clear=False),
                mock.patch.object(server, "_MAX_REVOCATIONS", 16),
            ):
                server._REVOKED_MEMORY.clear()
                victim = server.make_token("root")
                self.assertTrue(server.revoke_token(victim))
                self.assertEqual(server.valid_token(victim), (False, ""))

                epoch = server._session_epoch()
                for index in range(64):
                    bogus = f"{2 ** 62}:{index:024d}:root:{epoch}:{'d' * 64}"
                    self.assertFalse(server.revoke_token(bogus))

                # Clear the in-process cache so the on-disk registry is the only
                # thing keeping the victim revoked.
                server._REVOKED_MEMORY.clear()
                self.assertEqual(server.valid_token(victim), (False, ""))

    def test_revocation_pruning_drops_expired_before_live_entries(self) -> None:
        now = int(time.time())
        values = {f"expired{index}": now - 60 for index in range(50)}
        values.update({f"live{index}": now + 3600 for index in range(5)})
        with mock.patch.object(server, "_MAX_REVOCATIONS", 8):
            pruned = server._prune_revocations(values)
        self.assertEqual(set(pruned), {f"live{index}" for index in range(5)})

        with mock.patch.object(server, "_MAX_REVOCATIONS", 4):
            over = {f"live{index}": now + 100 + index for index in range(10)}
            pruned = server._prune_revocations(over)
        self.assertEqual(len(pruned), 4)
        # The furthest expirations are the ones worth keeping.
        self.assertEqual(set(pruned), {f"live{index}" for index in range(6, 10)})

    def test_throttle_identity_ignores_spoofable_forwarded_header(self) -> None:
        # Every proxied request arrives from loopback, so a client can supply
        # X-Real-IP itself. Keying the login throttle on it would let an attacker
        # reset the counter at will.
        handler = object.__new__(server.GateBSDHandler)
        headers = Message()
        headers["X-Real-IP"] = "203.0.113.7"
        handler.headers = headers
        handler.client_address = ("127.0.0.1", 12345)
        self.assertEqual(handler.client_identity(), "203.0.113.7")
        self.assertEqual(handler.throttle_identity(), "127.0.0.1")
        headers.replace_header("X-Real-IP", "203.0.113.99")
        self.assertEqual(handler.throttle_identity(), "127.0.0.1")

    def test_server_imports_stat_for_log_stream_guard(self) -> None:
        # handle_ws_logs uses stat.S_ISREG to refuse a symlinked log source.
        # Without the import every request raised NameError and the guard was
        # unreachable dead code.
        self.assertTrue(hasattr(server, "stat"))
        self.assertTrue(callable(server.stat.S_ISREG))

    def test_agent_reauthorizes_identity_bearing_endpoints(self) -> None:
        from gatebsd_ui import agent

        for path in ("/api/auth/password", "/api/terminal/start", "/api/terminal/write"):
            self.assertIn(path, agent._IDENTITY_BEARING_PATHS)

        self.assertIsNotNone(agent._reject_unauthorized_identity({}))
        self.assertIsNotNone(agent._reject_unauthorized_identity({"_user": [""]}))
        self.assertIsNotNone(agent._reject_unauthorized_identity({"_user": ["../root"]}))
        with mock.patch.object(agent, "_IDENTITY_BEARING_PATHS", agent._IDENTITY_BEARING_PATHS):
            with mock.patch("gatebsd_ui.auth.authorized_system_user", return_value=False):
                self.assertIsNotNone(agent._reject_unauthorized_identity({"_user": ["operator"]}))
            with mock.patch("gatebsd_ui.auth.authorized_system_user", return_value=True):
                self.assertIsNone(agent._reject_unauthorized_identity({"_user": ["operator"]}))

    def test_agent_peer_identity_is_kernel_supplied(self) -> None:
        import socket as socket_module

        from gatebsd_ui import agent

        left, right = socket_module.socketpair(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
        try:
            identity = agent.peer_identity(left)
            self.assertIsNotNone(identity)
            assert identity is not None
            self.assertEqual(identity[0], os.getuid())
        finally:
            left.close()
            right.close()

    def test_http_framing_rejects_transfer_encoding_and_duplicate_length(self) -> None:
        handler = object.__new__(server.GateBSDHandler)
        headers = Message()
        headers["Transfer-Encoding"] = "chunked"
        handler.headers = headers
        self.assertEqual(handler.content_length(), (None, "Transfer-Encoding is not supported"))

        duplicate = Message()
        duplicate["Content-Length"] = "1"
        duplicate["Content-Length"] = "1"
        handler.headers = duplicate
        self.assertEqual(
            handler.content_length(),
            (None, "multiple Content-Length headers are not allowed"),
        )

    def test_client_identity_trusts_real_ip_only_from_loopback(self) -> None:
        handler = object.__new__(server.GateBSDHandler)
        headers = Message()
        headers["X-Real-IP"] = "203.0.113.7"
        handler.headers = headers
        handler.client_address = ("127.0.0.1", 12345)
        self.assertEqual(handler.client_identity(), "203.0.113.7")
        handler.client_address = ("198.51.100.9", 12345)
        self.assertEqual(handler.client_identity(), "198.51.100.9")

    def test_command_timeout_is_not_blocked_by_unread_stdin(self) -> None:
        started = time.monotonic()
        result = run(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=0.2,
            input=b"x" * (64 * 1024),
        )
        self.assertFalse(result.ok)
        self.assertIn("timeout", result.error or "")
        self.assertLess(time.monotonic() - started, 3.0)

    def test_database_backup_rejects_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.db"
            with sqlite3.connect(source) as connection:
                connection.execute("create table sample(value integer)")
            output = root / "public"
            output.mkdir(mode=0o777)
            output.chmod(0o777)
            with (
                mock.patch.dict(os.environ, {"GATEBSD_DB_PATH": str(source)}, clear=False),
                self.assertRaises(OSError),
            ):
                storage.backup_database(output / "backup.db")

    def test_backup_snapshot_is_atomically_published(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "pf.conf"
            source.write_bytes(b"pass all\n")
            backup_root = root / "backups"
            with mock.patch.object(backup.paths, "BACKUP_DIR", backup_root):
                result = backup.backup_files([source], reason="test")
            destination = Path(result["dir"])
            self.assertTrue(destination.is_dir())
            self.assertFalse(destination.name.startswith("."))
            self.assertEqual([entry.name for entry in backup_root.iterdir()], [destination.name])
            self.assertEqual(len(result["files"]), 1)

    def test_smart_device_validation_does_not_rewrite_input(self) -> None:
        self.assertEqual(system_adapter._device_path("../ada0"), (None, "invalid device name"))
        self.assertEqual(system_adapter._device_path("ada0;id"), (None, "invalid device name"))

    def test_release_scripts_enforce_safe_roots_and_exact_uninstall(self) -> None:
        root = Path(__file__).resolve().parents[1]
        upgrade = (root / "sbin" / "gatebsd-upgrade").read_text(encoding="utf-8")
        self.assertIn("target package must be owned by root", upgrade)
        self.assertIn("private package copy does not match the target", upgrade)
        self.assertIn('safe_private_root "$BACKUP_ROOT"', upgrade)
        self.assertIn("--no-verify-peer --no-verify-hostname", upgrade)
        image_backup = (root / "sbin" / "gatebsd-backup.sh").read_text(encoding="utf-8")
        installer = (root / "sbin" / "gatebsd-install").read_text(encoding="utf-8")
        self.assertIn('safe_private_root "$BACKUP_DIR"', image_backup)
        self.assertIn('safe_private_root "$BACKUP_ROOT"', installer)
        makefile = (root / "Makefile").read_text(encoding="utf-8")
        self.assertNotIn("${SBINDIR}/gatebsd-*", makefile)

    def test_route_helper_is_packaged_and_watchdog_uses_it(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertIn("gatebsd-route-op", (root / "ci" / "build.sh").read_text(encoding="utf-8"))
        watchdog = (root / "sbin" / "gatebsd-watchdog.sh").read_text(encoding="utf-8")
        self.assertIn('route_op switch-underlay', watchdog)
        self.assertNotIn('route change default "$gw"', watchdog)


    def test_privileged_lock_reexecs_clear_inherited_environment(self) -> None:
        root = Path(__file__).resolve().parents[1]
        scripts = [
            "gatebsd-failoverctl",
            "gatebsd-ups-test.sh",
            "gatebsd-upgrade",
            "ru-bypass-update.sh",
            "ru-routes.sh",
        ]
        for name in scripts:
            text = (root / "sbin" / name).read_text(encoding="utf-8")
            self.assertIn("exec env -i", text, name)


if __name__ == "__main__":
    unittest.main()
