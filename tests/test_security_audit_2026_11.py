"""Regression tests for November 2026 infrastructure, OS, and WebUI security hardening."""
from __future__ import annotations

import hashlib
import importlib
import io
import json
import os
import pwd
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "webui" / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from gatebsd_ui import agent, api, fsutil, server, storage, writers  # noqa: E402
from gatebsd_ui.adapters import vpn as vpn_adapter  # noqa: E402
from gatebsd_ui.writers import ups as ups_writer  # noqa: E402

firewall_adapter = importlib.import_module("gatebsd_ui.adapters.firewall")


def _call_agent_handler(
    method: str,
    path: str,
    *,
    query: dict[str, list[str]] | None = None,
    body: dict | None = None,
) -> tuple[int, dict]:
    client_sock, server_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client_sock.settimeout(5.0)
        payload = {"method": method, "path": path, "query": query or {}, "body": body}
        client_sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        client_sock.shutdown(socket.SHUT_WR)
        with mock.patch.object(agent, "_peer_is_trusted", return_value=True):
            agent.AgentRequestHandler(server_sock, ("local", 0), mock.MagicMock())
        server_sock.close()
        chunks: list[bytes] = []
        while True:
            chunk = client_sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        decoded = json.loads(b"".join(chunks).decode("utf-8"))
        return int(decoded["status"]), decoded["payload"]
    finally:
        client_sock.close()
        server_sock.close()


class _FakeWfile:
    def __init__(self) -> None:
        self.buf = io.BytesIO()

    def write(self, data: bytes) -> int:
        return self.buf.write(data)


class AgentIdentityGrantTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = Path(self._td.name)

    def _run_handler(
        self,
        *,
        method: str,
        path: str,
        body: bytes = b"",
        cookies: list[str] | None = None,
    ) -> tuple[int, dict[str, list[str]], dict]:
        headers_sent: list[tuple[str, str]] = []
        status_holder: list[int] = []
        wfile = _FakeWfile()

        handler = server.GateBSDHandler.__new__(server.GateBSDHandler)
        handler.path = path
        handler.command = method
        handler.rfile = io.BytesIO(body)
        handler.wfile = wfile
        handler.client_address = ("127.0.0.1", 12345)
        handler.connection = None
        hdrs: dict[str, list[str]] = {"Host": ["127.0.0.1:8080"]}
        if body:
            hdrs["Content-Type"] = ["application/json"]
            hdrs["Content-Length"] = [str(len(body))]
            hdrs["Origin"] = ["http://127.0.0.1:8080"]
        if cookies:
            hdrs["Cookie"] = ["; ".join(cookies)]

        class _Headers:
            def get(self, key: str, default: str | None = None) -> str | None:
                for k, v in hdrs.items():
                    if k.lower() == key.lower():
                        return v[0]
                return default

            def get_all(self, key: str, default: list[str] | None = None) -> list[str]:
                for k, v in hdrs.items():
                    if k.lower() == key.lower():
                        return list(v)
                return [] if default is None else list(default)

        handler.headers = _Headers()
        handler.send_response = lambda code, *_a: status_holder.append(int(code))
        handler.send_header = lambda k, v: headers_sent.append((k, v))
        handler.end_headers = lambda: None
        handler.log_error = lambda *_a: None

        handler.route_request(method)
        header_map: dict[str, list[str]] = {}
        for k, v in headers_sent:
            header_map.setdefault(k.lower(), []).append(v)
        decoded = json.loads(wfile.buf.getvalue().decode("utf-8"))
        return status_holder[0], header_map, decoded

    def test_identity_bearing_paths_reject_missing_forged_or_expired_agent_token(self) -> None:
        grant_epoch_file = self.root / "agent-grant.epoch"
        grant_key_file = self.root / "agent-grant.key"
        with (
            mock.patch.object(agent, "AGENT_GRANT_KEY_FILE", grant_key_file, create=True),
            mock.patch.object(agent, "AGENT_GRANT_EPOCH_FILE", grant_epoch_file, create=True),
            mock.patch("gatebsd_ui.auth.authorized_system_user", return_value=True),
            mock.patch("gatebsd_ui.auth.verify_system_password", return_value=True),
            mock.patch.object(agent, "dispatch", return_value=(200, {"authenticated": True, "username": "operator"})),
        ):
            status, payload = _call_agent_handler(
                "POST",
                "/api/terminal/write",
                query={"_user": ["operator"]},
                body={"session": "s1", "data": "id\n"},
            )
            self.assertEqual(status, 403, payload)

            status, login_payload = _call_agent_handler(
                "POST",
                "/api/auth/login",
                body={"username": "operator", "password": "valid-password"},
            )
            self.assertEqual(status, 200, login_payload)
            self.assertTrue(login_payload.get("authenticated"))
            grant_token = login_payload.get("_agent_token", "")
            self.assertTrue(isinstance(grant_token, str) and len(grant_token) > 20, login_payload)

            with mock.patch.object(agent, "dispatch", return_value=(200, {"ok": True})) as disp:
                status, ok_payload = _call_agent_handler(
                    "POST",
                    "/api/terminal/write",
                    query={"_user": ["operator"], "_agent_token": [grant_token]},
                    body={"session": "s1", "data": "id\n"},
                )
                self.assertEqual(status, 200, ok_payload)
                self.assertEqual(disp.call_count, 1)

                # Cannot reuse operator's grant for root
                status, cross_payload = _call_agent_handler(
                    "POST",
                    "/api/terminal/write",
                    query={"_user": ["root"], "_agent_token": [grant_token]},
                    body={"session": "s1", "data": "id\n"},
                )
                self.assertEqual(status, 403, cross_payload)

                # Tampered token rejected
                tampered = grant_token[:-1] + ("a" if grant_token[-1] != "a" else "b")
                status, bad_payload = _call_agent_handler(
                    "POST",
                    "/api/terminal/write",
                    query={"_user": ["operator"], "_agent_token": [tampered]},
                    body={"session": "s1", "data": "id\n"},
                )
                self.assertEqual(status, 403, bad_payload)

                # Post-password-change / epoch bump invalidates prior grant
                agent.bump_agent_grant_epoch()
                status, stale_payload = _call_agent_handler(
                    "POST",
                    "/api/terminal/write",
                    query={"_user": ["operator"], "_agent_token": [grant_token]},
                    body={"session": "s1", "data": "id\n"},
                )
                self.assertEqual(status, 403, stale_payload)

    def test_server_strips_agent_token_from_json_stores_httponly_cookie_and_forwards(self) -> None:
        secret_file = self.root / "session.secret"
        epoch_file = self.root / "session.epoch"
        secret_file.write_text("0" * 64 + "\n", encoding="utf-8")
        epoch_file.write_text("1\n", encoding="utf-8")
        if hasattr(server, "_AGENT_GRANT_CACHE"):
            self.addCleanup(server._AGENT_GRANT_CACHE.clear)

        agent_grant = "9999999999:nonce1:operator:1:sigval"
        with (
            mock.patch.object(server, "AUTH_MODE", "system"),
            mock.patch.object(server, "SESSION_SECRET_FILE", secret_file),
            mock.patch.object(server, "SESSION_EPOCH_FILE", epoch_file),
            mock.patch.object(server, "_login_retry_after", return_value=0),
            mock.patch.object(server, "_record_login_result"),
            mock.patch.object(
                server,
                "agent_dispatch",
                return_value=(200, {"authenticated": True, "username": "operator", "_agent_token": agent_grant}),
            ),
        ):
            status, headers, body = self._run_handler(
                method="POST",
                path="/api/auth/login",
                body=json.dumps({"username": "operator", "password": "secret"}).encode("utf-8"),
            )
            self.assertEqual(status, 200, body)
            self.assertNotIn("_agent_token", body)
            set_cookies = headers.get("set-cookie", [])
            grant_cookies = [c for c in set_cookies if c.startswith("gatebsd_grant=")]
            self.assertEqual(len(grant_cookies), 1, set_cookies)
            self.assertIn("HttpOnly", grant_cookies[0])
            self.assertIn("SameSite=Strict", grant_cookies[0])

            sess_cookies = [c.split(";", 1)[0] for c in set_cookies if c.startswith("gatebsd_session=")]
            self.assertEqual(len(sess_cookies), 1, set_cookies)
            # Token must keep the exact 5-part format
            self.assertEqual(len(sess_cookies[0].split("=", 1)[1].split(":")), 5)

        captured: list[dict] = []

        def fake_agent_dispatch(method: str, path: str, query: dict, body: dict | None = None):
            captured.append({"method": method, "path": path, "query": dict(query), "body": body})
            return 200, {"ok": True}

        with (
            mock.patch.object(server, "AUTH_MODE", "system"),
            mock.patch.object(server, "SESSION_SECRET_FILE", secret_file),
            mock.patch.object(server, "SESSION_EPOCH_FILE", epoch_file),
            mock.patch.object(server, "agent_dispatch", side_effect=fake_agent_dispatch),
        ):
            status, _headers, resp = self._run_handler(
                method="POST",
                path="/api/auth/password",
                body=json.dumps({"current_password": "OldPassword1!", "password": "NewPassword1!"}).encode("utf-8"),
                cookies=[sess_cookies[0], f"gatebsd_grant={agent_grant}"],
            )
            self.assertEqual(status, 200, resp)
            self.assertEqual(len(captured), 1)
            self.assertEqual(captured[0]["query"].get("_agent_token"), [agent_grant])


class PasswordChangeCurrentPasswordTests(unittest.TestCase):
    def test_password_change_requires_valid_current_password(self) -> None:
        with (
            mock.patch.object(api, "verify_system_password", return_value=False) as ver_mock,
            mock.patch.object(api, "run") as run_mock,
        ):
            status, payload = api.dispatch(
                "/api/auth/password",
                {"_user": ["root"]},
                method="POST",
                body={"password": "NewStrongPassword123!"},
            )
            self.assertEqual(status, 403, payload)
            run_mock.assert_not_called()

            status, payload = api.dispatch(
                "/api/auth/password",
                {"_user": ["root"]},
                method="POST",
                body={"current_password": "WrongPassword", "password": "NewStrongPassword123!"},
            )
            self.assertEqual(status, 403, payload)
            ver_mock.assert_called_with("root", "WrongPassword")
            run_mock.assert_not_called()

        with (
            mock.patch.object(api, "verify_system_password", return_value=True) as ver_mock,
            mock.patch.object(api, "run", return_value=mock.Mock(ok=True, stdout="", stderr="", error="")) as run_mock,
        ):
            status, payload = api.dispatch(
                "/api/auth/password",
                {"_user": ["root"]},
                method="POST",
                body={"current_password": "CorrectOldPassword1!", "password": "NewStrongPassword123!"},
            )
            self.assertEqual(status, 200, payload)
            ver_mock.assert_called_once_with("root", "CorrectOldPassword1!")
            run_mock.assert_called_once()

    def test_frontend_password_modal_sends_current_password(self) -> None:
        app_js = (ROOT / "webui" / "frontend" / "app.js").read_text(encoding="utf-8")
        modal_section = app_js.split("function openPasswordModal()", 1)[1].split("/* ═══ Boot ═══ */", 1)[0]
        self.assertIn("currentPass", modal_section)
        self.assertIn("current_password", modal_section)


class RcConfAllowlistTests(unittest.TestCase):
    def test_rcconf_set_blocks_dangerous_keys_and_shell_metachars(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rc = Path(td) / "rc.conf"
            rc.write_text('hostname="gw0.lan"\n', encoding="utf-8")
            with mock.patch("gatebsd_ui.paths.RC_CONF", rc):
                for bad_key in ("sshd_program", "rc_conf_files", "local_startup", "cron_program", "gatebsd_flags"):
                    status, payload = writers.rcconf_set(bad_key, "/tmp/pwn")
                    self.assertEqual(status, 400, f"{bad_key}: {payload}")

                status, payload = writers.rcconf_set("hostname", "gw1; rm -rf /")
                self.assertEqual(status, 400, payload)

                with mock.patch("gatebsd_ui.backup.backup_files", return_value={}):
                    status, payload = writers.rcconf_set("hostname", "gw1.lan")
                    self.assertEqual(status, 200, payload)
                    self.assertIn('hostname="gw1.lan"', rc.read_text(encoding="utf-8"))


class FsutilAndStorageHardlinkSymlinkTests(unittest.TestCase):
    def test_atomic_write_bytes_rejects_swapped_or_hardlinked_tempfile(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "test.conf"
            extra_link = root / "attacker.link"
            real_chmod = os.chmod

            def inject_hardlink(path: object, mode: int) -> None:
                os.link(path, extra_link)
                real_chmod(path, mode)

            with mock.patch("gatebsd_ui.fsutil.os.chmod", side_effect=inject_hardlink):
                with self.assertRaises(OSError):
                    fsutil.atomic_write_bytes(target, b"ok=1\n", mode=0o600, preserve_metadata=False)
            self.assertFalse(target.exists())

    def test_storage_connect_rejects_symlinks_and_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real_db = root / "real.db"
            real_db.write_bytes(b"")

            sym_db = root / "sym.db"
            sym_db.symlink_to(real_db)
            with mock.patch.dict(os.environ, {"GATEBSD_DB_PATH": str(sym_db)}):
                with self.assertRaises(OSError):
                    storage.connect()

            hard_db = root / "hard.db"
            os.link(real_db, hard_db)
            with mock.patch.dict(os.environ, {"GATEBSD_DB_PATH": str(hard_db)}):
                with self.assertRaises(OSError):
                    storage.connect()

            sym_dir = root / "symdir"
            sym_dir.symlink_to(root)
            with mock.patch.dict(os.environ, {"GATEBSD_DB_PATH": str(sym_dir / "state.db")}):
                with self.assertRaises(OSError):
                    storage.connect()

            wal_test_db = root / "wal_test.db"
            Path(f"{wal_test_db}-wal").symlink_to(real_db)
            with mock.patch.dict(os.environ, {"GATEBSD_DB_PATH": str(wal_test_db)}):
                with self.assertRaises(OSError):
                    storage.connect()

            pub_dir = root / "public_db"
            pub_dir.mkdir()
            pub_dir.chmod(0o777)
            with mock.patch.dict(os.environ, {"GATEBSD_DB_PATH": str(pub_dir / "state.db")}):
                with self.assertRaises(OSError):
                    storage.connect()

            svc_dir = root / "svc_db"
            svc_dir.mkdir(mode=0o750)
            svc_uid = os.stat(svc_dir).st_uid
            with mock.patch.dict(os.environ, {"GATEBSD_DB_PATH": str(svc_dir / "state.db")}):
                with (
                    mock.patch("os.geteuid", return_value=0),
                    mock.patch("pwd.getpwnam", return_value=mock.Mock(pw_uid=svc_uid)),
                ):
                    conn = storage.connect()
                    conn.close()
                if svc_uid != 0:
                    with (
                        mock.patch("os.geteuid", return_value=0),
                        mock.patch("pwd.getpwnam", return_value=mock.Mock(pw_uid=svc_uid + 99999)),
                        self.assertRaises(OSError),
                    ):
                        storage.connect()


class VpnAndUpsHardeningTests(unittest.TestCase):
    def test_awg_peer_list_redacts_secrets_and_rejects_symlink_profile(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            conf_dir = Path(td)
            secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            work = conf_dir / "work.conf"
            work.write_text(
                f"[Interface]\nPrivateKey = {secret}\n\n"
                f"[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
                f"PresharedKey = {secret}\nAllowedIPs = 10.0.0.2/32\n",
                encoding="utf-8",
            )
            active = conf_dir / "awg0.conf"
            active.symlink_to(work)
            with (
                mock.patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", conf_dir),
                mock.patch("gatebsd_ui.writers.vpn.AMNEZIA_CONFIG", active),
                mock.patch("gatebsd_ui.writers.vpn.run", return_value=mock.Mock(ok=False, stdout="")),
            ):
                status, payload = writers.awg_peer_list("work")
                self.assertEqual(status, 200, payload)
                peer = payload["peers"][0]
                self.assertNotIn("PresharedKey", peer)
                self.assertNotIn("PrivateKey", peer)
                self.assertTrue(peer.get("has_preshared_key"))

            sym_profile = conf_dir / "evil.conf"
            sym_profile.symlink_to("/etc/passwd")
            with (
                mock.patch("gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", conf_dir),
                mock.patch("gatebsd_ui.writers.vpn.AMNEZIA_CONFIG", active),
            ):
                status, payload = writers.awg_peer_list("evil")
                self.assertGreaterEqual(status, 400, payload)

    def test_mpd_redaction_strips_unquoted_and_key_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mpd_conf = Path(td) / "mpd.conf"
            mpd_conf.write_text(
                'set auth authname "user1"\n'
                'set auth password "quotedsecret"\n'
                'set auth password unquotedsecret\n'
                'set l2tp secret anothersecret\n',
                encoding="utf-8",
            )
            with (
                mock.patch.object(vpn_adapter.paths, "MPD_CONF", mpd_conf, create=True),
                mock.patch.object(vpn_adapter, "_ifconfig_iface", return_value={"raw": "", "state": "down", "addresses": []}),
                mock.patch.object(vpn_adapter, "run", return_value=mock.Mock(ok=False)),
            ):
                data = vpn_adapter.pppoe()
                self.assertTrue(data["config"], "expected mpd.conf lines from paths.MPD_CONF")
                joined = "\n".join(data["config"])
                self.assertNotIn("quotedsecret", joined)
                self.assertNotIn("unquotedsecret", joined)
                self.assertNotIn("anothersecret", joined)

    def test_ups_rejects_leading_dash_and_nul_description(self) -> None:
        with self.assertRaises(ValueError):
            ups_writer._clean_name("-bad", "UPS name")
        with tempfile.TemporaryDirectory() as td:
            with (
                mock.patch.object(ups_writer, "NUT_DIR", Path(td)),
                mock.patch.object(ups_writer, "NUT_CONFIG_LOCK", Path(td) / ".nut.lock"),
                mock.patch.object(ups_writer, "NUT_FILES", (Path(td) / "nut.conf",)),
                mock.patch.object(ups_writer.paths, "RC_CONF", Path(td) / "rc.conf"),
                mock.patch("gatebsd_ui.writers.ups.backup.backup_files", return_value={}),
            ):
                status, payload = ups_writer.configure_ups({
                    "name": "ups",
                    "driver": "usbhid-ups",
                    "port": "/dev/null",
                    "mode": "standalone",
                    "master_user": "upsmon",
                    "client_user": "monuser",
                    "listeners": "127.0.0.1",
                    "low_charge": 20,
                    "low_runtime": 300,
                    "offdelay": 20,
                    "ondelay": 30,
                    "master_password": "ValidPassword123!",
                    "client_password": "ValidPassword456!",
                    "description": "ok\x00evil",
                })
                self.assertEqual(status, 400, payload)
                self.assertIn("description", payload.get("error", ""))


class SystemScriptHardeningTests(unittest.TestCase):
    def test_config_migrate_fixes_system_prefixes_and_skips_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            usr = root / "usr"
            local = usr / "local"
            sbin = local / "sbin"
            leftovers = root / "leftovers"
            ui_dir = root / "ui"
            bin_dir = root / "bin"
            for d in (usr, local, sbin, ui_dir, bin_dir):
                d.mkdir(parents=True)
            usr.chmod(0o775)
            local.chmod(0o775)
            sbin.chmod(0o775)
            stale_pkgsave = sbin / "pkg-static.pkgsave"
            stale_pkgsave.write_text("stale", encoding="utf-8")
            stale_before = sbin / "gatebsd.before-2026"
            stale_before.write_text("stale", encoding="utf-8")

            normal_file = ui_dir / "state.json"
            normal_file.write_text("{}", encoding="utf-8")
            secret_target = root / "secret.txt"
            secret_target.write_text("secret", encoding="utf-8")
            hard_file = ui_dir / "hardlinked.json"
            os.link(secret_target, hard_file)

            calls = root / "calls.txt"
            id_stub = bin_dir / "id"
            id_stub.write_text("#!/bin/sh\necho 0\n", encoding="ascii")
            id_stub.chmod(0o755)
            pw_stub = bin_dir / "pw"
            pw_stub.write_text(
                f"#!/bin/sh\nif [ \"$1\" = usershow ]; then echo \"gatebsd:*:{os.getuid()}:{os.getgid()}::0:0:x:/:/sbin/nologin\"; fi\nexit 0\n",
                encoding="ascii",
            )
            pw_stub.chmod(0o755)
            chown_stub = bin_dir / "chown"
            chown_stub.write_text(f'#!/bin/sh\necho "chown $*" >> "{calls}"\nexit 0\n', encoding="ascii")
            chown_stub.chmod(0o755)
            nginx_stub = bin_dir / "nginx"
            nginx_stub.write_text('#!/bin/sh\n[ "$1" = "-t" ] && exit 0\nexit 1\n', encoding="ascii")
            nginx_stub.chmod(0o755)

            sysctl_conf = root / "sysctl.conf"
            sysctl_conf.write_text("security.bsd.see_other_uids=0\n", encoding="utf-8")
            nginx_conf = root / "gatebsd.conf"
            nginx_conf.write_text(
                "server {\n    listen 10.88.0.1:443 ssl;\n    location /api/ {\n        proxy_pass http://127.0.0.1:8080;\n    }\n}\n",
                encoding="utf-8",
            )
            nginx_bak = root / "nginx-bak"

            env = {
                "PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_MAIN_CONF": str(root / "missing-main.conf"),
                "GATEBSD_FAILOVER_CONF": str(root / "missing-failover.conf"),
                "GATEBSD_SPLIT_DNS_CONF": str(root / "missing-split.conf"),
                "GATEBSD_GATEWAY_CONF": str(root / "missing-gw.conf"),
                "GATEBSD_UNBOUND_CONF": str(root / "missing-unbound.conf"),
                "GATEBSD_UNBOUND_SPLIT_DNS_CONF": str(root / "missing-unbound-split.conf"),
                "GATEBSD_UNBOUND_STATE_DIR": str(root / "missing-unbound-state"),
                "GATEBSD_PF_CONF": str(root / "missing-pf.conf"),
                "GATEBSD_RC_DIR": str(root / "missing-rc"),
                "GATEBSD_NGINX_CONF": str(nginx_conf),
                "GATEBSD_NGINX_BACKUP_DIR": str(nginx_bak),
                "GATEBSD_SYSCTL_CONF": str(sysctl_conf),
                "GATEBSD_LOG_DIR": str(root / "missing-log"),
                "GATEBSD_DB_DIR": str(ui_dir),
                "GATEBSD_UI_DB_DIR": str(ui_dir),
                "GATEBSD_LEGACY_RU_STATE": str(root / "missing-ru"),
                "RU_STATE_FILE": str(root / "missing-ru-new"),
                "GATEBSD_SYSTEM_PREFIXES": f"{usr} {local} {sbin}",
                "GATEBSD_SBIN_LEFTOVERS_DIR": str(leftovers),
                "GATEBSD_SSHD_CONF": str(root / "missing-sshd"),
                "GATEBSD_SSHD_GATEBSD_CONF": str(root / "missing-sshd-dropin"),
                "GATEBSD_SUDOERS_CONF": str(root / "missing-sudoers"),
            }
            res = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-config-migrate")],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(usr.stat().st_mode & 0o777, 0o755)
            self.assertEqual(local.stat().st_mode & 0o777, 0o755)
            self.assertEqual(sbin.stat().st_mode & 0o777, 0o755)
            self.assertFalse(stale_pkgsave.exists())
            self.assertFalse(stale_before.exists())
            self.assertTrue((leftovers / "pkg-static.pkgsave").exists())
            self.assertTrue((leftovers / "gatebsd.before-2026").exists())

            sys_txt = sysctl_conf.read_text(encoding="utf-8")
            self.assertIn("security.bsd.hardlink_check_uid=1", sys_txt)
            self.assertIn("security.bsd.hardlink_check_gid=1", sys_txt)
            nginx_txt = nginx_conf.read_text(encoding="utf-8")
            self.assertIn("location = /api/auth/login", nginx_txt)
            self.assertIn("zone=gatebsd_auth", nginx_txt)

            # Second run must be idempotent (no duplicate directives)
            res2 = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-config-migrate")],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res2.returncode, 0, res2.stderr)
            self.assertEqual(sysctl_conf.read_text(encoding="utf-8").count("hardlink_check_uid=1"), 1)
            self.assertEqual(nginx_conf.read_text(encoding="utf-8").count("location = /api/auth/login"), 1)

            logged = calls.read_text(encoding="utf-8") if calls.exists() else ""
            self.assertIn(f"chown -h", logged)
            self.assertIn(str(normal_file), logged)
            self.assertNotIn(str(hard_file), logged)

    def test_unbound_anchor_migration_accepts_normal_state_dir_nlink(self) -> None:
        migrate_src = (ROOT / "sbin" / "gatebsd-config-migrate").read_text(encoding="utf-8")
        self.assertNotIn('file_links "$_anchor_state"', migrate_src)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "unbound-checkconf").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (bin_dir / "unbound-checkconf").chmod(0o755)
            (bin_dir / "service").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            (bin_dir / "service").chmod(0o755)
            (bin_dir / "su").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (bin_dir / "su").chmod(0o755)
            (bin_dir / "id").write_text("#!/bin/sh\necho 0\n", encoding="utf-8")
            (bin_dir / "id").chmod(0o755)
            (bin_dir / "chown").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (bin_dir / "chown").chmod(0o755)
            # Strip -o/-g ownership flags from install(1) so unprivileged Linux tests exercise apply_unbound_anchor_locked.
            (bin_dir / "install").write_text(
                "#!/bin/sh\n"
                "src=\n"
                "while [ \"$#\" -gt 1 ]; do\n"
                "  case \"$1\" in -o|-g|-m) shift 2;; *) src=$1; shift;; esac\n"
                "done\n"
                "cp \"$src\" \"$1\"\n",
                encoding="utf-8",
            )
            (bin_dir / "install").chmod(0o755)

            conf = root / "unbound.conf"
            conf.write_text("server:\n    username: unbound\n", encoding="utf-8")
            state = root / "state"
            state.mkdir()
            (state / "sub").mkdir()  # Ensure directory st_nlink >= 3 like on FreeBSD UFS/ZFS.
            legacy = root / "legacy-root.key"
            legacy.write_text("seed-anchor\n", encoding="utf-8")

            env = {
                "PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_UNBOUND_CONF": str(conf),
                "GATEBSD_UNBOUND_STATE_DIR": str(state),
                "GATEBSD_UNBOUND_LEGACY_ANCHOR": str(legacy),
            }
            res = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-config-migrate"), "--locked-step", "apply_unbound_anchor_locked"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertNotIn("unexpected hardlinks", res.stderr)
            self.assertEqual((state / "root.key").read_text(encoding="utf-8"), "seed-anchor\n")
            self.assertIn('auto-trust-anchor-file: "/state/root.key"', conf.read_text(encoding="utf-8"))

    def test_agentctl_scopes_upgrade_path_rejects_newlines_and_retires_legacy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            calls = root / "calls.txt"
            for tool in ("id", "service", "pfctl", "pkg", "gatebsd-upgrade"):
                stub = bin_dir / tool
                if tool == "id":
                    stub.write_text("#!/bin/sh\necho 0\n", encoding="ascii")
                elif tool == "pkg":
                    stub.write_text(
                        f'#!/bin/sh\necho "pkg $*" >> "{calls}"\n'
                        'if [ "$1" = info ] && [ "$2" = -e ]; then\n'
                        '  case "$3" in python311|git) exit 0 ;; *) exit 1 ;; esac\n'
                        'fi\nexit 0\n',
                        encoding="ascii",
                    )
                elif tool == "gatebsd-upgrade":
                    stub.write_text(
                        f'#!/bin/sh\necho "gatebsd-upgrade $1 req_hash=${{GATEBSD_REQUIRE_REPO_HASH:-0}}" >> "{calls}"\nexit 0\n',
                        encoding="ascii",
                    )
                else:
                    stub.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{calls}"\nexit 0\n', encoding="ascii")
                stub.chmod(0o755)

            env = {
                "GATEBSD_PATH": f"{bin_dir}:/usr/bin:/bin",
                "PATH": f"{bin_dir}:/usr/bin:/bin",
            }
            # Reject outside fetch dir and nested subdirs
            bad = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-agentctl"), "gatebsd-upgrade", "/var/backups/gatebsd/evil.pkg"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(bad.returncode, 0)
            bad_sub = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-agentctl"), "gatebsd-upgrade", "/var/tmp/sub/gatebsd-2.9.140.pkg"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(bad_sub.returncode, 0)

            # Reject newline injection
            bad_nl = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-agentctl"), "gatebsd-upgrade", "/var/tmp/All/gatebsd-2.9.140.pkg\n--evil"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(bad_nl.returncode, 0)

            # Valid upgrade (both flat fetch dir and All/ subdir) sets GATEBSD_REQUIRE_REPO_HASH=1
            ok_flat = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-agentctl"), "gatebsd-upgrade", "/var/tmp/gatebsd-2.9.140.pkg"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(ok_flat.returncode, 0, ok_flat.stderr)
            self.assertIn("gatebsd-upgrade /var/tmp/gatebsd-2.9.140.pkg req_hash=1", calls.read_text(encoding="utf-8"))

            ok_all = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-agentctl"), "gatebsd-upgrade", "/var/tmp/All/gatebsd-2.9.140.pkg"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(ok_all.returncode, 0, ok_all.stderr)
            self.assertIn("gatebsd-upgrade /var/tmp/All/gatebsd-2.9.140.pkg req_hash=1", calls.read_text(encoding="utf-8"))

            # pkg-retire-legacy removes legacy installed packages
            retire = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-agentctl"), "pkg-retire-legacy"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(retire.returncode, 0, retire.stderr)
            calls_txt = calls.read_text(encoding="utf-8")
            self.assertIn("pkg delete -y python311", calls_txt)
            self.assertIn("pkg delete -y git", calls_txt)

    def test_upgrade_blocks_hardlink_downgrade_repo_hash_mismatch_and_symlink_db_restore(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            lock_dir = root / "run"
            lock_dir.mkdir()
            pkg_file = root / "gatebsd-2.9.135.pkg"
            pkg_file.write_bytes(b"fake-pkg")
            pkg_hash = hashlib.sha256(b"fake-pkg").hexdigest()

            (bin_dir / "id").write_text("#!/bin/sh\necho 0\n", encoding="ascii")
            (bin_dir / "id").chmod(0o755)
            (bin_dir / "install").write_text(
                "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in -d) mkdir=1; shift;; -o|-g|-m) shift 2;; *) target=\"$1\"; shift;; esac; done\n[ -z \"$mkdir\" ] || mkdir -p \"$target\"\nexit 0\n",
                encoding="ascii",
            )
            (bin_dir / "install").chmod(0o755)
            (bin_dir / "stat").write_text(
                "#!/bin/sh\ncase \"$2\" in %u) echo 0 ;; %Lp) echo 644 ;; %z) echo 8 ;; %l) /usr/bin/stat -c '%h' \"$3\" ;; *) /usr/bin/stat \"$@\" ;; esac\n",
                encoding="ascii",
            )
            (bin_dir / "stat").chmod(0o755)
            (bin_dir / "sha256").write_text(f"#!/bin/sh\necho {pkg_hash}\n", encoding="ascii")
            (bin_dir / "sha256").chmod(0o755)
            pkg_stub = bin_dir / "pkg"
            pkg_stub.write_text(
                '#!/bin/sh\n'
                'if [ "$1" = query ] && [ "$2" = -F ]; then\n'
                '  case "$4" in %n) echo gatebsd;; %v) echo 2.9.135;; %o) echo local/gatebsd;; %p) echo /usr/local;; esac; exit 0\n'
                'fi\n'
                'if [ "$1" = query ] && [ "$2" = %v ]; then echo 2.9.136; exit 0; fi\n'
                'if [ "$1" = version ] && [ "$2" = -t ]; then echo "<"; exit 0; fi\n'
                'if [ "$1" = checksum ]; then echo "2$goodcksum ($2)"; exit 0; fi\n'
                'if [ "$1" = rquery ]; then echo "%%{%}2.9.135 2$goodcksum"; exit 0; fi\n'
                'exit 0\n',
                encoding="ascii",
            )
            pkg_stub.chmod(0o755)

            base_env = {
                "GATEBSD_PATH": f"{bin_dir}:/usr/bin:/bin",
                "PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_UPGRADE_LOCK_HELD": "1",
                "GATEBSD_UPGRADE_CONFIG_LOCKS_HELD": "1",
                "GATEBSD_UPGRADE_LOCK": str(lock_dir / "upgrade.lock"),
                "GATEBSD_UPGRADE_BACKUP_ROOT": str(root / "backups"),
                "GATEBSD_UPGRADE_MIN_FREE_KIB": "1",
                "GATEBSD_CONFIG_GUARD": str(root / "no-guard"),
            }

            # Downgrade blocked
            res_down = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-upgrade"), str(pkg_file)],
                env=base_env, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(res_down.returncode, 0)
            self.assertIn("downgrade", res_down.stderr.lower())

            # Hardlink blocked
            hard_pkg = root / "gatebsd-hard.pkg"
            os.link(pkg_file, hard_pkg)
            env_allow_down = dict(base_env, GATEBSD_ALLOW_DOWNGRADE="1")
            res_hard = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-upgrade"), str(hard_pkg)],
                env=env_allow_down, capture_output=True, text=True, check=False,
            )
            hard_pkg.unlink()
            self.assertNotEqual(res_hard.returncode, 0)
            self.assertIn("hardlink", res_hard.stderr.lower())

            # Repo hash mismatch blocked when GATEBSD_REQUIRE_REPO_HASH=1
            pkg_stub.write_text(
                '#!/bin/sh\n'
                'if [ "$1" = query ] && [ "$2" = -F ]; then\n'
                '  case "$4" in %n) echo gatebsd;; %v) echo 2.9.140;; %o) echo local/gatebsd;; %p) echo /usr/local;; esac; exit 0\n'
                'fi\n'
                'if [ "$1" = query ] && [ "$2" = %v ]; then echo 2.9.136; exit 0; fi\n'
                'if [ "$1" = version ] && [ "$2" = -t ]; then echo ">"; exit 0; fi\n'
                'if [ "$1" = checksum ]; then echo "2$goodcksum ($2)"; exit 0; fi\n'
                'if [ "$1" = rquery ]; then echo "%%{%}2.9.140 2$badcksum"; exit 0; fi\n'
                'exit 0\n',
                encoding="ascii",
            )
            env_req = dict(base_env, GATEBSD_REQUIRE_REPO_HASH="1")
            res_hash = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-upgrade"), str(pkg_file)],
                env=env_req, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(res_hash.returncode, 0)
            self.assertIn("checksum", res_hash.stderr.lower())

            upgrade_src = (ROOT / "sbin" / "gatebsd-upgrade").read_text(encoding="utf-8")
            self.assertEqual(upgrade_src.count('GATEBSD_REQUIRE_REPO_HASH="$REQUIRE_REPO_HASH"'), 2)
            self.assertEqual(upgrade_src.count('GATEBSD_ALLOW_DOWNGRADE="$ALLOW_DOWNGRADE"'), 2)
            restore_fn = upgrade_src.split("restore_database() {", 1)[1].split("\n}", 1)[0]
            self.assertLess(restore_fn.index("! -L"), restore_fn.index("install -d"))

    def test_install_does_not_overwrite_symlinked_install_mode_and_collect_avoids_tmp_race(self) -> None:
        install_src = (ROOT / "sbin" / "gatebsd-install").read_text(encoding="utf-8")
        self.assertNotIn("> /var/db/gatebsd/install-mode", install_src)

        collect_src = (ROOT / "sbin" / "gatebsd-collect").read_text(encoding="utf-8")
        self.assertNotIn('rm -f "$ARCHIVE_TMP"', collect_src)
        self.assertIn("[Pp]reshared[Kk]ey", collect_src)
        self.assertIn("[Pp]rivate[Kk]ey", collect_src)
        redact_fn = collect_src.split("redact_stream() {", 1)[1].split("\n}", 1)[0]
        redacted = subprocess.run(
            ["sh", "-c", f"redact_stream() {{{redact_fn}\n}}\nredact_stream"],
            input="PrivateKey = supersecretpriv\nPresharedKey = supersecretpsk\nPassphrase=myphrase\n",
            capture_output=True, text=True, check=True,
        ).stdout
        self.assertNotIn("supersecretpriv", redacted)
        self.assertNotIn("supersecretpsk", redacted)
        self.assertNotIn("myphrase", redacted)

    def test_config_hardening_contracts(self) -> None:
        sysctl = (ROOT / "etc" / "sysctl.conf").read_text(encoding="utf-8")
        self.assertIn("security.bsd.hardlink_check_uid=1", sysctl)
        self.assertIn("security.bsd.hardlink_check_gid=1", sysctl)

        sudoers = (ROOT / "etc" / "sudoers.d" / "gatebsd-agent").read_text(encoding="utf-8")
        self.assertIn("Defaults:gatebsd-agent", sudoers)
        self.assertIn("runcwd=/", sudoers)

        pf = (ROOT / "etc" / "pf.conf.sample").read_text(encoding="utf-8")
        self.assertIn("tag LAN_TO_BACKUP", pf)
        self.assertIn("tagged LAN_TO_BACKUP", pf)
        self.assertLess(pf.index("tagged LAN_TO_BACKUP"), pf.index("pass out quick keep state"))

        limits = (ROOT / "etc" / "nginx" / "gatebsd-limits.conf").read_text(encoding="utf-8")
        self.assertIn("zone=gatebsd_auth", limits)
        ng_site = (ROOT / "etc" / "nginx" / "gatebsd.conf.sample").read_text(encoding="utf-8")
        self.assertIn("gatebsd_auth", ng_site)
        self.assertIn("auth/login", ng_site)

        rc_gatebsd = (ROOT / "rc.d" / "gatebsd").read_text(encoding="utf-8")
        agent_block = rc_gatebsd.split("-m gatebsd_ui.agent", 1)[0].rsplit("env -i", 1)[1]
        self.assertIn('GATEBSD_AUTH_MODE="$gatebsd_auth_mode"', agent_block)


class CiAndStandHardeningTests(unittest.TestCase):
    def test_ci_build_verify_only_never_executes_untrusted_commit_script(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo.git"
            work = root / "seed"
            marker = root / "pwned"
            (work / "infra" / "freebsd-ci").mkdir(parents=True)
            (work / "infra" / "freebsd-ci" / "verify-deployment.sh").write_text(
                f"#!/bin/sh\ntouch {marker}\nexit 1\n", encoding="ascii"
            )
            (work / "infra" / "freebsd-ci" / "deployment.manifest").write_text("", encoding="ascii")
            (work / "infra" / "freebsd-ci" / "packages.list").write_text("", encoding="ascii")
            (work / "infra" / "freebsd-ci" / "deployment.scan").write_text("", encoding="ascii")
            subprocess.run(["git", "init", str(work)], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "config", "user.email", "t@t"], check=True)
            subprocess.run(["git", "-C", str(work), "config", "user.name", "t"], check=True)
            subprocess.run(["git", "-C", str(work), "add", "."], check=True)
            subprocess.run(["git", "-C", str(work), "commit", "-m", "init"], check=True, capture_output=True)
            sha = subprocess.check_output(["git", "-C", str(work), "rev-parse", "HEAD"], text=True).strip()
            subprocess.run(["git", "clone", "--bare", str(work), str(repo)], check=True, capture_output=True)

            trusted_verify = root / "trusted-verify.sh"
            called = root / "trusted-called"
            trusted_verify.write_text(
                f'#!/bin/sh\necho "$GATEBSD_REPO_DIR" > "{called}"\nexit 0\n', encoding="ascii"
            )
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "id").write_text("#!/bin/sh\necho 0\n", encoding="ascii")
            (bin_dir / "id").chmod(0o755)
            env = {
                "PATH": "/usr/bin:/bin",
                "GATEBSD_ALLOW_TEST_PATH": "1",
                "GATEBSD_TEST_PATH_PREFIX": str(bin_dir),
                "GATEBSD_FORGEJO_REPOSITORY": str(repo),
                "GATEBSD_VERIFY_DEPLOYMENT": str(trusted_verify),
            }
            res = subprocess.run(
                ["sh", str(ROOT / "ci" / "host" / "gatebsd-ci-build"), "--verify-only", sha],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertFalse(marker.exists(), "untrusted commit verify-deployment.sh executed!")
            self.assertTrue(called.exists())

        ci_src = (ROOT / "ci" / "host" / "gatebsd-ci-build").read_text(encoding="utf-8")
        self.assertNotIn("tar -xpf", ci_src)
        build_section = ci_src.split("build_and_verify_in_jail()", 1)[1]
        self.assertGreater(
            build_section.index('install -o root -g www -m 0644 "$PACKAGE" "$ARTIFACT_DIR/"'),
            build_section.index("jail -r"),
        )

    def test_ci_dashboard_validates_repo_slug(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "forgejo.db"
            conn = sqlite3.connect(db_path)
            conn.close()

            bad_owner = subprocess.run(
                ["sh", str(ROOT / "infra" / "freebsd-ci" / "ci-dashboard-update.sh")],
                env={"FORGEJO_DB": str(db_path), "REPO_SLUG": "bad'slug/repo"},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(bad_owner.returncode, 2, bad_owner.stderr)
            self.assertIn("Invalid repository owner in REPO_SLUG", bad_owner.stderr)

            bad_name = subprocess.run(
                ["sh", str(ROOT / "infra" / "freebsd-ci" / "ci-dashboard-update.sh")],
                env={"FORGEJO_DB": str(db_path), "REPO_SLUG": "owner/bad/extra"},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(bad_name.returncode, 2, bad_name.stderr)
            self.assertIn("Invalid repository name in REPO_SLUG", bad_name.stderr)

            bad_project = subprocess.run(
                ["sh", str(ROOT / "infra" / "freebsd-ci" / "ci-dashboard-update.sh")],
                env={"FORGEJO_DB": str(db_path), "PROJECT_SLUG": "bad slug"},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(bad_project.returncode, 2, bad_project.stderr)
            self.assertIn("PROJECT_SLUG", bad_project.stderr)

    @unittest.skipUnless(shutil.which("sqlite3"), "the sqlite3 command line tool is required")
    def test_ci_dashboard_escapes_html_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_path = root / "forgejo.db"
            conn = sqlite3.connect(db_path)
            conn.executescript(
                """
                CREATE TABLE `user` (id INTEGER PRIMARY KEY, lower_name TEXT);
                CREATE TABLE repository (id INTEGER PRIMARY KEY, owner_id INTEGER, lower_name TEXT);
                CREATE TABLE action_run (id INTEGER PRIMARY KEY, repo_id INTEGER, `index` INTEGER, status INTEGER, event TEXT, ref TEXT, commit_sha TEXT, started INTEGER, stopped INTEGER, title TEXT);
                CREATE TABLE action_run_job (id INTEGER PRIMARY KEY, run_id INTEGER, name TEXT, status INTEGER, started INTEGER, stopped INTEGER, task_id INTEGER);
                CREATE TABLE action_task (id INTEGER PRIMARY KEY, log_filename TEXT);
                CREATE TABLE action_runner (name TEXT, version TEXT, last_online INTEGER);
                INSERT INTO `user` VALUES (1, 'owner');
                INSERT INTO repository VALUES (1, 1, 'gatebsd');
                INSERT INTO action_run VALUES (1, 1, 1, 1, 'push', 'refs/heads/feat"><img src=x>', '0123456789abcdef0123456789abcdef01234567', 1700000000, 1700000010, 'msg');
                INSERT INTO action_run_job VALUES (1, 1, 'job', 1, 1700000000, 1700000010, 0);
                """
            )
            conn.commit()
            conn.close()

            rel_root = root / "releases"
            (rel_root / "versions").mkdir(parents=True)
            (rel_root / "builds" / '20261115T000000Z-0123456789ab').mkdir(parents=True)
            (rel_root / "versions" / '2.9.<img').symlink_to('../builds/20261115T000000Z-0123456789ab')
            out_dir = root / "www" / "ci"

            env = {
                "FORGEJO_DB": str(db_path),
                "RELEASE_ROOT": str(rel_root),
                "ARTIFACT_ROOT": str(root / "artifacts"),
                "STATUS_DIR": str(root / "status"),
                "OUT_DIR": str(out_dir),
                "TEMPLATE_DIR": str(ROOT / "infra" / "freebsd-ci"),
                "SQLITE3": shutil.which("sqlite3") or "sqlite3",
            }
            ok = subprocess.run(
                ["sh", str(ROOT / "infra" / "freebsd-ci" / "ci-dashboard-update.sh")],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(ok.returncode, 0, ok.stderr)
            html = (out_dir / "index.html").read_text(encoding="utf-8")
            self.assertNotIn("<img src=x>", html)
            self.assertNotIn('">2.9.<img', html)
            status_obj = json.loads((out_dir / "status.json").read_text(encoding="utf-8"))
            self.assertEqual(len(status_obj["runs"]), 1)

    def test_mirror_and_backup_hardening_and_deployment_contracts(self) -> None:
        sync_src = (ROOT / "infra" / "freebsd-ci" / "mirror-sync-freebsd-15-amd64.sh").read_text(encoding="utf-8")
        self.assertIn("--safe-links", sync_src)
        self.assertIn("! -L", sync_src)

        pub_src = (ROOT / "infra" / "freebsd-ci" / "mirror-publish-release.sh").read_text(encoding="utf-8")
        self.assertIn("! -L", pub_src)

        backup_src = (ROOT / "infra" / "forgejo" / "backup.sh").read_text(encoding="utf-8")
        self.assertLess(backup_src.index("*[!A-Za-z0-9_./-]*"), backup_src.index("--file '$stage_dump'"))
        self.assertIn("_dump_links", backup_src)

        git_sync = (ROOT / "infra" / "freebsd-ci" / "mirror-sync-git.sh").read_text(encoding="utf-8")
        self.assertIn("refs/heads/2026Q4", git_sync)

        manifest = (ROOT / "infra" / "freebsd-ci" / "deployment.manifest").read_text(encoding="utf-8")
        for script_name in ("verify-deployment.sh", "leftovers.sh", "retire-leftovers.sh", "deployment.scan"):
            self.assertIn(f"infra/freebsd-ci/{script_name}", manifest)

        scan = (ROOT / "infra" / "freebsd-ci" / "deployment.scan").read_text(encoding="utf-8")
        self.assertIn("/usr/local/share/gatebsd/ports-overlay", scan)


class PostRebootBootAndLogRegressionTests(unittest.TestCase):
    def test_ru_bypass_worker_launch_uses_resolved_script_not_etc_rc(self) -> None:
        rc_path = ROOT / "rc.d" / "ru_bypass"
        rc_src = rc_path.read_text(encoding="utf-8")
        self.assertIn('RU_BYPASS_SCRIPT=${GATEBSD_RU_BYPASS_SCRIPT:-${_file:-$0}}', rc_src)
        self.assertIn('*) RU_BYPASS_SCRIPT=/usr/local/etc/rc.d/ru_bypass ;;', rc_src)
        self.assertIn('/bin/sh "$RU_BYPASS_SCRIPT" __ru-worker apply', rc_src)
        self.assertIn('/bin/sh "$RU_BYPASS_SCRIPT" __ru-worker clear', rc_src)
        self.assertNotIn('"$0" __ru-worker', rc_src)

        # Simulate `/etc/rc` sourcing `/usr/local/etc/rc.d/ru_bypass` via `. $_file` (`$0=/etc/rc`).
        resolve_snippet = "\n".join(
            [
                "RU_BYPASS_SCRIPT=${GATEBSD_RU_BYPASS_SCRIPT:-${_file:-$0}}",
                'case "$RU_BYPASS_SCRIPT" in',
                "    *ru_bypass*) ;;",
                "    *) RU_BYPASS_SCRIPT=/usr/local/etc/rc.d/ru_bypass ;;",
                "esac",
                'printf "%s\\n" "$RU_BYPASS_SCRIPT"',
            ]
        )
        sourced = subprocess.run(
            ["/bin/sh", "-c", f'_file=/usr/local/etc/rc.d/ru_bypass\n{resolve_snippet}', "/etc/rc"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(sourced.returncode, 0, sourced.stderr)
        self.assertEqual(sourced.stdout.strip(), "/usr/local/etc/rc.d/ru_bypass")

        fallback = subprocess.run(
            ["/bin/sh", "-c", resolve_snippet, "/etc/rc"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(fallback.returncode, 0, fallback.stderr)
        self.assertEqual(fallback.stdout.strip(), "/usr/local/etc/rc.d/ru_bypass")

    def test_watchdog_defers_on_lock_contention_75_without_error_logs(self) -> None:
        state_reader = ROOT / "sbin" / "gatebsd-state-value"
        watchdog_sh = ROOT / "sbin" / "gatebsd-watchdog.sh"

        def run_case(*, default_if: str, check_rc: int, op_rc: int) -> tuple[str, str]:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                bin_dir = root / "bin"
                run_dir = root / "run"
                db_dir = root / "db"
                fib_dir = root / "fibs"
                for d in (bin_dir, run_dir, db_dir, fib_dir):
                    d.mkdir(parents=True)
                    d.chmod(0o750)
                calls = root / "calls.log"
                log_path = root / "watchdog.log"
                conf = root / "failover.conf"
                ru_table = root / "ru.table"
                ru_table.write_text("1.2.3.0/24\n", encoding="ascii")
                conf.write_text(
                    "\n".join(
                        [
                            'PRIMARY_IF="ng0"',
                            'BACKUP_IF="ue0"',
                            'VPN_IF="awg0"',
                            'FAILOVER_MODE="automatic"',
                            'CHECK_TARGETS="198.51.100.1"',
                            'RU_CHECK_TARGETS="77.88.8.8"',
                            'CHECK_TCP_PORT="443"',
                            'PRIMARY_FIB="1"',
                            'BACKUP_FIB="2"',
                            'FAIL_THRESHOLD="1"',
                            'RECOVERY_THRESHOLD="1"',
                            'MIN_BACKUP_HOLD="0"',
                            'SWITCH_COOLDOWN="0"',
                            'CHECK_INTERVAL="0"',
                            'PING_TIMEOUT="1"',
                            'VPN_HANDSHAKE_MAX="180"',
                            'VPN_NET_FAIL_THRESHOLD="1"',
                            "",
                        ]
                    ),
                    encoding="ascii",
                )
                conf.chmod(0o600)

                (bin_dir / "ifconfig").write_text(
                    """#!/bin/sh
case "$1" in
  ng0) echo "ng0: flags=88d1<UP,POINTOPOINT,RUNNING> mtu 1492"; echo "	inet 203.0.113.9 --> 192.0.2.1 netmask 0xffffffff" ;;
  awg0) echo "awg0: flags=80c1<UP,RUNNING> mtu 1420" ;;
  *) exit 1 ;;
esac
""",
                    encoding="ascii",
                )
                (bin_dir / "route").write_text(
                    f"""#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in -n|-q|-v|-d|-4|-6|-t) shift ;; *) break ;; esac
done
if [ "${{1:-}}" = get ]; then
  echo "    gateway: 192.0.2.1"
  echo "  interface: {default_if}"
  exit 0
fi
exit 0
""",
                    encoding="ascii",
                )
                (bin_dir / "ping").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
                (bin_dir / "nc").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
                (bin_dir / "setfib").write_text('#!/bin/sh\nshift\nexec "$@"\n', encoding="ascii")
                (bin_dir / "sysctl").write_text('#!/bin/sh\necho 3\n', encoding="ascii")
                (bin_dir / "awg").write_text("#!/bin/sh\nnow=$(date +%s)\nprintf 'peer\\t%s\\n' \"$((now - 5))\"\n", encoding="ascii")
                (bin_dir / "service").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
                (bin_dir / "gatewayctl").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
                (bin_dir / "logger").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
                (bin_dir / "ru-routes.sh").write_text(
                    f'#!/bin/sh\necho "ru-routes $*" >> "{calls}"\n[ "${{1:-}}" = check ] && exit {check_rc}\nexit 0\n',
                    encoding="ascii",
                )
                (bin_dir / "gatebsd-route-op").write_text(
                    f'#!/bin/sh\necho "route-op $*" >> "{calls}"\nexit {op_rc}\n',
                    encoding="ascii",
                )
                (bin_dir / "stat").write_text(
                    """#!/bin/sh
if [ "$1" = -f ]; then
  fmt=$2; shift 2
  case "$fmt" in '%u') echo 0; exit 0 ;; '%Lp') exec /usr/bin/stat -c '%a' "$@" ;; *) exit 2 ;; esac
fi
exec /usr/bin/stat "$@"
""",
                    encoding="ascii",
                )
                (bin_dir / "lockf").write_text(
                    '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do case "$1" in -t) shift 2 ;; -k|-s|-n|-w|-T) shift ;; --) shift; break ;; -*) shift ;; *) break ;; esac; done\nshift\nexec "$@"\n',
                    encoding="ascii",
                )
                (bin_dir / "install").write_text(
                    '#!/bin/sh\ndir=0; mode=0755\nwhile [ "$#" -gt 0 ]; do case "$1" in -d) dir=1; shift ;; -o|-g) shift 2 ;; -m) mode=$2; shift 2 ;; *) break ;; esac; done\nif [ "$dir" = 1 ]; then for d in "$@"; do mkdir -p "$d" && chmod "$mode" "$d"; done; exit 0; fi\nexec /usr/bin/install "$@"\n',
                    encoding="ascii",
                )
                (bin_dir / "sleep").write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
                for p in bin_dir.iterdir():
                    p.chmod(0o755)
                for tool in ("mktemp", "date", "cat", "awk", "sed", "cmp", "sort", "id", "ps", "kill", "grep", "rm", "chmod", "mv", "head", "tr", "df"):
                    real = shutil.which(tool)
                    if real and not (bin_dir / tool).exists():
                        (bin_dir / tool).symlink_to(real)

                env = {
                    "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin",
                    "GATEBSD_FAILOVER_CONF": str(conf),
                    "GATEBSD_RUN_DIR": str(run_dir),
                    "GATEBSD_SERVICE_GROUP": "wheel",
                    "GATEBSD_ALLOW_TEST_RUN_DIR": "1",
                    "GATEBSD_WATCHDOG_STATE": str(run_dir / "watchdog.json"),
                    "GATEBSD_VPN_DISABLED_FLAG": str(db_dir / "vpn_disabled"),
                    "GATEBSD_ROUTE_HELPER": str(bin_dir / "gatebsd-route-op"),
                    "GATEBSD_STATE_READER": str(state_reader),
                    "GATEBSD_PYTHON_LAUNCHER": sys.executable,
                    "GATEBSD_RU_ROUTES_HELPER": str(bin_dir / "ru-routes.sh"),
                    "GATEBSD_DHCLIENT_LEASE_DIR": str(db_dir),
                    "RU_TABLE": str(ru_table),
                    "RU_STATE_FILE": str(db_dir / "ru-routes.applied"),
                    "EVENT_LOG": str(log_path),
                    "HOME": str(root),
                    "LANG": "C",
                }
                res = subprocess.run(["sh", str(watchdog_sh)], env=env, capture_output=True, text=True, timeout=20, check=False)
                self.assertEqual(res.returncode, 1, res.stderr)
                return log_path.read_text(encoding="utf-8"), calls.read_text(encoding="utf-8") if calls.exists() else ""

        # Startup VPN restore deferred on 75 without false ERROR
        vpn_log, _ = run_case(default_if="ng0", check_rc=0, op_rc=75)
        self.assertIn("gateway lock is held by another operation; deferring startup VPN restore", vpn_log)
        self.assertNotIn("ERROR: failed to restore VPN route transaction", vpn_log)

        # RU check returning 75 skips competing ru-apply and logs no ERROR
        check_busy_log, check_busy_calls = run_case(default_if="awg0", check_rc=75, op_rc=0)
        self.assertIn("gateway lock is held by another operation; deferring startup RU bypass check", check_busy_log)
        self.assertNotIn("ru-apply", check_busy_calls)
        self.assertNotIn("ERROR: RU route convergence failed", check_busy_log)

        # RU apply returning 75 defers cleanly on both startup and tick
        apply_busy_log, _ = run_case(default_if="awg0", check_rc=1, op_rc=75)
        self.assertIn("gateway lock is held by another operation; deferring startup RU bypass apply", apply_busy_log)
        self.assertIn("gateway lock is held by another operation; deferring RU route convergence", apply_busy_log)
        self.assertNotIn("ERROR: RU route convergence failed", apply_busy_log)

        # Real failure (rc=1) still logs ERROR
        real_err_log, _ = run_case(default_if="awg0", check_rc=1, op_rc=1)
        self.assertIn("ERROR: RU route convergence failed", real_err_log)

    def test_config_migrate_prunes_retired_failover_keys(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "id").write_text("#!/bin/sh\necho 0\n", encoding="ascii")
            (bin_dir / "chown").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            (bin_dir / "stat").write_text(
                """#!/bin/sh
set -eu
case "$1" in
  -c)
    fmt=$2; path=$3
    case "$fmt" in
      %u) echo 0 ;;
      *) exec /usr/bin/stat "$@" ;;
    esac
    ;;
  -f)
    fmt=$2; path=$3
    case "$fmt" in
      %u) echo 0 ;;
      %Lp) /usr/bin/stat -c %a "$path" ;;
      %l) /usr/bin/stat -c %h "$path" ;;
      *) exit 2 ;;
    esac
    ;;
esac
""",
                encoding="ascii",
            )
            for p in bin_dir.iterdir():
                p.chmod(0o755)

            failover = root / "failover.conf"
            failover.write_text(
                "\n".join(
                    [
                        'FAILOVER_MODE="automatic"',
                        'PRIMARY_IF="ng0"',
                        'STATE_FILE="/tmp/x"',
                        'LOCK_FILE="/tmp/y"',
                        'VPN_FAILURE_POLICY="open"',
                        'CHECK_INTERVAL="10"',
                        "",
                    ]
                ),
                encoding="ascii",
            )
            failover.chmod(0o644)

            env = {
                "PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_MAIN_CONF": str(root / "missing-main.conf"),
                "GATEBSD_FAILOVER_CONF": str(failover),
                "GATEBSD_SPLIT_DNS_CONF": str(root / "missing-split.conf"),
                "GATEBSD_GATEWAY_CONF": str(root / "missing-gw.conf"),
                "GATEBSD_UNBOUND_CONF": str(root / "missing-unbound.conf"),
                "GATEBSD_UNBOUND_SPLIT_DNS_CONF": str(root / "missing-unbound-split.conf"),
                "GATEBSD_UNBOUND_STATE_DIR": str(root / "missing-unbound-state"),
                "GATEBSD_PF_CONF": str(root / "missing-pf.conf"),
                "GATEBSD_RC_DIR": str(root / "missing-rc"),
                "GATEBSD_NGINX_CONF": str(root / "missing-nginx.conf"),
                "GATEBSD_NGINX_BACKUP_DIR": str(root / "nginx-bak"),
                "GATEBSD_SYSCTL_CONF": str(root / "missing-sysctl.conf"),
                "GATEBSD_LOG_DIR": str(root / "missing-log"),
                "GATEBSD_DB_DIR": str(root / "missing-db"),
                "GATEBSD_UI_DB_DIR": str(root / "missing-ui-db"),
                "GATEBSD_LEGACY_RU_STATE": str(root / "missing-ru"),
                "RU_STATE_FILE": str(root / "missing-ru-new"),
                "GATEBSD_SYSTEM_PREFIXES": "",
                "GATEBSD_SSHD_CONF": str(root / "missing-sshd"),
                "GATEBSD_SSHD_GATEBSD_CONF": str(root / "missing-sshd-dropin"),
                "GATEBSD_SUDOERS_CONF": str(root / "missing-sudoers"),
            }
            res = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-config-migrate")],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(failover.stat().st_mode & 0o777, 0o600)
            migrated = failover.read_text(encoding="ascii")
            self.assertIn('FAILOVER_MODE="automatic"', migrated)
            self.assertIn('PRIMARY_IF="ng0"', migrated)
            self.assertIn('CHECK_INTERVAL="10"', migrated)
            self.assertNotIn("STATE_FILE=", migrated)
            self.assertNotIn("LOCK_FILE=", migrated)
            self.assertNotIn("VPN_FAILURE_POLICY=", migrated)

            res2 = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-config-migrate")],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res2.returncode, 0, res2.stderr)
            self.assertEqual(failover.read_text(encoding="ascii"), migrated)

    def test_firewall_adapter_uses_quiet_dhcpd_syntax_check(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dhcp_conf = root / "dhcpd.conf"
            dhcp_conf.write_text("subnet 10.88.0.0 netmask 255.255.255.0 {}\n", encoding="utf-8")
            with (
                mock.patch.object(firewall_adapter, "DHCPD_CONF", dhcp_conf),
                mock.patch.object(firewall_adapter, "DHCPD_LEASES", root / "missing.leases"),
                mock.patch.object(firewall_adapter, "UNBOUND_CONF", root / "missing-unbound.conf"),
                mock.patch.object(
                    firewall_adapter,
                    "run",
                    return_value=SimpleNamespace(returncode=0, stdout="", stderr=""),
                ) as run_mock,
            ):
                payload = firewall_adapter.dhcpd()
            run_mock.assert_called_once_with(
                ["/usr/local/sbin/dhcpd", "-q", "-t", "-cf", str(dhcp_conf)],
                timeout=5,
            )
            self.assertEqual(payload["syntax"], "OK (dhcpd -q -t)")

            with (
                mock.patch.object(firewall_adapter, "DHCPD_CONF", dhcp_conf),
                mock.patch.object(firewall_adapter, "DHCPD_LEASES", root / "missing.leases"),
                mock.patch.object(firewall_adapter, "UNBOUND_CONF", root / "missing-unbound.conf"),
                mock.patch.object(
                    firewall_adapter,
                    "run",
                    return_value=SimpleNamespace(returncode=1, stdout="", stderr="line 1: semicolon expected."),
                ),
            ):
                err_payload = firewall_adapter.dhcpd()
            self.assertIn("ERROR (exit 1):", err_payload["syntax"])
            self.assertIn("semicolon expected.", err_payload["syntax"])

            from gatebsd_ui import backup as backup_mod, paths as paths_mod
            from gatebsd_ui.writers import dhcp as dhcp_writer

            self.assertEqual(backup_mod._restore_validator(paths_mod.DHCPD_CONF), ["dhcpd", "-q", "-t", "-cf"])
            with mock.patch.object(
                dhcp_writer,
                "run",
                return_value=SimpleNamespace(ok=True, stdout="", stderr="", error=""),
            ) as writer_run:
                ok, _ = dhcp_writer._validate_candidate("authoritative;\n", root)
            self.assertTrue(ok)
            self.assertEqual(writer_run.call_args[0][0][:3], ["/usr/local/sbin/dhcpd", "-q", "-t"])

            guard_bin = root / "guard-bin"
            guard_bin.mkdir()
            guard_calls = root / "guard-calls.log"
            (guard_bin / "dhcpd").write_text(
                f'#!/bin/sh\necho "$*" >> "{guard_calls}"\nexit 0\n',
                encoding="ascii",
            )
            (guard_bin / "sysrc").write_text("#!/bin/sh\necho NO\n", encoding="ascii")
            for p in guard_bin.iterdir():
                p.chmod(0o755)
            guard_res = subprocess.run(
                ["sh", str(ROOT / "sbin" / "gatebsd-config-guard")],
                env={
                    "PATH": f"{guard_bin}:/usr/bin:/bin",
                    "GATEBSD_PATH": f"{guard_bin}:/usr/bin:/bin",
                    "GATEBSD_KNOWN_GOOD_DIR": str(root / "known-good"),
                    "GATEBSD_PF_CONF": str(root / "absent-pf.conf"),
                    "GATEBSD_UNBOUND_CONF": str(root / "absent-unbound.conf"),
                    "GATEBSD_DHCPD_CONF": str(dhcp_conf),
                    "GATEBSD_NGINX_CONF": str(root / "absent-nginx.conf"),
                    "GATEBSD_UPS_BOOTSTRAP": str(root / "absent-ups-bootstrap"),
                    "HOME": str(root),
                    "LANG": "C",
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(guard_res.returncode, 0, guard_res.stderr)
            self.assertEqual(guard_calls.read_text(encoding="utf-8").strip(), f"-q -t -cf {dhcp_conf}")


if __name__ == "__main__":
    unittest.main()
