#!/usr/bin/env python3
"""Public TLS status and renewal results must never expose the DuckDNS token."""
from __future__ import annotations

import json
from datetime import datetime
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "webui" / "backend"))

from gatebsd_ui import agent, api, tls  # noqa: E402


class TlsStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.cert = root / "fullchain.pem"
        self.cert.write_text("fixture", encoding="ascii")
        self.log = root / "renew.log"
        self.log.write_text(
            "2026-11-01 02:17:01 certificate for gateway.duckdns.org renewed and nginx reloaded\n"
            "2026-11-05 02:17:02 ERROR: acme.sh issuance failed; the existing certificate is unchanged\n"
            "token=secret-value\n",
            encoding="utf-8",
        )
        self.cron = root / "cron"
        self.cron.write_text("17 2 * * * root /usr/local/sbin/gatebsd-renew-ssl\n", encoding="ascii")
        self.script = root / "renew"
        self.script.write_text("fixture", encoding="ascii")
        self.script.chmod(0o755)
        self.renew_ok = True
        self.paths = (
            patch.object(tls, "CERTIFICATE", self.cert),
            patch.object(tls, "LOG_FILE", self.log),
            patch.object(tls, "CRON_FILE", self.cron),
            patch.object(tls, "RENEW_SCRIPT", self.script),
            patch.object(tls.time, "time", return_value=1793980000),
        )
        for item in self.paths:
            item.start()
            self.addCleanup(item.stop)

    def fake_run(self, command, **_kwargs):
        if command[0] == "openssl":
            return SimpleNamespace(
                ok=True,
                stdout=(
                    "notAfter=Feb  4 01:02:03 2027 GMT\n"
                    "X509v3 Subject Alternative Name:\n"
                    "    DNS:gateway.duckdns.org, DNS:gateway.example\n"
                ),
                stderr="", error=None,
            )
        if command == [str(self.script)]:
            return SimpleNamespace(
                ok=self.renew_ok, stdout="",
                stderr="previous files restored" if not self.renew_ok else "", error=None,
            )
        raise AssertionError(command)

    def test_status_has_public_certificate_and_renewal_times(self) -> None:
        with patch.object(tls, "run", self.fake_run):
            payload = tls.status()
        self.assertTrue(payload["available"])
        self.assertEqual(payload["san"], ["gateway.duckdns.org", "gateway.example"])
        expected = int(datetime.strptime("2026-11-01 02:17:01", "%Y-%m-%d %H:%M:%S").timestamp())
        self.assertEqual(payload["last_success_at"], expected)
        self.assertEqual(payload["last_error"]["message"], "acme.sh issuance failed; the existing certificate is unchanged")
        self.assertGreater(payload["next_attempt"], 1793980000)
        self.assertNotIn("secret-value", json.dumps(payload))

    def test_renewal_result_reports_rollback_without_secret_output(self) -> None:
        self.renew_ok = False
        with patch.object(tls, "run", self.fake_run):
            status, payload = tls.renew()
        self.assertEqual(status, 500)
        self.assertFalse(payload["renewal"]["ok"])
        self.assertTrue(payload["renewal"]["rolled_back"])
        self.assertNotIn("secret-value", json.dumps(payload))

    def test_dispatch_and_agent_allow_status_and_renewal(self) -> None:
        with patch.object(tls, "run", self.fake_run):
            get_status, _ = api.dispatch("/api/tls/status", {})
            post_status, payload = api.dispatch("/api/tls/renew", {}, method="POST", body={})
        self.assertEqual(get_status, 200)
        self.assertEqual(post_status, 200)
        self.assertTrue(payload["renewal"]["ok"])
        self.assertTrue(agent._agent_allowed("GET", "/api/tls/status"))
        self.assertTrue(agent._agent_allowed("POST", "/api/tls/renew"))


@unittest.skipUnless(shutil.which("openssl"), "openssl is required for a real certificate")
class RealCertificateTests(unittest.TestCase):
    def test_status_parses_an_actual_x509_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "key.pem"
            cert = root / "fullchain.pem"
            subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", str(key)], check=True)
            subprocess.run([
                "openssl", "req", "-x509", "-new", "-key", str(key), "-days", "30",
                "-subj", "/CN=gateway.duckdns.org",
                "-addext", "subjectAltName=DNS:gateway.duckdns.org,DNS:gateway.example",
                "-out", str(cert),
            ], check=True)
            with patch.object(tls, "CERTIFICATE", cert), \
                    patch.object(tls, "LOG_FILE", root / "missing-log"), \
                    patch.object(tls, "CRON_FILE", root / "missing-cron"):
                payload = tls.status()
        self.assertTrue(payload["available"], payload)
        self.assertEqual(payload["san"], ["gateway.duckdns.org", "gateway.example"])
        self.assertGreater(payload["days_remaining"], 0)


if __name__ == "__main__":
    unittest.main()
