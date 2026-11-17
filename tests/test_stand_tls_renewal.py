"""The stand's TLS leaf must renew itself, and must refuse a bad renewal.

nginx serves Forgejo and the mirror with one ~30-day certificate from the local
step-ca. Nothing renewed it: it was minted by hand and trusted by hand, so the
pipeline died in July when it lapsed and was set to die again on 2026-08-29.

The dangerous half is not the renewal, it is everything that can go wrong
during one. A stand serving an expiring certificate still works; a stand
serving a certificate that does not match its key, or that nginx refuses,
locks out the pipeline that would fix it. So these tests RUN the script with a
stubbed `step` and assert on what ends up in place -- including the cases where
the right answer is "leave the old certificate alone".
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "infra" / "freebsd-ci" / "renew-stand-tls.sh"
OPENSSL = shutil.which("openssl")


def _openssl(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run([OPENSSL, *args], capture_output=True, text=True, check=True, **kwargs)


@unittest.skipUnless(OPENSSL, "the script validates certificates with openssl")
class StandTlsRenewalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)
        self.cert = self.dir / "server.crt"
        self.key = self.dir / "server.key"
        self.ca_root = self.dir / "root_ca.crt"
        self.log = self.dir / "calls.txt"

        # A real key and a real short-lived certificate: the script compares
        # public keys and expiry dates, so fixtures have to be genuine.
        _openssl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", str(self.key))
        self._issue(self.cert, days=20)
        _openssl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", str(self.dir / "other.key"))
        self.ca_root.write_text(self.cert.read_text(encoding="utf-8"), encoding="utf-8")

    def _issue(self, out: Path, days: int, key: Path | None = None) -> None:
        _openssl(
            "req", "-x509", "-new", "-key", str(key or self.key),
            "-subj", "/CN=buildhost.example.lan", "-days", str(days), "-out", str(out),
        )

    def _stub_step(self, body: str) -> Path:
        stub = self.dir / "step"
        stub.write_text(f"#!/bin/sh\necho \"step $*\" >> {self.log}\n{body}\n", encoding="utf-8")
        stub.chmod(0o755)
        return stub

    def _run(self, nginx_ok: bool = True, expires_in: str = "360h") -> subprocess.CompletedProcess:
        nginx = self.dir / "nginx"
        nginx.write_text(
            f"#!/bin/sh\necho \"nginx $*\" >> {self.log}\nexit {0 if nginx_ok else 1}\n",
            encoding="utf-8",
        )
        nginx.chmod(0o755)
        reload_stub = self.dir / "reload"
        reload_stub.write_text(f"#!/bin/sh\necho reload >> {self.log}\n", encoding="utf-8")
        reload_stub.chmod(0o755)

        environment = dict(os.environ)
        environment.update({
            "STAND_TLS_CERT": str(self.cert),
            "STAND_TLS_KEY": str(self.key),
            "STAND_TLS_CA_ROOT": str(self.ca_root),
            "STAND_TLS_STEP": str(self.dir / "step"),
            "STAND_TLS_OPENSSL": OPENSSL,
            "STAND_TLS_NGINX": str(nginx),
            "STAND_TLS_RELOAD": str(reload_stub),
            "STAND_TLS_EXPIRES_IN": expires_in,
        })
        return subprocess.run(
            ["sh", str(SCRIPT)], env=environment, capture_output=True, text=True, timeout=60,
        )

    def _expiry(self, path: Path) -> str:
        return _openssl("x509", "-in", str(path), "-noout", "-enddate").stdout.strip()

    def _calls(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""

    # ---------------------------------------------------------------- happy path
    def test_a_valid_renewal_is_installed_and_nginx_reloaded(self) -> None:
        self._stub_step(
            f'for a in "$@"; do case "$prev" in --out) out=$a;; esac; prev=$a; done\n'
            f'{OPENSSL} req -x509 -new -key {self.key} -subj /CN=buildhost.example.lan -days 90 -out "$out" 2>/dev/null'
        )
        before = self._expiry(self.cert)
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotEqual(self._expiry(self.cert), before, "the certificate was not replaced")
        self.assertIn("reload", self._calls())

    def test_outside_the_window_nothing_happens(self) -> None:
        """step writes no output when it is not due; that is success, not failure."""
        self._stub_step("exit 0")
        before = self._expiry(self.cert)
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self._expiry(self.cert), before)
        self.assertNotIn("reload", self._calls())
        self.assertIn("not due for renewal", result.stdout)

    # ---------------------------------------------------------------- refusals
    def test_a_certificate_for_a_different_key_is_refused(self) -> None:
        """Installing it would serve a certificate no client can handshake with."""
        self._stub_step(
            f'for a in "$@"; do case "$prev" in --out) out=$a;; esac; prev=$a; done\n'
            f'{OPENSSL} req -x509 -new -key {self.dir / "other.key"} -subj /CN=buildhost.example.lan '
            f'-days 90 -out "$out" 2>/dev/null'
        )
        before = self._expiry(self.cert)
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the private key", result.stderr)
        self.assertEqual(self._expiry(self.cert), before, "a mismatched certificate was installed")
        self.assertNotIn("reload", self._calls())

    def test_a_certificate_that_expires_sooner_is_refused(self) -> None:
        self._stub_step(
            f'for a in "$@"; do case "$prev" in --out) out=$a;; esac; prev=$a; done\n'
            f'{OPENSSL} req -x509 -new -key {self.key} -subj /CN=buildhost.example.lan -days 2 -out "$out" 2>/dev/null'
        )
        before = self._expiry(self.cert)
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        # Named explicitly: a date(1) that could not parse the expiry made this
        # test pass while comparing nothing at all.
        self.assertIn("does not outlive", result.stderr)
        self.assertEqual(self._expiry(self.cert), before)

    def test_garbage_from_step_is_refused(self) -> None:
        self._stub_step(
            'for a in "$@"; do case "$prev" in --out) out=$a;; esac; prev=$a; done\n'
            'printf "not a certificate\\n" > "$out"'
        )
        before = self._expiry(self.cert)
        self.assertNotEqual(self._run().returncode, 0)
        self.assertEqual(self._expiry(self.cert), before)

    def test_nginx_refusing_the_new_certificate_restores_the_old_one(self) -> None:
        """The check that matters most: never leave the stand unable to serve TLS."""
        self._stub_step(
            f'for a in "$@"; do case "$prev" in --out) out=$a;; esac; prev=$a; done\n'
            f'{OPENSSL} req -x509 -new -key {self.key} -subj /CN=buildhost.example.lan -days 90 -out "$out" 2>/dev/null'
        )
        before = self.cert.read_bytes()
        result = self._run(nginx_ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cert.read_bytes(), before, "the previous certificate was not restored")
        self.assertNotIn("reload", self._calls())

    def test_step_failing_leaves_everything_alone(self) -> None:
        self._stub_step('echo "renew failed" >&2; exit 1')
        before = self.cert.read_bytes()
        self.assertNotEqual(self._run().returncode, 0)
        self.assertEqual(self.cert.read_bytes(), before)


class RenewalIsScheduledTests(unittest.TestCase):
    """A renewal nothing runs is the state this whole change exists to end."""

    def test_cron_runs_it_daily_and_the_manifest_deploys_it(self) -> None:
        cron = (ROOT / "infra" / "freebsd-ci" / "freebsd-mirror.cron").read_text(encoding="utf-8")
        entry = [
            line for line in cron.splitlines()
            if line.strip() and not line.startswith("#") and "renew-stand-tls" in line
        ]
        self.assertEqual(len(entry), 1, "the renewal is not scheduled exactly once")
        fields = entry[0].split()
        self.assertNotIn("*", fields[1], "a certificate renewal has no business running hourly")
        self.assertEqual(fields[2:5], ["*", "*", "*"], "renewal must run every day, not monthly")
        self.assertEqual(fields[5], "root")

        manifest = (ROOT / "infra" / "freebsd-ci" / "deployment.manifest").read_text(encoding="utf-8")
        deployed = [
            line.split() for line in manifest.splitlines()
            if line.strip() and not line.startswith("#") and "renew-stand-tls" in line
        ]
        self.assertEqual(len(deployed), 1, "the script is not deployed by the manifest")
        self.assertEqual(deployed[0][1], "/usr/local/sbin/renew-stand-tls")


if __name__ == "__main__":
    unittest.main()
