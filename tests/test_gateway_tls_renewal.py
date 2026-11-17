from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "sbin" / "gatebsd-renew-ssl"
OPENSSL = shutil.which("openssl")
DOMAIN = "gateway.duckdns.org"


def openssl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([OPENSSL, *args], capture_output=True, text=True, check=True)


def issue_certificate(path: Path, key: Path, *, days: int) -> None:
    openssl(
        "req", "-x509", "-new", "-key", str(key), "-days", str(days),
        "-subj", f"/CN={DOMAIN}", "-addext", f"subjectAltName=DNS:{DOMAIN}",
        "-out", str(path),
    )


@unittest.skipUnless(OPENSSL, "the renewal validates real certificates with openssl")
class GatewayTlsRenewalTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.tls = self.dir / "tls"
        self.tls.mkdir()
        self.bin = self.dir / "bin"
        self.bin.mkdir()

        self.old_key = self.dir / "old.key"
        self.new_key = self.dir / "new.key"
        self.other_key = self.dir / "other.key"
        for path in (self.old_key, self.new_key, self.other_key):
            openssl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", str(path))
        self.old_cert = self.dir / "old.crt"
        self.new_cert = self.dir / "new.crt"
        issue_certificate(self.old_cert, self.old_key, days=1)
        issue_certificate(self.new_cert, self.new_key, days=60)
        for name in ("cert.pem", "fullchain.pem"):
            shutil.copyfile(self.old_cert, self.tls / name)
        shutil.copyfile(self.old_key, self.tls / "privkey.pem")
        (self.tls / "privkey.pem").chmod(0o600)

        self.config = self.dir / "duckdns.conf"
        self.config.write_text(
            f'DuckDNS_Token="test-token"\nGATEBSD_TLS_DOMAIN="{DOMAIN}"\n', encoding="utf-8"
        )
        self.config.chmod(0o600)
        self.call_log = self.dir / "calls"
        self.acme = self.dir / "acme"
        self.acme.write_text(
            """#!/bin/sh
printf 'acme %s\n' "$*" >> "$ACME_CALLS"
printf 'token=%s\n' "${DuckDNS_Token:+present}" >> "$ACME_CALLS"
case " $* " in
    *" --issue "*) [ "${ACME_FAIL:-0}" != 1 ] || exit 1 ;;
esac
case " $* " in
    *" --install-cert "*)
        cert=; key=; chain=
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --cert-file) cert=$2; shift 2 ;;
                --key-file) key=$2; shift 2 ;;
                --fullchain-file) chain=$2; shift 2 ;;
                *) shift ;;
            esac
        done
        cp "$ACME_CERT_SOURCE" "$cert"
        cp "$ACME_KEY_SOURCE" "$key"
        cp "$ACME_CERT_SOURCE" "$chain"
        ;;
esac
exit 0
""",
            encoding="utf-8",
        )
        self.acme.chmod(0o755)
        self._stub("id", "printf '0\\n'")
        self._stub(
            "stat",
            """if [ "$1" = -f ]; then
    case "$2" in
        %u) printf '0\\n'; exit 0 ;;
        %Lp)
            if [ "$(/usr/bin/uname -s)" = FreeBSD ]; then
                exec /usr/bin/stat -f '%Lp' "$3"
            else
                exec /usr/bin/stat -c '%a' "$3"
            fi
            ;;
    esac
fi
exec /usr/bin/stat "$@"
""",
        )
        self._stub("nginx", "printf 'nginx %s\\n' \"$*\" >> \"$CALLS\"\n[ ! -f \"$NGINX_FAIL_FILE\" ]")
        self._stub("service", "printf 'service %s\\n' \"$*\" >> \"$CALLS\"")

    def _stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        path.chmod(0o755)

    def run_renewal(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update({
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "GATEBSD_PATH": f"{self.bin}:/usr/bin:/bin",
            "GATEBSD_TLS_CONFIG": str(self.config),
            "GATEBSD_TLS_DIR": str(self.tls),
            "GATEBSD_TLS_LOG": str(self.dir / "renewal.log"),
            "GATEBSD_ACME": str(self.acme),
            "GATEBSD_OPENSSL": OPENSSL,
            "GATEBSD_NGINX": str(self.bin / "nginx"),
            "GATEBSD_SERVICE": str(self.bin / "service"),
            "GATEBSD_RENEW_LOCK_HELD": "1",
            "ACME_CALLS": str(self.call_log),
            "ACME_CERT_SOURCE": str(self.new_cert),
            "ACME_KEY_SOURCE": str(self.new_key),
            "CALLS": str(self.call_log),
            "NGINX_FAIL_FILE": str(self.dir / "nginx-fails"),
            "TMPDIR": str(self.dir),
        })
        env.update(overrides)
        return subprocess.run(
            ["sh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60,
        )

    def live_bytes(self) -> tuple[bytes, bytes, bytes]:
        return tuple((self.tls / name).read_bytes() for name in ("cert.pem", "fullchain.pem", "privkey.pem"))

    def recorded_calls(self) -> str:
        return self.call_log.read_text(encoding="utf-8") if self.call_log.exists() else ""

    def test_successful_renewal_uses_packaged_dnsapi_and_reloads(self) -> None:
        result = self.run_renewal()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.live_bytes(), (self.new_cert.read_bytes(), self.new_cert.read_bytes(), self.new_key.read_bytes()))
        calls = self.recorded_calls()
        self.assertIn("--home /var/db/acme/.acme.sh", calls)
        self.assertIn("--dns dns_duckdns", calls)
        self.assertNotIn("--force", calls)
        self.assertIn("token=present", calls)
        self.assertIn("service nginx reload", calls)
        self.assertNotIn("test-token", (self.dir / "renewal.log").read_text(encoding="utf-8"))

    def test_valid_certificate_outside_window_is_left_alone(self) -> None:
        for name in ("cert.pem", "fullchain.pem"):
            shutil.copyfile(self.new_cert, self.tls / name)
        shutil.copyfile(self.new_key, self.tls / "privkey.pem")
        result = self.run_renewal()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("acme ", self.recorded_calls())

    def test_acme_failure_preserves_the_previous_certificate(self) -> None:
        before = self.live_bytes()
        result = self.run_renewal(ACME_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.live_bytes(), before)
        self.assertNotIn("service nginx", self.recorded_calls())

    def test_mismatched_private_key_is_not_installed(self) -> None:
        before = self.live_bytes()
        result = self.run_renewal(ACME_KEY_SOURCE=str(self.other_key))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.live_bytes(), before)
        self.assertNotIn("service nginx", self.recorded_calls())

    def test_nginx_rejection_restores_the_previous_certificate(self) -> None:
        before = self.live_bytes()
        (self.dir / "nginx-fails").touch()
        result = self.run_renewal()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.live_bytes(), before)
        self.assertNotIn("service nginx reload", self.recorded_calls())

    def test_invalid_domain_is_refused_before_acme(self) -> None:
        original = self.config.read_text(encoding="utf-8")
        for domain in (".duckdns.org", "gateway.example", "bad_domain.duckdns.org"):
            self.config.write_text(original.replace(DOMAIN, domain), encoding="utf-8")
            result = self.run_renewal()
            self.assertNotEqual(result.returncode, 0, domain)
            self.assertNotIn("acme ", self.recorded_calls(), domain)
            self.call_log.unlink(missing_ok=True)

    def test_world_readable_secret_config_is_refused(self) -> None:
        self.config.chmod(0o644)
        result = self.run_renewal()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("acme ", self.recorded_calls())


class GatewayTlsDeliveryTests(unittest.TestCase):
    def test_daily_schedule_and_package_delivery(self) -> None:
        cron = (ROOT / "etc" / "cron.d" / "gatebsd-ssl-renew").read_text(encoding="utf-8")
        active = [line.split() for line in cron.splitlines() if line and not line.startswith("#")]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0][2:5], ["*", "*", "*"])
        self.assertEqual(active[0][5:], ["root", "/usr/local/sbin/gatebsd-renew-ssl"])
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        indexed = subprocess.run(
            ["git", "ls-files", "-s", "--", "sbin/gatebsd-renew-ssl"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        self.assertTrue(indexed.startswith("100755 "), indexed)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        self.assertIn("sbin/gatebsd-renew-ssl", makefile)
        self.assertIn("gatebsd-renew-ssl", build)
        self.assertIn("gatebsd-ssl-renew", build)
        backup = (ROOT / "webui" / "backend" / "gatebsd_ui" / "backup.py").read_text(encoding="utf-8")
        self.assertIn('/usr/local/etc/gatebsd/duckdns.conf', backup)
        self.assertIn('/usr/local/etc/cron.d/gatebsd-ssl-renew', backup)


if __name__ == "__main__":
    unittest.main()
