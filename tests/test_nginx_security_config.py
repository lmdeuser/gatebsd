from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "etc" / "nginx" / "gatebsd.conf.sample"
LIMITS = ROOT / "etc" / "nginx" / "gatebsd-limits.conf"
MAIN = ROOT / "etc" / "nginx" / "nginx.conf.sample"


class NginxSecurityConfigTests(unittest.TestCase):
    def test_fresh_install_gets_tls_and_bounded_body(self) -> None:
        text = SAMPLE.read_text(encoding="utf-8")
        self.assertIn("listen 443 ssl default_server;", text)
        self.assertIn("ssl_certificate /usr/local/etc/gatebsd/tls/cert.pem;", text)
        self.assertIn("ssl_certificate_key /usr/local/etc/gatebsd/tls/key.pem;", text)
        self.assertIn("client_max_body_size 1m;", text)
        self.assertNotIn("16g", text)
        self.assertIn("limit_req zone=gatebsd_api", text)

    def test_headers_have_one_owner_and_hsts_is_present(self) -> None:
        text = SAMPLE.read_text(encoding="utf-8")
        self.assertIn('Strict-Transport-Security "max-age=31536000; includeSubDomains" always', text)
        self.assertNotIn("X-Frame-Options SAMEORIGIN", text)
        self.assertNotIn("add_header X-Content-Type-Options", text)

    def test_static_assets_keep_hsts_despite_cache_override(self) -> None:
        text = SAMPLE.read_text(encoding="utf-8")
        static = text.split("location ~*", 1)[1].split("location /", 1)[0]
        self.assertIn("add_header Cache-Control", static)
        self.assertIn("add_header Strict-Transport-Security", static)

    def test_connection_and_request_limits_are_packaged(self) -> None:
        text = LIMITS.read_text(encoding="utf-8")
        self.assertIn("limit_req_zone $binary_remote_addr zone=gatebsd_api:1m rate=10r/s;", text)
        self.assertIn("limit_conn_zone $binary_remote_addr zone=gatebsd_conn:1m;", text)
        self.assertIn("limit_conn gatebsd_conn 32;", text)
        self.assertIn("server_tokens off;", text)
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        for source in (build, makefile):
            self.assertIn("etc/nginx/gatebsd-limits.conf", source)


if __name__ == "__main__":
    unittest.main()
