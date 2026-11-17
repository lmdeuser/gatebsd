from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gatebsd_ui import resolver

REPO_ROOT = Path(__file__).resolve().parents[1]
ROUTE_OP = REPO_ROOT / "sbin" / "gatebsd-route-op"


def _idna(domain: str) -> str:
    return domain.encode("idna").decode("ascii")


class ResolverMultiServerAndCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache_file = self.root / "endpoint-dns-cache"

    def test_falls_back_across_servers_then_os_and_writes_0600_cache(self) -> None:
        calls: list[tuple[str, str]] = []

        def fake_via_server(host: str, srv: str, timeout: float = 3.0) -> list[str]:
            calls.append((host, srv))
            if srv == "77.88.8.8":
                return ["198.51.100.10", "198.51.100.11"]
            return []

        with patch.object(resolver, "resolve_ipv4_via_server", side_effect=fake_via_server), patch.object(
            resolver, "resolve_ipv4", return_value=[]
        ):
            rc = resolver.main([
                "--server", "1.1.1.1",
                "--server", "9.9.9.9",
                "--server", "77.88.8.8",
                "--os-fallback",
                "--cache-file", str(self.cache_file),
                "vpn.example.com",
            ])
        self.assertEqual(rc, 0)
        self.assertEqual(
            calls,
            [("vpn.example.com", "1.1.1.1"), ("vpn.example.com", "9.9.9.9"), ("vpn.example.com", "77.88.8.8")],
        )
        self.assertEqual(stat.S_IMODE(self.cache_file.stat().st_mode), 0o600)
        self.assertEqual(json.loads(self.cache_file.read_text(encoding="utf-8")), {"vpn.example.com": ["198.51.100.10", "198.51.100.11"]})

        # Second host uses --os-fallback when all --server fail and preserves previous host in cache.
        with patch.object(resolver, "resolve_ipv4_via_server", return_value=[]), patch.object(
            resolver, "resolve_ipv4", return_value=["203.0.113.55"]
        ):
            rc2 = resolver.main([
                "--server", "1.1.1.1",
                "--os-fallback",
                "--cache-file", str(self.cache_file),
                "Впн.РФ",
            ])
        self.assertEqual(rc2, 0)
        cached = json.loads(self.cache_file.read_text(encoding="utf-8"))
        self.assertEqual(cached["vpn.example.com"], ["198.51.100.10", "198.51.100.11"])
        self.assertEqual(cached[_idna("впн.рф")], ["203.0.113.55"])

    def test_uses_cache_when_all_live_resolvers_fail_and_refuses_symlink(self) -> None:
        self.cache_file.write_text(json.dumps({"vpn.example.com": ["198.51.100.42"]}), encoding="utf-8")
        self.cache_file.chmod(0o600)

        with patch.object(resolver, "resolve_ipv4_via_server", return_value=[]), patch.object(
            resolver, "resolve_ipv4", return_value=[]
        ):
            rc = resolver.main([
                "--server", "1.1.1.1",
                "--server", "9.9.9.9",
                "--server", "77.88.8.8",
                "--os-fallback",
                "--cache-file", str(self.cache_file),
                "vpn.example.com",
            ])
            self.assertEqual(rc, 0)

            rc_missing = resolver.main([
                "--server", "1.1.1.1",
                "--cache-file", str(self.cache_file),
                "unknown.example.com",
            ])
            self.assertEqual(rc_missing, 1)

        target = self.root / "evil"
        target.write_text('{"vpn.example.com": ["1.2.3.4"]}', encoding="utf-8")
        sym_cache = self.root / "sym-cache"
        sym_cache.symlink_to(target)
        with patch.object(resolver, "resolve_ipv4_via_server", return_value=[]), patch.object(
            resolver, "resolve_ipv4", return_value=[]
        ):
            rc_sym = resolver.main([
                "--server", "1.1.1.1",
                "--cache-file", str(sym_cache),
                "vpn.example.com",
            ])
        self.assertEqual(rc_sym, 1)

        with patch.object(resolver, "resolve_ipv4_via_server", return_value=["198.51.100.99"]):
            rc_live = resolver.main([
                "--server", "1.1.1.1",
                "--cache-file", str(sym_cache),
                "other.example.com",
            ])
        self.assertEqual(rc_live, 0)
        self.assertEqual(target.read_text(encoding="utf-8"), '{"vpn.example.com": ["1.2.3.4"]}')


class RouteOpEndpointResilienceTests(unittest.TestCase):
    def test_route_op_endpoint_ip_falls_back_to_cache_and_handles_idn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            stat_stub = bin_dir / "stat"
            stat_stub.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                "if len(sys.argv) >= 4 and sys.argv[1] == '-f' and sys.argv[2] == '%u':\n"
                "    print('0')\n"
                "elif len(sys.argv) >= 4 and sys.argv[1] == '-f' and sys.argv[2] == '%Lp':\n"
                "    print('600')\n"
                "else:\n"
                "    sys.exit(0)\n",
                encoding="utf-8",
            )
            stat_stub.chmod(0o755)

            conf = root / "gateway.conf"
            conf.write_text('VPN_ENDPOINT_HOST="Впн.РФ"\nVPN_IF="awg0"\n', encoding="utf-8")
            cache = root / "endpoint-dns-cache"
            cache.write_text(json.dumps({_idna("впн.рф"): ["203.0.113.77"]}), encoding="utf-8")

            # Force resolver.resolve_ipv4_via_server and socket.getaddrinfo to fail via sitecustomize/wrapper launcher.
            launcher = root / "offline-python"
            launcher.write_text(
                f"#!/bin/sh\n"
                f"exec {sys.executable} -c 'import sys; "
                f"from gatebsd_ui import resolver; "
                f"resolver.resolve_ipv4_via_server = lambda *a, **k: []; "
                f"resolver.resolve_ipv4 = lambda *a, **k: []; "
                f"sys.exit(resolver.main(sys.argv[3:]))' \"$@\"\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)

            env = {
                "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin",
                "GATEBSD_ALLOW_TEST_PATH": "1",
                "GATEBSD_TEST_PATH_PREFIX": str(bin_dir),
                "GATEBSD_GATEWAY_CONF": str(conf),
                "GATEBSD_PYTHON_LAUNCHER": str(launcher),
                "GATEBSD_PYTHONPATH": str(REPO_ROOT / "webui" / "backend"),
                "GATEBSD_ENDPOINT_DNS_CACHE": str(cache),
            }
            proc = subprocess.run(
                ["sh", str(ROUTE_OP), "endpoint-ip"],
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(proc.stdout.strip(), "203.0.113.77")

            script_text = ROUTE_OP.read_text(encoding="utf-8")
            self.assertIn("--server 9.9.9.9", script_text)
            self.assertIn("--server 77.88.8.8", script_text)
            self.assertIn("--os-fallback", script_text)
            self.assertIn("--cache-file", script_text)


if __name__ == "__main__":
    unittest.main()
