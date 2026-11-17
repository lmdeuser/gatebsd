"""The panel must listen on the LAN, not on every address the device has.

Found auditing the production router from the outside in: both server blocks
said `listen 80 default_server;` and `listen 443 ssl default_server;` with no
address. nginx was therefore bound to the public PPPoE address, the backup
carrier's address and the tunnel's, answering whatever Host arrived. Nothing
was reachable, because pf drops inbound on all three -- which is the problem:
one ruleset was the entire defence. A pf that fails to load, or a single
`pfctl -F rules`, and the administration panel is on the internet.

The address is read off the interface gateway.conf names, never written into
the tree. Hardcoding one router's LAN address is the same defect as the pkg
repository config that lived only on one router (see test_repo_bootstrap).

Every test RUNS sbin/gatebsd-config-migrate. `ifconfig` and `nginx` are stubs
reached through GATEBSD_PATH, so the migration executes its real logic against
an interface and a validator that this test controls.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "sbin" / "gatebsd-config-migrate"

LAN_ADDRESS = "192.0.2.1"

UNBOUND_CONF = """server {
    listen 80 default_server;
    server_name gatebsd.example.lan netgate 10.88.0.1;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}

server {
    listen 443 ssl default_server;
    server_name gatebsd.example.lan netgate 10.88.0.1;
}
"""


@unittest.skipUnless(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    "gatebsd-config-migrate refuses to run unprivileged",
)
class NginxListensOnTheLanOnly(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)

        self.stubs = self.dir / "stubs"
        self.stubs.mkdir()
        self._write_ifconfig(LAN_ADDRESS)
        self._write_nginx(accepts=True)

        self.gateway = self.dir / "gateway.conf"
        self.gateway.write_text('WAN_IF="ng0"\nLAN_IF="re1"\n', encoding="utf-8")

        self.conf = self.dir / "gatebsd.conf"
        self.conf.write_text(UNBOUND_CONF, encoding="utf-8")
        self.conf.chmod(0o644)

        self.backups = self.dir / "backups"
        self.rc = self.dir / "rc.d"
        self.rc.mkdir()

    def _write_stub(self, name: str, body: str) -> None:
        path = self.stubs / name
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        path.chmod(0o755)

    def _write_ifconfig(self, address: str | None) -> None:
        if address is None:
            # The interface exists and has no IPv4 address, which is what a
            # device mid-boot looks like.
            self._write_stub("ifconfig", 'echo "re1: flags=8843<UP>"\nexit 0')
        else:
            self._write_stub(
                "ifconfig",
                f'echo "re1: flags=8843<UP>"\nprintf "\\tinet {address} netmask 0xffffff00\\n"\nexit 0',
            )

    def _write_nginx(self, accepts: bool) -> None:
        self._write_stub("nginx", "exit 0" if accepts else "exit 1")

    def _run(self) -> subprocess.CompletedProcess:
        environment = dict(os.environ)
        environment.update({
            "GATEBSD_PATH": f"{self.stubs}:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
            "GATEBSD_NGINX_CONF": str(self.conf),
            "GATEBSD_NGINX_BACKUP_DIR": str(self.backups),
            "GATEBSD_GATEWAY_CONF": str(self.gateway),
            "GATEBSD_RC_DIR": str(self.rc),
            # Everything else this script migrates is out of scope here.
            "GATEBSD_MAIN_CONF": str(self.dir / "absent-main.conf"),
            "GATEBSD_FAILOVER_CONF": str(self.dir / "absent-failover.conf"),
            "GATEBSD_UNBOUND_CONF": str(self.dir / "absent-unbound.conf"),
            "GATEBSD_PF_CONF": str(self.dir / "absent-pf.conf"),
            "GATEBSD_LEGACY_RU_STATE": str(self.dir / "absent-ru.state"),
            "RU_STATE_FILE": str(self.dir / "absent-ru-new.state"),
        })
        return subprocess.run(
            ["sh", str(MIGRATE)], env=environment,
            capture_output=True, text=True, timeout=60,
        )

    # ------------------------------------------------------------------ the hole
    def test_a_wildcard_listen_gets_the_lan_address(self) -> None:
        result = self._run()
        written = self.conf.read_text(encoding="utf-8")
        self.assertIn(f"listen {LAN_ADDRESS}:80 default_server;", written, result.stderr)
        self.assertIn(f"listen {LAN_ADDRESS}:443 ssl default_server;", written)
        self.assertNotIn("listen 80", written)
        self.assertNotIn("listen 443", written)

    def test_nothing_but_the_listen_lines_is_touched(self) -> None:
        self._run()
        written = self.conf.read_text(encoding="utf-8").splitlines()
        original = UNBOUND_CONF.splitlines()
        self.assertEqual(len(written), len(original))
        for before, after in zip(original, written):
            if "listen" in before:
                continue
            self.assertEqual(before, after)

    def test_the_address_comes_from_the_interface_gateway_conf_names(self) -> None:
        """A product cannot carry one router's LAN address in its tree."""
        self.gateway.write_text('LAN_IF="igc0"\n', encoding="utf-8")
        self._write_stub(
            "ifconfig",
            'case "$1" in igc0) printf "\\tinet 10.77.0.1 netmask 0xffffff00\\n";; '
            'esac\nexit 0',
        )
        self._run()
        self.assertIn("listen 10.77.0.1:80", self.conf.read_text(encoding="utf-8"))

    def test_the_previous_copy_is_kept(self) -> None:
        self._run()
        kept = list(self.backups.rglob("gatebsd.conf"))
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].read_text(encoding="utf-8"), UNBOUND_CONF)

    def test_the_file_keeps_its_own_mode(self) -> None:
        """Written in place, so a packaged file does not change identity."""
        self.conf.chmod(0o640)
        self._run()
        self.assertEqual(self.conf.stat().st_mode & 0o777, 0o640)

    # ------------------------------------------------------------------ restraint
    def test_an_already_bound_config_is_left_exactly_as_it_is(self) -> None:
        bound = UNBOUND_CONF.replace("listen 80", f"listen {LAN_ADDRESS}:80").replace(
            "listen 443", f"listen {LAN_ADDRESS}:443"
        )
        self.conf.write_text(bound, encoding="utf-8")
        result = self._run()
        self.assertEqual(self.conf.read_text(encoding="utf-8"), bound)
        self.assertFalse(self.backups.exists(), "a no-op left a pointless backup")
        self.assertNotIn("bound the web UI", result.stdout)

    def test_a_rejected_result_restores_the_original(self) -> None:
        """A config nginx will not load takes the panel down at the next restart."""
        self._write_nginx(accepts=False)
        result = self._run()
        self.assertEqual(self.conf.read_text(encoding="utf-8"), UNBOUND_CONF)
        self.assertIn("left unchanged", result.stderr)

    def test_an_interface_with_no_address_changes_nothing(self) -> None:
        """Mid-boot is not the moment to guess an address."""
        self._write_ifconfig(None)
        result = self._run()
        self.assertEqual(self.conf.read_text(encoding="utf-8"), UNBOUND_CONF)
        self.assertIn("cannot read an IPv4 address", result.stderr)

    def test_without_nginx_to_validate_it_changes_nothing(self) -> None:
        (self.stubs / "nginx").unlink()
        result = self._run()
        self.assertEqual(self.conf.read_text(encoding="utf-8"), UNBOUND_CONF)
        self.assertIn("unavailable to validate", result.stderr)

    def test_a_symlinked_config_is_never_written_through(self) -> None:
        elsewhere = self.dir / "elsewhere.conf"
        elsewhere.write_text(UNBOUND_CONF, encoding="utf-8")
        self.conf.unlink()
        self.conf.symlink_to(elsewhere)
        self._run()
        self.assertEqual(elsewhere.read_text(encoding="utf-8"), UNBOUND_CONF)

    def test_it_does_not_reload_nginx(self) -> None:
        """A package script's children are SIGKILLed when it returns.

        Three services were once started from post-install and killed seconds
        later, leaving a router with no failover. gatebsd-upgrade restarts
        nginx after pkg has returned, behind a health gate; this must not.
        """
        calls = self.dir / "service-calls"
        self._write_stub("service", f'echo "$@" >> "{calls}"\nexit 0')
        self._write_stub("nginx", f'echo "$@" >> "{calls}"\nexit 0')
        self._run()
        recorded = calls.read_text(encoding="utf-8") if calls.exists() else ""
        self.assertNotIn("reload", recorded)
        self.assertNotIn("restart", recorded)


if __name__ == "__main__":
    unittest.main()
