"""Tests for the HTTP route that makes the poudriere repository usable.

The stand built 140 packages and served none of them. poudriere publishes each
build into `.real_<epoch>` with a `.latest` symlink pointing at it, and the
mirror config hardens with

    location ~ /\\. { deny all; log_not_found off; }

so the only URL that reached the catalogue was denied, and autoindex hid the
directory too. `pkg update` answered 403 Forbidden for every file. Nothing
noticed, because the build succeeded -- the closed development loop the product
depends on was open at the last step, and the router kept pointing at upstream
quarterly.

These tests run the installer and then ask the resulting configuration which
location would answer a given request, rather than asserting on its text: the
defect is in what nginx *matches*, and a config can contain the right block and
still lose it to an earlier regex.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "infra" / "freebsd-ci" / "install-poudriere-repo-route.sh"

MASTER = "freebsd_151_amd64-default"
PACKAGES_ROOT = "/tank/packages/poudriere/data/packages"

# The parts of the deployed mirror config that decide this outcome, in their
# deployed order. The dotted-path deny comes first there, and that is the point.
FIXTURE_CONF = """\
server {
    listen 80;
    server_name mirror;

    location ~ /\\. { deny all; log_not_found off; }
    location ~ \\.(key|pem|crt|csr|p12|pfx|disabled|lock)$ { deny all; log_not_found off; }

    location ~ ^/(staging|quarantine)(/|$) { deny all; return 404; }

    location /gatebsd/packages/ {
        alias /tank/packages/poudriere/data/packages/;
        autoindex on;
        autoindex_exact_size off;
    }

    # ===== CI Artifacts =====
    location /gatebsd/releases/ {
        alias /tank/gatebsd/releases/;
        autoindex on;
    }
}
"""

LOCATION_RE = re.compile(r"^\s*location\s+~\s+(\S+)\s*\{", re.MULTILINE)


def matching_location(conf: str, uri: str) -> str | None:
    """Which regex location answers `uri`, by nginx's rule: first match wins.

    nginx tries regex locations in the order they appear and stops at the first
    that matches; the patterns here are plain PCRE that Python's `re` accepts
    unchanged. Prefix locations are deliberately not modelled -- a regex match
    beats them all, which is exactly how the deny rule swallowed the repository.
    """
    for pattern in LOCATION_RE.findall(conf):
        if re.search(pattern, uri):
            return pattern
    return None


class RepositoryRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.conf = self.root / "freebsd-mirror.conf"
        self.conf.write_text(FIXTURE_CONF, encoding="utf-8")

        # Stubs, so the test never validates or reloads the real web server.
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls.log"
        self.stub("nginx", 0)
        self.stub("service", 0)
        self.addCleanup(self._tmp.cleanup)

    def stub(self, name: str, status: int) -> None:
        path = self.bin / name
        path.write_text(
            f'#!/bin/sh\necho "{name} $*" >> "{self.log}"\nexit {status}\n',
            encoding="utf-8",
        )
        path.chmod(0o755)

    def install(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(INSTALLER)],
            capture_output=True,
            text=True,
            check=False,
            env={
                "PATH": f"{self.bin}:/usr/bin:/bin",
                "GATEBSD_PATH": f"{self.bin}:/usr/bin:/bin",
                "GATEBSD_MIRROR_CONF": str(self.conf),
                "GATEBSD_PACKAGES_ROOT": PACKAGES_ROOT,
                "GATEBSD_CONF_OWNER": str(os.getuid()),
                "GATEBSD_CONF_GROUP": str(os.getgid()),
                "TMPDIR": str(self.root),
                "HOME": str(self.root),
                "LANG": "C",
            },
        )

    def calls(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text(encoding="utf-8").split()

    # -- the defect itself ------------------------------------------------

    def test_the_dotted_poudriere_path_is_denied(self) -> None:
        """Why the repository was unreachable: the only URL that existed lost."""
        uri = f"/gatebsd/packages/{MASTER}/.latest/packagesite.pkg"
        self.assertEqual(matching_location(FIXTURE_CONF, uri), "/\\.")

    def test_a_client_can_fetch_the_catalogue_without_naming_the_dot(self) -> None:
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        conf = self.conf.read_text(encoding="utf-8")
        for name in ("packagesite.pkg", "meta.conf", "All/gatebsd-2.9.6.pkg"):
            uri = f"/gatebsd/packages/{MASTER}/latest/{name}"
            self.assertEqual(
                matching_location(conf, uri),
                "^/gatebsd/packages/([^/.][^/]*)/latest/(.*)$",
                f"{uri} is still not served by the repository route",
            )

    def test_the_dot_is_resolved_server_side(self) -> None:
        """The URI carries no dot; the filesystem path still has to."""
        self.install()
        conf = self.conf.read_text(encoding="utf-8")
        self.assertIn(f"alias {PACKAGES_ROOT}/$1/.latest/$2;", conf)

    def test_the_hardening_rule_still_covers_everything_else(self) -> None:
        """The fix resolves one known dot, it does not disarm the deny rule."""
        self.install()
        conf = self.conf.read_text(encoding="utf-8")
        for uri in (
            "/freebsd/packages/.ssh/id_rsa",
            f"/gatebsd/packages/{MASTER}/.latest/packagesite.pkg",
            "/gatebsd/packages/.hidden/latest/packagesite.pkg",
        ):
            self.assertEqual(
                matching_location(conf, uri), "/\\.", f"{uri} is no longer denied"
            )

    def test_symlinks_are_followed(self) -> None:
        """`.latest` is a symlink into `.real_<epoch>`; refusing it serves 403."""
        self.install()
        self.assertIn("disable_symlinks off;", self.conf.read_text(encoding="utf-8"))

    def test_the_route_is_read_only(self) -> None:
        self.install()
        self.assertIn(
            "limit_except GET HEAD { deny all; }", self.conf.read_text(encoding="utf-8")
        )

    # -- how it is applied ------------------------------------------------

    def test_the_configuration_is_validated_before_it_is_reloaded(self) -> None:
        """A bad config takes the mirror, the repository and Forgejo down together."""
        self.install()
        calls = self.calls()
        self.assertIn("nginx", calls)
        self.assertIn("service", calls)
        self.assertLess(calls.index("nginx"), calls.index("service"))

    def test_a_rejected_configuration_is_restored_and_not_reloaded(self) -> None:
        self.stub("nginx", 1)
        result = self.install()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), FIXTURE_CONF)
        self.assertNotIn("service", self.calls())

    def test_the_previous_configuration_is_kept(self) -> None:
        self.install()
        backups = list(self.root.glob("freebsd-mirror.conf.before-poudriere-route-*"))
        self.assertEqual(len(backups), 1, backups)
        self.assertEqual(backups[0].read_text(encoding="utf-8"), FIXTURE_CONF)

    def test_running_it_again_changes_nothing(self) -> None:
        self.install()
        after_first = self.conf.read_text(encoding="utf-8")
        second = self.install()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("already installed", second.stdout)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), after_first)

    def test_a_config_without_the_anchor_is_left_alone(self) -> None:
        """Better to fail loudly than to append a location to an unknown file."""
        self.conf.write_text("server {\n    listen 80;\n}\n", encoding="utf-8")
        original = self.conf.read_text(encoding="utf-8")
        result = self.install()
        self.assertEqual(result.returncode, 1)
        self.assertIn("anchor", result.stderr)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), original)
        self.assertEqual(self.calls(), [])

    def test_a_missing_config_is_reported(self) -> None:
        self.conf.unlink()
        result = self.install()
        self.assertEqual(result.returncode, 69)


if __name__ == "__main__":
    unittest.main()
