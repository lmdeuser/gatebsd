"""Tests for the route that makes poudriere's build UI show builds.

`http://mirror.example.lan/poudriere/` answered 200 and displayed nothing. The UI is
static HTML whose JavaScript resolves its data relative to the page --
`assets/poudriere.js` sets `data_url` to `"data/"`, `"data/<mastername>/"` or
`"data/<mastername>/<buildname>/"` and fetches `data_url + ".data.json"`. The
deployed config put the app at `/poudriere/` and its data at `/poudriere-data/`,
so the fetch went to a prefix that did not exist; and at the address where the
data really was, the hardening rule

    location ~ /\\. { deny all; log_not_found off; }

answered 403, because the name poudriere publishes starts with a dot. Same trap
that hid the package repository behind `.latest`, one layer further in.

The tests resolve URIs through a model of nginx's own matching order -- exact,
then longest prefix, then regex in order of appearance, with `^~` suppressing
the regex pass. That order *is* the defect: the old config contained a block
that named the data and still lost every request to a regex written above it.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "infra" / "freebsd-ci" / "install-poudriere-web-route.sh"

MASTER = "freebsd_151_amd64-default"
BUILD = "2026-07-30_16h55m57s"
HTML_ROOT = "/usr/local/share/poudriere/html"
LOGS_ROOT = "/tank/packages/poudriere/data/logs/bulk"

# The deployed mirror config, reduced to the parts that decide this outcome and
# kept in their deployed order: the denies come first there, and that is why.
FIXTURE_CONF = """\
server {
    listen 80;
    server_name _;

    location ~ /\\. { deny all; log_not_found off; }
    location ~ \\.(key|pem|crt|csr|p12|pfx|disabled|lock)$ { deny all; log_not_found off; }

    location ~ ^/(staging|quarantine)(/|$) { deny all; return 404; }

    location /freebsd/packages/ {
        alias /tank/mirror/packages/;
        autoindex on;
    }

    # ===== Poudriere Web UI =====
    location /poudriere/ {
        alias /usr/local/share/poudriere/html/;
        autoindex on;
        limit_except GET HEAD { deny all; }
    }

    location /poudriere-data/ {
        alias /tank/packages/poudriere/data/logs/bulk/;
        autoindex on;
        limit_except GET HEAD { deny all; }
    }

    # ===== GateBSD signed releases =====
    location /gatebsd/releases/ {
        alias /tank/gatebsd/releases/;
        autoindex on;
    }

    location / {
        return 404;
    }
}
"""

LOCATION_RE = re.compile(r"^\s*location\s+(=|\^~|~\*|~)?\s*(\S+)\s*\{(.*)$")


class Location:
    def __init__(self, modifier: str, pattern: str) -> None:
        self.modifier = modifier
        self.pattern = pattern
        self.children: list[Location] = []
        self.body_depth = 0

    def __repr__(self) -> str:  # pragma: no cover - failure messages only
        return f"location {self.modifier} {self.pattern}".replace("  ", " ")


def parse_locations(conf: str) -> list[Location]:
    """The location tree, by brace depth.

    The denies are written on one line -- `location ~ /\\. { deny all; }` -- and
    those are exactly the ones that decide this outcome, so a parser that only
    recognised block form would report the config as harmless and pass.
    """
    top: list[Location] = []
    stack: list[Location] = []
    depth = 0
    for line in conf.splitlines():
        match = LOCATION_RE.match(line)
        if match:
            location = Location(match.group(1) or "", match.group(2))
            (stack[-1].children if stack else top).append(location)
            rest = match.group(3)
            if rest.count("{") + 1 == rest.count("}"):
                continue  # opened and closed on the same line
            depth += 1 + rest.count("{") - rest.count("}")
            location.body_depth = depth
            stack.append(location)
            continue
        depth += line.count("{") - line.count("}")
        while stack and depth < stack[-1].body_depth:
            stack.pop()
    return top


def resolve(locations: list[Location], uri: str) -> Location | None:
    """Which location answers `uri`, following nginx's matching order."""
    for location in locations:
        if location.modifier == "=" and location.pattern == uri:
            return location

    prefix: Location | None = None
    for location in locations:
        if location.modifier in ("", "^~") and uri.startswith(location.pattern):
            if prefix is None or len(location.pattern) > len(prefix.pattern):
                prefix = location
    if prefix is not None and prefix.modifier == "^~":
        return prefix

    for location in locations:
        if location.modifier == "~" and re.search(location.pattern, uri):
            return location
    return prefix


def answering(conf: str, uri: str) -> str:
    """The winning location, resolved through nested blocks, as text."""
    locations = parse_locations(conf)
    winner = resolve(locations, uri)
    while winner is not None and winner.children:
        nested = resolve(winner.children, uri)
        if nested is None or nested is winner:
            break
        winner = nested
    return repr(winner) if winner else "<none>"


class PoudriereWebRouteTests(unittest.TestCase):
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
                "GATEBSD_POUDRIERE_HTML": HTML_ROOT,
                "GATEBSD_POUDRIERE_LOGS": LOGS_ROOT,
                "GATEBSD_CONF_OWNER": str(os.getuid()),
                "GATEBSD_CONF_GROUP": str(os.getgid()),
                "TMPDIR": str(self.root),
                "HOME": str(self.root),
                "LANG": "C",
            },
        )

    def installed(self) -> str:
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return self.conf.read_text(encoding="utf-8")

    def calls(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text(encoding="utf-8").split()

    # -- the defect itself ------------------------------------------------

    def test_the_ui_asked_for_a_prefix_that_did_not_exist(self) -> None:
        """`data_url` is relative, so the fetch never went to /poudriere-data/."""
        self.assertEqual(
            answering(FIXTURE_CONF, f"/poudriere/data/{MASTER}/{BUILD}/logs/pkg.log"),
            "location /poudriere/",
        )

    def test_the_data_was_denied_where_it_did_exist(self) -> None:
        """Even the right address lost: the name poudriere publishes has a dot."""
        self.assertEqual(
            answering(FIXTURE_CONF, "/poudriere-data/.data.json"),
            "location ~ /\\.",
        )

    # -- what the route has to do -----------------------------------------

    def test_every_page_reaches_its_data(self) -> None:
        conf = self.installed()
        for uri in (
            "/poudriere/data/.data.json",
            f"/poudriere/data/{MASTER}/.data.json",
            f"/poudriere/data/{MASTER}/{BUILD}/.data.json",
            f"/poudriere/data/{MASTER}/{BUILD}/.data.mini.json",
            f"/poudriere/data/{MASTER}/latest/.data.json",
        ):
            self.assertEqual(
                answering(conf, uri),
                "location ^~ /poudriere/data/",
                f"{uri} still does not reach the data",
            )

    def test_the_build_logs_are_reachable(self) -> None:
        conf = self.installed()
        self.assertEqual(
            answering(conf, f"/poudriere/data/{MASTER}/latest/logs/amnezia-kmod.log"),
            "location ^~ /poudriere/data/",
        )

    def test_the_data_prefix_points_at_the_log_tree(self) -> None:
        self.assertIn(f"alias {LOGS_ROOT}/;", self.installed())

    def test_the_app_still_serves_its_own_assets(self) -> None:
        conf = self.installed()
        self.assertEqual(
            answering(conf, "/poudriere/assets/poudriere.js"), "location /poudriere/"
        )
        self.assertIn(f"alias {HTML_ROOT}/;", conf)

    def test_symlinks_are_followed(self) -> None:
        """`latest` points at a dated build directory; refusing it serves 403."""
        self.assertIn("disable_symlinks off;", self.installed())

    def test_the_route_is_read_only(self) -> None:
        self.assertIn("limit_except GET HEAD { deny all; }", self.installed())

    def test_the_overview_link_to_latest_per_pkg_resolves(self) -> None:
        """index.html links `latest-per-pkg/` relatively; the tree is in data/."""
        conf = self.installed()
        self.assertEqual(
            answering(conf, "/poudriere/latest-per-pkg/amnezia-kmod/"),
            "location /poudriere/latest-per-pkg/",
        )
        self.assertIn(
            "rewrite ^/poudriere/latest-per-pkg/(.*)$ "
            "/poudriere/data/latest-per-pkg/$1 permanent;",
            conf,
        )

    def test_the_old_data_address_keeps_working(self) -> None:
        conf = self.installed()
        self.assertEqual(
            answering(conf, f"/poudriere-data/{MASTER}/"),
            "location /poudriere-data/",
        )
        self.assertIn(
            "rewrite ^/poudriere-data/(.*)$ /poudriere/data/$1 permanent;", conf
        )

    def test_the_old_blocks_are_replaced_not_duplicated(self) -> None:
        """The config is already an append log; a dead second answer is worse."""
        conf = self.installed()
        self.assertEqual(conf.count("location /poudriere/ {"), 1, conf)
        self.assertEqual(conf.count("location /poudriere-data/ {"), 1, conf)
        self.assertEqual(conf.count(f"alias {LOGS_ROOT}/;"), 1, conf)
        self.assertEqual(conf.count("# ===== Poudriere Web UI ====="), 1, conf)

    # -- what it must not do ----------------------------------------------

    def test_the_hardening_rule_still_covers_everything_else(self) -> None:
        """`^~` is scoped to one prefix; it does not disarm the deny rules."""
        conf = self.installed()
        for uri in (
            "/freebsd/packages/.ssh/id_rsa",
            "/gatebsd/releases/.git/config",
            "/poudriere/.htpasswd",
            "/freebsd/packages/repo.key",
        ):
            self.assertIn(
                answering(conf, uri),
                ("location ~ /\\.", "location ~ \\.(key|pem|crt|csr|p12|pfx|disabled|lock)$"),
                f"{uri} is no longer denied",
            )

    def test_poudriere_build_state_is_not_published(self) -> None:
        """`^~` skipped the server-wide denies here, so they are restated."""
        conf = self.installed()
        for uri in (
            f"/poudriere/data/{MASTER}/latest/.poudriere.pkg_pool%",
            f"/poudriere/data/{MASTER}/latest/.poudriere.ports.queued",
        ):
            self.assertEqual(
                answering(conf, uri), "location ~ /\\.poudriere\\.", f"{uri} is served"
            )

    def test_key_material_stays_denied_inside_the_opened_prefix(self) -> None:
        conf = self.installed()
        self.assertEqual(
            answering(conf, "/poudriere/data/pkg.key"),
            "location ~ \\.(key|pem|crt|csr|p12|pfx|disabled|lock)$",
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
        backups = list(self.root.glob("freebsd-mirror.conf.before-poudriere-web-*"))
        self.assertEqual(len(backups), 1, backups)
        self.assertEqual(backups[0].read_text(encoding="utf-8"), FIXTURE_CONF)

    def test_running_it_again_changes_nothing(self) -> None:
        after_first = self.installed()
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
        self.assertIn("/poudriere/", result.stderr)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), original)
        self.assertEqual(self.calls(), [])

    def test_a_missing_config_is_reported(self) -> None:
        self.conf.unlink()
        self.assertEqual(self.install().returncode, 69)


if __name__ == "__main__":
    unittest.main()
