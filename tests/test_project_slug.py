"""The mirror tree is rooted at a project slug, not at one product's name.

One stand serves the whole closed development loop, and it is about to serve a
second product. Every path and URL that tree is reached by was spelled
`gatebsd` in the machinery that publishes it -- the release root
`/tank/gatebsd/releases`, the HTTP prefixes `/gatebsd/releases/` and
`/gatebsd/packages/`, and the nginx regex location that resolves poudriere's
dot server-side. That is the product's name standing in for the platform's
role, and for a second product it would simply be false.

The root is now derived from `PROJECT_SLUG`, whose default is `gatebsd`. That
default is not a detail: devices in the field carry
`/usr/local/etc/pkg/repos/gatebsd.conf` pinned to these exact URLs, and their
only way to be told a new one is a package fetched over the URL being changed.
So the parameterisation must leave the published paths byte for byte what they
are today, and the first test of each installer below asserts precisely that.

These tests run the installers rather than reading them. An earlier wiring test
in this tree passed happily with the call it was checking sitting behind
`if false`; a test that greps for a variable name would pass just as happily
against a script that interpolates it nowhere.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POUDRIERE_INSTALLER = ROOT / "infra" / "freebsd-ci" / "install-poudriere-repo-route.sh"
RELEASE_INSTALLER = ROOT / "infra" / "freebsd-ci" / "install-gatebsd-release-route.sh"

# The default, and the only value any deployed device knows about.
DEFAULT_SLUG = "gatebsd"
# A second product, deliberately sharing no substring with the first: an
# assertion that passes for both would prove nothing.
OTHER_SLUG = "harborward"

PACKAGES_ROOT = "/tank/packages/poudriere/data/packages"

# Slugs that must be refused before anything is written. `PROJECT_SLUG` is
# interpolated into filesystem paths, into HTTP locations and -- in the
# poudriere installer -- into an nginx regex, and the installer replaces the
# live config before nginx ever sees it. A slug that escapes any one of those
# would be caught by `nginx -t` at best and silently change what the regex
# matches at worst.
BAD_SLUGS = (
    "",  # empty: the root would collapse to /tank//releases
    "../escape",  # climbs out of /tank
    "gate/bsd",  # a second path element
    "GateBSD",  # nginx locations are case-sensitive
    "gate bsd",  # word splitting
    "gate.bsd",  # a dot, which the hardening rule denies
    "gate*bsd",  # a glob, and a regex quantifier
)


def mirror_conf(slug: str) -> str:
    """The parts of the deployed mirror config that decide these outcomes.

    The dotted-path deny comes first, as it does on the stand, and the CI
    artifacts marker is there because the release route anchors on it.
    """
    return f"""\
server {{
    listen 80;
    server_name mirror;

    location ~ /\\. {{ deny all; log_not_found off; }}

    location /{slug}/packages/ {{
        alias {PACKAGES_ROOT}/;
        autoindex on;
    }}

    # ===== CI Artifacts =====
    location /ci/artifacts/ {{
        alias /tank/ci/artifacts/;
        autoindex on;
    }}
}}
"""


class InstallerHarness(unittest.TestCase):
    """Runs an installer against a private copy of the mirror config.

    nginx and service(8) are stubbed, so nothing here validates or reloads the
    real web server, and the config the installer edits is a temporary file.
    """

    installer: Path

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.conf = self.root / "freebsd-mirror.conf"
        self.tank = self.root / "tank"
        self.tank.mkdir()

        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls.log"
        self.stub("nginx", 0)
        self.stub("service", 0)

    def stub(self, name: str, status: int) -> None:
        path = self.bin / name
        path.write_text(
            f'#!/bin/sh\necho "{name} $*" >> "{self.log}"\nexit {status}\n',
            encoding="utf-8",
        )
        path.chmod(0o755)

    def write_conf(self, slug: str) -> str:
        text = mirror_conf(slug)
        self.conf.write_text(text, encoding="utf-8")
        return text

    def install(self, slug: str | None = None) -> subprocess.CompletedProcess:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "GATEBSD_PATH": f"{self.bin}:/usr/bin:/bin",
            "GATEBSD_MIRROR_CONF": str(self.conf),
            "GATEBSD_PACKAGES_ROOT": PACKAGES_ROOT,
            "GATEBSD_TANK_ROOT": str(self.tank),
            "GATEBSD_CONF_OWNER": str(os.getuid()),
            "GATEBSD_CONF_GROUP": str(os.getgid()),
            "GATEBSD_TREE_GROUP": str(os.getgid()),
            "TMPDIR": str(self.root),
            "HOME": str(self.root),
            "LANG": "C",
        }
        if slug is not None:
            env["PROJECT_SLUG"] = slug
        return subprocess.run(
            ["sh", str(self.installer)],
            capture_output=True, text=True, check=False, env=env,
        )

    def calls(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text(encoding="utf-8").split()

    def assertRefusesEverySlug(self) -> None:
        """A rejected slug must cost nothing: no edit, no reload, no backup."""
        for slug in BAD_SLUGS:
            with self.subTest(slug=slug):
                self.log.unlink(missing_ok=True)
                original = self.write_conf(DEFAULT_SLUG)
                result = self.install(slug)
                self.assertEqual(
                    result.returncode, 2,
                    f"{slug!r} was not refused: {result.stdout}{result.stderr}",
                )
                self.assertIn("PROJECT_SLUG", result.stderr)
                self.assertEqual(self.conf.read_text(encoding="utf-8"), original)
                self.assertEqual(self.calls(), [])
                self.assertEqual(list(self.root.glob("freebsd-mirror.conf.before-*")), [])


class PoudriereRouteSlugTests(InstallerHarness):
    installer = POUDRIERE_INSTALLER

    def inserted_location(self) -> str:
        conf = self.conf.read_text(encoding="utf-8")
        for line in conf.splitlines():
            if line.strip().startswith("location ~ ^/"):
                return line.strip()
        self.fail(f"no regex location was inserted:\n{conf}")

    def test_the_default_publishes_exactly_what_the_devices_already_fetch(self) -> None:
        """The URL a deployed device is pinned to, spelled out rather than
        derived: if this line ever changes, every appliance in the field loses
        its package source, and the fix would have to travel over the URL that
        just broke."""
        self.write_conf(DEFAULT_SLUG)
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            self.inserted_location(),
            "location ~ ^/gatebsd/packages/([^/.][^/]*)/latest/(.*)$ {",
        )

    def test_leaving_the_slug_unset_is_the_same_as_setting_it_to_the_default(self) -> None:
        """Otherwise the stand and a caller that spells the default out would
        drift apart, which is how two writers of one contract usually start."""
        self.write_conf(DEFAULT_SLUG)
        self.install()
        implicit = self.conf.read_text(encoding="utf-8")

        self.write_conf(DEFAULT_SLUG)
        self.install(DEFAULT_SLUG)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), implicit)

    def test_a_second_product_gets_a_root_of_its_own(self) -> None:
        self.write_conf(OTHER_SLUG)
        result = self.install(OTHER_SLUG)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            self.inserted_location(),
            f"location ~ ^/{OTHER_SLUG}/packages/([^/.][^/]*)/latest/(.*)$ {{",
        )

    def test_the_first_product_name_does_not_leak_into_the_second(self) -> None:
        """The failure this guards is a half-done parameterisation: one of the
        two spellings still hardcoded, so a second product's route is written
        under the first product's root and quietly shadows it."""
        self.write_conf(OTHER_SLUG)
        self.install(OTHER_SLUG)
        conf = self.conf.read_text(encoding="utf-8")
        self.assertNotIn(f"/{DEFAULT_SLUG}/", conf)

    def test_the_anchor_is_derived_from_the_slug_too(self) -> None:
        """Reintroduces the defect from the other side: a config holding only
        the first product's prefix must not be treated as the second's. If the
        anchor were left hardcoded this would happily insert a `harborward`
        route beside the `gatebsd` prefix it does not belong to."""
        original = self.write_conf(DEFAULT_SLUG)
        result = self.install(OTHER_SLUG)
        self.assertEqual(result.returncode, 1)
        self.assertIn("anchor", result.stderr)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), original)
        self.assertEqual(self.calls(), [])

    def test_a_slug_that_could_escape_its_own_path_is_refused(self) -> None:
        self.assertRefusesEverySlug()

    def test_the_hardening_rule_still_wins_under_a_second_root(self) -> None:
        """The route resolves one known dot; it does not reopen the hole the
        deny rule closes, and that has to hold for every project root."""
        self.write_conf(OTHER_SLUG)
        self.install(OTHER_SLUG)
        conf = self.conf.read_text(encoding="utf-8")
        deny_at = conf.index("location ~ /\\.")
        route_at = conf.index(f"location ~ ^/{OTHER_SLUG}/packages/")
        self.assertLess(
            deny_at, route_at,
            "the dotted-path deny must still be tried first",
        )


class ReleaseRouteSlugTests(InstallerHarness):
    installer = RELEASE_INSTALLER

    def inserted_block(self) -> tuple[str, str]:
        conf = self.conf.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(conf):
            if line.strip().startswith("location /") and "/releases/" in line:
                return line.strip(), conf[i + 1].strip()
        self.fail("no release location was inserted:\n" + "\n".join(conf))

    def test_the_default_publishes_exactly_what_is_deployed_today(self) -> None:
        self.write_conf(DEFAULT_SLUG)
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        location, alias = self.inserted_block()
        self.assertEqual(location, "location /gatebsd/releases/ {")
        self.assertEqual(alias, f"alias {self.tank}/gatebsd/releases/;")

    def test_the_location_and_the_alias_move_together(self) -> None:
        """Two halves of one contract. A URL pointing at a tree that is not
        there answers 500, and a tree nothing points at is invisible -- either
        half left behind breaks delivery on its own."""
        self.write_conf(OTHER_SLUG)
        result = self.install(OTHER_SLUG)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        location, alias = self.inserted_block()
        self.assertEqual(location, f"location /{OTHER_SLUG}/releases/ {{")
        self.assertEqual(alias, f"alias {self.tank}/{OTHER_SLUG}/releases/;")

    def test_the_tree_the_alias_names_is_created(self) -> None:
        """The route has to resolve before the first release is published,
        otherwise nginx answers 500 for a missing alias root rather than an
        empty index."""
        self.write_conf(OTHER_SLUG)
        self.install(OTHER_SLUG)
        for path in ("", "/builds", "/versions"):
            self.assertTrue(
                (self.tank / OTHER_SLUG / "releases").joinpath(path.lstrip("/")).is_dir(),
                f"{OTHER_SLUG}/releases{path} was not created",
            )

    def test_a_slug_that_could_escape_its_own_path_is_refused(self) -> None:
        self.assertRefusesEverySlug()

    def test_running_it_again_changes_nothing(self) -> None:
        self.write_conf(OTHER_SLUG)
        self.install(OTHER_SLUG)
        after_first = self.conf.read_text(encoding="utf-8")
        second = self.install(OTHER_SLUG)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("already installed", second.stdout)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), after_first)

    def test_a_rejected_configuration_is_restored_and_not_reloaded(self) -> None:
        self.write_conf(OTHER_SLUG)
        original = self.conf.read_text(encoding="utf-8")
        self.stub("nginx", 1)
        result = self.install(OTHER_SLUG)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.conf.read_text(encoding="utf-8"), original)
        self.assertNotIn("service", self.calls())


class NoRootIsSpelledOutTests(unittest.TestCase):
    """The literal must not come back.

    Every test above would still pass if someone added a second, hardcoded
    reference beside the derived one -- the derived path would be correct and
    the stray literal would sit there until a second product tripped over it.
    This reads the executable lines of each parameterised script and refuses
    the spellings that are supposed to be derived now.
    """

    # Scripts that form a mirror path or URL and are therefore parameterised.
    SCRIPTS = (
        ROOT / "ci" / "host" / "gatebsd-ci-build",
        ROOT / "ci" / "host" / "prepare-gatebsd-build-jail.sh",
        ROOT / "infra" / "freebsd-ci" / "ci-dashboard-update.sh",
        ROOT / "infra" / "freebsd-ci" / "install-gatebsd-release-route.sh",
        ROOT / "infra" / "freebsd-ci" / "install-poudriere-repo-route.sh",
    )

    # Spellings that are now derived from PROJECT_SLUG. `/gatebsd/` alone is
    # not one of them: the Forgejo repository really does live under an
    # organisation of that name, which is a different axis and not this one.
    FORBIDDEN = (
        "/gatebsd/releases",
        "/gatebsd/packages",
        "/tank/gatebsd",
    )

    def test_no_script_still_spells_the_default_root_in_code(self) -> None:
        for script in self.SCRIPTS:
            lines = script.read_text(encoding="utf-8").splitlines()
            for number, line in enumerate(lines, start=1):
                if line.lstrip().startswith("#"):
                    continue  # prose may name the default, and does
                for literal in self.FORBIDDEN:
                    with self.subTest(script=script.name, line=number):
                        self.assertNotIn(
                            literal, line,
                            f"{script.name}:{number} spells {literal} out; "
                            "derive it from PROJECT_SLUG instead",
                        )

    def test_every_parameterised_script_validates_the_slug(self) -> None:
        """A script that interpolates the slug without checking it hands an
        attacker-shaped value to install(1), to awk and to nginx."""
        for script in self.SCRIPTS:
            text = script.read_text(encoding="utf-8")
            with self.subTest(script=script.name):
                # `-`, not `:-`. With `:-` an explicitly empty slug silently
                # becomes the default, so the empty case in BAD_SLUGS above
                # could never reach the guard -- which is exactly how it was
                # written first, and what that case caught.
                self.assertIn("PROJECT_SLUG=${PROJECT_SLUG-gatebsd}", text)
                self.assertIn("*[!a-z0-9-]*", text)


if __name__ == "__main__":
    unittest.main()
