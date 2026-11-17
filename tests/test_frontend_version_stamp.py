"""The browser must actually receive a new release.

The defect these exist for: index.html referenced its assets as
``/app.js?v=2.4.1`` with the version frozen as a literal, while nginx serves
them ``cache-control: public, immutable``. The URL therefore never changed
between releases, and a browser that had fetched app.js once kept that copy for
a week regardless of what was installed underneath it. A router on 2.9.9 was
serving the 2.9.7 frontend: a stale navigation table against a newer API, raw
view ids where titles should be, and ``undefined.map`` on a section added since.

Every test runs ``scripts/stamp-frontend-version.sh`` rather than reading it.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAMP = ROOT / "scripts" / "stamp-frontend-version.sh"
INDEX = ROOT / "webui" / "frontend" / "index.html"
PLACEHOLDER = "__GATEBSD_VERSION__"

ASSET_REF = re.compile(r'(?:src|href)="/([A-Za-z0-9_.-]+\.(?:js|css))\?v=([^"]*)"')


def repo_version() -> str:
    return (ROOT / "VERSION").read_text(encoding="ascii").strip()


class FrontendStampTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        shutil.copy(INDEX, self.dir / "index.html")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_stamp(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(STAMP), str(self.dir), *args],
            check=False,
            capture_output=True,
            text=True,
        )

    # -- the repository copy ----------------------------------------------
    def test_repository_index_carries_a_placeholder_not_a_literal(self) -> None:
        """A literal is what went stale; it must not come back."""
        text = INDEX.read_text(encoding="utf-8")
        self.assertIn(PLACEHOLDER, text)
        for asset, version in ASSET_REF.findall(text):
            self.assertEqual(
                version,
                PLACEHOLDER,
                f"{asset} carries a hardcoded version; it will freeze at that value",
            )

    # -- the fix -----------------------------------------------------------
    def test_stamping_replaces_every_placeholder_with_the_release(self) -> None:
        result = self.run_stamp()
        self.assertEqual(result.returncode, 0, result.stderr)

        stamped = (self.dir / "index.html").read_text(encoding="utf-8")
        self.assertNotIn(PLACEHOLDER, stamped, "an unstamped asset URL would ship")
        refs = ASSET_REF.findall(stamped)
        self.assertTrue(refs, "no versioned asset references found")
        for asset, version in refs:
            self.assertEqual(version, repo_version(), asset)

    def test_two_releases_produce_two_different_asset_urls(self) -> None:
        """The property the cache needs, and the one the literal destroyed."""
        self.run_stamp("2.9.9")
        first = ASSET_REF.findall((self.dir / "index.html").read_text(encoding="utf-8"))

        shutil.copy(INDEX, self.dir / "index.html")
        self.run_stamp("2.9.10")
        second = ASSET_REF.findall((self.dir / "index.html").read_text(encoding="utf-8"))

        self.assertTrue(first and second)
        self.assertNotEqual(
            first,
            second,
            "asset URLs are identical across releases; an immutable cache never refetches",
        )

    def test_package_revision_in_the_version_is_accepted(self) -> None:
        result = self.run_stamp("2.9.10_2")
        self.assertEqual(result.returncode, 0, result.stderr)
        stamped = (self.dir / "index.html").read_text(encoding="utf-8")
        self.assertIn("?v=2.9.10_2", stamped)

    # -- refusals ----------------------------------------------------------
    def test_an_already_stamped_tree_is_refused_rather_than_shipped(self) -> None:
        """Silently shipping a tree with no placeholder is how this got frozen."""
        self.assertEqual(self.run_stamp("2.9.10").returncode, 0)
        second = self.run_stamp("2.9.11")
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("refusing", second.stderr)

    def test_a_malformed_version_never_reaches_the_html(self) -> None:
        result = self.run_stamp('1.0"><script>')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            PLACEHOLDER,
            (self.dir / "index.html").read_text(encoding="utf-8"),
            "the file must be left untouched when the version is rejected",
        )

    # -- reintroduction ----------------------------------------------------
    def test_reintroducing_the_frozen_literal_is_detected(self) -> None:
        """Put the defect back and prove the guard catches it.

        A hand-edited index.html with a fixed version stamps to the same URL for
        every release, which is exactly the state the router shipped in.
        """
        frozen = (self.dir / "index.html").read_text(encoding="utf-8").replace(
            PLACEHOLDER, "2.4.1"
        )
        (self.dir / "index.html").write_text(frozen, encoding="utf-8")

        result = self.run_stamp("2.9.10")
        self.assertNotEqual(
            result.returncode, 0, "a frozen literal must not pass silently"
        )
        for _asset, version in ASSET_REF.findall(
            (self.dir / "index.html").read_text(encoding="utf-8")
        ):
            self.assertEqual(version, "2.4.1")


if __name__ == "__main__":
    unittest.main()
