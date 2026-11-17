"""A version that has been published must keep meaning the same bytes.

The defect: ``versions/<VERSION>`` is a symlink into ``builds/``, so a second
build of an already-published version swapped the pointer and said nothing. It
happened on 15 August 2026 -- a ``workflow_dispatch`` re-run of commit 35541ac
republished 2.9.76 from the same tree as a different package (``fb793678...``
became ``873cd794...``, because ``BUILD_ID`` is embedded and builds are not
byte-identical). Both builds are still on the mirror; only the name moved. The
rule "bump the version" was carried entirely by whoever remembered it.

These tests **execute** ``publish_release`` from ``ci/host/gatebsd-ci-build``
-- the real function text, extracted verbatim -- against a temporary release
root. The reintroduction below deletes the guard and asserts the same case then
gets through, which is what proves these tests can see the difference at all.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "ci" / "host" / "gatebsd-ci-build"

OLD_BUILD = "20260814T202140Z-35541acfa930"
NEW_BUILD = "20260815T015256Z-35541acfa930"
VERSION = "2.9.76"


def extract_publish_release(source: str) -> str:
    """Return the real ``publish_release`` definition, body and all.

    Sliced from the opening line to the closing brace in column zero. If the
    function is ever renamed or reindented this raises rather than silently
    testing nothing.
    """
    start = re.search(r"^publish_release\(\)$", source, re.M)
    if start is None:
        raise AssertionError("publish_release() not found in gatebsd-ci-build")
    end = re.search(r"^\}$", source[start.start():], re.M)
    if end is None:
        raise AssertionError("publish_release() has no closing brace")
    return source[start.start():start.start() + end.end()]


class ReleaseVersionImmutable(unittest.TestCase):
    def run_publish(self, tmp: Path, function: str, build_id: str, env_extra=None):
        """Run the extracted function against a release root under ``tmp``."""
        release_root = tmp / "releases"
        (release_root / "builds" / OLD_BUILD).mkdir(parents=True, exist_ok=True)
        versions = release_root / "versions"
        versions.mkdir(parents=True, exist_ok=True)
        link = versions / VERSION
        if not link.is_symlink():
            link.symlink_to(Path("..") / "builds" / OLD_BUILD)

        script = tmp / "driver.sh"
        script.write_text(
            "RELEASE_ROOT=%s\nBUILD_ID=%s\nARTIFACT_DIR=%s\n%s\npublish_release %s\n"
            % (release_root, build_id, tmp / "artifact", function, VERSION),
            encoding="utf-8",
        )
        (tmp / "artifact").mkdir(exist_ok=True)
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
        env.update(env_extra or {})
        return subprocess.run(
            ["/bin/sh", str(script)],
            capture_output=True, text=True, env=env, timeout=60,
        ), link

    def test_refuses_to_repoint_a_published_version(self):
        function = extract_publish_release(BUILD_SCRIPT.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            done, link = self.run_publish(tmp, function, NEW_BUILD)
            self.assertNotEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertIn("already published", done.stderr)
            # The pointer must be untouched, and `current` never created: the
            # refusal has to happen before anything is staged.
            self.assertEqual(link.readlink().name, OLD_BUILD)
            self.assertFalse((tmp / "releases" / "current").exists())

    def test_same_build_id_is_idempotent_not_a_rewrite(self):
        """Re-running the identical build must get past the guard."""
        function = extract_publish_release(BUILD_SCRIPT.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as raw:
            done, _ = self.run_publish(Path(raw), function, OLD_BUILD)
            self.assertNotIn("already published", done.stderr)

    def test_republish_escape_hatch_is_honoured(self):
        function = extract_publish_release(BUILD_SCRIPT.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as raw:
            done, _ = self.run_publish(
                Path(raw), function, NEW_BUILD, {"GATEBSD_REPUBLISH": "1"}
            )
            self.assertNotIn("already published", done.stderr)

    def test_reintroducing_the_defect_is_visible(self):
        """Without the guard the same case must sail through.

        A test that passes with the defect put back is testing nothing. The
        assertion on the substitution is there because the version of this that
        merely deleted a comment would have looked identical.
        """
        function = extract_publish_release(BUILD_SCRIPT.read_text(encoding="utf-8"))
        without_guard = re.sub(
            r'\n *_published=.*?\n *fi\n', "\n", function, count=1, flags=re.S
        )
        self.assertNotIn("already published", without_guard,
                         "reintroduction did not apply")
        with tempfile.TemporaryDirectory() as raw:
            done, _ = self.run_publish(Path(raw), without_guard, NEW_BUILD)
            self.assertNotIn("already published", done.stderr)


if __name__ == "__main__":
    unittest.main()
