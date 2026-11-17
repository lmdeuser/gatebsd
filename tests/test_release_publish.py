"""Functional regression tests for release publication in gatebsd-ci-build.

The defect these exist for: the pipeline's stated goal is to end at a signed
package an operator can install, but the only copy of a signed release lived in
``/tank/ci/artifacts/<BUILD_ID>/``, which ``prune_builds()`` reclaims. With
``KEEP_BUILDS=10`` and ten builds already present, ten further pushes to master
deleted the signed 2.9.4 release outright -- and until then its URL contained a
build ID that could only be recovered by reading the CI job log.

``publish_release()`` copies the verified tree to a version-addressed path and
swaps ``current`` and ``versions/<VERSION>`` symlinks atomically;
``prune_releases()`` bounds growth without ever removing a build a symlink still
resolves to.

These tests extract both functions from ``ci/host/gatebsd-ci-build`` and execute
them against a temporary release root, so a refactor that reintroduces the
deletion, drops a symlink or publishes an unsigned tree fails here. The symlink
and prune semantics were additionally confirmed on FreeBSD 15.1, where the
pipeline actually runs.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "ci" / "host" / "gatebsd-ci-build"

EXTRACTED = ("publish_release", "prune_releases")


def extract_function(source: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\n\{{$", source, re.MULTILINE)
    if match is None:
        raise AssertionError(f"{name}() not found in ci/host/gatebsd-ci-build")
    end = source.index("\n}", match.start())
    return source[match.start() : end + 2]


class ReleasePublishHarness:
    """Runs the extracted publication functions over a temporary release root."""

    BUILD_ID = "20260130T120000Z-abcdef123456"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.release_root = root / "releases"
        self.artifact_dir = root / "artifacts" / self.BUILD_ID
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.source = BUILD_SCRIPT.read_text(encoding="utf-8")
        self.functions = "\n".join(extract_function(self.source, n) for n in EXTRACTED)
        for name in (
            "sh", "printf", "cp", "ln", "rm", "chmod",
            "find", "ls", "grep", "sort", "awk", "readlink", "basename", "cat", "mkdir",
        ):
            real = shutil.which(name)
            if real and not (self.bin / name).exists():
                (self.bin / name).symlink_to(real)
        # Two shims bridge the gap between this harness and the FreeBSD host the
        # pipeline actually runs on. Neither weakens what is under test: the
        # layout, the atomic symlink swap and the retention rules.
        #
        # `install -o root -g www` cannot work here -- the group does not exist
        # and the tests do not run as root -- so the ownership flags are dropped
        # while the directory and mode semantics the layout depends on are kept.
        self._stub(
            "install",
            self._filter_args(shutil.which("install") or "/usr/bin/install"),
        )
        self._stub("chown", "exit 0\n")
        # `mv -fh` is the FreeBSD spelling for replacing a symlink instead of
        # following it into its target directory. GNU coreutils rejects -h and
        # spells the same behaviour -T. Verified directly on FreeBSD 15.1 that
        # -fh replaces the link, which is the property the layout relies on.
        real_mv = shutil.which("mv") or "/bin/mv"
        self._stub(
            "mv",
            f'case "${{1:-}}" in\n'
            f'  -fh|-hf) shift; exec {real_mv} -fT "$@" ;;\n'
            f'esac\n'
            f'exec {real_mv} "$@"\n',
        )

    @staticmethod
    def _filter_args(real: str) -> str:
        """Drop -o/-g option pairs, preserving every other argument verbatim.

        Rotates the positional parameters behind a sentinel so that arguments
        containing whitespace survive intact.
        """
        return (
            'set -- "$@" "--end--"\n'
            "while :; do\n"
            '  case "$1" in\n'
            '    --end--) shift; break ;;\n'
            "    -o|-g) shift 2 ;;\n"
            '    *) set -- "$@" "$1"; shift ;;\n'
            "  esac\n"
            "done\n"
            f'exec {real} "$@"\n'
        )

    def _stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}", encoding="ascii")
        path.chmod(0o755)

    def stage_artifact(self, *, package: str = "gatebsd-2.9.4.pkg", signed: bool = True) -> None:
        """Write a plausible signed artifact tree: package plus tar catalogues."""
        (self.artifact_dir / package).write_bytes(b"package payload\n")
        (self.artifact_dir / "SHA256").write_text(
            f"SHA256 (./{package}) = 0\n", encoding="ascii"
        )
        (self.artifact_dir / "build.log").write_text("built\n", encoding="ascii")
        members = ["packagesite.yaml"]
        if signed:
            members.insert(0, "signature")
        for catalogue in ("packagesite.pkg", "data.pkg"):
            self._write_tar(self.artifact_dir / catalogue, members)

    def _write_tar(self, path: Path, members: list[str]) -> None:
        import tarfile

        staging = self.root / "tarstage"
        staging.mkdir(exist_ok=True)
        with tarfile.open(path, "w") as archive:
            for member in members:
                blob = staging / member
                blob.write_bytes(b"x")
                archive.add(blob, arcname=member)

    def make_build(self, build_id: str, *, package: str = "gatebsd.pkg") -> Path:
        """Create a previously published build directly under the release root."""
        target = self.release_root / "builds" / build_id
        target.mkdir(parents=True, exist_ok=True)
        (target / package).write_bytes(b"old package\n")
        return target

    def link_version(self, version: str, build_id: str) -> None:
        versions = self.release_root / "versions"
        versions.mkdir(parents=True, exist_ok=True)
        (versions / version).symlink_to(Path("..") / "builds" / build_id)

    def link_current(self, build_id: str) -> None:
        self.release_root.mkdir(parents=True, exist_ok=True)
        (self.release_root / "current").symlink_to(Path("builds") / build_id)

    def _preamble(self, *, package: str, build_id: str | None = None) -> str:
        return f"""
PATH={self.bin}:/usr/bin:/bin
export PATH
set -euf
BUILD_ID={build_id or self.BUILD_ID}
RELEASE_ROOT={self.release_root}
ARTIFACT_DIR={self.artifact_dir}
PACKAGE={self.artifact_dir}/{package}
{self.functions}
"""

    def publish(
        self, *, version: str = "2.9.4", package: str = "gatebsd-2.9.4.pkg",
        build_id: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        script = self._preamble(package=package, build_id=build_id) + f"""
publish_release {version}
printf 'publish exit=%s\\n' "$?"
"""
        return self._run(script)

    def prune(self, keep: int, *, package: str = "gatebsd-2.9.4.pkg") -> subprocess.CompletedProcess[str]:
        script = self._preamble(package=package) + f"""
prune_releases {keep}
printf 'prune exit=%s\\n' "$?"
"""
        return self._run(script)

    def _run(self, script: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", "-c", script], check=False, capture_output=True, text=True
        )


class ReleasePublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = ReleasePublishHarness(Path(self._tmp.name))
        self.release_root = self.harness.release_root

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_publish_exposes_the_release_at_a_stable_version_url(self) -> None:
        """The reason this feature exists: 2.9.4 must have a derivable path."""
        self.harness.stage_artifact()
        result = self.harness.publish(version="2.9.4")
        self.assertIn("publish exit=0", result.stdout, result.stderr)

        version_path = self.release_root / "versions" / "2.9.4"
        self.assertTrue(version_path.is_symlink(), "versions/2.9.4 must be a symlink")
        self.assertTrue(version_path.is_dir(), "versions/2.9.4 must resolve")
        self.assertTrue((version_path / "gatebsd-2.9.4.pkg").is_file())
        self.assertTrue((version_path / "packagesite.pkg").is_file())

    def test_publish_points_current_at_the_new_release(self) -> None:
        self.harness.stage_artifact()
        self.harness.publish()
        current = self.release_root / "current"
        self.assertTrue(current.is_symlink())
        self.assertEqual(
            current.readlink().as_posix(), f"builds/{self.harness.BUILD_ID}"
        )
        self.assertTrue((current / "gatebsd-2.9.4.pkg").is_file())

    def test_republishing_replaces_the_current_symlink_rather_than_nesting(self) -> None:
        """`mv` without -h would move the link *into* the directory it targets."""
        self.harness.stage_artifact()
        self.harness.publish()
        second = "20260131T120000Z-fedcba654321"
        result = self.harness.publish(version="2.9.5", build_id=second)
        self.assertIn("publish exit=0", result.stdout, result.stderr)

        current = self.release_root / "current"
        self.assertTrue(current.is_symlink())
        self.assertEqual(current.readlink().as_posix(), f"builds/{second}")
        self.assertFalse((self.release_root / "builds" / second / "builds").exists())
        # Both versions remain independently addressable.
        for version in ("2.9.4", "2.9.5"):
            with self.subTest(version=version):
                self.assertTrue((self.release_root / "versions" / version).is_dir())

    def test_publish_refuses_an_unsigned_catalogue(self) -> None:
        """An unsigned release must never reach a stable URL."""
        self.harness.stage_artifact(signed=False)
        result = self.harness.publish()
        self.assertNotIn("publish exit=0", result.stdout)
        self.assertIn("not signed", result.stderr)
        self.assertFalse((self.release_root / "versions" / "2.9.4").exists())
        self.assertFalse((self.release_root / "current").exists())

    def test_publish_refuses_when_the_package_is_missing(self) -> None:
        self.harness.stage_artifact()
        (self.harness.artifact_dir / "gatebsd-2.9.4.pkg").unlink()
        result = self.harness.publish()
        self.assertNotIn("publish exit=0", result.stdout)
        self.assertIn("missing the package", result.stderr)
        self.assertFalse((self.release_root / "current").exists())

    def test_a_failed_publish_leaves_no_staging_directory_behind(self) -> None:
        self.harness.stage_artifact(signed=False)
        self.harness.publish()
        builds = self.release_root / "builds"
        if builds.exists():
            leftovers = [p.name for p in builds.iterdir() if p.name.startswith(".staging")]
            self.assertEqual(leftovers, [], "staging tree must not be advertised")


class ReleaseRetentionTests(unittest.TestCase):
    """The deletion regression: pruning must never orphan an advertised URL."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = ReleasePublishHarness(Path(self._tmp.name))
        self.release_root = self.harness.release_root

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_a_version_still_advertised_is_never_pruned(self) -> None:
        """The core regression.

        prune_builds() deleted by age alone, which is what destroyed the only
        copy of a signed release while its URL was still published.
        """
        old = "20260101T000000Z-aaaaaaaaaaaa"
        self.harness.make_build(old)
        self.harness.link_version("2.9.3", old)
        self.harness.stage_artifact()
        self.harness.publish()

        result = self.harness.prune(1)
        self.assertIn("prune exit=0", result.stdout, result.stderr)
        self.assertTrue(
            (self.release_root / "builds" / old).is_dir(),
            "a build referenced by versions/2.9.3 must survive retention",
        )
        self.assertTrue((self.release_root / "versions" / "2.9.3").is_dir())

    def test_the_build_behind_current_is_never_pruned(self) -> None:
        old = "20260101T000000Z-aaaaaaaaaaaa"
        self.harness.make_build(old)
        self.harness.link_current(old)
        self.harness.prune(0)
        self.assertTrue((self.release_root / "builds" / old).is_dir())
        self.assertTrue((self.release_root / "current").is_dir())

    def test_an_unreferenced_superseded_build_is_reclaimed(self) -> None:
        """Retention still has to bound growth."""
        old = "20260101T000000Z-aaaaaaaaaaaa"
        self.harness.make_build(old)
        self.harness.stage_artifact()
        self.harness.publish()
        self.harness.prune(1)
        self.assertFalse(
            (self.release_root / "builds" / old).exists(),
            "an unreferenced old build must be reclaimed",
        )

    def test_the_release_being_published_is_never_pruned(self) -> None:
        self.harness.stage_artifact()
        self.harness.publish()
        self.harness.prune(0)
        self.assertTrue(
            (self.release_root / "builds" / self.harness.BUILD_ID).is_dir()
        )
        self.assertTrue((self.release_root / "versions" / "2.9.4").is_dir())

    def test_a_dangling_version_symlink_is_dropped(self) -> None:
        """pkg(8) reports a fetch error for a dangling repo, not an absent one."""
        self.harness.link_version("9.9.9", "20260101T000000Z-cccccccccccc")
        self.harness.stage_artifact()
        self.harness.publish()
        self.harness.prune(5)
        self.assertFalse((self.release_root / "versions" / "9.9.9").is_symlink())

    def test_pruning_an_empty_release_root_is_not_an_error(self) -> None:
        result = self.harness.prune(10)
        self.assertIn("prune exit=0", result.stdout, result.stderr)


class ReleasePublicationContractTests(unittest.TestCase):
    """Guards against the specific shape of the original defect."""

    def setUp(self) -> None:
        self.source = BUILD_SCRIPT.read_text(encoding="utf-8")

    def test_releases_are_not_published_under_the_pruned_artifact_root(self) -> None:
        # The default is itself an expansion now -- the release root is rooted
        # at ${PROJECT_SLUG}, because one stand serves more than one product.
        # `[^}]+` stopped at that inner brace and read the default as
        # unparseable; the greedy form takes the outer `}` instead.
        match = re.search(r"^RELEASE_ROOT=\$\{RELEASE_ROOT:-(.+)\}$", self.source, re.MULTILINE)
        self.assertIsNotNone(match, "RELEASE_ROOT must be defined and overridable")
        release_root = match.group(1)
        self.assertNotIn(
            "/tank/ci/artifacts",
            release_root,
            "publishing releases inside the pruned artifact root is the defect "
            "this change exists to fix",
        )

    def test_build_retention_never_walks_the_release_root(self) -> None:
        body = extract_function(self.source, "prune_builds")
        self.assertNotIn(
            "RELEASE_ROOT",
            body,
            "prune_builds() must not reach into the release tree; retention "
            "there is version-aware and lives in prune_releases()",
        )

    def test_release_retention_consults_the_symlinks_before_deleting(self) -> None:
        body = extract_function(self.source, "prune_releases")
        self.assertIn("readlink", body)
        self.assertRegex(
            body,
            r"grep -qxF \"\$_stale\" \"\$_referenced\"",
            "a build must be checked against the advertised symlinks before removal",
        )

    def test_the_stable_release_url_is_reported_to_the_operator(self) -> None:
        # The build ID URL alone is what made the release undiscoverable.
        self.assertIn("RELEASE_URL=", self.source)
        self.assertIn("CURRENT_URL=", self.source)

    def test_the_version_comes_from_the_package_not_the_checkout(self) -> None:
        self.assertRegex(
            self.source,
            r"VERSION=\$\(pkg query -F \"\$PACKAGE\" '%v'\)",
            "the published path must match the package an operator installs",
        )

    def test_the_published_version_is_validated_as_a_path_component(self) -> None:
        # The version reaches a filesystem path and a URL, so constrain it.
        self.assertRegex(self.source, r"grep -qE '\^\[0-9A-Za-z\._,\+-\]\+\$'")

    def test_release_traversal_does_not_rely_on_globs_under_set_f(self) -> None:
        """The script runs under `set -f`; a glob would never expand."""
        body = extract_function(self.source, "prune_releases")
        self.assertNotRegex(
            body,
            r'"\$\{?RELEASE_ROOT\}?"?/(versions|builds)/\*',
            "pathname expansion is disabled in this script, so retention must "
            "enumerate with find(1) rather than a glob",
        )


if __name__ == "__main__":
    unittest.main()
