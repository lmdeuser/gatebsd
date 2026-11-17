"""The package must install both explicitly selectable Amnezia backends.

amnezia-kmod 3.1 is the default for every supported profile. Userspace
``amneziawg-go`` remains necessary when an operator or an existing stored
profile explicitly selects ``UserLand = true``. Removing it from package
dependencies would silently break that supported choice during an upgrade.

This test RUNS ``ci/build.sh`` and reads the ``manifest.ucl`` it really writes.
Asserting on the text of the script instead would pass just as happily with the
dependency sitting behind a shell conditional that never fires -- and this repo
has already paid for a test that read a script rather than executing it
(``update-freebsd-local-repo`` lost ``-O gatebsd`` in a move that no test ran).

``pkg`` and a versioned FreeBSD Python are stubbed because the assertion is
about what build.sh composes, not about the build jail's inventory: the stub
answers ``pkg query`` for any name, so a missing dependency cannot hide behind a
stub that happens not to know it.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "ci" / "build.sh"

PKG_STUB = """#!/bin/sh
name=""; fmt=""
while [ $# -gt 0 ]; do
  case "$1" in
    -e) shift; name=$(printf '%s' "$1" | sed -E 's/.*= *"([^"]+)".*/\\1/') ;;
    %v) fmt=v ;; %o) fmt=o ;;
  esac
  shift
done
case "$fmt" in
  v) echo "9.9.9" ;;
  o) echo "testing/$name" ;;
esac
"""


def build_manifest(tmp: Path) -> str:
    """Run ci/build.sh far enough to write manifest.ucl, and return it."""
    binonly = tmp / "bin"
    localbase = tmp / "local"
    (localbase / "bin").mkdir(parents=True)
    binonly.mkdir()
    (binonly / "pkg").write_text(PKG_STUB, encoding="utf-8")
    (binonly / "pkg").chmod(0o755)
    # build.sh resolves one versioned interpreter under LOCALBASE that can
    # import sqlite3; the running one qualifies.
    os.symlink(sys.executable, localbase / "bin" / f"python3.{sys.version_info.minor}")

    env = dict(os.environ)
    env["PATH"] = f"{binonly}:{env['PATH']}"
    env["LOCALBASE"] = str(localbase)
    env["STAGE"] = str(tmp / "stage")
    env["DIST"] = str(tmp / "dist")
    # `pkg create` is the last step and the stub cannot do it. The manifest is
    # written before that, which is the part under test.
    subprocess.run(
        ["sh", str(BUILD)], env=env, cwd=str(ROOT),
        capture_output=True, text=True, timeout=600, check=False,
    )
    manifest = tmp / "dist" / "manifest.ucl"
    if not manifest.is_file():
        raise AssertionError("build.sh produced no manifest.ucl")
    return manifest.read_text(encoding="utf-8")


def deps_of(manifest: str) -> dict[str, str]:
    block = re.search(r"^deps:\s*\{(.*?)^\}", manifest, re.S | re.M)
    if block is None:
        raise AssertionError("manifest.ucl has no deps block")
    found = {}
    for line in block.group(1).splitlines():
        match = re.match(r'\s*([A-Za-z0-9._+-]+):\s*\{\s*origin:\s*"([^"]+)"', line)
        if match:
            found[match.group(1)] = match.group(2)
    return found


@unittest.skipUnless(shutil.which("sh"), "needs a POSIX shell")
class PackageDependencyTests(unittest.TestCase):
    manifest: str

    @classmethod
    def setUpClass(cls) -> None:
        with tempfile.TemporaryDirectory() as raw:
            cls.manifest = build_manifest(Path(raw))

    def test_the_package_requires_the_userspace_backend(self) -> None:
        deps = deps_of(self.manifest)
        self.assertIn(
            "amneziawg-go", deps,
            "the package does not require amneziawg-go, so an existing or operator-supplied "
            "profile with UserLand = true has no backend after an upgrade",
        )

    def test_both_backends_are_required(self) -> None:
        # Kernel is the efficient default; userspace remains an explicit choice.
        deps = deps_of(self.manifest)
        for name in ("amnezia-tools", "amnezia-kmod", "amneziawg-go"):
            self.assertIn(name, deps, f"{name} is missing from the package dependencies")

    def test_every_dependency_carries_an_origin(self) -> None:
        deps = deps_of(self.manifest)
        self.assertTrue(deps, "no dependencies were parsed at all")
        for name, origin in deps.items():
            self.assertIn("/", origin, f"{name} has no category in its origin: {origin}")

    def test_the_build_jail_installs_every_dependency_the_package_declares(self) -> None:
        """The two lists must agree, because build.sh reads versions off the jail.

        ``pkg_field`` takes each dependency's version from the package
        *installed in the build jail* and exits 2 if it is not there. So adding a
        dependency to build.sh without adding it to the jail's install list does
        not produce a package missing a dependency -- it produces no package at
        all, and only the CI log says why. That is exactly how release 2.9.64
        failed on its first run: "Required package is not installed or lacks
        metadata: amneziawg-go".

        The jail used to carry its own literal list, which made it the fourth
        copy of "what the appliance needs" beside build.sh's deps, the pkglist
        and EXPECTED_ORIGINS. Three releases -- 2.9.64, 2.9.65, 2.9.66 -- died on
        that copy being one entry short. It is gone: prepare-gatebsd-build-jail.sh
        now installs the origins in gatebsd-pkglist, the same file poudriere
        builds from. So the comparison here is against the declaration itself,
        and a dependency that nobody decided the appliance needs fails.
        """
        pkglist = (ROOT / "infra" / "freebsd-ci" / "gatebsd-pkglist").read_text(encoding="utf-8")
        declared = set()
        for line in pkglist.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            origin = line.split()[0]
            # `databases/py-sqlite3@py312` -> py-sqlite3; the flavour rides on
            # the origin, and the package it produces is named for the flavour.
            declared.add(origin.split("@", 1)[0].rsplit("/", 1)[-1])
        # One name is enough to prove the file parsed. Asserting amneziawg-go
        # here too would shadow the loop below: dropping it from the pkglist is
        # exactly the defect under test, and it should fail with the sentence
        # that names the consequence, not with "did not parse as expected".
        self.assertIn("nginx", declared, "the pkglist did not parse as expected")
        for name in deps_of(self.manifest):
            # The Python package name carries the minor version the build host
            # happens to run, and the sqlite3 package name carries its flavour;
            # neither can appear literally in a list of origins. Everything else
            # must be something this project decided to build.
            if re.fullmatch(r"python3\d*|py\d+-\w+", name):
                continue
            self.assertIn(
                name, declared,
                f"{name} is a package dependency but gatebsd-pkglist does not declare it, so "
                "the build jail never installs it, build.sh cannot read its version, and the "
                "build produces nothing",
            )


if __name__ == "__main__":
    unittest.main()
