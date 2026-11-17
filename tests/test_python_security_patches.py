from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PythonSecurityPatchTests(unittest.TestCase):
    def test_supported_runtime_gets_control_character_fixes(self) -> None:
        for version in ("python312",):
            overlay = ROOT / "infra" / "freebsd-ci" / "ports-overlay" / "lang" / version
            makefile = (overlay / "Makefile").read_text(encoding="utf-8")
            revision = re.search(r"^PORTREVISION=\s+(\d+)$", makefile, re.MULTILINE)
            self.assertIsNotNone(revision)
            self.assertGreaterEqual(int(revision.group(1)), 2)
            imap = (overlay / "files" / "patch-Lib-imaplib.py").read_text(encoding="utf-8")
            pop = (overlay / "files" / "patch-Lib-poplib.py").read_text(encoding="utf-8")
            self.assertIn("_control_chars", imap)
            self.assertIn("Control characters not allowed in commands", imap)
            self.assertIn("Control characters not allowed in commands", pop)

    def test_overlay_files_are_deployed_by_the_manifest(self) -> None:
        manifest = (ROOT / "infra" / "freebsd-ci" / "deployment.manifest").read_text(encoding="utf-8")
        for version in ("python312",):
            for name in ("Makefile", "Makefile.version", "pkg-descr", "pkg-plist", "files/patch-Lib-imaplib.py", "files/patch-Lib-poplib.py", "files/pkg-message.in"):
                relative = f"infra/freebsd-ci/ports-overlay/lang/{version}/{name}"
                self.assertIn(relative, manifest)
        self.assertNotIn("lang/python311", manifest)

    def test_makefile_version_is_not_a_leftover(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            makefile = root / "Makefile"
            makefile.write_text("", encoding="ascii")
            (root / "Makefile.version").write_text("", encoding="ascii")
            stale = root / "Makefile.bak"
            stale.write_text("", encoding="ascii")
            bin_dir = root / "bin"
            bin_dir.mkdir()
            pkg = bin_dir / "pkg"
            pkg.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
            pkg.chmod(0o755)
            script = ROOT / "infra" / "freebsd-ci" / "leftovers.sh"
            result = subprocess.run(
                ["sh", "-c", f'. "{script}"; leftovers_beside "$1"', "sh", str(makefile)],
                capture_output=True,
                text=True,
                env={"PATH": f"{bin_dir}:/usr/bin:/bin"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(stale))

    def test_agent_fetch_is_noninteractive(self) -> None:
        script = (ROOT / "sbin" / "gatebsd-agentctl").read_text(encoding="utf-8")
        self.assertIn("pkg fetch -y -r gatebsd-releases", script)

    def test_agent_updates_supported_python_runtime(self) -> None:
        script = (ROOT / "sbin" / "gatebsd-agentctl").read_text(encoding="utf-8")
        updates_block = script.split("pkg-security-updates)", 1)[1].split(";;", 1)[0]
        self.assertIn("rsync p5-Authen-SASL python312", updates_block)
        self.assertNotIn("python311", updates_block)

    def test_overlay_versions_match_the_current_ports_tree(self) -> None:
        expected = {"python312": "3.12.16"}
        for port, version in expected.items():
            with self.subTest(port=port):
                makefile = (
                    ROOT / "infra" / "freebsd-ci" / "ports-overlay" / "lang" / port / "Makefile.version"
                ).read_text(encoding="utf-8")
                self.assertIn(f"PYTHON_DISTVERSION=\t{version}", makefile)


if __name__ == "__main__":
    unittest.main()
