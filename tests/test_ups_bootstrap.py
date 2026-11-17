"""Behavioural proof for per-device NUT provisioning."""
from __future__ import annotations

import os
import grp
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "sbin" / "gatebsd-ups-bootstrap"
NAMES = ("nut.conf", "ups.conf", "upsd.conf", "upsd.users", "upsmon.conf")


class UpsBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.config = self.root / "nut"
        self.templates = self.root / "templates"
        self.templates.mkdir()
        for name in NAMES:
            shutil.copy2(ROOT / "etc" / "nut" / f"{name}.sample", self.templates / f"{name}.sample")

    def run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(SCRIPT), *args], capture_output=True, text=True, check=False,
            env={
                **os.environ,
                "GATEBSD_NUT_DIR": str(self.config),
                "GATEBSD_NUT_TEMPLATE_DIR": str(self.templates),
                "GATEBSD_NUT_GROUP": grp.getgrgid(os.getgid()).gr_name,
            },
        )

    def test_empty_device_gets_complete_unique_credentials_once(self) -> None:
        first = self.run_script()
        self.assertEqual(first.returncode, 0, first.stderr)
        rendered = {name: (self.config / name).read_text(encoding="utf-8") for name in NAMES}
        self.assertNotIn("CHANGEME_", "".join(rendered.values()))
        monitor = next(line.split() for line in rendered["upsmon.conf"].splitlines() if line.startswith("MONITOR "))
        self.assertIn(f"[{monitor[3]}]", rendered["upsd.users"])
        self.assertIn(f"password = {monitor[4]}", rendered["upsd.users"])
        before = {name: (self.config / name).read_bytes() for name in NAMES}
        second = self.run_script()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(before, {name: (self.config / name).read_bytes() for name in NAMES})

    def test_partial_configuration_fails_closed_without_filling_gaps(self) -> None:
        self.config.mkdir()
        (self.config / "nut.conf").write_text("MODE=netserver\n", encoding="utf-8")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("partial", result.stderr)
        self.assertEqual([path.name for path in self.config.iterdir()], ["nut.conf"])

    def test_check_mode_never_provisions_an_empty_device(self) -> None:
        result = self.run_script("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.config.exists())

    def test_mismatched_existing_monitor_password_is_rejected(self) -> None:
        self.assertEqual(self.run_script().returncode, 0)
        path = self.config / "upsmon.conf"
        lines = path.read_text(encoding="utf-8").splitlines()
        parts = next(line.split() for line in lines if line.startswith("MONITOR "))
        parts[4] = "wrong-password"
        path.write_text(
            "\n".join(" ".join(parts) if line.startswith("MONITOR ") else line for line in lines) + "\n",
            encoding="utf-8",
        )
        result = self.run_script("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("do not match", result.stderr)

    def test_script_is_executable_for_package_delivery(self) -> None:
        self.assertTrue(os.access(SCRIPT, os.X_OK))


if __name__ == "__main__":
    unittest.main()
