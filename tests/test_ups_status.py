#!/usr/bin/env python3
"""UPS telemetry must expose measurement time and suspicious readings."""
from __future__ import annotations

import importlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "webui" / "backend"))

from gatebsd_ui import api, paths  # noqa: E402
firewall = importlib.import_module("gatebsd_ui.adapters.firewall")  # noqa: E402
from gatebsd_ui.command import CommandResult  # noqa: E402


class UpsStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "ups-health.state"
        marker = object()
        self.previous = getattr(paths, "UPS_HEALTH_STATE", marker)
        paths.UPS_HEALTH_STATE = self.state
        self.addCleanup(self.restore_path, marker)
        self.telemetry = (
            "battery.charge: 100\n"
            "battery.voltage: 27.2\n"
            "ups.status: OL\n"
            "ups.load: 0\n"
            "input.voltage: 220\n"
        )
        self.measurement_ok = True

    def restore_path(self, marker) -> None:
        if self.previous is marker:
            del paths.UPS_HEALTH_STATE
        else:
            paths.UPS_HEALTH_STATE = self.previous

    def fake_run(self, command, **_kwargs):
        if command == ["/usr/local/bin/upsc", "-l"]:
            return CommandResult(command, True, 0, "ippon\n", "")
        if command[:2] == ["/usr/local/bin/upsc", "ippon@localhost"]:
            return CommandResult(
                command, self.measurement_ok, 0 if self.measurement_ok else 1,
                self.telemetry if self.measurement_ok else "",
                "" if self.measurement_ok else "connection refused",
            )
        if command[:2] == ["/usr/local/bin/upscmd", "-l"]:
            return CommandResult(command, True, 0, "beeper.toggle - Toggle beeper\n", "")
        raise AssertionError(command)

    def measure(self):
        with patch.object(firewall, "run", self.fake_run):
            return firewall.ups()

    def write_state(self, text: str) -> None:
        self.state.write_text(text, encoding="utf-8")

    def test_current_measurement_and_periodic_check_are_both_exposed(self) -> None:
        self.write_state("schema=1\nchecked_at=100\nok=true\nerrors=0\nlast_response_at=90\nstatus=OL\n")
        payload = self.measure()
        self.assertTrue(payload["ok"])
        self.assertIsInstance(payload["checked_at"], int)
        self.assertGreaterEqual(payload["last_response_at"], payload["checked_at"])
        self.assertEqual(payload["last_check"]["checked_at"], 100)
        self.assertTrue(payload["last_check"]["ok"])
        self.assertEqual(payload["last_check"]["errors"], 0)

    def test_connection_loss_keeps_the_previous_response_time(self) -> None:
        self.write_state("schema=1\nchecked_at=100\nok=false\nerrors=2\nlast_response_at=90\n")
        self.measurement_ok = False
        payload = self.measure()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["last_response_at"], 90)
        self.assertFalse(payload["last_check"]["ok"])
        self.assertEqual(payload["last_check"]["errors"], 2)

    def test_missing_health_state_is_unknown_not_success(self) -> None:
        payload = self.measure()
        self.assertFalse(payload["last_check"]["available"])

    def test_suspicious_values_are_named(self) -> None:
        self.telemetry = "battery.charge: unknown\nups.status: OL\nups.load: 150\ninput.voltage: 0\n"
        payload = self.measure()
        warnings = " | ".join(payload["warnings"])
        self.assertIn("charge", warnings.lower())
        self.assertIn("input", warnings.lower())
        self.assertIn("load", warnings.lower())

    def test_api_dispatch_carries_the_same_contract(self) -> None:
        with patch.object(firewall, "run", self.fake_run):
            status, payload = api.dispatch("/api/ups", {})
        self.assertEqual(status, 200)
        self.assertIn("checked_at", payload)
        self.assertIn("last_response_at", payload)
        self.assertIn("last_check", payload)
        self.assertIn("warnings", payload)


if __name__ == "__main__":
    unittest.main()
