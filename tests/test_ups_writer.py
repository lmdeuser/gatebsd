import unittest
from unittest.mock import patch

from gatebsd_ui.command import CommandResult
from gatebsd_ui.writers import ups, vpn
from gatebsd_ui.writers.ups import _sections, _update_section


class UpsWriterTests(unittest.TestCase):
    def test_upsmon_role_uses_nut_directive_syntax(self) -> None:
        rendered = _update_section(
            "[monitor]\n    upsmon = secondary\n",
            "monitor",
            {"upsmon"},
            [("upsmon", "primary")],
        )

        self.assertIn("    upsmon primary\n", rendered)
        self.assertNotIn("upsmon =", rendered)
        self.assertEqual(_sections(rendered)["monitor"]["upsmon"], "primary")

    def test_ambiguous_or_exit_driver_commands_are_blocked(self) -> None:
        for command in (
            "test.battery.start", "test.battery.start.deep", "driver.reload-or-exit",
            "load.off", "shutdown.return", "shutdown.stayoff",
        ):
            with self.subTest(command=command):
                status, payload = ups.ups_command(command)
                self.assertEqual(status, 403)
                self.assertFalse(payload["ok"])

    def test_restart_requires_live_ups_telemetry(self) -> None:
        results = [
            CommandResult(command=[], ok=True, returncode=0, stdout="", stderr=""),
            CommandResult(command=[], ok=True, returncode=0, stdout="", stderr=""),
            CommandResult(command=[], ok=False, returncode=1, stdout="", stderr="connection refused"),
        ]
        with patch.object(vpn, "run", side_effect=results):
            status, payload = vpn.nut_restart()
        self.assertEqual(status, 500)
        self.assertFalse(payload["telemetry"])


if __name__ == "__main__":
    unittest.main()
