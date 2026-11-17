"""Recovery must not compete with an in-flight failover request."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gatebsd_ui import recovery


class PendingFailoverTests(unittest.TestCase):
    def test_recovery_returns_busy_without_running_any_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "watchdog.json"
            state.write_text(
                json.dumps({"request_id": "request-42", "request_status": "pending"}),
                encoding="ascii",
            )
            with (
                mock.patch.object(recovery.paths, "FAILOVER_STATE", state),
                mock.patch.object(recovery, "LOCK_PATH", root / "recovery.lock"),
                mock.patch.object(recovery, "run") as run,
            ):
                status, report = recovery.recover_internet()

        self.assertEqual(status, 409)
        self.assertTrue(report["busy"])
        self.assertIn("request-42", report["message"])
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
