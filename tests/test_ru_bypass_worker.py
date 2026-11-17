"""The supervised RU worker receives the requested underlay, not the caller's lock."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RC_SCRIPT = ROOT / "rc.d" / "ru_bypass"


@unittest.skipUnless(Path("/etc/rc.subr").exists(), "FreeBSD rc.subr is required")
class WorkerEnvironmentTests(unittest.TestCase):
    def test_explicit_underlay_reaches_the_helper_without_the_outer_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            helper = root / "ru-routes.sh"
            helper.write_text(
                f"""#!/bin/sh
printf '%s\\n' "$1" > {report}
printf 'iface=%s\\n' "$GATEBSD_ACTIVE_WAN_IF" >> {report}
printf 'gateway=%s\\n' "$GATEBSD_ACTIVE_WAN_GW" >> {report}
printf 'reader=%s\\n' "$GATEBSD_STATE_READER" >> {report}
printf 'table=%s\\n' "$RU_TABLE" >> {report}
printf 'state=%s\\n' "$RU_STATE_FILE" >> {report}
printf 'held=%s\\n' "${{GATEBSD_GATEWAY_LOCK_HELD:-}}" >> {report}
""",
                encoding="ascii",
            )
            helper.chmod(0o755)
            result = subprocess.run(
                ["sh", str(RC_SCRIPT), "__ru-worker", "apply"],
                check=False,
                capture_output=True,
                text=True,
                env={
                    "PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
                    "GATEBSD_RU_ROUTES_HELPER": str(helper),
                    "GATEBSD_STATE_READER": "/test/state-reader",
                    "GATEBSD_ACTIVE_WAN_IF": "ue0",
                    "GATEBSD_ACTIVE_WAN_GW": "192.168.0.1",
                    "GATEBSD_GATEWAY_LOCK_HELD": "1",
                    "RU_TABLE": "/test/ru.table",
                    "RU_STATE_FILE": "/test/ru.state",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            values = dict(
                line.split("=", 1)
                for line in report.read_text(encoding="ascii").splitlines()[1:]
            )
            self.assertEqual(report.read_text(encoding="ascii").splitlines()[0], "apply")
            self.assertEqual(values["iface"], "ue0")
            self.assertEqual(values["gateway"], "192.168.0.1")
            self.assertEqual(values["reader"], "/test/state-reader")
            self.assertEqual(values["table"], "/test/ru.table")
            self.assertEqual(values["state"], "/test/ru.state")
            self.assertEqual(values["held"], "")


if __name__ == "__main__":
    unittest.main()
