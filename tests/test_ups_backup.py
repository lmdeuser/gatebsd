"""NUT backup/restore is one five-file configuration transaction."""
from __future__ import annotations

import unittest
from pathlib import Path

from gatebsd_ui import backup, paths


def payloads(password: str = "device-secret") -> list[tuple[Path, bytes, int]]:
    return [
        (paths.NUT_CONF, b"MODE=netserver\n", 0o640),
        (paths.UPS_CONF, b"[ippon]\n    driver = nutdrv_qx\n    port = /dev/cuaU0\n", 0o640),
        (paths.UPSD_CONF, b"LISTEN 127.0.0.1 3493\n", 0o640),
        (paths.UPSD_USERS, f"[upsmon-master]\n    password = {password}\n    upsmon primary\n".encode(), 0o640),
        (paths.UPSMON_CONF, b"MONITOR ippon@localhost 1 upsmon-master device-secret primary\n", 0o640),
    ]


class UpsBackupTests(unittest.TestCase):
    def test_all_live_nut_files_are_in_the_known_backup_set(self) -> None:
        expected = {paths.NUT_CONF, paths.UPS_CONF, paths.UPSD_CONF, paths.UPSD_USERS, paths.UPSMON_CONF}
        self.assertTrue(expected.issubset(set(paths.CONFIG_FILES.values())))

    def test_complete_consistent_snapshot_is_accepted(self) -> None:
        self.assertEqual(backup._validate_nut_restore_payloads(payloads()), [])

    def test_partial_snapshot_is_rejected_before_any_file_is_restored(self) -> None:
        errors = backup._validate_nut_restore_payloads(payloads()[:-1])
        self.assertTrue(any("incomplete" in error for error in errors), errors)

    def test_mismatched_credentials_are_rejected(self) -> None:
        errors = backup._validate_nut_restore_payloads(payloads("different-secret"))
        self.assertTrue(any("do not match" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
