import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from gatebsd_ui import storage


class StorageMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Path(self.tempdir.name) / "state.db"
        self.previous = os.environ.get("GATEBSD_DB_PATH")
        os.environ["GATEBSD_DB_PATH"] = str(self.db)

    def tearDown(self) -> None:
        if self.previous is None:
            os.environ.pop("GATEBSD_DB_PATH", None)
        else:
            os.environ["GATEBSD_DB_PATH"] = self.previous
        self.tempdir.cleanup()

    def test_initial_migration_is_idempotent(self) -> None:
        self.assertEqual(storage.migrate(), storage.SCHEMA_VERSION)
        self.assertEqual(storage.migrate(), storage.SCHEMA_VERSION)
        with sqlite3.connect(self.db) as conn:
            tables = {row[0] for row in conn.execute(
                "select name from sqlite_master where type='table'"
            )}
        self.assertTrue({"snapshots", "events", "device_last_seen"}.issubset(tables))

    def test_newer_schema_is_rejected(self) -> None:
        with sqlite3.connect(self.db) as conn:
            conn.execute(f"pragma user_version={storage.SCHEMA_VERSION + 1}")
        with self.assertRaisesRegex(RuntimeError, "newer than supported"):
            storage.migrate()


if __name__ == "__main__":
    unittest.main()
