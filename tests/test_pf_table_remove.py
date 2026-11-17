from __future__ import annotations

import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


def _write_table(p: Path, content: str) -> None:
    p.write_text(content)


def _read_table(p: Path) -> str:
    return p.read_text()


class PfTableRemoveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.table = Path(self.td.name) / "ru_bypass.table"
        self.backup_dir = Path(self.td.name) / "backups"
        self.backup_dir.mkdir(mode=0o700)
        self.table.write_text("")
        self.patcher = patch("gatebsd_ui.api.RU_TABLE", self.table)
        self.backup_patcher = patch("gatebsd_ui.paths.BACKUP_DIR", self.backup_dir)
        self.patcher.start()
        self.backup_patcher.start()

    def tearDown(self) -> None:
        self.backup_patcher.stop()
        self.patcher.stop()
        self.td.cleanup()

    # --- basic filtering ---

    def test_remove_single_cidr_preserves_others(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "# comment\n1.1.1.0/24\n2.2.2.0/24\n3.3.3.0/24\n")
        status, body = _pf_table_remove({"values": ["2.2.2.0/24"]})
        self.assertEqual(status, 200)
        result = _read_table(self.table)
        self.assertIn("# comment", result)
        self.assertIn("1.1.1.0/24", result)
        self.assertIn("3.3.3.0/24", result)
        self.assertNotIn("2.2.2.0/24", result)

    def test_remove_multiple_cidrs(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "1.1.1.0/24\n2.2.2.0/24\n3.3.3.0/24\n4.4.4.0/24\n")
        status, body = _pf_table_remove({"values": ["1.1.1.0/24", "3.3.3.0/24"]})
        self.assertEqual(status, 200)
        result = _read_table(self.table)
        self.assertNotIn("1.1.1.0/24", result)
        self.assertNotIn("3.3.3.0/24", result)
        self.assertIn("2.2.2.0/24", result)
        self.assertIn("4.4.4.0/24", result)

    def test_remove_absent_cidr(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        original = "1.1.1.0/24\n2.2.2.0/24\n"
        _write_table(self.table, original)
        status, body = _pf_table_remove({"values": ["9.9.9.0/24"]})
        self.assertEqual(status, 200)
        self.assertEqual(body["removed"], 0)
        self.assertEqual(_read_table(self.table), original)

    def test_preserves_comments_and_blank_lines(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "# header\n\n1.1.1.0/24\n\n# middle\n2.2.2.0/24\n\n")
        status, _ = _pf_table_remove({"values": ["1.1.1.0/24"]})
        self.assertEqual(status, 200)
        result = _read_table(self.table)
        self.assertEqual(result.count("# header"), 1)
        self.assertEqual(result.count("# middle"), 1)
        self.assertNotIn("1.1.1.0/24", result)
        self.assertIn("2.2.2.0/24", result)

    def test_order_preserved(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "1.1.1.0/24\n2.2.2.0/24\n3.3.3.0/24\n4.4.4.0/24\n")
        status, _ = _pf_table_remove({"values": ["2.2.2.0/24", "4.4.4.0/24"]})
        self.assertEqual(status, 200)
        lines = [l for l in _read_table(self.table).splitlines() if l.strip()]
        self.assertEqual(lines, ["1.1.1.0/24", "3.3.3.0/24"])

    def test_comment_with_leading_spaces_preserved(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "  # indented comment\n1.1.1.0/24\n")
        _pf_table_remove({"values": ["1.1.1.0/24"]})
        result = _read_table(self.table)
        self.assertIn("# indented comment", result)

    # --- no-write when nothing removed ---

    def test_no_write_when_nothing_removed(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        original = b"a\nb"
        self.table.write_bytes(original)
        replace_calls: list[bool] = []
        real_replace = os.replace

        def tracking_replace(src: str, dst: str) -> None:
            replace_calls.append(True)
            return real_replace(src, dst)

        with patch("gatebsd_ui.api.os.replace", tracking_replace):
            status, body = _pf_table_remove({"values": ["9.9.9.0/24"]})
        self.assertEqual(status, 200)
        self.assertEqual(body["removed"], 0)
        self.assertEqual(self.table.read_bytes(), original)
        self.assertEqual(replace_calls, [])

    def test_no_trailing_newline_preserved(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        original = b"a\nb"
        self.table.write_bytes(original)
        _pf_table_remove({"values": ["9.9.9.0/24"]})
        self.assertEqual(self.table.read_bytes(), original)

    # --- error / edge cases ---

    def test_missing_table_returns_404(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        self.table.unlink(missing_ok=True)
        status, body = _pf_table_remove({"values": ["1.1.1.0/24"]})
        self.assertEqual(status, 404)

    def test_replace_failure_preserves_original(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        original = "# header\n1.1.1.0/24\n"
        _write_table(self.table, original)

        def broken_replace(src: str, dst: str) -> None:
            raise OSError("simulated replace failure")

        with patch("gatebsd_ui.api.os.replace", broken_replace):
            status, body = _pf_table_remove({"values": ["1.1.1.0/24"]})
        self.assertEqual(status, 500)
        self.assertIn("failed to update table", body.get("error", ""))
        self.assertEqual(_read_table(self.table), original)

    def test_mode_preserved(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "1.1.1.0/24\n2.2.2.0/24\n")
        os.chmod(self.table, 0o640)
        original_mode = os.stat(self.table).st_mode
        _pf_table_remove({"values": ["1.1.1.0/24"]})
        self.assertEqual(os.stat(self.table).st_mode, original_mode)

    def test_no_temp_files_after_error(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "1.1.1.0/24\n")
        before = set(self.table.parent.iterdir())

        def broken_replace(src: str, dst: str) -> None:
            raise OSError("simulated")

        with patch("gatebsd_ui.api.os.replace", broken_replace):
            status, body = _pf_table_remove({"values": ["1.1.1.0/24"]})
        self.assertEqual(status, 500)
        self.assertIn("failed to update table", body.get("error", ""))
        after = set(self.table.parent.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set(), f"temp files left: {new_files}")

    def test_different_temp_file_names(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        names: list[str] = []
        real_mkdtemp = tempfile.mkstemp

        def tracking_mkdtemp(**kwargs: object) -> tuple[int, str]:  # type: ignore[override]
            fd, name = real_mkdtemp(**kwargs)  # type: ignore[arg-type]
            names.append(name)
            return fd, name

        with patch("gatebsd_ui.fsutil.tempfile.mkstemp", tracking_mkdtemp):
            _write_table(self.table, "1.1.1.0/24\n2.2.2.0/24\n")
            _pf_table_remove({"values": ["1.1.1.0/24"]})
            _pf_table_remove({"values": ["2.2.2.0/24"]})
        table_names = [name for name in names if Path(name).name.startswith(f".{self.table.name}.")]
        self.assertEqual(len(table_names), 2)
        self.assertNotEqual(table_names[0], table_names[1])

    def test_cleanup_error_does_not_mask_replace_error(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "1.1.1.0/24\n2.2.2.0/24\n")
        original = _read_table(self.table)

        def broken_replace(src: str, dst: str) -> None:
            raise OSError("replace failed")

        def broken_unlink(self_path: Path, **kwargs: object) -> None:
            raise OSError("unlink failed")

        with (
            patch("gatebsd_ui.api.os.replace", broken_replace),
            patch.object(Path, "unlink", broken_unlink),
        ):
            status, body = _pf_table_remove({"values": ["1.1.1.0/24"]})
        self.assertEqual(status, 500)
        self.assertIn("replace failed", body.get("error", ""))
        self.assertEqual(_read_table(self.table), original)

    # --- concurrency ---

    def test_concurrent_removal(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "1.1.1.0/24\n2.2.2.0/24\n3.3.3.0/24\n")
        errors: list[Exception] = []

        def remove_a() -> None:
            try:
                _pf_table_remove({"values": ["1.1.1.0/24"]})
            except Exception as e:
                errors.append(e)

        def remove_b() -> None:
            try:
                _pf_table_remove({"values": ["2.2.2.0/24"]})
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=remove_a)
        t2 = threading.Thread(target=remove_b)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        self.assertEqual(errors, [])
        result = _read_table(self.table)
        lines = [l.strip() for l in result.splitlines() if l.strip()]
        self.assertEqual(lines, ["3.3.3.0/24"])

    # --- lock file ---

    def test_lock_file_permissions(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "1.1.1.0/24\n")
        lock_path = self.table.with_suffix(self.table.suffix + ".lock")
        self.assertFalse(lock_path.exists())
        _pf_table_remove({"values": ["1.1.1.0/24"]})
        mode = os.stat(lock_path).st_mode
        self.assertEqual(mode & 0o111, 0, "lock file must have no exec bits")
        self.assertEqual(mode & 0o077, 0, "lock file must not be group/other accessible")

    # --- validation ---

    def test_missing_values_returns_400(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        status, body = _pf_table_remove({})
        self.assertEqual(status, 400)

    def test_empty_list_returns_400(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        status, body = _pf_table_remove({"values": []})
        self.assertEqual(status, 400)

    def test_values_not_list_returns_400(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        status, body = _pf_table_remove({"values": "1.1.1.0/24"})
        self.assertEqual(status, 400)

    def test_values_non_string_returns_400(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        status, body = _pf_table_remove({"values": [123]})
        self.assertEqual(status, 400)

    def test_only_whitespace_returns_400(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        status, body = _pf_table_remove({"values": ["  ", "\t"]})
        self.assertEqual(status, 400)

    def test_validation_error_no_file_change(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        original = b"a\nb\n"
        self.table.write_bytes(original)
        lock_path = self.table.with_suffix(self.table.suffix + ".lock")
        _pf_table_remove({"values": []})
        self.assertEqual(self.table.read_bytes(), original)
        self.assertFalse(lock_path.exists())

    def test_duplicates_accepted(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "1.1.1.0/24\n2.2.2.0/24\n")
        status, body = _pf_table_remove({"values": ["1.1.1.0/24", "1.1.1.0/24"]})
        self.assertEqual(status, 200)
        self.assertEqual(body["removed"], 1)
        self.assertNotIn("1.1.1.0/24", _read_table(self.table))
        self.assertIn("2.2.2.0/24", _read_table(self.table))

    def test_values_stripped(self) -> None:
        from gatebsd_ui.api import _pf_table_remove

        _write_table(self.table, "1.1.1.0/24\n2.2.2.0/24\n")
        status, body = _pf_table_remove({"values": ["  1.1.1.0/24  "]})
        self.assertEqual(status, 200)
        self.assertEqual(body["removed"], 1)
        self.assertNotIn("1.1.1.0/24", _read_table(self.table))


if __name__ == "__main__":
    unittest.main()
