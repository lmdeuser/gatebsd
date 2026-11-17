#!/usr/bin/env python3
"""The panel must report a big blocklist as working.

Reintroducing the defect: with the blocklist read through a size-capped whole
file read, a list past the cap comes back as an empty string, and an empty
string is indistinguishable from an empty blocklist. The panel then showed
"filtering inactive, 0 blocked domains" while the resolver was in
fact answering 0.0.0.0 for 255881 names -- a device lying about its own
working state, which is worse than one that is merely broken.

Growing the cap would only move the cliff. The header carries the total, so the
panel reads the head and never touches the body.
"""
import unittest
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))

from gatebsd_ui import adblock  # noqa: E402

HEADER = """# GateBSD Ad Blocker
# Sources: https://example.invalid/one https://example.invalid/two
# Sources used: 5
# Verdict: always_null
# Allowlisted by source authors: 2
# Generated: 2026-08-02 15:21 UTC
# Total: 255881 domains
server:
"""


def _write_blocklist(path: Path, zones: int) -> None:
    with path.open("w", encoding="utf-8") as handle:
        handle.write(HEADER)
        for index in range(zones):
            handle.write(f'    local-zone: "n{index}.example." always_null\n')


class LargeBlocklist(unittest.TestCase):
    def test_a_list_past_the_old_eight_megabyte_cap_is_still_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "adblock.conf"
            _write_blocklist(path, 200_000)
            self.assertGreater(
                path.stat().st_size,
                8 * 1024 * 1024,
                "fixture must exceed the cap that caused the defect",
            )
            head = adblock._read_head(path)
            self.assertIn("# Total: 255881 domains", head)

    def test_header_is_found_without_reading_the_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "adblock.conf"
            _write_blocklist(path, 200_000)
            head = adblock._read_head(path)
            self.assertLessEqual(len(head.encode()), 65536)
            self.assertIn("Verdict: always_null", head)

    def test_counting_falls_back_to_streaming_when_the_header_is_absent(self):
        """An older blocklist has no Total line; counting must still work."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "adblock.conf"
            with path.open("w", encoding="utf-8") as handle:
                handle.write("server:\n")
                for index in range(50_000):
                    handle.write(f'    local-zone: "n{index}.example." always_null\n')
            self.assertEqual(adblock._count_zones(path), 50_000)

    def test_missing_file_counts_zero_rather_than_raising(self):
        self.assertEqual(adblock._count_zones(Path("/nonexistent/adblock.conf")), 0)
        self.assertEqual(adblock._read_head(Path("/nonexistent/adblock.conf")), "")


if __name__ == "__main__":
    unittest.main()
