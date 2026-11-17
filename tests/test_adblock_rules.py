#!/usr/bin/env python3
"""Local allow/block rules must survive comments and avoid duplicates."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "webui" / "backend"))

from gatebsd_ui import adblock, agent, api  # noqa: E402


class AdblockRulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "adblock-extra"
        self.path.write_text(
            "# operator comment\n0.0.0.0 ads.example.com\n@@||allowed.example^\n",
            encoding="utf-8",
        )
        self.patch = patch.object(adblock, "EXTRA_FILE", self.path)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_rules_are_read_with_direction(self) -> None:
        payload = adblock.rules()
        self.assertEqual(payload["entries"], [
            {"kind": "block", "value": "ads.example.com", "display_value": "ads.example.com"},
            {"kind": "allow", "value": "allowed.example", "display_value": "allowed.example"},
        ])

    def test_add_preserves_comments_and_duplicate_is_noop(self) -> None:
        status, body = adblock.change_rule("new.example", kind="block", add=True)
        self.assertEqual(status, 200, body)
        text = self.path.read_text(encoding="utf-8")
        self.assertIn("# operator comment", text)
        self.assertIn("0.0.0.0 new.example", text)
        before = self.path.read_bytes()
        status, body = adblock.change_rule("new.example", kind="block", add=True)
        self.assertEqual(status, 200)
        self.assertFalse(body["changed"])
        self.assertEqual(self.path.read_bytes(), before)

    def test_changing_kind_leaves_one_rule(self) -> None:
        status, _body = adblock.change_rule("ads.example.com", kind="allow", add=True)
        self.assertEqual(status, 200)
        text = self.path.read_text(encoding="utf-8")
        self.assertNotIn("0.0.0.0 ads.example.com", text)
        self.assertIn("@@||ads.example.com^", text)
        self.assertEqual(text.count("ads.example.com"), 1)

    def test_remove_preserves_other_lines(self) -> None:
        status, _body = adblock.change_rule("allowed.example", kind="allow", add=False)
        self.assertEqual(status, 200)
        text = self.path.read_text(encoding="utf-8")
        self.assertIn("# operator comment", text)
        self.assertIn("0.0.0.0 ads.example.com", text)
        self.assertNotIn("allowed.example", text)

    def test_invalid_values_are_rejected(self) -> None:
        for value in ("", "bad name", "*.example.com", "203.0.113.1", "localhost"):
            status, _body = adblock.change_rule(value, kind="block", add=True)
            self.assertEqual(status, 400, value)

    def test_dispatch_and_agent_allow_rule_editing(self) -> None:
        status, _ = api.dispatch("/api/adblock/rules", {})
        self.assertEqual(status, 200)
        status, _ = api.dispatch("/api/adblock/rules/add", {}, method="POST", body={"kind": "block", "value": "api.example"})
        self.assertEqual(status, 200)
        status, _ = api.dispatch("/api/adblock/rules/remove", {}, method="POST", body={"kind": "block", "value": "api.example"})
        self.assertEqual(status, 200)
        for path in ("/api/adblock/rules/add", "/api/adblock/rules/remove"):
            self.assertTrue(agent._agent_allowed("POST", path))
        self.assertTrue(agent._agent_allowed("GET", "/api/adblock/rules"))


if __name__ == "__main__":
    unittest.main()
