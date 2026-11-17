#!/usr/bin/env python3
"""Per-source run details and read-only blocked/control DNS checks."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "webui" / "backend"))

from gatebsd_ui import adblock, agent, api  # noqa: E402
from gatebsd_ui.command import CommandResult  # noqa: E402


NOERROR_ZERO = """;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 10
;; ANSWER SECTION:
blocked.example. 300 IN A 0.0.0.0
"""
NOERROR_CONTROL = """;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 11
;; ANSWER SECTION:
control.example. 300 IN A 203.0.113.10
"""
NXDOMAIN = ";; ->>HEADER<<- opcode: QUERY, rcode: NXDOMAIN, id: 12\n"
REFUSED = ";; ->>HEADER<<- opcode: QUERY, rcode: REFUSED, id: 13\n"


class RunDetailsTests(unittest.TestCase):
    def test_sources_and_last_success_are_exposed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            path.write_text(json.dumps({
                "schema": 2, "checked_at": 200, "last_success_at": 150,
                "outcome": "failed", "sources_configured": 2, "sources_used": 1,
                "sources_skipped": "https://b.invalid/hosts", "domains": None, "reason": "download",
                "sources": [
                    {"url": "https://a.invalid/hosts", "downloaded": 100, "parsed": 80, "status": "ok"},
                    {"url": "https://b.invalid/hosts", "downloaded": 0, "parsed": 0, "status": "rejected", "reason": "download_failed"},
                ],
            }), encoding="utf-8")
            with patch.object(adblock, "RUN_STATUS", path):
                state = adblock.run_status()
        self.assertEqual(state["last_success_at"], 150)
        self.assertEqual(state["sources"][0]["downloaded"], 100)
        self.assertEqual(state["sources"][0]["parsed"], 80)
        self.assertEqual(state["sources"][1]["status"], "rejected")
        self.assertEqual(state["sources"][1]["reason"], "download_failed")


class DnsProbeTests(unittest.TestCase):
    def fake_run(self, command, **_kwargs):
        host = command[1]
        answers = {
            "blocked.example": NOERROR_ZERO,
            "control.example": NOERROR_CONTROL,
            "nxdomain.example": NXDOMAIN,
            "refused.example": REFUSED,
        }
        return CommandResult(command, True, 0, answers[host], "")

    def test_null_block_and_real_control_succeed(self):
        with patch.object(adblock, "run", self.fake_run):
            status, payload = adblock.dns_probe("blocked.example", "control.example", "always_null")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["blocked"]["ok"])
        self.assertEqual(payload["blocked"]["addresses"], ["0.0.0.0"])
        self.assertTrue(payload["control"]["ok"])

    def test_nxdomain_and_refused_verdicts_are_distinguished(self):
        for verdict, host, rcode in (
            ("always_nxdomain", "nxdomain.example", "NXDOMAIN"),
            ("always_refuse", "refused.example", "REFUSED"),
        ):
            with self.subTest(verdict=verdict), patch.object(adblock, "run", self.fake_run):
                status, payload = adblock.dns_probe(host, "control.example", verdict)
            self.assertEqual(status, 200)
            self.assertTrue(payload["blocked"]["ok"], payload)
            self.assertEqual(payload["blocked"]["rcode"], rcode)

    def test_control_failure_means_the_probe_is_not_successful(self):
        with patch.object(adblock, "run", self.fake_run):
            status, payload = adblock.dns_probe("blocked.example", "nxdomain.example", "always_null")
        self.assertEqual(status, 200)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["blocked"]["ok"])
        self.assertFalse(payload["control"]["ok"])

    def test_dispatch_and_agent_allow_the_read_only_probe(self):
        body = {"blocked": "blocked.example", "control": "control.example", "verdict": "always_null"}
        with patch.object(adblock, "run", self.fake_run):
            status, payload = api.dispatch("/api/adblock/probe", {}, method="POST", body=body)
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(agent._agent_allowed("POST", "/api/adblock/probe"))

    def test_probe_uses_the_configured_unbound_interface(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "unbound.conf"
            conf.write_text("server:\n    interface: 10.88.0.1\n", encoding="ascii")
            with patch.object(adblock.paths, "UNBOUND_CONF", conf), \
                    patch.object(adblock, "run", side_effect=self.fake_run) as mocked:
                status, payload = adblock.dns_probe("blocked.example", "control.example", "always_null")
        self.assertEqual(status, 200, payload)
        self.assertEqual(mocked.call_args_list[0].args[0][3], "@10.88.0.1")

    def test_invalid_names_and_verdict_are_refused_without_calling_drill(self):
        with patch.object(adblock, "run", side_effect=AssertionError("drill must not be called")):
            status, _payload = adblock.dns_probe("bad name", "control.example", "always_null")
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
