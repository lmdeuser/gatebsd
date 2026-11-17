"""The LTE button measures the whole underlay through its own FIB."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from gatebsd_ui import api, failover
from gatebsd_ui.command import CommandResult


class WanTestTests(unittest.TestCase):
    def run_test(
        self,
        *,
        icmp: bool = True,
        tcp: bool = True,
        dns: bool = True,
        https: bool = True,
    ) -> tuple[dict, list[list[str]]]:
        calls: list[list[str]] = []

        def fake_run(command, timeout=None, env=None, **kwargs):
            calls.append(list(command))
            name = Path(command[0]).name
            if name == "setfib":
                name = Path(command[2]).name
            if name == "ping":
                ok, output = icmp, "round-trip time=50.0 ms\n"
            elif name == "nc":
                ok, output = tcp, ""
            elif name == "gatebsd-python":
                ok, output = dns, "one.one.one.one\n"
            elif name == "fetch":
                ok, output = https, ""
            else:
                raise AssertionError(command)
            return CommandResult(
                command=list(command), ok=ok, returncode=0 if ok else 1,
                stdout=output, stderr="",
            )

        with (
            mock.patch.object(failover.shutil, "which", return_value="/sbin/setfib"),
            mock.patch.object(failover, "run", side_effect=fake_run),
            mock.patch.object(
                failover,
                "_check_gateway",
                return_value={"has_gw": True, "gateway": "192.168.0.1", "local_ip": "192.168.0.180"},
            ),
        ):
            _status, payload = api._wan_test("ue0")
        return payload, calls

    def test_icmp_filter_does_not_hide_a_working_lte_path(self) -> None:
        payload, calls = self.run_test(icmp=False)
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["loss_pct"], 100.0)
        self.assertEqual(payload["fib"], 2)
        for name in ("nc", "gatebsd-python", "fetch"):
            command = next(command for command in calls if Path(command[2]).name == name)
            self.assertEqual(command[:2], ["/sbin/setfib", "2"])
        self.assertIn("--server", next(command for command in calls if Path(command[2]).name == "gatebsd-python"))

    def test_tcp_failure_is_not_painted_green_by_ping(self) -> None:
        payload, _calls = self.run_test(tcp=False)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["checks"]["internet_ping"]["ok"])
        self.assertFalse(payload["checks"]["tcp_443"]["ok"])

    def test_dns_failure_is_distinct_from_transport(self) -> None:
        payload, _calls = self.run_test(dns=False)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["checks"]["tcp_443"]["ok"])
        self.assertFalse(payload["checks"]["dns"]["ok"])


if __name__ == "__main__":
    unittest.main()
