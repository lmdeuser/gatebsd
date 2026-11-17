#!/usr/bin/env python3
"""The HTTP API and privileged agent must share an exact route contract.

The HTTP API had implemented ``/api/repo/sources`` and ``/api/repo/scan``, and
the browser requested them, but the privileged agent omitted POST handlers
from its independent allowlist.  In production, requests cross the agent Unix
socket boundary and fail with 404 ``endpoint not allowed`` whenever a route is
missing from ``agent.py``.

These checks execute the gatekeeper and request framing used by the live agent
and verify AST parity between ``api.py`` and ``agent.py``.
"""
from __future__ import annotations

import ast
import json
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "webui" / "backend"))

from gatebsd_ui import agent, api, writers  # noqa: E402


def _call_agent_handler(method: str, path: str, *, body: dict | None = None) -> tuple[int, dict]:
    """Run ``agent.AgentRequestHandler`` over an isolated in-process socketpair."""
    client_sock, server_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client_sock.settimeout(5.0)
        payload = {"method": method, "path": path, "query": {}, "body": body}
        client_sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        client_sock.shutdown(socket.SHUT_WR)
        with mock.patch.object(agent, "_peer_is_trusted", return_value=True):
            agent.AgentRequestHandler(server_sock, ("local", 0), mock.MagicMock())
        server_sock.close()
        chunks: list[bytes] = []
        while True:
            chunk = client_sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        decoded = json.loads(b"".join(chunks).decode("utf-8"))
        return int(decoded["status"]), decoded["payload"]
    finally:
        client_sock.close()
        server_sock.close()


class SettingsEndpointContract(unittest.TestCase):
    sources_endpoint = "/api/repo/sources"
    scan_endpoint = "/api/repo/scan"

    def test_repository_sources_get_and_post_cross_the_agent(self) -> None:
        self.assertTrue(agent._agent_allowed("GET", self.sources_endpoint))
        self.assertTrue(agent._agent_allowed("GET", self.sources_endpoint + "?refresh=1"))
        self.assertTrue(agent._agent_allowed("POST", self.sources_endpoint))
        self.assertTrue(agent._agent_allowed("POST", self.scan_endpoint))

        with (
            mock.patch.object(
                writers, "repo_sources_set", return_value=(200, {"ok": True, "changed": False})
            ) as set_mock,
            mock.patch.object(
                writers, "repo_scan", return_value=(200, {"candidates": [], "found": []})
            ) as scan_mock,
        ):
            status, body = _call_agent_handler(
                "POST", self.sources_endpoint, body={"active": "http://mirror.example.lan", "known": []}
            )
            self.assertEqual(status, 200, body)
            self.assertTrue(body["ok"])
            set_mock.assert_called_once()

            status, body = _call_agent_handler("POST", self.scan_endpoint, body={})
            self.assertEqual(status, 200, body)
            self.assertEqual(body, {"candidates": [], "found": []})
            scan_mock.assert_called_once()

    def test_reintroduced_omission_is_rejected(self) -> None:
        agent.AGENT_ALLOWED_GET.remove(self.sources_endpoint)
        self.addCleanup(agent.AGENT_ALLOWED_GET.add, self.sources_endpoint)
        self.assertFalse(agent._agent_allowed("GET", self.sources_endpoint))

        for path in (self.sources_endpoint, self.scan_endpoint):
            if path in agent.AGENT_ALLOWED_POST:
                agent.AGENT_ALLOWED_POST.remove(path)
                self.addCleanup(agent.AGENT_ALLOWED_POST.add, path)
            status, payload = _call_agent_handler("POST", path, body={})
            self.assertEqual(status, 404, f"{path}: {payload}")
            self.assertEqual(payload, {"error": "endpoint not allowed"})


class ApiAgentParityContract(unittest.TestCase):
    """Every GET and POST route handled by api.dispatch() must be allowlisted in agent.py."""

    @staticmethod
    def _extract_api_routes() -> tuple[set[str], set[str]]:
        source = Path(api.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        dispatch_fn = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "dispatch"
        )

        get_routes: set[str] = set()
        post_routes: set[str] = set()

        for stmt in dispatch_fn.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == "get_routes":
                        if isinstance(stmt.value, ast.Dict):
                            for key in stmt.value.keys:
                                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                                    if key.value.startswith("/api/"):
                                        get_routes.add(key.value)
            if isinstance(stmt, ast.If) and ApiAgentParityContract._is_post_guard(stmt.test):
                for node in ast.walk(stmt):
                    if not isinstance(node, ast.Compare):
                        continue
                    if not (isinstance(node.left, ast.Name) and node.left.id == "path"):
                        continue
                    for comp in node.comparators:
                        if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                            if comp.value.startswith("/api/"):
                                post_routes.add(comp.value)
                        elif isinstance(comp, (ast.Set, ast.Tuple, ast.List)):
                            for elt in comp.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    if elt.value.startswith("/api/"):
                                        post_routes.add(elt.value)

        return get_routes, post_routes

    @staticmethod
    def _is_post_guard(test: ast.AST) -> bool:
        return (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "method"
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == "POST"
        )

    def test_every_api_dispatch_route_is_allowlisted_by_agent(self) -> None:
        get_routes, post_routes = self._extract_api_routes()
        self.assertGreaterEqual(len(get_routes), 40)
        self.assertGreaterEqual(len(post_routes), 55)

        missing_get = sorted(r for r in get_routes if not agent._agent_allowed("GET", r))
        missing_post = sorted(r for r in post_routes if not agent._agent_allowed("POST", r))
        self.assertEqual(missing_get, [], f"GET routes missing from AGENT_ALLOWED_GET: {missing_get}")
        self.assertEqual(missing_post, [], f"POST routes missing from AGENT_ALLOWED_POST: {missing_post}")


class SplitDnsEndpointContract(unittest.TestCase):
    endpoint = "/api/dns/split"

    def test_split_dns_get_and_post_cross_the_agent(self) -> None:
        self.assertTrue(agent._agent_allowed("GET", self.endpoint))
        self.assertTrue(agent._agent_allowed("POST", self.endpoint))

    def test_reintroduced_omission_is_rejected(self) -> None:
        agent.AGENT_ALLOWED_GET.remove(self.endpoint)
        agent.AGENT_ALLOWED_POST.remove(self.endpoint)
        self.addCleanup(agent.AGENT_ALLOWED_GET.add, self.endpoint)
        self.addCleanup(agent.AGENT_ALLOWED_POST.add, self.endpoint)
        self.assertFalse(agent._agent_allowed("GET", self.endpoint))
        self.assertFalse(agent._agent_allowed("POST", self.endpoint))


if __name__ == "__main__":
    unittest.main()
