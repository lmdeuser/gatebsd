#!/usr/bin/env python3
"""A button must report the world, not the wrapper it happened to call.

Four lies came out of the button sweep on 4 August, and they are executed here
rather than described -- a test that reads the source proves nothing, as this
project has now paid to learn three separate times (the `if false` call, the
wiring test that passed on its own comment, the guard that skipped under root).

So everything below runs: the real `service_control` against a real stub
`service(8)` reached through `command._SAFE_PATH`, the real `mpd5_restart`
against a real stub `ifconfig`, the real `_pf_table_add` against a real file,
and the real `dispatch()` the agent uses.

What is substituted is the machine, never the logic under test.
"""
from __future__ import annotations

import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))

from gatebsd_ui import action_state, api, command  # noqa: E402
from gatebsd_ui.api import dispatch  # noqa: E402
from gatebsd_ui.writers import system as writers_system, vpn as writers_vpn  # noqa: E402


def _stub_bin(directory: Path, name: str, body: str) -> None:
    script = directory / name
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


class _StubMachine(unittest.TestCase):
    """A temp directory prepended to the PATH `command.run` imposes on itself."""

    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        saved = command._SAFE_PATH
        command._SAFE_PATH = f"{self.bin}:{saved}"
        self.addCleanup(setattr, command, "_SAFE_PATH", saved)


class TheVocabularyItself(unittest.TestCase):
    """`unverified` has to be unpleasant to look at, or nobody will fix it."""

    def test_every_state_can_be_drawn(self):
        for state in action_state.LABELS:
            block = action_state.describe(state, target="x", detail="y")
            self.assertTrue(block["label"], state)
            self.assertIn(block["level"], {"success", "warning", "error", "info"}, state)

    def test_only_done_is_green(self):
        for state in action_state.LABELS:
            level = action_state.describe(state)["level"]
            if state == action_state.DONE:
                self.assertEqual(level, "success")
            else:
                self.assertNotEqual(level, "success", f"{state} would toast green")

    def test_succeeded_and_verified_are_not_the_same_field(self):
        block = action_state.unverified("svc", "ran, nobody looked")
        self.assertIs(block["succeeded"], True)
        self.assertIs(block["verified"], False)

    def test_not_measured_never_becomes_failed(self):
        """`unknown` collapsing into `ok: False` would be the same bug again."""
        payload = action_state.attach({}, action_state.unknown("svc"))
        self.assertNotIn("ok", payload)
        self.assertIsNone(payload["action"]["succeeded"])

    def test_an_invented_state_is_refused(self):
        with self.assertRaises(ValueError):
            action_state.describe("probably_fine")


class ServiceButtonReportsTheService(_StubMachine):
    """B-1 and B-2: `${unit}: ${r.active}` and `${r.active||action}`.

    `active` was never a field of this reply, so the customer read
    "unbound: undefined" -- in green -- and the fallback printed the name of
    the action back at them. Both are reports about the request.
    """

    def install_service(self, *, action_rc: int, status_out: str, status_rc: int) -> None:
        _stub_bin(self.bin, "service", f"""
case "$2" in
  status) printf '%s\\n' '{status_out}'; exit {status_rc} ;;
  *) echo "Stopping $1."; echo "Starting $1."; exit {action_rc} ;;
esac""")

    def test_a_service_that_came_back_is_done(self):
        self.install_service(action_rc=0, status_out="unbound is running as pid 1234.", status_rc=0)
        status, payload = writers_system.service_control("unbound", "restart")
        self.assertEqual(status, 200)
        self.assertEqual(payload["action"]["state"], action_state.DONE)
        self.assertIs(payload["ok"], True)
        self.assertIn("running", payload["action"]["detail"])

    def test_a_restart_that_exited_zero_over_a_dead_daemon_is_not_success(self):
        """The lie itself: `service(8)` exits 0, the daemon is gone.

        This is the whole reason the exit code cannot be the report. Before the
        change the reply was `{"ok": true, "output": ...}` and the toast was
        green with the word `undefined` in it.
        """
        self.install_service(action_rc=0, status_out="unbound is not running.", status_rc=1)
        status, payload = writers_system.service_control("unbound", "restart")
        self.assertEqual(status, 200)
        self.assertEqual(payload["action"]["state"], action_state.FAILED)
        self.assertIs(payload["ok"], False)
        self.assertNotEqual(payload["action"]["level"], "success")

    def test_a_stop_that_left_it_running_is_not_success(self):
        self.install_service(action_rc=0, status_out="pf is running as pid 7.", status_rc=0)
        status, payload = writers_system.service_control("pf", "stop")
        self.assertEqual(payload["action"]["state"], action_state.FAILED)
        self.assertIs(payload["ok"], False)

    def test_an_unreadable_status_is_unverified_and_not_green(self):
        """`security.bsd.see_other_uids=0` makes a live daemon look stopped.

        We ship that sysctl ourselves, so "the status command told me nothing"
        is a state this box actually reaches -- and it is neither running nor
        stopped.
        """
        self.install_service(action_rc=0, status_out="", status_rc=3)
        status, payload = writers_system.service_control("unbound", "restart")
        self.assertEqual(payload["action"]["state"], action_state.UNVERIFIED)
        self.assertIs(payload["action"]["verified"], False)
        self.assertNotEqual(payload["action"]["level"], "success")

    def test_a_failed_command_is_failed(self):
        self.install_service(action_rc=1, status_out="unbound is not running.", status_rc=1)
        status, payload = writers_system.service_control("unbound", "restart")
        self.assertEqual(status, 500)
        self.assertEqual(payload["action"]["state"], action_state.FAILED)

    def test_enable_does_not_claim_the_service_changed(self):
        self.install_service(action_rc=0, status_out="unbound is not running.", status_rc=1)
        status, payload = writers_system.service_control("unbound", "enable")
        self.assertEqual(payload["action"]["state"], action_state.UNVERIFIED)
        self.assertIn("rc.conf", payload["action"]["detail"])

    def test_status_is_a_reading_and_says_which(self):
        self.install_service(action_rc=0, status_out="cron is running as pid 9.", status_rc=0)
        status, payload = writers_system.service_control("cron", "status")
        self.assertEqual(payload["action"]["state"], action_state.DONE)
        self.assertIs(payload["running"], True)

    def test_the_panel_always_gets_something_to_draw(self):
        """`actionToast` falls back to "result not verified"; it must not have to."""
        self.install_service(action_rc=0, status_out="cron is running as pid 9.", status_rc=0)
        for action in ("start", "stop", "restart", "status", "enable", "disable"):
            _status, payload = writers_system.service_control("cron", action)
            block = payload.get("action")
            self.assertIsInstance(block, dict, action)
            for field in ("state", "label", "level", "detail"):
                self.assertTrue(block.get(field), f"{action}: no {field}")

    def test_the_route_carries_it(self):
        self.install_service(action_rc=0, status_out="cron is running as pid 9.", status_rc=0)
        status, payload = dispatch("/api/services/manage", {}, method="POST", body={"unit": "cron", "action": "restart"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["action"]["state"], action_state.DONE)

    def test_a_service_outside_the_list_is_still_refused(self):
        status, payload = writers_system.service_control("sendmail", "restart")
        self.assertEqual(status, 403)


class PppoeReconnectReportsTheLink(_StubMachine):
    """B-3: `payload["active"] = "restarted"`, unconditionally, in `api.py`.

    A literal. `service mpd5 restart` returns as soon as the daemon respawns --
    PADI/PADO/PADR/PADS and IPCP all happen after that -- so the panel said the
    uplink was back at the exact moment it demonstrably was not.
    """

    def setUp(self) -> None:
        super().setUp()
        _stub_bin(self.bin, "service", "exit 0")
        patcher = patch.object(writers_vpn, "_PPPOE_VERIFY_SECONDS", 0.0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def set_link(self, *, session: bool) -> None:
        body = (
            'echo "ng0: flags=88d1<UP,POINTOPOINT,RUNNING> metric 0 mtu 1492"; '
            'echo "	inet 10.1.2.3 --> 10.9.9.9 netmask 0xffffffff"'
            if session else
            'echo "ng0: flags=88d1<UP,POINTOPOINT> metric 0 mtu 1492"'
        )
        _stub_bin(self.bin, "ifconfig", body)

    def test_a_negotiated_session_is_done(self):
        self.set_link(session=True)
        status, payload = writers_vpn.mpd5_restart(verify_seconds=0.0)
        self.assertEqual(status, 200)
        self.assertEqual(payload["action"]["state"], action_state.DONE)
        self.assertIs(payload["link_up"], True)

    def test_an_interface_without_a_session_is_not_reconnected(self):
        """UP is not connected. This is the state the literal painted green."""
        self.set_link(session=False)
        status, payload = writers_vpn.mpd5_restart(verify_seconds=0.0)
        self.assertEqual(status, 200)
        self.assertEqual(payload["action"]["state"], action_state.IN_PROGRESS)
        self.assertIs(payload["action"]["verified"], False)
        self.assertNotEqual(payload["action"]["level"], "success")

    def test_the_literal_is_gone_from_the_route(self):
        """The two assignments in `api.py` are what the panel actually printed."""
        self.set_link(session=False)
        status, payload = dispatch("/api/pppoe/reconnect", {}, method="POST", body={})
        self.assertEqual(status, 200)
        self.assertNotEqual(payload.get("active"), "restarted")
        self.assertNotEqual(payload.get("primary"), "restarted")
        self.assertEqual(payload["action"]["state"], action_state.IN_PROGRESS)

    def test_an_unreadable_interface_is_unverified_not_connected(self):
        _stub_bin(self.bin, "ifconfig", "echo 'ifconfig: permission denied' >&2; exit 71")
        status, payload = writers_vpn.mpd5_restart(verify_seconds=0.0)
        self.assertEqual(payload["action"]["state"], action_state.UNVERIFIED)
        self.assertIsNone(payload["link_up"])

    def test_a_dead_mpd5_is_failed(self):
        _stub_bin(self.bin, "service", "echo 'mpd5 does not exist' >&2; exit 1")
        self.set_link(session=False)
        status, payload = writers_vpn.mpd5_restart(verify_seconds=0.0)
        self.assertEqual(status, 500)
        self.assertEqual(payload["action"]["state"], action_state.FAILED)
        self.assertIs(payload["ok"], False)


class RuBypassButtonReportsTheTable(unittest.TestCase):
    """B-4: the toast counted `values.length` -- what the operator typed.

    Re-entering five addresses that were already in the table announced
    "5 entries processed" while the backend was answering `added: 0`.
    """

    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.table = Path(self.td.name) / "ru_bypass.table"
        self.table.write_text("")
        backups = Path(self.td.name) / "backups"
        backups.mkdir(mode=0o700)
        for patcher in (
            patch("gatebsd_ui.api.RU_TABLE", self.table),
            patch("gatebsd_ui.paths.BACKUP_DIR", backups),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_the_reply_counts_the_table_not_the_textarea(self):
        values = ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]
        status, first = api._pf_table_add({"values": values})
        self.assertEqual(status, 200)
        self.assertEqual(first["added"], 3)
        self.assertEqual(first["action"]["state"], action_state.DONE)

        status, again = api._pf_table_add({"values": values})
        self.assertEqual(status, 200)
        self.assertEqual(again["added"], 0)
        self.assertEqual(again["requested"], 3)
        self.assertIn("0 of 3", again["action"]["detail"])

    def test_removing_what_is_not_there_says_zero(self):
        self.table.write_text("10.0.0.0/24\n")
        status, payload = api._pf_table_remove({"values": ["10.9.9.0/24"]})
        self.assertEqual(status, 200)
        self.assertEqual(payload["removed"], 0)
        self.assertIn("0 of 1", payload["action"]["detail"])

    def test_removing_what_is_there_counts_the_file(self):
        self.table.write_text("10.0.0.0/24\n10.0.1.0/24\n")
        status, payload = api._pf_table_remove({"values": ["10.0.0.0/24", "10.9.9.0/24"]})
        self.assertEqual(payload["removed"], 1)
        self.assertIn("1 of 2", payload["action"]["detail"])


class PowerButtonIsNotDone(unittest.TestCase):
    """`/api/system/power` answered `{"ok": true}` two seconds before `shutdown`.

    It could never have answered anything else: a box that has rebooted cannot
    report that it did. That is `in_progress`, and nothing else ever will be.
    """

    def test_the_reply_says_it_has_not_happened_yet(self):
        started: list[object] = []

        class _NoThread:
            def __init__(self, *args, **kwargs):
                started.append(kwargs.get("target"))

            def start(self):
                pass

        # Both patches are load-bearing: the handler builds its own thread and
        # calls the module-level `run`. If either escaped, this test would
        # reboot the machine it is running on.
        with patch.object(threading, "Thread", _NoThread), \
                patch.object(api, "run") as fake_run:
            status, payload = dispatch("/api/system/power", {}, method="POST", body={"action": "reboot"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["action"]["state"], action_state.IN_PROGRESS)
        self.assertIs(payload["action"]["verified"], False)
        fake_run.assert_not_called()
        self.assertEqual(len(started), 1)

    def test_a_made_up_action_is_still_refused(self):
        status, payload = dispatch("/api/system/power", {}, method="POST", body={"action": "melt"})
        self.assertEqual(status, 400)


class ThePanelDrawsAndDoesNotDecide(unittest.TestCase):
    """A text guard, and named as one -- the proof is every class above.

    This only stops the four expressions from growing back; it does not
    measure anything. Executable frontend behavior belongs in the Node.js
    regression suite instead of another source-text assertion.
    """

    def setUp(self) -> None:
        root = Path(__file__).resolve().parent.parent
        self.app_js = (root / "webui" / "frontend" / "app.js").read_text(encoding="utf-8")

    def test_the_helper_exists(self):
        self.assertIn("function actionToast(", self.app_js)

    def test_the_four_expressions_are_gone(self):
        for expression in (
            "${unit}: ${r.active}",
            "${r.active||action}",
            "${r.primary || r.active}",
            "${values.length} entries processed",
        ):
            self.assertNotIn(expression, self.app_js, expression)

    def test_the_four_buttons_call_it(self):
        for function in ("doRestart", "doManageService", "doPppoeReconnect", "doVpnNft"):
            start = self.app_js.index(f"function {function}(")
            body = self.app_js[start:start + 700]
            self.assertIn("actionToast(", body, function)


class TheDnsButtonAdmitsTheAnchorFailed(_StubMachine):
    """`/api/dns/restart` printed green over `fatal error`.

    The port's rc script runs `unbound-anchor` inside the start. It writes the
    trust anchor through a temporary file created beside it, and
    /usr/local/etc/unbound is root:wheel 0755 -- so the daemon's own account
    cannot create that file. Measured on the production router, 7 August:

        fatal error: could not open autotrust file for writing,
        /usr/local/etc/unbound/root.key.21101-0-3053dc71: Permission denied

    rc.subr does not call that a failure. `service unbound restart` exits 0 and
    the daemon comes up, so the old body -- a second, hand-rolled copy of
    `service_control` that never went through action_state -- answered
    `{"ok": true}` and the panel toasted green with no text at all.

    Two facts, not one: the service did come back, and the anchor is not being
    maintained. The reply has to carry both.
    """

    ANCHOR_FATAL = (
        "fatal error: could not open autotrust file for writing, "
        "/usr/local/etc/unbound/root.key.21101-0-3053dc71: Permission denied"
    )

    def install_service(self, *, anchor_fails: bool, running: bool = True) -> None:
        anchor = f"echo '{self.ANCHOR_FATAL}' >&2" if anchor_fails else "echo 'Obtaining a trust anchor..'"
        status_out = "unbound is running as pid 5474." if running else "unbound is not running."
        status_rc = 0 if running else 1
        _stub_bin(self.bin, "service", f"""
case "$2" in
  status) printf '%s\\n' '{status_out}'; exit {status_rc} ;;
  *) {anchor}; echo "Stopping unbound."; echo "Starting unbound."; exit 0 ;;
esac""")

    def test_the_service_coming_back_is_still_reported_as_done(self):
        """The anchor is a footnote; it must not displace the answer."""
        self.install_service(anchor_fails=True)
        _status, payload = writers_vpn.unbound_restart()
        self.assertEqual(payload["action"]["state"], action_state.DONE)
        self.assertIs(payload["running"], True)

    def test_the_failed_anchor_is_named_in_what_the_panel_shows(self):
        self.install_service(anchor_fails=True)
        _status, payload = writers_vpn.unbound_restart()
        self.assertIs(payload["trust_anchor_writable"], False)
        self.assertIn("anchor", payload["action"]["detail"].lower(),
                      "a fatal error inside the restart is invisible to the operator")

    def test_a_clean_restart_does_not_invent_the_warning(self):
        self.install_service(anchor_fails=False)
        _status, payload = writers_vpn.unbound_restart()
        self.assertNotIn("trust_anchor_writable", payload)
        self.assertNotIn("anchor", payload["action"]["detail"].lower())

    def test_a_dead_daemon_is_still_not_success(self):
        """Delegating must not lose what service_control already got right."""
        self.install_service(anchor_fails=True, running=False)
        _status, payload = writers_vpn.unbound_restart()
        self.assertEqual(payload["action"]["state"], action_state.FAILED)
        self.assertIs(payload["ok"], False)

    def test_the_route_is_wired_to_it(self):
        """Executed, not read: the fix is worthless behind an unreached route."""
        self.install_service(anchor_fails=True)
        status, payload = dispatch("/api/dns/restart", {}, method="POST", body={})
        self.assertEqual(status, 200)
        self.assertIs(payload["trust_anchor_writable"], False)

    def test_the_old_body_showed_none_of_this(self):
        """The reintroduction, run rather than described.

        Without it the assertions above would pass just as happily against a
        reply that never mentions the anchor, because nothing here would have
        demonstrated that they can fail.
        """
        self.install_service(anchor_fails=True)
        r = command.run(["service", "unbound", "restart"], timeout=10)
        old_payload = {"ok": r.ok, "out": r.stdout + r.stderr}

        self.assertIs(old_payload["ok"], True, "the old body called this a success")
        self.assertNotIn("action", old_payload)
        self.assertNotIn("trust_anchor_writable", old_payload)
        # The fatal error existed all along -- it was simply never surfaced
        # anywhere the operator looks.
        self.assertIn("autotrust", old_payload["out"])

    def test_putting_the_old_body_back_makes_the_route_assertion_fail(self):
        """The reintroduction that matters: the verdict must invert.

        Showing that the old shape lacked the fields is not enough -- it does
        not demonstrate that the assertion guarding the route can fail. This
        puts the old body back behind the real route and requires the check to
        break, which is the only thing that makes the check worth having.
        """
        self.install_service(anchor_fails=True)

        def old_unbound_restart():
            r = command.run(["service", "unbound", "restart"], timeout=10)
            return (200 if r.ok else 500), {"ok": r.ok, "out": r.stdout + r.stderr}

        with patch("gatebsd_ui.writers.unbound_restart", old_unbound_restart):
            _status, payload = dispatch("/api/dns/restart", {}, method="POST", body={})
        with self.assertRaises(KeyError):
            payload["trust_anchor_writable"]

if __name__ == "__main__":
    unittest.main()
