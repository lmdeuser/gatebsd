#!/usr/bin/env python3
"""The panel's reading of operator.json.

This is the half of sec. 0.5 the whole feature exists for: `backup_ok=false` has
three different causes, the device used to report all three identically, and we
took an unpaid tariff for normal behaviour for two weeks because of it.

The tests that matter are about honesty rather than content:

  * a state file we could not read must not come back looking like a state
    file that said nothing is wrong. That distinction is what the panel got
    wrong about the DNS filter, where a failed read returned "" and "" was
    indistinguishable from an empty blocklist;
  * a reading the monitor could not confirm must be shown as unconfirmed, not
    quietly rendered as current.

The fixtures are the shape sms_monitor really writes -- the live file from the
router on 2 August is reproduced verbatim in LIVE.
"""
import itertools
import json
import unittest
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))

from gatebsd_ui import paths  # noqa: E402
from gatebsd_ui.adapters import operator_state as panel  # noqa: E402

LIVE = {
    "schema": 2,
    "timestamp": 1785686292,
    "stale": False,
    "stamp_tz_offset": 10800,
    "delivery_lag": None,
    "unplaceable_stamps": 0,
    "alert_active": False,
    "alert_unknown": False,
    "alert_kinds": [],
    "alert_text": "",
    "alerts": {},
    "operator_paid": True,
    "operator_state_text": (
        "02.08.2026 17:39 списана абонентская плата по тарифу Партнер M в размере "
        "300.00 руб. Пакет услуг разблокирован. Текущий баланс 0.00 руб. "
        "Дата следующего списания абонентской платы - 02.09.2026"
    ),
    "operator_seen": "2026-08-02T17:39:26+03:00",
    "next_charge": "2026-09-02",
    "last_payment": "2026-08-02T17:44:25+03:00",
    "unknown_count": 0,
    "unknown_sample": None,
    "unknown_senders": [],
    "seen_ids": [329, 330],
    "messages_seen": 14,
}

# What counts as a claim about the backup path, in either direction. Every
# sentence the panel publishes about the backup contains one of these, so the
# two halves of the payload can be compared without knowing which half wrote
# which sentence.
SAYS_DOWN = ("backup unavailable", "backup restricted")
SAYS_UP = ("backup is ok", "backup is working")


def claims(texts, phrases):
    return [t for t in texts if any(p in t.lower() for p in phrases)]


class PanelCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

        self._saved = (paths.OPERATOR_STATE, paths.FAILOVER_STATE)
        paths.OPERATOR_STATE = self.dir / "operator.json"
        paths.FAILOVER_STATE = self.dir / "watchdog.json"
        self.addCleanup(self._restore)
        self.set_backup_ok(True)

    def _restore(self):
        paths.OPERATOR_STATE, paths.FAILOVER_STATE = self._saved

    def write(self, data):
        paths.OPERATOR_STATE.write_text(
            data if isinstance(data, str) else json.dumps(data, ensure_ascii=False),
            encoding="utf-8",
        )

    def set_backup_ok(self, ok):
        paths.FAILOVER_STATE.write_text(json.dumps({"backup_ok": ok}), encoding="utf-8")

    def messages(self, state):
        return " | ".join(w["msg"] for w in state["warnings"])

    def statements(self, state):
        """Everything the payload says out loud, warnings and verdict alike.

        The customer reads one screen, not two fields, so the honesty check
        has to be over the whole of it.
        """
        return [state.get("diagnosis") or ""] + [w["msg"] for w in state["warnings"]]


class UnreadableIsNotQuiet(PanelCase):
    """A file we could not read is never a file that reported nothing."""

    def test_missing_file_says_so(self):
        state = panel.operator()
        self.assertFalse(state["available"])
        self.assertIn("has not run", state["error"])
        self.assertIn("unknown", self.messages(state))

    def test_corrupt_json_says_so(self):
        self.write("{ this is not json")
        state = panel.operator()
        self.assertFalse(state["available"])
        self.assertIn("corrupted", state["error"])
        self.assertTrue(state["warnings"])

    def test_empty_file_says_so(self):
        self.write("")
        state = panel.operator()
        self.assertFalse(state["available"])
        self.assertTrue(state["warnings"])

    def test_json_that_is_not_an_object_says_so(self):
        self.write("[1, 2, 3]")
        state = panel.operator()
        self.assertFalse(state["available"])
        self.assertIn("JSON object", state["error"])

    def test_unreadable_is_never_reported_as_healthy(self):
        """The regression in one line: no file must not read as no problem."""
        self.assertNotEqual(panel.operator()["warnings"], [])


class LiveReading(PanelCase):
    def test_a_healthy_paid_line_warns_about_nothing(self):
        self.write(LIVE)
        state = panel.operator()
        self.assertTrue(state["available"])
        self.assertFalse(state["stale"])
        self.assertEqual(state["warnings"], [])
        self.assertEqual(state["diagnosis"], "backup is ok")

    def test_next_charge_is_carried_through(self):
        self.write(LIVE)
        self.assertEqual(panel.operator()["next_charge"], "2026-09-02")

    def test_no_balance_is_ever_published(self):
        """SMS give state, never a balance -- a 0.00 over a funded SIM lies."""
        self.write(LIVE)
        self.assertNotIn("balance", json.dumps(panel.operator()))


class StaleIsSaidOutLoud(PanelCase):
    def setUp(self):
        super().setUp()
        stale = dict(LIVE, stale=True, modem_error="<urlopen error timed out>",
                     checked_at=LIVE["timestamp"] + 3600)
        self.write(stale)

    def test_it_warns(self):
        state = panel.operator()
        self.assertTrue(state["stale"])
        self.assertIn("unresponsive", self.messages(state))

    def test_it_names_the_age_of_what_it_shows(self):
        """Not "here is the state" but "here is the state as of when"."""
        self.assertIn("confirmed reading from", self.messages(panel.operator()))

    def test_the_modem_error_reaches_the_customer(self):
        self.assertIn("timed out", self.messages(panel.operator()))


class TheThreeCauses(PanelCase):
    """One `backup_ok=false`, three different answers."""

    def setUp(self):
        super().setUp()
        self.set_backup_ok(False)

    def test_air_alert_is_not_a_fault(self):
        self.write(dict(LIVE, alert_active=True,
                        alert_kinds=["UAV alert"]))
        state = panel.operator()
        self.assertIn("UAV alert active", state["diagnosis"])
        self.assertIn("not a fault", state["diagnosis"])
        self.assertIn("not due to hardware fault", self.messages(state))

    def test_unpaid_tariff_needs_a_human_not_a_repair(self):
        self.write(dict(LIVE, operator_paid=False))
        state = panel.operator()
        self.assertIn("unpaid", state["diagnosis"])
        self.assertIn("human action required", self.messages(state))
        self.assertEqual(
            [w["level"] for w in state["warnings"] if "unpaid" in w["msg"]],
            ["error"],
        )

    def test_silence_from_the_operator_is_a_real_defect(self):
        self.write(LIVE)
        self.assertIn("this is a fault", panel.operator()["diagnosis"])

    def test_an_alert_without_a_cancel_is_unknown_not_active(self):
        self.write(dict(LIVE, alert_active=False, alert_unknown=True))
        state = panel.operator()
        self.assertIn("all-clear not received", self.messages(state))
        self.assertIn("state unknown", state["diagnosis"])


class AnAlertOverAWorkingBackup(PanelCase):
    """The combination that was live on 6 August 2026 and had no test.

    `TheThreeCauses` puts the backup down in setUp, so every case that
    exercised the alert warning had `backup_ok=false` already. The router was
    serving the opposite: alert since 10:20, watchdog reporting backup_ok
    true, and the red card announcing an outage that had not happened.
    """

    def setUp(self):
        super().setUp()
        self.set_backup_ok(True)
        self.write(dict(LIVE, alert_active=True,
                        alert_kinds=["missile alert"]))

    def test_the_alert_is_still_announced(self):
        """Silence is not the fix: the restriction is coming, say so."""
        self.assertIn("missile alert", self.messages(panel.operator()))

    def test_it_does_not_call_a_working_backup_unavailable(self):
        state = panel.operator()
        self.assertEqual(claims(self.statements(state), SAYS_DOWN), [], state)

    def test_the_two_halves_of_the_payload_agree(self):
        state = panel.operator()
        self.assertEqual(state["diagnosis"], "backup is ok")
        self.assertTrue(claims([self.messages(state)], SAYS_UP), state)

    def test_a_prediction_is_not_painted_as_a_fault(self):
        levels = [w["level"] for w in panel.operator()["warnings"]]
        self.assertEqual(levels, ["info"])

    def test_the_outage_wording_returns_once_the_backup_is_down(self):
        """The sentence is right as an explanation, wrong as an announcement."""
        self.set_backup_ok(False)
        state = panel.operator()
        self.assertIn("not due to hardware fault", self.messages(state))
        self.assertEqual(claims(self.statements(state), SAYS_UP), [], state)


class OneScreenNeverContradictsItself(PanelCase):
    """No combination may put opposite claims about the backup on one screen.

    The specific case above is one cell of this table; the guard is here so
    the next sentence added to `warnings()` cannot reintroduce the shape.
    """

    def test_every_combination(self):
        grid = itertools.product((True, False), (True, False), (True, False),
                                 (True, False, None))
        for backup_ok, alert_active, alert_unknown, paid in grid:
            with self.subTest(backup_ok=backup_ok, alert_active=alert_active,
                              alert_unknown=alert_unknown, paid=paid):
                self.set_backup_ok(backup_ok)
                self.write(dict(
                    LIVE,
                    alert_active=alert_active,
                    alert_kinds=["missile alert"] if alert_active else [],
                    alert_unknown=alert_unknown,
                    operator_paid=paid,
                ))
                said = self.statements(panel.operator())
                down, up = claims(said, SAYS_DOWN), claims(said, SAYS_UP)
                self.assertFalse(down and up, said)
                # And the claim that is made is the measured one, not the
                # predicted one -- agreeing on a falsehood is not honesty.
                self.assertEqual(down if backup_ok else up, [], said)


class UnreadTemplates(PanelCase):
    def test_unparsed_messages_surface(self):
        """Class four of sec. 0.5: the operator changes templates on its own."""
        self.write(dict(LIVE, unknown_count=3))
        self.assertIn("unparsed", self.messages(panel.operator()).lower())

    def test_none_is_silent(self):
        self.write(LIVE)
        self.assertNotIn("unparsed", self.messages(panel.operator()).lower())


class WhitelistWarnings(PanelCase):
    def test_backup_whitelist_warns_without_saying_up(self):
        self.write(LIVE)
        paths.FAILOVER_STATE.write_text(
            json.dumps({"backup_ok": False, "backup_ru_ok": True, "backup_fitted": True}),
            encoding="utf-8",
        )
        state = panel.operator()
        self.assertIn("Backup uplink is restricted (allowlist mode)", self.messages(state))
        said = self.statements(state)
        self.assertTrue(claims(said, SAYS_DOWN), said)
        self.assertEqual(claims(said, SAYS_UP), [], said)

    def test_primary_whitelist_warns(self):
        self.write(LIVE)
        paths.FAILOVER_STATE.write_text(
            json.dumps({"primary_ok": False, "primary_ru_ok": True, "backup_ok": True}),
            encoding="utf-8",
        )
        state = panel.operator()
        self.assertIn("Primary uplink is in domestic allowlist mode", self.messages(state))

    def test_whitelist_warning_surfaces_even_without_operator_json(self):
        if paths.OPERATOR_STATE.exists():
            paths.OPERATOR_STATE.unlink()
        paths.FAILOVER_STATE.write_text(
            json.dumps({"backup_ok": False, "backup_ru_ok": True}),
            encoding="utf-8",
        )
        state = panel.operator()
        self.assertFalse(state["available"])
        msgs = self.messages(state)
        self.assertIn("Backup carrier state unknown", msgs)
        self.assertIn("Backup uplink is restricted (allowlist mode)", msgs)


class WiredIntoTheOverview(unittest.TestCase):
    """The panel fetches /api/overview; the block has to be in it.

    Runs the aggregator rather than reading it: the version of this that
    grepped app.js would pass with the call sitting behind `if false`.
    """

    def test_overview_carries_the_operator_block(self):
        from gatebsd_ui.adapters import system_overview
        payload = system_overview.overview()
        self.assertIn("operator", payload)
        self.assertIn("warnings", payload["operator"])


if __name__ == "__main__":
    unittest.main()
