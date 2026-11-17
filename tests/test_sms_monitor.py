#!/usr/bin/env python3
"""The SMS monitor: placing messages in time, and failing out loud.

The parser has its own suite. This one covers the two things the monitor adds
on top of it, both of which are about not lying:

  * a message is placed in absolute time from the offset its own stamp carries,
    never from a guess about which clock is whose. The stamps here are the
    bytes the ZTE MF833U1 actually returned on 2 August 2026;
  * a poll that could not reach the modem keeps the last state and says it is
    stale, without moving the date that says when the state was read.

The regression that prompted the first half is in `delivery_lag`'s docstring:
the router recorded a -9336 s clock offset where the two zones differ by
-7200, because on its first run every message in the store looked new and the
newest of them was already 36 minutes old.
"""
import json
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))

from gatebsd_ui import sms, sms_monitor  # noqa: E402

MSK = timezone(timedelta(hours=3))
YEKT = timezone(timedelta(hours=5))

DRONE_ON = "В 09.20 объявлена Беспилотная опасность. Телефон экстренных служб 112"
DRONE_OFF = "В 14.55 снята Беспилотная опасность. Телефон экстренных служб 112"
CHARGED = (
    "02.08.2026 17:39 списана абонентская плата по тарифу Партнер M в размере "
    "300.00 руб. Пакет услуг разблокирован. Текущий баланс 0.00 руб. "
    "Дата следующего списания абонентской платы - 02.09.2026"
)


def msg(idx, sender, when, text):
    return sms.Message(id=idx, sender=sender, received=when, text=text)


class Stamps(unittest.TestCase):
    """`26,08,02,17,44,25,+12` -- verbatim from the modem."""

    def test_trailing_field_is_quarter_hours(self):
        stamp = sms_monitor._parse_stamp("26,08,02,17,44,25,+12")
        self.assertEqual(stamp, datetime(2026, 8, 2, 17, 44, 25, tzinfo=MSK))
        self.assertEqual(stamp.utcoffset(), timedelta(hours=3))

    def test_stamp_and_router_clock_are_one_hour_apart_not_three(self):
        """The measurement that showed the old reconciliation was unnecessary.

        The router read 20:44:20 +05 while this message was stamped 17:44:25
        +03. Believing the wall time alone makes it three hours old; reading
        the offset it carries makes it one, which is what it was.
        """
        stamp = sms_monitor._parse_stamp("26,08,02,17,44,25,+12")
        router_now = datetime(2026, 8, 2, 20, 44, 20, tzinfo=YEKT)
        self.assertEqual(router_now - stamp, timedelta(hours=0, minutes=59, seconds=55))

    def test_negative_offset_is_accepted(self):
        stamp = sms_monitor._parse_stamp("26,08,02,17,44,25,-20")
        self.assertEqual(stamp.utcoffset(), timedelta(hours=-5))

    def test_stamp_without_an_offset_is_not_placed(self):
        """Six fields and no zone: unplaceable, and it must not be invented."""
        self.assertIsNone(sms_monitor._parse_stamp("26,08,02,17,44,25"))

    def test_absurd_offset_is_rejected(self):
        self.assertIsNone(sms_monitor._parse_stamp("26,08,02,17,44,25,+400"))

    def test_unparsable_fields_are_rejected(self):
        self.assertIsNone(sms_monitor._parse_stamp(""))
        self.assertIsNone(sms_monitor._parse_stamp("26,08,32,17,44,25,+12"))
        self.assertIsNone(sms_monitor._parse_stamp("26,08,02,ab,44,25,+12"))


class DeliveryLag(unittest.TestCase):
    def test_first_poll_measures_nothing(self):
        """The bug, stated as a test.

        With no previous state every message in the store is new. The old code
        took the newest one as a clock probe; here the newest message is a
        month old, and treating that as an offset would put the device's idea
        of now a month in the past -- with a raised alert reading as current
        for ever.
        """
        now = datetime(2026, 8, 2, 20, 44, tzinfo=YEKT)
        old = msg(300, "RSCHS", datetime(2026, 7, 2, 9, 20, tzinfo=MSK), DRONE_ON)
        self.assertIsNone(sms_monitor.delivery_lag([old], {}, now))

    def test_month_old_alert_on_a_first_poll_is_stale_not_active(self):
        """The consequence the bound protects: a cold start at a customer."""
        now = datetime(2026, 8, 2, 20, 44, tzinfo=YEKT)
        old = msg(300, "RSCHS", datetime(2026, 7, 2, 9, 20, tzinfo=MSK), DRONE_ON)
        state = sms_monitor.build_state([old], {}, now)
        self.assertFalse(state["alert_active"])
        self.assertTrue(state["alert_unknown"])

    def test_measured_from_a_message_that_arrived_while_watching(self):
        now = datetime(2026, 8, 2, 20, 44, 20, tzinfo=YEKT)
        arrived = msg(330, "t2.ru", datetime(2026, 8, 2, 17, 44, 25, tzinfo=MSK), CHARGED)
        lag = sms_monitor.delivery_lag([arrived], {"seen_ids": [329]}, now)
        self.assertAlmostEqual(lag, 3595.0)

    def test_nothing_new_measures_nothing(self):
        now = datetime(2026, 8, 2, 20, 44, tzinfo=YEKT)
        old = msg(329, "t2.ru", datetime(2026, 8, 2, 17, 40, 42, tzinfo=MSK), CHARGED)
        self.assertIsNone(sms_monitor.delivery_lag([old], {"seen_ids": [329]}, now))


class BuiltState(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 2, 20, 44, 20, tzinfo=YEKT)
        self.messages = [
            msg(324, "RSCHS", datetime(2026, 8, 2, 8, 9, 38, tzinfo=MSK), DRONE_ON),
            msg(325, "RSCHS", datetime(2026, 8, 2, 15, 5, 16, tzinfo=MSK), DRONE_OFF),
            msg(328, "t2.ru", datetime(2026, 8, 2, 17, 39, 26, tzinfo=MSK), CHARGED),
        ]

    def test_the_live_reading_reproduced(self):
        state = sms_monitor.build_state(self.messages, {"seen_ids": [324, 325]}, self.now)
        self.assertFalse(state["alert_active"])
        self.assertTrue(state["operator_paid"])
        self.assertEqual(state["next_charge"], "2026-09-02")
        self.assertEqual(state["unknown_count"], 0)

    def test_offset_is_reported_as_carried_not_estimated(self):
        state = sms_monitor.build_state(self.messages, {}, self.now)
        self.assertEqual(state["stamp_tz_offset"], 10800)

    def test_a_fresh_reading_is_not_stale(self):
        state = sms_monitor.build_state(self.messages, {}, self.now)
        self.assertFalse(state["stale"])
        self.assertEqual(state["timestamp"], int(self.now.timestamp()))

    def test_unplaceable_stamps_are_counted_not_swallowed(self):
        state = sms_monitor.build_state(self.messages, {}, self.now, unplaceable=2)
        self.assertEqual(state["unplaceable_stamps"], 2)

    def test_an_alert_raised_within_the_ttl_is_active(self):
        raised = [msg(331, "RSCHS", datetime(2026, 8, 2, 19, 20, tzinfo=MSK), DRONE_ON)]
        state = sms_monitor.build_state(raised, {"seen_ids": [330]}, self.now)
        self.assertTrue(state["alert_active"])
        self.assertEqual(state["alert_kinds"], ["UAV alert"])

    def test_an_alert_older_than_the_ttl_is_unknown(self):
        raised = [msg(331, "RSCHS", datetime(2026, 8, 1, 4, 0, tzinfo=MSK), DRONE_ON)]
        state = sms_monitor.build_state(raised, {"seen_ids": [330]}, self.now)
        self.assertFalse(state["alert_active"])
        self.assertTrue(state["alert_unknown"])


class UnreachableModem(unittest.TestCase):
    """A poll that failed must not read as a poll that succeeded."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_file = Path(self.tmp.name) / "operator.json"
        self._saved = sms_monitor.STATE_FILE
        sms_monitor.STATE_FILE = self.state_file
        self.addCleanup(lambda: setattr(sms_monitor, "STATE_FILE", self._saved))

        self._fetch = sms_monitor.fetch_messages
        self.addCleanup(lambda: setattr(sms_monitor, "fetch_messages", self._fetch))

        self.last_good = {
            "schema": 2,
            "timestamp": 1785685200,
            "stale": False,
            "alert_active": True,
            "alert_kinds": ["UAV alert"],
            "operator_paid": True,
            "seen_ids": [329, 330],
        }
        self.state_file.write_text(json.dumps(self.last_good), encoding="utf-8")

    def _fail_with(self, exc):
        def boom():
            raise exc
        sms_monitor.fetch_messages = boom
        return sms_monitor.main([])

    def written(self):
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def test_previous_state_is_kept(self):
        self._fail_with(urllib.error.URLError("host is down"))
        written = self.written()
        self.assertTrue(written["alert_active"])
        self.assertEqual(written["alert_kinds"], ["UAV alert"])
        self.assertTrue(written["operator_paid"])

    def test_it_is_marked_stale_and_the_error_is_recorded(self):
        self._fail_with(urllib.error.URLError("host is down"))
        written = self.written()
        self.assertTrue(written["stale"])
        self.assertIn("host is down", written["modem_error"])

    def test_the_reading_date_does_not_move(self):
        """The whole point: `timestamp` dates the reading, not the attempt.

        Refreshing it on failure makes a state nobody could confirm look
        freshly confirmed -- the same quiet lie the panel told about the
        filter, where a failed read came back as an innocent-looking value.
        """
        self._fail_with(urllib.error.URLError("host is down"))
        written = self.written()
        self.assertEqual(written["timestamp"], self.last_good["timestamp"])
        self.assertGreater(written["checked_at"], written["timestamp"])

    def test_it_exits_non_zero(self):
        self.assertEqual(self._fail_with(urllib.error.URLError("down")), 1)

    def test_a_failure_before_any_success_says_it_has_nothing(self):
        self.state_file.unlink()
        self._fail_with(urllib.error.URLError("host is down"))
        written = self.written()
        self.assertTrue(written["stale"])
        self.assertIsNone(written["timestamp"])
        self.assertNotIn("operator_paid", written)

    def test_recovery_clears_the_stale_mark(self):
        self._fail_with(urllib.error.URLError("host is down"))
        self.assertTrue(self.written()["stale"])

        good = [msg(331, "t2.ru", datetime(2026, 8, 2, 17, 39, 26, tzinfo=MSK), CHARGED)]
        sms_monitor.fetch_messages = lambda: (good, 0)
        self.assertEqual(sms_monitor.main([]), 0)

        written = self.written()
        self.assertFalse(written["stale"])
        self.assertNotIn("modem_error", written)


if __name__ == "__main__":
    unittest.main()
