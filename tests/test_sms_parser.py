#!/usr/bin/env python3
"""The SMS parser, on the messages the modem actually delivered.

Every fixture here is a verbatim message from the backup dongle, captured
2 August 2026 (corpus: <external-sms-corpus>).
Nothing is invented, because every trap in this parser came from a real
template and a made-up one would have exercised the easy path.

The tests that matter are the ones asserting what the parser must *not*
conclude: a zero balance is not an unpaid tariff, a warning about tomorrow's
charge is not a charge, and money arriving is not the tariff being paid.
"""
import unittest
from datetime import datetime, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))

from gatebsd_ui import sms  # noqa: E402


def msg(idx, sender, when, text):
    return sms.Message(id=idx, sender=sender, received=when, text=text)


T = datetime(2026, 8, 2, 17, 39, 0)

UNPAID = (
    "Недостаточно средств для списания абон. платы 300 руб. за тариф Партнер M. "
    "Текущий баланс 0.00. До внесения абон. платы действуют базовые условия."
)
REMINDER = (
    "Ваш тариф не оплачен, вы не cможете полноценно использовать пакеты услуг. "
    "А там столько всего интересного! Текущий баланс: %SUMM_AVAILABLE% руб."
)
UPCOMING = (
    "Завтра ночью будет списана абонентская плата по тарифу Партнер M в размере "
    "300.00 руб. Самое время перейти на тариф побольше!"
)
CHARGED = (
    "02.08.2026 17:39 списана абонентская плата по тарифу Партнер M в размере "
    "300.00 руб. Пакет услуг разблокирован. Текущий баланс 0.00 руб. "
    "Дата следующего списания абонентской платы - 02.09.2026"
)
# Note the Latin p (U+0070) in "pуб." -- this is byte-for-byte what arrived.
PAYMENT = "Внесена сумма 300.00 pуб."
RECEIPT = (
    "Check 300.00p 02.08.26 17:39:00 FPD:1466829434 KKT:7337141001754 "
    "https://consumer.1-ofd.ru/v1?t=20260802T173800&s=300.00&fn=7380440902623107"
)

DRONE_ON = "В 09.20 объявлена Беспилотная опасность. Телефон экстренных служб 112"
DRONE_OFF = "В 14.55 снята Беспилотная опасность. Телефон экстренных служб 112"
MISSILE_ON = "В 04.53 объявлена Ракетная опасность. Телефон экстренных служб 112"
MISSILE_OFF = "В 06.55 отмена Ракетной опасности. Телефон экстренных служб 112"


class Homoglyphs(unittest.TestCase):
    def test_latin_p_in_payment_still_matches(self):
        """The operator mixes alphabets inside its own templates."""
        self.assertIn("p", PAYMENT, "fixture lost its Latin p")
        self.assertEqual(
            sms.classify(msg(1, "t2.ru", T, PAYMENT)), sms.KIND_OPERATOR
        )

    def test_fold_is_only_for_matching(self):
        state = sms.summarize([msg(1, "t2.ru", T, CHARGED)], now=T)
        self.assertEqual(state.operator.state_text, CHARGED)


class BillingState(unittest.TestCase):
    def test_unpaid_is_read_from_the_verb(self):
        state = sms.summarize([msg(1, "t2.ru", T, UNPAID)], now=T)
        self.assertIs(state.operator.paid, False)

    def test_zero_balance_after_a_successful_charge_is_not_unpaid(self):
        """The trap that would have fired at the exact moment things got good.

        `Текущий баланс 0.00` appears in both the July failure and the August
        success: the 300 roubles paid in went straight out to the tariff.
        """
        state = sms.summarize(
            [msg(1, "t2.ru", T, UNPAID), msg(2, "t2.ru", T, CHARGED)], now=T
        )
        self.assertIs(state.operator.paid, True)
        self.assertEqual(state.operator.next_charge, "2026-09-02")

    def test_warning_about_tomorrows_charge_is_not_a_charge(self):
        """"будет списана" contains the same verb as "списана"."""
        state = sms.summarize(
            [msg(1, "t2.ru", T, UNPAID), msg(2, "t2.ru", T, UPCOMING)], now=T
        )
        self.assertIs(state.operator.paid, False)

    def test_money_arriving_does_not_pay_the_tariff(self):
        """The second top-up stood alone: the tariff was already paid."""
        state = sms.summarize(
            [msg(1, "t2.ru", T, UNPAID), msg(2, "t2.ru", T, PAYMENT)], now=T
        )
        self.assertIs(state.operator.paid, False)
        self.assertEqual(state.operator.last_payment, T)

    def test_reminder_with_unsubstituted_placeholder_is_unpaid(self):
        state = sms.summarize([msg(1, "t2.ru", T, REMINDER)], now=T)
        self.assertIs(state.operator.paid, False)

    def test_no_balance_is_ever_reported(self):
        """SMS give state, never a balance -- see OperatorState's docstring."""
        state = sms.summarize([msg(1, "t2.ru", T, CHARGED)], now=T)
        self.assertFalse(hasattr(state.operator, "balance"))

    def test_next_charge_is_taken_as_stated_not_derived(self):
        state = sms.summarize([msg(1, "t2.ru", T, CHARGED)], now=T)
        self.assertEqual(state.operator.next_charge, "2026-09-02")


class Receipts(unittest.TestCase):
    def test_fiscal_receipt_is_noise_not_unknown(self):
        self.assertEqual(sms.classify(msg(1, "t2.ru", T, RECEIPT)), sms.KIND_NOISE)

    def test_receipt_does_not_touch_state_or_unknown_counter(self):
        state = sms.summarize(
            [msg(1, "t2.ru", T, UNPAID), msg(2, "t2.ru", T, RECEIPT)], now=T
        )
        self.assertIs(state.operator.paid, False)
        self.assertEqual(state.unknown_count, 0)


class Alerts(unittest.TestCase):
    def test_drone_raised_then_cleared(self):
        state = sms.summarize(
            [
                msg(1, "RSCHS", datetime(2026, 8, 2, 8, 9), DRONE_ON),
                msg(2, "RSCHS", datetime(2026, 8, 2, 15, 5), DRONE_OFF),
            ],
            now=datetime(2026, 8, 2, 15, 30),
        )
        self.assertFalse(state.alert_active)

    def test_missile_cancel_uses_a_different_verb_and_case(self):
        """"отмена Ракетной опасности", not "снята Ракетная опасность".

        Matching the drone phrasing leaves the device in a missile alert for
        good, and a stuck alert pauses the keep-alive forever.
        """
        state = sms.summarize(
            [
                msg(1, "RSCHS", datetime(2026, 7, 4, 3, 58), MISSILE_ON),
                msg(2, "RSCHS", datetime(2026, 7, 4, 5, 43), MISSILE_OFF),
            ],
            now=datetime(2026, 7, 4, 6, 0),
        )
        self.assertFalse(state.alert_active)

    def test_clearing_one_kind_leaves_the_other_standing(self):
        state = sms.summarize(
            [
                msg(1, "RSCHS", datetime(2026, 8, 2, 10, 0), MISSILE_ON),
                msg(2, "RSCHS", datetime(2026, 8, 2, 11, 9), DRONE_ON),
                msg(3, "RSCHS", datetime(2026, 8, 2, 15, 5), DRONE_OFF),
            ],
            now=datetime(2026, 8, 2, 15, 30),
        )
        self.assertTrue(state.alert_active)
        self.assertEqual(state.alert_kinds, ["missile alert"])

    def test_alert_without_a_cancel_goes_unknown_not_active(self):
        state = sms.summarize(
            [msg(1, "RSCHS", datetime(2026, 8, 1, 3, 0), MISSILE_ON)],
            now=datetime(2026, 8, 2, 15, 30),
        )
        self.assertFalse(state.alert_active)
        self.assertTrue(state.alert_unknown)

    def test_stated_time_is_kept_apart_from_delivery_time(self):
        delivered = datetime(2026, 8, 2, 15, 5, 16)
        state = sms.summarize([msg(1, "RSCHS", delivered, DRONE_OFF)], now=delivered)
        alert = state.alerts["UAV alert"]
        self.assertEqual(alert.stated_time, "14:55")
        self.assertEqual(alert.since, delivered)


class Ordering(unittest.TestCase):
    def test_the_last_message_by_id_wins_not_the_first_listed(self):
        """The modem lists newest first; a payment produced three in 26 s."""
        listed_newest_first = [
            msg(3, "t2.ru", T, CHARGED),
            msg(2, "t2.ru", T, PAYMENT),
            msg(1, "t2.ru", T, RECEIPT),
        ]
        state = sms.summarize(listed_newest_first, now=T)
        self.assertIs(state.operator.paid, True)

    def test_half_a_batch_is_survivable(self):
        """Receipt and confirmation came 3m43s apart; a 5-minute poll splits them."""
        first_poll = sms.summarize([msg(1, "t2.ru", T, RECEIPT)], now=T)
        self.assertIsNone(first_poll.operator.paid)
        self.assertEqual(first_poll.unknown_count, 0)


class Unknown(unittest.TestCase):
    def test_unreadable_message_does_not_change_state(self):
        state = sms.summarize(
            [
                msg(1, "t2.ru", T, CHARGED),
                msg(2, "MTS", T, "Совершенно новый шаблон, которого мы не видели"),
            ],
            now=T,
        )
        self.assertIs(state.operator.paid, True)
        self.assertEqual(state.unknown_count, 1)
        self.assertEqual(state.unknown_senders, ["MTS"])

    def test_unknown_is_reported_rather_than_swallowed(self):
        state = sms.summarize([msg(1, "someone", T, "щось нове")], now=T)
        self.assertEqual(state.unknown_count, 1)
        self.assertIsNotNone(state.unknown_sample)


class Diagnosis(unittest.TestCase):
    def test_alert_explains_a_dead_backup(self):
        state = sms.summarize(
            [msg(1, "RSCHS", datetime(2026, 8, 2, 8, 9), DRONE_ON)],
            now=datetime(2026, 8, 2, 9, 0),
        )
        self.assertIn("not a fault", sms.diagnose(state, backup_ok=False))

    def test_unpaid_explains_a_dead_backup(self):
        state = sms.summarize([msg(1, "t2.ru", T, UNPAID)], now=T)
        text = sms.diagnose(state, backup_ok=False)
        self.assertIn("unpaid", text)

    def test_silence_from_the_operator_means_a_real_defect(self):
        state = sms.summarize([msg(1, "t2.ru", T, CHARGED)], now=T)
        self.assertIn("fault", sms.diagnose(state, backup_ok=False))

    def test_working_backup_on_an_unpaid_tariff_is_still_worth_saying(self):
        """Exactly the state the device sat in from 15 July: working, unpaid."""
        state = sms.summarize([msg(1, "t2.ru", T, UNPAID)], now=T)
        self.assertIn("unpaid", sms.diagnose(state, backup_ok=True))


class Decoding(unittest.TestCase):
    def test_ucs2_hex_body(self):
        encoded = "Внесена".encode("utf-16-be").hex()
        self.assertEqual(sms.decode_body(encoded), "Внесена")

    def test_plain_text_body_survives(self):
        self.assertEqual(sms.decode_body("plain"), "plain")


if __name__ == "__main__":
    unittest.main()
