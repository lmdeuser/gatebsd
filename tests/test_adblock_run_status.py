#!/usr/bin/env python3
"""The panel's reading of the blocklist run record.

Why the record exists at all: on the night of 4 August a rebuild published
five sources instead of six and 307943 domains instead of 384499, and the
router served that list until morning. The only trace was one WARNING line in
/var/log/gatebsd-adblock.log. Every reader that could have noticed was looking
at the published blocklist -- whose header, on a run that refuses to publish,
still describes the PREVIOUS run and reads perfectly healthy.

So the tests here are about the same honesty the operator card was built for:

  * a record we could not read must not come back looking like a record that
    reported nothing wrong;
  * a refusal must produce a line the customer can see, not an entry in a log
    nobody opens;
  * and the quiet cases must stay quiet, or the warnings card becomes noise
    and stops being read at all.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui" / "backend"))

from gatebsd_ui import adblock  # noqa: E402

# The shape the updater really writes, taken from a run of the script itself.
PUBLISHED = {
    "schema": 1,
    "checked_at": 1785900000,
    "outcome": "published",
    "sources_configured": 6,
    "sources_used": 6,
    "sources_skipped": "",
    "domains": 385226,
    "reason": "",
}
# What the night of 4 August would have written, had this existed then.
REFUSED = {
    "schema": 1,
    "checked_at": 1785900000,
    "outcome": "failed",
    "sources_configured": 6,
    "sources_used": 5,
    "sources_skipped": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "domains": None,
    "reason": (
        "only 5 of 6 sources downloaded; current blocklist preserved "
        "(skipped: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)"
    ),
}


class RecordCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "adblock-status.json"
        self._saved = adblock.RUN_STATUS
        adblock.RUN_STATUS = self.path
        self.addCleanup(self._restore)

    def _restore(self):
        adblock.RUN_STATUS = self._saved

    def write(self, data):
        self.path.write_text(
            data if isinstance(data, str) else json.dumps(data, ensure_ascii=False),
            encoding="utf-8",
        )

    def messages(self, state):
        return " | ".join(w["msg"] for w in state["warnings"])


class ARefusalIsVisible(RecordCase):
    def test_a_refused_rebuild_reaches_the_warnings_card(self):
        self.write(REFUSED)
        state = adblock.run_status()
        self.assertTrue(state["available"])
        self.assertEqual(state["outcome"], "failed")
        self.assertEqual(len(state["warnings"]), 1)
        self.assertEqual(state["warnings"][0]["level"], "error")
        self.assertIn("not updated", self.messages(state))
        self.assertIn("5 of 6", self.messages(state))

    def test_the_customer_is_told_the_list_is_the_old_one(self):
        """"Failed" alone would read as "no filtering". It is still filtering,
        on the last list that built cleanly, and that is what has to be said."""
        self.write(REFUSED)
        self.assertIn("previous list", self.messages(adblock.run_status()))

    def test_a_failure_with_all_sources_still_says_why(self):
        self.write({**REFUSED, "sources_used": 6, "sources_skipped": "",
                    "reason": "generated blocklist has invalid Unbound syntax"})
        message = self.messages(adblock.run_status())
        self.assertIn("not updated", message)
        self.assertIn("invalid Unbound syntax", message)

    def test_a_failure_before_any_download_does_not_invent_a_source_count(self):
        """sources_used is null when nothing was fetched. Reading that as 0
        would produce "0 of 6 sources available" over a run that never tried."""
        self.write({**REFUSED, "sources_used": None, "sources_skipped": "",
                    "reason": "unsupported blocklist verdict: always_transmogrify"})
        state = adblock.run_status()
        self.assertIsNone(state["sources_used"])
        self.assertNotIn("of 6", self.messages(state))
        self.assertIn("always_transmogrify", self.messages(state))


class TheQuietCasesStayQuiet(RecordCase):
    def test_a_clean_rebuild_says_nothing(self):
        self.write(PUBLISHED)
        state = adblock.run_status()
        self.assertTrue(state["available"])
        self.assertEqual(state["warnings"], [])
        self.assertEqual(state["domains"], 385226)

    def test_an_unchanged_run_says_nothing(self):
        """`--if-changed` deciding there was nothing to do is a success."""
        self.write({**PUBLISHED, "outcome": "unchanged", "sources_used": None,
                    "domains": None})
        self.assertEqual(adblock.run_status()["warnings"], [])

    def test_a_device_that_has_not_reported_yet_says_nothing(self):
        """Cron rebuilds every six hours; an alarm on every fresh install is
        how a warnings card becomes something nobody reads."""
        state = adblock.run_status()
        self.assertFalse(state["available"])
        self.assertIn("has not reported", state["error"])
        self.assertEqual(state["warnings"], [])


class PartialButPublished(RecordCase):
    def test_a_partial_first_build_is_still_announced(self):
        """The updater takes what it can get when nothing is published yet --
        a partial list beats no filtering on a freshly flashed device. That is
        a deliberate compromise, so it is stated rather than hidden."""
        self.write({**PUBLISHED, "sources_used": 4, "domains": 200000,
                    "sources_skipped": "https://a.invalid https://b.invalid"})
        state = adblock.run_status()
        self.assertEqual(len(state["warnings"]), 1)
        self.assertEqual(state["warnings"][0]["level"], "warn")
        self.assertIn("4 of 6", self.messages(state))
        self.assertEqual(state["sources_skipped"],
                         ["https://a.invalid", "https://b.invalid"])


class UnreadableIsNotQuiet(RecordCase):
    """A record we could not read is never a record that reported nothing.

    It is not turned into an alarm either: an unreadable file says nothing
    about the blocklist, and claiming it does would be the same invention in
    the other direction. The distinction lives in `available`/`error`, which
    the DNS card shows -- not in a warning about a rebuild we know nothing of.
    """

    def test_corrupt_json_says_so(self):
        self.write("{ this is not json")
        state = adblock.run_status()
        self.assertFalse(state["available"])
        self.assertIn("corrupted", state["error"])
        self.assertEqual(state["warnings"], [])

    def test_json_that_is_not_an_object_says_so(self):
        self.write("[1, 2, 3]")
        state = adblock.run_status()
        self.assertFalse(state["available"])
        self.assertIn("is not a JSON object", state["error"])

    def test_an_empty_file_is_not_a_clean_run(self):
        self.write("")
        state = adblock.run_status()
        self.assertFalse(state["available"])
        self.assertEqual(state["warnings"], [])

    def test_a_directory_where_the_record_should_be_says_so(self):
        self.path.mkdir()
        state = adblock.run_status()
        self.assertFalse(state["available"])
        self.assertIn("unreadable", state["error"])

    def test_a_record_full_of_the_wrong_types_does_not_crash_the_panel(self):
        self.write({"outcome": {"nested": True}, "sources_used": "five",
                    "sources_configured": None, "domains": [], "checked_at": "now"})
        state = adblock.run_status()
        self.assertTrue(state["available"])
        self.assertIsNone(state["sources_used"])
        self.assertEqual(state["sources_configured"], 0)
        self.assertEqual(state["warnings"], [])

    def test_a_boolean_is_not_a_source_count(self):
        """`True` is an int in Python, and would render as "1 of 6 sources available"."""
        self.write({**REFUSED, "sources_used": True})
        self.assertIsNone(adblock.run_status()["sources_used"])


class TheOverviewCarriesIt(RecordCase):
    """Built by CALLING overview(), not by reading its source.

    The version of this that grepped the module passed happily against its own
    explanatory comment, which is the same failure this project has already
    paid for: a wiring test that reads text agrees with a call sitting behind
    `if false`.
    """

    def test_the_record_reaches_the_payload_the_warnings_card_reads(self):
        from gatebsd_ui.adapters import system_overview

        self.write(REFUSED)
        payload = system_overview.overview()
        self.assertEqual(payload["adblock"]["outcome"], "failed")
        self.assertIn("not updated", payload["adblock"]["warnings"][0]["msg"])

    def test_the_polled_payload_never_shells_out_to_unbound(self):
        """adblock.status() runs unbound-control and unbound-checkconf. The
        overview is polled by every open panel; only the record belongs here.
        """
        from gatebsd_ui.adapters import system_overview

        def refuse():
            raise AssertionError("overview must not call adblock.status()")

        saved, adblock.status = adblock.status, refuse
        self.addCleanup(lambda: setattr(adblock, "status", saved))
        self.write(PUBLISHED)
        self.assertEqual(system_overview.overview()["adblock"]["outcome"], "published")

    def test_the_panel_renders_the_warnings_the_backend_decided(self):
        """A source-text guard supplements, not replaces, the Node.js suite.

        The rule itself lives in the backend and app.js only forwards a list it
        did not compute.
        """
        source = (Path(__file__).resolve().parent.parent / "webui" / "frontend"
                  / "app.js").read_text()
        self.assertIn("o.adblock?.warnings", source)


if __name__ == "__main__":
    unittest.main()
