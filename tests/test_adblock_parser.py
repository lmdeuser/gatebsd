#!/usr/bin/env python3
"""The blocklist parser, run as the update script actually runs it.

The parser reads two formats now. hosts lines are what it always read. Adblock
Plus syntax is what the mobile and RU filter lists publish, and only its
unambiguous subset is taken -- `||domain^` and nothing else. A rule carrying a
path, a wildcard or $options describes a request, not a name; a resolver cannot
honour it, and turning one into a domain block is how a DNS blocklist starts
breaking sites its author never meant to touch.

`@@||domain^` is the author's own exception, so those names are collected and
subtracted rather than dropped on the floor.
"""
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ADBLOCK_SCRIPT = REPO_ROOT / "sbin" / "gatebsd-adblock-update.sh"

_AWK_OPEN = "awk -v block_file="
_AWK_CLOSE = "' \"$WORKDIR/sources\""


class TestAdblockParser(unittest.TestCase):
    def run_awk_parser(self, source_text: str) -> tuple[list[str], list[str]]:
        """Run the exact awk parser out of sbin/gatebsd-adblock-update.sh.

        Returns (blocked, allowed). The parser writes to two files rather than
        to stdout, because the allowlist has to be subtracted afterwards.
        """
        script_content = ADBLOCK_SCRIPT.read_text(encoding="utf-8")
        marker = script_content.find(_AWK_OPEN)
        self.assertGreater(marker, 0, "Could not locate the awk parser in the adblock script")
        awk_start = script_content.find("'", marker) + 1
        awk_end = script_content.find(_AWK_CLOSE, awk_start)
        self.assertGreater(awk_end, awk_start, "Could not locate the awk parser end")
        awk_code = script_content[awk_start:awk_end]

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            sources = work / "sources"
            sources.write_text(source_text, encoding="utf-8")
            blocked = work / "block.list"
            allowed = work / "allow.list"
            subprocess.run(
                [
                    "awk",
                    "-v", f"block_file={blocked}",
                    "-v", f"allow_file={allowed}",
                    awk_code,
                    str(sources),
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            def lines(path: Path) -> list[str]:
                if not path.exists():
                    return []
                return sorted(
                    line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                )

            return lines(blocked), lines(allowed)

    # ------------------------------------------------------------ hosts format
    def test_hosts_prefix_stripping_and_validation(self):
        source = """
# Test hosts list
0.0.0.0 creative.hpyrdr.com
0.0.0.0 0.0.0.0.creative.hpyrdr.com
0.0.0.0 0.0.0.0.0.0.0.0.example.com
127.0.0.1 tracker.example.com
127.0.0.1 127.0.0.1.tracker.example.com
0.0.0.0 localhost
0.0.0.0 bad..example.com
0.0.0.0 -invalid.example.com
"""
        blocked, allowed = self.run_awk_parser(source)

        self.assertIn("creative.hpyrdr.com", blocked)
        self.assertIn("example.com", blocked)
        self.assertIn("tracker.example.com", blocked)
        self.assertEqual(allowed, [])

        for name in blocked:
            self.assertFalse(name.startswith("0.0.0.0."), f"IP prefix survived: {name}")
            self.assertFalse(name.startswith("127.0.0.1."), f"IP prefix survived: {name}")
            self.assertNotIn("localhost", name)
            self.assertNotIn("bad..example", name)
            self.assertNotIn("-invalid", name)

    def test_a_bare_label_is_not_a_domain(self):
        """`0.0.0.0 broadcasthost` and friends would block a whole TLD-less name."""
        blocked, _ = self.run_awk_parser("0.0.0.0 broadcasthost\n0.0.0.0 localdomain\n")
        self.assertEqual(blocked, [])

    def test_an_address_is_not_a_domain(self):
        """Sources block by address too, and this parser can only express names.

        Every label of 203.0.113.7 passes the structural checks -- right
        characters, right lengths, more than one label -- so these went
        through, and 73 of them were found sitting in the live blocklist as
        local-zone entries for names nobody will ever look up. Harmless, but a
        list that says it holds domains should hold domains.

        The last two lines are the ones that make the rule safe to state as
        "no numeric final label": a name may legitimately start with digits or
        carry them in the middle.
        """
        blocked, _ = self.run_awk_parser(
            "0.0.0.0 203.0.113.7\n"
            "0.0.0.0 0.0.0.0\n"
            "127.0.0.1 198.51.100.42\n"
            "||192.0.2.1^\n"
            "0.0.0.0 1tracker.example.com\n"
            "0.0.0.0 cdn2.example.net\n"
        )
        self.assertEqual(blocked, ["1tracker.example.com", "cdn2.example.net"])

    # -------------------------------------------------------- adblock plus subset
    def test_a_plain_domain_rule_is_taken(self):
        blocked, allowed = self.run_awk_parser("||ads.example.com^\n")
        self.assertEqual(blocked, ["ads.example.com"])
        self.assertEqual(allowed, [])

    def test_an_exception_rule_is_collected_separately(self):
        blocked, allowed = self.run_awk_parser("||ads.example.com^\n@@||ads.example.com^\n")
        self.assertEqual(blocked, ["ads.example.com"])
        self.assertEqual(allowed, ["ads.example.com"])

    def test_rules_a_resolver_cannot_honour_are_refused(self):
        """Each of these means something narrower than "block this name"."""
        source = "\n".join([
            "||example.com/banner.gif",          # a path
            "||*.example.com^",                  # a wildcard
            "||example.com^$third-party",        # options
            "||example.com^$script,domain=x.tld",
            "example.com##.ad-banner",           # a cosmetic rule
            "/ads/*",                            # a bare pattern
            "|http://example.com|",              # an address rule
        ]) + "\n"
        blocked, allowed = self.run_awk_parser(source)
        self.assertEqual(blocked, [])
        self.assertEqual(allowed, [])

    def test_filter_list_comments_are_ignored(self):
        """`!` opens a comment in this syntax, and `[Adblock Plus 2.0]` heads the file."""
        source = "! Title: Example\n[Adblock Plus 2.0]\n# also a comment\n||real.example.com^\n"
        blocked, _ = self.run_awk_parser(source)
        self.assertEqual(blocked, ["real.example.com"])

    def test_both_formats_in_one_stream(self):
        """The sources are concatenated before parsing, so this is the real case."""
        source = "0.0.0.0 hosts.example.com\n||abp.example.com^\n@@||abp.example.com^\n"
        blocked, allowed = self.run_awk_parser(source)
        self.assertEqual(blocked, ["abp.example.com", "hosts.example.com"])
        self.assertEqual(allowed, ["abp.example.com"])


if __name__ == "__main__":
    unittest.main()
