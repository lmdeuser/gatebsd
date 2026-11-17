"""Clients must not be able to walk past this device's resolver.

The canary stops a browser from *choosing* DoH. It does nothing about the two
cases actually measured on the production router: a client simply pointed at
8.8.8.8, and a client already holding DoT connections to 9.9.9.9:853 and
149.112.112.112:853. Neither ever consults Unbound, so the 96766-domain
blocklist does not apply to them.

Both need pf, and pf is where placement is the whole problem. Translation rules
must precede filter rules or the ruleset is refused outright; among `quick`
filter rules the first match wins, so a block appended after the existing
`pass in quick ... to any` parses, loads, and does nothing. A test that reads
the migration's source cannot tell those apart -- this project has already
shipped a wiring test that passed with the call sitting behind `if false`. So
every test here RUNS sbin/gatebsd-config-migrate and inspects the ruleset it
produced.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "sbin" / "gatebsd-config-migrate"
SAMPLE = ROOT / "etc" / "pf.conf.sample"

RDR = "rdr on $lan_if proto { tcp udp } from $lan_net to ! <local_nets> port 53"
BLOCK = "block in quick on $lan_if proto { tcp udp } from $lan_net to ! <local_nets> port 853"

# A device already in the field: the shipped ruleset as it was before this
# change, which is what the migration has to recognise.
LEGACY = """\
wan_if="ng0"
lan_if="re1"
vpn_if="awg0"
lan_net="10.88.0.0/24"

table <local_nets> const { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }

set skip on lo
set block-policy drop

scrub in all

nat on $wan_if from $lan_net to any -> ($wan_if)
nat on $vpn_if from $lan_net to any -> ($vpn_if)

pass in quick on $lan_if proto tcp from $lan_net to ($lan_if) port 3493 keep state

block in all

pass out quick keep state
pass in quick on $lan_if from $lan_net to $lan_net keep state
pass in quick on $lan_if from $lan_net to ($lan_if) keep state
pass in quick on $lan_if from $lan_net to any keep state
"""


class DnsInterceptionMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            # Same gate as the canary migration tests: the script refuses to run
            # unprivileged and chowns what it writes. A root container or
            # FreeBSD host is where these actually execute.
            self.skipTest("the migration runs as root and chowns files")
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)
        self.pf = self.dir / "pf.conf"
        self.stub_dir = self.dir / "bin"
        self.stub_dir.mkdir()
        self.calls = self.dir / "calls.txt"
        self._stub("pfctl", accept=True)

    def _stub(self, name: str, accept: bool = True) -> None:
        stub = self.stub_dir / name
        stub.write_text(
            f'#!/bin/sh\necho "{name} $*" >> "{self.calls}"\n'
            f'case "$1" in -nf) exit {0 if accept else 1} ;; esac\nexit 0\n',
            encoding="utf-8",
        )
        stub.chmod(0o755)

    def _run(self, ruleset: str | None = LEGACY) -> subprocess.CompletedProcess:
        if ruleset is not None:
            self.pf.write_text(ruleset, encoding="utf-8")
        environment = dict(os.environ)
        environment.update({
            "GATEBSD_PF_CONF": str(self.pf),
            "GATEBSD_PATH": f"{self.stub_dir}:/sbin:/bin:/usr/sbin:/usr/bin",
            # Steer every other migration step at throwaway paths so this test
            # exercises the pf work and nothing else.
            "GATEBSD_MAIN_CONF": str(self.dir / "absent-main.conf"),
            "GATEBSD_FAILOVER_CONF": str(self.dir / "absent-failover.conf"),
            "GATEBSD_GATEWAY_CONF": str(self.dir / "absent-gateway.conf"),
            "GATEBSD_UNBOUND_CONF": str(self.dir / "absent-unbound.conf"),
            "GATEBSD_LEGACY_RU_STATE": str(self.dir / "absent-ru.state"),
            "RU_STATE_FILE": str(self.dir / "absent-ru-new.state"),
        })
        return subprocess.run(
            ["sh", str(MIGRATE)], env=environment,
            capture_output=True, text=True, timeout=60,
        )

    def _lines(self) -> list[str]:
        return self.pf.read_text(encoding="utf-8").splitlines()

    def _index_of(self, needle: str) -> int:
        for index, line in enumerate(self._lines()):
            if needle in line:
                return index
        self.fail(f"not found in the ruleset: {needle}")
        return -1

    # ------------------------------------------------------------------ placement
    def test_the_redirect_stays_inside_the_translation_section(self) -> None:
        """After the last nat rule and before any filter rule, or pf refuses the file."""
        self._run()
        rdr_at = self._index_of(RDR)
        last_nat = max(i for i, line in enumerate(self._lines()) if line.startswith("nat on "))
        first_filter = min(
            i for i, line in enumerate(self._lines())
            if line.startswith(("block ", "pass "))
        )
        self.assertGreater(rdr_at, last_nat)
        self.assertLess(rdr_at, first_filter, "a translation rule after a filter rule is a parse error")

    def test_the_dot_block_precedes_every_quick_pass(self) -> None:
        """First matching quick rule wins; placed after them the block is dead."""
        self._run()
        block_at = self._index_of(BLOCK)
        broad_passes = [
            i for i, line in enumerate(self._lines())
            if line.startswith("pass in quick on $lan_if") and " port " not in line
        ]
        self.assertTrue(broad_passes)
        self.assertLess(block_at, min(broad_passes))

    def test_local_traffic_is_left_alone(self) -> None:
        """A DNS server on the LAN is a legitimate setup, not something to break."""
        self._run()
        for rule in (RDR, BLOCK):
            self.assertIn("! <local_nets>", self._lines()[self._index_of(rule)])

    # ------------------------------------------------------------------ safety
    def test_running_twice_changes_nothing_the_second_time(self) -> None:
        self._run()
        once = self.pf.read_text(encoding="utf-8")
        self._run(ruleset=None)
        self.assertEqual(self.pf.read_text(encoding="utf-8"), once)

    def test_an_unrecognised_ruleset_is_left_untouched(self) -> None:
        """A hand-written ruleset belongs to the operator; refuse rather than mangle."""
        hand_written = "set skip on lo\npass in all\npass out all\n"
        result = self._run(ruleset=hand_written)
        self.assertEqual(self.pf.read_text(encoding="utf-8"), hand_written)
        self.assertIn("does not have the expected shape", result.stderr)

    def test_a_ruleset_pf_rejects_is_not_installed(self) -> None:
        self._stub("pfctl", accept=False)
        result = self._run()
        self.assertEqual(self.pf.read_text(encoding="utf-8"), LEGACY, "a rejected ruleset was installed")
        self.assertIn("pf rejected", result.stderr)

    def test_the_staged_ruleset_is_validated_before_being_installed(self) -> None:
        self._run()
        self.assertIn("pfctl -nf", self.calls.read_text(encoding="utf-8"))


class ShippedSampleTests(unittest.TestCase):
    """A fresh device gets the rules from the sample, not from the migration."""

    def test_the_sample_carries_both_rules_in_the_right_order(self) -> None:
        lines = SAMPLE.read_text(encoding="utf-8").splitlines()

        def index_of(needle: str) -> int:
            for i, line in enumerate(lines):
                if needle in line:
                    return i
            self.fail(f"the shipped sample is missing: {needle}")
            return -1

        rdr_at = index_of(RDR)
        block_at = index_of(BLOCK)
        last_nat = max(i for i, line in enumerate(lines) if line.startswith("nat on "))
        first_filter = min(i for i, line in enumerate(lines) if line.startswith(("block ", "pass ")))
        # Only the broad rules can shadow it. The NUT rule above `block in all`
        # is `quick` too but names tcp/3493, which cannot match port 853.
        broad_passes = [
            i for i, line in enumerate(lines)
            if line.startswith("pass in quick on $lan_if") and " port " not in line
        ]

        self.assertGreater(rdr_at, last_nat)
        self.assertLess(rdr_at, first_filter)
        self.assertTrue(broad_passes)
        self.assertLess(block_at, min(broad_passes))


if __name__ == "__main__":
    unittest.main()
