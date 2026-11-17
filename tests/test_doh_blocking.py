"""Port 443 was the one way left out of this resolver, and it was open.

Port 53 is redirected to the local resolver and port 853 is blocked, so a
client that wants a resolver of its own has exactly one route: DoH over HTTPS,
indistinguishable from any other web request. The working note claimed this was
"closed by a list of known endpoints". Measured on the production router, pf
carried no such table and no such rule -- `pfctl -sT` listed only <local_nets>.
The note described a plan.

What is closable is closed here: the well-known public resolvers, at stable
anycast addresses. What is not is DoH from an address that also serves ordinary
web content, since blocking those blocks the sites sharing them -- which is why
the endpoint list carries no CDN ranges and why this narrows the escape instead
of sealing it.

Every test RUNS sbin/gatebsd-config-migrate against a real pfctl parse.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "sbin" / "gatebsd-config-migrate"
ENDPOINTS = ROOT / "etc" / "gatebsd" / "doh-endpoints"

# The shape the migration anchors on: a table section, the translation rules,
# `block in all`, and the quick pass that would swallow a rule appended after it.
BASE_PF = """\
wan_if="ng0"
lan_if="re1"
lan_net="10.88.0.0/24"

table <local_nets> const { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }

set skip on lo
set block-policy drop

nat on $wan_if from $lan_net to any -> ($wan_if)

block in all

pass out quick keep state
pass in quick on $lan_if from $lan_net to any keep state
"""

TABLE_MARK = 'table <doh> persist file'
RULE_MARK = "block in quick on $lan_if proto { tcp udp } from $lan_net to <doh> port 443"


@unittest.skipUnless(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    "gatebsd-config-migrate refuses to run unprivileged",
)
class DohIsBlockedOnPortFourFourThree(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)
        self.pf = self.dir / "pf.conf"
        self.pf.write_text(BASE_PF, encoding="utf-8")
        self.pf.chmod(0o600)
        self.endpoints = self.dir / "doh-endpoints"
        shutil.copyfile(ENDPOINTS, self.endpoints)
        self.rc = self.dir / "rc.d"
        self.rc.mkdir()
        # pfctl exists on the router and not in the harness, so the migration
        # would bail before touching anything and every assertion below would
        # pass on an untouched file. The stub records what it was asked.
        self.stub_dir = self.dir / "bin"
        self.stub_dir.mkdir()
        self.calls = self.dir / "calls.txt"
        self._stub_pfctl(accept=True)

    def _stub_pfctl(self, accept: bool, *, real_parse: bool = False) -> None:
        stub = self.stub_dir / "pfctl"
        # Even the real parser is sandboxed: status says PF is absent and every
        # operation except -n is refused, so no test can load rules into a host.
        parse = '/sbin/pfctl "$@"' if real_parse else f'exit {0 if accept else 1}'
        stub.write_text(
            f'#!/bin/sh\necho "pfctl $*" >> "{self.calls}"\n'
            f'case "$1" in\n'
            f'  -nf) {parse} ;;\n'
            f'  -s) exit 1 ;;\n'
            f'  *) exit 99 ;;\n'
            f'esac\nexit 0\n',
            encoding="utf-8",
        )
        stub.chmod(0o755)

    def _run(self, **overrides: str) -> subprocess.CompletedProcess:
        environment = dict(os.environ)
        environment.update({
            "GATEBSD_PF_CONF": str(self.pf),
            "GATEBSD_DOH_ENDPOINTS": str(self.endpoints),
            "GATEBSD_PATH": f"{self.stub_dir}:/sbin:/bin:/usr/sbin:/usr/bin",
            "GATEBSD_RC_DIR": str(self.rc),
            # Everything else this script migrates is out of scope here.
            "GATEBSD_MAIN_CONF": str(self.dir / "absent-main.conf"),
            "GATEBSD_FAILOVER_CONF": str(self.dir / "absent-failover.conf"),
            "GATEBSD_GATEWAY_CONF": str(self.dir / "absent-gateway.conf"),
            "GATEBSD_UNBOUND_CONF": str(self.dir / "absent-unbound.conf"),
            "GATEBSD_NGINX_CONF": str(self.dir / "absent-nginx.conf"),
            "GATEBSD_LEGACY_RU_STATE": str(self.dir / "absent-ru.state"),
            "RU_STATE_FILE": str(self.dir / "absent-ru-new.state"),
        })
        environment.update(overrides)
        return subprocess.run(
            ["sh", str(MIGRATE)], env=environment,
            capture_output=True, text=True, timeout=60,
        )

    def _rules(self) -> list[str]:
        return [line.strip() for line in self.pf.read_text(encoding="utf-8").splitlines()]

    # ------------------------------------------------------------------ the hole
    def test_the_table_and_the_rule_are_both_added(self) -> None:
        result = self._run()
        text = self.pf.read_text(encoding="utf-8")
        self.assertIn(TABLE_MARK, text, result.stderr)
        self.assertIn(RULE_MARK, text)

    def test_the_rule_lands_where_it_can_actually_match(self) -> None:
        """First matching `quick` rule wins.

        A block appended at the end parses, loads, and does nothing: the
        `pass in quick ... to any` above it has already matched. This is the
        same trap the DNS interception rules were written around.
        """
        self._run()
        rules = self._rules()
        block_all = rules.index("block in all")
        doh = next(i for i, line in enumerate(rules) if line == RULE_MARK)
        passes = [i for i, line in enumerate(rules) if line.startswith("pass in quick")]
        self.assertGreater(doh, block_all, "the rule must follow block in all")
        self.assertTrue(all(doh < i for i in passes), "a quick pass would match first")

    def test_the_table_is_declared_before_the_rule_that_uses_it(self) -> None:
        self._run()
        rules = self._rules()
        table = next(i for i, line in enumerate(rules) if line.startswith(TABLE_MARK))
        doh = next(i for i, line in enumerate(rules) if line == RULE_MARK)
        self.assertLess(table, doh)

    def test_the_result_is_a_ruleset_pf_accepts(self) -> None:
        """The real parser, where there is one. A stub proves only plumbing."""
        if platform.system() != "FreeBSD" or not Path("/sbin/pfctl").exists():
            self.skipTest("a real pfctl only exists on FreeBSD")
        self._stub_pfctl(accept=True, real_parse=True)
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = subprocess.run(
            ["pfctl", "-nf", str(self.pf)], capture_output=True, text=True
        )
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        commands = self.calls.read_text(encoding="utf-8")
        self.assertNotIn("pfctl -f ", commands, "a test must never replace host PF rules")

    # ------------------------------------------------------------------ restraint
    def test_running_twice_does_not_duplicate_anything(self) -> None:
        self._run()
        first = self.pf.read_text(encoding="utf-8")
        self._run()
        self.assertEqual(self.pf.read_text(encoding="utf-8"), first)
        self.assertEqual(first.count(RULE_MARK), 1)
        self.assertEqual(first.count(TABLE_MARK), 1)

    def test_without_the_endpoint_list_nothing_is_written(self) -> None:
        """pf fails the whole ruleset over a persist table whose file is gone.

        That would take down the rules keeping this router closed from outside,
        so a missing list is a reason to do nothing, not to write the rule and
        hope.
        """
        self.endpoints.unlink()
        result = self._run()
        # The claim is that *these* rules were not written. The interception
        # step legitimately edits the same file, so byte equality would be
        # testing the wrong thing -- the same mistake the canary test made.
        text = self.pf.read_text(encoding="utf-8")
        self.assertNotIn(TABLE_MARK, text)
        self.assertNotIn(RULE_MARK, text)
        self.assertIn("no DoH endpoint list", result.stderr)

    def test_a_ruleset_of_another_shape_is_left_alone(self) -> None:
        """A hand-written ruleset is the operator's; mangling it is worse."""
        foreign = "# somebody else's firewall\npass in all\n"
        self.pf.write_text(foreign, encoding="utf-8")
        result = self._run()
        self.assertEqual(self.pf.read_text(encoding="utf-8"), foreign)
        self.assertIn("does not have the expected shape", result.stderr)

    def test_a_ruleset_pf_rejects_is_never_published(self) -> None:
        self._stub_pfctl(accept=False)
        result = self._run()
        text = self.pf.read_text(encoding="utf-8")
        self.assertNotIn(TABLE_MARK, text)
        self.assertNotIn(RULE_MARK, text)
        self.assertIn("pf rejected the DoH rules", result.stderr)
        self.assertIn("pfctl -nf", self.calls.read_text(encoding="utf-8"))

    def test_the_file_keeps_its_mode(self) -> None:
        self._run()
        self.assertEqual(self.pf.stat().st_mode & 0o777, 0o600)


class TheEndpointListIsUsable(unittest.TestCase):
    def test_every_entry_is_an_address_or_a_network(self) -> None:
        import ipaddress

        seen: set[str] = set()
        for raw in ENDPOINTS.read_text(encoding="utf-8").splitlines():
            entry = raw.split("#", 1)[0].strip()
            if not entry:
                continue
            ipaddress.ip_network(entry, strict=True)
            self.assertNotIn(entry, seen, f"duplicate entry: {entry}")
            seen.add(entry)
        self.assertGreater(len(seen), 20, "the list lost most of its entries")

    def test_no_cdn_range_crept_in(self) -> None:
        """A shared address serves DoH and somebody's website from one IP.

        Blocking those is how a DNS policy starts taking unrelated sites down,
        so the list is dedicated resolver addresses only. Cloudflare's
        cloudflare-dns.com also answers inside 104.16.0.0/12; that is exactly
        what must not be here.
        """
        import ipaddress

        forbidden = [ipaddress.ip_network("104.16.0.0/12")]
        for raw in ENDPOINTS.read_text(encoding="utf-8").splitlines():
            entry = raw.split("#", 1)[0].strip()
            if not entry:
                continue
            network = ipaddress.ip_network(entry, strict=True)
            for cdn in forbidden:
                self.assertFalse(
                    network.subnet_of(cdn) if network.version == cdn.version else False,
                    f"{entry} is inside shared CDN space {cdn}",
                )

    def test_the_router_own_forwarders_are_listed(self) -> None:
        """Blocking 1.1.1.1:443 from the LAN must not be mistaken for a conflict.

        The resolver forwards to these on port 53 from the router itself; the
        rule matches inbound on the LAN interface from the LAN network, so the
        two never meet. Listing them is the point -- they are the most likely
        DoH endpoints a client would pick.
        """
        entries = {
            raw.split("#", 1)[0].strip()
            for raw in ENDPOINTS.read_text(encoding="utf-8").splitlines()
            if raw.split("#", 1)[0].strip()
        }
        for forwarder in ("1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"):
            self.assertIn(forwarder, entries)


class ThePackageCarriesTheEndpointList(unittest.TestCase):
    """Staged is not packaged, and unstaged does not even build.

    The first attempt shipped an install line without adding the directory to
    build.sh's mkdir, and the build died on the stand: `install: /build/stage/
    usr/local/etc/gatebsd: No such file or directory`. The staging test that
    existed created its own directories first, so it proved the install line
    and hid the missing mkdir. This one runs both statements together, as the
    build does.
    """

    def setUp(self) -> None:
        self.build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")

    def test_the_stage_directory_and_the_install_come_as_a_pair(self) -> None:
        start = self.build.index("mkdir -p \\\n")
        end = self.build.index('"$DIST"', start) + len('"$DIST"')
        mkdir_block = self.build[start:end]

        install_lines = [
            line.strip()
            for line in self.build.splitlines()
            if "doh-endpoints" in line
            and line.strip().startswith("install -m")
        ]
        self.assertTrue(install_lines, "build.sh no longer stages the DoH list")

        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            dist = Path(tmp) / "dist"
            script = "\n".join(
                ["set -eu", f'STAGE="{stage}"', f'DIST="{dist}"', f'REPO_DIR="{ROOT}"',
                 mkdir_block] + install_lines
            )
            result = subprocess.run(
                ["/bin/sh", "-c", script], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            staged = stage / "usr/local/etc/gatebsd/doh-endpoints"
            self.assertTrue(staged.is_file(), "the package would not carry the list")
            self.assertEqual(staged.read_bytes(), ENDPOINTS.read_bytes())


if __name__ == "__main__":
    unittest.main()
