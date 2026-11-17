#!/usr/bin/env python3
"""Local blocklist additions, run through the real update script.

A name we caught ourselves has to survive the next update, so it cannot live in
a downloaded list. It goes in /usr/local/etc/gatebsd/adblock-extra and is merged
with the sources before parsing, which also means it inherits the shrink
protection: a typo here cannot empty the blocklist.

The test that matters is the missing-file one. `set -e` plus a bare read of a
file that is not there is exactly how the adblock update has been killed before
-- and a device that never added anything of its own is the normal case, not
the exception.
"""
import functools
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "sbin" / "gatebsd-adblock-update.sh"
EXTRA = REPO_ROOT / "etc" / "gatebsd" / "adblock-extra"


def shipped_names() -> list[str]:
    """Every name the additions file carries, comments and blanks dropped."""
    return [
        line.split()[1]
        for line in EXTRA.read_text(encoding="utf-8").splitlines()
        if line.startswith("0.0.0.0 ")
    ]


class ShippedAdditions(unittest.TestCase):
    def test_the_file_ships_hosts_entries_and_abp_exceptions(self):
        lines = [
            line.split()
            for line in EXTRA.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertTrue(lines, "additions file has no entries")
        for parts in lines:
            if parts[0].startswith("@@||"):
                self.assertEqual(len(parts), 1, f"invalid ABP exception: {parts}")
                self.assertTrue(parts[0].endswith("^"), f"invalid ABP exception: {parts}")
            else:
                self.assertEqual(len(parts), 2, f"not a hosts line: {parts}")
                self.assertEqual(parts[0], "0.0.0.0")

    def test_the_names_we_caught_are_in_it(self):
        names = shipped_names()
        for caught in (
            "ads.vk.com",
            "smi2.ru",
            "imasdk.googleapis.com",
            "tracker.my.com",
            "mytracker.mail.ru",
            "trk.mail.ru",
            "tracker.mail.ru",
            "ads.vk.ru",
            "appmetrica.yandex.ru",
            "ads.rustore.ru",
            "api.inappstory.ru",
            "rs.mail.ru",
        ):
            self.assertIn(caught, names)

    def test_the_store_itself_is_never_blocked(self):
        """ads.rustore.ru shares an address with backapi.rustore.ru.

        Blocking the ad endpoint is free only because DNS blocks a name, not
        an address. The failure mode to guard is someone "tidying up" by
        adding the parent or the API host, which takes the whole store --
        catalogue, installs and updates -- off the LAN.
        """
        keep = {
            "rustore.ru",
            "api.rustore.ru",
            "backapi.rustore.ru",
            "rc.rustore.ru",
            "static-rustore.cdn-vk.ru",
            "cdn-vk.ru",
            "sdk.mail.ru",
        }
        for name in shipped_names():
            self.assertNotIn(name, keep, f"this name is the store, not its ads: {name}")

    def test_no_entry_takes_out_a_whole_shared_zone(self):
        """Same guard as the IMA one, for the zones the app trackers live in.

        These names sit under domains that also carry mail, login and the
        search engine. vk.com, vk.ru, mail.ru and yandex.ru answer a wildcard,
        so a name here that resolves proves nothing -- and a bare second-level
        entry would null the whole zone while looking like a normal addition.
        """
        shared = {"vk.com", "vk.ru", "mail.ru", "my.com", "yandex.ru", "yandex.net"}
        for name in shipped_names():
            self.assertNotIn(name, shared, f"entry nulls a whole shared zone: {name}")
            self.assertTrue(
                name.count(".") >= 1, f"entry is not a hostname: {name}"
            )

    def test_the_ima_entry_is_one_exact_name(self):
        """It blocks the ad SDK, not googleapis.com at large.

        A wildcard or a bare googleapis.com here would take out fonts, maps and
        every other API a page on this LAN loads, and the breakage would look
        like anything but the blocklist.
        """
        for name in shipped_names():
            self.assertNotEqual(name, "googleapis.com")
            self.assertFalse(name.startswith("*"), f"wildcard entry: {name}")

    def test_both_delivery_paths_install_it(self):
        """The image and the package must land on the same device state."""
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        build = (REPO_ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        self.assertIn("etc/gatebsd/adblock-extra", makefile)
        self.assertIn("etc/gatebsd/adblock-extra", build)


class BrowserExtensionCompatibility(unittest.TestCase):
    def test_kimi_telemetry_is_not_blocked(self):
        self.assertIn(
            "@@||gator.volces.com^",
            EXTRA.read_text(encoding="utf-8").splitlines(),
        )


class SourceList(unittest.TestCase):
    def test_the_adguard_dns_filter_is_a_source(self):
        """The list AdGuard Home itself uses, not just the browser filters.

        Having only the browser filters is why a phone running AdGuard blocked
        names this router let through.
        """
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("AdGuardSDNSFilter", text)

    def test_hagezi_pro_is_a_source(self):
        """Chosen by measurement on 3 August, and the measurement is in the file.

        Of five candidates it had the best hit rate per name added against the
        twelve names this project had found by hand, and it is curated against
        breakage. OISD Big brought 345k names and matched two of the twelve;
        1Hosts Xtra brought a million and calls itself aggressive. Neither is
        here, and the comment above the source list says why so that nobody
        adds them back on the strength of the domain count alone.
        """
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("hagezi/dns-blocklists", text)
        self.assertNotIn("oisd.nl", text)
        self.assertNotIn("1Hosts/Xtra", text)


@unittest.skipUnless(
    shutil.which("fetch") and shutil.which("unbound-checkconf"),
    "needs FreeBSD tools; covered by the Docker/stand harness",
)
class MissingFileIsNormal(unittest.TestCase):
    """The additions file is optional, and its absence must not kill the run."""

    def _run(self, extra_path: str | None) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            unbound_conf = tmp_path / "unbound.conf"
            unbound_conf.write_text("server:\n", encoding="utf-8")
            env = dict(os.environ)
            env.update(
                {
                    "GATEBSD_ADBLOCK_URLS": "http://127.0.0.1:1/nope",
                    "GATEBSD_UNBOUND_CONF": str(unbound_conf),
                    "GATEBSD_ADBLOCK_CONF": str(tmp_path / "adblock.conf"),
                    "GATEBSD_ADBLOCK_LOG": str(tmp_path / "adblock.log"),
                    "GATEBSD_ADBLOCK_LOCK": str(tmp_path / "lock"),
                    "GATEBSD_ADBLOCK_LOCK_HELD": "1",
                }
            )
            if extra_path is not None:
                env["GATEBSD_ADBLOCK_EXTRA"] = extra_path
            return subprocess.run(
                ["sh", str(SCRIPT)],
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )

    def test_absent_additions_file_does_not_abort_before_the_source_gate(self):
        """With no sources and no additions file, it must fail on the sources.

        Failing with "no blocklist source could be downloaded" is the correct
        refusal. Dying earlier and silently on the missing additions file is
        the regression this guards.
        """
        result = self._run(str(Path(tempfile.gettempdir()) / "definitely-absent-adblock-extra"))
        combined = result.stdout + result.stderr
        self.assertIn("no blocklist source", combined.lower())

    def test_unset_additions_path_behaves_the_same(self):
        result = self._run(None)
        combined = result.stdout + result.stderr
        self.assertIn("no blocklist source", combined.lower())


@unittest.skipUnless(
    shutil.which("fetch") and shutil.which("unbound-checkconf"),
    "needs FreeBSD tools; covered by the Docker/stand harness",
)
class MergeReachesTheBlocklist(unittest.TestCase):
    def test_additions_land_in_the_generated_blocklist(self):
        import http.server
        import threading

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            served = tmp_path / "served"
            served.mkdir()
            (served / "hosts").write_text(
                "\n".join(f"0.0.0.0 filler{n}.example" for n in range(2000))
                + "\n0.0.0.0 gator.volces.com\n",
                encoding="utf-8",
            )
            handler = functools.partial(
                http.server.SimpleHTTPRequestHandler, directory=str(served)
            )
            server = http.server.HTTPServer(("127.0.0.1", 0), handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                unbound_conf = tmp_path / "unbound.conf"
                unbound_conf.write_text("server:\n", encoding="utf-8")
                blocklist = tmp_path / "adblock.conf"
                env = dict(os.environ)
                env.update({
                    "GATEBSD_ADBLOCK_URLS": f"http://127.0.0.1:{server.server_port}/hosts",
                    "GATEBSD_UNBOUND_CONF": str(unbound_conf),
                    "GATEBSD_ADBLOCK_CONF": str(blocklist),
                    "GATEBSD_ADBLOCK_LOG": str(tmp_path / "adblock.log"),
                    "GATEBSD_ADBLOCK_LOCK": str(tmp_path / "lock"),
                    "GATEBSD_ADBLOCK_LOCK_HELD": "1",
                    "GATEBSD_ADBLOCK_EXTRA": str(EXTRA),
                    # This run succeeds, so it writes the inputs stamp. Keep it
                    # in the fixture: the production default is under
                    # /var/db/gatebsd-system, and a suite run as root on a real
                    # device would leave a stamp there describing this test.
                    "GATEBSD_ADBLOCK_STAMP": str(tmp_path / "adblock-inputs"),
                })
                result = subprocess.run(
                    ["sh", str(SCRIPT)], env=env, capture_output=True,
                    text=True, timeout=180,
                )
            finally:
                server.shutdown()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            produced = blocklist.read_text(encoding="utf-8")
            for name in shipped_names():
                self.assertIn(name, produced, f"addition did not reach the blocklist: {name}")
            self.assertNotIn('local-zone: "gator.volces.com."', produced)


if __name__ == "__main__":
    unittest.main()
