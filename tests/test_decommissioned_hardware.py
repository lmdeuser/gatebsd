"""Nothing in the tree describes the machine that was taken apart.

The stand was a physical mini-PC until 14 August 2026. It became a virtual
machine, was powered off on the 15th, and its disk was reformatted on the 16th;
it will not come back. Two things it left behind were still in the repository:

  * ci/host/repair_n100_boot.sh and ci/host/configure_n100_console_samba.sh --
    bring-up tools for that hardware, one of which wrote a lagg and a static
    address that no longer exist anywhere;
  * /usr/local/etc/rc.d/n100_network_ready -- a live rc script named after the
    machine model rather than the role, deployed on a stand that is not that
    machine.

Dead tools are not inert here. The repair script's own header records that a
stale hand-installed copy of it would have put a fifteen-second wait for a
removed USB NIC back into rc.d, where rcorder(8) reads every file whatever it
is called, and nothing would have said so until the next boot. Keeping a script
that "obviously nobody would run" is how that happens.

The rc script was renamed to stand_network_ready. A rename there is not one row
in a manifest: rcorder reads the whole directory, so the old file had to be
carried out of rc.d and its `_enable` variable replaced in rc.conf, or the
stand would have run two of them at boot.
"""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "infra" / "freebsd-ci" / "deployment.manifest"
RC_SOURCE = ROOT / "infra" / "freebsd-ci" / "rc.d-stand_network_ready"

RC_NAME = "stand_network_ready"

# The address the decommissioned machine answered on. It appears in no live
# configuration; every remaining mention was provenance prose, and prose that
# names a dead address reads as a fact about the running system.
RETIRED_ADDRESS = "10.88.0.164"

GONE = (
    "ci/host/repair_n100_boot.sh",
    "ci/host/configure_n100_console_samba.sh",
    "ci/controller/n100_ci_config",
    "ci/controller/n100_ci_known_hosts",
    "infra/freebsd-ci/rc.d-n100_network_ready",
)


# Directories that are not source: version control, agent scratch, and the
# secrets tree, which is untracked and holds credentials rather than prose.
SKIP_DIRS = {".git", ".claude", ".secrets", "__pycache__", "node_modules"}


def source_files() -> list[Path]:
    """Every file in the tree, walked rather than asked of git.

    An earlier version shelled out to `git ls-files` and died wherever the
    checkout was not a repository git would talk about -- the read-only Docker
    harness among them. Walking also covers files that are present but
    untracked, which is the more useful question here anyway.
    """
    found = []
    for path in ROOT.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            found.append(path)
    return found


class TheHardwareIsGone(unittest.TestCase):
    def test_its_bring_up_tools_are_not_in_the_tree(self) -> None:
        for path in GONE:
            with self.subTest(path=path):
                self.assertFalse((ROOT / path).exists(), f"{path} is still here")

    def test_nothing_in_the_tree_names_its_address(self) -> None:
        """No exemptions left, and that is the point.

        For a while docs/ and renew-stand-tls.sh were allowed to name it,
        because one true statement remained: the stand's live TLS certificate
        still carried the address in its SAN, and `step ca renew` reissues the
        same names, so no renewal would ever drop it. Hiding that to make this
        test pass would have turned an open item into an invisible one.

        The certificate was reissued on 16 August 2026 and the statement stopped
        being true, so the exemptions went with it. The address now appears
        nowhere -- which is the only state in which this test means anything.
        """
        offenders = []
        for path in source_files():
            if path == Path(__file__).resolve():
                continue  # it has to spell the address to look for it
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue  # binary or unreadable: no address to find in it
            for number, line in enumerate(text.splitlines(), start=1):
                if RETIRED_ADDRESS in line:
                    offenders.append(f"{path.relative_to(ROOT)}:{number}")
        self.assertEqual(
            offenders, [],
            f"{RETIRED_ADDRESS} belongs to a machine that was reformatted",
        )


class TheRcScriptIsNamedForItsRole(unittest.TestCase):
    """Four places have to agree, and rcorder only reads one of them.

    The file name, the `name=`/`rcvar=` pair rc.subr dispatches on, the PROVIDE
    line rcorder reads, and the manifest row that decides where it is installed.
    A rename that misses any one of them leaves a script that is deployed and
    inert, or enabled under a variable nobody sets.
    """

    def setUp(self) -> None:
        self.text = RC_SOURCE.read_text(encoding="utf-8")

    def test_the_script_declares_the_role_name_throughout(self) -> None:
        self.assertIn(f"# PROVIDE: {RC_NAME}\n", self.text)
        self.assertIn(f'name="{RC_NAME}"\n', self.text)
        self.assertIn(f'rcvar="{RC_NAME}_enable"\n', self.text)
        self.assertIn("run_rc_command", self.text)

    def test_the_old_name_survives_only_as_history(self) -> None:
        """The rename is worth recording; the name is not worth dispatching on."""
        for number, line in enumerate(self.text.splitlines(), start=1):
            if "n100" in line:
                self.assertTrue(
                    line.lstrip().startswith("#"),
                    f"rc.d-{RC_NAME}:{number} still runs on the old name: {line!r}",
                )

    def test_the_manifest_deploys_it_under_the_same_name(self) -> None:
        row = None
        for line in MANIFEST.read_text(encoding="utf-8").splitlines():
            stripped = line.split("#", 1)[0].strip()
            if stripped.startswith("infra/freebsd-ci/rc.d-"):
                row = stripped.split()
        self.assertIsNotNone(row, "no rc.d row in the manifest")
        source, target = row[0], row[1]
        self.assertEqual(source, f"infra/freebsd-ci/rc.d-{RC_NAME}")
        self.assertEqual(target, f"/usr/local/etc/rc.d/{RC_NAME}")
        self.assertTrue((ROOT / source).is_file(), source)

    def test_nothing_deploys_the_old_rc_script(self) -> None:
        """Two files in rc.d with a PROVIDE line is two scripts at boot."""
        self.assertNotIn("rc.d/n100_network_ready", MANIFEST.read_text(encoding="utf-8"))

    def test_the_address_is_read_from_rc_conf_rather_than_known(self) -> None:
        """The whole reason the script stopped naming a machine: it puts back
        what rc.conf already declared, so it is correct on a stand it has never
        seen."""
        self.assertRegex(self.text, r"ifconfig_\[a-z\]|ifconfig_")
        self.assertNotRegex(self.text, r"^[^#]*inet 172\.31\.")


if __name__ == "__main__":
    unittest.main()
