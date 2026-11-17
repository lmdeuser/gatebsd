"""The USB quirk that silences the ZTE stick's storage function.

The stick presents three interfaces: CDC ECM (the modem, which is the whole
reason it is plugged in), CDC-data, and a mass-storage function carrying a
"zero-CD" virtual CD-ROM and an empty card slot. The empty slot answers every
size query with NOT READY, and the router accumulated 171 such lines.

These tests *run* the delivery -- the make target and the staging lines lifted
out of ci/build.sh -- rather than reading them, because a delivery step that is
merely present in the source can still be unreachable.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "etc" / "loader.conf.d" / "gatebsd.conf"

# usb_quirk(4): hw.usb.quirk.<n>="<vid> <pid> <revlo> <revhi> <UQ_NAME> ..."
_QUIRK = re.compile(
    r'^hw\.usb\.quirk\.(\d+)="'
    r"(0x[0-9a-fA-F]{4})\s+(0x[0-9a-fA-F]{4})\s+"
    r"(\S+)\s+(\S+)\s+"
    r'(UQ_[A-Z0-9_]+(?:\s+UQ_[A-Z0-9_]+)*)"$'
)


def _settings(text: str) -> dict[str, str]:
    """Parse a loader config the way the loader does: comments and blanks out."""
    found = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        found[key.strip()] = value.strip()
    return found


class LoaderQuirkFileTests(unittest.TestCase):
    def test_the_shipped_quirk_is_well_formed_and_names_the_zte_stick(self) -> None:
        settings = _settings(SOURCE.read_text(encoding="utf-8"))
        self.assertIn("hw.usb.quirk.0", settings)
        line = f'hw.usb.quirk.0={settings["hw.usb.quirk.0"]}'

        match = _QUIRK.match(line)
        self.assertIsNotNone(match, f"not a usb_quirk(4) line: {line}")
        assert match is not None
        _index, vid, pid, _revlo, _revhi, names = match.groups()
        self.assertEqual(vid.lower(), "0x19d2", "vendor must stay ZTE")
        self.assertEqual(pid.lower(), "0x1405", "product must stay the MSM stick")
        self.assertIn("UQ_MSC_IGNORE", names.split())

    def test_the_root_mount_does_not_wait_for_usb(self) -> None:
        """A loose USB stick must not be able to make the appliance unbootable.

        usb(4) holds the root mount so a system rooted on USB can wait for it.
        This one is rooted on the internal SATA disk, so the hold buys nothing
        and costs everything: on 2026-08-01, after a power cut, the production
        router sat at "Root mount waiting for: usbus0" across repeated attempts
        because a MediaTek zero-CD dongle on a loose connector never finished
        enumerating. ada1 had already been found and sized. Reseating the stick
        by hand was the cure, and the screen named the bus, not the device --
        nothing a customer could act on.
        """
        settings = _settings(SOURCE.read_text(encoding="utf-8"))
        self.assertEqual(
            settings.get("hw.usb.no_boot_wait"), '"1"',
            "the root mount must not be held for USB enumeration",
        )

    def test_every_setting_is_one_the_loader_will_accept(self) -> None:
        """A typo here is silent: the loader skips what it cannot parse."""
        settings = _settings(SOURCE.read_text(encoding="utf-8"))
        self.assertTrue(settings, "the shipped loader config sets nothing")
        for key, value in settings.items():
            self.assertRegex(key, r"^[A-Za-z][A-Za-z0-9_.]*$", key)
            self.assertRegex(value, r'^".*"$', f"{key} must be quoted")

    def test_the_quirk_is_narrowed_to_one_device_and_spares_the_modem(self) -> None:
        """A wildcard here would blind umass(4) to every USB disk on the box."""
        text = SOURCE.read_text(encoding="utf-8")
        for wildcard in ('"0x0000', '0xffff 0xffff', "UQ_MATCH_VENDOR"):
            self.assertNotIn(wildcard, text, f"quirk must not match broadly: {wildcard}")
        # cdce(4) owns interface 0; nothing here may reach for the whole device.
        self.assertNotIn("UQ_CFG_INDEX", text)

    def test_the_file_is_named_conf_because_the_loader_ignores_anything_else(self) -> None:
        """loader.conf(5): the lua loader processes *.conf in loader_conf_dirs.

        This is nginx's rule, not cron(8)'s or rcorder(8)'s -- both of which read
        every file in their directory and have already cost this project an
        outage apiece. A leftover gatebsd.conf.bak here is inert; the same name
        in cron.d or rc.d is not.
        """
        self.assertEqual(SOURCE.suffix, ".conf")


INSTALLER = ROOT / "scripts" / "install-loader-conf.sh"


class LoaderQuirkDeliveryTests(unittest.TestCase):
    """Both delivery paths run one installer; these tests run it too.

    The installer is a script rather than a recipe inside the Makefile for two
    reasons. The same fact written in two files is the failure this product
    keeps paying for -- and the validation host has no make(1) at all, so a
    test that shelled out to it could only ever be skipped there, which is a
    test that does not exist.
    """

    def _installed(self, dest: Path) -> dict[str, str]:
        return _settings((dest / "gatebsd.conf").read_text(encoding="utf-8"))

    def test_the_installer_lands_the_quirk_in_the_loader_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "loader.conf.d"
            result = subprocess.run(
                [str(INSTALLER), str(dest)], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((dest / "gatebsd.conf").is_file())
            self.assertEqual(
                self._installed(dest), _settings(SOURCE.read_text(encoding="utf-8"))
            )

    def test_the_installer_resolves_its_source_without_a_working_directory(self) -> None:
        """ci/build.sh runs from a staging tree, not from the repository root."""
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "loader.conf.d"
            result = subprocess.run(
                [str(INSTALLER), str(dest)],
                cwd=tmp,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((dest / "gatebsd.conf").is_file())

    def test_the_installer_refuses_a_symlinked_loader_directory(self) -> None:
        """/boot is shared; following a symlink there writes somewhere else."""
        with tempfile.TemporaryDirectory() as tmp:
            elsewhere = Path(tmp) / "elsewhere"
            elsewhere.mkdir()
            dest = Path(tmp) / "loader.conf.d"
            dest.symlink_to(elsewhere)
            result = subprocess.run(
                [str(INSTALLER), str(dest)], capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0, "symlinked directory accepted")
            self.assertFalse((elsewhere / "gatebsd.conf").exists())

    def test_package_staging_line_puts_the_quirk_under_boot(self) -> None:
        """Run build.sh's own staging statement against a throwaway stage."""
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        statements = [
            line.strip()
            for line in build.splitlines()
            if "install-loader-conf.sh" in line and not line.strip().startswith("#")
        ]
        self.assertTrue(statements, "build.sh no longer stages the loader config")

        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            stage.mkdir()
            script = "\n".join(
                ["set -eu", f'STAGE="{stage}"', f'REPO_DIR="{ROOT}"'] + statements
            )
            result = subprocess.run(
                ["/bin/sh", "-c", script], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            staged = stage / "boot" / "loader.conf.d"
            self.assertTrue(
                (staged / "gatebsd.conf").is_file(), "package would not carry the quirk"
            )
            self.assertEqual(
                self._installed(staged), _settings(SOURCE.read_text(encoding="utf-8"))
            )

    def test_the_generated_file_list_carries_what_lives_outside_the_prefix(self) -> None:
        """Staged is not packaged.

        The first attempt shipped nothing: the file reached the staging tree,
        but the list the manifest is built from was generated by walking
        $STAGE/usr/local, so anything outside the prefix was dropped without a
        word. The device showed an empty /boot/loader.conf.d and the build was
        green. This runs the generator against a synthetic stage.
        """
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        start = build.index("FILES_LIST=$(cd ")
        end = build.index("done)", start) + len("done)")
        generator = build[start:end]

        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            for relative in (
                "usr/local/sbin/gatebsd-scan",
                "usr/local/share/gatebsd/VERSION",
                "boot/loader.conf.d/gatebsd.conf",
            ):
                path = stage / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x", encoding="utf-8")

            result = subprocess.run(
                ["/bin/sh", "-c", f'set -eu\nSTAGE="{stage}"\n{generator}\nprintf "%s\\n" "$FILES_LIST"'],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            listed = result.stdout
            self.assertIn("/boot/loader.conf.d/gatebsd.conf:", listed)
            self.assertIn("/usr/local/share/gatebsd/VERSION:", listed)
            # Executable modes must survive the move to absolute paths.
            self.assertIn('/usr/local/sbin/gatebsd-scan: "0755"', listed)

    def test_the_make_path_delegates_to_the_same_installer(self) -> None:
        """Not a source check for its own sake: make(1) is absent on the

        validation host, so the only thing that can be asserted everywhere is
        that the make path has not grown a second copy of the logic.
        """
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        after = makefile.split("\ninstall-loader-conf:", 1)[1].splitlines()[1:]
        # A recipe runs until the first line that is not indented with a tab.
        recipe = []
        for line in after:
            if not line.startswith("\t"):
                break
            recipe.append(line)
        lines = [ln.strip() for ln in recipe if ln.strip()]
        self.assertTrue(lines, "install-loader-conf has no recipe at all")
        self.assertTrue(
            all("install-loader-conf.sh" in ln or ln.startswith("#") for ln in lines),
            f"make path must delegate, not reimplement: {lines}",
        )


if __name__ == "__main__":
    unittest.main()
