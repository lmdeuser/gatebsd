"""Regression tests for first-boot device provisioning.

The product is delivered by writing one image to many mini PCs, so everything in
that image starts out identical on every unit. Some of it must not stay that
way. A fleet whose units all present the same SSH host key is a fleet where host
key verification proves nothing: one unit's key impersonates every other, and an
operator who trusted their own box trusts an attacker's equally. The same is
true of a shared TLS private key for the management UI, and of a shared ZFS host
ID.

The guarantees asserted here:

* SSH host keys, the TLS certificate and the host ID are regenerated per device;
* each step records its own completion, so a power loss part way through first
  boot resumes rather than redoing or skipping the rest;
* a completed step is not repeated on later boots -- an identity the customer
  already trusted must not change underneath them;
* a failed security step is reported as failure, so the device does not come up
  serving the image's identity while claiming success;
* a failed convenience step does not block the boot;
* the rc script orders provisioning before sshd, which is what makes any of it
  effective.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIRSTBOOT = ROOT / "sbin" / "gatebsd-firstboot"
RC_SCRIPT = ROOT / "rc.d" / "gatebsd_firstboot"


class FirstBootTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "state"
        self.tls = self.root / "tls"
        self.ssh = self.root / "ssh"
        self.ssh.mkdir()
        self.hostid = self.root / "hostid"
        self.identity = self.root / "db" / "device-identity"
        self.calls = self.root / "calls.log"

        # The shipped image's identity: identical on every unit until first boot.
        (self.ssh / "ssh_host_ed25519_key").write_text("IMAGE KEY\n", encoding="utf-8")
        (self.ssh / "ssh_host_ed25519_key.pub").write_text("IMAGE PUB\n", encoding="utf-8")
        self.hostid.write_text("00000000-0000-0000-0000-000000000000\n", encoding="utf-8")

        self._stub("ssh-keygen", 'printf "DEVICE KEY\\n" > "$SSHDIR/ssh_host_ed25519_key"')
        self._stub("uuidgen", 'printf "11111111-2222-3333-4444-555555555555\\n"')
        self._stub("logger", "true")
        self._stub("kenv", "exit 1")
        self._stub("zpool", "exit 1")
        self._stub("gatebsd-ups-bootstrap", "exit 0")
        self._openssl_stub()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _stub(self, name: str, body: str) -> None:
        target = self.bin / name
        target.write_text(
            f'#!/bin/sh\nSSHDIR="{self.ssh}"\n'
            f'printf "{name} %s\\n" "$*" >> "{self.calls}"\n{body}\n',
            encoding="utf-8",
        )
        target.chmod(0o755)

    def _openssl_stub(self, succeed: bool = True) -> None:
        target = self.bin / "openssl"
        body = (
            'key=""; cert=""\n'
            'while [ $# -gt 0 ]; do\n'
            '  case "$1" in -keyout) key=$2; shift ;; -out) cert=$2; shift ;; esac\n'
            '  shift\n'
            'done\n'
        )
        if succeed:
            body += 'printf "DEVICE PRIVATE KEY\\n" > "$key"\nprintf "DEVICE CERT\\n" > "$cert"\nexit 0\n'
        else:
            body += "exit 1\n"
        target.write_text(
            f'#!/bin/sh\nprintf "openssl\\n" >> "{self.calls}"\n{body}', encoding="utf-8"
        )
        target.chmod(0o755)

    def run_firstboot(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(FIRSTBOOT)],
            capture_output=True,
            text=True,
            check=False,
            env={
                "PATH": f"{self.bin}:/usr/bin:/bin",
                "GATEBSD_PATH": f"{self.bin}:/usr/bin:/bin",
                "GATEBSD_FIRSTBOOT_STATE": str(self.state),
                "GATEBSD_TLS_DIR": str(self.tls),
                "GATEBSD_SSH_DIR": str(self.ssh),
                "GATEBSD_HOSTID_FILE": str(self.hostid),
                "GATEBSD_IDENTITY_FILE": str(self.identity),
                "GATEBSD_UPS_BOOTSTRAP": str(self.bin / "gatebsd-ups-bootstrap"),
                "HOME": str(self.root),
                "LANG": "C",
            },
        )

    def test_the_image_identity_is_replaced_on_first_boot(self) -> None:
        result = self.run_firstboot()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.ssh / "ssh_host_ed25519_key").read_text(encoding="utf-8"), "DEVICE KEY\n"
        )
        self.assertEqual((self.tls / "key.pem").read_text(encoding="utf-8"), "DEVICE PRIVATE KEY\n")
        self.assertNotIn("00000000-0000", self.hostid.read_text(encoding="utf-8"))

    def test_the_shipped_public_key_does_not_survive(self) -> None:
        """A leftover .pub from the image contradicts the new private key."""
        self.run_firstboot()
        stale = self.ssh / "ssh_host_ed25519_key.pub"
        if stale.exists():
            self.assertNotIn("IMAGE PUB", stale.read_text(encoding="utf-8"))

    def test_the_private_key_is_not_world_readable(self) -> None:
        self.run_firstboot()
        self.assertEqual((self.tls / "key.pem").stat().st_mode & 0o077, 0)

    def test_a_second_boot_does_not_change_an_established_identity(self) -> None:
        """The customer has already trusted this key; rotating it breaks them."""
        self.run_firstboot()
        first = (self.ssh / "ssh_host_ed25519_key").read_text(encoding="utf-8")
        self._stub("ssh-keygen", 'printf "SECOND KEY\\n" > "$SSHDIR/ssh_host_ed25519_key"')

        result = self.run_firstboot()
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.ssh / "ssh_host_ed25519_key").read_text(encoding="utf-8"), first)

    def test_an_interrupted_first_boot_resumes_where_it_stopped(self) -> None:
        """Power is lost at customer sites; that must not strand a step."""
        self._openssl_stub(succeed=False)
        first = self.run_firstboot()
        self.assertEqual(first.returncode, 1, first.stdout)
        self.assertTrue((self.state / "ssh_host_keys.done").exists())
        self.assertFalse((self.state / "tls_certificate.done").exists())
        established = (self.ssh / "ssh_host_ed25519_key").read_text(encoding="utf-8")

        # The unit is powered on again, and the certificate step now works.
        self._openssl_stub(succeed=True)
        self._stub("ssh-keygen", 'printf "SECOND KEY\\n" > "$SSHDIR/ssh_host_ed25519_key"')
        second = self.run_firstboot()

        self.assertEqual(second.returncode, 0, second.stdout)
        self.assertTrue((self.state / "tls_certificate.done").exists())
        # The completed step was not redone: the host key did not change.
        self.assertEqual(
            (self.ssh / "ssh_host_ed25519_key").read_text(encoding="utf-8"), established
        )

    def test_a_failed_security_step_is_reported_as_failure(self) -> None:
        self._openssl_stub(succeed=False)
        result = self.run_firstboot()
        self.assertEqual(result.returncode, 1)
        self.assertIn("CRITICAL", result.stdout)
        self.assertIn("image identity", result.stdout)

    def test_a_failed_convenience_step_does_not_fail_the_boot(self) -> None:
        """A pool that could not grow is not a reason to keep a device down."""
        result = self.run_firstboot()  # the zpool stub always fails
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("grow_pool", result.stdout)
        self.assertFalse((self.state / "grow_pool.done").exists())

    def test_grow_pool_uses_a_mirror_leaf_device(self) -> None:
        self._stub(
            "zpool",
            'if [ "$1" = list ]; then\n'
            '  printf "zroot 102G 22.9G 79.1G - - 17%% 22%% 1.00x ONLINE -\\n"\n'
            '  printf "mirror-0 102G 22.9G 79.1G - - 17%% 22.4%% - ONLINE -\\n"\n'
            '  printf "ada0p3 103G - - - - - - - ONLINE -\\n"\n'
            '  printf "ada1p3 103G - - - - - - - ONLINE -\\n"\n'
            "fi\n"
            "exit 0\n",
        )
        self._stub("gpart", "exit 0")

        result = self.run_firstboot()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.state / "grow_pool.done").exists(), result.stdout)
        calls = self.calls.read_text(encoding="utf-8")
        self.assertIn("gpart recover ada0\n", calls)
        self.assertIn("gpart resize -i 3 ada0\n", calls)
        self.assertIn("zpool online -e zroot ada0p3\n", calls)

    def test_a_step_that_failed_is_not_marked_complete(self) -> None:
        self._openssl_stub(succeed=False)
        self.run_firstboot()
        self.assertFalse((self.state / "tls_certificate.done").exists())

    def test_the_device_identity_records_the_image_version(self) -> None:
        self.run_firstboot()
        recorded = self.identity.read_text(encoding="utf-8")
        self.assertIn("serial=", recorded)
        self.assertIn("provisioned=", recorded)
        self.assertIn("image_version=", recorded)

    def test_a_placeholder_smbios_serial_is_not_used_as_an_identity(self) -> None:
        """Mini PCs ship 'To be filled by O.E.M.' far more often than a serial."""
        self._stub("kenv", 'printf "To be filled by O.E.M.\\n"')
        self.run_firstboot()
        recorded = self.identity.read_text(encoding="utf-8")
        self.assertNotIn("To be filled", recorded)
        self.assertIn("11111111-2222", recorded)


class FirstBootOrderingTests(unittest.TestCase):
    def test_provisioning_is_ordered_before_sshd(self) -> None:
        """Provisioning after sshd means first boot is served with image keys."""
        script = RC_SCRIPT.read_text(encoding="utf-8")
        before = [
            line for line in script.splitlines() if line.startswith("# BEFORE:")
        ]
        self.assertTrue(before, "the rc script declares no BEFORE line")
        self.assertIn("sshd", before[0])

    def test_provisioning_is_not_backgrounded(self) -> None:
        """Unlike the VPN apply, this one must block: ordering is the point."""
        script = RC_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("daemon -f", script)

    def test_it_is_enabled_by_default(self) -> None:
        """A shipped image whose provisioning is off defeats the whole exercise."""
        script = RC_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('gatebsd_firstboot_enable:="YES"', script)

    def test_the_provisioner_is_installed_by_makefile_and_package(self) -> None:
        self.assertIn("gatebsd-firstboot", (ROOT / "Makefile").read_text(encoding="utf-8"))
        self.assertIn("gatebsd_firstboot", (ROOT / "Makefile").read_text(encoding="utf-8"))
        build = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        self.assertIn("gatebsd-firstboot", build)
        self.assertIn("gatebsd_firstboot", build)

    def test_both_files_are_executable(self) -> None:
        for path in (FIRSTBOOT, RC_SCRIPT):
            self.assertTrue(os.access(path, os.X_OK), path.name)


class DeliveryParityTests(unittest.TestCase):
    """The two ways a device gets its software must produce the same device.

    A unit flashed from an image and a unit upgraded by package are both
    supported, and both must end up identical at the same version. They are
    built by different code -- `make install` and `ci/build.sh` -- and a
    component added to one and forgotten in the other produces two device
    populations that only differ under the exact conditions nobody tests. That
    divergence is invisible until a customer reports behaviour the fleet
    "cannot" have.
    """

    def _makefile_installs(self, directory: str) -> set[str]:
        import re

        text = (ROOT / "Makefile").read_text(encoding="utf-8")
        return set(re.findall(rf"install -m \d+ {directory}/([A-Za-z0-9._-]+)", text))

    def _package_installs(self, directory: str) -> set[str]:
        """The package builder lists its components in `for file in ...` loops."""
        import re

        text = (ROOT / "ci" / "build.sh").read_text(encoding="utf-8")
        names: set[str] = set()
        for match in re.finditer(r"for file in (.+?); do\n(.*?)\ndone", text, re.S):
            body = match.group(2)
            if f'"$REPO_DIR/{directory}/$file"' not in body:
                continue
            listed = match.group(1).replace("\\\n", " ")
            names.update(name for name in listed.split() if name not in {"\\"})
        return names

    def test_the_package_ships_every_script_the_makefile_installs(self) -> None:
        for directory in ("sbin", "rc.d"):
            from_make = self._makefile_installs(directory)
            from_package = self._package_installs(directory)
            self.assertTrue(from_make, f"parsed nothing from the Makefile for {directory}")
            self.assertTrue(from_package, f"parsed nothing from ci/build.sh for {directory}")
            missing = sorted(from_make - from_package)
            self.assertEqual(
                missing, [], f"{directory}: installed by make but absent from the package"
            )

    def test_the_makefile_installs_every_script_the_package_ships(self) -> None:
        for directory in ("sbin", "rc.d"):
            missing = sorted(self._package_installs(directory) - self._makefile_installs(directory))
            self.assertEqual(
                missing, [], f"{directory}: shipped in the package but not installed by make"
            )


if __name__ == "__main__":
    unittest.main()
