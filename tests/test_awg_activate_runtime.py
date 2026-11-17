"""Activation must report what the device did, not what a script claimed.

Measured on the rig, 2026-08-01: selecting a new profile through the panel
returned 200 with every step "ok" while the kernel interface kept serving the
previous server's peer. `service amnezia restart` is an rc.subr script that
iterates $amnezia_interfaces; with the rcvar off it prints

    Cannot 'restart' amnezia. Set amnezia_enable to YES in /etc/rc.conf
    or use 'onerestart' instead of 'restart'.

and exits 0, so an absent restart and a successful one are indistinguishable by
return code. Nothing failed, so the rollback branch never ran either -- the
device simply kept the old tunnel with a new config on disk, and the divergence
would surface at the next reboot, looking like the upgrade's fault.

These tests drive the real awg_activate. The stubs stand in for the commands
only; every decision under test is executed.
"""
from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gatebsd_ui.command import CommandResult
from gatebsd_ui.writers import vpn

OLD_PEER = base64.b64encode(b"\x11" * 32).decode()
NEW_PEER = base64.b64encode(b"\x22" * 32).decode()
PRIVATE = base64.b64encode(b"\x33" * 32).decode()

OLD_ENDPOINT = ("198.51.100.1", "51820")
NEW_ENDPOINT = ("203.0.113.9", "51821")

# The rc.subr refusal, verbatim: it goes to stdout and the exit status is 0.
RC_REFUSAL = (
    "Cannot 'restart' amnezia. Set amnezia_enable to YES in /etc/rc.conf "
    "or use 'onerestart' instead of 'restart'."
)


def _profile(peer: str, endpoint: tuple[str, str]) -> str:
    host, port = endpoint
    return (
        "[Interface]\n"
        "Table = off\n"
        "Address = 10.9.0.2/24\n"
        f"PrivateKey = {PRIVATE}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {peer}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        f"Endpoint = {host}:{port}\n"
    )


GATEWAY_CONF = """\
WAN_IF="ng0"
LAN_IF="re1"
VPN_IF="awg0"

VPN_ENDPOINT_HOST="{host}"
VPN_ENDPOINT_PORT="{port}"

VPN_MTU="1280"
CHECK_IP="1.1.1.1"
"""


class AwgActivateRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)
        self.active = self.conf_dir / "awg0.conf"
        self.marker = self.conf_dir / "vpn_disabled"

        self.old_profile = self.conf_dir / "old.conf"
        self.old_profile.write_text(_profile(OLD_PEER, OLD_ENDPOINT), encoding="utf-8")
        self.new_profile = self.conf_dir / "new.conf"
        self.new_profile.write_text(_profile(NEW_PEER, NEW_ENDPOINT), encoding="utf-8")
        self.gateway = self.conf_dir / "gateway.conf"
        self.gateway.write_text(
            GATEWAY_CONF.format(host=OLD_ENDPOINT[0], port=OLD_ENDPOINT[1]),
            encoding="utf-8",
        )
        self.active.symlink_to(self.old_profile)

        # The peer set the stubbed `awg show` reports; each test decides whether
        # the restart actually took effect by changing this.
        self.running_peers = [OLD_PEER]
        self.gatewayctl_ok = True
        self.gatewayctl_output = (
            "[gatewayctl] === apply: start ===\n"
            "[gatewayctl] no awg0 peer completed a handshake within 15s\n"
            "[gatewayctl] no VPN handshake; rolling back to WAN\n"
        )
        self.commands: list[list[str]] = []

        for target, value in (
            ("AMNEZIA_CONF_DIR", self.conf_dir),
            ("AMNEZIA_CONFIG", self.active),
        ):
            patcher = patch.object(vpn, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # The marker lives in `paths`, which is where `gatewayctl`, the watchdog
        # and `adapters.vpn_path` all read it. The writer used to keep its own
        # `Path("/var/db/gatebsd/vpn_disabled")`, so this patch moved the file
        # the writer touched while every reader still looked at the real one --
        # a split that only a non-default `GATEBSD_VPN_DISABLED_FLAG` reveals.
        patcher = patch.object(vpn.paths, "VPN_DISABLED", self.marker)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(vpn.backup, "backup_known_configs", return_value={})
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(vpn, "run", self._fake_run)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.td.cleanup)

    def _fake_run(self, command, timeout=4.0, **kwargs) -> CommandResult:
        self.commands.append(list(command))
        if command[:2] == ["service", "amnezia"]:
            # Exactly what rc.subr does with the rcvar off: complain, succeed.
            # Nothing should be calling this any more -- see the test below.
            return CommandResult(command, True, 0, RC_REFUSAL, "")
        if command[0].endswith("awg-quick"):
            return CommandResult(command, True, 0, "", "")
        if command[0].endswith("gatewayctl"):
            if self.gatewayctl_ok:
                return CommandResult(command, True, 0, "apply: OK", "")
            return CommandResult(command, False, 1, self.gatewayctl_output, "")
        if command[1:3] == ["show", "awg0"] and command[3:4] == ["peers"]:
            return CommandResult(command, True, 0, "\n".join(self.running_peers), "")
        return CommandResult(command, True, 0, "", "")

    def _endpoint_in_gateway_conf(self) -> tuple[str, str]:
        values: dict[str, str] = {}
        for line in self.gateway.read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, _sep, raw = line.partition("=")
            if key.strip() in {"VPN_ENDPOINT_HOST", "VPN_ENDPOINT_PORT"}:
                values[key.strip()] = raw.strip().strip('"')
        return values.get("VPN_ENDPOINT_HOST", ""), values.get("VPN_ENDPOINT_PORT", "")

    # ------------------------------------------------------------------ the defect
    def test_silent_no_op_restart_is_not_reported_as_success(self) -> None:
        """The interface still serves the old peer: activation must not claim success."""
        self.running_peers = [OLD_PEER]

        status, payload = vpn.awg_activate("new")

        self.assertNotEqual(status, 200, "a device that kept the old tunnel reported success")
        self.assertFalse(payload.get("ok"))
        verify = [step for step in payload["steps"] if step["stage"] == "verify runtime"]
        self.assertEqual(len(verify), 1)
        self.assertFalse(verify[0]["ok"])

    def test_failed_activation_puts_the_profile_and_the_endpoint_back(self) -> None:
        """Rollback has to restore both halves, or the device is left split."""
        self.running_peers = [OLD_PEER]

        status, payload = vpn.awg_activate("new")

        self.assertNotEqual(status, 200)
        self.assertTrue(payload.get("rolled_back"), payload)
        self.assertEqual(Path(self.active.readlink()), self.old_profile)
        self.assertEqual(self._endpoint_in_gateway_conf(), OLD_ENDPOINT)

    # ------------------------------------------------------------------ the good path
    def test_real_restart_activates_and_moves_the_endpoint_with_it(self) -> None:
        """When the interface does adopt the profile, the pin must follow it."""
        self.running_peers = [NEW_PEER]

        status, payload = vpn.awg_activate("new")

        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["ok"])
        self.assertEqual(Path(self.active.readlink()), self.new_profile)
        self.assertEqual(self._endpoint_in_gateway_conf(), NEW_ENDPOINT)

    def test_endpoint_is_synced_before_routes_are_applied(self) -> None:
        """gatewayctl pins from gateway.conf, so the sync is useless afterwards."""
        self.running_peers = [NEW_PEER]
        seen: list[tuple[str, str]] = []

        original = vpn._restart_active_runtime

        def observing_restart():
            seen.append(self._endpoint_in_gateway_conf())
            return original()

        with patch.object(vpn, "_restart_active_runtime", observing_restart):
            status, _payload = vpn.awg_activate("new")

        self.assertEqual(status, 200)
        self.assertEqual(seen, [NEW_ENDPOINT],
                         "gateway.conf still named the old server when apply ran")

    def test_activation_does_not_depend_on_the_amnezia_rcvar(self) -> None:
        """`service amnezia restart` cannot be trusted, so it must not be used.

        The rcvar being off makes that script a no-op that still exits 0. The
        tunnel is torn down instead, which needs no rcvar and forces the next
        apply to build the interface from the profile that is active now -- so
        the handshake gate judges the new tunnel, not the old one.
        """
        self.running_peers = [NEW_PEER]

        vpn.awg_activate("new")

        self.assertFalse(
            any(command[:2] == ["service", "amnezia"] for command in self.commands),
            "activation still routes the restart through the rcvar-gated rc script",
        )

    def test_the_teardown_and_the_apply_are_one_locked_operation(self) -> None:
        """The guarantee did not go away; it moved to where the lock lives.

        Tearing the tunnel down from here and then asking gatewayctl to apply
        was two operations with a gap between them, and the gap belonged to
        nobody: `awg-quick down` takes no gateway lock, and by then the active
        symlink already pointed at the new profile with the disabled marker
        cleared. The watchdog wakes every 10s, saw "the VPN is wanted and the
        default route is not on it", took the lock first and applied the new
        profile itself -- after which this activation's own apply found `awg0
        already up` and its verification gate judged a tunnel it had not built.

        `gatewayctl rebuild` does both halves under the single lock gatewayctl
        already takes for a whole operation. That the verb really tears the
        tunnel down first, and really excludes a second caller, is proven where
        `lockf` is real -- rehearse_gateway_lock.sh on the stand. The Linux
        harness stubs lockf away, so it cannot be asked here.
        """
        self.running_peers = [NEW_PEER]

        vpn.awg_activate("new")

        gateway = [c for c in self.commands if c[0].endswith("gatewayctl")]
        self.assertEqual(1, len(gateway),
                         f"activation runs more than one gateway operation: {gateway}")
        self.assertEqual(["rebuild"], gateway[0][1:],
                         "activation no longer asks for the single locked rebuild")
        self.assertFalse(
            any(command[0].endswith("awg-quick") for command in self.commands),
            "the teardown is being done outside the gateway lock again",
        )

    def test_a_failure_reports_what_gatewayctl_said(self) -> None:
        """Otherwise the only way to learn the reason is to reproduce it by hand.

        `"rebuild tunnel": false` names the step and nothing else. gatewayctl
        already prints the cause -- no handshake, health check failed, endpoint
        unroutable -- and on a device whose only uplink is the tunnel, guessing
        at it is the worst available option.
        """
        self.gatewayctl_ok = False
        self.running_peers = [OLD_PEER]

        status, payload = vpn.awg_activate("new")

        self.assertNotEqual(status, 200)
        self.assertIn("output", payload, "gatewayctl's reason was thrown away")
        self.assertIn("no VPN handshake", payload["output"])

    def test_the_diagnostic_output_is_bounded(self) -> None:
        """awg-quick echoes every command it runs; the tail is the useful part."""
        self.gatewayctl_ok = False
        self.gatewayctl_output = "noise\n" * 5000 + "[gatewayctl] the actual reason\n"
        self.running_peers = [OLD_PEER]

        _status, payload = vpn.awg_activate("new")

        self.assertLess(len(payload["output"]), 2200)
        self.assertIn("the actual reason", payload["output"])

    def test_gateway_conf_keeps_every_other_setting(self) -> None:
        """Rewriting two assignments must not disturb the rest of the file."""
        self.running_peers = [NEW_PEER]

        vpn.awg_activate("new")

        text = self.gateway.read_text(encoding="utf-8")
        for expected in ('WAN_IF="ng0"', 'LAN_IF="re1"', 'VPN_MTU="1280"', 'CHECK_IP="1.1.1.1"'):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
