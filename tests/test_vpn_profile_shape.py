"""The panel must tell profiles apart, and must not call a route a tunnel.

Three faults in one family, all of them things the operator sees.

The tunnel card read ``vpn.is_default`` and printed it under the word
"Tunnel". Those are different facts: ``active`` is "the interface is up",
``is_default`` is "the tunnel carries the default route". A tunnel can be up and
bypassed -- the state the whole vpn_path work exists for -- and the card called
that "stopped".

Then the buttons inherited it. With the tunnel up, "Start" was painted the
inviting colour and offered an action that does nothing: ``awg-quick up`` on a
live interface dies with "already exists". With the tunnel down, "Stop"
was the green one. Every one of the four combinations was wrong except one.

And ``_vpn_status`` reported False when gatewayctl could not be read at all,
which is this project's oldest recurring confusion: not measured is not off.

A profile also cannot be told apart by looking at it, so the card reports both
its obfuscation generation and the backend selected by `UserLand`. With the
current amnezia-kmod 3.1 stack every generation can use the kernel, except for
magic headers at or below 4, which still require userspace.
"""
from __future__ import annotations

import base64
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from gatebsd_ui.writers.vpn import _profile_adjustments, _profile_shape

APP_JS = (Path(__file__).resolve().parent.parent / "webui" / "frontend" / "app.js").read_text(encoding="utf-8")

PRIV = base64.b64encode(b"\x41" * 32).decode()
PUB = base64.b64encode(b"\x42" * 32).decode()
HPK = base64.b64encode(b"\x44" * 32).decode()


class ProfileShapeTests(unittest.TestCase):
    def test_classic_amneziawg_is_carried_by_the_kernel(self) -> None:
        shape = _profile_shape(f"[Interface]\nPrivateKey = {PRIV}\nJc = 4\nS1 = 16\nH1 = 5\n\n[Peer]\nPublicKey = {PUB}\n")
        self.assertEqual({"generation": "1.5", "engine": "kernel"}, shape)

    def test_plain_wireguard_is_neither_obfuscated_nor_userspace(self) -> None:
        shape = _profile_shape(f"[Interface]\nPrivateKey = {PRIV}\n\n[Peer]\nPublicKey = {PUB}\n")
        self.assertEqual({"generation": "wireguard", "engine": "kernel"}, shape)

    def test_a_2_0_profile_is_named_2_0(self) -> None:
        shape = _profile_shape(
            f"[Interface]\nPrivateKey = {PRIV}\nJc = 5\nHeaderProtectionKey = {HPK}\n\n[Peer]\nPublicKey = {PUB}\n"
        )
        self.assertEqual("2.0", shape["generation"])

    def test_userland_true_is_what_selects_the_userspace_engine(self) -> None:
        base = f"[Interface]\nPrivateKey = {PRIV}\nJc = 5\nHeaderProtectionKey = {HPK}\n\n[Peer]\nPublicKey = {PUB}\n"
        self.assertEqual("kernel", _profile_shape(base)["engine"])
        with_userland = base.replace("[Interface]\n", "[Interface]\nUserLand = true\n", 1)
        self.assertEqual("userspace", _profile_shape(with_userland)["engine"])

    def test_userland_false_is_not_userspace(self) -> None:
        text = f"[Interface]\nUserLand = false\nPrivateKey = {PRIV}\nJc = 5\n\n[Peer]\nPublicKey = {PUB}\n"
        self.assertEqual("kernel", _profile_shape(text)["engine"])

    def test_a_peer_section_directive_does_not_decide_the_interface(self) -> None:
        # The generation is a property of [Interface]. A stray name under [Peer]
        # must not promote a plain profile to 2.0.
        text = f"[Interface]\nPrivateKey = {PRIV}\n\n[Peer]\nPublicKey = {PUB}\nJc = 4\n"
        self.assertEqual("wireguard", _profile_shape(text)["generation"])


class VpnStatusTests(unittest.TestCase):
    """Unknown is a third answer, not a quiet False."""

    def _status(self, stdout: str, ok: bool = True) -> dict:
        from gatebsd_ui import api

        class R:
            def __init__(self) -> None:
                self.stdout = stdout
                self.stderr = ""
                self.ok = ok
                self.rc = 0 if ok else 1

        with patch("gatebsd_ui.command.run", return_value=R()):
            return api._vpn_status()

    def test_up_and_default_is_read_as_both(self) -> None:
        out = "  awg0     flags=<UP,RUNNING>\n== default route ==\n  interface:   awg0\n"
        status = self._status(out)
        self.assertIs(True, status["active"])
        self.assertIs(True, status["is_default"])

    def test_up_but_bypassed_is_up(self) -> None:
        # The exact state the tunnel card used to call "stopped".
        out = "  awg0     flags=<UP,RUNNING>\n== default route ==\n  interface:   ng0\n"
        status = self._status(out)
        self.assertIs(True, status["active"], "an up tunnel was reported as not active")
        self.assertIs(False, status["is_default"])

    def test_unreadable_status_is_unknown_and_not_off(self) -> None:
        status = self._status("", ok=False)
        self.assertIsNone(status["active"], "could-not-read was reported as 'the tunnel is down'")
        self.assertIsNone(status["is_default"], "could-not-read was reported as 'not the default route'")


class PanelWiringTests(unittest.TestCase):
    """app.js must render the facts it is handed, not invent them."""

    def test_the_tunnel_state_is_not_derived_from_the_default_route(self) -> None:
        self.assertNotIn("const tunnelActive=vpn.is_default || a.vpn_is_default;", APP_JS)
        self.assertIn("vpn.active === true", APP_JS)

    def test_an_unknown_tunnel_state_is_shown_as_unknown(self) -> None:
        # "Not measured" must not be painted as "stopped"; the panel has a
        # third word for it.
        self.assertIn("unknown", APP_JS)

    def test_the_start_button_is_inert_while_the_tunnel_is_up(self) -> None:
        block = re.search(r'actionCard\("Start tunnel".*?\)\}', APP_JS, re.S)
        self.assertIsNotNone(block, "could not find the start-tunnel card")
        self.assertIn('tunnelUp === true ? "noop"', block.group(0))

    def test_the_stop_button_is_inert_while_the_tunnel_is_down(self) -> None:
        block = re.search(r'actionCard\("Stop tunnel".*?\)\}', APP_JS, re.S)
        self.assertIsNotNone(block, "could not find the stop-tunnel card")
        self.assertIn('tunnelUp === false ? "noop"', block.group(0))

    def test_a_noop_button_does_not_claim_to_be_forbidden(self) -> None:
        # "Unavailable" with a padlock sends the operator looking for a
        # permission they do not lack. A no-op says what is already true.
        self.assertIn('risk === "noop" ? disabledBtn(btnLabel, icon, noopReason)', APP_JS)
        self.assertIn('noop:"Nothing to do"', APP_JS)

    def test_profiles_are_shown_as_choices_with_their_kind_and_engine(self) -> None:
        self.assertIn("profile-grid", APP_JS)
        self.assertIn("PROFILE_KIND", APP_JS)
        self.assertIn("PROFILE_ENGINE", APP_JS)
        self.assertIn("Activate", APP_JS)


class ProfileNormalisationTests(unittest.TestCase):
    """A provider issues a profile for a laptop; this is a router.

    Three directives a laptop is happy with are wrong on this machine, and
    refusing the file is not an option a sold box has -- "your profile is fine,
    add three lines" has not carried the profile. So the box adjusts it, and
    the adjustments are reported rather than done behind the operator's back.
    """

    PREMIUM = (
        f"[Interface]\nAddress = 100.94.24.181/32\nDNS = 100.64.0.1, 8.8.4.4\n"
        # S1..S4 are here because HeaderProtectionKey is: the nonce that hides
        # each header is taken out of the junk before it, so the validator now
        # requires all four to be at least 12. These are the Premium profile's
        # real values.
        f"PrivateKey = {PRIV}\nJc = 5\nS1 = 29\nS2 = 610\nS3 = 713\nS4 = 12\n"
        f"H1 = 1\nHeaderProtectionKey = {HPK}\n"
        f"RekeyTimeout = 3-8\n\n[Peer]\nPublicKey = {PUB}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.98:5375\n"
        f"PersistentKeepalive = 25-35\n"
    )

    def stored(self, text: str) -> str:
        from gatebsd_ui.writers.vpn import _validate_awg_config_text
        content, error = _validate_awg_config_text(text)
        self.assertIsNone(error, error)
        assert content is not None
        return content.decode()

    def test_table_off_is_forced_so_the_route_has_one_owner(self) -> None:
        # Without it, AllowedIPs = 0.0.0.0/0 makes awg-quick install 0.0.0.0/1
        # and 128.0.0.0/1 itself, beside the default route gatewayctl owns.
        self.assertIn("Table = off", self.stored(self.PREMIUM))

    def test_an_operator_table_of_something_else_is_overridden(self) -> None:
        text = self.PREMIUM.replace("[Interface]\n", "[Interface]\nTable = auto\n", 1)
        stored = self.stored(text)
        self.assertIn("Table = off", stored)
        self.assertNotIn("Table = auto", stored)

    def test_a_missing_mtu_gets_a_stated_fallback(self) -> None:
        from gatebsd_ui.writers.vpn import _MTU_FALLBACK, _profile_adjustments
        self.assertIn(f"MTU = {_MTU_FALLBACK}", self.stored(self.PREMIUM))
        # And it must say it is a fallback: awg-quick's own autodiscovery
        # degenerates on this box, so an absent MTU is not a measured one.
        self.assertTrue(any("fallback" in note for note in _profile_adjustments(self.PREMIUM)))

    def test_an_operators_own_mtu_is_left_alone(self) -> None:
        text = self.PREMIUM.replace("[Interface]\n", "[Interface]\nMTU = 1360\n", 1)
        stored = self.stored(text)
        self.assertIn("MTU = 1360", stored)
        self.assertNotIn("MTU = 1280", stored)

    def test_the_dns_line_is_removed(self) -> None:
        # `resolvconf -a <if> -x` makes the profile's servers exclusive, so the
        # box stops naming its own unbound -- and a rollback then has to resolve
        # the previous endpoint hostname through the tunnel being torn down.
        self.assertNotIn("DNS =", self.stored(self.PREMIUM))

    def test_the_changes_are_reported_not_silent(self) -> None:
        from gatebsd_ui.writers.vpn import _profile_adjustments
        notes = _profile_adjustments(self.PREMIUM)
        self.assertTrue(notes)
        joined = " ".join(notes)
        for expected in ("DNS", "UserLand", "Table", "MTU"):
            self.assertIn(expected, joined, f"{expected} was changed without saying so")

    def test_a_3_1_profile_is_not_moved_to_userspace(self) -> None:
        text = (
            f"[Interface]\nTable = off\nMTU = 1280\nPrivateKey = {PRIV}\n"
            f"RandomTrailers = on\nDisableCookies = off\n\n[Peer]\nPublicKey = {PUB}\n"
            f"AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
        )
        self.assertNotIn("UserLand", self.stored(text))
        self.assertFalse(any("UserLand" in note for note in _profile_adjustments(text)))

    def test_normalisation_is_idempotent(self) -> None:
        from gatebsd_ui.writers.vpn import _profile_adjustments
        once = self.stored(self.PREMIUM)
        self.assertEqual(once, self.stored(once))
        self.assertEqual([], _profile_adjustments(once))

    def test_a_profile_already_shaped_for_this_box_is_not_churned(self) -> None:
        # The live router profile: Table = off, MTU set, no DNS. Nothing to do,
        # and a normaliser that rewrites it anyway would change the hash the
        # panel shows on every read.
        text = (
            f"[Interface]\nTable = off\nAddress = 10.8.1.11/32\nMTU = 1280\n"
            f"PrivateKey = {PRIV}\nJc = 4\nH1 = 5\n\n[Peer]\nPublicKey = {PUB}\n"
            f"AllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.net:51820\n"
            f"PersistentKeepalive = 25\n"
        )
        self.assertEqual([], _profile_adjustments(text))
        self.assertEqual(text, self.stored(text))


if __name__ == "__main__":
    unittest.main()
