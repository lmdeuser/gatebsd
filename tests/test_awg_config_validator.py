"""What the profile validator must accept, and what it must refuse.

`_validate_awg_config_text` decides whether a customer's profile is written at
all: `awg_set_config` calls it before touching the disk, `awg_activate` calls it
again before capturing the active config, and the profile listing calls it to
mark each file valid or not. Until now it had no test of its own -- and it
showed. There was no list of known directive names, so `[Interface]` accepted
`ThisKeyDoesNotExist = 42` and every misspelling of a real directive with it:
the file was written, the tunnel came up without the knob, and nothing said a
word.

The rule these tests hold it to is the one that matters for a sold box: the
validator must not accept what the box cannot carry, and must not promise a
backend the box will not use. Official amnezia-kmod 3.1 and amnezia-tools carry
all supported obfuscation generations through the FreeBSD nvlist ABI. The
shipped awg-quick tries the kernel first; only explicit `UserLand = true`
selects amneziawg-go, and the validator preserves that operator choice.

The shapes below are the two real ones: the profile the router runs today, and
the Premium profile the customer has. Both were run end to end against
amneziawg-go 3.0 on the stand (awg2_proof.sh) before being written down here.
"""
from __future__ import annotations

import base64
import unittest

from gatebsd_ui.writers.vpn import _profile_shape, _validate_awg_config_text

PRIV = base64.b64encode(b"\x41" * 32).decode()
PUB = base64.b64encode(b"\x42" * 32).decode()
PSK = base64.b64encode(b"\x43" * 32).decode()
HPK = base64.b64encode(b"\x44" * 32).decode()

# What the router carries today: AmneziaWG 1.5 knobs, magic headers as ranges
# well above 4, one special packet, a plain keepalive.
LIVE = f"""[Interface]
Table = off
Address = 10.8.1.11/32
MTU = 1280
PrivateKey = {PRIV}
Jc = 4
Jmin = 10
Jmax = 50
S1 = 16
S2 = 139
S3 = 46
S4 = 7
H1 = 166523029-1043862245
H2 = 1801950478-2097588000
H3 = 2131739143-2134927416
H4 = 2141583327-2143072151
I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>

[Peer]
PublicKey = {PUB}
PresharedKey = {PSK}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.invalid:51820
PersistentKeepalive = 25
"""

# The Premium profile: AmneziaWG 2.0. Magic headers at 1,2,3,4 are legal
# because header protection hides them; the old kernel module rejected them.
PREMIUM = f"""[Interface]
Address = 100.94.24.181/32
DNS = 100.64.0.1, 8.8.4.4
PrivateKey = {PRIV}
Jc = 5
Jmin = 10
Jmax = 80
S1 = 29
S2 = 610
S3 = 713
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = {HPK}
RekeyAfterTime = 100-120
RekeyTimeout = 3-8
RejectAfterTime = 150-180
KeepaliveTimeout = 7-13
MaxHandshakeAttempts = 15-20
ContentPaddingAddition = 10-100

[Peer]
PublicKey = {PUB}
PresharedKey = {PSK}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.98:5375
PersistentKeepalive = 25-35
"""

# Plain WireGuard: no obfuscation at all, so awg-quick creates a kernel
# interface. Everything 2.0 is out of reach from here.
PLAIN = f"""[Interface]
Address = 10.7.0.2/32
PrivateKey = {PRIV}

[Peer]
PublicKey = {PUB}
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.7:51820
PersistentKeepalive = 25
"""


def accepted(text: str) -> tuple[bytes | None, str | None]:
    return _validate_awg_config_text(text)


class RealProfilesTests(unittest.TestCase):
    """Neither of the two profiles that exist may be turned away."""

    def test_live_router_profile_is_accepted(self) -> None:
        content, error = accepted(LIVE)
        self.assertIsNone(error)
        self.assertIsNotNone(content)

    def test_premium_2_0_profile_is_accepted(self) -> None:
        content, error = accepted(PREMIUM)
        self.assertIsNone(error, f"the customer's own profile was refused: {error}")
        self.assertIsNotNone(content)

    def test_plain_wireguard_profile_is_accepted(self) -> None:
        content, error = accepted(PLAIN)
        self.assertIsNone(error)
        self.assertIsNotNone(content)


class UnknownDirectiveTests(unittest.TestCase):
    """An invented or misspelled name is a defect, not a comment."""

    def test_invented_interface_directive_is_refused(self) -> None:
        text = LIVE.replace("Jc = 4", "Jc = 4\nThisKeyDoesNotExist = 42")
        _content, error = accepted(text)
        self.assertIsNotNone(error)
        self.assertIn("ThisKeyDoesNotExist", error or "")

    def test_error_names_the_line(self) -> None:
        text = LIVE.replace("Jc = 4", "Jc = 4\nThisKeyDoesNotExist = 42")
        _content, error = accepted(text)
        expected_line = text.splitlines().index("ThisKeyDoesNotExist = 42") + 1
        self.assertIn(f"line {expected_line}", error or "")

    def test_misspelled_2_0_directive_is_refused(self) -> None:
        # The whole point: this used to pass, the profile was written, and the
        # rekey interval silently stayed at the default.
        text = PREMIUM.replace("RekeyAfterTime = 100-120", "RekeyAfterTme = 100-120")
        _content, error = accepted(text)
        self.assertIsNotNone(error)
        self.assertIn("RekeyAfterTme", error or "")

    def test_unknown_peer_directive_is_refused(self) -> None:
        text = PREMIUM.replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 0.0.0.0/0, ::/0\nAllowdIPs = 10.0.0.0/8")
        _content, error = accepted(text)
        self.assertIsNotNone(error)
        self.assertIn("AllowdIPs", error or "")

    def test_interface_directive_in_peer_section_is_refused(self) -> None:
        text = PREMIUM.replace("PersistentKeepalive = 25-35", "PersistentKeepalive = 25-35\nJc = 5")
        _content, error = accepted(text)
        self.assertIsNotNone(error)
        self.assertIn("[Peer]", error or "")

    def test_unsafe_directives_are_still_refused(self) -> None:
        for directive in ("PostUp", "PreUp", "PostDown", "PreDown", "SaveConfig"):
            with self.subTest(directive=directive):
                text = LIVE.replace("MTU = 1280", f"MTU = 1280\n{directive} = /bin/sh -c id")
                _content, error = accepted(text)
                self.assertIsNotNone(error)


class BackendTests(unittest.TestCase):
    """AWG 2.0 runs on the kernel by default, with two userspace exceptions.

    amnezia-kmod 3.1.0 and the official amnezia-tools FreeBSD backend carry
    the complete AWG 3.1 nvlist ABI. The shipped awg-quick gives an operator an
    explicit escape hatch: `UserLand = true` selects amneziawg-go. Magic headers
    at or below 4 also require userspace because the kernel rejects them.
    """

    def test_2_0_profile_uses_the_kernel_backend_by_default(self) -> None:
        text = PLAIN.replace(
            f"PrivateKey = {PRIV}",
            f"PrivateKey = {PRIV}\nContentPaddingAddition = 10-100\nRekeyTimeout = 3-8",
        )
        content, error = accepted(text)
        self.assertIsNone(error)
        stored = (content or b"").decode()
        self.assertNotIn("UserLand", stored)
        self.assertEqual("kernel", _profile_shape(stored)["engine"])

    def test_classic_directives_alone_do_not_select_userspace(self) -> None:
        text = PLAIN.replace(f"PrivateKey = {PRIV}", f"PrivateKey = {PRIV}\nJc = 5")
        content, error = accepted(text)
        self.assertIsNone(error)
        self.assertNotIn(
            "UserLand",
            (content or b"").decode(),
            "a 1.5-era profile was pushed to userspace, which costs twice the CPU",
        )

    def test_2_0_with_userland_false_is_accepted(self) -> None:
        text = PLAIN.replace(
            f"PrivateKey = {PRIV}",
            f"PrivateKey = {PRIV}\nUserLand = false\nContentPaddingAddition = 10-100",
        )
        content, error = accepted(text)
        self.assertIsNone(error)
        self.assertEqual(1, (content or b"").decode().count("UserLand = false"))

    def test_operator_choice_of_userspace_is_left_alone(self) -> None:
        text = PLAIN.replace(
            f"PrivateKey = {PRIV}",
            f"PrivateKey = {PRIV}\nUserLand = true\nContentPaddingAddition = 10-100",
        )
        content, error = accepted(text)
        self.assertIsNone(error)
        self.assertEqual(1, (content or b"").decode().count("UserLand"))

    def test_userland_must_be_a_bool(self) -> None:
        text = PLAIN.replace(f"PrivateKey = {PRIV}", f"PrivateKey = {PRIV}\nUserLand = yes")
        _content, error = accepted(text)
        self.assertIsNotNone(error)
        self.assertIn("UserLand", error or "")

    def test_keepalive_range_is_fine_on_the_kernel_backend(self) -> None:
        text = PLAIN.replace("PersistentKeepalive = 25", "PersistentKeepalive = 25-35")
        content, error = accepted(text)
        self.assertIsNone(error)
        self.assertEqual("kernel", _profile_shape((content or b"").decode())["engine"])

    def test_keepalive_range_is_fine_on_the_userspace_backend(self) -> None:
        _content, error = accepted(PREMIUM)
        self.assertIsNone(error)


class RangeSyntaxTests(unittest.TestCase):
    """Ranges belong to the directives that have them, and to no others."""

    def test_plain_uint16_directive_refuses_a_range(self) -> None:
        for directive in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"):
            with self.subTest(directive=directive):
                lines = []
                for line in PREMIUM.splitlines():
                    if line.startswith(f"{directive} = "):
                        line = f"{directive} = 10-20"
                    lines.append(line)
                _content, error = accepted("\n".join(lines) + "\n")
                self.assertIsNotNone(error, f"{directive} accepted a range it cannot carry")

    def test_reversed_range_is_refused(self) -> None:
        text = PREMIUM.replace("RekeyTimeout = 3-8", "RekeyTimeout = 8-3")
        _content, error = accepted(text)
        self.assertIsNotNone(error)

    def test_range_above_uint16_is_refused(self) -> None:
        # u16_range_from_string bounds against UINT32_MAX and then packs the
        # value as hi<<16|lo, so 70000 silently becomes 4464.
        text = PREMIUM.replace("RejectAfterTime = 150-180", "RejectAfterTime = 150-70000")
        _content, error = accepted(text)
        self.assertIsNotNone(error)

    def test_magic_header_range_up_to_uint32_is_accepted(self) -> None:
        text = PREMIUM.replace("H1 = 1", "H1 = 1-4294967295")
        _content, error = accepted(text)
        self.assertIsNone(error)

    def test_magic_header_above_uint32_is_refused(self) -> None:
        text = PREMIUM.replace("H1 = 1", "H1 = 4294967296")
        _content, error = accepted(text)
        self.assertIsNotNone(error)

    def test_non_numeric_range_is_refused(self) -> None:
        text = PREMIUM.replace("KeepaliveTimeout = 7-13", "KeepaliveTimeout = seven-13")
        _content, error = accepted(text)
        self.assertIsNotNone(error)


class ValueTests(unittest.TestCase):
    def test_header_protection_key_must_be_a_key(self) -> None:
        text = PREMIUM.replace(f"HeaderProtectionKey = {HPK}", "HeaderProtectionKey = notakey")
        _content, error = accepted(text)
        self.assertIsNotNone(error)
        self.assertIn("HeaderProtectionKey", error or "")

    def test_listen_port_out_of_range_is_refused(self) -> None:
        text = LIVE.replace("MTU = 1280", "MTU = 1280\nListenPort = 70000")
        _content, error = accepted(text)
        self.assertIsNotNone(error)

    def test_advanced_security_must_be_a_bool(self) -> None:
        good = PREMIUM.replace("PersistentKeepalive = 25-35", "PersistentKeepalive = 25-35\nAdvancedSecurity = true")
        _content, error = accepted(good)
        self.assertIsNone(error)
        bad = PREMIUM.replace("PersistentKeepalive = 25-35", "PersistentKeepalive = 25-35\nAdvancedSecurity = yes")
        _content, error = accepted(bad)
        self.assertIsNotNone(error)


class Awg31Tests(unittest.TestCase):
    """The two directives AmneziaWG 3.1 added, without forcing a backend.

    The Amnezia client writes RandomTrailers and DisableCookies into every
    profile it generates for a 3.1 container -- both lines, unconditionally,
    defaulting to "on" (protocolConstants.h, defaultRandomTrailers). So a
    validator that does not know the names refuses every 3.1 profile outright.
    amnezia-tools before 3.1 does exactly that, and it was measured on the
    router: `awg setconf` answers "Line unrecognized: `RandomTrailers=on'" and
    fails the whole file, for `off` just as much as for `on`.

    The fixtures below are built on LIVE, not on PREMIUM, so the 3.1 flags are
    exercised independently from the 2.0 directives a real profile also carries.
    """

    def as_31(self, random_trailers: str, disable_cookies: str = "off") -> str:
        """LIVE plus the two flags, with its range headers flattened to single
        values -- ranges alongside junk and RandomTrailers are refused by the
        combination rule, and these tests are about the flags themselves."""
        text = LIVE
        for line in LIVE.splitlines():
            if line[:2].lower() in {"h1", "h2", "h3", "h4"} and "-" in line:
                text = text.replace(line, line.split("-")[0].rstrip())
        return text.replace(
            "[Peer]",
            f"RandomTrailers = {random_trailers}\nDisableCookies = {disable_cookies}\n\n[Peer]",
            1,
        )

    def engine_of(self, text: str) -> str:
        """The backend selected by the validated, stored profile."""
        content, error = accepted(text)
        self.assertIsNone(error)
        assert content is not None
        return _profile_shape(content.decode())["engine"]

    def test_a_whole_3_1_profile_is_accepted(self) -> None:
        """The client's low magic headers still require userspace on FreeBSD."""
        text = PREMIUM.replace(
            "ContentPaddingAddition = 10-100",
            "ContentPaddingAddition = 10-100\nRandomTrailers = on\nDisableCookies = on",
        )
        content, error = accepted(text)
        self.assertIsNone(error)
        assert content is not None
        self.assertEqual(_profile_shape(content.decode())["generation"], "3.1")
        self.assertEqual(_profile_shape(content.decode())["engine"], "userspace")

    def test_the_same_3_1_profile_with_higher_headers_uses_the_kernel(self) -> None:
        text = PREMIUM.replace(
            "ContentPaddingAddition = 10-100",
            "ContentPaddingAddition = 10-100\nRandomTrailers = on\nDisableCookies = on",
        )
        for header, value in (("H1", "5"), ("H2", "6"), ("H3", "7"), ("H4", "8")):
            text = text.replace(f"{header} = {int(value) - 4}", f"{header} = {value}")
        content, error = accepted(text)
        self.assertIsNone(error)
        self.assertEqual("kernel", _profile_shape((content or b"").decode())["engine"])

    def test_low_magic_headers_with_userland_false_are_refused(self) -> None:
        text = PREMIUM.replace("[Peer]", "UserLand = false\n\n[Peer]", 1)
        _content, error = accepted(text)
        self.assertIsNotNone(error)
        self.assertIn("UserLand = false", error or "")

    def test_random_trailers_on_keeps_the_kernel_engine(self) -> None:
        self.assertEqual(self.engine_of(self.as_31("on")), "kernel")

    def test_random_trailers_on_with_userland_false_is_accepted(self) -> None:
        text = self.as_31("on").replace("[Peer]", "UserLand = false\n\n[Peer]", 1)
        content, error = accepted(text)
        self.assertIsNone(error)
        self.assertEqual("kernel", _profile_shape((content or b"").decode())["engine"])

    def test_both_flags_off_leaves_the_kernel_path_alone(self) -> None:
        self.assertEqual(self.engine_of(self.as_31("off", "off")), "kernel")

    def test_a_number_is_a_bool_the_way_awg_reads_it(self) -> None:
        for value in ("1", "0"):
            with self.subTest(value=value):
                self.assertEqual(self.engine_of(self.as_31(value)), "kernel")

    def test_a_value_awg_would_die_on_is_refused_here(self) -> None:
        """`1x` gets past awg's char_is_digit and then calls exit(1) mid-parse."""
        for value in ("yes", "1x", "true", ""):
            with self.subTest(value=value):
                _content, error = accepted(self.as_31(value))
                self.assertIsNotNone(error)

    def test_a_misspelled_3_1_directive_is_still_refused(self) -> None:
        text = self.as_31("on").replace("RandomTrailers", "RandomTrailer")
        _content, error = accepted(text)
        self.assertIsNotNone(error)



class HeaderProtectionJunkTests(unittest.TestCase):
    """HeaderProtectionKey needs junk longer than the nonce it hides in.

    amneziawg-go derives the header cipher's nonce from the junk that precedes
    each packet, so every one of S1..S4 has to be at least HeaderCipherNonceSize
    -- 12 -- or `awg setconf` refuses the entire profile with "Invalid argument".
    Measured in the jail rig on the stand, 2026-08-27, against amneziawg-go
    3.1.20260814: S4 = 7 refused, S4 = 12 accepted, S4 = 13 accepted.

    Two details of the upstream message are wrong and cost an hour, so they are
    pinned here: it names the field "S0" when it means S1 (it prints the array
    index), and it says "more then 12" when the comparison admits exactly 12.
    """

    def with_s4(self, value: str) -> str:
        return PREMIUM.replace("S4 = 12", f"S4 = {value}")

    def test_the_premium_profile_sits_exactly_on_the_floor(self) -> None:
        _content, error = accepted(PREMIUM)
        self.assertIsNone(error)

    def test_junk_below_the_nonce_is_refused(self) -> None:
        _content, error = accepted(self.with_s4("7"))
        self.assertIsNotNone(error)
        assert error is not None
        self.assertIn("s4", error)

    def test_the_floor_itself_is_accepted(self) -> None:
        for value in ("12", "13", "700"):
            with self.subTest(value=value):
                _content, error = accepted(self.with_s4(value))
                self.assertIsNone(error)

    def test_a_missing_junk_size_counts_as_zero(self) -> None:
        _content, error = accepted(PREMIUM.replace("S4 = 12\n", ""))
        self.assertIsNotNone(error)

    def test_without_the_key_small_junk_is_fine(self) -> None:
        """The router's own profile has S4 = 7 and no key. It must stay valid."""
        text = self.with_s4("7")
        text = "\n".join(l for l in text.splitlines() if "HeaderProtectionKey" not in l)
        _content, error = accepted(text)
        self.assertIsNone(error)



class RandomTrailersCombinationTests(unittest.TestCase):
    """The combination that comes up green and drops a quarter of the traffic.

    Measured 2026-08-27 from the stand against the official
    amneziavpn/amneziawg-go container, 100 ICMP packets per run, LAN baseline
    0%: each of junk sizes, range headers and RandomTrailers alone loses
    nothing, every pair of them loses nothing, and the three together lose 40,
    41 and 51% across three runs. The Amnezia client ships all three on by
    default for a 3.1 container, which is what makes this worth refusing rather
    than documenting.
    """

    def profile(self, extra: str) -> str:
        return PREMIUM.replace("ContentPaddingAddition = 10-100", extra)

    def test_the_three_together_are_refused(self) -> None:
        text = self.profile(
            "H1 = 166523029-1043862245\nRandomTrailers = on"
        )
        _content, error = accepted(text)
        self.assertIsNotNone(error)
        assert error is not None
        self.assertIn("RandomTrailers", error)

    def test_range_headers_without_trailers_are_fine(self) -> None:
        _content, error = accepted(self.profile("H1 = 166523029-1043862245"))
        self.assertIsNone(error)

    def test_trailers_with_single_value_headers_are_fine(self) -> None:
        _content, error = accepted(self.profile("RandomTrailers = on"))
        self.assertIsNone(error)

    def test_trailers_without_junk_are_fine(self) -> None:
        text = self.profile("H1 = 166523029-1043862245\nRandomTrailers = on")
        text = "\n".join(
            l for l in text.splitlines()
            if l[:2].lower() not in {"s1", "s2", "s3", "s4"} and "HeaderProtectionKey" not in l
        )
        _content, error = accepted(text)
        self.assertIsNone(error)



class DigitsAndDuplicatesTests(unittest.TestCase):
    """Two holes an outside review opened on 2026-08-27, both reproduced first.

    Neither was invented for this file: the numeric check had used
    `str.isdigit()` since the validator existed, and the HeaderProtectionKey
    rule added the same day read only the first value of a directive that may
    legally repeat.
    """

    def test_a_unicode_digit_is_not_a_digit(self) -> None:
        """awg parses the file with strtoul() on bytes.

        `"\u0661\u0662"` is Arabic-Indic twelve: str.isdigit() accepts it and int()
        converts it, so the profile was written out looking valid and the box
        then refused to bring the tunnel up.
        """
        for value in ("\u0661\u0662", "\u2081\u2082", "\uff11\uff12"):
            with self.subTest(value=value):
                _content, error = accepted(PREMIUM.replace("S4 = 12", f"S4 = {value}"))
                self.assertIsNotNone(error)

    def test_a_digit_int_cannot_read_does_not_crash_the_request(self) -> None:
        """`"\u00b2"` passes str.isdigit() and raises in int().

        The old code called one after the other, so this reached the panel as a
        500 rather than as a refused profile.
        """
        for directive, value in (("S4 = 12", "S4 = \u00b2"), ("Jc = 5", "Jc = \u00b2")):
            with self.subTest(directive=directive):
                _content, error = accepted(PREMIUM.replace(directive, value))
                self.assertIsNotNone(error)

    def test_a_repeated_junk_size_is_judged_by_all_its_values(self) -> None:
        """awg keeps the last value it reads; the validator used to read the first.

        `S1 = 29` then `S1 = 0` was accepted with HeaderProtectionKey present,
        and 0 is shorter than the nonce header protection is derived from.
        """
        text = PREMIUM.replace("S1 = 29", "S1 = 29\nS1 = 0")
        _content, error = accepted(text)
        self.assertIsNotNone(error)
        assert error is not None
        self.assertIn("s1", error)

    def test_the_repeat_is_only_refused_when_a_value_is_bad(self) -> None:
        _content, error = accepted(PREMIUM.replace("S1 = 29", "S1 = 29\nS1 = 31"))
        self.assertIsNone(error)


if __name__ == "__main__":
    unittest.main()
