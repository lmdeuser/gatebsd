"""Regression tests for awg_key_rotate."""
from __future__ import annotations

import base64
import fcntl
import multiprocessing
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

# Real 32-byte WireGuard keys (base64, 44 chars)
KEY_A = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
KEY_B = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
# Canonical 32-byte base64 keys for wg genkey / wg pubkey output
NEW_PRIV = base64.b64encode(b"\x41" * 32).decode()   # 44 chars, decodes to 32 bytes
NEW_PUB = base64.b64encode(b"\x42" * 32).decode()    # 44 chars, decodes to 32 bytes

AWG_TOOL = "/usr/local/bin/awg"


class _ChildSynchronizationError(RuntimeError):
    """Raised in child processes when an Event.wait timeout expires."""
    pass


class AwgKeyRotateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)
        self.patcher_conf = patch(
            "gatebsd_ui.writers.vpn.AMNEZIA_CONF_DIR", self.conf_dir
        )
        self.patcher_backup = patch("gatebsd_ui.writers.vpn.backup.backup_files",
                                    return_value={})
        self.patcher_conf.start()
        self.patcher_backup.start()

    def tearDown(self) -> None:
        self.patcher_backup.stop()
        self.patcher_conf.stop()
        self.td.cleanup()

    def _write(self, name: str, content: str | bytes) -> Path:
        p = self.conf_dir / name
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
        return p

    def _read_bytes(self, name: str) -> bytes:
        return (self.conf_dir / name).read_bytes()

    @staticmethod
    def _make_noncanonical(canonical: str) -> str:
        """Return a non-canonical Base64 string that decodes to the same bytes."""
        alphabet = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/"
        )
        assert len(canonical) == 44
        assert canonical.endswith("=")
        pos = len(canonical) - 2
        idx = alphabet.index(canonical[pos])
        assert idx & 0b11 == 0, "padding bits must be zero for canonical form"
        replacement = alphabet[idx | 0b01]
        candidate = canonical[:pos] + replacement + canonical[pos + 1:]
        assert candidate != canonical
        assert len(candidate) == 44
        assert base64.b64decode(candidate, validate=True) == base64.b64decode(canonical, validate=True)
        assert len(base64.b64decode(candidate, validate=True)) == 32
        return candidate

    def _patch_wg(self, priv: str = NEW_PRIV, pub: str = NEW_PUB) -> list:
        """Patch command.run for wg genkey and wg pubkey."""
        calls: list[list[str]] = []

        def fake_run(cmd: list[str], **kw: object) -> object:
            calls.append(cmd)
            if cmd == [AWG_TOOL, "genkey"]:
                return type("R", (), {"ok": True, "stdout": priv, "stderr": ""})()
            if cmd == [AWG_TOOL, "pubkey"]:
                return type("R", (), {"ok": True, "stdout": pub, "stderr": ""})()
            return type("R", (), {"ok": False, "stdout": "", "stderr": "fail"})()

        return [patch("gatebsd_ui.writers.vpn.run", side_effect=fake_run), calls]

    def _assert_409_no_change(self, conf: bytes) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        self.patcher_backup.stop()
        call_count: list[int] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 409)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertEqual(call_count, [])

    def _assert_invalid_privkey_500(self, bad_priv: object) -> None:
        """Assert wg genkey with bad output returns 500, no change, no backup."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        self.patcher_backup.stop()
        call_count: list[int] = []
        run_calls: list[list[str]] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()

        def tracking_run(cmd: list[str], **kw: object) -> object:
            run_calls.append(cmd)
            if cmd == [AWG_TOOL, "genkey"]:
                return type("R", (), {"ok": True, "stdout": bad_priv, "stderr": ""})()
            return type("R", (), {"ok": False, "stdout": "", "stderr": "fail"})()

        with patch("gatebsd_ui.writers.vpn.run", side_effect=tracking_run):
            status, body = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(body["error"], "awg genkey returned invalid private key")
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertEqual(call_count, [])
        self.assertFalse(any(c == [AWG_TOOL, "pubkey"] for c in run_calls))

    def _assert_invalid_pubkey_500(self, bad_pub: object) -> None:
        """Assert wg pubkey with bad output returns 500, no change, no backup."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        self.patcher_backup.stop()
        call_count: list[int] = []
        run_calls: list[list[str]] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()

        def tracking_run(cmd: list[str], **kw: object) -> object:
            run_calls.append(cmd)
            if cmd == [AWG_TOOL, "genkey"]:
                return type("R", (), {"ok": True, "stdout": NEW_PRIV, "stderr": ""})()
            if cmd == [AWG_TOOL, "pubkey"]:
                return type("R", (), {"ok": True, "stdout": bad_pub, "stderr": ""})()
            return type("R", (), {"ok": False, "stdout": "", "stderr": "fail"})()

        with patch("gatebsd_ui.writers.vpn.run", side_effect=tracking_run):
            status, body = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(body["error"], "awg pubkey returned invalid public key")
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertEqual(call_count, [])

    # =========================================================
    # 1-8: BASIC OPERATIONS (full bytes assertions)
    # =========================================================

    def test_replaces_only_interface_private_key(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = (
            b"[Interface]\n"
            b"Address = 10.0.0.1/24\n"
            b"PrivateKey = OLDKEY\n"
            b"\n"
            b"[Peer]\n"
            b"PublicKey = " + KEY_A.encode() + b"\n"
            b"AllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, body = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        self.assertEqual(body["public_key"], NEW_PUB)
        result = self._read_bytes("wg0.conf")
        expected = (
            b"[Interface]\n"
            b"Address = 10.0.0.1/24\n"
            b"PrivateKey = " + NEW_PRIV.encode() + b"\n"
            b"\n"
            b"[Peer]\n"
            b"PublicKey = " + KEY_A.encode() + b"\n"
            b"AllowedIPs = 10.0.0.2/32\n"
        )
        self.assertEqual(result, expected)

    def test_pubkeys_unchanged(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = (
            b"[Interface]\nPrivateKey = OLDKEY\n\n"
            b"[Peer]\nPublicKey = " + KEY_A.encode() + b"\nAllowedIPs = 10.0.0.2/32\n\n"
            b"[Peer]\nPublicKey = " + KEY_B.encode() + b"\nAllowedIPs = 10.0.0.3/32\n"
        )
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = (
            b"[Interface]\nPrivateKey = " + NEW_PRIV.encode() + b"\n\n"
            b"[Peer]\nPublicKey = " + KEY_A.encode() + b"\nAllowedIPs = 10.0.0.2/32\n\n"
            b"[Peer]\nPublicKey = " + KEY_B.encode() + b"\nAllowedIPs = 10.0.0.3/32\n"
        )
        self.assertEqual(result, expected)

    def test_peer_privatekey_unchanged(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = (
            b"[Interface]\nPrivateKey = IFACE_KEY\n\n"
            b"[Peer]\nPrivateKey = PEER_KEY\nPublicKey = " + KEY_A.encode() + b"\n"
        )
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = (
            b"[Interface]\nPrivateKey = " + NEW_PRIV.encode() + b"\n\n"
            b"[Peer]\nPrivateKey = PEER_KEY\nPublicKey = " + KEY_A.encode() + b"\n"
        )
        self.assertEqual(result, expected)

    def test_privatekey_extra_unchanged(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\nPrivateKeyExtra = EXTRA\n"
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = b"[Interface]\nPrivateKey = " + NEW_PRIV.encode() + b"\nPrivateKeyExtra = EXTRA\n"
        self.assertEqual(result, expected)

    def test_commented_privatekey_unchanged(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\n# PrivateKey = commented\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = b"[Interface]\n# PrivateKey = commented\nPrivateKey = " + NEW_PRIV.encode() + b"\n"
        self.assertEqual(result, expected)

    def test_comments_and_blanks_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"# header\n\n[Interface]\n# iface comment\nPrivateKey = OLDKEY\n\n"
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = b"# header\n\n[Interface]\n# iface comment\nPrivateKey = " + NEW_PRIV.encode() + b"\n\n"
        self.assertEqual(result, expected)

    def test_preamble_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"# generated\n# keep this\n[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = b"# generated\n# keep this\n[Interface]\nPrivateKey = " + NEW_PRIV.encode() + b"\n"
        self.assertEqual(result, expected)

    def test_sections_after_peers_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = (
            b"[Interface]\nPrivateKey = OLDKEY\n\n"
            b"[Peer]\nPublicKey = " + KEY_A.encode() + b"\n\n"
            b"[SomeOther]\nKey = value\n"
        )
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = (
            b"[Interface]\nPrivateKey = " + NEW_PRIV.encode() + b"\n\n"
            b"[Peer]\nPublicKey = " + KEY_A.encode() + b"\n\n"
            b"[SomeOther]\nKey = value\n"
        )
        self.assertEqual(result, expected)

    # =========================================================
    # 9-12: BYTES-SAFETY
    # =========================================================

    def test_crlf_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\r\nPrivateKey = OLDKEY\r\n\r\n[Peer]\r\nPublicKey = " + KEY_A.encode() + b"\r\n"
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = (
            b"[Interface]\r\nPrivateKey = " + NEW_PRIV.encode() + b"\r\n"
            b"\r\n[Peer]\r\nPublicKey = " + KEY_A.encode() + b"\r\n"
        )
        self.assertEqual(result, expected)

    def test_mixed_endings_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = (
            b"# header\r\n"
            b"[Interface]\n"
            b"PrivateKey = OLDKEY\r\n"
            b"\n"
            b"[Peer]\r\n"
            b"PublicKey = " + KEY_A.encode() + b"\r\n"
        )
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = (
            b"# header\r\n"
            b"[Interface]\n"
            b"PrivateKey = " + NEW_PRIV.encode() + b"\r\n"
            b"\n"
            b"[Peer]\r\n"
            b"PublicKey = " + KEY_A.encode() + b"\r\n"
        )
        self.assertEqual(result, expected)

    def test_invalid_utf8_byte_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"# comment\xff\n[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = b"# comment\xff\n[Interface]\nPrivateKey = " + NEW_PRIV.encode() + b"\n"
        self.assertEqual(result, expected)

    def test_no_trailing_newline_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY"
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = b"[Interface]\nPrivateKey = " + NEW_PRIV.encode()
        self.assertEqual(result, expected)

    # =========================================================
    # INLINE COMMENT AND SPACES
    # =========================================================

    def test_inline_comment_and_spaces_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\n    PrivateKey  =  OLDKEY   # interface key\n"
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = b"[Interface]\n    PrivateKey  =  " + NEW_PRIV.encode() + b"   # interface key\n"
        self.assertEqual(result, expected)

    # =========================================================
    # QUOTE HANDLING
    # =========================================================

    def test_quoted_key_no_comment(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b'[Interface]\nPrivateKey = "OLDKEY"\n'
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = b'[Interface]\nPrivateKey = "' + NEW_PRIV.encode() + b'"\n'
        self.assertEqual(result, expected)

    def test_quoted_key_with_spaces_and_comment(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b'[Interface]\n    PrivateKey  =  "OLDKEY"   # my key\n'
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = b'[Interface]\n    PrivateKey  =  "' + NEW_PRIV.encode() + b'"   # my key\n'
        self.assertEqual(result, expected)

    def test_quoted_key_crlf(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b'[Interface]\r\nPrivateKey = "OLDKEY"\r\n'
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = b'[Interface]\r\nPrivateKey = "' + NEW_PRIV.encode() + b'"\r\n'
        self.assertEqual(result, expected)

    def test_opening_quote_only_409(self) -> None:
        conf = b'[Interface]\nPrivateKey = "OLDKEY\n'
        self._assert_409_no_change(conf)

    def test_closing_quote_only_409(self) -> None:
        conf = b'[Interface]\nPrivateKey = OLDKEY"\n'
        self._assert_409_no_change(conf)

    def test_nested_quotes_409(self) -> None:
        conf = b'[Interface]\nPrivateKey = ""OLDKEY""\n'
        self._assert_409_no_change(conf)

    def test_extra_quotes_409(self) -> None:
        conf = b'[Interface]\nPrivateKey = "OLD"KEY"\n'
        self._assert_409_no_change(conf)

    def test_quote_in_middle_409(self) -> None:
        conf = b'[Interface]\nPrivateKey = OLD"KEY\n'
        self._assert_409_no_change(conf)

    def test_two_quotes_in_middle_409(self) -> None:
        conf = b'[Interface]\nPrivateKey = OLD"KE"Y\n'
        self._assert_409_no_change(conf)

    def test_quoted_with_trailing_409(self) -> None:
        conf = b'[Interface]\nPrivateKey = "OLDKEY"extra\n'
        self._assert_409_no_change(conf)

    def test_quoted_with_leading_409(self) -> None:
        conf = b'[Interface]\nPrivateKey = extra"OLDKEY"\n'
        self._assert_409_no_change(conf)

    def test_comment_with_quotes_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b'[Interface]\nPrivateKey = OLDKEY   # comment with "quotes"\n'
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        result = self._read_bytes("wg0.conf")
        expected = b'[Interface]\nPrivateKey = ' + NEW_PRIV.encode() + b'   # comment with "quotes"\n'
        self.assertEqual(result, expected)

    # =========================================================
    # AMBIGUOUS CONFIGS → 409
    # =========================================================

    def test_no_interface_section(self) -> None:
        conf = b"[Peer]\nPublicKey = " + KEY_A.encode() + b"\n"
        self._assert_409_no_change(conf)

    def test_two_interface_sections(self) -> None:
        conf = b"[Interface]\nPrivateKey = A\n\n[Interface]\nPrivateKey = B\n"
        self._assert_409_no_change(conf)

    def test_no_privatekey_in_interface(self) -> None:
        conf = b"[Interface]\nAddress = 10.0.0.1/24\n"
        self._assert_409_no_change(conf)

    def test_two_privatekeys_in_interface(self) -> None:
        conf = b"[Interface]\nPrivateKey = A\nPrivateKey = B\n"
        self._assert_409_no_change(conf)

    # =========================================================
    # CONF_NAME VALIDATION
    # =========================================================

    def _assert_conf_name_400(self, name: object) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        before = set(self.conf_dir.iterdir())
        self.patcher_backup.stop()
        call_count: list[int] = []
        run_calls: list[bool] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()

        def tracking_run(*a: object, **kw: object) -> object:
            run_calls.append(True)
            return type("R", (), {"ok": False, "stdout": "", "stderr": ""})()

        with patch("gatebsd_ui.writers.vpn.run", side_effect=tracking_run):
            status, body = awg_key_rotate(name)  # type: ignore[arg-type]
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "invalid config name"})
        self.assertEqual(call_count, [])
        self.assertEqual(run_calls, [])
        self.assertEqual(set(self.conf_dir.iterdir()), before)

    def test_conf_name_none(self) -> None:
        self._assert_conf_name_400(None)

    def test_conf_name_int(self) -> None:
        self._assert_conf_name_400(123)

    def test_conf_name_list(self) -> None:
        self._assert_conf_name_400([])

    def test_conf_name_dict(self) -> None:
        self._assert_conf_name_400({})

    def test_conf_name_empty_string(self) -> None:
        self._assert_conf_name_400("")

    def test_conf_name_with_lf(self) -> None:
        self._assert_conf_name_400("wg0\n")

    def test_conf_name_with_crlf(self) -> None:
        self._assert_conf_name_400("wg0\r\n")

    def test_conf_name_with_tab(self) -> None:
        self._assert_conf_name_400("wg0\t")

    def test_conf_name_path_traversal(self) -> None:
        self._assert_conf_name_400("../wg0")

    def test_conf_name_slash(self) -> None:
        self._assert_conf_name_400("wg/0")

    def test_conf_name_space(self) -> None:
        self._assert_conf_name_400("wg 0")

    def test_conf_name_unicode(self) -> None:
        self._assert_conf_name_400("тест")

    def test_conf_name_null_byte(self) -> None:
        self._assert_conf_name_400("wg\x00")

    def test_conf_name_valid_awg0(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("awg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("awg0")
        self.assertEqual(status, 200)

    def test_conf_name_valid_underscore(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg_0.conf", b"[Interface]\nPrivateKey = OLD\n")
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("wg_0")
        self.assertEqual(status, 200)

    def test_conf_name_valid_hyphen(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg-0.conf", b"[Interface]\nPrivateKey = OLD\n")
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("wg-0")
        self.assertEqual(status, 200)

    def test_conf_name_valid_mixed(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("AWG_test-1.conf", b"[Interface]\nPrivateKey = OLD\n")
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("AWG_test-1")
        self.assertEqual(status, 200)

    # =========================================================
    # INVALID WG GENKEY OUTPUT → 500
    # =========================================================

    def test_genkey_empty_output(self) -> None:
        self._assert_invalid_privkey_500("")

    def test_genkey_only_whitespace(self) -> None:
        self._assert_invalid_privkey_500("   \t  \n")

    def test_genkey_too_short(self) -> None:
        self._assert_invalid_privkey_500("QUFB")

    def test_genkey_too_long(self) -> None:
        self._assert_invalid_privkey_500(NEW_PRIV + "A")

    def test_genkey_internal_lf(self) -> None:
        self._assert_invalid_privkey_500(NEW_PRIV[:22] + "\n" + NEW_PRIV[22:])

    def test_genkey_internal_crlf(self) -> None:
        self._assert_invalid_privkey_500(NEW_PRIV[:22] + "\r\n" + NEW_PRIV[22:])

    def test_genkey_non_ascii(self) -> None:
        self._assert_invalid_privkey_500("тест" * 11)

    def test_genkey_invalid_base64_char(self) -> None:
        self._assert_invalid_privkey_500("!" * 44)

    def test_genkey_wrong_decode_length(self) -> None:
        bad = base64.b64encode(b"\x00" * 33).decode()
        self._assert_invalid_privkey_500(bad)

    def test_genkey_none_stdout(self) -> None:
        self._assert_invalid_privkey_500(None)

    def test_genkey_bytes_stdout(self) -> None:
        self._assert_invalid_privkey_500(b"not a string")

    def test_genkey_int_stdout(self) -> None:
        self._assert_invalid_privkey_500(12345)

    def test_genkey_leading_space(self) -> None:
        self._assert_invalid_privkey_500(" " + NEW_PRIV)

    def test_genkey_trailing_space(self) -> None:
        self._assert_invalid_privkey_500(NEW_PRIV + " ")

    def test_genkey_trailing_lf(self) -> None:
        self._assert_invalid_privkey_500(NEW_PRIV + "\n")

    def test_genkey_trailing_crlf(self) -> None:
        self._assert_invalid_privkey_500(NEW_PRIV + "\r\n")

    def test_genkey_non_canonical_base64(self) -> None:
        canonical = NEW_PRIV
        noncanonical = self._make_noncanonical(canonical)
        self.assertNotEqual(canonical, noncanonical)
        self.assertEqual(len(canonical), 44)
        self.assertEqual(len(noncanonical), 44)
        self.assertEqual(
            base64.b64decode(canonical, validate=True),
            base64.b64decode(noncanonical, validate=True),
        )
        self.assertEqual(len(base64.b64decode(noncanonical, validate=True)), 32)
        self._assert_invalid_privkey_500(noncanonical)

    def test_genkey_failure_no_change(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        self.patcher_backup.stop()
        call_count: list[int] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()

        def fail_run(cmd: list[str], **kw: object) -> object:
            return type("R", (), {"ok": False, "stdout": "", "stderr": "fail"})()

        with patch("gatebsd_ui.writers.vpn.run", side_effect=fail_run):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertEqual(call_count, [])

    # =========================================================
    # INVALID WG PUBKEY OUTPUT → 500
    # =========================================================

    def test_pubkey_empty_output(self) -> None:
        self._assert_invalid_pubkey_500("")

    def test_pubkey_internal_lf(self) -> None:
        self._assert_invalid_pubkey_500(NEW_PUB[:22] + "\n" + NEW_PUB[22:])

    def test_pubkey_non_ascii(self) -> None:
        self._assert_invalid_pubkey_500("тест" * 11)

    def test_pubkey_wrong_length(self) -> None:
        self._assert_invalid_pubkey_500("A" * 30)

    def test_pubkey_invalid_base64(self) -> None:
        self._assert_invalid_pubkey_500("!" * 44)

    def test_pubkey_wrong_decode_length(self) -> None:
        bad = base64.b64encode(b"\x00" * 33).decode()
        self._assert_invalid_pubkey_500(bad)

    def test_pubkey_none_stdout(self) -> None:
        self._assert_invalid_pubkey_500(None)

    def test_pubkey_bytes_stdout(self) -> None:
        self._assert_invalid_pubkey_500(b"not a string")

    def test_pubkey_int_stdout(self) -> None:
        self._assert_invalid_pubkey_500(12345)

    def test_pubkey_leading_space(self) -> None:
        self._assert_invalid_pubkey_500(" " + NEW_PUB)

    def test_pubkey_trailing_space(self) -> None:
        self._assert_invalid_pubkey_500(NEW_PUB + " ")

    def test_pubkey_trailing_lf(self) -> None:
        self._assert_invalid_pubkey_500(NEW_PUB + "\n")

    def test_pubkey_trailing_crlf(self) -> None:
        self._assert_invalid_pubkey_500(NEW_PUB + "\r\n")

    def test_pubkey_non_canonical_base64(self) -> None:
        canonical = NEW_PUB
        noncanonical = self._make_noncanonical(canonical)
        self.assertNotEqual(canonical, noncanonical)
        self.assertEqual(len(canonical), 44)
        self.assertEqual(len(noncanonical), 44)
        self.assertEqual(
            base64.b64decode(canonical, validate=True),
            base64.b64decode(noncanonical, validate=True),
        )
        self.assertEqual(len(base64.b64decode(noncanonical, validate=True)), 32)
        self._assert_invalid_pubkey_500(noncanonical)

    def test_pubkey_failure_no_change(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        self.patcher_backup.stop()
        call_count: list[int] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()
        genkey_ok = type("R", (), {"ok": True, "stdout": "priv\n", "stderr": ""})()
        genkey_fail = type("R", (), {"ok": False, "stdout": "", "stderr": "fail"})()

        def selective_run(cmd: list[str], **kw: object) -> object:
            if cmd == [AWG_TOOL, "genkey"]:
                return genkey_ok
            return genkey_fail

        with patch("gatebsd_ui.writers.vpn.run", side_effect=selective_run):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertEqual(call_count, [])

    # =========================================================
    # SUCCESSFUL KEY GENERATION
    # =========================================================

    def test_valid_privkey_passed_to_pubkey(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        received_input: list[str] = []

        def tracking_run(cmd: list[str], input: str = "", **kw: object) -> object:
            if cmd == [AWG_TOOL, "genkey"]:
                return type("R", (), {"ok": True, "stdout": NEW_PRIV, "stderr": ""})()
            if cmd == [AWG_TOOL, "pubkey"]:
                received_input.append(input)
                return type("R", (), {"ok": True, "stdout": NEW_PUB, "stderr": ""})()
            return type("R", (), {"ok": False, "stdout": "", "stderr": ""})()

        with patch("gatebsd_ui.writers.vpn.run", side_effect=tracking_run):
            status, body = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        self.assertEqual(received_input, [NEW_PRIV])
        self.assertEqual(body["public_key"], NEW_PUB)

    def test_full_config_byte_match(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = (
            b"# preamble\n"
            b"[Interface]\n"
            b"Address = 10.0.0.1/24\n"
            b"PrivateKey = OLDKEY\n"
            b"ListenPort = 51820\n"
            b"\n"
            b"[Peer]\n"
            b"PublicKey = " + KEY_A.encode() + b"\n"
            b"AllowedIPs = 10.0.0.2/32\n"
        )
        self._write("wg0.conf", conf)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, body = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        result = self._read_bytes("wg0.conf")
        expected = (
            b"# preamble\n"
            b"[Interface]\n"
            b"Address = 10.0.0.1/24\n"
            b"PrivateKey = " + NEW_PRIV.encode() + b"\n"
            b"ListenPort = 51820\n"
            b"\n"
            b"[Peer]\n"
            b"PublicKey = " + KEY_A.encode() + b"\n"
            b"AllowedIPs = 10.0.0.2/32\n"
        )
        self.assertEqual(result, expected)

    def test_canonical_vs_non_canonical_privkey(self) -> None:
        """Canonical accepted; non-canonical (same bytes) rejected."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        canonical = NEW_PRIV
        noncanonical = self._make_noncanonical(canonical)
        self.assertNotEqual(canonical, noncanonical)
        self.assertEqual(len(canonical), 44)
        self.assertEqual(len(noncanonical), 44)
        self.assertEqual(
            base64.b64decode(canonical, validate=True),
            base64.b64decode(noncanonical, validate=True),
        )
        self.assertEqual(len(base64.b64decode(noncanonical, validate=True)), 32)
        # Canonical → 200
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        wg_patch, _ = self._patch_wg(priv=canonical, pub=NEW_PUB)
        with wg_patch:
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        # Non-canonical → 500
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        self._assert_invalid_privkey_500(noncanonical)

    # =========================================================
    # ATOMIC WRITE TESTS
    # =========================================================

    def test_os_replace_called(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        replace_calls: list[tuple[str, str]] = []
        real_replace = os.replace

        def tracking_replace(src: str, dst: str) -> None:
            replace_calls.append((str(src), str(dst)))
            return real_replace(src, dst)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.replace", tracking_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        self.assertEqual(len(replace_calls), 1)
        self.assertIn("wg0.conf", replace_calls[0][1])

    def test_mode_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        p = self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        os.chmod(p, 0o640)
        original_mode = os.stat(p).st_mode
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)

    def test_uid_gid_preserved(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        p = self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        st = os.stat(p)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            awg_key_rotate("wg0")
        new_st = os.stat(p)
        self.assertEqual(new_st.st_uid, st.st_uid)
        self.assertEqual(new_st.st_gid, st.st_gid)

    def test_fsync_called_before_replace(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        fsync_fds: list[int] = []
        real_fsync = os.fsync

        def tracking_fsync(fd: int) -> None:
            fsync_fds.append(fd)
            return real_fsync(fd)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.fsync", tracking_fsync):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        # File data is fsynced before publication and the containing
        # directory is fsynced after os.replace.
        self.assertEqual(len(fsync_fds), 2)

    def test_fdopen_error_preserves_original(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")

        def broken_fdopen(fd: int, mode: str = "r", **kw: object) -> object:
            if "w" in mode:
                raise OSError("disk full")
            return os.fdopen(fd, mode, **kw)  # type: ignore[call-overload]

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.fdopen", broken_fdopen):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_flush_error_preserves_original(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        real_fdopen = os.fdopen

        def tracking_fdopen(fd: int, mode: str = "r", **kw: object) -> object:
            f = real_fdopen(fd, mode, **kw)
            if "w" in mode:
                original_flush = f.flush
                def broken_flush() -> None:
                    raise OSError("flush failed")
                f.flush = broken_flush  # type: ignore[method-assign]
            return f

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.fdopen", tracking_fdopen):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_fsync_error_preserves_original(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")

        def broken_fsync(fd: int) -> None:
            raise OSError("fsync failed")

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.fsync", broken_fsync):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_mode_error_preserves_original(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")

        def broken_chmod(path: object, mode: int) -> None:
            raise OSError("chmod failed")

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.chmod", broken_chmod):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_chown_error_preserves_original(self) -> None:
        """chown failure must abort: return 500, no replace, original unchanged."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        before = set(self.conf_dir.iterdir())
        replace_called = [False]

        def broken_chown(path: object, uid: int, gid: int) -> None:
            raise OSError("chown failed")

        def tracking_replace(src: str, dst: str) -> None:
            replace_called[0] = True
            os.replace(src, dst)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.chown", broken_chown), \
             patch("gatebsd_ui.writers.vpn.os.replace", tracking_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertFalse(replace_called[0])
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set(), f"temp files left: {new_files}")

    def test_replace_error_preserves_original(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")

        def broken_replace(src: str, dst: str) -> None:
            raise OSError("replace failed")

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.replace", broken_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_no_temp_files_after_replace_error(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        before = set(self.conf_dir.iterdir())

        def broken_replace(src: str, dst: str) -> None:
            raise OSError("simulated")

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.replace", broken_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set(), f"temp files left: {new_files}")

    def test_no_temp_files_after_chmod_error(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        before = set(self.conf_dir.iterdir())

        def broken_chmod(path: object, mode: int) -> None:
            raise OSError("chmod failed")

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.chmod", broken_chmod):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set(), f"temp files left: {new_files}")

    def test_no_temp_files_after_chown_error(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        before = set(self.conf_dir.iterdir())

        def broken_chown(path: object, uid: int, gid: int) -> None:
            raise OSError("chown failed")

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.chown", broken_chown):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set(), f"temp files left: {new_files}")

    def test_two_sequential_calls_use_different_tmp_names(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        tmp_names: list[str] = []
        real_mkdtemp = tempfile.mkstemp

        def tracking_mkdtemp(**kwargs: object) -> tuple[int, str]:  # type: ignore[override]
            fd, name = real_mkdtemp(**kwargs)  # type: ignore[arg-type]
            tmp_names.append(name)
            return fd, name

        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.tempfile.mkstemp", tracking_mkdtemp):
            awg_key_rotate("wg0")
            awg_key_rotate("wg0")
        self.assertEqual(len(tmp_names), 2)
        self.assertNotEqual(tmp_names[0], tmp_names[1])

    # =========================================================
    # NEW: exists error, stat error, and mkstemp error tests
    # =========================================================

    def test_exists_error_returns_500(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        original = self._read_bytes("wg0.conf")

        real_lstat = Path.lstat

        def broken_lstat(self_path: Path, *a: object, **kw: object) -> object:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                raise OSError("permission denied")
            return real_lstat(self_path, *a, **kw)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(Path, "lstat", broken_lstat):
            status, body = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertIn("error", body)
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_exists_error_no_temp_files(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        before = set(self.conf_dir.iterdir())

        real_lstat = Path.lstat

        def broken_lstat(self_path: Path, *a: object, **kw: object) -> object:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                raise OSError("permission denied")
            return real_lstat(self_path, *a, **kw)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(Path, "lstat", broken_lstat):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set())

    def test_stat_error_returns_500(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        original = self._read_bytes("wg0.conf")

        import inspect
        real_lstat = Path.lstat

        def selective_lstat(self_path: Path, *a: object, **kw: object) -> object:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                for frame in inspect.stack():
                    if frame.function == "atomic_write_bytes":
                        raise OSError("lstat failed")
            return real_lstat(self_path, *a, **kw)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(Path, "lstat", selective_lstat):
            status, body = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertIn("error", body)
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_stat_error_no_temp_files(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        before = set(self.conf_dir.iterdir())

        import inspect
        real_lstat = Path.lstat

        def selective_lstat(self_path: Path, *a: object, **kw: object) -> object:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                for frame in inspect.stack():
                    if frame.function == "atomic_write_bytes":
                        raise OSError("lstat failed")
            return real_lstat(self_path, *a, **kw)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(Path, "lstat", selective_lstat):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set())


    def test_mkstemp_error_returns_500(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        original = self._read_bytes("wg0.conf")

        def broken_mkstemp(**kwargs: object) -> tuple[int, str]:
            raise OSError("mkstemp failed")

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.tempfile.mkstemp", broken_mkstemp):
            status, body = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertIn("error", body)
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_mkstemp_error_no_temp_files(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        before = set(self.conf_dir.iterdir())

        def broken_mkstemp(**kwargs: object) -> tuple[int, str]:
            raise OSError("mkstemp failed")

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.tempfile.mkstemp", broken_mkstemp):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set())

    # =========================================================
    # NEW: fdopen fd leak test
    # =========================================================

    def test_fdopen_error_closes_fd(self) -> None:
        """When fdopen fails, the raw fd must be closed exactly once."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        original = self._read_bytes("wg0.conf")
        captured_fds: list[int] = []
        real_open = os.open

        def tracking_open(path: object, flags: int, mode: int = 0o666) -> int:
            fd = real_open(path, flags, mode)
            captured_fds.append(fd)
            return fd

        def broken_fdopen(fd: int, mode: str = "r", **kw: object) -> object:
            if "w" in mode:
                raise OSError("fdopen failed")
            return os.fdopen(fd, mode, **kw)  # type: ignore[call-overload]

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.open", tracking_open), \
             patch("gatebsd_ui.writers.vpn.os.fdopen", broken_fdopen):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertTrue(len(captured_fds) >= 1)
        for fd in captured_fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_fdopen_error_no_temp_files(self) -> None:
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        before = set(self.conf_dir.iterdir())

        def broken_fdopen(fd: int, mode: str = "r", **kw: object) -> object:
            if "w" in mode:
                raise OSError("fdopen failed")
            return os.fdopen(fd, mode, **kw)  # type: ignore[call-overload]

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.fdopen", broken_fdopen):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set())

    # =========================================================
    # NEW: write error (separate from fdopen)
    # =========================================================

    def test_write_error_preserves_original(self) -> None:
        """tmp.write() failure: 500, original unchanged, temp file removed."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        before = set(self.conf_dir.iterdir())

        class WriteFailWrapper:
            def write(self, data: object) -> None:
                raise OSError("disk full")
            def flush(self) -> None:
                pass
            def fileno(self) -> int:
                return -1
            def __enter__(self) -> "WriteFailWrapper":
                return self
            def __exit__(self, *a: object) -> None:
                pass

        real_fdopen = os.fdopen

        def wrapping_fdopen(fd: int, mode: str = "r", **kw: object) -> object:
            if "w" in mode:
                return WriteFailWrapper()
            return real_fdopen(fd, mode, **kw)  # type: ignore[call-overload]

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.fdopen", wrapping_fdopen):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set(), f"temp files left: {new_files}")

    # =========================================================
    # NEW: comprehensive operation order test
    # =========================================================

    def test_operation_order(self) -> None:
        """Prove write→flush→fsync→chown→chmod→replace order."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        call_order: list[str] = []

        class TrackingWrite:
            def write(self, data: object) -> None:
                call_order.append("write")
            def flush(self) -> None:
                call_order.append("flush")
            def fileno(self) -> int:
                return -1
            def __enter__(self) -> "TrackingWrite":
                return self
            def __exit__(self, *a: object) -> None:
                pass

        real_fdopen = os.fdopen

        def tracking_fdopen(fd: int, mode: str = "r", **kw: object) -> object:
            if "w" in mode:
                return TrackingWrite()
            return real_fdopen(fd, mode, **kw)  # type: ignore[call-overload]

        def tracking_fsync(fd: int) -> None:
            call_order.append("fsync")

        def tracking_chown(path: object, uid: int, gid: int) -> None:
            call_order.append("chown")

        def tracking_chmod(path: object, mode: int) -> None:
            call_order.append("chmod")

        real_replace = os.replace

        def tracking_replace(src: str, dst: str) -> None:
            call_order.append("replace")
            return real_replace(src, dst)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.fdopen", tracking_fdopen), \
             patch("gatebsd_ui.writers.vpn.os.fsync", tracking_fsync), \
             patch("gatebsd_ui.writers.vpn.os.chown", tracking_chown), \
             patch("gatebsd_ui.writers.vpn.os.chmod", tracking_chmod), \
             patch("gatebsd_ui.writers.vpn.os.replace", tracking_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        self.assertEqual(call_order, [
            "write", "flush", "fsync", "chown", "chmod", "replace", "fsync",
        ])

    def test_fsync_before_replace(self) -> None:
        """fsync must happen before os.replace."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        call_order: list[str] = []

        def tracking_fsync(fd: int) -> None:
            call_order.append("fsync")

        real_replace = os.replace

        def tracking_replace(src: str, dst: str) -> None:
            call_order.append("replace")
            return real_replace(src, dst)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.fsync", tracking_fsync), \
             patch("gatebsd_ui.writers.vpn.os.replace", tracking_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        self.assertIn("fsync", call_order)
        self.assertIn("replace", call_order)
        self.assertLess(call_order.index("fsync"), call_order.index("replace"))

    def test_chown_before_replace(self) -> None:
        """chown must happen before os.replace."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        call_order: list[str] = []

        real_chown = os.chown

        def tracking_chown(path: object, uid: int, gid: int) -> None:
            call_order.append("chown")
            return real_chown(path, uid, gid)

        real_replace = os.replace

        def tracking_replace(src: str, dst: str) -> None:
            call_order.append("replace")
            return real_replace(src, dst)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.chown", tracking_chown), \
             patch("gatebsd_ui.writers.vpn.os.replace", tracking_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        self.assertLess(call_order.index("chown"), call_order.index("replace"))

    def test_chmod_before_replace(self) -> None:
        """chmod must happen before os.replace."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        call_order: list[str] = []

        real_chmod = os.chmod

        def tracking_chmod(path: object, mode: int) -> None:
            call_order.append("chmod")
            return real_chmod(path, mode)

        real_replace = os.replace

        def tracking_replace(src: str, dst: str) -> None:
            call_order.append("replace")
            return real_replace(src, dst)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.chmod", tracking_chmod), \
             patch("gatebsd_ui.writers.vpn.os.replace", tracking_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        self.assertLess(call_order.index("chmod"), call_order.index("replace"))

    def test_backup_before_write(self) -> None:
        """Backup must happen before the atomic write."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        call_order: list[str] = []
        self.patcher_backup.stop()

        def tracking_backup(*a: object, **kw: object) -> dict:
            call_order.append("backup")
            return {}

        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=tracking_backup,
        )
        self.patcher_backup.start()
        real_replace = os.replace

        def tracking_replace(src: str, dst: str) -> None:
            call_order.append("replace")
            return real_replace(src, dst)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.replace", tracking_replace):
            awg_key_rotate("wg0")
        self.assertEqual(call_order, ["backup", "replace"])

    # =========================================================
    # NEW: comprehensive cleanup verification across all errors
    # =========================================================

    def _verify_500_cleanup(self, patches_map: dict[str, object]) -> None:
        """Common assertion: error returns 500, original unchanged, no temp files."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Interface]\nPrivateKey = OLDKEY\n"
        self._write("wg0.conf", conf)
        original = self._read_bytes("wg0.conf")
        before = set(self.conf_dir.iterdir())
        replace_called = [False]

        if "os.replace" not in patches_map:
            real_replace = os.replace

            def tracking_replace(src: str, dst: str) -> None:
                replace_called[0] = True
                return real_replace(src, dst)

            patches_map = {**patches_map, "os.replace": tracking_replace}

        active: list[object] = []
        for key, eff in patches_map.items():
            p = patch(f"gatebsd_ui.writers.vpn.{key}", eff)
            active.append(p)

        wg_patch, _ = self._patch_wg()
        wg_patch.__enter__()
        try:
            for p in active:
                p.__enter__()
            status, _ = awg_key_rotate("wg0")
        finally:
            for p in reversed(active):
                p.__exit__(None, None, None)
            wg_patch.__exit__(None, None, None)
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertFalse(replace_called[0])
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set(), f"temp files left: {new_files}")

    def test_cleanup_on_fdopen_error(self) -> None:
        def broken(fd: int, mode: str = "r", **kw: object) -> object:
            if "w" in mode:
                raise OSError("fdopen failed")
            return os.fdopen(fd, mode, **kw)  # type: ignore[call-overload]
        self._verify_500_cleanup({"os.fdopen": broken})

    def test_cleanup_on_fsync_error(self) -> None:
        def broken(fd: int) -> None:
            raise OSError("fsync failed")
        self._verify_500_cleanup({"os.fsync": broken})

    def test_cleanup_on_chmod_error(self) -> None:
        def broken(path: object, mode: int) -> None:
            raise OSError("chmod failed")
        self._verify_500_cleanup({"os.chmod": broken})

    def test_cleanup_on_chown_error(self) -> None:
        def broken(path: object, uid: int, gid: int) -> None:
            raise OSError("chown failed")
        self._verify_500_cleanup({"os.chown": broken})

    def test_cleanup_on_replace_error(self) -> None:
        def broken(src: str, dst: str) -> None:
            raise OSError("replace failed")
        self._verify_500_cleanup({"os.replace": broken})

    def test_cleanup_on_write_error(self) -> None:
        class WriteFail:
            def write(self, data: object) -> None:
                raise OSError("disk full")
            def flush(self) -> None:
                pass
            def fileno(self) -> int:
                return -1
            def __enter__(self) -> "WriteFail":
                return self
            def __exit__(self, *a: object) -> None:
                pass

        real_fdopen = os.fdopen

        def wrapping(fd: int, mode: str = "r", **kw: object) -> object:
            if "w" in mode:
                return WriteFail()
            return real_fdopen(fd, mode, **kw)  # type: ignore[call-overload]

        self._verify_500_cleanup({"os.fdopen": wrapping})

    def test_cleanup_on_flush_error(self) -> None:
        real_fdopen = os.fdopen

        def tracking_fdopen(fd: int, mode: str = "r", **kw: object) -> object:
            f = real_fdopen(fd, mode, **kw)
            if "w" in mode:
                original_flush = f.flush

                def broken_flush() -> None:
                    raise OSError("flush failed")
                f.flush = broken_flush  # type: ignore[method-assign]
            return f

        self._verify_500_cleanup({"os.fdopen": tracking_fdopen})

    # =========================================================
    # FLOCK TESTS
    # =========================================================

    def test_invalid_conf_name_no_lock_file(self) -> None:
        """Invalid conf_name returns 400 and does not create a lock file."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        before = set(self.conf_dir.iterdir())
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("../wg0")
        self.assertEqual(status, 400)
        after = set(self.conf_dir.iterdir())
        self.assertEqual(after, before)

    def test_lock_file_path(self) -> None:
        """Lock file is named wg0.conf.lock."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        self.assertTrue((self.conf_dir / "wg0.conf.lock").exists())

    def test_new_lock_file_mode_0600(self) -> None:
        """New lock file is created with mode 0600."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        lock_path = self.conf_dir / "wg0.conf.lock"
        self.assertTrue(lock_path.exists())
        mode = os.stat(lock_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_existing_lock_file_mode_fixed_to_0600(self) -> None:
        """Existing lock file with wrong mode gets corrected to 0600."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        lock_path = self.conf_dir / "wg0.conf.lock"
        lock_path.touch()
        os.chmod(lock_path, 0o666)
        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        mode = os.stat(lock_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_lock_ex_before_read_backup_replace(self) -> None:
        """LOCK_EX is acquired before read_bytes, backup, and replace."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        call_order: list[str] = []

        real_flock = fcntl.flock

        def tracking_flock(fd: int, operation: int) -> None:
            if operation == fcntl.LOCK_EX:
                call_order.append("flock_EX")
            elif operation == fcntl.LOCK_UN:
                call_order.append("flock_UN")
            return real_flock(fd, operation)

        self.patcher_backup.stop()

        def tracking_backup(*a: object, **kw: object) -> dict:
            call_order.append("backup")
            return {}

        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=tracking_backup,
        )
        self.patcher_backup.start()

        real_replace = os.replace

        def tracking_replace(src: str, dst: str) -> None:
            call_order.append("replace")
            return real_replace(src, dst)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(fcntl, "flock", tracking_flock), \
             patch("gatebsd_ui.writers.vpn.os.replace", tracking_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        self.assertIn("flock_EX", call_order)
        self.assertIn("backup", call_order)
        self.assertIn("replace", call_order)
        self.assertLess(call_order.index("flock_EX"), call_order.index("backup"))
        self.assertLess(call_order.index("flock_EX"), call_order.index("replace"))

    def test_lock_un_after_replace_on_success(self) -> None:
        """LOCK_UN is called after os.replace on success."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        call_order: list[str] = []

        real_flock = fcntl.flock

        def tracking_flock(fd: int, operation: int) -> None:
            if operation == fcntl.LOCK_EX:
                call_order.append("flock_EX")
            elif operation == fcntl.LOCK_UN:
                call_order.append("flock_UN")
            return real_flock(fd, operation)

        real_replace = os.replace

        def tracking_replace(src: str, dst: str) -> None:
            call_order.append("replace")
            return real_replace(src, dst)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(fcntl, "flock", tracking_flock), \
             patch("gatebsd_ui.writers.vpn.os.replace", tracking_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 200)
        self.assertIn("flock_EX", call_order)
        self.assertIn("flock_UN", call_order)
        self.assertIn("replace", call_order)
        self.assertLess(call_order.index("replace"), call_order.index("flock_UN"))

    def test_409_releases_lock(self) -> None:
        """409 error inside locked region releases lock."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        conf = b"[Peer]\nPublicKey = " + KEY_A.encode() + b"\n"
        self._write("wg0.conf", conf)
        flock_calls: list[int] = []

        real_flock = fcntl.flock

        def tracking_flock(fd: int, operation: int) -> None:
            flock_calls.append(operation)
            return real_flock(fd, operation)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(fcntl, "flock", tracking_flock):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 409)
        self.assertIn(fcntl.LOCK_EX, flock_calls)
        self.assertIn(fcntl.LOCK_UN, flock_calls)
        self.assertLess(flock_calls.index(fcntl.LOCK_EX),
                        flock_calls.index(fcntl.LOCK_UN))

    def test_open_error_returns_500_no_backup(self) -> None:
        """os.open error returns 500, no backup, config unchanged."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        original = self._read_bytes("wg0.conf")
        self.patcher_backup.stop()
        call_count: list[int] = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (call_count.append(1) or {}),
        )
        self.patcher_backup.start()

        def broken_open(path: object, flags: int, mode: int = 0o666) -> int:
            raise OSError("open failed")

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.open", broken_open):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        self.assertEqual(call_count, [])

    def test_fchmod_error_returns_500_fd_closed(self) -> None:
        """os.fchmod error returns 500, fd closed, config unchanged."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        original = self._read_bytes("wg0.conf")
        captured_fds: list[int] = []
        real_open = os.open

        def tracking_open(path: object, flags: int, mode: int = 0o666) -> int:
            fd = real_open(path, flags, mode)
            captured_fds.append(fd)
            return fd

        def broken_fchmod(fd: int, mode: int) -> None:
            raise OSError("fchmod failed")

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.open", tracking_open), \
             patch("gatebsd_ui.writers.vpn.os.fchmod", broken_fchmod):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        for fd in captured_fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_flock_error_returns_500_fd_closed(self) -> None:
        """LOCK_EX error returns 500, fd closed, config unchanged."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        original = self._read_bytes("wg0.conf")
        captured_fds: list[int] = []
        real_open = os.open

        def tracking_open(path: object, flags: int, mode: int = 0o666) -> int:
            fd = real_open(path, flags, mode)
            captured_fds.append(fd)
            return fd

        real_flock = fcntl.flock

        def broken_flock(fd: int, operation: int) -> None:
            if operation == fcntl.LOCK_EX:
                raise OSError("flock failed")
            return real_flock(fd, operation)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.open", tracking_open), \
             patch.object(fcntl, "flock", broken_flock):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(self._read_bytes("wg0.conf"), original)
        for fd in captured_fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_error_during_write_releases_lock_fd_closed(self) -> None:
        """Error during atomic write releases lock and closes fd."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        captured_fds: list[int] = []
        real_open = os.open

        def tracking_open(path: object, flags: int, mode: int = 0o666) -> int:
            fd = real_open(path, flags, mode)
            captured_fds.append(fd)
            return fd

        def broken_replace(src: str, dst: str) -> None:
            raise OSError("replace failed")

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.open", tracking_open), \
             patch("gatebsd_ui.writers.vpn.os.replace", broken_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        for fd in captured_fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    # =========================================================
    # FLOCK ERROR PATHS: read_bytes and backup_files
    # =========================================================

    def test_read_error_returns_500(self) -> None:
        """OSError from read_bytes returns 500 with correct message."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        original = self._read_bytes("wg0.conf")

        real_read = Path.read_bytes

        def selective_read(self_path: Path, *a: object, **kw: object) -> bytes:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                raise OSError("read failed")
            return real_read(self_path, *a, **kw)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(Path, "read_bytes", selective_read):
            status, body = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(body["error"], "failed to read config")
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_read_error_no_replace(self) -> None:
        """OSError from read_bytes does not call os.replace."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")

        real_read = Path.read_bytes

        def selective_read(self_path: Path, *a: object, **kw: object) -> bytes:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                raise OSError("read failed")
            return real_read(self_path, *a, **kw)

        replace_called = []
        real_replace = os.replace

        def tracking_replace(src: str, dst: str) -> None:
            replace_called.append(True)
            return real_replace(src, dst)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(Path, "read_bytes", selective_read), \
             patch("gatebsd_ui.writers.vpn.os.replace", tracking_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(replace_called, [])

    def test_read_error_no_mkstemp(self) -> None:
        """OSError from read_bytes does not call tempfile.mkstemp."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")

        real_read = Path.read_bytes

        def selective_read(self_path: Path, *a: object, **kw: object) -> bytes:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                raise OSError("read failed")
            return real_read(self_path, *a, **kw)

        mkstemp_called = []

        def tracking_mkstemp(**kw: object) -> tuple[int, str]:
            mkstemp_called.append(True)
            return tempfile.mkstemp(**kw)  # type: ignore[arg-type]

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(Path, "read_bytes", selective_read), \
             patch("gatebsd_ui.writers.vpn.tempfile.mkstemp", tracking_mkstemp):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(mkstemp_called, [])

    def test_read_error_no_backup(self) -> None:
        """OSError from read_bytes does not call backup_files."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")

        real_read = Path.read_bytes

        def selective_read(self_path: Path, *a: object, **kw: object) -> bytes:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                raise OSError("read failed")
            return real_read(self_path, *a, **kw)

        self.patcher_backup.stop()
        backup_called = []
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=lambda *a, **kw: (backup_called.append(True) or {}),
        )
        self.patcher_backup.start()

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(Path, "read_bytes", selective_read):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(backup_called, [])

    def test_read_error_no_temp_files(self) -> None:
        """OSError from read_bytes leaves no temp files."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        before = set(self.conf_dir.iterdir())

        real_read = Path.read_bytes

        def selective_read(self_path: Path, *a: object, **kw: object) -> bytes:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                raise OSError("read failed")
            return real_read(self_path, *a, **kw)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(Path, "read_bytes", selective_read):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set())

    def test_read_error_lock_file_exists_mode_0600(self) -> None:
        """OSError from read_bytes: lock file exists with mode 0600."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")

        real_read = Path.read_bytes

        def selective_read(self_path: Path, *a: object, **kw: object) -> bytes:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                raise OSError("read failed")
            return real_read(self_path, *a, **kw)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(Path, "read_bytes", selective_read):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        lock_path = self.conf_dir / "wg0.conf.lock"
        self.assertTrue(lock_path.exists())
        mode = os.stat(lock_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_read_error_lock_fd_closed(self) -> None:
        """OSError from read_bytes: lock fd is closed after return."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        captured_fds: list[int] = []
        real_open = os.open

        def tracking_open(path: object, flags: int, mode: int = 0o666) -> int:
            fd = real_open(path, flags, mode)
            captured_fds.append(fd)
            return fd

        real_read = Path.read_bytes

        def selective_read(self_path: Path, *a: object, **kw: object) -> bytes:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                raise OSError("read failed")
            return real_read(self_path, *a, **kw)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.open", tracking_open), \
             patch.object(Path, "read_bytes", selective_read):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertTrue(len(captured_fds) >= 1)
        for fd in captured_fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_read_error_lock_released_immediately(self) -> None:
        """OSError from read_bytes: new fd can acquire LOCK_EX|LOCK_NB."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        lock_path = self.conf_dir / "wg0.conf.lock"

        real_read = Path.read_bytes

        def selective_read(self_path: Path, *a: object, **kw: object) -> bytes:
            if self_path.name == "wg0.conf" and self_path.parent == self.conf_dir:
                raise OSError("read failed")
            return real_read(self_path, *a, **kw)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch.object(Path, "read_bytes", selective_read):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def test_backup_error_returns_500(self) -> None:
        """OSError from backup_files returns 500 with correct message."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        original = self._read_bytes("wg0.conf")

        self.patcher_backup.stop()
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=OSError("backup failed"),
        )
        self.patcher_backup.start()

        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, body = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(body["error"], "failed to back up config")
        self.assertEqual(self._read_bytes("wg0.conf"), original)

    def test_backup_error_no_replace(self) -> None:
        """OSError from backup_files does not call os.replace."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")

        self.patcher_backup.stop()
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=OSError("backup failed"),
        )
        self.patcher_backup.start()

        replace_called = []
        real_replace = os.replace

        def tracking_replace(src: str, dst: str) -> None:
            replace_called.append(True)
            return real_replace(src, dst)

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.replace", tracking_replace):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(replace_called, [])

    def test_backup_error_no_mkstemp(self) -> None:
        """OSError from backup_files does not call tempfile.mkstemp."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")

        self.patcher_backup.stop()
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=OSError("backup failed"),
        )
        self.patcher_backup.start()

        mkstemp_called = []

        def tracking_mkstemp(**kw: object) -> tuple[int, str]:
            mkstemp_called.append(True)
            return tempfile.mkstemp(**kw)  # type: ignore[arg-type]

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.tempfile.mkstemp", tracking_mkstemp):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertEqual(mkstemp_called, [])

    def test_backup_error_no_temp_files(self) -> None:
        """OSError from backup_files leaves no temp files."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        before = set(self.conf_dir.iterdir())

        self.patcher_backup.stop()
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=OSError("backup failed"),
        )
        self.patcher_backup.start()

        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        after = set(self.conf_dir.iterdir())
        new_files = {f for f in (after - before) if not f.name.endswith(".lock")}
        self.assertEqual(new_files, set())

    def test_backup_error_lock_file_exists_mode_0600(self) -> None:
        """OSError from backup_files: lock file exists with mode 0600."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")

        self.patcher_backup.stop()
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=OSError("backup failed"),
        )
        self.patcher_backup.start()

        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        lock_path = self.conf_dir / "wg0.conf.lock"
        self.assertTrue(lock_path.exists())
        mode = os.stat(lock_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_backup_error_lock_fd_closed(self) -> None:
        """OSError from backup_files: lock fd is closed after return."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        captured_fds: list[int] = []
        real_open = os.open

        def tracking_open(path: object, flags: int, mode: int = 0o666) -> int:
            fd = real_open(path, flags, mode)
            captured_fds.append(fd)
            return fd

        self.patcher_backup.stop()
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=OSError("backup failed"),
        )
        self.patcher_backup.start()

        wg_patch, _ = self._patch_wg()
        with wg_patch, patch("gatebsd_ui.writers.vpn.os.open", tracking_open):
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        self.assertTrue(len(captured_fds) >= 1)
        for fd in captured_fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_backup_error_lock_released_immediately(self) -> None:
        """OSError from backup_files: new fd can acquire LOCK_EX|LOCK_NB."""
        from gatebsd_ui.writers.vpn import awg_key_rotate
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLDKEY\n")
        lock_path = self.conf_dir / "wg0.conf.lock"

        self.patcher_backup.stop()
        self.patcher_backup = patch(
            "gatebsd_ui.writers.vpn.backup.backup_files",
            side_effect=OSError("backup failed"),
        )
        self.patcher_backup.start()

        wg_patch, _ = self._patch_wg()
        with wg_patch:
            status, _ = awg_key_rotate("wg0")
        self.assertEqual(status, 500)
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)


# =========================================================
# REAL FLOCK TESTS (multiprocessing)
# =========================================================

def _child_rotate(conf_dir_str: str, result_queue: object,
                  close_fd: int = -1) -> None:
    """Run awg_key_rotate in a child process."""
    if close_fd >= 0:
        os.close(close_fd)
    import gatebsd_ui.writers.vpn as vpn
    from unittest.mock import patch as _patch

    vpn.AMNEZIA_CONF_DIR = Path(conf_dir_str)

    def fake_run(cmd: list[str], **kw: object) -> object:
        if cmd == [AWG_TOOL, "genkey"]:
            return type("R", (), {"ok": True, "stdout": NEW_PRIV, "stderr": ""})()
        if cmd == [AWG_TOOL, "pubkey"]:
            return type("R", (), {"ok": True, "stdout": NEW_PUB, "stderr": ""})()
        return type("R", (), {"ok": False, "stdout": "", "stderr": "fail"})()

    with _patch.object(vpn, "run", side_effect=fake_run), \
         _patch.object(vpn.backup, "backup_files", return_value={}):
        status, body = vpn.awg_key_rotate("wg0")
    result_queue.put((status, body.get("error", ""), body.get("public_key", "")))


def _child_rotate_controlled(
    conf_dir_str: str,
    read_done_event: object,
    continue_event: object,
    result_queue: object,
    no_flock: bool = False,
    sync_timeout: float = 10,
) -> None:
    """Rotate with synchronization: signals after read, waits before write."""
    import gatebsd_ui.writers.vpn as vpn
    import fcntl as _fcntl
    import traceback
    from unittest.mock import patch as _patch

    try:
        vpn.AMNEZIA_CONF_DIR = Path(conf_dir_str)
        conf_dir = Path(conf_dir_str)

        def fake_run(cmd: list[str], **kw: object) -> object:
            if cmd == [AWG_TOOL, "genkey"]:
                return type("R", (), {"ok": True, "stdout": NEW_PRIV, "stderr": ""})()
            if cmd == [AWG_TOOL, "pubkey"]:
                return type("R", (), {"ok": True, "stdout": NEW_PUB, "stderr": ""})()
            return type("R", (), {"ok": False, "stdout": "", "stderr": "fail"})()

        real_read = Path.read_bytes

        def intercepted_read(self_path: Path, *a: object, **kw: object) -> bytes:
            result = real_read(self_path, *a, **kw)
            if self_path.name == "wg0.conf" and self_path.parent == conf_dir:
                read_done_event.set()  # type: ignore[union-attr]
                if not continue_event.wait(timeout=sync_timeout):  # type: ignore[union-attr]
                    raise _ChildSynchronizationError(
                        "rotate: continue_event timed out")
            return result

        patchers = [
            _patch.object(vpn, "run", side_effect=fake_run),
            _patch.object(vpn.backup, "backup_files", return_value={}),
            _patch.object(Path, "read_bytes", intercepted_read),
        ]
        if no_flock:
            patchers.append(_patch.object(_fcntl, "flock"))

        for p in patchers:
            p.start()
        try:
            status, body = vpn.awg_key_rotate("wg0")
        finally:
            for p in reversed(patchers):
                p.stop()
        result_queue.put((status, body.get("error", ""), body.get("public_key", "")))
    except Exception as exc:
        tb = traceback.format_exc()
        result_queue.put(("CHILD_ERROR", type(exc).__name__, str(exc), tb))
        # Flush the diagnostic tuple before exiting non-zero, without leaking
        # the expected negative-control traceback to the suite stderr.
        result_queue.close()
        result_queue.join_thread()
        raise SystemExit(1)


def _child_peer_remove(
    conf_dir_str: str, peer_pubkey: str, result_queue: object,
) -> None:
    """Run awg_peer_remove in a child process."""
    import gatebsd_ui.writers.vpn as vpn
    from unittest.mock import patch as _patch

    vpn.AMNEZIA_CONF_DIR = Path(conf_dir_str)

    with _patch.object(vpn.backup, "backup_files", return_value={}):
        status, body = vpn.awg_peer_remove("wg0", peer_pubkey)
    result_queue.put((status, body.get("error", "")))


def _child_peer_remove_controlled(
    conf_dir_str: str,
    peer_pubkey: str,
    attempted_lock_event: object,
    read_done_event: object,
    continue_event: object,
    result_queue: object,
    no_flock: bool = False,
    sync_timeout: float = 10,
) -> None:
    """Remove with synchronization: signals before flock, optional read/wait."""
    import gatebsd_ui.writers.vpn as vpn
    import fcntl as _fcntl
    import traceback
    from unittest.mock import patch as _patch

    try:
        vpn.AMNEZIA_CONF_DIR = Path(conf_dir_str)
        conf_dir = Path(conf_dir_str)

        real_read = Path.read_bytes

        def intercepted_read(self_path: Path, *a: object, **kw: object) -> bytes:
            result = real_read(self_path, *a, **kw)
            if self_path.name == "wg0.conf" and self_path.parent == conf_dir:
                if read_done_event is not None:
                    read_done_event.set()  # type: ignore[union-attr]
                if continue_event is not None:
                    if not continue_event.wait(timeout=sync_timeout):  # type: ignore[union-attr]
                        raise _ChildSynchronizationError(
                            "remove: continue_event timed out")
            return result

        real_flock = _fcntl.flock

        def signaling_flock(fd: int, operation: int) -> None:
            if operation & _fcntl.LOCK_EX:
                attempted_lock_event.set()  # type: ignore[union-attr]
            return real_flock(fd, operation)

        patchers = [
            _patch.object(vpn.backup, "backup_files", return_value={}),
            _patch.object(Path, "read_bytes", intercepted_read),
        ]
        if no_flock:
            patchers.append(_patch.object(_fcntl, "flock"))
        else:
            patchers.append(_patch.object(_fcntl, "flock", side_effect=signaling_flock))

        for p in patchers:
            p.start()
        try:
            status, body = vpn.awg_peer_remove("wg0", peer_pubkey)
        finally:
            for p in reversed(patchers):
                p.stop()
        result_queue.put((status, body.get("error", "")))
    except Exception as exc:
        tb = traceback.format_exc()
        result_queue.put(("CHILD_ERROR", type(exc).__name__, str(exc), tb))
        # Flush the diagnostic tuple before exiting non-zero, without leaking
        # the expected negative-control traceback to the suite stderr.
        result_queue.close()
        result_queue.join_thread()
        raise SystemExit(1)


# How long a spawned child gets to start and reach its first checkpoint.
#
# This was 5 seconds and it made the release gate flaky: three of these tests
# failed on the validator with "rotate did not signal read_done" while the
# same tree was green locally. Nothing was wrong with the locking -- forking a
# Python interpreter and importing the module simply took longer than five
# seconds on a loaded machine, and every wait AFTER this point already allowed
# ten.
#
# Raising it weakens nothing. What these tests prove is ORDERING, and the
# ordering proof is the SHORT wait: remove_read_done must still be unset half
# a second into rotate holding the lock. That 0.5 stays 0.5. This constant
# only covers "has the child got going at all", which has no upper bound worth
# asserting.
CHILD_START_TIMEOUT = 30


class AwgKeyRotateFlockRealTests(unittest.TestCase):
    """Real flock serialization tests using multiprocessing."""

    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.conf_dir = Path(self.td.name)

    def tearDown(self) -> None:
        self.td.cleanup()

    def _write(self, name: str, content: bytes) -> Path:
        p = self.conf_dir / name
        p.write_bytes(content)
        return p

    def _read_bytes(self, name: str) -> bytes:
        return (self.conf_dir / name).read_bytes()

    def test_parent_holds_lock_child_blocks(self) -> None:
        """Parent holds LOCK_EX; child blocks until released."""
        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")
        lock_path = str(self.conf_dir / "wg0.conf.lock")

        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

        ctx = multiprocessing.get_context("spawn")
        result_queue: multiprocessing.Queue = ctx.Queue()

        p = ctx.Process(
            target=_child_rotate,
            args=(str(self.conf_dir), result_queue),
        )
        try:
            p.start()

            time.sleep(0.3)
            self.assertTrue(p.is_alive())

            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
            lock_fd = -1

            # Drain the queue before join so the child queue feeder can exit.
            status, error, pubkey = result_queue.get(timeout=10)
            p.join(timeout=10)
            self.assertFalse(p.is_alive())
            self.assertEqual(p.exitcode, 0)
            self.assertEqual(status, 200)
            self.assertEqual(pubkey, NEW_PUB)
            self.assertEqual(
                self._read_bytes("wg0.conf"),
                b"[Interface]\nPrivateKey = " + NEW_PRIV.encode() + b"\n",
            )
        finally:
            if lock_fd >= 0:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(lock_fd)
            if p.is_alive():
                p.terminate()
                p.join(timeout=5)
            result_queue.close()
            result_queue.join_thread()

    def _assert_child_result(self, proc: multiprocessing.Process,
                             q: multiprocessing.Queue,
                             name: str) -> tuple:
        """Check child process result in strict order.

        1. process not alive
        2. get from queue (CHILD_ERROR → fail, empty → fail)
        3. exitcode == 0
        4. return result for status/body checks
        """
        self.assertFalse(proc.is_alive(),
                         f"{name} still alive (exitcode={proc.exitcode})")
        try:
            result = q.get(timeout=5)
        except Exception:
            self.fail(f"{name} queue empty (exitcode={proc.exitcode})")
        if not isinstance(result, tuple):
            self.fail(f"{name} unexpected queue item: {result!r} "
                      f"(exitcode={proc.exitcode})")
        if result[0] == "CHILD_ERROR":
            self.fail(f"{name} child error: {result[1]}: {result[2]}\n"
                      f"{result[3]}\n(exitcode={proc.exitcode})")
        self.assertEqual(proc.exitcode, 0,
                         f"{name} exitcode={proc.exitcode}")
        return result

    def _cleanup_processes(self, procs_events_queues: list) -> None:
        """Clean up processes, events, and queues with guaranteed queue close.

        procs_events_queues: list of (process, started_flag, [events...], [queues...])
        """
        cleanup_error = None
        try:
            # Step 1: set all continue events
            for _, _, events, _ in procs_events_queues:
                for ev in events:
                    ev.set()
            # Step 2: join/terminate processes
            for proc, started, _, _ in procs_events_queues:
                if not started:
                    continue
                try:
                    if proc.exitcode is None:
                        proc.join(timeout=5)
                except Exception as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
                try:
                    if proc.is_alive():
                        proc.terminate()
                        proc.join(timeout=5)
                except Exception as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
        finally:
            # Step 3: close all queues in separate finally
            queue_close_error = None
            for _, _, _, queues in procs_events_queues:
                for q in queues:
                    try:
                        q.close()
                        q.join_thread()
                    except Exception as exc:
                        if queue_close_error is None:
                            queue_close_error = exc
            if cleanup_error is not None:
                raise cleanup_error  # type: ignore[misc]
            if queue_close_error is not None:
                raise queue_close_error  # type: ignore[misc]

    def test_concurrent_rotate_and_peer_remove(self) -> None:
        """Deterministic: rotate holds lock, remove blocks, no lost update.

        Sequence:
        1. rotate acquires LOCK_EX, reads config, signals read_done, waits
        2. remove opens lock file, signals attempted_lock, blocks on flock
        3. parent proves remove has NOT reached read_bytes (remove_read_done
           remains False while lock is held)
        4. parent signals rotate to continue
        5. rotate writes new key, releases lock
        6. parent verifies remove_read_done becomes True after lock release
        7. remove writes config with peer B removed
        8. Final: new key + peer A, no peer B
        """
        ctx = multiprocessing.get_context("spawn")

        self._write("wg0.conf", (
            b"[Interface]\nPrivateKey = OLD\n\n"
            b"[Peer]\nPublicKey = " + KEY_A.encode() + b"\n"
            b"AllowedIPs = 10.0.0.2/32\n\n"
            b"[Peer]\nPublicKey = " + KEY_B.encode() + b"\n"
            b"AllowedIPs = 10.0.0.3/32\n"
        ))

        rotate_read_done = ctx.Event()
        rotate_continue = ctx.Event()
        remove_attempted_lock = ctx.Event()
        remove_read_done = ctx.Event()
        rotate_q: multiprocessing.Queue = ctx.Queue()
        remove_q: multiprocessing.Queue = ctx.Queue()

        p_rotate = ctx.Process(
            target=_child_rotate_controlled,
            args=(str(self.conf_dir), rotate_read_done, rotate_continue,
                  rotate_q, False),
        )
        # remove_continue=None: remove proceeds freely after acquiring lock
        p_remove = ctx.Process(
            target=_child_peer_remove_controlled,
            args=(str(self.conf_dir), KEY_B, remove_attempted_lock,
                  remove_read_done, None, remove_q, False),
        )

        rotate_started = False
        remove_started = False
        try:
            # Step 1: start rotate — it acquires lock, reads config, pauses
            p_rotate.start()
            rotate_started = True
            self.assertTrue(rotate_read_done.wait(timeout=CHILD_START_TIMEOUT),
                            "rotate did not signal read_done")

            # Step 2: start remove — it opens lock file and blocks on flock
            p_remove.start()
            remove_started = True
            self.assertTrue(remove_attempted_lock.wait(timeout=CHILD_START_TIMEOUT),
                            "remove did not signal attempted_lock")

            # Step 3: prove remove has NOT reached read_bytes while lock held
            self.assertFalse(
                remove_read_done.wait(timeout=0.5),
                "remove reached read_bytes while rotate holds the lock",
            )

            # Step 4: let rotate finish — it writes new key, releases lock
            rotate_continue.set()
            p_rotate.join(timeout=10)

            # Step 5: verify remove_read_done becomes True after lock release
            self.assertTrue(remove_read_done.wait(timeout=CHILD_START_TIMEOUT),
                            "remove did not read after lock was released")

            # Step 6: remove should now proceed and finish
            p_remove.join(timeout=10)

            # Step 7: verify results (exitcode checked after queue)
            rotate_result = self._assert_child_result(
                p_rotate, rotate_q, "rotate")
            remove_result = self._assert_child_result(
                p_remove, remove_q, "remove")

            s1, _, pk = rotate_result
            s2, _ = remove_result
            self.assertEqual(s1, 200)
            self.assertEqual(s2, 200)

            result = self._read_bytes("wg0.conf")
            self.assertIn(NEW_PRIV.encode(), result)   # new key present
            self.assertNotIn(KEY_B.encode(), result)   # peer B removed
            self.assertIn(KEY_A.encode(), result)      # peer A intact

        finally:
            self._cleanup_processes([
                (p_rotate, rotate_started,
                 [rotate_continue], [rotate_q]),
                (p_remove, remove_started,
                 [], [remove_q]),
            ])

    def test_lost_update_detected_without_flock(self) -> None:
        """Negative control: without flock, rotate overwrites remove's work.

        Sequence (no flock in children):
        1. rotate reads old config (OLD key + KEY_A + KEY_B), pauses
        2. remove reads old config (OLD key + KEY_A + KEY_B), pauses
        3. parent signals remove to write first
        4. remove writes: OLD key + KEY_A (peer B removed)
        5. parent signals rotate to write
        6. rotate writes stale snapshot: NEW key + KEY_A + KEY_B
        7. Final: KEY_B reappeared — lost update detected
        """
        ctx = multiprocessing.get_context("spawn")

        self._write("wg0.conf", (
            b"[Interface]\nPrivateKey = OLD\n\n"
            b"[Peer]\nPublicKey = " + KEY_A.encode() + b"\n"
            b"AllowedIPs = 10.0.0.2/32\n\n"
            b"[Peer]\nPublicKey = " + KEY_B.encode() + b"\n"
            b"AllowedIPs = 10.0.0.3/32\n"
        ))

        rotate_read_done = ctx.Event()
        rotate_continue = ctx.Event()
        remove_attempted_lock = ctx.Event()
        remove_read_done = ctx.Event()
        remove_continue = ctx.Event()
        rotate_q: multiprocessing.Queue = ctx.Queue()
        remove_q: multiprocessing.Queue = ctx.Queue()

        p_rotate = ctx.Process(
            target=_child_rotate_controlled,
            args=(str(self.conf_dir), rotate_read_done, rotate_continue,
                  rotate_q, True),  # no_flock=True
        )
        p_remove = ctx.Process(
            target=_child_peer_remove_controlled,
            args=(str(self.conf_dir), KEY_B, remove_attempted_lock,
                  remove_read_done, remove_continue, remove_q, True),
        )

        rotate_started = False
        remove_started = False
        try:
            # Step 1: start rotate without flock — reads old config, pauses
            p_rotate.start()
            rotate_started = True
            self.assertTrue(rotate_read_done.wait(timeout=CHILD_START_TIMEOUT),
                            "rotate did not signal read_done")

            # Step 2: start remove without flock — reads old config, pauses
            p_remove.start()
            remove_started = True
            self.assertTrue(remove_read_done.wait(timeout=CHILD_START_TIMEOUT),
                            "remove did not signal read_done")

            # Step 3: let remove write first (no flock, it can proceed)
            remove_continue.set()
            p_remove.join(timeout=10)

            remove_result = self._assert_child_result(
                p_remove, remove_q, "remove")
            s2, _ = remove_result
            self.assertEqual(s2, 200)

            # Verify remove's write: peer B is gone
            mid_result = self._read_bytes("wg0.conf")
            self.assertNotIn(KEY_B.encode(), mid_result,
                             "remove should have removed peer B")
            self.assertIn(KEY_A.encode(), mid_result)

            # Step 4: let rotate write its stale snapshot
            rotate_continue.set()
            p_rotate.join(timeout=10)

            rotate_result = self._assert_child_result(
                p_rotate, rotate_q, "rotate")
            s1, _, pk = rotate_result
            self.assertEqual(s1, 200)

            # Step 5: verify lost update — peer B reappeared
            final = self._read_bytes("wg0.conf")
            self.assertIn(KEY_B.encode(), final,
                          "lost update: rotate's stale write re-introduced peer B")
            self.assertIn(KEY_A.encode(), final)
            self.assertIn(NEW_PRIV.encode(), final)

        finally:
            self._cleanup_processes([
                (p_rotate, rotate_started,
                 [rotate_continue], [rotate_q]),
                (p_remove, remove_started,
                 [remove_continue], [remove_q]),
            ])

    def test_rotate_sync_timeout_reports_child_error(self) -> None:
        """When rotate's continue_event is never set, child reports CHILD_ERROR."""
        ctx = multiprocessing.get_context("spawn")

        self._write("wg0.conf", b"[Interface]\nPrivateKey = OLD\n")

        read_done = ctx.Event()
        never_set = ctx.Event()  # deliberately never set
        q: multiprocessing.Queue = ctx.Queue()

        p = ctx.Process(
            target=_child_rotate_controlled,
            args=(str(self.conf_dir), read_done, never_set, q, False, 1),
        )
        started = False
        try:
            p.start()
            started = True
            self.assertTrue(read_done.wait(timeout=CHILD_START_TIMEOUT),
                            "rotate did not signal read_done")

            # Drain the traceback-bearing queue before join; otherwise the
            # child queue feeder can block on a full pipe during shutdown.
            result = q.get(timeout=10)
            p.join(timeout=10)
            self.assertFalse(p.is_alive(),
                             f"rotate stuck, exitcode={p.exitcode}")

            # Queue result is authoritative for the controlled child error.
            self.assertIsInstance(result, tuple)
            self.assertEqual(result[0], "CHILD_ERROR")
            self.assertEqual(result[1], "_ChildSynchronizationError")
            self.assertIn("timed out", result[2])
            self.assertTrue(len(result[3]) > 0, "traceback should be non-empty")
            self.assertNotEqual(p.exitcode, 0,
                                "exitcode should be non-zero on timeout")

            # config must remain unchanged
            self.assertEqual(self._read_bytes("wg0.conf"),
                             b"[Interface]\nPrivateKey = OLD\n")
        finally:
            self._cleanup_processes([
                (p, started, [never_set], [q]),
            ])

    def test_remove_sync_timeout_reports_child_error(self) -> None:
        """When remove's continue_event is never set, child reports CHILD_ERROR."""
        ctx = multiprocessing.get_context("spawn")

        self._write("wg0.conf", (
            b"[Interface]\nPrivateKey = OLD\n\n"
            b"[Peer]\nPublicKey = " + KEY_A.encode() + b"\n"
            b"AllowedIPs = 10.0.0.2/32\n"
        ))

        attempted = ctx.Event()
        read_done = ctx.Event()
        never_set = ctx.Event()  # deliberately never set
        q: multiprocessing.Queue = ctx.Queue()

        p = ctx.Process(
            target=_child_peer_remove_controlled,
            args=(str(self.conf_dir), KEY_A, attempted, read_done,
                  never_set, q, True, 1),
        )
        started = False
        try:
            p.start()
            started = True
            self.assertTrue(read_done.wait(timeout=CHILD_START_TIMEOUT),
                            "remove did not signal read_done")

            # Drain the traceback-bearing queue before join; otherwise the
            # child queue feeder can block on a full pipe during shutdown.
            result = q.get(timeout=10)
            p.join(timeout=10)
            self.assertFalse(p.is_alive(),
                             f"remove stuck, exitcode={p.exitcode}")

            # Queue result is authoritative for the controlled child error.
            self.assertEqual(result[0], "CHILD_ERROR")
            self.assertEqual(result[1], "_ChildSynchronizationError")
            self.assertIn("timed out", result[2])
            self.assertTrue(len(result[3]) > 0, "traceback should be non-empty")
            self.assertNotEqual(p.exitcode, 0,
                                "exitcode should be non-zero on timeout")

            # config must remain unchanged
            self.assertIn(KEY_A.encode(), self._read_bytes("wg0.conf"))
        finally:
            self._cleanup_processes([
                (p, started, [never_set], [q]),
            ])

    def test_assert_child_result_rejects_nonzero_exitcode(self) -> None:
        """Regression: successful queue result must not mask non-zero exitcode."""
        ctx = multiprocessing.get_context("spawn")
        q: multiprocessing.Queue = ctx.Queue()
        q.put((200, "", "key"))

        class _FakeProc:
            exitcode = 1
            def is_alive(self) -> bool:
                return False
            def join(self, timeout: object = None) -> None:
                pass

        try:
            with self.assertRaises(AssertionError) as cm:
                self._assert_child_result(_FakeProc(), q, "fake")  # type: ignore[arg-type]
            self.assertIn("exitcode=1", str(cm.exception))
        finally:
            q.close()
            q.join_thread()

    def test_cleanup_closes_queues_on_join_exception(self) -> None:
        """Queue close must happen even if join/terminate raises."""

        class _FakeQueue:
            def __init__(self) -> None:
                self.closed = False
                self.joined = False
            def close(self) -> None:
                self.closed = True
            def join_thread(self) -> None:
                self.joined = True

        class _BadProc:
            exitcode = None
            def is_alive(self) -> bool:
                return False
            def join(self, timeout: object = None) -> None:
                raise RuntimeError("join exploded")
            def terminate(self) -> None:
                pass

        q1 = _FakeQueue()
        q2 = _FakeQueue()
        proc = _BadProc()
        try:
            self._cleanup_processes([
                (proc, True, [], [q1, q2]),
            ])
            self.fail("should have raised RuntimeError")
        except RuntimeError as e:
            self.assertIn("join exploded", str(e))
        # Both queues must be closed and joined despite the exception
        self.assertTrue(q1.closed, "q1 not closed")
        self.assertTrue(q2.closed, "q2 not closed")
        self.assertTrue(q1.joined, "q1 not joined")
        self.assertTrue(q2.joined, "q2 not joined")

    def test_cleanup_skips_unstarted_process(self) -> None:
        """Cleanup does not touch join/is_alive/terminate for unstarted proc.

        Uses fake objects with call counters to prove the started=False guard.
        The test must fail if _cleanup_processes calls is_alive/join/terminate
        on a process with started=False.
        """

        class _FakeQueue:
            def __init__(self) -> None:
                self.close_called = False
                self.join_thread_called = False

            def close(self) -> None:
                self.close_called = True

            def join_thread(self) -> None:
                self.join_thread_called = True

        class _TrackingProc:
            """Fake process that records every method call."""
            def __init__(self) -> None:
                self.join_calls = 0
                self.is_alive_calls = 0
                self.terminate_calls = 0

            @property
            def exitcode(self) -> int | None:
                return None

            def join(self, timeout: object = None) -> None:
                self.join_calls += 1

            def is_alive(self) -> bool:
                self.is_alive_calls += 1
                return False

            def terminate(self) -> None:
                self.terminate_calls += 1

        proc = _TrackingProc()
        q1 = _FakeQueue()
        q2 = _FakeQueue()

        self._cleanup_processes([
            (proc, False, [], [q1, q2]),
        ])

        # No process methods should have been called
        self.assertEqual(proc.join_calls, 0,
                         "join was called on unstarted process")
        self.assertEqual(proc.is_alive_calls, 0,
                         "is_alive was called on unstarted process")
        self.assertEqual(proc.terminate_calls, 0,
                         "terminate was called on unstarted process")

        # Both queues must still be closed and joined
        self.assertTrue(q1.close_called, "q1.close() not called")
        self.assertTrue(q1.join_thread_called, "q1.join_thread() not called")
        self.assertTrue(q2.close_called, "q2.close() not called")
        self.assertTrue(q2.join_thread_called, "q2.join_thread() not called")

    def test_cleanup_skips_unstarted_process_mutation(self) -> None:
        """Mutation guard: is_alive before started-guard must fail the test.

        If _cleanup_processes checks proc.is_alive() before the
        'if not started: continue' guard, this test detects it.
        """

        class _ExplosiveProc:
            """Process that raises if any method is called."""

            @property
            def exitcode(self) -> int | None:
                return None

            def join(self, timeout: object = None) -> None:
                self.fail("_cleanup_processes called join on unstarted proc")

            def is_alive(self) -> bool:
                self.fail("_cleanup_processes called is_alive on unstarted proc")
                return False  # unreachable, satisfies type checker

            def terminate(self) -> None:
                self.fail("_cleanup_processes called terminate on unstarted proc")

            @staticmethod
            def fail(msg: str) -> None:
                raise AssertionError(msg)

        proc = _ExplosiveProc()
        # Should complete without raising
        self._cleanup_processes([
            (proc, False, [], []),
        ])


if __name__ == "__main__":
    unittest.main()
