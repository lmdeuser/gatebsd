"""AmneziaWG, PPPoE, DHCP, DNS, UPS write operations."""
from __future__ import annotations

import base64
import binascii
import fcntl
import ipaddress
import os
import re
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ..command import run
from .. import action_state, backup, paths
from ..fsutil import atomic_symlink, atomic_write_bytes, exclusive_lock, _fsync_directory, read_regular_bytes, read_regular_text
from ..adapters import (
    AMNEZIA_CONFIG, AMNEZIA_CONF_DIR, DHCPD_CONF, UNBOUND_CONF, VPN_IF, WAN_IF,
)

# How long to wait for PPPoE to come back before saying so. Short on purpose:
# the panel's own fetch aborts at 20 s, and an answer that never arrives is a
# worse report than an honest "not confirmed yet".
_PPPOE_VERIFY_SECONDS = float(os.environ.get("GATEBSD_PPPOE_VERIFY_SECONDS", "5") or 5)


def pppoe_link_up(iface: str = WAN_IF) -> bool | None:
    """Does the PPPoE interface carry a negotiated session -- or can't we tell.

    A session is an address *and* a peer (`inet A --> B`): mpd5 creates `ng0`
    and brings it UP before PPP has agreed on anything, so "the interface
    exists" is the state that made `active="restarted"` look true.
    """
    r = run(["ifconfig", iface], timeout=3)
    if not r.ok:
        text = (r.stdout or "") + (r.stderr or "")
        if "does not exist" in text:
            return False
        return None
    return "inet " in r.stdout and "-->" in r.stdout


def mpd5_restart(verify_seconds: float | None = None) -> tuple[int, dict[str, Any]]:
    """Bounce PPPoE and report the link, not the exit code of `service(8)`.

    `service mpd5 restart` returns as soon as the daemon is respawned -- PPPoE
    discovery, PADI/PADO/PADR/PADS and IPCP all happen afterwards. `api.py` used
    to stamp `active="restarted"` onto this reply unconditionally, so the panel
    announced a working uplink at the exact moment there was none.
    """
    r = run(["service", "mpd5", "restart"], timeout=15)
    output = r.stdout + r.stderr
    payload: dict[str, Any] = {"out": output, "output": output, "interface": WAN_IF}
    if not r.ok:
        block = action_state.failed(WAN_IF, "mpd5 failed to restart", action_name="reconnect")
        return 500, action_state.attach(payload, block)

    deadline = time.monotonic() + (_PPPOE_VERIFY_SECONDS if verify_seconds is None else verify_seconds)
    link: bool | None = None
    while True:
        link = pppoe_link_up()
        if link:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(0.5)

    payload["link_up"] = link
    if link:
        block = action_state.done(WAN_IF, f"PPPoE connected, session on {WAN_IF}", action_name="reconnect")
    elif link is None:
        block = action_state.unverified(
            WAN_IF,
            f"mpd5 restarted, failed to read {WAN_IF} state",
            action_name="reconnect",
        )
    else:
        block = action_state.in_progress(
            WAN_IF,
            f"mpd5 restarted, PPPoE still negotiating — no session on {WAN_IF} yet",
            action_name="reconnect",
        )
    return 200, action_state.attach(payload, block)


def gatewayctl(cmd: str) -> tuple[int, dict[str, Any]]:
    """Run gatewayctl <cmd>: apply | down | rollback | reload | status"""
    allowed = {"apply", "down", "rollback", "reload", "status"}
    if cmd not in allowed:
        return 400, {"error": f"unknown command: {cmd}"}
    r = run(["/usr/local/sbin/gatewayctl", cmd], timeout=30)
    return (200 if r.ok else 500), {"ok": r.ok, "output": r.stdout + r.stderr}


_CONF_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SECTION_RE = re.compile(rb"^\s*\[([^\]]+)\]\s*$")
_PEER_HEADER_RE = re.compile(rb"^\s*\[Peer\]\s*$")
_PUBKEY_RE = re.compile(rb"^PublicKey\s*=\s*(.*)$")
_PUBKEY_VALID_RE = re.compile(r"^[A-Za-z0-9+/=]{43,45}$")
_INTERFACE_HEADER_RE = re.compile(rb"^\s*\[Interface\]\s*$")
_PRIVKEY_RE = re.compile(rb"^(\s*PrivateKey\s*=\s*)(.*?)(\s*(?:#.*)?)?$")
_UNSAFE_INTERFACE_DIRECTIVES = {"preup", "postup", "predown", "postdown", "saveconfig"}

# ---------------------------------------------------------------- directives
#
# Directive names accepted by amnezia-tools 3.1 and both data paths. The
# official FreeBSD backend passes the AWG 2.0/3.1 set to amnezia-kmod through
# nvlist, except magic headers at or below 4, which still require amneziawg-go.
#
# There was no allow-list here before, so `ThisKeyDoesNotExist = 42` was
# accepted, and so was any misspelling of a real directive: the profile was
# written, the tunnel came up without the knob, and nothing said a word.
#
# awg-quick consumes these itself; they never reach `awg setconf`.
_QUICK_INTERFACE_DIRECTIVES = {
    "address", "mtu", "dns", "table", "userland",
    "preup", "predown", "postup", "postdown", "saveconfig",
}
# Plain uint16 obfuscation knobs.
_AWG_UINT16_DIRECTIVES = {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4"}
# Magic headers: one number or a range, up to 2^32-1.
_AWG_U32_RANGE_DIRECTIVES = {"h1", "h2", "h3", "h4"}
# Special packets: opaque text, handed to the tools untouched.
_AWG_TEXT_DIRECTIVES = {"i1", "i2", "i3", "i4", "i5"}
# Classic obfuscation normally leaves backend selection to explicit UserLand;
# the measured low-header exception below is the only automatic selection.
_AWG_CLASSIC_DIRECTIVES = _AWG_UINT16_DIRECTIVES | _AWG_U32_RANGE_DIRECTIVES | _AWG_TEXT_DIRECTIVES
# AmneziaWG 2.0 ranges and header protection.
_AWG2_RANGE_DIRECTIVES = {
    "contentpaddingaddition", "rekeyaftertime", "rekeytimeout",
    "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts",
}
_AWG2_DIRECTIVES = _AWG2_RANGE_DIRECTIVES | {"headerprotectionkey"}
# AmneziaWG 3.1 added exactly these two, and both are booleans. The Amnezia
# client writes BOTH lines into every profile it generates for a 3.1 container
# -- unconditionally, defaulting to "on" -- so refusing the names outright
# would refuse every such profile. amnezia-tools before 3.1 does exactly that:
# an unknown key fails the WHOLE file, so `awg-quick up` dies whatever the
# value is. Measured on the router, 2026-08-27.
_AWG31_BOOL_DIRECTIVES = {"randomtrailers", "disablecookies"}
_INTERFACE_DIRECTIVES = (
    _QUICK_INTERFACE_DIRECTIVES
    | _AWG_CLASSIC_DIRECTIVES
    | _AWG2_DIRECTIVES
    | _AWG31_BOOL_DIRECTIVES
    | {"privatekey", "listenport", "fwmark"}
)
_PEER_DIRECTIVES = {
    "publickey", "presharedkey", "allowedips", "endpoint",
    "persistentkeepalive", "advancedsecurity",
}
# u16_range_from_string() bounds against UINT32_MAX even though the value is
# then packed as hi<<16|lo, so anything above 65535 is silently truncated on the
# way in. Accepting it would be accepting a number the box cannot carry.
# amneziawg-go device/uapi.go: HeaderCipherNonceSize.
_HEADER_CIPHER_NONCE_SIZE = 12
_U16_CEILING = 0xFFFF
_U32_CEILING = 0xFFFFFFFF


def _profile_shape(text: str) -> dict[str, str]:
    """What kind of profile this is, and which backend would carry it.

    Every supported obfuscation generation uses the kernel by default, except
    magic headers at or below 4, which amnezia-kmod rejects and therefore moves
    to userspace. Explicit UserLand = true also selects userspace. Reads the same
    tables the validator uses; there is no second list here.
    """
    interface: set[str] = set()
    userland = False
    section = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.strip("[]").lower()
            continue
        if section != "interface" or "=" not in stripped:
            continue
        key, _, raw_value = stripped.partition("=")
        key = key.strip().lower()
        interface.add(key)
        if key == "userland":
            parsed = _config_value(raw_value)
            userland = (parsed or "").strip().lower() == "true"
    if _AWG31_BOOL_DIRECTIVES & interface:
        generation = "3.1"
    elif _AWG2_DIRECTIVES & interface:
        generation = "2.0"
    elif _AWG_CLASSIC_DIRECTIVES & interface:
        generation = "1.5"
    else:
        generation = "wireguard"
    return {"generation": generation, "engine": "userspace" if userland else "kernel"}


def _is_ascii_digits(value: str) -> bool:
    """Decimal digits as C reads them, which is not what str.isdigit() means.

    `str.isdigit()` is true for every Unicode digit: "\u0661\u0662" (Arabic-Indic twelve)
    and "\u00b2" (superscript two) both pass it. Neither is what ends up in the
    profile file, and awg parses that file with strtoul() on bytes -- so a
    value accepted here would be written out and then refused by the box, with
    the panel having said the profile was fine.

    "\u00b2" is worse than wrong: int() raises on it, so the old check crashed the
    request instead of refusing the profile. Found by review, reproduced, 2026-08-27.
    """
    return value.isascii() and value.isdigit()


def _valid_uint_range(value: str, ceiling: int, allow_range: bool) -> bool:
    """One number, or `lo-hi` with lo <= hi, both within the ceiling."""
    parts = value.split("-")
    if len(parts) == 1:
        low = high = parts[0]
    elif len(parts) == 2 and allow_range:
        low, high = parts
    else:
        return False
    if not _is_ascii_digits(low) or not _is_ascii_digits(high):
        return False
    return 0 <= int(low) <= int(high) <= ceiling


def _magic_headers_rejected_by_kernel(interface: dict[str, list[str]]) -> list[str]:
    """amnezia-kmod 3.1 rejects H1..H4 <= 4, including with header protection."""
    rejected = []
    for directive in sorted(_AWG_U32_RANGE_DIRECTIVES):
        for item in interface.get(directive, []):
            low = item.split("-", 1)[0]
            if _is_ascii_digits(low) and int(low) <= 4:
                rejected.append(directive)
                break
    return rejected


_NON_PROFILE_FILENAMES_STATIC = {"gateway.conf", "awg0.conf", "direct-exceptions.conf"}
AWG_TOOL = os.environ.get("GATEBSD_AWG_TOOL", "/usr/local/bin/awg")


def _non_awg_conf_names() -> set[str]:
    names = {"gateway", "direct-exceptions"}
    if paths.DIRECT_EXCEPTIONS.suffix == ".conf" and paths.DIRECT_EXCEPTIONS.stem:
        names.add(paths.DIRECT_EXCEPTIONS.stem)
    return names


def _reserved_profile_names() -> set[str]:
    names = _non_awg_conf_names()
    if AMNEZIA_CONFIG.stem:
        names.add(AMNEZIA_CONFIG.stem)
    return names


def _non_profile_filenames() -> set[str]:
    names = set(_NON_PROFILE_FILENAMES_STATIC)
    if AMNEZIA_CONFIG.name:
        names.add(AMNEZIA_CONFIG.name)
    if paths.DIRECT_EXCEPTIONS.name:
        names.add(paths.DIRECT_EXCEPTIONS.name)
    return names


def _profile_lock_path() -> Path:
    return AMNEZIA_CONF_DIR / ".gatebsd-profiles.lock"


def _active_config_path() -> Path:
    return AMNEZIA_CONFIG


def _valid_conf_name(value: object) -> bool:
    return isinstance(value, str) and _CONF_NAME_RE.fullmatch(value) is not None and value not in _non_awg_conf_names()


def _valid_profile_name(value: object) -> bool:
    return _valid_conf_name(value) and value not in _reserved_profile_names()


def _config_value(raw: str) -> str | None:
    value = raw.strip()
    if not value:
        return ""
    if value.startswith('"'):
        end = value.find('"', 1)
        if end < 0 or value[1:end].find('"') >= 0:
            return None
        tail = value[end + 1:].strip()
        if tail and not tail.startswith("#"):
            return None
        return value[1:end]
    if '"' in value:
        return None
    if " #" in value or "\t#" in value:
        value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
    return value


def _validate_awg_config_text(value: object) -> tuple[bytes | None, str | None]:
    if not isinstance(value, str):
        return None, "config must be a string"
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return None, "config is not valid UTF-8"
    if not encoded or len(encoded) > 1024 * 1024:
        return None, "config must be between 1 byte and 1 MiB"
    if b"\x00" in encoded:
        return None, "config contains NUL byte"

    sections: list[tuple[str, dict[str, list[str]]]] = []
    current_name: str | None = None
    current_values: dict[str, list[str]] | None = None
    # Where each directive was first seen, so an error can point at a line
    # instead of leaving the customer to find the typo.
    first_line: dict[tuple[int, str], int] = {}
    for line_number, line in enumerate(value.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        match = re.fullmatch(r"\[([A-Za-z]+)\]", stripped)
        if match:
            section_name = match.group(1).lower()
            if section_name not in {"interface", "peer"}:
                return None, f"unsupported section [{match.group(1)}] at line {line_number}"
            current_name = section_name
            current_values = {}
            sections.append((current_name, current_values))
            continue
        if current_values is None or "=" not in line:
            return None, f"invalid config line {line_number}"
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key):
            return None, f"invalid directive name at line {line_number}"
        lowered = key.lower()
        known = _INTERFACE_DIRECTIVES if current_name == "interface" else _PEER_DIRECTIVES
        if lowered not in known:
            section_label = "[Interface]" if current_name == "interface" else "[Peer]"
            return None, f"unknown {section_label} directive \"{key}\" at line {line_number}"
        parsed = _config_value(raw_value)
        if parsed is None:
            return None, f"invalid quoting at line {line_number}"
        first_line.setdefault((len(sections) - 1, lowered), line_number)
        current_values.setdefault(lowered, []).append(parsed)

    interfaces = [values for name, values in sections if name == "interface"]
    peers = [values for name, values in sections if name == "peer"]
    if len(interfaces) != 1:
        return None, "config must contain exactly one [Interface] section"
    if not peers:
        return None, "config must contain at least one [Peer] section"

    interface = interfaces[0]
    interface_index = next(index for index, (name, _values) in enumerate(sections) if name == "interface")
    private_keys = interface.get("privatekey", [])
    if len(private_keys) != 1 or not _is_valid_wg_key(private_keys[0]):
        return None, "[Interface] must contain one valid PrivateKey"
    for directive in _UNSAFE_INTERFACE_DIRECTIVES:
        if directive in interface:
            return None, f"unsafe [Interface] directive is not accepted: {directive}"
    if len(interface.get("mtu", [])) > 1:
        return None, "[Interface] contains multiple MTU values"
    if interface.get("mtu"):
        mtu = interface["mtu"][0]
        if not mtu.isdigit() or not 576 <= int(mtu) <= 9000:
            return None, "invalid [Interface] MTU"
    for address_line in interface.get("address", []):
        addresses = [item.strip() for item in address_line.split(",")]
        if not addresses or any(not item for item in addresses):
            return None, "invalid [Interface] Address"
        try:
            for address in addresses:
                ipaddress.ip_interface(address)
        except ValueError:
            return None, "invalid [Interface] Address"
    for dns_line in interface.get("dns", []):
        servers = [item.strip() for item in dns_line.split(",")]
        if not servers or any(not item for item in servers):
            return None, "invalid [Interface] DNS"
        for server in servers:
            try:
                ipaddress.ip_address(server)
            except ValueError:
                if not _valid_hostname(server):
                    return None, "invalid [Interface] DNS"

    # awg-quick tries `ifconfig amn create` first; explicit UserLand = true
    # selects amneziawg-go. The official 3.1 kernel ABI carries every directive
    # below, with the measured low-magic-header exception handled later.
    userland_values = interface.get("userland", [])
    if len(userland_values) > 1:
        return None, "[Interface] contains multiple UserLand values"
    for flag in userland_values:
        # awg-quick's read_bool dies on anything that is not true or false, and
        # it dies before the interface exists.
        if flag.lower() not in {"true", "false"}:
            return None, "invalid [Interface] UserLand: expected true or false"

    # awg's parse_bool takes on/off case-insensitively, or a decimal number
    # where 0 is false. Anything else is refused -- and a value that merely
    # STARTS with a digit makes awg call exit(1) mid-parse, so "1x" has to die
    # here rather than there.
    enabled_31: list[str] = []
    for directive in sorted(_AWG31_BOOL_DIRECTIVES & set(interface)):
        if len(interface[directive]) > 1:
            return None, f"[Interface] contains multiple {directive} values"
        item = interface[directive][0]
        lowered_value = item.lower()
        if lowered_value not in {"on", "off"} and not _is_ascii_digits(item):
            line = first_line.get((interface_index, directive), 0)
            return None, (
                f"invalid [Interface] {directive} at line {line}: expected on, off or a number"
            )
        if lowered_value == "on" or (_is_ascii_digits(item) and int(item) != 0):
            enabled_31.append(directive)

    # RandomTrailers together with junk and range headers loses a quarter of the
    # traffic. Measured 2026-08-27 against the official amneziavpn/amneziawg-go
    # container from the stand, ICMP over 100 packets, against a LAN baseline of
    # 0% loss:
    #
    #     S alone / H alone / RandomTrailers alone      0%
    #     S + H,  S + trailers,  H + trailers           0%
    #     S + H + ContentPaddingAddition                1%   (noise)
    #     S + H + RandomTrailers                       40, 41, 51%
    #     the client's own 3.1 defaults                22, 24, 29%
    #
    # Every pair is clean; only the three together break it. The Amnezia client
    # sets RandomTrailers on by default and puts junk sizes and range headers in
    # the same profile, so a box upgraded to a 3.1 container as issued gets a
    # tunnel that comes up, handshakes, and silently drops a quarter of what
    # crosses it. Refusing is better than that: the customer reads one line here
    # instead of chasing "the internet got slow after the update" for a week.
    #
    # The mechanism is not fully understood -- device/receive.go stops requiring
    # an exact size for handshake packets once trailers are on, which can make a
    # transport packet look like one, but the arithmetic does not account for the
    # whole loss. The rule is empirical and the numbers above are the evidence.
    if "randomtrailers" in enabled_31:
        # S1..S4 only: Jc/Jmin/Jmax govern the junk PACKETS sent before a
        # handshake, and dropping them from the set changed nothing --
        # the full profile without Jc still lost 22%.
        junk_used = sorted({"s1", "s2", "s3", "s4"} & set(interface))
        ranged_headers = sorted(
            directive for directive in _AWG_U32_RANGE_DIRECTIVES & set(interface)
            if any("-" in item for item in interface[directive])
        )
        if junk_used and ranged_headers:
            return None, (
                "[Interface] enables RandomTrailers together with junk sizes "
                f"({', '.join(junk_used)}) and range magic headers ({', '.join(ranged_headers)}); "
                "that combination was measured losing 20-50% of the traffic while the tunnel "
                "still comes up and handshakes. Turn RandomTrailers off in the profile"
            )
    for directive in sorted(_AWG_UINT16_DIRECTIVES & set(interface)):
        for item in interface[directive]:
            if not _valid_uint_range(item, _U16_CEILING, allow_range=False):
                line = first_line.get((interface_index, directive), 0)
                return None, f"invalid [Interface] {directive} at line {line}: expected 0..65535"
    for directive in sorted(_AWG_U32_RANGE_DIRECTIVES & set(interface)):
        for item in interface[directive]:
            if not _valid_uint_range(item, _U32_CEILING, allow_range=True):
                return None, f"invalid [Interface] {directive}: expected N or N-M within 0..4294967295"
    for directive in sorted(_AWG2_RANGE_DIRECTIVES & set(interface)):
        for item in interface[directive]:
            if not _valid_uint_range(item, _U16_CEILING, allow_range=True):
                return None, f"invalid [Interface] {directive}: expected N or N-M within 0..65535"
    for header_key in interface.get("headerprotectionkey", []):
        if not _is_valid_wg_key(header_key):
            return None, "[Interface] contains invalid HeaderProtectionKey"
    # Header protection encrypts the four packet headers with a nonce taken out
    # of the junk that precedes each one, so every junk has to be at least as
    # long as that nonce. amneziawg-go refuses the whole `awg setconf` when it
    # is not -- uapi.go: `if padding < HeaderCipherNonceSize` over
    # [init, response, cookie, transport], which are S1..S4. Measured in the
    # jail rig: with S4 = 7 setconf answers "Invalid argument", with S4 = 12 it
    # is accepted. Two things in the upstream message are wrong and cost time,
    # so they are written down here rather than trusted: it says "S0" for S1
    # (the loop prints the array index), and it says "more then 12" while the
    # comparison admits exactly 12. The Amnezia client keeps its own floor at
    # the same value (junkPacketSizeMin = 12), so a profile it generates passes
    # -- one edited by hand may not.
    if interface.get("headerprotectionkey"):
        for directive in ("s1", "s2", "s3", "s4"):
            values = interface.get(directive, [])
            # EVERY value, not the first: a directive may be repeated, and awg
            # keeps the last one it reads. Checking values[0] let `S1 = 29`
            # followed by `S1 = 0` through -- the profile was written, the box
            # then refused it. Found by review, reproduced, 2026-08-27.
            offending = next(
                (v for v in values if not _is_ascii_digits(v) or int(v) < _HEADER_CIPHER_NONCE_SIZE),
                None,
            )
            if not values or offending is not None:
                return None, (
                    f"[Interface] sets HeaderProtectionKey but {directive} is "
                    f"{offending if values else 'absent'}; every one of S1..S4 must be at least "
                    f"{_HEADER_CIPHER_NONCE_SIZE}, otherwise the junk is shorter than the nonce "
                    "header protection is derived from and amneziawg-go refuses the profile"
                )

    # Measured on the stand against amnezia-kmod 3.1.0 and the official tools:
    # every H1..H4 value at or below WG_PKT_DATA is rejected with EINVAL, even
    # when HeaderProtectionKey is present. Only this shape still needs userspace.
    rejected_headers = _magic_headers_rejected_by_kernel(interface)
    if rejected_headers and userland_values and userland_values[0].lower() == "false":
        return None, (
            f"[Interface] uses magic headers at or below 4 ({', '.join(rejected_headers)}) "
            "together with UserLand = false; amnezia-kmod rejects them even with "
            "HeaderProtectionKey"
        )
    add_userland = bool(rejected_headers) and not userland_values

    if len(interface.get("listenport", [])) > 1:
        return None, "[Interface] contains multiple ListenPort values"
    for port in interface.get("listenport", []):
        if not port.isdigit() or not 0 <= int(port) <= 65535:
            return None, "invalid [Interface] ListenPort"

    seen_public_keys: set[str] = set()
    for index, peer in enumerate(peers, 1):
        public_keys = peer.get("publickey", [])
        if len(public_keys) != 1 or not _is_valid_wg_key(public_keys[0]):
            return None, f"[Peer] #{index} must contain one valid PublicKey"
        if public_keys[0] in seen_public_keys:
            return None, f"[Peer] #{index} duplicates an existing PublicKey"
        seen_public_keys.add(public_keys[0])
        preshared = peer.get("presharedkey", [])
        if len(preshared) > 1 or (preshared and not _is_valid_wg_key(preshared[0])):
            return None, f"[Peer] #{index} contains invalid PresharedKey"
        if len(peer.get("endpoint", [])) > 1:
            return None, f"[Peer] #{index} contains multiple Endpoint values"
        if peer.get("endpoint"):
            _endpoint, error = _validate_endpoint(peer["endpoint"][0])
            if error:
                return None, f"[Peer] #{index}: {error}"
        if len(peer.get("allowedips", [])) > 1:
            return None, f"[Peer] #{index} contains multiple AllowedIPs values"
        if peer.get("allowedips"):
            _allowed, error = _validate_allowed_ips(peer["allowedips"][0])
            if error:
                return None, f"[Peer] #{index}: {error}"
        keepalive = peer.get("persistentkeepalive", [])
        if len(keepalive) > 1:
            return None, f"[Peer] #{index} contains multiple PersistentKeepalive values"
        if keepalive and not _valid_uint_range(keepalive[0], _U16_CEILING, allow_range=True):
            return None, f"[Peer] #{index} contains invalid PersistentKeepalive"
        for flag in peer.get("advancedsecurity", []):
            if flag.lower() not in {"true", "false"}:
                return None, f"[Peer] #{index} contains invalid AdvancedSecurity"

    # Preserve user formatting but ensure the file ends with one newline.
    normalized = value.rstrip("\r\n") + "\n"
    normalized, _notes = _normalize_profile_text(normalized, add_userland)
    return normalized.encode("utf-8"), None


# What the box writes into a profile before it will carry it, and why.
#
# A provider issues a profile for a laptop. This is a router, and three of the
# directives a laptop is happy with are wrong here -- not invalid, wrong for
# this machine. Refusing the profile and telling the operator to edit it is not
# an option a sold box has: "your file is fine, add three lines" is not carrying
# the profile. So the box adjusts it, and says which lines it touched.
_MTU_FALLBACK = 1280


def _normalize_profile_text(text: str, add_userland: bool) -> tuple[str, list[str]]:
    """Return the profile as this box will run it, plus what was changed.

    Deterministic and idempotent: running it on its own output changes nothing
    and reports nothing, which is what lets the validator and the upload path
    both call it and agree.
    """
    notes: list[str] = []
    lines = text.splitlines()
    out: list[str] = []
    section = ""
    seen_table = False
    seen_mtu = False
    interface_at = -1

    for line in lines:
        stripped = line.strip()
        if re.fullmatch(r"\[[A-Za-z]+\]", stripped):
            section = stripped.strip("[]").lower()
            out.append(line)
            if section == "interface":
                interface_at = len(out)
            continue
        if section != "interface" or "=" not in stripped or stripped.startswith(("#", ";")):
            out.append(line)
            continue
        key = stripped.split("=", 1)[0].strip().lower()
        if key == "table":
            seen_table = True
            # gatewayctl owns the default route: it pins the endpoint through
            # the underlay, moves the default only once the tunnel answers, and
            # takes it back on failure. A profile with AllowedIPs = 0.0.0.0/0
            # and no Table makes awg-quick install 0.0.0.0/1 and 128.0.0.0/1
            # itself, so the route has two owners and split routing has three.
            if _config_value(stripped.split("=", 1)[1]) != "off":
                notes.append("Table set to off: default route is managed by gatewayctl")
            out.append("Table = off")
            continue
        if key == "mtu":
            seen_mtu = True
            out.append(line)
            continue
        if key == "dns":
            # awg-quick hands these to `resolvconf -a <if> -x`, and -x makes
            # them exclusive: /etc/resolv.conf stops naming the box's own
            # unbound. Two things break. The LAN keeps working -- clients ask
            # the router, not resolv.conf -- but the router's own lookups leave
            # through the tunnel's provider; and a rollback has to resolve the
            # previous profile's endpoint hostname through a resolver that
            # lives inside the tunnel being torn down.
            notes.append(f"DNS line removed ({_config_value(stripped.split('=', 1)[1])}): gateway uses its own resolver")
            continue
        out.append(line)

    if interface_at < 0:
        return "\n".join(out) + "\n", notes

    inserts: list[str] = []
    if add_userland:
        inserts.append("UserLand = true")
        notes.append("Added UserLand = true: kernel module rejects H1-H4 <= 4")
    if not seen_table:
        inserts.append("Table = off")
        notes.append("Added Table = off: default route is managed by gatewayctl")
    if not seen_mtu:
        # Not a measurement and must not be mistaken for one. awg-quick's own
        # autodiscovery degenerates on this box -- it lowers the MTU only when
        # the underlay is already below 1420, and ng0 is 1492 -- so an absent
        # MTU means the module default, 1420, with 72 bytes of headroom that
        # AmneziaWG 2.0 junk and padding do not fit into. 1280 is what the
        # working profile carries and what this box is known to pass.
        inserts.append(f"MTU = {_MTU_FALLBACK}")
        notes.append(f"Added MTU = {_MTU_FALLBACK}: omitted from profile; fallback value, not measured")
    for offset, item in enumerate(inserts):
        out.insert(interface_at + offset, item)
    return "\n".join(out) + "\n", notes


def _profile_adjustments(text: str) -> list[str]:
    """What _normalize_profile_text would change, for reporting to the operator."""
    interface: dict[str, list[str]] = {}
    section = ""
    for line in text.splitlines():
        stripped = line.strip()
        if re.fullmatch(r"\[[A-Za-z]+\]", stripped):
            section = stripped.strip("[]").lower()
            continue
        if section != "interface" or "=" not in stripped or stripped.startswith(("#", ";")):
            continue
        key = stripped.split("=", 1)[0].strip().lower()
        parsed = _config_value(stripped.split("=", 1)[1])
        interface.setdefault(key, []).append(parsed or "")
    add_userland = bool(_magic_headers_rejected_by_kernel(interface)) and "userland" not in interface
    _text, notes = _normalize_profile_text(text, add_userland)
    return notes


def _valid_hostname(value: str) -> bool:
    if not value or len(value) > 253 or value.startswith(".") or value.endswith(".") or ".." in value:
        return False
    labels = value.rstrip(".").split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) is not None
        for label in labels
    )


def _validate_endpoint(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str):
        return None, "endpoint must be a string"
    endpoint = value.strip()
    if not endpoint:
        return "", None
    if len(endpoint) > 255 or any(ord(ch) < 32 or ord(ch) == 127 for ch in endpoint):
        return None, "invalid endpoint"
    host = ""
    port_text = ""
    if endpoint.startswith("["):
        close = endpoint.find("]")
        if close <= 1 or close + 1 >= len(endpoint) or endpoint[close + 1] != ":":
            return None, "invalid endpoint"
        host = endpoint[1:close]
        port_text = endpoint[close + 2:]
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return None, "invalid endpoint"
    else:
        if endpoint.count(":") != 1:
            return None, "invalid endpoint"
        host, port_text = endpoint.rsplit(":", 1)
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            if not _valid_hostname(host):
                return None, "invalid endpoint"
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        return None, "invalid endpoint port"
    return endpoint, None


def _validate_allowed_ips(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str):
        return None, "allowed_ips must be a string"
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(not part for part in parts) or len(parts) > 64:
        return None, "invalid allowed_ips"
    normalized: list[str] = []
    try:
        for part in parts:
            normalized.append(str(ipaddress.ip_network(part, strict=False)))
    except ValueError:
        return None, "invalid allowed_ips"
    return ", ".join(normalized), None


def _capture_active_config() -> tuple[str, object | None]:
    try:
        if AMNEZIA_CONFIG.is_symlink():
            return "symlink", Path(os.readlink(AMNEZIA_CONFIG))
        if AMNEZIA_CONFIG.exists():
            return "file", (
                AMNEZIA_CONFIG.read_bytes(),
                AMNEZIA_CONFIG.stat(),
            )
    except OSError:
        raise
    return "missing", None


def _restore_active_config(kind: str, payload: object | None) -> None:
    if kind == "symlink":
        assert isinstance(payload, Path)
        atomic_symlink(AMNEZIA_CONFIG, payload)
    elif kind == "file":
        assert isinstance(payload, tuple)
        content, metadata = payload
        atomic_write_bytes(
            AMNEZIA_CONFIG,
            content,
            mode=stat.S_IMODE(metadata.st_mode),
            preserve_metadata=False,
            uid=metadata.st_uid,
            gid=metadata.st_gid,
        )
    else:
        try:
            AMNEZIA_CONFIG.unlink(missing_ok=True)
        except OSError:
            pass


def _regular_profile(path: Path) -> bool:
    try:
        return not path.is_symlink() and path.is_file()
    except OSError:
        return False




def _managed_config_path(conf_name: str) -> tuple[int, Path | None, str | None]:
    """Resolve a managed config without ever replacing an active-profile symlink.

    Ordinary profile symlinks are rejected.  The canonical awg0.conf link is
    allowed only when it resolves to a regular *.conf file inside the managed
    Amnezia directory.
    """
    candidate = AMNEZIA_CONF_DIR / f"{conf_name}.conf"
    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        return 404, None, f"{conf_name}.conf not found"
    except OSError:
        return 500, None, "failed to inspect config"

    if stat.S_ISLNK(metadata.st_mode):
        if candidate.name != _active_config_path().name:
            return 409, None, "refusing symlink config"
        try:
            root = candidate.parent.resolve(strict=True)
            target = candidate.resolve(strict=True)
            target_meta = target.lstat()
        except (OSError, RuntimeError):
            return 409, None, "invalid active profile symlink"
        if target.parent != root or target.suffix != ".conf" or not stat.S_ISREG(target_meta.st_mode):
            return 409, None, "active profile points outside the managed config directory"
        return 200, target, None

    if not stat.S_ISREG(metadata.st_mode):
        return 409, None, "config is not a regular file"
    return 200, candidate, None

@contextmanager
def _locked_managed_config(conf_name: str) -> Iterator[tuple[int, Path | None, str | None]]:
    """Keep profile selection stable for the complete read-modify-write cycle."""
    with exclusive_lock(_profile_lock_path()):
        status, path, error = _managed_config_path(conf_name)
        if path is None:
            yield status, None, error
            return
        with exclusive_lock(path.with_suffix(path.suffix + ".lock")):
            status2, current, error2 = _managed_config_path(conf_name)
            if current is None:
                yield status2, None, error2
                return
            if current != path:
                yield 409, None, "active profile changed while waiting for lock"
                return
            yield 200, path, None


def _profile_is_active(path: Path) -> bool:
    try:
        active = _active_config_path()
        if not (active.is_symlink() or active.is_file()):
            return False
        return active.resolve(strict=True) == path.resolve(strict=True)
    except (OSError, RuntimeError):
        return False


def _sync_running_interface(conf_path: Path) -> dict[str, Any]:
    """Reload the kernel peer set from a just-edited active profile.

    Writing the file alone leaves the running tunnel unchanged, so a removed
    peer keeps working and a newly added one cannot connect -- until the next
    reboot or service restart, at which point the behaviour changes with no
    operator action. Reporting success for an edit that has not taken effect is
    worse than failing, because on a router whose VPN is the only uplink an
    operator will trust the confirmation and stop investigating.

    ``awg syncconf`` applies the peer set without tearing the interface down, so
    an existing handshake survives. Returns a structured result; the caller
    surfaces it rather than failing the write, which has already succeeded.
    """
    if not _profile_is_active(conf_path):
        return {"applied": False, "reason": "profile is not active"}
    interface = _active_config_path().stem
    stripped = run(
        ["/usr/local/bin/awg-quick", "strip", interface],
        timeout=10,
        env={"AWG_QUICK_CONFIG_SEARCH_PATHS": str(AMNEZIA_CONF_DIR)},
    )
    if not stripped.ok:
        return {
            "applied": False,
            "reason": "awg-quick strip failed",
            "detail": (stripped.stderr or stripped.error or "")[:300],
        }
    fd = -1
    candidate: str | None = None
    try:
        fd, candidate = tempfile.mkstemp(dir=str(AMNEZIA_CONF_DIR), prefix=".gatebsd-sync.", suffix=".conf")
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            stream.write(stripped.stdout)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(candidate, 0o600)
        synced = run([AWG_TOOL, "syncconf", interface, candidate], timeout=15)
        if synced.ok:
            return {"applied": True}
        return {
            "applied": False,
            "reason": "awg syncconf failed",
            "detail": (synced.stderr or synced.stdout or synced.error or "")[:300],
        }
    except OSError as exc:
        return {"applied": False, "reason": f"cannot stage stripped config: {exc}"}
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if candidate:
            try:
                Path(candidate).unlink(missing_ok=True)
            except OSError:
                pass


_GATEWAY_ASSIGN_RE = re.compile(r"^(\s*)(VPN_ENDPOINT_HOST|VPN_ENDPOINT_PORT)(\s*=\s*).*$")


def _gateway_conf_path() -> Path:
    # Resolved on call, like the other managed paths in this module, so the
    # regression harness can point the whole set at a temporary directory.
    return AMNEZIA_CONF_DIR / "gateway.conf"


def _profile_endpoint(text: str) -> tuple[str, str] | None:
    """Return (host, port) of the first [Peer] Endpoint in a profile."""
    in_peer = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = re.fullmatch(r"\[([A-Za-z]+)\]", stripped)
        if match:
            in_peer = match.group(1).lower() == "peer"
            continue
        if not in_peer or "=" not in stripped:
            continue
        key, raw_value = stripped.split("=", 1)
        if key.strip().lower() != "endpoint":
            continue
        value = _config_value(raw_value)
        if value is None:
            return None
        endpoint, error = _validate_endpoint(value)
        if error or not endpoint:
            return None
        host, _sep, port = endpoint.rpartition(":")
        return host.strip("[]"), port
    return None


def _read_gateway_endpoint() -> tuple[str, str] | None:
    """Current VPN_ENDPOINT_HOST/PORT as gatewayctl would source them."""
    try:
        text, _metadata = read_regular_text(_gateway_conf_path(), max_size=1024 * 1024)
    except OSError:
        return None
    found: dict[str, str] = {}
    for line in text.splitlines():
        match = _GATEWAY_ASSIGN_RE.fullmatch(line)
        if not match:
            continue
        value = _config_value(line.split("=", 1)[1])
        if value is not None:
            found[match.group(2)] = value.strip('"')
    if "VPN_ENDPOINT_HOST" not in found:
        return None
    return found["VPN_ENDPOINT_HOST"], found.get("VPN_ENDPOINT_PORT", "")


def _write_gateway_endpoint(host: str, port: str) -> bool:
    """Point gateway.conf at `host:port`, leaving every other line untouched.

    The endpoint lives in two places that nothing kept in step: the [Peer]
    Endpoint of the active profile, which is what the tunnel dials, and
    VPN_ENDPOINT_HOST in gateway.conf, which is the only thing gatebsd-route-op
    consults when it pins a host route for the endpoint through the WAN.
    Activating a profile changed the first and not the second, so the pin stayed on
    the previous server: the new endpoint had no route of its own, followed the
    default into the tunnel it was trying to establish, and never handshook.
    """
    try:
        text, metadata = read_regular_text(_gateway_conf_path(), max_size=1024 * 1024)
    except OSError:
        return False
    replacements = {"VPN_ENDPOINT_HOST": host, "VPN_ENDPOINT_PORT": port}
    seen: set[str] = set()
    rebuilt: list[str] = []
    for line in text.splitlines():
        match = _GATEWAY_ASSIGN_RE.fullmatch(line)
        if match and match.group(2) in replacements:
            name = match.group(2)
            seen.add(name)
            rebuilt.append(f'{match.group(1)}{name}{match.group(3)}"{replacements[name]}"')
        else:
            rebuilt.append(line)
    for name, value in replacements.items():
        if name not in seen and value:
            rebuilt.append(f'{name}="{value}"')
    try:
        atomic_write_bytes(
            _gateway_conf_path(),
            ("\n".join(rebuilt).rstrip("\n") + "\n").encode("utf-8"),
            mode=stat.S_IMODE(metadata.st_mode),
            preserve_metadata=True,
        )
    except (OSError, ValueError):
        return False
    return True


def _running_peer_keys(interface: str) -> set[str] | None:
    """Peer public keys the kernel interface is actually configured with."""
    result = run([AWG_TOOL, "show", interface, "peers"], timeout=5)
    if not result.ok:
        return None
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _profile_peer_keys(text: str) -> set[str]:
    keys: set[str] = set()
    in_peer = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = re.fullmatch(r"\[([A-Za-z]+)\]", stripped)
        if match:
            in_peer = match.group(1).lower() == "peer"
            continue
        if not in_peer or "=" not in stripped:
            continue
        key, raw_value = stripped.split("=", 1)
        if key.strip().lower() != "publickey":
            continue
        value = _config_value(raw_value)
        if value:
            keys.add(value)
    return keys


def _runtime_adopted_profile(profile_text: str) -> tuple[bool, str]:
    """Did the live interface actually take the profile we just selected?

    `service amnezia restart` is not evidence. Its rc script iterates
    $amnezia_interfaces and does nothing when the rcvar is off -- rc.subr then
    prints "Cannot 'restart' amnezia ... use 'onerestart' instead" and exits 0,
    so a completely absent restart is indistinguishable from a successful one by
    return code alone. Measured on the rig: activation reported all three steps
    OK while the kernel kept serving the previous server's peer, and the
    divergence would only have surfaced at the next reboot -- by which time the
    change looks like the upgrade's fault. Compare the peer set instead, which
    is a fact about the running interface rather than a claim about a script.
    """
    wanted = _profile_peer_keys(profile_text)
    if not wanted:
        return False, "profile declares no peer to verify against"
    interface = _active_config_path().stem
    running = _running_peer_keys(interface)
    if running is None:
        return False, f"cannot read the running state of {interface}"
    missing = wanted - running
    if missing:
        return False, f"{interface} is not serving the selected profile's peer set"
    return True, ""


def _restore_disabled_marker(previously_present: bool) -> None:
    if previously_present:
        atomic_write_bytes(
            paths.VPN_DISABLED,
            b"",
            mode=0o640,
            preserve_metadata=paths.VPN_DISABLED.exists(),
        )
    else:
        paths.VPN_DISABLED.unlink(missing_ok=True)


def _stop_active_interface() -> None:
    """Take the tunnel down so the next apply has to build it from the profile.

    Deliberately not `service amnezia restart`. That rc script iterates
    $amnezia_interfaces and is a no-op when the rcvar is off -- and rc.subr then
    exits 0, so the absence of a restart is invisible to the caller. Worse, a
    tunnel left standing makes `gatewayctl apply` report success without doing
    anything: ensure_awg sees "awg0 already up" and the handshake gate is then
    satisfied by the very tunnel the operator asked to replace.

    Tearing it down first removes both problems at once and needs no rcvar: the
    interface can only come back through apply, reading the profile that is
    active now, and the gate judges that tunnel and no other. A missing
    interface is not an error -- the VPN may legitimately be stopped.
    """
    run(
        ["/usr/local/bin/awg-quick", "down", _active_config_path().stem],
        timeout=20,
        env={"AWG_QUICK_CONFIG_SEARCH_PATHS": str(AMNEZIA_CONF_DIR)},
    )


# gatewayctl says exactly why it refused -- "no VPN handshake", "internet health
# check failed", "endpoint routing failed" -- and none of it used to leave this
# function. The operator saw `"rebuild tunnel": false` and had to reproduce the
# apply by hand to learn anything, which on a device whose only uplink is the
# tunnel is the worst possible time to be guessing. Bounded because the log
# carries awg-quick's command echo and can run long; the tail is the part that
# says what went wrong.
_DIAGNOSTIC_TAIL = 2000


def _diagnostic_output(result: Any) -> str:
    text = "\n".join(part for part in (getattr(result, "stdout", ""),
                                       getattr(result, "stderr", "")) if part).strip()
    if len(text) > _DIAGNOSTIC_TAIL:
        return "...\n" + text[-_DIAGNOSTIC_TAIL:]
    return text


def _restart_active_runtime() -> Any:
    """Rebuild the tunnel from the active profile and commit routing to it.

    One call, not two. Tearing the tunnel down here and then asking gatewayctl
    to apply left a gap that belonged to nobody: `awg-quick down` takes no
    gateway lock, and by then the active symlink already pointed at the new
    profile with the disabled marker cleared. The watchdog wakes every 10s, saw
    "the VPN is wanted and the default route is not on it", took the lock first
    and applied the new profile itself -- after which the apply below found
    `awg0 already up` and its verification gate judged a tunnel this switch had
    not built.

    `gatewayctl rebuild` does the teardown and the apply under the single lock
    gatewayctl already takes for a whole operation.
    """
    # gatewayctl waits for endpoint resolution and then for a handshake before
    # it will move the default route, so this is minutes-scale work in the worst
    # case, not seconds.
    return run(["/usr/local/sbin/gatewayctl", "rebuild"], timeout=90)


def awg_set_config(conf_name: str, conf_text: str) -> tuple[int, dict[str, Any]]:
    if not _valid_profile_name(conf_name):
        return 400, {"error": "invalid or reserved profile name"}
    content, error = _validate_awg_config_text(conf_text)
    if error is not None or content is None:
        return 400, {"error": error or "invalid config"}
    # The stored profile is not always the file the operator handed over, and
    # they are entitled to know which lines the box changed and why. Silently
    # rewriting somebody's configuration is how a device stops being explicable.
    adjustments = _profile_adjustments(conf_text)

    destination = AMNEZIA_CONF_DIR / f"{conf_name}.conf"
    try:
        AMNEZIA_CONF_DIR.mkdir(parents=True, exist_ok=True)
        with exclusive_lock(_profile_lock_path()):
            if destination.is_symlink():
                return 409, {"error": "refusing symlink profile"}
            existing = destination.is_file()
            backup_meta = backup.backup_files(
                [destination] if existing else [],
                reason="awg-set-config",
            )
            atomic_write_bytes(destination, content, mode=0o600, preserve_metadata=existing)
    except OSError as exc:
        return 500, {"error": f"failed to write config: {exc}"}
    return 200, {"ok": True, "path": str(destination), "backup": backup_meta,
                 "adjustments": adjustments}


def awg_activate(conf_name: str) -> tuple[int, dict[str, Any]]:
    if not _valid_profile_name(conf_name):
        return 400, {"error": "invalid or reserved profile name"}
    source = AMNEZIA_CONF_DIR / f"{conf_name}.conf"
    if not _regular_profile(source):
        return 404, {"error": f"{conf_name}.conf not found"}

    steps: list[dict[str, Any]] = []
    try:
        with exclusive_lock(_profile_lock_path()):
            if not _regular_profile(source):
                return 404, {"error": f"{conf_name}.conf not found"}
            try:
                source_text = source.read_text(encoding="utf-8", errors="strict")
            except (OSError, UnicodeError) as exc:
                return 400, {"error": f"profile cannot be read safely: {exc}"}
            _validated, validation_error = _validate_awg_config_text(source_text)
            if validation_error is not None:
                return 400, {"error": f"invalid profile: {validation_error}"}
            previous_kind, previous_payload = _capture_active_config()
            marker_was_present = paths.VPN_DISABLED.exists()
            backup_meta = backup.backup_known_configs(reason="awg-activate")
            atomic_symlink(AMNEZIA_CONFIG, source)
            steps.append({"stage": "select profile", "ok": True})
            try:
                paths.VPN_DISABLED.unlink(missing_ok=True)
            except OSError as exc:
                _restore_active_config(previous_kind, previous_payload)
                return 500, {
                    "ok": False,
                    "error": f"failed to clear VPN disabled state: {exc}",
                    "steps": steps,
                    "backup": backup_meta,
                }

            # gatewayctl pins the endpoint from gateway.conf, so it has to be
            # pointing at the new server *before* apply runs, not after.
            previous_endpoint = _read_gateway_endpoint()
            wanted_endpoint = _profile_endpoint(source_text)
            endpoint_synced = True
            if wanted_endpoint is not None and wanted_endpoint != previous_endpoint:
                endpoint_synced = _write_gateway_endpoint(*wanted_endpoint)
                steps.append({"stage": "sync endpoint", "ok": endpoint_synced})

            route_result = _restart_active_runtime()
            adopted, adoption_error = _runtime_adopted_profile(source_text)
            steps.extend([
                {"stage": "rebuild tunnel", "ok": route_result.ok},
                {"stage": "verify runtime", "ok": adopted},
            ])
            if not endpoint_synced or not route_result.ok or not adopted:
                rollback_errors: list[str] = []
                try:
                    _restore_active_config(previous_kind, previous_payload)
                except OSError as exc:
                    rollback_errors.append(f"profile: {exc}")
                # The endpoint has to go back with the profile. Leaving it on the
                # rejected server would pin a host route for a machine this
                # device is no longer talking to, which is the same split state
                # the sync exists to prevent -- only harder to see, because the
                # profile on disk would look correct.
                if wanted_endpoint is not None and previous_endpoint is not None:
                    if not _write_gateway_endpoint(*previous_endpoint):
                        rollback_errors.append("endpoint: gateway.conf not restored")
                try:
                    _restore_disabled_marker(marker_was_present)
                except OSError as exc:
                    rollback_errors.append(f"marker: {exc}")
                rollback_routes = _restart_active_runtime()
                steps.append({"stage": "rollback tunnel", "ok": rollback_routes.ok})
                if not rollback_routes.ok:
                    rollback_errors.append("tunnel restore failed")
                payload: dict[str, Any] = {
                    "ok": False,
                    "error": "failed to activate profile; rollback attempted",
                    "rolled_back": not rollback_errors,
                    "steps": steps,
                    "backup": backup_meta,
                }
                if not adopted and adoption_error:
                    payload["detail"] = adoption_error
                _diagnostics = _diagnostic_output(route_result)
                if _diagnostics:
                    payload["output"] = _diagnostics
                _rollback_diagnostics = _diagnostic_output(rollback_routes)
                if not rollback_routes.ok and _rollback_diagnostics:
                    payload["rollback_output"] = _rollback_diagnostics
                if rollback_errors:
                    payload["rollback_errors"] = rollback_errors
                return 500, payload

            return 200, {
                "ok": True,
                "active": True,
                "steps": steps,
                "backup": backup_meta,
            }
    except OSError as exc:
        return 500, {"ok": False, "error": f"failed to activate profile: {exc}", "steps": steps}


def awg_stop() -> tuple[int, dict[str, Any]]:
    """Stop AWG and restore WAN routing, recording the user's choice."""
    try:
        atomic_write_bytes(
            paths.VPN_DISABLED,
            b"",
            mode=0o640,
            preserve_metadata=paths.VPN_DISABLED.exists(),
        )
    except OSError as exc:
        return 500, {"error": f"failed to persist VPN disabled state: {exc}"}
    service_result = run(["service", "amnezia", "stop"], timeout=15)
    route_result = run(["/usr/local/sbin/gatewayctl", "down"], timeout=15)
    steps = [
        {"stage": "stop service", "ok": service_result.ok},
        {"stage": "restore wan routes", "ok": route_result.ok},
    ]
    ok = service_result.ok and route_result.ok
    return (200 if ok else 500), {
        "ok": ok,
        "active": False if ok else None,
        "interface": "awg0",
        "steps": steps,
    }


def awg_delete_profile(conf_name: str) -> tuple[int, dict[str, Any]]:
    """Delete an inactive profile after creating a backup.

    Active profiles are intentionally not deleted: switching first keeps the
    runtime and the on-disk active symlink in a well-defined state.
    """
    if not _valid_profile_name(conf_name):
        return 400, {"error": "invalid or reserved profile name"}
    source = AMNEZIA_CONF_DIR / f"{conf_name}.conf"
    if not _regular_profile(source):
        return 404, {"error": f"{conf_name}.conf not found"}

    try:
        with exclusive_lock(_profile_lock_path()):
            if not _regular_profile(source):
                return 404, {"error": f"{conf_name}.conf not found"}
            try:
                active = (
                    AMNEZIA_CONFIG.is_symlink()
                    and AMNEZIA_CONFIG.resolve(strict=True) == source.resolve(strict=True)
                )
            except (OSError, RuntimeError) as exc:
                return 500, {"error": f"failed to inspect active profile: {exc}"}
            if active:
                return 409, {"error": "active profile cannot be deleted; switch to another profile first"}
            backup_meta = backup.backup_files([source], reason="awg-delete-profile")
            source.unlink()
            _fsync_directory(source.parent)
            return 200, {
                "ok": True,
                "profile": conf_name,
                "was_active": False,
                "backup": backup_meta,
            }
    except OSError as exc:
        return 500, {"error": f"failed to delete profile: {exc}"}


def awg_profiles() -> dict[str, Any]:
    """Return profile metadata without exposing private configuration content."""
    profiles: list[dict[str, Any]] = []
    active_path: Path | None = None
    try:
        if AMNEZIA_CONFIG.is_symlink():
            active_path = AMNEZIA_CONFIG.resolve(strict=False)
        elif AMNEZIA_CONFIG.is_file():
            active_path = AMNEZIA_CONFIG.resolve(strict=False)
    except (OSError, RuntimeError):
        active_path = None

    try:
        entries = sorted(AMNEZIA_CONF_DIR.glob("*.conf")) if AMNEZIA_CONF_DIR.is_dir() else []
    except OSError:
        entries = []
    non_profiles = _non_profile_filenames()
    for path in entries:
        if path == AMNEZIA_CONFIG or path == paths.DIRECT_EXCEPTIONS or path.name in non_profiles:
            continue
        if not _regular_profile(path):
            continue
        valid = False
        error = ""
        size = 0
        updated = 0
        shape = {"generation": "", "engine": ""}
        try:
            metadata = path.stat()
            size = metadata.st_size
            updated = int(metadata.st_mtime)
            text = path.read_text(encoding="utf-8", errors="strict")
            _content, error_value = _validate_awg_config_text(text)
            valid = error_value is None
            error = error_value or ""
            shape = _profile_shape(text)
            resolved = path.resolve(strict=True)
        except (OSError, UnicodeError, RuntimeError) as exc:
            resolved = path
            error = str(exc)
            shape = {"generation": "", "engine": ""}
        profiles.append({
            "id": path.stem,
            "name": path.stem,
            "path": str(path),
            "active": active_path is not None and resolved == active_path,
            "valid": valid,
            "error": error,
            "size": size,
            "updated": updated,
            "generation": shape["generation"],
            "engine": shape["engine"],
        })
    active = next((item["id"] for item in profiles if item["active"]), "")
    return {"profiles": profiles, "active": active}


def awg_peer_list(conf_name: str) -> tuple[int, dict[str, Any]]:
    """List peer sections from a regular profile or the active awg0 symlink."""
    if not _valid_conf_name(conf_name):
        return 400, {"error": "invalid config name"}
    status, conf_path, error = _managed_config_path(conf_name)
    if conf_path is None:
        return status, {"error": error or "config unavailable"}
    try:
        raw, _metadata = read_regular_bytes(conf_path, max_size=1024 * 1024)
    except FileNotFoundError:
        return 404, {"error": f"{conf_name}.conf not found"}
    except OSError as exc:
        return 409, {"error": f"failed to read config: {exc}"}

    peers: list[dict[str, Any]] = []
    current_peer: dict[str, Any] | None = None
    for raw_line in raw.splitlines():
        stripped = raw_line.strip()
        section_match = _SECTION_RE.fullmatch(stripped)
        if section_match:
            if current_peer is not None:
                peers.append(current_peer)
            current_peer = {} if section_match.group(1).strip().lower() == b"peer" else None
            continue
        if current_peer is None or b"=" not in stripped or stripped.startswith((b"#", b";")):
            continue
        key, value = stripped.split(b"=", 1)
        try:
            key_text = key.decode("ascii", errors="strict").strip()
            value_text = value.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            continue
        normalized = _normalize_pubkey_value(value_text)
        current_peer[key_text] = normalized if normalized is not None else value_text
    if current_peer is not None:
        peers.append(current_peer)

    live: dict[str, str] = {}
    interface_name = _active_config_path().stem
    if conf_name == interface_name or _profile_is_active(conf_path):
        result = run([AWG_TOOL, "show", interface_name, "latest-handshakes"], timeout=5)
        if result.ok:
            for line in result.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    live[parts[0]] = parts[1]
    for peer in peers:
        has_psk = any(k.lower() == "presharedkey" and bool(peer[k]) for k in peer)
        for secret_key in [k for k in peer if k.lower() in {"presharedkey", "privatekey"}]:
            peer.pop(secret_key, None)
        peer["has_preshared_key"] = has_psk
        public_key = str(peer.get("PublicKey", ""))
        raw_age = live.get(public_key, "0")
        age = int(raw_age) if raw_age.isdigit() else 0
        peer["handshake_age_s"] = age
        peer["handshake_fresh"] = 0 < age < 180
    return 200, {"peers": peers, "count": len(peers), "config": str(conf_path)}


def _append_peer_bytes(raw: bytes, block: bytes) -> bytes:
    """Append a peer without normalising or decoding existing config bytes."""
    if not raw:
        return block
    if raw.endswith(b"\r\n\r\n") or raw.endswith(b"\n\n"):
        return raw + block
    if raw.endswith(b"\r\n") or raw.endswith(b"\n"):
        return raw + b"\n" + block
    return raw + b"\n\n" + block


def awg_peer_add(conf_name: str, peer_pubkey: str, endpoint: str = "",
                 allowed_ips: str = "0.0.0.0/0",
                 preshared_key: str = "") -> tuple[int, dict[str, Any]]:
    """Add one validated peer using a bytes-preserving atomic update."""
    if not _valid_conf_name(conf_name):
        return 400, {"error": "invalid config name"}
    # A real WireGuard/AmneziaWG key is exactly 44 base64 characters decoding to
    # 32 bytes. The former 43-45 character pattern accepted truncated and
    # re-wrapped keys, which were written to the live config and only rejected
    # later by awg-quick -- so the tunnel silently failed to come up on the next
    # service restart rather than at the point of the mistake.
    if not _is_valid_wg_key(peer_pubkey):
        return 400, {"error": "invalid peer public key"}
    endpoint_value, endpoint_error = _validate_endpoint(endpoint)
    if endpoint_error:
        return 400, {"error": endpoint_error}
    allowed_value, allowed_error = _validate_allowed_ips(allowed_ips)
    if allowed_error or allowed_value is None:
        return 400, {"error": allowed_error or "invalid allowed_ips"}
    if preshared_key and not _is_valid_wg_key(preshared_key):
        return 400, {"error": "invalid preshared key"}

    conf_path: Path | None = None
    try:
        with _locked_managed_config(conf_name) as (status, conf_path, error):
            if conf_path is None:
                return status, {"error": error or "config unavailable"}
            try:
                raw = conf_path.read_bytes()
            except OSError:
                return 500, {"error": "failed to read config"}
            in_peer = False
            for line in raw.splitlines():
                stripped = line.strip()
                section = _SECTION_RE.fullmatch(stripped)
                if section:
                    in_peer = section.group(1).strip().lower() == b"peer"
                    continue
                if not in_peer:
                    continue
                match = _PUBKEY_RE.match(stripped)
                if not match:
                    continue
                try:
                    raw_value = match.group(1).decode("ascii", errors="strict")
                except UnicodeDecodeError:
                    return 409, {"error": "invalid PublicKey encoding in config"}
                if _normalize_pubkey_value(raw_value) == peer_pubkey:
                    return 409, {"error": "peer already exists in config"}

            lines = [b"[Peer]", f"PublicKey = {peer_pubkey}".encode("ascii"),
                     f"AllowedIPs = {allowed_value}".encode("ascii")]
            if endpoint_value:
                lines.append(f"Endpoint = {endpoint_value}".encode("ascii"))
            if preshared_key:
                lines.append(f"PresharedKey = {preshared_key}".encode("ascii"))
            block = b"\n".join(lines) + b"\n"
            try:
                backup_meta = backup.backup_files([conf_path], reason="awg-peer-add")
            except OSError:
                return 500, {"error": "failed to back up config"}
            try:
                atomic_write_bytes(
                    conf_path,
                    _append_peer_bytes(raw, block),
                    mode=0o600,
                    preserve_metadata=True,
                )
            except (OSError, ValueError):
                return 500, {"error": "failed to write config"}
    except OSError:
        return 500, {"error": "failed to lock config"}
    reload_result = _sync_running_interface(conf_path)
    return 200, {
        "ok": True,
        "path": str(conf_path),
        "backup": backup_meta,
        "reload": reload_result,
        # Explicit so the UI can tell the operator the edit is on disk but not
        # yet in effect, instead of implying it is live.
        "reload_required": not reload_result.get("applied", False),
    }


def _normalize_pubkey_value(raw: str) -> str | None:
    """Return stripped key value if quotes are balanced, else None."""
    val = raw.strip()
    if not val:
        return None
    if val[0] == '"':
        if len(val) < 2 or val[-1] != '"':
            return None
        inner = val[1:-1]
        if '"' in inner:
            return None
        return inner
    if '"' in val:
        return None
    return val


def awg_peer_remove(conf_name: str, peer_pubkey: str) -> tuple[int, dict[str, Any]]:
    """Remove exactly one unambiguous peer with a bytes-preserving update."""
    if not _valid_conf_name(conf_name):
        return 400, {"error": "invalid config name"}
    # Deliberately lenient: a peer written before the strict check existed must
    # remain removable, so removal only requires the key to be well-formed
    # enough to match unambiguously.
    if not isinstance(peer_pubkey, str) or not _PUBKEY_VALID_RE.fullmatch(peer_pubkey):
        return 400, {"error": "invalid peer public key"}
    conf_path: Path | None = None
    try:
        with _locked_managed_config(conf_name) as (status, conf_path, error):
            if conf_path is None:
                return status, {"error": error or "config unavailable"}
            try:
                raw = conf_path.read_bytes()
            except OSError:
                return 500, {"error": "failed to read config"}
            lines = raw.splitlines(keepends=True)
            preamble: list[bytes] = []
            sections: list[tuple[bytes, list[bytes]]] = []
            header: bytes | None = None
            body: list[bytes] = []
            for line in lines:
                if _SECTION_RE.fullmatch(line.rstrip(b"\r\n")):
                    if header is not None:
                        sections.append((header, body))
                    header, body = line, []
                elif header is None:
                    preamble.append(line)
                else:
                    body.append(line)
            if header is not None:
                sections.append((header, body))

            target: int | None = None
            for index, (section_header, section_body) in enumerate(sections):
                match_header = _SECTION_RE.fullmatch(section_header.rstrip(b"\r\n"))
                if not match_header or match_header.group(1).strip().lower() != b"peer":
                    continue
                keys: list[str] = []
                for line in section_body:
                    match = _PUBKEY_RE.match(line.strip())
                    if not match:
                        continue
                    try:
                        value = match.group(1).decode("ascii", errors="strict")
                    except UnicodeDecodeError:
                        return 409, {"error": "invalid PublicKey encoding in config"}
                    normalized = _normalize_pubkey_value(value)
                    if normalized is None:
                        return 409, {"error": "ambiguous PublicKey quoting in section"}
                    keys.append(normalized)
                if len(keys) > 1:
                    return 409, {"error": "ambiguous PublicKey in section"}
                if keys and keys[0] == peer_pubkey:
                    if target is not None:
                        return 409, {"error": "duplicate PublicKey in config"}
                    target = index
            if target is None:
                return 404, {"error": "peer not found in config"}
            try:
                backup_meta = backup.backup_files([conf_path], reason="awg-peer-remove")
            except OSError:
                return 500, {"error": "failed to back up config"}
            rebuilt = list(preamble)
            for index, (section_header, section_body) in enumerate(sections):
                if index != target:
                    rebuilt.append(section_header)
                    rebuilt.extend(section_body)
            try:
                atomic_write_bytes(
                    conf_path,
                    b"".join(rebuilt),
                    mode=0o600,
                    preserve_metadata=True,
                )
            except (OSError, ValueError):
                return 500, {"error": "failed to write config"}
    except OSError:
        return 500, {"error": "failed to lock config"}
    # Without this the removed peer keeps its handshake and keeps working until
    # the next reboot, while the UI shows it as gone.
    reload_result = _sync_running_interface(conf_path)
    return 200, {
        "ok": True,
        "backup": backup_meta,
        "path": str(conf_path),
        "reload": reload_result,
        "reload_required": not reload_result.get("applied", False),
    }


def _is_valid_wg_key(value: object) -> bool:
    """Return True for a canonical 32-byte WireGuard/AmneziaWG key."""
    if not isinstance(value, str) or len(value) != 44:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(decoded) == 32 and base64.b64encode(decoded).decode("ascii") == value


def awg_key_rotate(conf_name: str) -> tuple[int, dict[str, Any]]:
    """Rotate the interface key in a regular profile or active awg0 symlink."""
    if not _valid_conf_name(conf_name):
        return 400, {"error": "invalid config name"}
    private_result = run([AWG_TOOL, "genkey"], timeout=5)
    if not private_result.ok:
        return 500, {"error": "failed to generate private key"}
    private_key = private_result.stdout
    if not _is_valid_wg_key(private_key):
        return 500, {"error": "awg genkey returned invalid private key"}
    public_result = run([AWG_TOOL, "pubkey"], timeout=5, input=private_key)
    if not public_result.ok:
        return 500, {"error": "failed to derive public key"}
    public_key = public_result.stdout
    if not _is_valid_wg_key(public_key):
        return 500, {"error": "awg pubkey returned invalid public key"}

    conf_path: Path | None = None
    try:
        with _locked_managed_config(conf_name) as (status, conf_path, error):
            if conf_path is None:
                return status, {"error": error or "config unavailable"}
            try:
                raw = conf_path.read_bytes()
            except OSError:
                return 500, {"error": "failed to read config"}
            lines = raw.splitlines(keepends=True)
            in_interface = False
            interface_count = 0
            key_indices: list[int] = []
            for index, line in enumerate(lines):
                section = _SECTION_RE.fullmatch(line.rstrip(b"\r\n"))
                if section:
                    in_interface = section.group(1).strip().lower() == b"interface"
                    if in_interface:
                        interface_count += 1
                    continue
                if in_interface and _PRIVKEY_RE.fullmatch(line.rstrip(b"\r\n")):
                    key_indices.append(index)
            if interface_count != 1:
                return 409, {"error": "config must contain exactly one [Interface] section"}
            if len(key_indices) != 1:
                return 409, {"error": "[Interface] must contain exactly one PrivateKey"}

            key_index = key_indices[0]
            old_line = lines[key_index]
            ending = b"\r\n" if old_line.endswith(b"\r\n") else (b"\n" if old_line.endswith(b"\n") else b"")
            match = _PRIVKEY_RE.fullmatch(old_line.rstrip(b"\r\n"))
            if match is None:
                return 409, {"error": "ambiguous PrivateKey directive"}
            raw_value = match.group(2)
            quote_count = raw_value.count(b'"')
            if quote_count == 0:
                replacement = private_key.encode("ascii")
            elif quote_count == 2 and raw_value.startswith(b'"') and raw_value.endswith(b'"'):
                replacement = b'"' + private_key.encode("ascii") + b'"'
            else:
                return 409, {"error": "ambiguous PrivateKey quoting in [Interface]"}
            lines[key_index] = match.group(1) + replacement + (match.group(3) or b"") + ending
            try:
                backup_meta = backup.backup_files([conf_path], reason="awg-key-rotate")
            except OSError:
                return 500, {"error": "failed to back up config"}
            try:
                atomic_write_bytes(
                    conf_path,
                    b"".join(lines),
                    mode=0o600,
                    preserve_metadata=True,
                )
            except (OSError, ValueError):
                return 500, {"error": "failed to write config"}
    except OSError:
        return 500, {"error": "failed to lock config"}

    live_applied = False
    is_active = _profile_is_active(conf_path) or conf_name == VPN_IF
    if is_active:
        iface = _active_config_path().stem or VPN_IF
        ifc = run(["ifconfig", iface], timeout=3)
        if ifc.ok and "UP" in ifc.stdout:
            key_tmp = AMNEZIA_CONF_DIR / f".gatebsd-key.{os.getpid()}.{time.monotonic_ns()}.key"
            fd = -1
            try:
                fd = os.open(str(key_tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.fchmod(fd, 0o600)
                os.write(fd, (private_key + "\n").encode("ascii"))
                os.close(fd)
                fd = -1
                set_res = run([AWG_TOOL, "set", iface, "private-key", str(key_tmp)], timeout=5)
                live_applied = set_res.ok
            except OSError:
                live_applied = False
            finally:
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                try:
                    key_tmp.unlink(missing_ok=True)
                except OSError:
                    pass

    return 200, {
        "ok": True,
        "public_key": public_key,
        "backup": backup_meta,
        "path": str(conf_path),
        "live_applied": live_applied,
    }

def ru_bypass_update() -> tuple[int, dict[str, Any]]:
    r = run(["/usr/local/sbin/ru-bypass-update.sh"], timeout=120)
    return (200 if r.ok else 500), {"ok": r.ok, "output": r.stdout + r.stderr}


def dhcpd_get_conf() -> tuple[int, dict[str, Any]]:
    try:
        content, _metadata = read_regular_text(DHCPD_CONF, max_size=2 * 1024 * 1024, errors="replace")
        return 200, {"conf": content}
    except FileNotFoundError:
        return 404, {"error": "dhcpd.conf not found"}
    except OSError:
        return 500, {"error": "failed to read dhcpd.conf safely"}


def dhcpd_restart() -> tuple[int, dict[str, Any]]:
    r = run(["service", "isc-dhcpd", "restart"], timeout=10)
    return (200 if r.ok else 500), {"ok": r.ok, "out": r.stdout + r.stderr}


def unbound_get_conf() -> tuple[int, dict[str, Any]]:
    try:
        content, _metadata = read_regular_text(UNBOUND_CONF, max_size=2 * 1024 * 1024, errors="replace")
        return 200, {"conf": content}
    except FileNotFoundError:
        return 404, {"error": "unbound.conf not found"}
    except OSError:
        return 500, {"error": "failed to read unbound.conf safely"}


# unbound-anchor fails inside every start, and nothing above it says so.
#
# The port's rc script runs `su -m unbound -c /usr/local/sbin/unbound-anchor` in
# its start_precmd. unbound-anchor writes the anchor through a temporary file
# created *beside* the target, and /usr/local/etc/unbound is root:wheel 0755 --
# so the daemon's own account cannot create it. Measured on the production
# router 2026-08-07:
#
#     fatal error: could not open autotrust file for writing,
#     /usr/local/etc/unbound/root.key.21101-0-3053dc71: Permission denied
#
# rc.subr does not treat that as a failure. `service unbound restart` exits 0,
# the daemon comes up, and the old body here returned `{"ok": r.ok}` over the
# whole thing -- so a fatal error printed as a green toast with no text. That is
# the exact shape action_state was built to refuse, arriving through a route
# that never went through it: this function was a second, hand-rolled copy of
# `service_control`, which has done the honest thing since 4 August.
#
# So it delegates, and adds the one fact the generic path cannot know. The
# restart really did happen and the daemon really is up -- that is the truth
# about the *action*, and downgrading it would be its own lie. What failed is a
# condition inside it, and conditions are reported the way `vpn_path` reports
# them: named, in the text the panel already renders, with a machine-readable
# field beside it.
_ANCHOR_WRITE_FAILURE = "could not open autotrust file for writing"


def unbound_restart() -> tuple[int, dict[str, Any]]:
    from .system import service_control

    status, payload = service_control("unbound", "restart")
    output = payload.get("output", "") or ""
    if _ANCHOR_WRITE_FAILURE not in output:
        return status, payload

    payload["trust_anchor_writable"] = False
    block = payload.get("action")
    if isinstance(block, dict):
        detail = block.get("detail", "")
        # Appended rather than replaced: whether the service came back is the
        # answer to what was pressed, and it must not be displaced by the
        # footnote.
        block["detail"] = (
            f"{detail}; DNSSEC anchor not updated — service lacks write access "
            "to /usr/local/etc/unbound"
        ).lstrip("; ")
    return status, payload


def nut_restart() -> tuple[int, dict[str, Any]]:
    r1 = run(["service", "nut", "restart"], timeout=10)
    r2 = run(["service", "nut_upsmon", "restart"], timeout=10)
    probe = run(["/usr/local/bin/upsc", "-l", "localhost"], timeout=10)
    ok = r1.ok and r2.ok and probe.ok and bool(probe.stdout.strip())
    output = "\n".join(
        part for part in (r1.stdout, r1.stderr, r2.stdout, r2.stderr, probe.stdout, probe.stderr)
        if part
    )
    return (200 if ok else 500), {
        "ok": ok, "nut": r1.ok, "upsmon": r2.ok,
        "telemetry": probe.ok and bool(probe.stdout.strip()), "output": output,
    }
