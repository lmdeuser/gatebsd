from __future__ import annotations

import re


SECRET_KEYS = ("pass", "password", "psk", "secret", "key", "token", "privatekey", "presharedkey")
NON_SECRET_KEYS = ("wpa_key_mgmt",)


def redact_value(key: str, value: str) -> str:
    lo = key.lower()
    if lo in NON_SECRET_KEYS:
        return value
    if any(marker in lo for marker in SECRET_KEYS):
        return "******"
    return value


def redact_text(text: str) -> str:
    patterns = [
        r"(?i)(password\s*[=:]\s*)[^\s\";]+",
        r"(?i)(set\s+auth\s+password\s+).*$",
        r"(?i)(privatekey\s*[=:]\s*).*$",
        r"(?i)(presharedkey\s*[=:]\s*).*$",
        r"(?i)(token\s*[=:]\s*)[^\s\";]+",
        r"(?i)(api[_-]?key\s*[=:]\s*)[^\s\";]+",
        r"(?i)(secret\s*[=:]\s*)[^\s\";]+",
    ]
    redacted = text
    for pattern in patterns:
        redacted = re.sub(pattern, r"\1<REDACTED>", redacted, flags=re.MULTILINE)
    return redacted



