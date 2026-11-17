"""Package source selection.

The panel manages where packages are fetched from, never whose signature is
accepted. The panel writes the sources list to repo-sources.conf and never
touches pkg's gatebsd.conf directly, preserving the single-writer invariant
asserted by the test suite. The stand's public key path is hardcoded by the
repo bootstrap renderer, so a tampered sources file cannot introduce an
untrusted signer.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .. import backup, paths
from ..command import run
from ..fsutil import atomic_write_text, exclusive_lock, read_regular_text

SOURCES_FILE = paths.REPO_SOURCES
BOOTSTRAP = str(paths.REPO_BOOTSTRAP)
LIVE_REPO_CONF = paths.REPO_CONF
PKG = str(paths.PKG_BIN)
DEFAULT_SOURCE = "http://mirror.example.lan"
MAX_SOURCES = 16

_PUBKEY_PATH = "/usr/local/etc/pkg/keys/gatebsd-stand.pub"

_HEADER = """# Where this device fetches its packages from.
#
# Written by the web panel, read by gatebsd-repo-bootstrap, which renders
# /usr/local/etc/pkg/repos/gatebsd.conf from it. The panel never writes that
# config itself: one managed file, one writer.
#
# Format is one entry per line, `<state>|<base-url>`. `state` is `active` for
# the source in use or `known` for one that was found and kept for later;
# exactly one entry may be active. The URL is a bare host with no path -- the
# repository paths below it are this product's, not the operator's, and are
# added by the renderer.
#
# Choosing a source decides where packages come from. It does NOT decide whose
# signature is accepted: that is the stand's public key, and the renderer
# writes its path as a literal.
"""

_HOST_CHAR_RE = re.compile(r"^[a-zA-Z0-9.-]+$")
_PKG_URL_RE = re.compile(r'url\s*:\s*["\']([^"\']+)["\']')
_LEASE_IP_RE = re.compile(r"^\s*lease\s+([0-9a-fA-F.:]+)\s*\{")
_FIXED_IP_RE = re.compile(r"^\s*fixed-address\s+([^;]+);")


def _validate_url(value: object) -> tuple[str | None, str | None]:
    """Validate a bare base URL with no path, credentials, or query parameters.

    URLs are interpolated into pkg repo configuration files without shell escaping,
    so characters that could escape quotation or inject options must be rejected here.
    """
    if not isinstance(value, str):
        return None, "URL must be a string"
    raw = value.strip()
    if not raw:
        return None, "URL must not be empty"

    if any(ch.isspace() or ch in {'"', "'", "\\", "?", "#", "@"} for ch in raw):
        return None, f"URL contains forbidden characters: {raw!r}"

    if raw.startswith("http://"):
        scheme = "http://"
        rest = raw[7:]
    elif raw.startswith("https://"):
        scheme = "https://"
        rest = raw[8:]
    else:
        return None, "URL must start with http:// or https://"

    if "/" in rest:
        return None, f"URL must be a bare host, no path: {raw}"

    if ":" in rest:
        parts = rest.split(":")
        if len(parts) != 2:
            return None, f"URL must be a bare host, no path: {raw}"
        host, port_str = parts
        if not port_str.isdigit():
            return None, f"invalid port: {raw}"
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None, f"invalid port: {raw}"
        port_suffix = f":{port}"
    else:
        host = rest
        port_suffix = ""

    if not host or len(host) > 253:
        return None, f"invalid host: {raw}"
    if host.startswith(".") or host.endswith(".") or host.startswith("-") or host.endswith("-"):
        return None, f"invalid host: {raw}"
    if not _HOST_CHAR_RE.match(host):
        return None, f"invalid host: {raw}"

    normalized = f"{scheme}{host.lower()}{port_suffix}"
    return normalized, None


def _parse(text: str) -> tuple[list[dict[str, str]] | None, str | None]:
    """Parse the line-oriented sources configuration matching shell reader semantics."""
    entries: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    active_count = 0

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if "|" not in stripped:
            return None, f"{SOURCES_FILE}:{line_number}: expected <state>|<url>"

        parts = stripped.split("|")
        if len(parts) != 2:
            return None, f"{SOURCES_FILE}:{line_number}: extra delimiter"

        state, raw_url = parts[0].strip(), parts[1].strip()

        if state not in {"active", "known"}:
            return None, f"{SOURCES_FILE}:{line_number}: unknown state '{state}'"

        url, err = _validate_url(raw_url)
        if url is None:
            return None, f"{SOURCES_FILE}:{line_number}: {err}"

        if url in seen_urls:
            return None, f"{SOURCES_FILE}:{line_number}: duplicate package source URL: {url}"

        seen_urls.add(url)
        if state == "active":
            active_count += 1

        entries.append({"url": url, "state": state})

    if active_count == 0:
        return None, f"{SOURCES_FILE}: no active package source"
    if active_count > 1:
        return None, f"{SOURCES_FILE}: {active_count} active sources, expected exactly one"

    return entries, None


def _render(entries: list[dict[str, str]]) -> str:
    """Render configuration entries with the shipped header and active entry first."""
    sorted_entries = sorted(entries, key=lambda e: 0 if e["state"] == "active" else 1)
    body = "\n".join(f"{entry['state']}|{entry['url']}" for entry in sorted_entries)
    return f"{_HEADER}{body}\n"


def _read_applied_url() -> str | None:
    """Extract the base source URL currently written in the live pkg configuration."""
    try:
        text, _ = read_regular_text(LIVE_REPO_CONF, max_size=256 * 1024, errors="strict")
    except OSError:
        return None

    match = _PKG_URL_RE.search(text)
    if not match:
        return None

    full_url = match.group(1).strip()
    idx = full_url.find("/gatebsd/")
    if idx != -1:
        base = full_url[:idx]
    else:
        base = full_url

    validated, _ = _validate_url(base)
    return validated


def read_sources() -> dict[str, Any]:
    """Read the configured package sources, falling back to shipped defaults if unbootstrapped."""
    applied_url = _read_applied_url()
    try:
        text, _ = read_regular_text(SOURCES_FILE, max_size=64 * 1024, errors="strict")
    except FileNotFoundError:
        text = None
    except (OSError, UnicodeError) as exc:
        # An unreadable file is not the same as an absent one, and reporting the
        # default as if it were in force would be a lie: bootstrap reads the
        # same file and would refuse. The panel has to be able to say so.
        return {
            "path": str(SOURCES_FILE),
            "sources": [],
            "active": None,
            "applied": applied_url,
            "default": DEFAULT_SOURCE,
            "bootstrapped": True,
            "error": f"cannot read {SOURCES_FILE}: {exc}",
        }

    if text is not None:
        entries, err = _parse(text)
        if entries is None:
            return {
                "path": str(SOURCES_FILE),
                "sources": [],
                "active": None,
                "applied": applied_url,
                "default": DEFAULT_SOURCE,
                "bootstrapped": True,
                "error": err,
            }
        active_entry = next((e["url"] for e in entries if e["state"] == "active"), None)
        return {
            "path": str(SOURCES_FILE),
            "sources": entries,
            "active": active_entry,
            "applied": applied_url,
            "default": DEFAULT_SOURCE,
            "bootstrapped": True,
        }

    default_entries = [{"url": DEFAULT_SOURCE, "state": "active"}]
    return {
        "path": str(SOURCES_FILE),
        "sources": default_entries,
        "active": DEFAULT_SOURCE,
        "applied": applied_url,
        "default": DEFAULT_SOURCE,
        "bootstrapped": False,
    }


def set_sources(value: object) -> tuple[int, dict[str, Any]]:
    """Validate and atomically persist package sources, running bootstrap under lock.

    This function never writes LIVE_REPO_CONF directly. It updates repo-sources.conf
    and invokes gatebsd-repo-bootstrap to render the pkg configuration, preserving
    the single-writer invariant.
    """
    if not isinstance(value, dict):
        return 400, {"error": "request body must be a JSON object"}

    active_raw = value.get("active")
    known_raw = value.get("known", [])

    if not isinstance(active_raw, str):
        return 400, {"error": "'active' must be a URL string"}
    if not isinstance(known_raw, list):
        return 400, {"error": "'known' must be a list of URL strings"}

    active_url, active_err = _validate_url(active_raw)
    if active_url is None:
        return 400, {"error": f"invalid active URL: {active_err}"}

    validated_known: list[str] = []
    seen: set[str] = {active_url}

    for item in known_raw:
        if not isinstance(item, str):
            return 400, {"error": "each item in 'known' must be a string"}
        k_url, k_err = _validate_url(item)
        if k_url is None:
            return 400, {"error": f"invalid known URL {item!r}: {k_err}"}
        if k_url not in seen:
            seen.add(k_url)
            validated_known.append(k_url)

    total_count = 1 + len(validated_known)
    if total_count > MAX_SOURCES:
        return 400, {"error": f"total sources ({total_count}) exceeds limit of {MAX_SOURCES}"}

    entries: list[dict[str, str]] = [{"url": active_url, "state": "active"}]
    for k_url in validated_known:
        entries.append({"url": k_url, "state": "known"})

    rendered = _render(entries)
    lock_path = SOURCES_FILE.with_suffix(SOURCES_FILE.suffix + ".gatebsd.lock")

    try:
        # install -d re-applies ownership to a directory that already exists and
        # both shared runtime directories in this product have been broken that
        # way, so what is already there is left exactly as it is.
        if not SOURCES_FILE.parent.exists():
            SOURCES_FILE.parent.mkdir(parents=True, mode=0o755)
        with exclusive_lock(lock_path):
            original_text: str | None = None
            if SOURCES_FILE.exists():
                try:
                    original_text, _ = read_regular_text(SOURCES_FILE, max_size=64 * 1024, errors="strict")
                except OSError:
                    original_text = None

            if original_text is not None and original_text == rendered:
                return 200, {
                    "ok": True,
                    "sources": entries,
                    "active": active_url,
                    "changed": False,
                }

            # backup_files skips what is not there, so the first write on a
            # device that never had a source list needs no special case.
            backup_meta = backup.backup_files([SOURCES_FILE], reason="repo-sources")

            atomic_write_text(SOURCES_FILE, rendered, mode=0o644, preserve_metadata=True)

            bootstrap_res = run([BOOTSTRAP], timeout=60.0)
            if not bootstrap_res.ok:
                _rollback(original_text)
                return 500, {
                    "error": "Failed to bootstrap package repository configuration",
                    "detail": bootstrap_res.stderr or bootstrap_res.stdout or bootstrap_res.error or "",
                    "rolled_back": True,
                    "backup": backup_meta,
                }

            pkg_update_res = run([PKG, "update", "-f"], timeout=180.0)
            if not pkg_update_res.ok:
                rollback_ok = _rollback(original_text)
                return 500, {
                    "error": "Failed to update package catalogs from new source",
                    "detail": pkg_update_res.stderr or pkg_update_res.stdout or pkg_update_res.error or "",
                    "rolled_back": rollback_ok,
                    "backup": backup_meta,
                }

            return 200, {
                "ok": True,
                "sources": entries,
                "active": active_url,
                "changed": True,
                "backup": backup_meta,
            }

    except (OSError, UnicodeError, ValueError) as exc:
        return 500, {"error": f"failed to update package sources: {exc}"}


def _rollback(previous_text: str | None) -> bool:
    """Restore previous repo-sources.conf and re-run bootstrap to sync pkg configuration."""
    try:
        if previous_text is None:
            SOURCES_FILE.unlink(missing_ok=True)
        else:
            atomic_write_text(SOURCES_FILE, previous_text, mode=0o644, preserve_metadata=True)
        res = run([BOOTSTRAP], timeout=60.0)
        return res.ok
    except (OSError, ValueError):
        return False


def _candidates() -> list[str]:
    """Gather candidate base URLs from configured sources and local DHCP discovery."""
    candidates: list[str] = []
    seen: set[str] = set()

    def add_candidate(raw: str) -> None:
        url, err = _validate_url(raw)
        if url is not None and url not in seen and len(candidates) < MAX_SOURCES:
            seen.add(url)
            candidates.append(url)

    current = read_sources()
    for entry in current.get("sources", []):
        add_candidate(entry.get("url", ""))

    add_candidate(DEFAULT_SOURCE)

    try:
        leases_text, _ = read_regular_text(paths.DHCPD_LEASES, max_size=1024 * 1024, errors="replace")
        for line in leases_text.splitlines():
            match = _LEASE_IP_RE.match(line)
            if match:
                add_candidate(f"http://{match.group(1)}")
    except OSError:
        pass

    try:
        conf_text, _ = read_regular_text(paths.DHCPD_CONF, max_size=1024 * 1024, errors="replace")
        for line in conf_text.splitlines():
            match = _FIXED_IP_RE.match(line)
            if match:
                for ip in match.group(1).split(","):
                    add_candidate(f"http://{ip.strip()}")
    except OSError:
        pass

    return candidates


def probe(url: str) -> dict[str, Any]:
    """Whether this address can actually deliver the appliance.

    `pkg update` is not the test, and believing it was is a mistake this code
    already made. Measured against the real mirror on the stand: pointed at a
    freshly generated public key that signs nothing here, `pkg update -f` prints
    a complaint about the key and still exits 0. An update that "succeeded"
    therefore says only that something answered on the port.

    Asking the catalogue for the appliance package is what separates the cases:
    with the stand's key it answers `gatebsd-2.9.92` and exits 0, with a
    stranger's key it answers nothing and exits 1, because the catalogue was
    never loaded. So the query is the verdict and the update is only the fetch.
    """
    validated_url, err = _validate_url(url)
    if validated_url is None:
        return {"url": url, "ok": False, "detail": err or "invalid URL"}

    with TemporaryDirectory(prefix="repo-probe-") as tmpdir:
        tmp_path = Path(tmpdir)
        repos_dir = tmp_path / "repos"
        db_dir = tmp_path / "db"
        cache_dir = tmp_path / "cache"

        repos_dir.mkdir(parents=True, exist_ok=True)
        db_dir.mkdir(parents=True, exist_ok=True)
        cache_dir.mkdir(parents=True, exist_ok=True)

        probe_conf = repos_dir / "probe.conf"
        # Both repositories, because a mirror that serves one and not the other
        # is not a usable source: releases carry the appliance, ports carry what
        # it runs on, and an upgrade needs both. Probing only one would report a
        # half-built mirror as good and fail at the next upgrade instead.
        conf_content = (
            'FreeBSD: { enabled: no }\n'
            'FreeBSD-ports: { enabled: no }\n'
            'FreeBSD-ports-kmods: { enabled: no }\n'
            'probe-releases: {\n'
            f'  url: "{validated_url}/gatebsd/releases/current",\n'
            '  mirror_type: "none",\n'
            '  signature_type: "pubkey",\n'
            f'  pubkey: "{_PUBKEY_PATH}",\n'
            '  enabled: yes\n'
            '}\n'
            'probe-ports: {\n'
            f'  url: "{validated_url}/gatebsd/packages/freebsd_151_amd64-default/latest",\n'
            '  mirror_type: "none",\n'
            '  signature_type: "pubkey",\n'
            f'  pubkey: "{_PUBKEY_PATH}",\n'
            '  enabled: yes\n'
            '}\n'
        )
        probe_conf.write_text(conf_content, encoding="utf-8")

        options = [
            PKG,
            "-o", f"REPOS_DIR={repos_dir}",
            "-o", f"PKG_DBDIR={db_dir}",
            "-o", f"PKG_CACHEDIR={cache_dir}",
        ]
        cmd = options + ["update", "-f"]
        fetched = run(cmd, timeout=45.0)
        if not fetched.ok:
            detail = fetched.stderr or fetched.stdout or fetched.error or ""
            return {
                "url": validated_url,
                "ok": False,
                "version": None,
                "detail": detail.strip()[:400],
            }

        released = run(options + ["rquery", "-r", "probe-releases", "%n-%v", "gatebsd"], timeout=30.0)
        # Any single package name would do for the ports repository; -a asks for
        # the whole catalogue, and an empty answer means it never loaded.
        ported = run(options + ["rquery", "-r", "probe-ports", "-a", "%n"], timeout=30.0)

        version = released.stdout.strip().splitlines()[-1] if released.ok and released.stdout.strip() else None
        ok = bool(version) and ported.ok and bool(ported.stdout.strip())
        if ok:
            detail = f"catalogue signed by stand key, {version} available"
        elif version:
            detail = "releases readable, but dependency catalogue is empty or signed by another key"
        else:
            detail = "catalogue cannot be read with stand key"
        return {
            "url": validated_url,
            "ok": ok,
            "version": version,
            "detail": detail,
        }


def scan() -> tuple[int, dict[str, Any]]:
    """Probe all candidate package sources.

    Scanning is an operator-initiated diagnostic action rather than a background poll
    to prevent unwanted network traffic and resource consumption.
    """
    candidate_urls = _candidates()
    results: list[dict[str, Any]] = []
    found: list[str] = []

    for candidate in candidate_urls:
        res = probe(candidate)
        results.append(res)
        if res.get("ok"):
            found.append(res["url"])

    return 200, {
        "candidates": results,
        "found": found,
    }
