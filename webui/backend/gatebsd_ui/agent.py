"""agent.py — gatebsd background agent (FreeBSD edition).

Uses FreeBSD-native traffic sampling and delegates all WAN/VPN failover
routing to the unified gatebsd-watchdog service.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import hmac
import json
import os
import pwd
import secrets
import socket
import socketserver
import stat
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any

from . import adapters, storage
from . import config
from .api import dispatch
from .fsutil import atomic_write_text, read_regular_text

AGENT_ALLOWED_GET = {
    "/api/overview",
    "/api/system",
    "/api/memory",
    "/api/disks",
    "/api/interfaces",
    "/api/physical_ports",
    "/api/system/updates",
    "/api/system/updates/log",
    "/api/stats/traffic",
    "/api/wan",
    "/api/services",
    "/api/services/all",
    "/api/firewall",
    "/api/firewall/detail",
    "/api/pf/conf/pending",
    "/api/port-forwards",
    "/api/reverse-ssh",
    "/api/dhcp",
    "/api/clients",
    "/api/pppoe",
    "/api/modem",
    "/api/amnezia",
    "/api/ups",
    "/api/pf/conf",
    "/api/dhcp/conf",
    "/api/dns/conf",
    "/api/dns/split",
    "/api/repo/sources",
    "/api/rcconf",
    "/api/history",
    "/api/stats/traffic",
    "/api/terminal/read",
    "/api/logs",
    "/api/health",
    "/api/backups",
    "/api/backups/diff",
    "/api/discovery",
    "/api/import",
    "/api/split-tunnel",
    "/api/diagnostics",
    "/api/failover",
    "/api/vpn/peers",
    "/api/vpn",
    "/api/vpn/status",
    "/api/vpn/profiles",
    "/api/vpn/exceptions",
    "/api/adblock/status",
    "/api/adblock/rules",
    "/api/tls/status",
    "/api/secureboot/status",
    "/api/amnezia/repository/status",
    "/api/ups/config",
    "/api/zfs",
    "/api/disks/io",
    "/api/disks/smart",
}

AGENT_ALLOWED_POST = {
    "/api/auth/login",
    "/api/auth/password",
    "/api/system/power",
    "/api/system/upgrade",
    "/api/system/updates/check",
    "/api/system/updates/install",
    "/api/pf/reload",
    "/api/pf/conf",
    "/api/pppoe/restart",
    "/api/amnezia/apply",
    "/api/amnezia/down",
    "/api/amnezia/rollback",
    "/api/amnezia/status",
    "/api/amnezia/ru_bypass/update",
    "/api/amnezia/config",
    "/api/amnezia/activate",
    "/api/vpn/apply",
    "/api/vpn/down",
    "/api/vpn/rollback",
    "/api/vpn/init/pf",
    "/api/vpn/init/routes",
    "/api/vpn/peers",
    "/api/vpn/peers/remove",
    "/api/vpn/key-rotate",
    "/api/vpn/nft/plus",
    "/api/vpn/nft/minus",
    "/api/dhcp/restart",
    "/api/dhcp/static/add",
    "/api/dhcp/static/remove",
    "/api/dhcp/range",
    "/api/dns/restart",
    "/api/ups/restart",
    "/api/service/control",
    "/api/services/manage",
    "/api/diag/traceroute",
    "/api/diag/nslookup",
    "/api/terminal/write",
    "/api/terminal/resize",
    "/api/terminal/close",
    "/api/failover/mode",
    "/api/failover/switch",
    "/api/discovery/scan",
    "/api/import/run",
    "/api/backups/create",
    "/api/backups/delete",
    "/api/backups/restore",
    "/api/diagnose/run",
    "/api/wol",
    "/api/rcconf",
    "/api/amnezia/diagnose",
    "/api/disks/smart/test",
    "/api/disks/mount",
    "/api/disks/unmount",
    "/api/amnezia/update-ru-ips",
    "/api/dns/upstreams",
    "/api/dns/split",
    "/api/repo/sources",
    "/api/repo/scan",
    "/api/pppoe/reconnect",
    "/api/secureboot/enroll",
    "/api/ups/command",
    "/api/ups/config",
    "/api/vpn/profile/delete",
    "/api/vpn/profile/switch",
    "/api/vpn/profile/upload",
    "/api/vpn/stop",
    "/api/vpn/exceptions/add",
    "/api/vpn/exceptions/remove",
    "/api/vpn/exceptions/diagnose",
    "/api/pf/conf/confirm",
    "/api/port-forwards/save",
    "/api/port-forwards/delete",
    "/api/port-forwards/test",
    "/api/reverse-ssh/save",
    "/api/reverse-ssh/delete",
    "/api/adblock/update",
    "/api/adblock/probe",
    "/api/adblock/rules/add",
    "/api/adblock/rules/remove",
    "/api/tls/renew",
    "/api/wan/test",
    "/api/internet/repair",
}


def _agent_allowed(method: str, path: str) -> bool:
    # Strip query string for path matching
    clean_path = path.split("?")[0] if "?" in path else path
    if method == "GET":
        return clean_path in AGENT_ALLOWED_GET
    if method == "POST":
        return clean_path in AGENT_ALLOWED_POST
    return False


# Endpoints that act on behalf of a named system principal.  For these the
# agent must not take the caller's word for who that principal is.
_IDENTITY_BEARING_PATHS = {
    "/api/auth/password",
    "/api/terminal/start",
    "/api/terminal/write",
    "/api/terminal/resize",
    "/api/terminal/read",
    "/api/terminal/close",
}


def peer_identity(sock: "socket.socket") -> tuple[int, int] | None:
    """Return the (uid, gid) of the connected peer, or None if unavailable.

    FreeBSD exposes this through LOCAL_PEERCRED (struct xucred); Linux through
    SO_PEERCRED (struct ucred). Both are kernel-supplied and cannot be forged
    by the peer, which is what makes them usable as an authorization input.
    """
    local_peercred = getattr(socket, "LOCAL_PEERCRED", 1)
    sol_local = getattr(socket, "SOL_LOCAL", 0)
    try:
        # struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[16]; ... }
        raw = sock.getsockopt(sol_local, local_peercred, 4 + 4 + 2 + 2 + 16 * 4)
        version, uid, ngroups = struct.unpack("IIh", raw[:10])
        if ngroups > 0:
            (gid,) = struct.unpack("I", raw[12:16])
        else:
            gid = -1
        return uid, gid
    except (OSError, struct.error, ValueError):
        pass
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, gid = struct.unpack("3i", raw)
        return uid, gid
    except (OSError, AttributeError, struct.error, ValueError):
        return None


def _peer_is_trusted(sock: "socket.socket", service_group: str) -> bool:
    """Whether the peer is entitled to speak to the privileged agent at all.

    The socket mode already restricts this to root and the service group; this
    is a second, explicit check so that a permission regression on the socket
    does not silently become an authorization bypass.
    """
    identity = peer_identity(sock)
    if identity is None:
        # The platform did not give us credentials.  The socket mode is then the
        # only control, and it is enforced by the kernel, so proceed.
        return True
    uid, gid = identity
    if uid == 0:
        return True
    try:
        group = grp.getgrnam(service_group)
    except (KeyError, OSError):
        return False
    if gid == group.gr_gid:
        return True
    try:
        name = pwd.getpwuid(uid).pw_name
    except (KeyError, OSError):
        return False
    return name in group.gr_mem


AGENT_GRANT_KEY_FILE = Path(os.environ.get("GATEBSD_AGENT_GRANT_KEY", "/var/db/gatebsd-system/agent-grant.key"))
AGENT_GRANT_EPOCH_FILE = Path(os.environ.get("GATEBSD_AGENT_GRANT_EPOCH", "/var/db/gatebsd-system/agent-grant.epoch"))
AGENT_GRANT_TTL = 12 * 3600
_AGENT_GRANT_LOCK = threading.Lock()


def _agent_grant_secret() -> bytes:
    with _AGENT_GRANT_LOCK:
        try:
            raw, _meta = read_regular_text(AGENT_GRANT_KEY_FILE, max_size=4096, errors="strict")
            candidate = raw.strip()
            if len(candidate) == 64:
                return bytes.fromhex(candidate)
        except (FileNotFoundError, OSError, UnicodeError, ValueError):
            pass
        generated = secrets.token_hex(32)
        atomic_write_text(AGENT_GRANT_KEY_FILE, generated + "\n", mode=0o600, preserve_metadata=False)
        return bytes.fromhex(generated)


def _agent_grant_epoch() -> int:
    try:
        raw, _meta = read_regular_text(AGENT_GRANT_EPOCH_FILE, max_size=256, errors="strict")
        text = raw.strip()
        if text.isdigit() and int(text) >= 1:
            return int(text)
    except (FileNotFoundError, OSError, UnicodeError, ValueError):
        pass
    return 1


def bump_agent_grant_epoch() -> int:
    with _AGENT_GRANT_LOCK:
        nxt = _agent_grant_epoch() + 1
        atomic_write_text(AGENT_GRANT_EPOCH_FILE, f"{nxt}\n", mode=0o600, preserve_metadata=False)
        return nxt


def mint_agent_grant(username: str) -> str:
    exp = int(time.time()) + AGENT_GRANT_TTL
    nonce = secrets.token_hex(16)
    epoch = _agent_grant_epoch()
    body = f"{exp}:{nonce}:{username}:{epoch}"
    sig = hmac.new(_agent_grant_secret(), body.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{body}:{sig}"


def _reject_invalid_agent_grant(query: object) -> str | None:
    if not isinstance(query, dict):
        return "missing agent capability token"
    user_vals = query.get("_user")
    username = user_vals[0] if isinstance(user_vals, list) and user_vals else ""
    grant_vals = query.get("_agent_token")
    token = grant_vals[0] if isinstance(grant_vals, list) and grant_vals else ""
    if not isinstance(token, str) or not token:
        return "missing agent capability token"
    parts = token.split(":")
    if len(parts) != 5:
        return "invalid agent capability token"
    exp_s, nonce, tok_user, epoch_s, sig = parts
    if not exp_s.isdigit() or not epoch_s.isdigit() or not nonce or len(sig) != 64:
        return "invalid agent capability token"
    if int(exp_s) < int(time.time()):
        return "expired agent capability token"
    if tok_user != username:
        return "agent capability token principal mismatch"
    try:
        current_epoch = _agent_grant_epoch()
        if int(epoch_s) != current_epoch:
            return "stale agent capability token"
        body = f"{exp_s}:{nonce}:{tok_user}:{epoch_s}"
        expected = hmac.new(_agent_grant_secret(), body.encode("utf-8"), hashlib.sha256).hexdigest()
    except (OSError, ValueError):
        return "agent capability validation unavailable"
    if not hmac.compare_digest(expected, sig):
        return "invalid agent capability signature"
    return None


def _reject_unauthorized_identity(query: object) -> str | None:
    """Re-authorize the asserted principal inside the privileged agent.

    The UI process sets ``_user`` after authenticating the session, but the agent
    must not treat that as sufficient: if the unprivileged UI is compromised it
    can name any account, including root, and reach ``pw moduser`` or ``su``.
    Re-running the same admin-group check the login path uses means a forged
    name only succeeds for accounts that were already permitted to administer
    the router.
    """
    from .auth import authorized_system_user, valid_username

    values = query.get("_user") if isinstance(query, dict) else None
    username = values[0] if isinstance(values, list) and values else ""
    if not valid_username(username):
        return "privileged operation requires an authenticated system account"
    if not authorized_system_user(username):
        return "account is not authorized to administer this system"
    return None


class AgentRequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(config.MAX_AGENT_REQUEST + 1)
        try:
            if not raw or not raw.endswith(b"\n"):
                raise ValueError("incomplete or oversized agent request")
            request = json.loads(raw.decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError("agent request must be a JSON object")
            path   = str(request.get("path", ""))
            method = str(request.get("method", "GET")).upper()
            query  = request.get("query") or {}
            body   = request.get("body")
            if not isinstance(query, dict):
                query = {}
            if body is not None and not isinstance(body, dict):
                raise ValueError("agent body must be a JSON object")
            service_group = os.environ.get("GATEBSD_SERVICE_GROUP", "gatebsd").strip() or "gatebsd"
            if not _peer_is_trusted(self.connection, service_group):
                status, payload = 403, {"error": "peer is not authorized to use the agent"}
            elif not _agent_allowed(method, path):
                status, payload = 404, {"error": "endpoint not allowed"}
            else:
                clean_path = path.split("?", 1)[0]
                identity_error = None
                if clean_path in _IDENTITY_BEARING_PATHS:
                    identity_error = _reject_unauthorized_identity(query)
                    if identity_error is None:
                        identity_error = _reject_invalid_agent_grant(query)
                if identity_error is not None:
                    status, payload = 403, {"error": identity_error}
                else:
                    status, payload = dispatch(path, query, method=method, body=body)
                    if clean_path == "/api/auth/login" and method == "POST" and status == 200 and isinstance(payload, dict) and payload.get("authenticated"):
                        login_user = str(payload.get("username") or "")
                        if login_user:
                            payload = dict(payload)
                            payload["_agent_token"] = mint_agent_grant(login_user)
                    elif clean_path == "/api/auth/password" and method == "POST" and status == 200:
                        bump_agent_grant_epoch()
                        pw_vals = query.get("_user")
                        pw_user = pw_vals[0] if isinstance(pw_vals, list) and pw_vals else ""
                        if isinstance(payload, dict) and pw_user:
                            payload = dict(payload)
                            payload["_agent_token"] = mint_agent_grant(pw_user)
            response: dict[str, Any] = {"status": status, "payload": payload}
        except Exception as exc:
            print(f"gatebsd-agent request failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            response = {"status": 500, "payload": {"error": "internal agent error"}}
        try:
            encoded = json.dumps(response, ensure_ascii=False).encode("utf-8")
            if len(encoded) > config.MAX_AGENT_RESPONSE:
                encoded = json.dumps({"status": 500, "payload": {"error": "agent response too large"}}).encode("utf-8")
            self.wfile.write(encoded + b"\n")
        except BrokenPipeError:
            pass


class UnixAgentServer(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 32


def _bsd_iface_bytes(iface: str) -> tuple[int, int]:
    """Return (rx_bytes, tx_bytes) for an interface via netstat."""
    from .adapters.network import iface_counters
    return iface_counters(iface)


def sample_once() -> None:
    now = int(time.time())
    overview = adapters.overview()
    clients  = adapters.lan_clients()
    services = adapters.services()
    wan      = adapters.wan_status()
    storage.save_snapshot("overview", overview, ts=now)
    storage.save_snapshot("clients",  clients,  ts=now)
    storage.save_snapshot("services", services, ts=now)
    storage.update_devices(clients, ts=now)
    storage.update_wan(wan, ts=now)


def sampler(interval: int) -> None:
    storage.add_event("agent.start", "gatebsd agent started", payload={"interval": interval})
    while True:
        try:
            sample_once()
        except Exception as exc:
            storage.add_event("agent.sample_error", str(exc), severity="error")
        time.sleep(interval)


def serve(socket_path: str) -> None:
    path = Path(socket_path)
    if not path.is_absolute():
        raise ValueError("agent socket path must be absolute")
    service_group = os.environ.get("GATEBSD_SERVICE_GROUP", "gatebsd").strip() or "gatebsd"
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_metadata = path.parent.lstat()
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise OSError(f"refusing unsafe agent socket directory: {path.parent}")
    try:
        socket_metadata = path.lstat()
    except FileNotFoundError:
        socket_metadata = None
    if socket_metadata is not None:
        if not stat.S_ISSOCK(socket_metadata.st_mode):
            raise OSError(f"refusing to unlink non-socket path: {path}")
        path.unlink()

    previous_umask = os.umask(0o117)
    try:
        server = UnixAgentServer(str(path), AgentRequestHandler)
    finally:
        os.umask(previous_umask)
    try:
        gid = grp.getgrnam(service_group).gr_gid
        os.chown(path, 0, gid)
        os.chmod(path, 0o660)
    except Exception:
        server.server_close()
        path.unlink(missing_ok=True)
        raise
    print(f"gatebsd agent listening on unix://{path}")

    interval = config.SAMPLE_INTERVAL
    threading.Thread(target=sampler, args=(interval,), daemon=True).start()

    try:
        server.serve_forever()
    finally:
        server.server_close()
        try:
            metadata = path.lstat()
            if stat.S_ISSOCK(metadata.st_mode):
                path.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="gatebsd local management agent")
    parser.add_argument("--socket", default=config.AGENT_SOCKET)
    args = parser.parse_args()
    serve(args.socket)


if __name__ == "__main__":
    main()
