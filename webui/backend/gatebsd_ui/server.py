from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import select
import signal
import socket
import ssl
import stat
import subprocess
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .api import dispatch
from .auth import valid_password_text, valid_username, verify_system_password as _auth_verify_system_password
from .fsutil import atomic_write_text, exclusive_lock, read_regular_bytes, read_regular_text


ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
AGENT_SOCKET = os.environ.get("GATEBSD_SOCKET", "/var/run/gatebsd/agent.sock")
_AUTH_MODE_RAW = os.environ.get("GATEBSD_AUTH_MODE", "system").strip().lower()
# There is deliberately no unauthenticated mode.  A gateway that is the only
# uplink for its site must never serve its management API without proving who
# the caller is: the API reaches a root agent that can rewrite PF, routing and
# system passwords.  An unrecognised value fails closed to full system auth.
AUTH_MODE = _AUTH_MODE_RAW if _AUTH_MODE_RAW in {"system", "sudo", "password"} else "system"

# Identity is asserted by this process and consumed by the privileged agent.
# Any request-supplied key in this namespace is forged by definition and is
# stripped before dispatch.
TRUSTED_QUERY_PREFIX = "_"
AUTH_HASH_FILE = Path(os.environ.get("GATEBSD_AUTH_HASH_FILE", "/var/db/gatebsd/auth.hash"))
SESSION_SECRET_FILE = Path(os.environ.get("GATEBSD_SESSION_SECRET_FILE", "/var/db/gatebsd/session.secret"))
SESSION_REVOCATION_FILE = Path(os.environ.get("GATEBSD_SESSION_REVOCATION_FILE", "/var/db/gatebsd/revoked-sessions.json"))
SESSION_EPOCH_FILE = Path(os.environ.get("GATEBSD_SESSION_EPOCH_FILE", "/var/db/gatebsd/session.epoch"))
def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


SESSION_TTL = _env_int("GATEBSD_SESSION_TTL", 43200, minimum=300, maximum=7 * 86400)
MAX_JSON_BODY = _env_int("GATEBSD_MAX_JSON_BODY", 512 * 1024, minimum=1024, maximum=8 * 1024 * 1024)
MAX_AGENT_REQUEST = _env_int("GATEBSD_MAX_AGENT_REQUEST", 1024 * 1024, minimum=4096, maximum=16 * 1024 * 1024)
MAX_AGENT_RESPONSE = _env_int("GATEBSD_MAX_AGENT_RESPONSE", 8 * 1024 * 1024, minimum=4096, maximum=64 * 1024 * 1024)
LOGIN_WINDOW = _env_int("GATEBSD_LOGIN_WINDOW", 60, minimum=10, maximum=3600)
LOGIN_MAX_FAILURES = _env_int("GATEBSD_LOGIN_MAX_FAILURES", 5, minimum=1, maximum=100)
COOKIE_SECURE = os.environ.get("GATEBSD_COOKIE_SECURE", "no").strip().lower() in {"1", "yes", "true", "on"}
_ALLOW_PUBLIC_BIND = os.environ.get("GATEBSD_ALLOW_PUBLIC_BIND", "no").strip().lower() in {"1", "yes", "true", "on"}
SERVICE_USER = os.environ.get("GATEBSD_SERVICE_USER", "gatebsd").strip() or "gatebsd"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_LOGIN_LOCK = threading.Lock()
_LOGIN_FAILURES: dict[str, list[float]] = {}
_REVOKED_LOCK = threading.Lock()
_REVOKED_MEMORY: dict[str, int] = {}
_MAX_REVOCATIONS = 4096


def _login_retry_after(address: str) -> int:
    now = time.monotonic()
    cutoff = now - LOGIN_WINDOW
    with _LOGIN_LOCK:
        failures = [stamp for stamp in _LOGIN_FAILURES.get(address, []) if stamp >= cutoff]
        if failures:
            _LOGIN_FAILURES[address] = failures
        else:
            _LOGIN_FAILURES.pop(address, None)
        if len(failures) < LOGIN_MAX_FAILURES:
            return 0
        return max(1, int(LOGIN_WINDOW - (now - failures[0])))


def _record_login_result(address: str, success: bool) -> None:
    with _LOGIN_LOCK:
        if success:
            _LOGIN_FAILURES.pop(address, None)
            return
        now = time.monotonic()
        cutoff = now - LOGIN_WINDOW
        failures = [stamp for stamp in _LOGIN_FAILURES.get(address, []) if stamp >= cutoff]
        failures.append(now)
        _LOGIN_FAILURES[address] = failures[-LOGIN_MAX_FAILURES:]


def _read_secret(path: Path) -> str:
    env_secret = os.environ.get("GATEBSD_SESSION_SECRET", "").strip()
    if env_secret:
        return env_secret
    lock_path = path.with_suffix(path.suffix + ".lock")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with exclusive_lock(lock_path):
            try:
                value, _metadata = read_regular_text(path, max_size=4096, errors="strict")
                value = value.strip()
            except FileNotFoundError:
                value = ""
            if value:
                return value
            secret = secrets.token_hex(32)
            atomic_write_text(path, secret + "\n", mode=0o640, preserve_metadata=path.exists())
            return secret
    except (OSError, UnicodeError):
        if not hasattr(_read_secret, "_fallback"):
            setattr(_read_secret, "_fallback", secrets.token_hex(32))
        return getattr(_read_secret, "_fallback")


def _session_epoch() -> int:
    try:
        text, _metadata = read_regular_text(SESSION_EPOCH_FILE, max_size=64, errors="strict")
        value = int(text.strip())
        return value if 0 <= value <= 2**63 - 1 else 0
    except (FileNotFoundError, OSError, UnicodeError, ValueError):
        return 0


def _advance_session_epoch() -> int:
    lock_path = SESSION_EPOCH_FILE.with_suffix(SESSION_EPOCH_FILE.suffix + ".lock")
    with exclusive_lock(lock_path):
        value = _session_epoch() + 1
        atomic_write_text(
            SESSION_EPOCH_FILE,
            f"{value}\n",
            mode=0o640,
            preserve_metadata=SESSION_EPOCH_FILE.exists(),
        )
        return value


def _token_expiry(token: str) -> int | None:
    first = token.split(":", 1)[0]
    if not first.isdigit():
        return None
    try:
        return int(first)
    except ValueError:
        return None


_AGENT_GRANT_LOCK = threading.Lock()
_AGENT_GRANT_CACHE: dict[str, str] = {}
_MAX_AGENT_GRANT_CACHE = 256
_IDENTITY_BEARING_PATHS = frozenset({
    "/api/auth/password",
    "/api/terminal/start",
    "/api/terminal/write",
    "/api/terminal/resize",
    "/api/terminal/read",
    "/api/terminal/close",
})


def _grant_cache_key(session_token: str) -> str:
    return hashlib.sha256(session_token.encode("utf-8")).hexdigest()


def _store_agent_grant(session_token: str, grant: str) -> None:
    if not session_token or not grant:
        return
    key = _grant_cache_key(session_token)
    with _AGENT_GRANT_LOCK:
        _AGENT_GRANT_CACHE.pop(key, None)
        while len(_AGENT_GRANT_CACHE) >= _MAX_AGENT_GRANT_CACHE:
            _AGENT_GRANT_CACHE.pop(next(iter(_AGENT_GRANT_CACHE)))
        _AGENT_GRANT_CACHE[key] = grant


def _lookup_agent_grant(session_token: str) -> str:
    if not session_token:
        return ""
    key = _grant_cache_key(session_token)
    with _AGENT_GRANT_LOCK:
        return _AGENT_GRANT_CACHE.get(key, "")


def _drop_agent_grant(session_token: str) -> None:
    if not session_token:
        return
    key = _grant_cache_key(session_token)
    with _AGENT_GRANT_LOCK:
        _AGENT_GRANT_CACHE.pop(key, None)


def _clear_agent_grants() -> None:
    with _AGENT_GRANT_LOCK:
        _AGENT_GRANT_CACHE.clear()


def _read_revocations() -> dict[str, int]:
    now = int(time.time())
    try:
        text, _metadata = read_regular_text(SESSION_REVOCATION_FILE, max_size=1024 * 1024, errors="strict")
    except FileNotFoundError:
        return {}
    raw = json.loads(text)
    if not isinstance(raw, dict):
        raise ValueError("revocation registry must be an object")
    result: dict[str, int] = {}
    for digest, expiry in raw.items():
        if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) and isinstance(expiry, int) and expiry >= now:
            result[digest] = expiry
    return result


def _is_token_revoked(token: str) -> bool:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = int(time.time())
    with _REVOKED_LOCK:
        expiry = _REVOKED_MEMORY.get(digest)
        if expiry is not None:
            if expiry >= now:
                return True
            _REVOKED_MEMORY.pop(digest, None)
    try:
        return digest in _read_revocations()
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        # An unsafe/corrupt revocation registry must not silently resurrect a
        # token which may already have been revoked.
        return SESSION_REVOCATION_FILE.exists() or SESSION_REVOCATION_FILE.is_symlink()


def revoke_token(token: str) -> bool:
    # Only a token this service actually issued may enter the registry.  A
    # signature check is what makes that true: without it any caller could
    # submit unlimited well-formed but unsigned tokens carrying far-future
    # expirations and, because the registry is bounded, push genuine
    # revocations out of it — resurrecting logged-out sessions.
    signed, _username = valid_token(token)
    if not signed:
        return False
    expiry = _token_expiry(token)
    if expiry is None or expiry < int(time.time()):
        return False
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with _REVOKED_LOCK:
        _REVOKED_MEMORY[digest] = expiry
    lock_path = SESSION_REVOCATION_FILE.with_suffix(SESSION_REVOCATION_FILE.suffix + ".lock")
    try:
        with exclusive_lock(lock_path):
            try:
                values = _read_revocations()
            except FileNotFoundError:
                values = {}
            values[digest] = expiry
            values = _prune_revocations(values)
            atomic_write_text(
                SESSION_REVOCATION_FILE,
                json.dumps(values, sort_keys=True) + "\n",
                mode=0o640,
                preserve_metadata=SESSION_REVOCATION_FILE.exists(),
            )
        return True
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return False


def _prune_revocations(values: dict[str, int]) -> dict[str, int]:
    """Bound the registry by dropping entries that can no longer matter.

    An expired token is rejected by ``valid_token`` on its own, so forgetting
    its revocation is safe. Only if the registry is still over the cap after
    that do we discard live entries, and then the nearest expirations are
    discarded first because they are the soonest to become irrelevant anyway.
    """
    now = int(time.time())
    live = {digest: expiry for digest, expiry in values.items() if expiry >= now}
    if len(live) <= _MAX_REVOCATIONS:
        return live
    ordered = sorted(live.items(), key=lambda item: item[1], reverse=True)
    return dict(ordered[:_MAX_REVOCATIONS])


def _rotate_session_secret() -> None:
    # The epoch is authoritative even when deployments inject the HMAC secret
    # through the environment and the on-disk secret cannot affect validation.
    _advance_session_epoch()
    if os.environ.get("GATEBSD_SESSION_SECRET", "").strip():
        return
    lock_path = SESSION_SECRET_FILE.with_suffix(SESSION_SECRET_FILE.suffix + ".lock")
    with exclusive_lock(lock_path):
        atomic_write_text(
            SESSION_SECRET_FILE,
            secrets.token_hex(32) + "\n",
            mode=0o640,
            preserve_metadata=SESSION_SECRET_FILE.exists(),
        )


def _password_hash() -> str:
    env_hash = os.environ.get("GATEBSD_PASSWORD_HASH", "").strip()
    if env_hash:
        return env_hash
    try:
        value, _metadata = read_regular_text(AUTH_HASH_FILE, max_size=8192, errors="strict")
        return value.strip()
    except (OSError, UnicodeError):
        return ""


def _hash_password(password: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return digest.hex()


def verify_password(password: str) -> bool:
    stored = _password_hash()
    if not stored or ":" not in stored:
        return False
    salt, digest = stored.split(":", 1)
    if re.fullmatch(r"[0-9a-f]{32}", salt) is None or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        return False
    return hmac.compare_digest(_hash_password(password, salt), digest)


def _verify_system_password(username: str, password: str) -> bool:
    return _auth_verify_system_password(username, password)


def auth_enabled() -> bool:
    # Authentication is not optional; retained as a function because the API
    # status endpoint and the frontend both report it.
    return True


def make_token(username: str = "") -> str:
    if username and not valid_username(username):
        raise ValueError("invalid session username")
    expires = int(time.time()) + SESSION_TTL
    nonce = secrets.token_hex(12)
    epoch = _session_epoch()
    payload = f"{expires}:{nonce}:{username}:{epoch}"
    sig = hmac.new(_read_secret(SESSION_SECRET_FILE).encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def valid_token(token: str) -> tuple[bool, str]:
    if not isinstance(token, str) or not 1 <= len(token) <= 512:
        return False, ""
    parts = token.split(":")
    if len(parts) != 5:
        return False, ""
    expires, nonce, username, epoch, sig = parts
    if (
        not expires.isdigit()
        or int(expires) < int(time.time())
        or re.fullmatch(r"[0-9a-f]{24}", nonce) is None
        or (username and not valid_username(username))
        or not epoch.isdigit()
        or int(epoch) != _session_epoch()
        or re.fullmatch(r"[0-9a-f]{64}", sig) is None
    ):
        return False, ""
    payload = f"{expires}:{nonce}:{username}:{epoch}"
    expected = hmac.new(_read_secret(SESSION_SECRET_FILE).encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected) or _is_token_revoked(token):
        return False, ""
    return True, username


def _strip_trusted_query(query: dict[str, list[str]]) -> dict[str, list[str]]:
    """Remove any request-supplied key in the trusted-identity namespace.

    The privileged agent treats ``_user``/``_session``/``_auth_mode`` as proof
    that this process authenticated the caller. A client that can set them
    directly can therefore claim to be root. Stripping unconditionally, rather
    than overwriting only on some code paths, keeps that guarantee independent
    of which branch the request took.
    """
    return {
        key: value
        for key, value in query.items()
        if not key.startswith(TRUSTED_QUERY_PREFIX)
    }


def resolve_child(base: Path, relative: str) -> Path | None:
    try:
        root = base.resolve()
        requested = (root / relative).resolve()
    except OSError:
        return None
    if requested == root or root not in requested.parents:
        return None
    return requested


def agent_dispatch(method: str, path: str, query: dict[str, list[str]],
                   body: dict | None = None) -> tuple[int, object] | None:
    if not AGENT_SOCKET:
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(_env_float("GATEBSD_AGENT_TIMEOUT", 180.0, minimum=1.0, maximum=900.0))
            client.connect(AGENT_SOCKET)
            request = json.dumps(
                {"method": method, "path": path, "query": query, "body": body},
                ensure_ascii=False,
            ).encode("utf-8") + b"\n"
            if len(request) > MAX_AGENT_REQUEST:
                return 413, {"error": "agent request too large"}
            client.sendall(request)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_AGENT_RESPONSE:
                    raise ValueError("agent response exceeds the size limit")
                chunks.append(chunk)
                if b"\n" in chunk:
                    break
        raw_response = b"".join(chunks)
        if not raw_response.endswith(b"\n"):
            raise ValueError("incomplete agent response")
        response = json.loads(raw_response.decode("utf-8"))
        if not isinstance(response, dict):
            raise ValueError("invalid agent response")
        return int(response.get("status", 500)), response.get("payload", {})
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"gatebsd agent unavailable: {type(exc).__name__}: {exc}", file=os.sys.stderr)
        return 503, {"error": "agent unavailable", "service": "gatebsd"}


class GateBSDHandler(BaseHTTPRequestHandler):
    server_version = "GateBSD/2.0"
    sys_version = ""

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        super().end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        print("%s - - [%s] %s" % (self.address_string(), self.log_date_time_string(), fmt % args))

    def send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # client disconnected mid-response

    def _secure_cookie(self) -> bool:
        forwarded = self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
        peer = self.client_address[0] if self.client_address else ""
        trusted_proxy = peer in {"127.0.0.1", "::1"}
        return COOKIE_SECURE or (trusted_proxy and forwarded == "https") or isinstance(self.connection, ssl.SSLSocket)

    def send_auth_cookie(self, token: str) -> None:
        self.send_header(
            "Set-Cookie",
            f"gatebsd_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}"
            + ("; Secure" if self._secure_cookie() else ""),
        )

    def clear_auth_cookie(self) -> None:
        self.send_header(
            "Set-Cookie",
            "gatebsd_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            + ("; Secure" if self._secure_cookie() else ""),
        )

    def send_grant_cookie(self, grant: str) -> None:
        self.send_header(
            "Set-Cookie",
            f"gatebsd_grant={grant}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}"
            + ("; Secure" if self._secure_cookie() else ""),
        )

    def clear_grant_cookie(self) -> None:
        self.send_header(
            "Set-Cookie",
            "gatebsd_grant=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            + ("; Secure" if self._secure_cookie() else ""),
        )

    def _cookie_value(self, name: str) -> str:
        raw = self.headers.get("Cookie", "")
        for item in raw.split(";"):
            if "=" not in item:
                continue
            key, value = item.strip().split("=", 1)
            if key == name:
                return value
        return ""

    def cookie_token(self) -> str:
        return self._cookie_value("gatebsd_session")

    def cookie_grant(self) -> str:
        return self._cookie_value("gatebsd_grant")

    def _current_agent_grant(self) -> str:
        return self.cookie_grant() or _lookup_agent_grant(self.cookie_token())
    def get_authenticated_user(self) -> tuple[bool, str]:
        ok, user = valid_token(self.cookie_token())
        # A valid token must always name a principal.  Anonymous-but-valid was
        # previously reachable and left the trusted-parameter block below
        # unexecuted, so forged identity survived into the privileged agent.
        if ok and not user:
            return False, ""
        return ok, user

    def is_authenticated(self) -> bool:
        ok, _ = self.get_authenticated_user()
        return ok
    def send_file(self, path: Path) -> None:
        try:
            content, _metadata = read_regular_bytes(path, max_size=16 * 1024 * 1024)
        except (FileNotFoundError, OSError):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # client disconnected mid-response

    def do_GET(self) -> None:
        self.route_request("GET")

    def do_HEAD(self) -> None:
        self.route_request("GET")

    def do_POST(self) -> None:
        self.route_request("POST")

    def same_origin_request(self) -> bool:
        """Reject browser cross-origin state changes while allowing local CLI clients."""
        origin = self.headers.get("Origin", "").strip()
        if not origin:
            referer = self.headers.get("Referer", "").strip()
            origin = referer if referer else ""
        if not origin:
            return True
        if origin == "null":
            return False
        try:
            parsed = urlparse(origin)
        except ValueError:
            return False
        host = self.headers.get("Host", "").strip().lower()
        return parsed.scheme in {"http", "https"} and bool(host) and parsed.netloc.lower() == host

    def json_content_type(self) -> bool:
        media_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        return media_type == "application/json"

    def client_identity(self) -> str:
        """Identify the caller for logging and display.

        ``X-Real-IP`` is attacker-controlled in practice: every external request
        arrives from nginx on loopback, so "peer is loopback" does not establish
        that the header came from nginx rather than from the client. It is
        therefore reported but never used as a rate-limit key -- see
        ``throttle_identity``.
        """
        peer = self.client_address[0] if self.client_address else "unknown"
        if peer not in {"127.0.0.1", "::1"}:
            return peer
        forwarded = self.headers.get("X-Real-IP", "").strip()
        if forwarded:
            try:
                return str(ipaddress.ip_address(forwarded))
            except ValueError:
                pass
        return peer

    def throttle_identity(self) -> str:
        """Return a rate-limit key the client cannot rotate.

        Keyed on the real transport peer only. When that peer is the reverse
        proxy, every proxied client shares one bucket -- deliberately, because a
        shared bucket that cannot be escaped is stronger than a per-client
        bucket that a single spoofed header resets.
        """
        return self.client_address[0] if self.client_address else "unknown"

    def content_length(self) -> tuple[int | None, str]:
        if self.headers.get("Transfer-Encoding") is not None:
            return None, "Transfer-Encoding is not supported"
        values = self.headers.get_all("Content-Length", [])
        if len(values) > 1:
            return None, "multiple Content-Length headers are not allowed"
        raw = values[0] if values else "0"
        if not re.fullmatch(r"[0-9]+", raw.strip()):
            return None, "invalid Content-Length"
        length = int(raw)
        return length, ""

    def read_body(self) -> tuple[dict | None, str]:
        length, error = self.content_length()
        if error:
            return None, error
        assert length is not None
        if length <= 0:
            return None, ""
        if length > MAX_JSON_BODY:
            return None, f"request body too large; max {MAX_JSON_BODY} bytes"
        raw = self.rfile.read(length)
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, "invalid JSON body"
        if not isinstance(decoded, dict):
            return None, "JSON body must be an object"
        return decoded, ""

    def route_request(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/ws/logs":
            self.handle_ws_logs(parse_qs(parsed.query))
            return
        if path.startswith("/api/"):
            body = None
            if method == "POST":
                if not self.same_origin_request():
                    self.send_json({"error": "cross-origin request rejected"}, HTTPStatus.FORBIDDEN)
                    return
                if not self.json_content_type():
                    self.send_json({"error": "Content-Type must be application/json"}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
                    return
                body, body_error = self.read_body()
                if body_error:
                    status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE if "too large" in body_error else HTTPStatus.BAD_REQUEST
                    self.send_json({"error": body_error}, status)
                    return
            if path.startswith("/api/auth/"):
                self.handle_auth(method, path, body)
                return
            
            ok, username = self.get_authenticated_user()
            if not ok:
                self.send_json({"error": "authentication required"}, HTTPStatus.UNAUTHORIZED)
                return
            if not username:
                self.send_json({"error": "authentication required"}, HTTPStatus.UNAUTHORIZED)
                return

            parsed_query = _strip_trusted_query(parse_qs(parsed.query))
            parsed_query["_user"] = [username]
            parsed_query["_session"] = [hashlib.sha256(self.cookie_token().encode("utf-8")).hexdigest()]
            parsed_query["_auth_mode"] = [AUTH_MODE]
            if path in _IDENTITY_BEARING_PATHS:
                grant = self._current_agent_grant()
                if grant:
                    parsed_query["_agent_token"] = [grant]
            self.handle_api(method, path, parsed_query, body)
            return
        if method == "POST":
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
            return
        if path in ("", "/"):
            self.send_file(FRONTEND / "index.html")
            return
        requested = (FRONTEND / path.lstrip("/")).resolve()
        if FRONTEND.resolve() not in requested.parents and requested != FRONTEND.resolve():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        self.send_file(requested)

    def handle_auth(self, method: str, path: str, body: dict | None = None) -> None:
        if path == "/api/auth/status" and method == "GET":
            self.send_json({
                "authenticated": self.is_authenticated(),
                "enabled": auth_enabled(),
                "mode": AUTH_MODE,
            })
            return
        if path == "/api/auth/login" and method == "POST":
            client_address = self.throttle_identity()
            retry_after = _login_retry_after(client_address)
            if retry_after:
                self.send_json(
                    {"error": "too many login failures", "retry_after": retry_after},
                    HTTPStatus.TOO_MANY_REQUESTS,
                )
                return
            authenticated = False
            login_payload: object = {"authenticated": False}
            failure_status = HTTPStatus.UNAUTHORIZED
            if AUTH_MODE in ("sudo", "system"):
                result = agent_dispatch("POST", "/api/auth/login", {}, body or {})
                if result is None:
                    login_payload = {"error": "auth requires gatebsd-agent"}
                    failure_status = HTTPStatus.SERVICE_UNAVAILABLE
                else:
                    status, login_payload = result
                    authenticated = status == 200 and bool((login_payload or {}).get("authenticated"))
                    failure_status = HTTPStatus(status)
            else:
                password = str((body or {}).get("password", ""))
                authenticated = verify_password(password)
                login_payload = {"authenticated": authenticated}

            _record_login_result(client_address, authenticated)
            if authenticated:
                username = (login_payload or {}).get("username", "") if isinstance(login_payload, dict) else ""
                if not username:
                    username = "gatebsd"
                agent_grant = ""
                response_payload: object = login_payload
                if isinstance(login_payload, dict):
                    response_payload = dict(login_payload)
                    agent_grant = str(response_payload.pop("_agent_token", "") or "")
                token = make_token(username)
                if agent_grant:
                    _store_agent_grant(token, agent_grant)
                payload = json.dumps(response_payload, ensure_ascii=False).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(payload)))
                self.send_auth_cookie(token)
                if agent_grant:
                    self.send_grant_cookie(agent_grant)
                self.end_headers()
                self.wfile.write(payload)
                return
            error = (login_payload or {}).get("error") if isinstance(login_payload, dict) else None
            self.send_json({"error": error or "invalid login"}, failure_status)
            return
        if path == "/api/auth/logout" and method == "POST":
            # Logout writes to disk, so it must not be an unauthenticated,
            # unthrottled entry point.  Clearing the cookie on an unauthenticated
            # request is still honoured; only the persistent revocation is gated.
            token = self.cookie_token()
            _drop_agent_grant(token)
            if not self.is_authenticated():
                payload = json.dumps({"authenticated": False}).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(payload)))
                self.clear_auth_cookie()
                self.clear_grant_cookie()
                self.end_headers()
                self.wfile.write(payload)
                return
            if token and not revoke_token(token):
                self.log_error("failed to persist session revocation; rotating all sessions")
                try:
                    _rotate_session_secret()
                except OSError:
                    self.log_error("failed to rotate sessions after revocation failure")
            payload = json.dumps({"authenticated": False}).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.clear_auth_cookie()
            self.clear_grant_cookie()
            self.end_headers()
            self.wfile.write(payload)
            return
        if path == "/api/auth/password" and method == "POST":
            if not self.is_authenticated():
                self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            current_password = (body or {}).get("current_password", "")
            new_password = (body or {}).get("password", "")
            if not valid_password_text(new_password, minimum=8, maximum=1024):
                self.send_json({"error": "password must be 8-1024 characters without NUL or newlines"}, HTTPStatus.BAD_REQUEST)
                return
            username = ""
            if self.is_authenticated():
                _, username = self.get_authenticated_user()
            if AUTH_MODE in {"system", "sudo"} and username:
                dispatch_query: dict[str, list[str]] = {"_user": [username]}
                grant = self._current_agent_grant()
                if grant:
                    dispatch_query["_agent_token"] = [grant]
                result = agent_dispatch(
                    "POST",
                    "/api/auth/password",
                    dispatch_query,
                    {"current_password": current_password, "password": new_password},
                )
                if result is None:
                    self.send_json({"error": "password change requires gatebsd-agent"}, HTTPStatus.SERVICE_UNAVAILABLE)
                else:
                    status, payload = result
                    if status == 200:
                        new_grant = ""
                        response_payload: object = payload
                        if isinstance(payload, dict):
                            response_payload = dict(payload)
                            new_grant = str(response_payload.pop("_agent_token", "") or "")
                        _clear_agent_grants()
                        try:
                            _rotate_session_secret()
                            token = make_token(username)
                        except OSError:
                            self.send_json({"error": "password changed but sessions could not be rotated"}, HTTPStatus.INTERNAL_SERVER_ERROR)
                            return
                        if new_grant:
                            _store_agent_grant(token, new_grant)
                        encoded = json.dumps(response_payload, ensure_ascii=False).encode("utf-8")
                        self.send_response(HTTPStatus.OK)
                        self.send_header("Content-Type", "application/json; charset=utf-8")
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("Content-Length", str(len(encoded)))
                        self.send_auth_cookie(token)
                        if new_grant:
                            self.send_grant_cookie(new_grant)
                        else:
                            self.clear_grant_cookie()
                        self.end_headers()
                        self.wfile.write(encoded)
                    else:
                        self.send_json(payload, HTTPStatus(status))
            else:
                if _password_hash() and (not isinstance(current_password, str) or not current_password or not verify_password(current_password)):
                    self.send_json({"error": "current password is incorrect"}, HTTPStatus.FORBIDDEN)
                    return
                salt = secrets.token_hex(16)
                digest = _hash_password(new_password, salt)
                try:
                    import grp
                    import pwd
                    AUTH_HASH_FILE.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        uid = pwd.getpwnam(SERVICE_USER).pw_uid
                        gid = grp.getgrnam(SERVICE_USER).gr_gid
                    except KeyError:
                        uid = gid = None
                    atomic_write_text(
                        AUTH_HASH_FILE,
                        f"{salt}:{digest}\n",
                        mode=0o640,
                        preserve_metadata=False,
                        uid=uid,
                        gid=gid,
                    )
                    _rotate_session_secret()
                    token = make_token(username or "gatebsd")
                    encoded = json.dumps({"ok": True}).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.send_auth_cookie(token)
                    self.end_headers()
                    self.wfile.write(encoded)
                except Exception as exc:
                    self.log_error("password update failed: %s", exc)
                    self.send_json({"error": "failed to update password"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self.send_json({"error": "unknown auth endpoint"}, HTTPStatus.NOT_FOUND)

    def handle_api(self, method: str, path: str, query: dict[str, list[str]],
                   body: dict | None = None) -> None:
        try:
            result = agent_dispatch(method, path, query, body)
            if result is None:
                result = dispatch(path, query, method=method, body=body)
            status, payload = result
            self.send_json(payload, HTTPStatus(status))
        except Exception as exc:
            self.log_error("API request failed for %s %s: %s", method, path, exc)
            self.send_json({"error": "internal server error"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_ws_logs(self, query: dict[str, list[str]]) -> None:
        if not self.same_origin_request():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not self.is_authenticated():
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        version = self.headers.get("Sec-WebSocket-Version", "")
        upgrade = self.headers.get("Upgrade", "").lower()
        if version != "13" or upgrade != "websocket":
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        try:
            raw_key = base64.b64decode(key, validate=True)
        except (ValueError, binascii.Error):
            raw_key = b""
        if len(raw_key) != 16:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        source = query.get("source", ["messages"])[0]
        unit = query.get("unit", ["gatebsd"])[0]
        if source not in {"messages", "dmesg"}:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if source == "messages":
            try:
                metadata = Path("/var/log/messages").lstat()
            except OSError:
                self.send_error(HTTPStatus.SERVICE_UNAVAILABLE)
                return
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                self.send_error(HTTPStatus.FORBIDDEN)
                return
        if not re.match(r"^[A-Za-z0-9_.:\-]+$", unit):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")
        self.send_response(HTTPStatus.SWITCHING_PROTOCOLS)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        command = ["dmesg", "-a"] if source == "dmesg" else ["tail", "-n", "120", "-F", "/var/log/messages"]
        proc = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
            start_new_session=True,
            env={"PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin", "LANG": "C", "LC_ALL": "C"},
        )
        token = self.cookie_token()
        expiry = _token_expiry(token) or int(time.time())
        buffer = b""
        try:
            assert proc.stdout is not None
            while int(time.time()) <= expiry and valid_token(token)[0]:
                readable, _, _ = select.select([proc.stdout], [], [], 1.0)
                if not readable:
                    if proc.poll() is not None:
                        break
                    continue
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    raw_line, buffer = buffer.split(b"\n", 1)
                    line = raw_line[:65536].decode("utf-8", errors="replace")
                    payload = json.dumps({"source": source, "unit": unit, "line": line}, ensure_ascii=False)
                    self.ws_send_text(payload)
                if len(buffer) > 65536:
                    line = buffer[:65536].decode("utf-8", errors="replace") + " [truncated]"
                    buffer = b""
                    self.ws_send_text(json.dumps({"source": source, "unit": unit, "line": line}, ensure_ascii=False))
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
                proc.wait()

    def ws_send_text(self, text: str) -> None:
        data = text.encode("utf-8")
        header = bytearray([0x81])
        length = len(data)
        if length < 126:
            header.append(length)
        elif length < 65536:
            header.extend([126, (length >> 8) & 0xFF, length & 0xFF])
        else:
            header.append(127)
            header.extend(length.to_bytes(8, "big"))
        self.wfile.write(bytes(header) + data)
        self.wfile.flush()



def _is_loopback_bind(host: str) -> bool:
    value = host.strip().lower()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False

def main() -> None:
    parser = argparse.ArgumentParser(description="GateBSD router web UI")
    parser.add_argument("--host", default=os.environ.get("GATEBSD_HOST", "127.0.0.1"))
    parser.add_argument("--port", default=int(os.environ.get("GATEBSD_PORT", "8080")), type=int)
    args = parser.parse_args()
    # A non-loopback bind exposes the management API directly rather than through
    # the nginx entry point that terminates TLS and applies access control.
    if not _is_loopback_bind(args.host) and not _ALLOW_PUBLIC_BIND:
        parser.error(
            "refusing to bind %s: the UI is reached through nginx on loopback; "
            "set GATEBSD_ALLOW_PUBLIC_BIND=yes to override" % args.host
        )
    server = ThreadingHTTPServer((args.host, args.port), GateBSDHandler)
    try:
        server.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1200)
    except Exception:
        pass
    
    cert_file = Path("/usr/local/etc/gatebsd/tls/cert.pem")
    key_file = Path("/usr/local/etc/gatebsd/tls/key.pem")
    try:
        cert_meta = cert_file.lstat()
        key_meta = key_file.lstat()
        tls_available = (
            cert_file.is_file() and not cert_file.is_symlink()
            and key_file.is_file() and not key_file.is_symlink()
            and key_meta.st_uid == 0
            and key_meta.st_mode & 0o027 == 0
        )
    except OSError:
        tls_available = False
    if tls_available:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Pin the floor explicitly rather than inheriting whatever the linked
        # OpenSSL happens to default to.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print(f"gatebsd UI listening on https://{args.host}:{args.port}")
    else:
        print(f"gatebsd UI listening on http://{args.host}:{args.port}")
        
    server.serve_forever()


if __name__ == "__main__":
    main()
