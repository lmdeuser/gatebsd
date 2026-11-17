from __future__ import annotations

import argparse
import json
import os
import pwd
import sqlite3
import stat
import tempfile
import time
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = "/var/db/gatebsd/state.db"
SCHEMA_VERSION = 1


def db_path() -> str:
    return os.environ.get("GATEBSD_DB_PATH", DEFAULT_DB_PATH)


def _allowed_db_dir_uids() -> set[int]:
    euid = os.geteuid()
    allowed = {0, euid}
    if euid == 0:
        service_user = os.environ.get("GATEBSD_SERVICE_USER", "gatebsd")
        try:
            allowed.add(pwd.getpwnam(service_user).pw_uid)
        except KeyError:
            pass
    return allowed


def connect() -> sqlite3.Connection:
    path = Path(db_path())
    if path.parent.is_symlink():
        raise OSError(f"refusing symlinked database directory: {path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_stat = path.parent.lstat()
    if (
        stat.S_ISLNK(parent_stat.st_mode)
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid not in _allowed_db_dir_uids()
        or bool(parent_stat.st_mode & stat.S_IWOTH)
    ):
        raise OSError(f"unsafe database directory ownership or type: {path.parent}")
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"), Path(f"{path}-journal")):
        if candidate.is_symlink():
            raise OSError(f"refusing symlinked database file: {candidate}")
        if candidate.exists():
            db_stat = candidate.lstat()
            if not stat.S_ISREG(db_stat.st_mode) or db_stat.st_nlink != 1:
                raise OSError(f"refusing non-regular or hardlinked database file: {candidate}")
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("pragma journal_mode=WAL")
    conn.execute("pragma synchronous=NORMAL")
    conn.execute("pragma foreign_keys=ON")
    conn.execute("pragma busy_timeout=10000")
    conn.row_factory = sqlite3.Row
    init(conn)
    if os.geteuid() == 0 and parent_stat.st_uid != 0:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
            try:
                fd = os.open(candidate, flags)
            except FileNotFoundError:
                continue
            try:
                st = os.fstat(fd)
                if stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == 0:
                    os.fchown(fd, parent_stat.st_uid, parent_stat.st_gid)
                    os.fchmod(fd, 0o640)
            finally:
                os.close(fd)
    return conn


def init(conn: sqlite3.Connection) -> None:
    current = int(conn.execute("pragma user_version").fetchone()[0])
    if current > SCHEMA_VERSION:
        raise RuntimeError(f"database schema {current} is newer than supported {SCHEMA_VERSION}")
    if current < 1:
        conn.executescript(
        """
        create table if not exists snapshots (
            id integer primary key autoincrement,
            ts integer not null,
            kind text not null,
            payload text not null
        );
        create index if not exists snapshots_kind_ts on snapshots(kind, ts desc);

        create table if not exists events (
            id integer primary key autoincrement,
            ts integer not null,
            severity text not null,
            kind text not null,
            message text not null,
            payload text not null default '{}'
        );
        create index if not exists events_ts on events(ts desc);

        create table if not exists device_last_seen (
            mac text primary key,
            ip text not null default '',
            hostname text not null default '',
            connection text not null default '',
            bridge_port text not null default '',
            state text not null default '',
            first_seen integer not null,
            last_seen integer not null,
            static integer not null default 0,
            payload text not null default '{}'
        );
        """
        )
        conn.execute("pragma user_version=1")
    conn.commit()


def migrate() -> int:
    with connect() as conn:
        return int(conn.execute("pragma user_version").fetchone()[0])



def backup_database(destination: str | Path) -> Path:
    """Create a consistent SQLite backup in a private, trusted directory."""
    target = Path(destination)
    if not target.is_absolute():
        raise ValueError("database backup destination must be absolute")
    target.parent.mkdir(parents=True, exist_ok=True)
    parent_metadata = target.parent.lstat()
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise OSError(f"refusing unsafe database backup directory: {target.parent}")
    if parent_metadata.st_uid != os.geteuid() or stat.S_IMODE(parent_metadata.st_mode) & 0o022:
        raise OSError(f"database backup directory must be private and owned by the caller: {target.parent}")
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None and (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise OSError(f"refusing unsafe database backup destination: {target}")

    fd = -1
    temporary_name: str | None = None
    try:
        fd, temporary_name = tempfile.mkstemp(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
        )
        os.close(fd)
        fd = -1
        temporary = Path(temporary_name)
        with connect() as source, sqlite3.connect(temporary) as output:
            source.backup(output)
            output.execute("pragma journal_mode=DELETE")
            output.commit()
        os.chmod(temporary, 0o600)
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        temporary_name = None
        directory_fd = os.open(
            target.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return target
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass

def save_snapshot(kind: str, payload: Any, ts: int | None = None) -> None:
    now = ts or int(time.time())
    with connect() as conn:
        conn.execute(
            "insert into snapshots(ts, kind, payload) values (?, ?, ?)",
            (now, kind, json.dumps(payload, ensure_ascii=False, sort_keys=True)),
        )
        prune_snapshots(conn, kind)
        conn.commit()


def prune_snapshots(conn: sqlite3.Connection, kind: str, keep: int = 1000) -> None:
    conn.execute(
        """
        delete from snapshots
        where kind = ?
          and id not in (
            select id from snapshots where kind = ? order by ts desc, id desc limit ?
          )
        """,
        (kind, kind, keep),
    )


def add_event(kind: str, message: str, severity: str = "info", payload: Any | None = None, ts: int | None = None) -> None:
    now = ts or int(time.time())
    with connect() as conn:
        conn.execute(
            "insert into events(ts, severity, kind, message, payload) values (?, ?, ?, ?, ?)",
            (now, severity, kind, message, json.dumps(payload or {}, ensure_ascii=False, sort_keys=True)),
        )
        conn.execute(
            "delete from events where id not in (select id from events order by ts desc, id desc limit 2000)"
        )
        conn.commit()


def update_devices(clients_payload: dict[str, Any], ts: int | None = None) -> None:
    now = ts or int(time.time())
    clients = clients_payload.get("clients", [])
    with connect() as conn:
        for client in clients:
            mac = (client.get("mac") or "").lower()
            if not mac:
                continue
            existing = conn.execute("select * from device_last_seen where mac = ?", (mac,)).fetchone()
            hostname = client.get("hostname") or ""
            ip = client.get("ip") or ""
            connection = client.get("connection") or ""
            bridge_port = client.get("bridge_port") or ""
            state = client.get("state") or ""
            static = 1 if client.get("static") else 0
            payload = json.dumps(client, ensure_ascii=False, sort_keys=True)
            if existing is None:
                conn.execute(
                    """
                    insert into device_last_seen(
                        mac, ip, hostname, connection, bridge_port, state, first_seen, last_seen, static, payload
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (mac, ip, hostname, connection, bridge_port, state, now, now, static, payload),
                )
                conn.execute(
                    "insert into events(ts, severity, kind, message, payload) values (?, ?, ?, ?, ?)",
                    (now, "info", "device.new", f"New LAN device {hostname or mac} {ip}".strip(), payload),
                )
            else:
                changes = []
                for field, value in (
                    ("ip", ip),
                    ("hostname", hostname),
                    ("connection", connection),
                    ("bridge_port", bridge_port),
                ):
                    if value and existing[field] and existing[field] != value:
                        changes.append(f"{field}: {existing[field]} -> {value}")
                conn.execute(
                    """
                    update device_last_seen
                    set ip = ?, hostname = ?, connection = ?, bridge_port = ?, state = ?,
                        last_seen = ?, static = ?, payload = ?
                    where mac = ?
                    """,
                    (ip, hostname, connection, bridge_port, state, now, static, payload, mac),
                )
                if changes:
                    conn.execute(
                        "insert into events(ts, severity, kind, message, payload) values (?, ?, ?, ?, ?)",
                        (now, "warn", "device.change", f"Device {hostname or mac}: " + "; ".join(changes), payload),
                    )
        conn.commit()


def update_wan(wan_payload: dict[str, Any], ts: int | None = None) -> None:
    now = ts or int(time.time())
    primary_raw = wan_payload.get("wan") if isinstance(wan_payload.get("wan"), dict) else wan_payload.get("primary")
    secondary_raw = wan_payload.get("backup") if isinstance(wan_payload.get("backup"), dict) else wan_payload.get("secondary")
    primary = primary_raw if isinstance(primary_raw, dict) else {}
    secondary = secondary_raw if isinstance(secondary_raw, dict) else {}
    health = wan_payload.get("health", {}) if isinstance(wan_payload.get("health"), dict) else {}
    primary_h_raw = health.get("wan") if isinstance(health.get("wan"), dict) else health.get("primary")
    secondary_h_raw = health.get("backup") if isinstance(health.get("backup"), dict) else health.get("secondary")
    primary_health = primary_h_raw if isinstance(primary_h_raw, dict) else {}
    secondary_health = secondary_h_raw if isinstance(secondary_h_raw, dict) else {}
    sys_info = wan_payload.get("sys_info", {}) if isinstance(wan_payload.get("sys_info"), dict) else {}
    primary_name = str(primary.get("name") or wan_payload.get("primary_iface") or sys_info.get("wan_if") or "primary")
    secondary_name = str(secondary.get("name") or wan_payload.get("secondary_iface") or sys_info.get("backup_if") or "secondary")
    current = {
        "active_iface": wan_payload.get("active_iface") or "",
        "active_default": wan_payload.get("active_gw") or wan_payload.get("active_default") or "",
        "primary_iface": primary_name,
        "secondary_iface": secondary_name,
        "primary_addresses": primary.get("addresses", []),
        "secondary_addresses": secondary.get("addresses", []),
        "primary_ok": bool(primary_health.get("ok")),
        "secondary_ok": bool(secondary_health.get("ok")),
    }
    previous = latest_snapshot("wan")
    if previous:
        old = previous["payload"]
        if old.get("active_iface") != current["active_iface"]:
            add_event(
                "wan.active_change",
                f"Active WAN changed {old.get('active_iface') or 'none'} -> {current['active_iface'] or 'none'}",
                severity="warn",
                payload={"old": old, "new": current},
                ts=now,
            )
        for key in ("primary_ok", "secondary_ok"):
            if bool(old.get(key)) != bool(current.get(key)):
                add_event(
                    "wan.health_change",
                    f"{key} changed {old.get(key)} -> {current.get(key)}",
                    severity="warn" if not current.get(key) else "info",
                    payload={"old": old, "new": current},
                    ts=now,
                )
        for key in ("primary_addresses", "secondary_addresses"):
            if old.get(key) != current.get(key):
                add_event(
                    "wan.address_change",
                    f"{key} changed",
                    severity="info",
                    payload={"old": old.get(key), "new": current.get(key)},
                    ts=now,
                )
    save_snapshot("wan", current, ts=now)


def latest_snapshot(kind: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "select ts, kind, payload from snapshots where kind = ? order by ts desc, id desc limit 1",
            (kind,),
        ).fetchone()
    if row is None:
        return None
    return {"ts": row["ts"], "kind": row["kind"], "payload": json.loads(row["payload"])}


def history(limit: int = 100) -> dict[str, Any]:
    safe_limit = max(10, min(limit, 500))
    with connect() as conn:
        events = [
            {
                "ts": row["ts"],
                "severity": row["severity"],
                "kind": row["kind"],
                "message": row["message"],
                "payload": json.loads(row["payload"]),
            }
            for row in conn.execute("select * from events order by ts desc, id desc limit ?", (safe_limit,))
        ]
        devices = [
            {
                "mac": row["mac"],
                "ip": row["ip"],
                "hostname": row["hostname"],
                "connection": row["connection"],
                "bridge_port": row["bridge_port"],
                "state": row["state"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "static": bool(row["static"]),
            }
            for row in conn.execute("select * from device_last_seen order by last_seen desc limit ?", (safe_limit,))
        ]
        snapshot_counts = [
            {"kind": row["kind"], "count": row["count"], "latest": row["latest"]}
            for row in conn.execute(
                "select kind, count(*) as count, max(ts) as latest from snapshots group by kind order by kind"
            )
        ]
    return {"events": events, "devices": devices, "snapshot_counts": snapshot_counts, "db_path": db_path()}


def main() -> int:
    parser = argparse.ArgumentParser(description="GateBSD SQLite maintenance")
    parser.add_argument("--backup", metavar="PATH", help="write a consistent SQLite backup")
    args = parser.parse_args()
    if args.backup:
        print(backup_database(args.backup))
    else:
        print(f"GateBSD database schema {migrate()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
