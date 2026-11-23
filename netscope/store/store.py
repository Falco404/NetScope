"""SQLite persistence: scan history, device rows, per-scan ports, diff.

DB path comes from NETSCOPE_DB (env var) — never committed; default is a
gitignored file. Schema version lives in PRAGMA user_version; bump it and
extend `_SCHEMA` if the shape changes (no migration framework at this stage).
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from netscope.device import Device, merge_scan
from netscope.scanner.models import ScanResult

SCHEMA_VERSION = 1
DEFAULT_DB_PATH = "netscope.db"

_SCHEMA = """
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,               -- ISO-8601 UTC
    target TEXT NOT NULL,
    duration_seconds REAL
);
CREATE TABLE devices (
    identity TEXT PRIMARY KEY,      -- MAC uppercase, else IP
    ip TEXT NOT NULL,
    hostname TEXT,
    mac TEXT,
    vendor TEXT,
    os_guess TEXT,
    last_seen_scan INTEGER NOT NULL
);
CREATE TABLE device_ports (
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    identity TEXT NOT NULL REFERENCES devices(identity),
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service TEXT,
    version TEXT
);
CREATE INDEX idx_device_ports_scan ON device_ports(scan_id);
"""


def db_path() -> str:
    return os.environ.get("NETSCOPE_DB", DEFAULT_DB_PATH)


@dataclass(frozen=True)
class ScanSummary:
    id: int
    ts: str
    target: str
    duration_seconds: float | None


@dataclass(frozen=True)
class ScanDiff:
    """Difference between two stored scans."""

    new_devices: tuple[str, ...]  # identity keys that appear in b but not a
    gone_devices: tuple[str, ...]  # in a but not b
    changed_devices: tuple[str, ...]  # in both, port set differs


class SQLiteStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or db_path()
        # The API runs scans in a background thread that writes here, so the
        # connection is shared across threads (SQLite serializes internally).
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys = ON")
        if self.conn.execute("PRAGMA user_version").fetchone()[0] == 0:
            self.conn.executescript(_SCHEMA)
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "SQLiteStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def save_scan(
        self,
        result: ScanResult,
        devices: dict[str, Device],
        duration_seconds: float | None = None,
        ts: str | None = None,
    ) -> tuple[int, dict[str, Device]]:
        """Persist one scan + update device rows. Returns (scan_id, merged devices)."""
        ts = ts or datetime.now(UTC).isoformat()
        cur = self.conn.execute(
            "INSERT INTO scans (ts, target, duration_seconds) VALUES (?, ?, ?)",
            (ts, result.target, duration_seconds),
        )
        scan_id = int(cur.lastrowid or 0)

        merged = merge_scan(devices, result.hosts, scan_id=scan_id)
        for device in merged.values():
            self.conn.execute(
                """
                INSERT INTO devices (identity, ip, hostname, mac, vendor, os_guess, last_seen_scan)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(identity) DO UPDATE SET
                    ip = excluded.ip,
                    hostname = COALESCE(excluded.hostname, devices.hostname),
                    mac = COALESCE(excluded.mac, devices.mac),
                    vendor = COALESCE(excluded.vendor, devices.vendor),
                    os_guess = COALESCE(excluded.os_guess, devices.os_guess),
                    last_seen_scan = excluded.last_seen_scan
                """,
                (
                    device.identity,
                    device.ip,
                    device.hostname,
                    device.mac,
                    device.vendor,
                    device.os_guess,
                    scan_id,
                ),
            )
            for p in device.open_ports:
                self.conn.execute(
                    """
                    INSERT INTO device_ports
                        (scan_id, identity, ip, port, protocol, service, version)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (scan_id, device.identity, device.ip, p.port, p.protocol, p.service, p.version),
                )
        self.conn.commit()
        return scan_id, merged

    def list_scans(self) -> list[ScanSummary]:
        rows = self.conn.execute(
            "SELECT id, ts, target, duration_seconds FROM scans ORDER BY id DESC"
        ).fetchall()
        return [ScanSummary(id=r[0], ts=r[1], target=r[2], duration_seconds=r[3]) for r in rows]

    def latest_scan_id(self) -> int | None:
        row = self.conn.execute("SELECT MAX(id) FROM scans").fetchone()
        return row[0]

    def load_devices(self) -> list[Device]:
        rows = self.conn.execute(
            """
            SELECT identity, ip, hostname, mac, vendor, os_guess, last_seen_scan
            FROM devices ORDER BY identity
            """
        ).fetchall()
        return [
            Device(
                identity=r[0],
                ip=r[1],
                hostname=r[2],
                mac=r[3],
                vendor=r[4],
                os_guess=r[5],
                last_seen_scan=r[6],
            )
            for r in rows
        ]

    def devices_in_scan(self, scan_id: int) -> list[Device]:
        """Devices that had at least one open port in this scan."""
        rows = self.conn.execute(
            """
            SELECT DISTINCT d.identity, d.ip, d.hostname, d.mac, d.vendor, d.os_guess
            FROM devices d JOIN device_ports p ON p.identity = d.identity
            WHERE p.scan_id = ? ORDER BY d.identity
            """,
            (scan_id,),
        ).fetchall()
        return [
            Device(identity=r[0], ip=r[1], hostname=r[2], mac=r[3], vendor=r[4], os_guess=r[5])
            for r in rows
        ]

    def scan_ports(self, scan_id: int) -> dict[str, frozenset[tuple[int, str]]]:
        """identity -> set of (port, protocol) open in this scan."""
        rows = self.conn.execute(
            "SELECT identity, port, protocol FROM device_ports WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        out: dict[str, set[tuple[int, str]]] = {}
        for identity, port, protocol in rows:
            out.setdefault(identity, set()).add((port, protocol))
        return {k: frozenset(v) for k, v in out.items()}

    def port_history(self, identity: str) -> list[tuple[int, int, str, str | None, str | None]]:
        """(scan_id, port, protocol, service, version) rows for one device, newest scan first."""
        return self.conn.execute(
            """
            SELECT scan_id, port, protocol, service, version
            FROM device_ports WHERE identity = ? ORDER BY scan_id DESC, port
            """,
            (identity,),
        ).fetchall()

    def diff_scans(self, a_id: int, b_id: int) -> ScanDiff:
        a = self.scan_ports(a_id)
        b = self.scan_ports(b_id)
        new = tuple(sorted(set(b) - set(a)))
        gone = tuple(sorted(set(a) - set(b)))
        changed = tuple(sorted(k for k in set(a) & set(b) if a[k] != b[k]))
        return ScanDiff(new_devices=new, gone_devices=gone, changed_devices=changed)
