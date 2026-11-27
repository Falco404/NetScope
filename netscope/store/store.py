"""SQLite persistence: scan history, device rows, per-scan ports, diff.

DB path comes from NETSCOPE_DB (env var) — never committed; default is a
gitignored file. Schema version lives in PRAGMA user_version; bump it and
extend `_SCHEMA` if the shape changes (no migration framework at this stage).
"""

from __future__ import annotations

import ipaddress
import os
import sqlite3
import threading
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from netscope.device import Device, merge_scan
from netscope.scanner.models import ScanResult

SCHEMA_VERSION = 4
DEFAULT_DB_PATH = "netscope.db"


def _suppress_ambiguous_hostnames(devices: list[Device]) -> list[Device]:
    """Drop hostnames that several devices share (#38, `blocked.local`).

    nmap's reverse-DNS (PTR) name is only a label when it identifies ONE
    machine. On Falco's LAN the local resolver answered every PTR query with
    `blocked.local` (a DNS sinkhole — e.g. a Pi-hole on Atom), so nine
    devices carried the same "hostname": the Devices table showed it nine
    times and the diff said `blocked.local appeared` twice with no way to
    tell which host. A name shared by two identities is a resolver artifact,
    never a machine name, so it is suppressed at read time and
    ``display_name`` falls through its chain to vendor+IP / bare IP.
    The DB row keeps the raw hostname (nothing is rewritten), so a later
    scan that resolves a unique name still wins via the merge COALESCE.
    """
    counts = Counter(d.hostname for d in devices if d.hostname)
    return [
        replace(d, hostname=None) if d.hostname and counts[d.hostname] > 1 else d
        for d in devices
    ]

_SCHEMA = """
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,               -- ISO-8601 UTC
    target TEXT NOT NULL,
    duration_seconds REAL,
    mode TEXT NOT NULL DEFAULT 'deep'  -- 'quick' = discovery only, 'deep' = ports/OS too (#39)
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
CREATE TABLE device_names (
    identity TEXT PRIMARY KEY REFERENCES devices(identity),
    name TEXT NOT NULL              -- manual label set in the UI, beats any scan
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
CREATE TABLE scan_devices (
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    identity TEXT NOT NULL REFERENCES devices(identity),
    ip TEXT NOT NULL,               -- presence: this identity responded in this scan (#31)
    PRIMARY KEY (scan_id, identity)
);
CREATE INDEX idx_device_ports_scan ON device_ports(scan_id);
CREATE INDEX idx_scan_devices_scan ON scan_devices(scan_id);
"""

# Added in schema v2 (M8): exists on its own so v1 databases can be upgraded
# in place without touching existing rows.
_DEVICE_NAMES_TABLE = """
CREATE TABLE IF NOT EXISTS device_names (
    identity TEXT PRIMARY KEY REFERENCES devices(identity),
    name TEXT NOT NULL              -- manual label set in the UI, beats any scan
);
"""

# Added in schema v3 (#31): presence is a sighting, not an open port. Older
# databases backfill from device_ports — best effort: a device that was up
# with zero ports in an old scan cannot be recovered, but every stored port
# row implies a sighting.
_SCAN_DEVICES_TABLE = """
CREATE TABLE IF NOT EXISTS scan_devices (
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    identity TEXT NOT NULL REFERENCES devices(identity),
    ip TEXT NOT NULL,
    PRIMARY KEY (scan_id, identity)
);
CREATE INDEX IF NOT EXISTS idx_scan_devices_scan ON scan_devices(scan_id);
"""
_BACKFILL_SCAN_DEVICES = """
INSERT OR IGNORE INTO scan_devices (scan_id, identity, ip)
SELECT DISTINCT scan_id, identity, ip FROM device_ports;
"""

# Added in schema v4 (#39): a scan records whether it was discovery-only.
# Existing rows default to 'deep' — every scan before #39 ran the service
# pass, so that is the truthful backfill and no separate UPDATE is needed.
_SCANS_MODE_COLUMN = "ALTER TABLE scans ADD COLUMN mode TEXT NOT NULL DEFAULT 'deep'"


def db_path() -> str:
    return os.environ.get("NETSCOPE_DB", DEFAULT_DB_PATH)


def _ip_in_target(ip: str, target: str) -> bool:
    """True if ip lies inside the CIDR target (False if either is unparseable)."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False


@dataclass(frozen=True)
class ScanSummary:
    id: int
    ts: str
    target: str
    duration_seconds: float | None
    mode: str = "deep"  # #39: 'quick' (discovery only) | 'deep'


@dataclass(frozen=True)
class ScanDiff:
    """Difference between two stored scans, by sightings (#31): identities
    sighted in b but not a, sighted in a but not b, sighted in both with a
    different open-port set. Only devices inside both scans' targets count."""

    new_devices: tuple[str, ...]  # identity keys sighted in b but not a
    gone_devices: tuple[str, ...]  # sighted in a but not b
    changed_devices: tuple[str, ...]  # in both, port set differs


class SQLiteStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or db_path()
        # #37: one connection PER THREAD. A single shared connection means every
        # request thread reads — and can commit — the scan thread's open
        # transaction, so `set_device_name` could commit a half-written
        # `save_scan`. check_same_thread=False stays because close() runs on a
        # different thread than the one that opened some connections.
        self._local = threading.local()
        self._conns: list[sqlite3.Connection] = []
        self._write_lock = threading.Lock()
        conn = self.conn
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            conn.executescript(_SCHEMA)
        elif version < SCHEMA_VERSION:
            # In-place upgrades: v1 databases get device_names (M8), every
            # database older than v3 gets scan_devices (#31) backfilled from
            # device_ports so stored scans keep their presence data, and every
            # database older than v4 gets `scans.mode` (#39) defaulting to
            # 'deep' — every scan before #39 ran the service pass.
            if version < 2:
                conn.executescript(_DEVICE_NAMES_TABLE)
            if version < 3:
                conn.executescript(_SCAN_DEVICES_TABLE)
                conn.executescript(_BACKFILL_SCAN_DEVICES)
            if version < 4:
                conn.execute(_SCANS_MODE_COLUMN)
        if version != SCHEMA_VERSION:
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        # foreign_keys/journal_mode/busy_timeout are per-connection settings, so
        # every thread's connection needs them. WAL lets readers run while the
        # scan thread writes; busy_timeout turns a brief writer collision into
        # a wait instead of an OperationalError.
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        self._restrict_permissions()
        self._conns.append(conn)
        return conn

    def _restrict_permissions(self) -> None:
        """Make the DB (and its WAL sidecars) owner-only (#security).

        The file is a ready-made target list — every MAC, IP, hostname, open
        port and service version on the LAN — and sqlite3 creates it with the
        process umask (0644 on the usual 022). Windows uses ACLs, and chmod
        there only toggles the read-only bit, so this is POSIX-only.
        """
        if os.name != "posix":
            return
        path = os.fspath(self.path)
        if not path or path == ":memory:" or path.startswith("file:"):
            return
        for suffix in ("", "-wal", "-shm"):
            try:
                os.chmod(path + suffix, 0o600)
            except FileNotFoundError:
                pass  # sidecars appear once WAL mode has written something

    @property
    def conn(self) -> sqlite3.Connection:
        """This thread's connection, created on first use."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    def close(self) -> None:
        for conn in self._conns:
            conn.close()
        self._conns.clear()

    def __enter__(self) -> "SQLiteStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def _write_txn(self) -> Iterator[None]:
        """Serialize writers and end the transaction cleanly (#37).

        Without the rollback, a failed write leaves an open transaction on that
        thread's connection: the uncommitted rows block every other writer until
        busy_timeout gives up, and a later commit on that connection would
        publish them.
        """
        with self._write_lock:
            try:
                yield
            except BaseException:
                self.conn.rollback()
                raise

    def save_scan(
        self,
        result: ScanResult,
        devices: dict[str, Device],
        duration_seconds: float | None = None,
        ts: str | None = None,
    ) -> tuple[int, dict[str, Device]]:
        """Persist one scan + update device rows. Returns (scan_id, merged devices).

        All writes share one lock (#37): with per-thread connections two
        concurrent writers would otherwise interleave transactions and can hit
        SQLITE_BUSY. Readers never take the lock — WAL gives each of them a
        consistent snapshot of committed data while a scan write is open.
        """
        with self._write_txn():
            return self._write_scan(result, devices, duration_seconds, ts)

    def _write_scan(
        self,
        result: ScanResult,
        devices: dict[str, Device],
        duration_seconds: float | None = None,
        ts: str | None = None,
    ) -> tuple[int, dict[str, Device]]:
        ts = ts or datetime.now(UTC).isoformat()
        cur = self.conn.execute(
            "INSERT INTO scans (ts, target, duration_seconds, mode) VALUES (?, ?, ?, ?)",
            (ts, result.target, duration_seconds, result.mode),
        )
        scan_id = int(cur.lastrowid or 0)

        merged, rekeys = merge_scan(devices, result.hosts, scan_id=scan_id)

        # #35: an IP-keyed device that just learned its MAC re-keys. Migrate
        # its rows (manual name, port history, sightings) BEFORE the upserts
        # below, in the same transaction as the scan write, so history follows
        # the machine instead of orphaning under the old IP key.
        for old_identity, new_identity in rekeys:
            self._rekey_identity(old_identity, new_identity)

        # Presence is a sighting (#31): every host that responded to THIS scan
        # gets a scan_devices row, even with zero open ports. Resolve each up
        # host to the identity merge_scan keyed it under (MAC if the device
        # already has one, else IP) so a sighting never forks or misses a row.
        sighted: dict[str, Device] = {}
        for host in result.hosts:
            if not host.up:
                continue
            mac = host.mac.upper() if host.mac else None
            for candidate in (mac, host.ip):
                if candidate is not None and candidate in merged:
                    sighted[candidate] = merged[candidate]
                    break

        # Only sighted devices touch the devices table: a device absent from
        # this scan keeps its previous last_seen_scan (#31 bug 2).
        for identity, device in sighted.items():
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
            self.conn.execute(
                "INSERT INTO scan_devices (scan_id, identity, ip) VALUES (?, ?, ?)",
                (scan_id, identity, device.ip),
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

    def _rekey_identity(self, old: str, new: str) -> None:
        """Move a device row from an IP key to its MAC key (#35).

        Order matters with ``PRAGMA foreign_keys = ON``: create the new parent
        first so child updates never dangle, migrate children, then drop the
        old parent. Runs inside save_scan's transaction, so a failure rolls
        the whole scan write back.
        """
        self.conn.execute(
            """
            INSERT INTO devices (identity, ip, hostname, mac, vendor, os_guess, last_seen_scan)
            SELECT ?, ip, hostname, ?, vendor, os_guess, last_seen_scan
            FROM devices WHERE identity = ?
            """,
            (new, new, old),
        )
        self.conn.execute("UPDATE device_ports SET identity = ? WHERE identity = ?", (new, old))
        self.conn.execute("UPDATE scan_devices SET identity = ? WHERE identity = ?", (new, old))
        self.conn.execute(
            """
            INSERT OR IGNORE INTO device_names (identity, name)
            SELECT ?, name FROM device_names WHERE identity = ?
            """,
            (new, old),
        )
        self.conn.execute("DELETE FROM device_names WHERE identity = ?", (old,))
        self.conn.execute("DELETE FROM devices WHERE identity = ?", (old,))

    def list_scans(self) -> list[ScanSummary]:
        rows = self.conn.execute(
            "SELECT id, ts, target, duration_seconds, mode FROM scans ORDER BY id DESC"
        ).fetchall()
        return [
            ScanSummary(id=r[0], ts=r[1], target=r[2], duration_seconds=r[3], mode=r[4])
            for r in rows
        ]

    def latest_scan_id(self) -> int | None:
        row = self.conn.execute("SELECT MAX(id) FROM scans").fetchone()
        return row[0]

    def load_devices(self) -> list[Device]:
        rows = self.conn.execute(
            """
            SELECT d.identity, d.ip, d.hostname, d.mac, d.vendor, d.os_guess,
                   d.last_seen_scan, n.name
            FROM devices d
            LEFT JOIN device_names n ON n.identity = d.identity
            ORDER BY d.identity
            """
        ).fetchall()
        return _suppress_ambiguous_hostnames(
            [
                Device(
                    identity=r[0],
                    ip=r[1],
                    hostname=r[2],
                    mac=r[3],
                    vendor=r[4],
                    os_guess=r[5],
                    last_seen_scan=r[6],
                    name=r[7],
                )
                for r in rows
            ]
        )

    def devices_in_scan(self, scan_id: int) -> list[Device]:
        """Devices sighted (up) in this scan — ports are irrelevant (#31)."""
        rows = self.conn.execute(
            """
            SELECT DISTINCT d.identity, d.ip, d.hostname, d.mac, d.vendor, d.os_guess, n.name
            FROM devices d
            LEFT JOIN device_names n ON n.identity = d.identity
            JOIN scan_devices sd ON sd.identity = d.identity AND sd.scan_id = ?
            ORDER BY d.identity
            """,
            (scan_id,),
        ).fetchall()

        return _suppress_ambiguous_hostnames(
            [
                Device(
                    identity=r[0],
                    ip=r[1],
                    hostname=r[2],
                    mac=r[3],
                    vendor=r[4],
                    os_guess=r[5],
                    name=r[6],
                )
                for r in rows
            ]
        )

    def scan_ports(self, scan_id: int) -> dict[str, frozenset[tuple[int, str]]]:
        """identity -> set of (port, protocol) open in this scan."""
        rows = self.conn.execute(
            "SELECT identity, port, protocol FROM device_ports WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        out: dict[str, set[tuple[int, str]]] = {}
        for identity, port, protocol in rows:
            out.setdefault(identity, set()).add((port, protocol))
        return {k: frozenset(v) for k, v in out.items()}

    def scan_port_details(
        self, scan_id: int
    ) -> dict[str, list[tuple[int, str, str | None, str | None]]]:
        """identity -> [(port, protocol, service, version)] open in ONE scan.

        #43: the export needs the service/version nmap found, which
        `scan_ports` drops (it only answers "which ports are open"). Same rows,
        same scan, so an export can never show a port the UI does not.
        """
        rows = self.conn.execute(
            """
            SELECT identity, port, protocol, service, version
            FROM device_ports WHERE scan_id = ? ORDER BY port, protocol
            """,
            (scan_id,),
        ).fetchall()
        out: dict[str, list[tuple[int, str, str | None, str | None]]] = {}
        for identity, port, protocol, service, version in rows:
            out.setdefault(identity, []).append((port, protocol, service, version))
        return out

    def port_history(self, identity: str) -> list[tuple[int, int, str, str | None, str | None]]:
        """(scan_id, port, protocol, service, version) rows for one device, newest scan first."""
        return self.conn.execute(
            """
            SELECT scan_id, port, protocol, service, version
            FROM device_ports WHERE identity = ? ORDER BY scan_id DESC, port
            """,
            (identity,),
        ).fetchall()

    def sightings(self, scan_id: int) -> dict[str, str]:
        """identity -> ip for every device sighted (up) in this scan (#31)."""
        rows = self.conn.execute(
            "SELECT identity, ip FROM scan_devices WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return dict(rows)

    def scan_target(self, scan_id: int) -> str | None:
        row = self.conn.execute("SELECT target FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return row[0] if row is not None else None

    def scan_mode(self, scan_id: int) -> str | None:
        """'quick' | 'deep' for a stored scan, None for an unknown id (#39)."""
        row = self.conn.execute("SELECT mode FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return row[0] if row is not None else None

    def scan_exists(self, scan_id: int) -> bool:
        """Is this scan id stored at all? (#38: the API must tell "no such
        scan" apart from "nothing changed" — an unknown id otherwise diffs
        two empty sighting sets and answers 200 with three empty lists.)"""
        return (
            self.conn.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone()
            is not None
        )

    def latest_scan_covering(self, ip: str) -> int | None:
        """Newest stored scan whose target contains this IP (None if none).

        Presence for a device is judged against the latest scan that could
        have seen it — a single-IP scan of another device says nothing about
        this one (#31).
        """
        for s in self.list_scans():  # newest first
            if _ip_in_target(ip, s.target):
                return s.id
        return None

    def diff_scans(self, a_id: int, b_id: int) -> ScanDiff:
        """Diff two scans by *sightings*, not ports (#31).

        A device is gone only if it was sighted in a and not in b, and only
        when its IP falls inside BOTH scans' targets — a single-IP scan after
        a /24 must not report every other device as disappeared or new.

        "changed" is a port-set comparison and is therefore only meaningful
        when BOTH scans probed ports (#39): a quick scan has no port data at
        all, so comparing it would report every sighted device as "changed
        open ports" (deep -> quick) or as newly opened (quick -> deep).
        Appeared/disappeared still work for any mode — that is what a quick
        scan contributes.
        """
        sa, sb = self.sightings(a_id), self.sightings(b_id)
        ta, tb = self.scan_target(a_id), self.scan_target(b_id)

        def covered(ip: str) -> bool:
            return (
                ta is not None
                and tb is not None
                and _ip_in_target(ip, ta)
                and _ip_in_target(ip, tb)
            )

        new = tuple(sorted(i for i in sb.keys() - sa.keys() if covered(sb[i])))
        gone = tuple(sorted(i for i in sa.keys() - sb.keys() if covered(sa[i])))
        if self.scan_mode(a_id) != "deep" or self.scan_mode(b_id) != "deep":
            changed: tuple[str, ...] = ()
        else:
            ports_a, ports_b = self.scan_ports(a_id), self.scan_ports(b_id)
            changed = tuple(
                sorted(
                    i
                    for i in sa.keys() & sb.keys()
                    if ports_a.get(i, frozenset()) != ports_b.get(i, frozenset())
                )
            )
        return ScanDiff(new_devices=new, gone_devices=gone, changed_devices=changed)

    MAX_NAME_LEN = 64

    def set_device_name(self, identity: str, name: str) -> str:
        """Set a manual label on a known device (M8).

        Raises KeyError for an unknown identity, ValueError for a blank or
        over-long name. Returns the stored (stripped) name.
        """
        name = name.strip()
        if not name:
            raise ValueError("device name must not be empty")
        if len(name) > self.MAX_NAME_LEN:
            raise ValueError(f"device name must be at most {self.MAX_NAME_LEN} characters")
        with self._write_txn():
            if (
                self.conn.execute(
                    "SELECT 1 FROM devices WHERE identity = ?", (identity,)
                ).fetchone()
                is None
            ):
                raise KeyError(identity)
            self.conn.execute(
                """
                INSERT INTO device_names (identity, name) VALUES (?, ?)
                ON CONFLICT(identity) DO UPDATE SET name = excluded.name
                """,
                (identity, name),
            )
            self.conn.commit()
        return name

    def clear_device_name(self, identity: str) -> None:
        """Remove a manual label; display falls back to hostname/vendor/IP."""
        with self._write_txn():
            if (
                self.conn.execute(
                    "SELECT 1 FROM devices WHERE identity = ?", (identity,)
                ).fetchone()
                is None
            ):
                raise KeyError(identity)
            self.conn.execute("DELETE FROM device_names WHERE identity = ?", (identity,))
            self.conn.commit()
