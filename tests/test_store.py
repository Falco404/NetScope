"""Store tests on temp DBs (pytest tmp_path) — no shared state, no network."""

from pathlib import Path

import pytest

from netscope.scanner.models import HostResult, PortResult, ScanResult
from netscope.scanner.parser import parse_nmap_xml
from netscope.store import SQLiteStore, db_path

FIXTURES = Path(__file__).parent / "fixtures"

TS1 = "2026-11-23T12:00:00+00:00"
TS2 = "2026-11-23T12:10:00+00:00"
TS3 = "2026-11-23T13:00:00+00:00"


def fixture_scan(name: str) -> ScanResult:
    return parse_nmap_xml((FIXTURES / name).read_text(), "192.168.1.0/24")


def scan_single_host(ip: str, port: int) -> ScanResult:
    """One up host with a single open port — used to simulate disappearance."""
    xml = (
        f'<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
        f'<hostname name="{ip}" type="PTR"/>'
        f'<ports><port protocol="tcp" portid="{port}">'
        f'<state state="open"/></port></ports></host></nmaprun>'
    )
    return parse_nmap_xml(xml, "192.168.1.0/24")


@pytest.fixture()
def store(tmp_path):
    with SQLiteStore(tmp_path / "test.db") as s:
        yield s


def test_schema_created_and_versioned(tmp_path):
    path = tmp_path / "test.db"
    with SQLiteStore(path):
        pass
    import sqlite3

    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"scans", "devices", "device_ports", "device_names"} <= tables


def test_v1_database_is_upgraded_in_place(tmp_path):
    """Schema v1 databases gain the device_names table without losing rows."""
    path = tmp_path / "old.db"
    import sqlite3

    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            target TEXT NOT NULL, duration_seconds REAL);
        CREATE TABLE devices (identity TEXT PRIMARY KEY, ip TEXT NOT NULL, hostname TEXT,
            mac TEXT, vendor TEXT, os_guess TEXT, last_seen_scan INTEGER NOT NULL);
        CREATE TABLE device_ports (scan_id INTEGER NOT NULL REFERENCES scans(id),
            identity TEXT NOT NULL REFERENCES devices(identity), ip TEXT NOT NULL,
            port INTEGER NOT NULL, protocol TEXT NOT NULL, service TEXT, version TEXT);
        CREATE INDEX idx_device_ports_scan ON device_ports(scan_id);
        INSERT INTO devices (identity, ip, hostname, last_seen_scan)
        VALUES ('192.168.1.5', '192.168.1.5', 'oldbox', 1);
        """
    )
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()

    with SQLiteStore(path) as s:
        assert s.conn.execute("PRAGMA user_version").fetchone()[0] == 2
        assert s.load_devices()[0].identity == "192.168.1.5"  # old row survives
        assert s.set_device_name("192.168.1.5", "Renamed box") == "Renamed box"
        assert s.load_devices()[0].display_name == "Renamed box"


def test_manual_name_beats_hostname_and_survives_scans(store):
    store.save_scan(fixture_scan("nmap_service.xml"), {}, ts=TS1)
    identity = "AA:BB:CC:DD:EE:01"
    assert store.set_device_name(identity, "Atom homeserver") == "Atom homeserver"

    atom = next(d for d in store.load_devices() if d.identity == identity)
    assert atom.hostname == "atom"  # scan-learned hostname untouched
    assert atom.name == "Atom homeserver"
    assert atom.display_name == "Atom homeserver"

    # A later scan must not overwrite the manual label.
    store.save_scan(fixture_scan("nmap_service.xml"), {}, ts=TS2)
    atom = next(d for d in store.load_devices() if d.identity == identity)
    assert atom.name == "Atom homeserver"
    assert atom.display_name == "Atom homeserver"


def test_clear_device_name_falls_back_to_hostname(store):
    store.save_scan(fixture_scan("nmap_service.xml"), {}, ts=TS1)
    identity = "AA:BB:CC:DD:EE:01"
    store.set_device_name(identity, "Atom homeserver")
    store.clear_device_name(identity)
    atom = next(d for d in store.load_devices() if d.identity == identity)
    assert atom.name is None
    assert atom.display_name == "atom"


def test_device_name_validation(store):
    store.save_scan(fixture_scan("nmap_service.xml"), {}, ts=TS1)
    identity = "AA:BB:CC:DD:EE:01"
    with pytest.raises(ValueError):
        store.set_device_name(identity, "   ")
    with pytest.raises(ValueError):
        store.set_device_name(identity, "x" * 65)
    with pytest.raises(KeyError):
        store.set_device_name("AA:BB:CC:DD:EE:99", "ghost")
    with pytest.raises(KeyError):
        store.clear_device_name("AA:BB:CC:DD:EE:99")
    assert store.set_device_name(identity, "  Atom  ") == "Atom"  # stored stripped


def test_save_load_roundtrip(store):
    scan_id, _ = store.save_scan(
        fixture_scan("nmap_service.xml"), {}, duration_seconds=12.5, ts=TS1
    )

    scans = store.list_scans()
    assert len(scans) == 1
    assert scans[0].id == scan_id
    assert scans[0].target == "192.168.1.0/24"
    assert scans[0].duration_seconds == 12.5

    loaded = store.load_devices()
    assert [d.identity for d in loaded] == ["192.168.1.20", "AA:BB:CC:DD:EE:01"]
    atom = loaded[1]
    assert atom.hostname == "atom"
    assert atom.vendor == "MicroStar Intl"
    assert atom.os_guess == "Linux 2.6.32 - 3.x"
    assert atom.last_seen_scan == scan_id

    ports = store.scan_ports(scan_id)
    assert ports["AA:BB:CC:DD:EE:01"] == frozenset({(22, "tcp"), (80, "tcp")})
    assert ports["192.168.1.20"] == frozenset({(53, "tcp")})


def test_second_scan_updates_devices_without_duplicates(store):
    _, devices = store.save_scan(fixture_scan("nmap_discovery.xml"), {}, ts=TS1)
    scan2, _ = store.save_scan(fixture_scan("nmap_service.xml"), devices, ts=TS2)

    loaded = store.load_devices()
    assert len(loaded) == 2  # same two machines, no forked identities
    atom = next(d for d in loaded if d.hostname == "atom")
    # Identity is stable: MAC from the discovery pass stays the key, OS/hostname
    # absorbed from the service pass.
    assert atom.identity == "AA:BB:CC:DD:EE:01"
    assert atom.mac == "AA:BB:CC:DD:EE:01"
    assert atom.os_guess == "Linux 2.6.32 - 3.x"
    assert atom.last_seen_scan == scan2
    assert store.latest_scan_id() == scan2


def test_diff_new_and_gone_device(store):
    store.save_scan(fixture_scan("nmap_service.xml"), {}, ts=TS1)
    s1 = store.latest_scan_id()
    # Later scan sees only apollo -> atom disappeared, apollo unchanged.
    store.save_scan(scan_single_host("192.168.1.20", 53), {}, ts=TS3)
    s2 = store.latest_scan_id()

    diff = store.diff_scans(s1, s2)
    assert diff.gone_devices == ("AA:BB:CC:DD:EE:01",)
    assert diff.new_devices == ()
    assert diff.changed_devices == ()


def test_diff_changed_port_set(store):
    host = HostResult(
        ip="192.168.1.10",
        up=True,
        hostname="atom",
        mac="AA:BB:CC:DD:EE:01",
        ports=(
            PortResult(port=22, protocol="tcp", state="open", service="ssh"),
            PortResult(port=443, protocol="tcp", state="open", service="https"),
        ),
    )
    store.save_scan(fixture_scan("nmap_service.xml"), {}, ts=TS1)
    s1 = store.latest_scan_id()
    store.save_scan(ScanResult(target="192.168.1.0/24", hosts=(host,)), {}, ts=TS3)
    s2 = store.latest_scan_id()

    diff = store.diff_scans(s1, s2)
    assert diff.changed_devices == ("AA:BB:CC:DD:EE:01",)  # 80 closed, 443 opened
    assert diff.gone_devices == ("192.168.1.20",)


def test_diff_new_device_appears(store):
    store.save_scan(scan_single_host("192.168.1.20", 53), {}, ts=TS1)
    s1 = store.latest_scan_id()
    store.save_scan(fixture_scan("nmap_service.xml"), {}, ts=TS2)
    s2 = store.latest_scan_id()

    diff = store.diff_scans(s1, s2)
    assert diff.new_devices == ("AA:BB:CC:DD:EE:01",)  # atom appeared
    assert diff.gone_devices == ()


def test_db_path_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSCOPE_DB", str(tmp_path / "from-env.db"))
    assert db_path() == str(tmp_path / "from-env.db")
    with SQLiteStore() as s:  # picks up env var, no explicit path
        s.save_scan(scan_single_host("192.168.1.5", 80), {}, ts=TS1)
    assert (tmp_path / "from-env.db").exists()
