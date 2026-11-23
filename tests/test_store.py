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
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"scans", "devices", "device_ports"} <= tables


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
    assert atom.os_guess == "Linux"
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
    assert atom.os_guess == "Linux"
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
