"""Store tests on temp DBs (pytest tmp_path) — no shared state, no network."""

import threading
from pathlib import Path

import pytest

import netscope.store.store as store_module
from netscope.device import Device
from netscope.scanner.models import HostResult, PortResult, ScanResult
from netscope.scanner.parser import parse_nmap_xml
from netscope.store import SQLiteStore, db_path

FIXTURES = Path(__file__).parent / "fixtures"

TS1 = "2026-11-23T12:00:00+00:00"
TS2 = "2026-11-23T12:10:00+00:00"
TS3 = "2026-11-23T13:00:00+00:00"


def fixture_scan(name: str) -> ScanResult:
    return parse_nmap_xml((FIXTURES / name).read_text(), "192.168.1.0/24")


def scan_single_host(ip: str, port: int, target: str = "192.168.1.0/24") -> ScanResult:
    """One up host with a single open port — used to simulate disappearance."""
    xml = (
        f'<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
        f'<hostname name="{ip}" type="PTR"/>'
        f'<ports><port protocol="tcp" portid="{port}">'
        f'<state state="open"/></port></ports></host></nmaprun>'
    )
    return parse_nmap_xml(xml, target)


def scan_host_no_ports(ip: str, target: str = "192.168.1.0/24") -> ScanResult:
    """One up host that exposes zero ports (#31: still a sighting)."""
    xml = (
        f'<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
        f'<hostname name="{ip}" type="PTR"/></host></nmaprun>'
    )
    return parse_nmap_xml(xml, target)


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
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"scans", "devices", "device_ports", "device_names", "scan_devices"} <= tables


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
        assert s.conn.execute("PRAGMA user_version").fetchone()[0] == 3
        assert s.load_devices()[0].identity == "192.168.1.5"  # old row survives
        assert s.set_device_name("192.168.1.5", "Renamed box") == "Renamed box"
        assert s.load_devices()[0].display_name == "Renamed box"


def test_v2_database_is_upgraded_in_place(tmp_path):
    """Schema v2 databases gain scan_devices (#31) backfilled from device_ports."""
    path = tmp_path / "v2.db"
    import sqlite3

    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            target TEXT NOT NULL, duration_seconds REAL);
        CREATE TABLE devices (identity TEXT PRIMARY KEY, ip TEXT NOT NULL, hostname TEXT,
            mac TEXT, vendor TEXT, os_guess TEXT, last_seen_scan INTEGER NOT NULL);
        CREATE TABLE device_names (identity TEXT PRIMARY KEY REFERENCES devices(identity),
            name TEXT NOT NULL);
        CREATE TABLE device_ports (scan_id INTEGER NOT NULL REFERENCES scans(id),
            identity TEXT NOT NULL REFERENCES devices(identity), ip TEXT NOT NULL,
            port INTEGER NOT NULL, protocol TEXT NOT NULL, service TEXT, version TEXT);
        CREATE INDEX idx_device_ports_scan ON device_ports(scan_id);
        INSERT INTO scans (id, ts, target) VALUES (1, '2026-11-23T12:00:00+00:00',
            '192.168.1.0/24');
        INSERT INTO devices (identity, ip, last_seen_scan) VALUES ('192.168.1.7',
            '192.168.1.7', 1);
        INSERT INTO device_ports (scan_id, identity, ip, port, protocol)
        VALUES (1, '192.168.1.7', '192.168.1.7', 80, 'tcp');
        """
    )
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()

    with SQLiteStore(path) as s:
        assert s.conn.execute("PRAGMA user_version").fetchone()[0] == 3
        # Every stored port row implies a sighting: old scans keep presence data.
        assert s.sightings(1) == {"192.168.1.7": "192.168.1.7"}
        assert s.scan_target(1) == "192.168.1.0/24"


def test_up_host_without_ports_is_sighted(store):
    """#31 bug 1: an up host with zero open ports is present, not absent."""
    scan_id, _ = store.save_scan(scan_host_no_ports("192.168.1.30"), {}, ts=TS1)

    assert store.sightings(scan_id) == {"192.168.1.30": "192.168.1.30"}
    assert [d.identity for d in store.devices_in_scan(scan_id)] == ["192.168.1.30"]
    assert store.scan_ports(scan_id) == {}  # no ports, yet still sighted

    dev = store.load_devices()[0]
    assert dev.identity == "192.168.1.30"
    assert dev.open_ports == ()
    assert dev.last_seen_scan == scan_id


def test_absent_device_keeps_last_seen_scan(store):
    """#31 bug 2: a device NOT in this scan keeps its previous last_seen_scan."""
    _, devices = store.save_scan(fixture_scan("nmap_service.xml"), {}, ts=TS1)
    s1 = store.latest_scan_id()
    # Second scan covers the same /24 but only apollo answers.
    store.save_scan(scan_single_host("192.168.1.20", 53), devices, ts=TS3)

    atom = next(d for d in store.load_devices() if d.identity == "AA:BB:CC:DD:EE:01")
    assert atom.last_seen_scan == s1  # NOT stamped with the scan that missed it
    apollo = next(d for d in store.load_devices() if d.identity == "192.168.1.20")
    assert apollo.last_seen_scan == store.latest_scan_id()


def test_diff_ignores_scans_of_other_target(store):
    """#31 bug 3: a single-IP scan must not report devices outside its target
    as disappeared or new."""
    store.save_scan(fixture_scan("nmap_service.xml"), {}, ts=TS1)  # atom + apollo
    s1 = store.latest_scan_id()
    # /32 scan of apollo only — atom was never in scope for this scan.
    store.save_scan(scan_single_host("192.168.1.20", 53, target="192.168.1.20/32"), {}, ts=TS3)
    s2 = store.latest_scan_id()

    diff = store.diff_scans(s1, s2)
    assert diff.gone_devices == ()  # atom not covered by the /32 target
    assert diff.new_devices == ()
    assert diff.changed_devices == ()  # apollo's port set is identical


def test_diff_counts_portless_sightings(store):
    """#31: appeared/disappeared come from sightings, so a portless up host
    appearing in b counts as new (and vanishing counts as gone)."""
    store.save_scan(scan_single_host("192.168.1.20", 53), {}, ts=TS1)
    s1 = store.latest_scan_id()
    store.save_scan(scan_host_no_ports("192.168.1.30"), {}, ts=TS3)
    s2 = store.latest_scan_id()

    diff = store.diff_scans(s1, s2)
    assert diff.new_devices == ("192.168.1.30",)  # up, zero ports, still new
    assert diff.gone_devices == ("192.168.1.20",)


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


def known_map(store) -> dict[str, Device]:
    """The dict the API passes to save_scan: currently known devices by identity."""
    return {d.identity: d for d in store.load_devices()}


def test_rekey_migrates_name_ports_and_sightings(store):
    # #35: scan 1 (unprivileged) keys the machine by IP; scan 2 (privileged)
    # learns its MAC. Every DB row must follow the machine to the MAC key.
    store.save_scan(scan_single_host("192.168.1.10", 22), {}, ts=TS1)
    store.set_device_name("192.168.1.10", "Atom")

    scan2 = parse_nmap_xml(
        '<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>'
        '<address addr="AA:BB:CC:DD:EE:01" addrtype="mac"/></host></nmaprun>',
        "192.168.1.0/24",
    )
    store.save_scan(scan2, known_map(store), ts=TS2)

    devices = store.load_devices()
    assert [d.identity for d in devices] == ["AA:BB:CC:DD:EE:01"], "old IP key must be gone"
    atom = devices[0]
    assert atom.name == "Atom", "manual label migrated"
    assert atom.mac == "AA:BB:CC:DD:EE:01"
    assert atom.last_seen_scan == 2

    # scan 1's port row migrated to the new key; nothing left under the old one
    assert store.port_history("AA:BB:CC:DD:EE:01") == [(1, 22, "tcp", None, None)]
    assert store.port_history("192.168.1.10") == []
    # sightings of BOTH scans now live under the MAC key
    assert store.sightings(1) == {"AA:BB:CC:DD:EE:01": "192.168.1.10"}
    assert store.sightings(2) == {"AA:BB:CC:DD:EE:01": "192.168.1.10"}


def test_conflicting_mac_stays_separate_in_store(store):
    # #35 bug 2: a legacy DB row keyed by IP but already carrying a MAC.
    # A different machine answering at the same IP must become its own device.
    store.save_scan(scan_single_host("192.168.1.10", 22), {}, ts=TS1)
    store.conn.execute(
        "UPDATE devices SET mac = 'AA:BB:CC:DD:EE:01' WHERE identity = '192.168.1.10'"
    )
    store.conn.commit()

    scan2 = parse_nmap_xml(
        '<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>'
        '<address addr="FF:AA:BB:CC:DD:EE" addrtype="mac"/></host></nmaprun>',
        "192.168.1.0/24",
    )
    store.save_scan(scan2, known_map(store), ts=TS2)

    devices = store.load_devices()
    assert [d.identity for d in devices] == ["192.168.1.10", "FF:AA:BB:CC:DD:EE"]
    old = devices[0]
    assert old.mac == "AA:BB:CC:DD:EE:01", "stored MAC not overwritten"
    assert old.last_seen_scan == 1, "old machine not sighted in scan 2"
    assert store.sightings(2) == {"FF:AA:BB:CC:DD:EE": "192.168.1.10"}


# --- #37: one SQLite connection shared across threads ---
# merge_scan is the seam inside save_scan's transaction: the `scans` row is
# already inserted there, no device row is yet. A barrier there makes the race
# deterministic instead of timing-dependent.


def test_reader_never_sees_half_written_scan(tmp_path, monkeypatch):
    """A request thread must not observe a scan row without its devices."""
    store = SQLiteStore(tmp_path / "race.db")
    result = scan_single_host("192.168.1.10", 22)
    inside = threading.Barrier(2, timeout=5)
    resume = threading.Barrier(2, timeout=5)

    real_merge = store_module.merge_scan

    def merge_and_pause(*args, **kwargs):
        out = real_merge(*args, **kwargs)
        inside.wait()  # writer parked with its transaction still open
        resume.wait()
        return out

    monkeypatch.setattr(store_module, "merge_scan", merge_and_pause)
    writer = threading.Thread(target=store.save_scan, args=(result, {}))
    writer.start()

    inside.wait()
    scan_id = store.latest_scan_id()
    sighted = store.devices_in_scan(scan_id) if scan_id is not None else []
    resume.wait()
    writer.join()

    assert scan_id is None or sighted, (
        f"reader saw scan {scan_id} with {len(sighted)} devices — half-written scan"
    )


def test_name_write_cannot_commit_a_partial_scan(tmp_path, monkeypatch):
    """`set_device_name` commits on its own; it must not commit another thread's
    half-written `save_scan` (issue #37)."""
    store = SQLiteStore(tmp_path / "race.db")
    store.save_scan(scan_single_host("192.168.1.10", 22), {}, ts=TS1)

    inside = threading.Barrier(2, timeout=5)
    resume = threading.Barrier(2, timeout=1)  # times out: the scan gives up

    real_merge = store_module.merge_scan

    def merge_then_boom(*args, **kwargs):
        real_merge(*args, **kwargs)
        inside.wait()
        try:
            resume.wait()
        except Exception:  # BarrierTimeout: the parked scan write gives up
            pass
        raise RuntimeError("simulated mid-scan failure")

    monkeypatch.setattr(store_module, "merge_scan", merge_then_boom)

    def run_failing_scan() -> None:
        try:
            store.save_scan(scan_single_host("192.168.1.11", 80), {})
        except RuntimeError:
            pass  # the scan write failed on purpose; only its rollback matters

    writer = threading.Thread(target=run_failing_scan)
    writer.start()

    inside.wait()
    # The name-write must wait for the scan transaction to end, not slip a
    # commit into it: it can only finish once the scan has failed and rolled back.
    name_thread = threading.Thread(target=lambda: store.set_device_name("192.168.1.10", "lab"))
    name_thread.start()
    name_thread.join(timeout=10)
    writer.join()

    assert not name_thread.is_alive(), "name-write deadlocked behind the scan write"
    assert len(store.list_scans()) == 1, "failed scan left a half-written row behind"
    named = store.conn.execute(
        "SELECT name FROM device_names WHERE identity = '192.168.1.10'"
    ).fetchone()
    assert named == ("lab",), "name-write lost while waiting"


def test_each_thread_gets_its_own_connection(tmp_path):
    store = SQLiteStore(tmp_path / "own.db")
    ids: list[int] = []

    def grab() -> None:
        ids.append(id(store.conn))

    thread = threading.Thread(target=grab)
    thread.start()
    thread.join()
    assert len(ids) == 1 and ids[0] != id(store.conn)
    assert store.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def sinkhole_scan() -> ScanResult:
    """Two distinct machines whose reverse-DNS name is identical.

    On Falco's LAN nmap's PTR lookup returned `blocked.local` for nine
    different IPs (the local resolver answers every PTR query with the same
    name — a DNS sinkhole), so the Devices table showed `blocked.local`
    nine times and the diff said `blocked.local appeared` twice.
    """
    return ScanResult(
        target="192.168.0.0/24",
        hosts=(
            HostResult(
                ip="192.168.0.5",
                up=True,
                hostname="blocked.local",
                mac_vendor="Google",
                ports=(PortResult(port=8008, protocol="tcp", state="open"),),
            ),
            HostResult(
                ip="192.168.0.6",
                up=True,
                hostname="blocked.local",
                mac_vendor="Frontier Silicon",
                ports=(PortResult(port=80, protocol="tcp", state="open"),),
            ),
        ),
    )


def test_ambiguous_hostname_is_not_used_as_label(store):
    """A hostname shared by several devices cannot label any of them: the
    display must fall through to vendor+IP / bare IP instead of showing
    `blocked.local` for every row."""
    store.save_scan(sinkhole_scan(), {}, ts=TS1)
    devs = {d.identity: d for d in store.load_devices()}
    assert set(devs) == {"192.168.0.5", "192.168.0.6"}
    for d in devs.values():
        assert d.hostname is None, "shared hostname must not survive as a label"
    assert devs["192.168.0.5"].display_name == "Google device (192.168.0.5)"
    assert devs["192.168.0.6"].display_name == "Frontier Silicon device (192.168.0.6)"


def test_unique_hostname_still_labels(store):
    """Regression guard: a PTR name belonging to exactly one device is
    still the best label (atom/apollo in the service fixture)."""
    store.save_scan(fixture_scan("nmap_service.xml"), {}, ts=TS1)
    devs = store.load_devices()
    assert {d.display_name for d in devs} == {"atom", "apollo"}
    assert {d.hostname for d in devs} == {"atom", "apollo"}


def test_manual_name_beats_ambiguous_hostname(store):
    """A deliberate label survives even when the hostname is suppressed."""
    store.save_scan(sinkhole_scan(), {}, ts=TS1)
    store.set_device_name("192.168.0.5", "NAS")
    devs = {d.identity: d for d in store.load_devices()}
    assert devs["192.168.0.5"].display_name == "NAS"
    assert devs["192.168.0.6"].display_name == "Frontier Silicon device (192.168.0.6)"


def test_scan_exists(tmp_path):
    """#38: the API needs to tell "no such scan" apart from "nothing changed"."""
    store = SQLiteStore(tmp_path / "exists.db")
    assert not store.scan_exists(1)
    store.save_scan(fixture_scan("nmap_discovery.xml"), {}, ts=TS1)
    assert store.scan_exists(1)
    assert not store.scan_exists(2)
