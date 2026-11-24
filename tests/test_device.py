"""Device identity tests driven by the recorded fixtures — zero network/DNS."""

from pathlib import Path

from netscope.device import Device, device_from_host, merge_scan
from netscope.scanner.parser import parse_nmap_xml
from netscope.vendor_registry import vendor_from_mac

FIXTURES = Path(__file__).parent / "fixtures"


def _hosts(name: str):
    return parse_nmap_xml((FIXTURES / name).read_text(), "192.168.1.0/24").hosts


def test_resolution_from_service_fixture():
    devices = [device_from_host(h) for h in _hosts("nmap_service.xml")]
    atom, apollo = devices

    assert atom.identity == "AA:BB:CC:DD:EE:01"  # MAC, not IP
    assert atom.hostname == "atom"
    assert atom.os_guess == "Linux 2.6.32 - 3.x"
    assert atom.vendor == "MicroStar Intl"
    assert atom.display_name == "atom"
    # closed 443 must not appear
    assert [p.port for p in atom.open_ports] == [22, 80]


def test_identity_falls_back_to_ip_without_mac():
    devices = [device_from_host(h) for h in _hosts("nmap_discovery.xml")]
    apollo = devices[1]
    assert apollo.identity == "192.168.1.20"
    assert apollo.display_name == "192.168.1.20"


def test_vendor_registry_fallback_and_normalization():
    assert vendor_from_mac("3c:07:59:aa:bb:cc") == "Intel"  # lowercase ok
    assert vendor_from_mac("3C-07-59-AA-BB-CC") == "Intel"  # dashes ok
    assert vendor_from_mac("FF:FF:FF:FF:FF:FF") is None  # unknown


def test_dedup_across_two_scans():
    # Scan 1: discovery only -> devices keyed by IP (no MAC yet).
    known = merge_scan({}, _hosts("nmap_discovery.xml"), scan_id=1)
    assert len(known) == 2  # down host excluded? -> see note below

    # Scan 2: service pass reveals MAC + hostname + OS for the same machines.
    known = merge_scan(known, _hosts("nmap_service.xml"), scan_id=2)
    assert len(known) == 2, "same machines must not fork into new identities"

    atom = known["AA:BB:CC:DD:EE:01"]
    assert atom.hostname == "atom"
    assert atom.os_guess == "Linux 2.6.32 - 3.x"
    assert atom.last_seen_scan == 2

    # Apollo had no MAC in either scan: stays keyed by IP, hostname absorbed.
    apollo = known["192.168.1.20"]
    assert apollo.hostname == "apollo"
    assert apollo.mac is None
    assert apollo.last_seen_scan == 2


def test_down_hosts_are_not_devices():
    # merge_scan keeps only up hosts; a down host is not a device sighting.
    hosts = tuple(h for h in _hosts("nmap_discovery.xml") if h.up)
    known = merge_scan({}, hosts, scan_id=1)
    assert [d.ip for d in known.values()] == ["192.168.1.10", "192.168.1.20"]


def test_existing_device_keeps_fields_when_scan2_has_less():
    seed = {
        "AA:BB:CC:DD:EE:01": Device(
            identity="AA:BB:CC:DD:EE:01",
            ip="192.168.1.10",
            hostname="atom",
            mac="AA:BB:CC:DD:EE:01",
            os_guess="Linux 2.6.32 - 3.x",
        )
    }
    bare = parse_nmap_xml(
        '<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>'
        "<address addr=\"AA:BB:CC:DD:EE:01\" addrtype=\"mac\"/></host></nmaprun>",
        "192.168.1.0/24",
    ).hosts
    merged = merge_scan(seed, bare, scan_id=3)
    atom = merged["AA:BB:CC:DD:EE:01"]
    assert atom.hostname == "atom"  # kept, empty scan didn't blank it
    assert atom.os_guess == "Linux 2.6.32 - 3.x"  # kept
    assert atom.open_ports == ()  # ports are a fresh snapshot
    assert atom.last_seen_scan == 3
