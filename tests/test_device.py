"""Device identity tests driven by the recorded fixtures — zero network/DNS."""

from pathlib import Path

from netscope.device import Device, device_from_host, merge_scan
from netscope.scanner.models import HostResult, PortResult
from netscope.scanner.parser import parse_nmap_xml
from netscope.vendor_registry import OUI_VENDORS, vendor_from_mac

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
    assert vendor_from_mac("b8:27:eb:11:22:33") == "Raspberry Pi Foundation"  # lowercase ok
    assert vendor_from_mac("B8-27-EB-11-22-33") == "Raspberry Pi Foundation"  # dashes ok
    assert vendor_from_mac("FF:FF:FF:FF:FF:FF") is None  # unknown


def test_shipped_registry_contains_no_lab_only_prefixes():
    """#38: the table shipped `AA:BB:CC -> MicroStar Intl`, but that prefix only
    exists in our recorded fixtures and the vendor name was made up for them.
    A real device whose MAC happens to start with AA:BB:CC would be labelled
    with a company that never manufactured it."""
    assert "AA:BB:CC" not in OUI_VENDORS
    assert vendor_from_mac("AA:BB:CC:DD:EE:01") is None


def test_shipped_prefixes_match_the_oui_registrations():
    """Each shipped prefix must resolve to the company the IEEE OUI registry
    actually assigns it (checked against uic.io on 2026-11-25). Three of the
    old entries did not: `00:0C:AC` is Citizen Watch, not Dell; `A4:50:55` is
    BUSWARE.DE, not Apple; `E0:37:BF` is WNC Corporation, not Microsoft."""
    assert vendor_from_mac("00:0C:AC:11:22:33") == "Citizen Watch Co., Ltd."
    assert vendor_from_mac("A4:50:55:11:22:33") == "BUSWARE.DE"
    assert vendor_from_mac("B8:27:EB:11:22:33") == "Raspberry Pi Foundation"
    assert vendor_from_mac("DC:A6:32:11:22:33") == "Raspberry Pi Trading Ltd"
    assert vendor_from_mac("E0:37:BF:11:22:33") == "WNC Corporation"


def test_unverified_prefixes_are_not_shipped():
    """`3C:07:59` was labelled Intel but has no OUI registration in either
    source checked, so it must not ship at all: an unverified prefix is worse
    than no prefix."""
    assert "3C:07:59" not in OUI_VENDORS
    assert vendor_from_mac("3C:07:59:AA:BB:CC") is None


def test_device_without_vendor_attribute_gets_no_invented_label():
    """User-visible consequence: a MAC-only host with no `vendor=` attribute
    must not be labelled with a fake vendor; the display name falls through
    to the bare IP."""
    host = HostResult(ip="192.168.1.9", up=True, mac="AA:BB:CC:DD:EE:01")
    device = device_from_host(host)
    assert device.vendor is None
    assert device.display_name == "192.168.1.9"


def test_dedup_across_two_scans():
    # Scan 1: discovery only -> devices keyed by IP (no MAC yet).
    known, _ = merge_scan({}, _hosts("nmap_discovery.xml"), scan_id=1)
    assert len(known) == 2  # down host excluded? -> see note below

    # Scan 2: service pass reveals MAC + hostname + OS for the same machines.
    known, _ = merge_scan(known, _hosts("nmap_service.xml"), scan_id=2)
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
    known, _ = merge_scan({}, hosts, scan_id=1)
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
        '<address addr="AA:BB:CC:DD:EE:01" addrtype="mac"/></host></nmaprun>',
        "192.168.1.0/24",
    ).hosts
    merged, _ = merge_scan(seed, bare, scan_id=3)
    atom = merged["AA:BB:CC:DD:EE:01"]
    assert atom.hostname == "atom"  # kept, empty scan didn't blank it
    assert atom.os_guess == "Linux 2.6.32 - 3.x"  # kept
    assert atom.open_ports == ()  # ports are a fresh snapshot
    assert atom.last_seen_scan == 3


def test_mac_arriving_later_rekeys_ip_keyed_device():
    # #35: unprivileged scan 1 keys the machine by IP; privileged scan 2
    # learns its MAC. The device must re-key to the MAC, not keep the IP key.
    scan1 = parse_nmap_xml(
        '<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22">'
        '<state state="open"/></port></ports></host></nmaprun>',
        "192.168.1.0/24",
    ).hosts
    known, rekeys = merge_scan({}, scan1, scan_id=1)
    assert list(known) == ["192.168.1.10"]
    assert rekeys == ()

    scan2 = parse_nmap_xml(
        '<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>'
        '<address addr="aa:bb:cc:dd:ee:01" addrtype="mac"/></host></nmaprun>',
        "192.168.1.0/24",
    ).hosts
    known, rekeys = merge_scan(known, scan2, scan_id=2)
    assert rekeys == (("192.168.1.10", "AA:BB:CC:DD:EE:01"),)
    assert "192.168.1.10" not in known, "old IP key must not linger beside the MAC key"
    atom = known["AA:BB:CC:DD:EE:01"]
    assert atom.mac == "AA:BB:CC:DD:EE:01"
    assert atom.ip == "192.168.1.10"
    assert atom.last_seen_scan == 2


def test_rekey_keeps_manual_name_and_identity_intact():
    # A manual label set in the UI must survive the re-key.
    seed = {
        "192.168.1.10": Device(
            identity="192.168.1.10",
            ip="192.168.1.10",
            name="Atom",
            open_ports=(PortResult(port=22, protocol="tcp", state="open"),),
        )
    }
    scan2 = parse_nmap_xml(
        '<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>'
        '<address addr="AA:BB:CC:DD:EE:01" addrtype="mac"/></host></nmaprun>',
        "192.168.1.0/24",
    ).hosts
    known, rekeys = merge_scan(seed, scan2, scan_id=2)
    assert rekeys == (("192.168.1.10", "AA:BB:CC:DD:EE:01"),)
    atom = known["AA:BB:CC:DD:EE:01"]
    assert atom.name == "Atom"
    assert atom.identity == "AA:BB:CC:DD:EE:01"


def test_conflicting_mac_creates_separate_device():
    # #35 bug 2: after a DHCP change a *different* machine answers at the same
    # IP. The stored row (already carrying a MAC) must not be overwritten.
    seed = {
        "192.168.1.10": Device(
            identity="192.168.1.10",
            ip="192.168.1.10",
            mac="AA:BB:CC:DD:EE:01",
        )
    }
    scan = parse_nmap_xml(
        '<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>'
        '<address addr="FF:AA:BB:CC:DD:EE" addrtype="mac"/></host></nmaprun>',
        "192.168.1.0/24",
    ).hosts
    known, rekeys = merge_scan(seed, scan, scan_id=2)
    assert rekeys == ()
    assert len(known) == 2, "different machine must become its own device"
    assert known["192.168.1.10"].mac == "AA:BB:CC:DD:EE:01", "stored MAC not overwritten"
    assert known["192.168.1.10"].last_seen_scan is None, "old machine not sighted this scan"
    assert known["FF:AA:BB:CC:DD:EE"].ip == "192.168.1.10"
