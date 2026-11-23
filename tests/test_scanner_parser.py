"""Parser tests against recorded nmap XML fixtures — zero network."""

from pathlib import Path

import pytest

from netscope.scanner.parser import parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_discovery_fixture():
    result = parse_nmap_xml(fixture("nmap_discovery.xml"), "192.168.1.0/24")
    assert result.target == "192.168.1.0/24"
    assert len(result.hosts) == 3
    assert [h.ip for h in result.hosts] == ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    assert [h.up for h in result.hosts] == [True, True, False]
    assert result.hosts[0].mac == "AA:BB:CC:DD:EE:01"
    assert result.hosts[0].mac_vendor == "MicroStar Intl"
    assert result.hosts[1].mac is None


def test_service_fixture():
    result = parse_nmap_xml(fixture("nmap_service.xml"), "192.168.1.0/24")
    atom, apollo = result.hosts

    assert atom.hostname == "atom"
    assert atom.os_match == "Linux"
    assert atom.mac_vendor == "MicroStar Intl"
    assert len(atom.ports) == 3

    ssh = atom.ports[0]
    assert (ssh.port, ssh.protocol, ssh.state) == (22, "tcp", "open")
    assert ssh.service == "ssh"
    assert ssh.version == "8.4p1 Debian"

    http = atom.ports[1]
    assert (http.port, http.state, http.service, http.version) == (80, "open", "http", "1.22.1")

    closed = atom.ports[2]
    assert closed.state == "closed"
    assert closed.version is None

    assert apollo.hostname == "apollo"
    assert apollo.os_match is None
    assert len(apollo.ports) == 1
    assert apollo.ports[0].service is None  # open port, no service probe result


def test_empty_fixture():
    result = parse_nmap_xml(fixture("nmap_empty.xml"), "192.168.1.0/24")
    assert result.hosts == ()


def test_real_nmap_attribute_is_portid_not_port():
    # Regression: a real scan wrote every port as 0 because the parser read
    # `port` — nmap's XML attribute is `portid`. A made-up `port` attribute
    # must produce NO port, never a fabricated port 0.
    real = (
        '<nmaprun><host><status state="up"/>'
        '<address addr="192.168.1.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="443">'
        '<state state="open"/></port></ports></host></nmaprun>'
    )
    invented = real.replace(' portid="443"', ' port="443"')

    assert parse_nmap_xml(real, "192.168.1.0/24").hosts[0].ports[0].port == 443
    assert parse_nmap_xml(invented, "192.168.1.0/24").hosts[0].ports == ()


def test_malformed_xml_raises():
    import xml.etree.ElementTree

    with pytest.raises(xml.etree.ElementTree.ParseError):
        parse_nmap_xml("<nmaprun><unclosed", "192.168.1.0/24")
