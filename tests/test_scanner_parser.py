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
    assert atom.os_match == "Linux 2.6.32 - 3.x"  # real nmap: osmatch/@name
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


REAL_SHAPE = (
    '<?xml version="1.0"?><nmaprun><host starttime="1">'
    '<status state="up" reason="arp-response"/>'
    '<address addr="192.168.0.250" addrtype="ipv4"/>'
    '<address addr="B8:27:EB:11:22:33" addrtype="mac" vendor="Raspberry Pi Foundation"/>'
    '<hostnames><hostname name="atom.lan" type="PTR"/></hostnames>'
    '<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>'
    '<service name="ssh" product="OpenSSH" version="9.2p1"/></port></ports>'
    '<os><portused state="open" proto="tcp" portid="22"/>'
    '<osmatch name="Linux 5.0 - 5.14" accuracy="100" line="1">'
    '<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="100"/>'
    '</osmatch></os>'
    '</host></nmaprun>'
)


def test_real_nmap_nests_hostname_and_osmatch():
    # Regression: the parser looked for `hostname` and `os/osclass` as direct
    # children of <host>; real nmap nests <hostname> inside <hostnames> and
    # <osclass> inside <osmatch>. Real-shaped XML must yield both fields.
    host = parse_nmap_xml(REAL_SHAPE, "192.168.0.0/24").hosts[0]
    assert host.hostname == "atom.lan"
    assert host.os_match == "Linux 5.0 - 5.14"  # osmatch name, most accurate match
    assert host.mac == "B8:27:EB:11:22:33"
    assert host.ports[0].port == 22


def test_real_nmap_os_falls_back_to_osfamily():
    # An <osmatch> without a name attribute still gives a family via osclass.
    no_name = REAL_SHAPE.replace(' name="Linux 5.0 - 5.14"', "")
    host = parse_nmap_xml(no_name, "192.168.0.0/24").hosts[0]
    assert host.os_match == "Linux"


def test_hostname_prefers_ptr_then_user():
    xml = (
        '<nmaprun><host><status state="up"/>'
        '<address addr="192.168.1.5" addrtype="ipv4"/>'
        '<hostnames><hostname name="spoofed" type="user"/>'
        '<hostname name="real.lan" type="PTR"/></hostnames></host></nmaprun>'
    )
    assert parse_nmap_xml(xml, "192.168.1.0/24").hosts[0].hostname == "real.lan"

    only_user = xml.replace('<hostname name="real.lan" type="PTR"/>', "")
    assert parse_nmap_xml(only_user, "192.168.1.0/24").hosts[0].hostname == "spoofed"


def test_missing_hostname_and_os_elements_are_none():
    xml = (
        '<nmaprun><host><status state="up"/>'
        '<address addr="192.168.1.5" addrtype="ipv4"/></host></nmaprun>'
    )
    host = parse_nmap_xml(xml, "192.168.1.0/24").hosts[0]
    assert host.hostname is None
    assert host.os_match is None


def test_malformed_xml_raises():
    import xml.etree.ElementTree

    with pytest.raises(xml.etree.ElementTree.ParseError):
        parse_nmap_xml("<nmaprun><unclosed", "192.168.1.0/24")
