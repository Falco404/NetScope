"""Parse nmap XML output into structured results — pure, no network."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from netscope.scanner.models import HostResult, PortResult, ScanResult


def parse_nmap_xml(xml_text: str, target: str) -> ScanResult:
    """Parse one nmap XML document (as produced by `-oX -`).

    Missing optional elements (hostname, mac, os, ports) become None/empty.
    A host is up iff its status element has state="up".
    """
    root = ET.fromstring(xml_text)
    hosts: list[HostResult] = []

    for host in root.findall("host"):
        ip_el = host.find("address[@addrtype='ipv4']")
        if ip_el is None:
            continue
        ip = ip_el.get("addr", "")

        status_el = host.find("status")
        up = status_el is not None and status_el.get("state") == "up"

        # Real nmap nests hostnames under <hostnames>. PTR (reverse DNS) is the
        # trustworthy one, so prefer it, then a user-set entry, then any.
        # ElementTree cannot filter by attribute in a path expression, so
        # select explicitly.
        hostnames = host.findall("hostnames/hostname")
        hostname_el = next((h for h in hostnames if h.get("type") == "PTR"), None)
        if hostname_el is None:
            hostname_el = next((h for h in hostnames if h.get("type") == "user"), None)
        if hostname_el is None and hostnames:
            hostname_el = hostnames[0]
        hostname = hostname_el.get("name") if hostname_el is not None else None

        mac_el = host.find("address[@addrtype='mac']")
        mac = mac_el.get("addr") if mac_el is not None else None
        mac_vendor = mac_el.get("vendor") if mac_el is not None else None

        # Real nmap nests the match under <os><osmatch name="Linux 5.0 - 5.14">;
        # the first osmatch is the most accurate one. Its name attribute is the
        # guess; <osclass> lives inside osmatch and only gives a family
        # (osfamily, e.g. "Linux") as fallback.
        osmatch_el = host.find("os/osmatch")
        os_match = osmatch_el.get("name") if osmatch_el is not None else None
        if os_match is None and osmatch_el is not None:
            osclass_el = osmatch_el.find("osclass")
            os_match = osclass_el.get("osfamily") if osclass_el is not None else None

        ports: list[PortResult] = []
        for port_el in host.findall("ports/port"):
            # REAL nmap writes the port number as `portid` (not `port`); reading
            # the wrong attribute silently yields 0 for every port.
            portid = port_el.get("portid")
            if portid is None:
                continue  # no usable port number -> not a port sighting
            proto = port_el.get("protocol", "")
            state_el = port_el.find("state")
            state = (state_el.get("state") if state_el is not None else None) or "unknown"
            service_el = port_el.find("service")
            version = service_el.get("version") if service_el is not None else None
            ports.append(
                PortResult(
                    port=int(portid),
                    protocol=proto,
                    state=state,
                    service=service_el.get("name") if service_el is not None else None,
                    version=version,
                )
            )

        hosts.append(
            HostResult(
                ip=ip,
                up=up,
                hostname=hostname,
                mac=mac,
                mac_vendor=mac_vendor,
                os_match=os_match,
                ports=tuple(ports),
            )
        )

    return ScanResult(target=target, hosts=tuple(hosts))
