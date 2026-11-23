"""Device model: machines identified across scans, not per-IP snapshots.

Identity = MAC when known (hardware, stable across DHCP leases), else IP.
A HostResult from a scan is resolved into a Device; merging a new scan into
known devices updates fields without creating duplicates.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from netscope.scanner.models import HostResult, PortResult
from netscope.vendor_registry import vendor_from_mac


@dataclass(frozen=True)
class Device:
    """A physical machine as NetScope knows it."""

    identity: str  # MAC (uppercase) if known, else IP
    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    open_ports: tuple[PortResult, ...] = ()
    last_seen_scan: int | None = None  # scan id, filled by the store (M5)

    @property
    def display_name(self) -> str:
        """Best human label: hostname first, then vendor+model-ish, then IP."""
        if self.hostname:
            return self.hostname
        if self.vendor:
            return f"{self.vendor} device ({self.ip})"
        return self.ip


def device_from_host(host: HostResult) -> Device:
    """Resolve one scan result into a device identity."""
    mac = host.mac.upper() if host.mac else None
    vendor = host.mac_vendor or (vendor_from_mac(host.mac) if host.mac else None)
    identity = mac or host.ip
    return Device(
        identity=identity,
        ip=host.ip,
        hostname=host.hostname,
        mac=mac,
        vendor=vendor,
        os_guess=host.os_match,
        open_ports=tuple(p for p in host.ports if p.state == "open"),
    )


def merge_scan(
    known: dict[str, Device], hosts: tuple[HostResult, ...], scan_id: int | None = None
) -> dict[str, Device]:
    """Merge a scan's hosts into the known device map.

    Same identity -> update in place (latest non-empty hostname/OS wins,
    ports replaced by this scan's view — a scan is a fresh snapshot).
    New identity -> added. Unknown-MAC hosts that show up with a MAC later
    keep their old IP identity and do not fork into two devices.
    """
    merged = dict(known)
    for host in hosts:
        if not host.up:
            continue  # a down host is not a device sighting
        new = device_from_host(host)
        # A host that already exists by IP is the same machine even if we
        # only now learned its MAC.
        existing = merged.get(new.identity) or merged.get(host.ip)
        if existing is None:
            merged[new.identity] = replace(new, last_seen_scan=scan_id)
            continue
        merged[existing.identity] = replace(
            existing,
            ip=new.ip,
            hostname=new.hostname or existing.hostname,
            mac=new.mac or existing.mac,
            vendor=new.vendor or existing.vendor,
            os_guess=new.os_guess or existing.os_guess,
            open_ports=new.open_ports,
            last_seen_scan=scan_id,
        )
    return merged
