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
    name: str | None = None  # manual label from the UI (M8), set outside scans
    open_ports: tuple[PortResult, ...] = ()
    last_seen_scan: int | None = None  # scan id, filled by the store (M5)

    @property
    def display_name(self) -> str:
        """Best human label: manual name first (deliberate), then hostname,
        then vendor+IP, then bare IP."""
        if self.name:
            return self.name
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
) -> tuple[dict[str, Device], tuple[tuple[str, str], ...]]:
    """Merge a scan's hosts into the known device map.

    Returns ``(merged, rekeys)``; ``rekeys`` lists ``(old_identity, new_identity)``
    for devices whose key changed, so the store can migrate their DB rows.

    Same identity -> update in place (latest non-empty hostname/OS wins,
    ports replaced by this scan's view — a scan is a fresh snapshot).
    New identity -> added. An IP-keyed device seen with a MAC re-keys to the
    MAC (#35); a row that already carries a *different* MAC is a different
    machine, so the host becomes a separate device instead of overwriting it.
    """
    merged = dict(known)
    rekeys: list[tuple[str, str]] = []
    for host in hosts:
        if not host.up:
            continue  # a down host is not a device sighting
        new = device_from_host(host)
        existing = merged.get(new.identity)
        rekey_from: str | None = None
        if existing is None and new.mac:
            ip_row = merged.get(host.ip)
            if ip_row is not None and (ip_row.mac is None or ip_row.mac == new.mac):
                # Same machine, MAC learned only now: re-key IP -> MAC.
                existing = ip_row
                rekey_from = host.ip
            # else: the IP row carries a different MAC -> different machine,
            # and this host is a new device under its own MAC.
        if existing is None:
            merged[new.identity] = replace(new, last_seen_scan=scan_id)
            continue
        updated = replace(
            existing,
            ip=new.ip,
            hostname=new.hostname or existing.hostname,
            mac=new.mac or existing.mac,
            vendor=new.vendor or existing.vendor,
            os_guess=new.os_guess or existing.os_guess,
            open_ports=new.open_ports,
            last_seen_scan=scan_id,
        )
        if rekey_from is not None:
            del merged[rekey_from]
            merged[new.identity] = replace(updated, identity=new.identity)
            rekeys.append((rekey_from, new.identity))
        else:
            merged[existing.identity] = updated
    return merged, tuple(rekeys)
