"""mDNS / DNS-SD name suggestions (#41).

Devices that speak Bonjour/Avahi announce ``<host>.local`` over multicast DNS
(UDP 5353, group 224.0.0.251). Reading those announcements gives a hostname
WITHOUT asking the router, which matters on Falco's LAN where the DNS resolver
is a sinkhole and answers every PTR query with ``blocked.local``.

How the lookup works, in DNS-SD terms (RFC 6762 / RFC 6763):

1. Browse ``_services._dns-sd._udp.local.`` — the answer lists the service
   types present on the LAN (``_googlecast._tcp.local.``, ``_ipp._tcp.local.``…).
2. Browse each of those types — the answers are service instances.
3. Resolve an instance — its SRV record names the host (``Chromecast-1a2b.local``)
   and its A/AAAA records give the addresses.

Only the address -> host mapping is kept: that is what a scan can attach to a
device it already found.

Everything here is best-effort. A scan must never fail because multicast is
blocked, the network changed, or a device answers with garbage, so every
exception becomes "no names" and the caller keeps the scan's own data.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

# The DNS-SD meta-query: "which service types are advertised here?"
SERVICE_TYPES = "_services._dns-sd._udp.local."

DEFAULT_TIMEOUT = 3.5  # seconds spent listening for browse answers
INFO_BUDGET = 1.5  # extra seconds for resolving SRV/A of the instances found
INFO_TIMEOUT_MS = 400  # per instance resolve; the records are usually cached
MAX_SERVICE_TYPES = 40  # a LAN with more types than this is not worth waiting for
MAX_SERVICE_INFO_CALLS = 20


class NameResolver(Protocol):
    """Anything that can propose host names for IP addresses."""

    def names_by_ip(self) -> Mapping[str, str]:
        """Map IP address -> host name, e.g. ``{"192.168.0.250": "atom.local"}``."""
        ...


class _Collector(ServiceListener):
    """Minimal ServiceListener: records ``(type, name)`` pairs, ignores the rest."""

    def __init__(self) -> None:
        self.items: list[tuple[str, str]] = []

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        item = (type_, name)
        if item not in self.items:
            self.items.append(item)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass  # a departing device is not an event a scan cares about

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass


class MdnsNameResolver:
    """Discover ``.local`` names with python-zeroconf and map them to IPs.

    ``factory`` exists for tests: production always uses ``Zeroconf()``, which
    opens the multicast sockets. Nothing in this class touches the network
    until ``names_by_ip()`` is called.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        factory: Callable[[], Any] = Zeroconf,
    ) -> None:
        self.timeout = timeout
        self._factory = factory

    def names_by_ip(self) -> Mapping[str, str]:
        """Best-effort; returns ``{}`` on any failure (never raises)."""
        try:
            zc = self._factory()
        except Exception:
            return {}
        try:
            return self._discover(zc)
        except Exception:
            return {}
        finally:
            try:
                zc.close()
            except Exception:
                pass

    def _discover(self, zc: Any) -> dict[str, str]:
        start = time.monotonic()
        browse_deadline = start + self.timeout
        mapping_deadline = browse_deadline + INFO_BUDGET

        types = _Collector()
        ServiceBrowser(zc, SERVICE_TYPES, listener=types)
        # Give the meta-query a slice of the budget, then browse what it found.
        _wait_until(min(browse_deadline, start + self.timeout * 0.4))

        instances = _Collector()
        for type_ in sorted({name for _, name in types.items})[:MAX_SERVICE_TYPES]:
            ServiceBrowser(zc, type_, listener=instances)
        _wait_until(browse_deadline)

        return self._map(zc, list(instances.items), mapping_deadline)

    def _map(self, zc: Any, instances: list[tuple[str, str]], deadline: float) -> dict[str, str]:
        """Resolve instances to ``ip -> host``; first name per address wins."""
        names: dict[str, str] = {}
        for index, (type_, name) in enumerate(instances):
            if index >= MAX_SERVICE_INFO_CALLS or time.monotonic() >= deadline:
                break
            try:
                info = zc.get_service_info(type_, name, timeout=INFO_TIMEOUT_MS)
            except Exception:
                continue
            if info is None or not info.server:
                continue
            host = info.server.rstrip(".")
            if not host:
                continue
            for address in info.parsed_addresses():
                ip = address.split("%", 1)[0]  # drop an IPv6 scope id
                names.setdefault(ip, host)
        return names


def _wait_until(deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)
