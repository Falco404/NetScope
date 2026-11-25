"""mDNS resolver tests (#41) — no sockets, no network.

The browse *flow* is exercised with a fake `ServiceBrowser`, and the address
mapping with fake ServiceInfo objects. Both are our own seams: the protocols
(mDNS 5353, DNS-SD) are zeroconf's responsibility, and inventing "recorded
mDNS output" here would prove nothing about the library.
"""

import time
from types import SimpleNamespace

import pytest

import netscope.mdns as mdns
from netscope.mdns import MdnsNameResolver


def info(server: str, addresses: list[str]) -> SimpleNamespace:
    return SimpleNamespace(server=server, parsed_addresses=lambda: addresses)


class FakeZc:
    def __init__(self, infos: dict[tuple[str, str], object] | None = None) -> None:
        self.infos = infos or {}
        self.asked: list[tuple[str, str]] = []
        self.closed = False

    def get_service_info(self, type_: str, name: str, timeout: int = 3000):
        self.asked.append((type_, name))
        return self.infos.get((type_, name))

    def close(self) -> None:
        self.closed = True


def test_map_turns_instances_into_ip_to_host_names():
    instance = ("_ipp._tcp.local.", "printer._ipp._tcp.local.")
    zc = FakeZc({instance: info("printer.local.", ["192.168.0.30"])})
    names = MdnsNameResolver()._map(zc, [instance], time.monotonic() + 5)
    assert names == {"192.168.0.30": "printer.local"}


def test_map_strips_the_trailing_dot_and_ipv6_scope_and_keeps_every_address():
    zc = FakeZc(
        {
            ("_x._tcp.local.", "a._x._tcp.local."): info(
                "box.local.", ["192.168.0.40", "fe80::1%eth0"]
            )
        }
    )
    instance = ("_x._tcp.local.", "a._x._tcp.local.")
    names = MdnsNameResolver()._map(zc, [instance], time.monotonic() + 5)
    assert names == {"192.168.0.40": "box.local", "fe80::1": "box.local"}


def test_map_keeps_the_first_name_per_address():
    """Two services on one host are normal (a TV advertises _airplay and _raop);
    the address must map to one name, not flip-flop."""
    zc = FakeZc(
        {
            ("_a._tcp.local.", "tv._a._tcp.local."): info("tv.local.", ["192.168.0.6"]),
            ("_b._tcp.local.", "tv._b._tcp.local."): info("tv-other.local.", ["192.168.0.6"]),
        }
    )
    names = MdnsNameResolver()._map(
        zc,
        [("_a._tcp.local.", "tv._a._tcp.local."), ("_b._tcp.local.", "tv._b._tcp.local.")],
        time.monotonic() + 5,
    )
    assert names == {"192.168.0.6": "tv.local"}


def test_map_stops_at_the_deadline():
    """A slow device must not make the lookup overrun: past the deadline the
    remaining instances are skipped."""
    zc = FakeZc({("_a._tcp.local.", "a._a._tcp.local."): info("a.local.", ["192.168.0.7"])})
    names = MdnsNameResolver()._map(
        zc, [("_a._tcp.local.", "a._a._tcp.local.")], time.monotonic() - 1
    )
    assert names == {}
    assert zc.asked == []


def test_map_skips_answers_without_a_host_or_with_an_error():
    zc = FakeZc(
        {
            ("_a._tcp.local.", "no-server._a._tcp.local."): info("", ["192.168.0.8"]),
            ("_a._tcp.local.", "missing._a._tcp.local."): None,
        }
    )
    names = MdnsNameResolver()._map(
        zc,
        [
            ("_a._tcp.local.", "no-server._a._tcp.local."),
            ("_a._tcp.local.", "missing._a._tcp.local."),
        ],
        time.monotonic() + 5,
    )
    assert names == {}


def test_names_by_ip_returns_empty_when_zeroconf_cannot_start():
    """No multicast interface / blocked sockets: the scan keeps its own data."""

    def factory() -> object:
        raise OSError("no multicast interface")

    assert MdnsNameResolver(factory=factory).names_by_ip() == {}


def test_names_by_ip_returns_empty_and_closes_when_browsing_explodes(monkeypatch):
    zc = FakeZc()

    def boom(*_args, **_kwargs):
        raise RuntimeError("browse failed")

    monkeypatch.setattr(mdns, "ServiceBrowser", boom)
    assert MdnsNameResolver(timeout=0.01, factory=lambda: zc).names_by_ip() == {}
    assert zc.closed is True


def test_discover_browses_the_meta_type_then_every_discovered_type(monkeypatch):
    """DNS-SD two-stage flow: `_services._dns-sd._udp.local.` lists the types,
    then each type lists instances, then SRV/A resolve instance -> host."""
    browsed: list[str] = []
    instance = ("_ipp._tcp.local.", "printer._ipp._tcp.local.")
    zc = FakeZc({instance: info("printer.local.", ["192.168.0.30"])})

    class FakeBrowser:
        def __init__(self, zc_arg, type_, listener=None):
            assert listener is not None
            browsed.append(type_)
            if type_ == mdns.SERVICE_TYPES:
                listener.add_service(zc_arg, type_, "_ipp._tcp.local.")
            else:
                listener.add_service(zc_arg, type_, "printer._ipp._tcp.local.")

    monkeypatch.setattr(mdns, "ServiceBrowser", FakeBrowser)
    names = MdnsNameResolver(timeout=0.02, factory=lambda: zc).names_by_ip()

    assert browsed[0] == mdns.SERVICE_TYPES
    assert "_ipp._tcp.local." in browsed[1:]
    assert names == {"192.168.0.30": "printer.local"}
    assert zc.closed is True


def test_collector_ignores_departures_and_duplicates():
    zc = FakeZc()
    collector = mdns._Collector()
    collector.add_service(zc, "_a._tcp.local.", "x._a._tcp.local.")
    collector.add_service(zc, "_a._tcp.local.", "x._a._tcp.local.")
    collector.remove_service(zc, "_a._tcp.local.", "x._a._tcp.local.")
    collector.update_service(zc, "_a._tcp.local.", "x._a._tcp.local.")
    assert collector.items == [("_a._tcp.local.", "x._a._tcp.local.")]


def test_timeout_bounds_the_lookup():
    """The browsing phase never waits longer than the configured timeout."""
    zc = FakeZc()
    start = time.monotonic()
    MdnsNameResolver(timeout=0.2, factory=lambda: zc).names_by_ip()
    assert time.monotonic() - start < 1.0


@pytest.mark.parametrize("timeout", [0.0, 0.05])
def test_tiny_timeout_still_returns_a_mapping(timeout):
    zc = FakeZc()
    assert isinstance(MdnsNameResolver(timeout=timeout, factory=lambda: zc).names_by_ip(), dict)
