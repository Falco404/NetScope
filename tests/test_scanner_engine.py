"""Engine tests: replay fixtures through a fake runner — zero network."""

from pathlib import Path

import pytest

from netscope.scanner.engine import NmapScanner, service_pass_addresses
from netscope.scanner.models import HostResult
from netscope.target import IllegalTargetError, validate_target

FIXTURES = Path(__file__).parent / "fixtures"


class FakeRunner:
    """Replays recorded XML per pass and records the args it was called with."""

    def __init__(self, discovery: str, service: str, os_probe: bool = True) -> None:
        self.discovery = discovery
        self.service = service
        self.os_probe = os_probe
        self.calls: list[list[str]] = []

    def run(self, args: list[str]) -> str:
        self.calls.append(args)
        return self.discovery if "-sn" in args else self.service

    def probe_os(self) -> bool:
        return self.os_probe


def fake_runner() -> FakeRunner:
    return FakeRunner(
        (FIXTURES / "nmap_discovery.xml").read_text(),
        (FIXTURES / "nmap_service.xml").read_text(),
    )


def discovery_with(*addresses: str) -> str:
    """Minimal discovery XML: one up host per given <address addr> value.

    Constructed, not captured: this is the hostile-input case (the point is an
    address nmap would never write), so a real capture cannot exist for it.
    """
    hosts = "".join(
        f'<host><status state="up"/><address addr="{addr}" addrtype="ipv4"/></host>'
        for addr in addresses
    )
    return f"<nmaprun>{hosts}</nmaprun>"


def test_discovered_addresses_are_revalidated_before_the_service_pass():
    """#security: argv elements come out of a parsed document. An address that
    is not plain IPv4 inside the scanned network must never reach nmap — a value
    like `-oN/tmp/pwn` would be read as a flag by the second pass."""
    runner = FakeRunner(
        discovery_with("192.168.1.10", "-oN/tmp/pwn", "8.8.8.8", "192.168.1.007"),
        (FIXTURES / "nmap_service.xml").read_text(),
    )
    NmapScanner(runner).scan("192.168.1.0/24")

    assert runner.calls[1] == ["-sV", "-O", "-oX", "-", "192.168.1.10"]


def test_no_usable_address_means_no_service_pass():
    runner = FakeRunner(
        discovery_with("-oN/tmp/pwn", "10.0.0.1"),  # one flag, one outside the target
        (FIXTURES / "nmap_service.xml").read_text(),
    )
    result = NmapScanner(runner).scan("192.168.1.0/24")

    assert len(runner.calls) == 1, "only the discovery pass may run"
    assert result.hosts == ()


def test_service_pass_addresses_keeps_order_and_drops_duplicates_never():
    # A repeated address is passed through as-is: nmap dedupes, and silently
    # dropping one would make the number of probed hosts disagree with the UI.
    hosts = [
        HostResult(ip="192.168.1.20", up=True),
        HostResult(ip="192.168.1.10", up=True),
        HostResult(ip="192.168.1.20", up=True),
    ]
    net = validate_target("192.168.1.0/24")
    assert service_pass_addresses(hosts, net) == [
        "192.168.1.20",
        "192.168.1.10",
        "192.168.1.20",
    ]


def test_two_pass_flow():
    runner = fake_runner()
    result = NmapScanner(runner).scan("192.168.1.0/24")

    assert len(runner.calls) == 2  # discovery + service (probe is separate)
    assert runner.calls[0] == ["-sn", "-oX", "-", "192.168.1.0/24"]
    # service pass targets ONLY hosts that responded to discovery; -O fingerprints OS
    assert runner.calls[1] == ["-sV", "-O", "-oX", "-", "192.168.1.10", "192.168.1.20"]
    assert result.os_detection_available is True

    assert len(result.hosts) == 2
    assert result.hosts[0].hostname == "atom"
    assert result.hosts[1].hostname == "apollo"


def test_illegal_target_never_reaches_runner():
    runner = fake_runner()
    with pytest.raises(IllegalTargetError):
        NmapScanner(runner).scan("8.8.8.8")
    assert runner.calls == []  # guard ran before any nmap invocation


def test_no_hosts_up_skips_service_pass():
    runner = FakeRunner(
        (FIXTURES / "nmap_empty.xml").read_text(),
        (FIXTURES / "nmap_service.xml").read_text(),
    )
    result = NmapScanner(runner).scan("192.168.1.0/24")
    assert len(runner.calls) == 1  # discovery only
    assert result.hosts == ()


def test_single_ip_target_normalized():
    runner = fake_runner()
    NmapScanner(runner).scan("192.168.1.10")
    assert runner.calls[0] == ["-sn", "-oX", "-", "192.168.1.10/32"]


def test_progress_callback_fires_per_host_per_phase():
    seen: list[tuple[str, str]] = []
    NmapScanner(fake_runner()).scan(
        "192.168.1.0/24",
        progress=lambda phase, h: seen.append((phase, h.ip)) if h else None,
    )
    assert seen == [
        ("discovery", "192.168.1.10"),
        ("discovery", "192.168.1.20"),
        ("services", "192.168.1.10"),
        ("services", "192.168.1.20"),
    ]


def test_phase_start_sentinel_fires_before_each_pass():
    """#37: the engine announces each pass with progress(PHASE, None) BEFORE
    running it, so the UI can label the pass the instant it begins — during
    the long -sn sweep there are no hosts yet, but the user should still see
    'discovery' as the current phase."""
    events: list[str] = []
    runner = fake_runner()

    def on_progress(phase: str, host) -> None:
        events.append(f"{phase}:start" if host is None else f"{phase}:{host.ip}")

    original_run = runner.run

    def logged_run(args: list[str]) -> str:
        events.append("run:" + args[0])
        return original_run(args)

    runner.run = logged_run  # type: ignore[method-assign]
    NmapScanner(runner).scan("192.168.1.0/24", progress=on_progress)

    # discovery start precedes the -sn run; services start precedes the -sV run.
    assert events[0] == "discovery:start"
    assert events[1] == "run:-sn"
    assert "services:start" in events
    assert events.index("services:start") < events.index("run:-sV")


def test_discovery_progress_fires_before_service_pass_runs():
    """#37: the -sn pass must report hosts as they are discovered, not wait
    for the -sV pass. A /24 spends most of its time in discovery, so a UI
    that only learns about hosts after the service pass shows 0 until the
    very end."""
    events: list[str] = []
    runner = fake_runner()

    def on_progress(phase: str, host) -> None:
        if host is not None:
            events.append(f"{phase}:{host.ip}")

    original_run = runner.run

    def logged_run(args: list[str]) -> str:
        events.append("run:" + args[0])
        return original_run(args)

    runner.run = logged_run  # type: ignore[method-assign]
    NmapScanner(runner).scan("192.168.1.0/24", progress=on_progress)

    # Every discovery callback must precede the -sV invocation.
    first_service = events.index("run:-sV")
    discovery_events = [e for e in events[:first_service] if e.startswith("discovery:")]
    assert discovery_events == ["discovery:192.168.1.10", "discovery:192.168.1.20"]
    # And the service pass reports its own hosts afterwards.
    assert [e for e in events[first_service:] if e.startswith("services:")] == [
        "services:192.168.1.10",
        "services:192.168.1.20",
    ]


def test_no_os_probe_fallback():
    """When -O probe fails, service pass runs without -O and flag is False."""
    runner = FakeRunner(
        (FIXTURES / "nmap_discovery.xml").read_text(),
        (FIXTURES / "nmap_service.xml").read_text(),
        os_probe=False,
    )
    result = NmapScanner(runner).scan("192.168.1.0/24")

    assert len(runner.calls) == 2
    assert runner.calls[0] == ["-sn", "-oX", "-", "192.168.1.0/24"]
    # service pass does NOT include -O
    assert runner.calls[1] == ["-sV", "-oX", "-", "192.168.1.10", "192.168.1.20"]
    assert result.os_detection_available is False


def test_quick_scan_runs_only_the_discovery_pass():
    """#39: a quick scan is `-sn` and nothing else.

    `probe_os()` itself runs nmap, so the quick path must not touch it — the
    assertion is on the runner's calls, not just on the returned hosts.
    """
    runner = fake_runner()
    result = NmapScanner(runner).scan("192.168.1.0/24", deep=False)

    assert runner.calls == [["-sn", "-oX", "-", "192.168.1.0/24"]]
    assert result.mode == "quick"
    assert [h.ip for h in result.hosts] == ["192.168.1.10", "192.168.1.20"]
    # Discovery yields no ports and no OS guesses.
    assert all(h.ports == () and h.os_match is None for h in result.hosts)


def test_quick_scan_never_probes_for_os():
    """A runner whose probe_os raises proves the quick path skips it entirely."""
    runner = fake_runner()
    runner.probe_os = lambda: pytest.fail("quick scan must not run the -O probe")
    NmapScanner(runner).scan("192.168.1.0/24", deep=False)


def test_deep_scan_is_the_default_and_reports_its_mode():
    runner = fake_runner()
    result = NmapScanner(runner).scan("192.168.1.0/24")
    assert result.mode == "deep"
    assert len(runner.calls) == 2


def test_quick_scan_reports_only_the_discovery_phase():
    events: list[str] = []
    runner = fake_runner()

    def on_progress(phase, host):
        events.append(f"{phase}:{host.ip if host is not None else '-'}")

    NmapScanner(runner).scan("192.168.1.0/24", progress=on_progress, deep=False)
    assert events == ["discovery:-", "discovery:192.168.1.10", "discovery:192.168.1.20"]


class FakeResolver:
    """Stands in for netscope.mdns.MdnsNameResolver (#41) — no sockets."""

    def __init__(self, names: dict[str, str] | None = None, fail: bool = False) -> None:
        self.names = names or {}
        self.fail = fail
        self.calls = 0

    def names_by_ip(self) -> dict[str, str]:
        self.calls += 1
        if self.fail:
            raise RuntimeError("multicast is blocked")
        return self.names


def test_quick_scan_fills_missing_hostnames_from_mdns():
    """The discovery fixture has no PTR names at all, so both hosts get one."""
    runner = fake_runner()
    resolver = FakeResolver({"192.168.1.10": "atom.local", "192.168.1.20": "apollo.local"})
    result = NmapScanner(runner, resolver=resolver).scan("192.168.1.0/24", deep=False)

    assert [h.hostname for h in result.hosts] == ["atom.local", "apollo.local"]
    assert resolver.calls == 1


def test_mdns_never_overrides_a_unique_ptr_name():
    """A name the network reports (PTR) beats a self-reported `.local` one."""
    runner = fake_runner()
    resolver = FakeResolver({"192.168.1.10": "wrong.local", "192.168.1.20": "wrong2.local"})
    result = NmapScanner(runner, resolver=resolver).scan("192.168.1.0/24")

    assert [h.hostname for h in result.hosts] == ["atom", "apollo"]


def test_mdns_replaces_a_hostname_shared_by_several_hosts():
    """The sinkhole signature: every PTR answer is `blocked.local`, which the
    store suppresses. mDNS names replace it for the hosts that answer, while a
    unique PTR name (`pi.hole`) is kept and unanswered hosts are unchanged."""
    real = (FIXTURES / "home_lan_complete_2026-11-25.xml").read_text()
    runner = FakeRunner(real, real)
    resolver = FakeResolver(
        {
            "192.168.0.2": "router.local",
            "192.168.0.250": "wrong-for-pi-hole.local",
        }
    )
    result = NmapScanner(runner, resolver=resolver).scan("192.168.0.0/24")
    by_ip = {h.ip: h.hostname for h in result.hosts}

    assert by_ip["192.168.0.2"] == "router.local"  # was blocked.local
    assert by_ip["192.168.0.4"] == "blocked.local"  # no mDNS answer: untouched
    assert by_ip["192.168.0.250"] == "pi.hole"  # unique PTR name wins
    assert by_ip["192.168.0.14"] is None  # no PTR, no mDNS answer


def test_a_failing_name_lookup_never_fails_the_scan():
    runner = fake_runner()
    result = NmapScanner(runner, resolver=FakeResolver(fail=True)).scan("192.168.1.0/24")

    assert result.mode == "deep"
    assert [h.hostname for h in result.hosts] == ["atom", "apollo"]  # untouched
    assert len(runner.calls) == 2


def test_no_resolver_means_no_name_lookup_at_all():
    """Default construction (tests, embedders) stays pure nmap."""
    runner = fake_runner()
    result = NmapScanner(runner).scan("192.168.1.0/24")
    assert [h.hostname for h in result.hosts] == ["atom", "apollo"]


class FakeNetbios:
    """Stands in for netscope.netbios.NetbiosNameResolver (#41 part 2)."""

    def __init__(self, names: dict[str, str] | None = None, fail: bool = False) -> None:
        self.names = names or {}
        self.fail = fail
        self.asked: list[list[str]] = []

    def names_by_ip(self, ips) -> dict[str, str]:
        self.asked.append(list(ips))
        if self.fail:
            raise RuntimeError("UDP 137 blocked")
        return self.names


def test_netbios_names_fill_missing_hostnames():
    """The discovery fixture has no PTR names, so NetBIOS supplies them."""
    runner = fake_runner()
    netbios = FakeNetbios({"192.168.1.20": "DESKTOP-ABC123"})
    result = NmapScanner(runner, netbios=netbios).scan("192.168.1.0/24", deep=False)

    assert [h.hostname for h in result.hosts] == [None, "DESKTOP-ABC123"]
    # Only the hosts discovery found are queried — never the whole subnet.
    assert netbios.asked == [["192.168.1.10", "192.168.1.20"]]


def test_netbios_never_overrides_a_unique_ptr_name():
    runner = fake_runner()
    netbios = FakeNetbios({"192.168.1.10": "WRONGBOX", "192.168.1.20": "WRONGTOO"})
    result = NmapScanner(runner, netbios=netbios).scan("192.168.1.0/24")

    assert [h.hostname for h in result.hosts] == ["atom", "apollo"]


def test_mdns_beats_netbios_for_the_same_host():
    """Priority is PTR (unique) > mDNS > NetBIOS: mDNS names are the plan's
    primary source, NetBIOS only fills what is still empty."""
    runner = fake_runner()
    mdns = FakeResolver({"192.168.1.20": "apollo.local"})
    netbios = FakeNetbios({"192.168.1.20": "DESKTOP-ABC123"})
    result = NmapScanner(runner, resolver=mdns, netbios=netbios).scan("192.168.1.0/24", deep=False)

    assert [h.hostname for h in result.hosts] == [None, "apollo.local"]


def test_a_failing_netbios_lookup_never_fails_the_scan():
    runner = fake_runner()
    result = NmapScanner(runner, netbios=FakeNetbios(fail=True)).scan("192.168.1.0/24")

    assert result.mode == "deep"
    assert [h.hostname for h in result.hosts] == ["atom", "apollo"]
    assert len(runner.calls) == 2


def test_netbios_is_not_consulted_when_not_configured():
    runner = fake_runner()
    # Default construction: pure nmap, no name sources at all.
    result = NmapScanner(runner).scan("192.168.1.0/24", deep=False)
    assert [h.hostname for h in result.hosts] == [None, None]
