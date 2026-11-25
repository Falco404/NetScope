"""Engine tests: replay fixtures through a fake runner — zero network."""

from pathlib import Path

import pytest

from netscope.scanner.engine import NmapScanner
from netscope.target import IllegalTargetError

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
