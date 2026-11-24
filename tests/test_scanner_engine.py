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


def test_progress_callback_fires_per_host():
    seen: list[str] = []
    NmapScanner(fake_runner()).scan("192.168.1.0/24", progress=lambda h: seen.append(h.ip))
    assert seen == ["192.168.1.10", "192.168.1.20"]


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
