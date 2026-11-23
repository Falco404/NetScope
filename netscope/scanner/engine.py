"""Scan engine: guard -> discovery pass -> service pass, via an NmapRunner."""

from __future__ import annotations

from collections.abc import Callable

from netscope.scanner.models import HostResult, ScanResult
from netscope.scanner.parser import parse_nmap_xml
from netscope.scanner.runner import NmapRunner
from netscope.target import validate_target

ProgressCallback = Callable[[HostResult], None]


class NmapScanner:
    """Two-pass scan: `-sn` discovery on the subnet, then `-sV` only on
    hosts that responded — keeps a /24 fast.

    The TargetGuard runs before the runner is ever touched, so an illegal
    target never reaches nmap.
    """

    def __init__(self, runner: NmapRunner) -> None:
        self.runner = runner

    def scan(self, target: str, progress: ProgressCallback | None = None) -> ScanResult:
        net = validate_target(target)  # raises IllegalTargetError before any run()
        target_str = str(net)

        discovery_xml = self.runner.run(["-sn", "-oX", "-", target_str])
        discovered = [h.ip for h in parse_nmap_xml(discovery_xml, target_str).hosts if h.up]

        if not discovered:
            return ScanResult(target=target_str, hosts=())

        service_xml = self.runner.run(["-sV", "-oX", "-", *discovered])
        result = parse_nmap_xml(service_xml, target_str)

        if progress is not None:
            for host in result.hosts:
                progress(host)

        return result
