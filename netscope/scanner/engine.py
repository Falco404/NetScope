"""Scan engine: guard -> discovery pass -> service pass, via an NmapRunner."""

from __future__ import annotations

from collections.abc import Callable

from netscope.scanner.models import HostResult, ScanResult
from netscope.scanner.parser import parse_nmap_xml
from netscope.scanner.runner import NmapRunner
from netscope.target import validate_target

ProgressCallback = Callable[[HostResult], None]


class NmapScanner:
    """Two-pass scan: `-sn` discovery on the subnet, then `-sV` (optionally
    `-O`) port/service and OS fingerprinting on hosts that responded.

    Before the service pass, a quick `-O` probe on localhost determines
    whether OS fingerprinting is available without privileges.  If the
    probe fails the service pass retries without `-O` so the scan still
    completes (just without OS guesses).

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

        # Privilege probe: can nmap do -O without root/admin?
        os_available = self.runner.probe_os()

        if os_available:
            service_xml = self.runner.run(["-sV", "-O", "-oX", "-", *discovered])
        else:
            service_xml = self.runner.run(["-sV", "-oX", "-", *discovered])

        result = parse_nmap_xml(service_xml, target_str)

        if progress is not None:
            for host in result.hosts:
                progress(host)

        return ScanResult(
            target=target_str,
            hosts=result.hosts,
            os_detection_available=os_available,
        )
