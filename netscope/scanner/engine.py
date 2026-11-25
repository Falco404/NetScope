"""Scan engine: guard -> discovery pass -> service pass, via an NmapRunner."""

from __future__ import annotations

from collections.abc import Callable

from netscope.scanner.models import HostResult, ScanResult
from netscope.scanner.parser import parse_nmap_xml
from netscope.scanner.runner import NmapRunner
from netscope.target import validate_target

ProgressCallback = Callable[[str, HostResult | None], None]

# The two nmap passes, named for the UI and for /api/scan/status.
# Discovery (`-sn`) is the slow sweep of the whole subnet; services (`-sV`)
# only runs on hosts that answered. Progress is reported per host IN each
# phase (#37): a caller that only learns about hosts after the service pass
# shows nothing for most of the scan.
#
# The callback is called in two ways:
#   progress(PHASE_X, None)  -> the engine is ENTERING pass X (host=None is a
#                               phase-start sentinel; lets the UI label the
#                               pass the instant it begins, before any host
#                               is known).
#   progress(PHASE_X, host)  -> pass X reported one host.
# nmap's XML arrives only when a pass finishes, so per-host events cluster
# at the end of each pass — that is the finest granularity nmap offers,
# and it is honest (no fake ticking).
PHASE_DISCOVERY = "discovery"
PHASE_SERVICES = "services"


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

        if progress is not None:
            progress(PHASE_DISCOVERY, None)  # entering the discovery pass

        discovery_xml = self.runner.run(["-sn", "-oX", "-", target_str])
        discovered_hosts = [h for h in parse_nmap_xml(discovery_xml, target_str).hosts if h.up]

        if progress is not None:
            for host in discovered_hosts:
                progress(PHASE_DISCOVERY, host)

        discovered = [h.ip for h in discovered_hosts]

        if not discovered:
            return ScanResult(target=target_str, hosts=())

        # Privilege probe: can nmap do -O without root/admin?
        os_available = self.runner.probe_os()

        if progress is not None:
            progress(PHASE_SERVICES, None)  # entering the service pass

        if os_available:
            service_xml = self.runner.run(["-sV", "-O", "-oX", "-", *discovered])
        else:
            service_xml = self.runner.run(["-sV", "-oX", "-", *discovered])

        result = parse_nmap_xml(service_xml, target_str)

        if progress is not None:
            for host in result.hosts:
                progress(PHASE_SERVICES, host)

        return ScanResult(
            target=target_str,
            hosts=result.hosts,
            os_detection_available=os_available,
        )
