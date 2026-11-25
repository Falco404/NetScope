"""Scan engine: guard -> discovery pass -> (deep only) service pass, via an NmapRunner."""

from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import replace

from netscope.mdns import NameResolver
from netscope.netbios import NetbiosNameResolver
from netscope.scanner.models import HostResult, ScanResult
from netscope.scanner.parser import parse_nmap_xml
from netscope.scanner.runner import NmapRunner
from netscope.target import validate_target

ProgressCallback = Callable[[str, HostResult | None], None]

# The two nmap passes, named for the UI and for /api/scan/status.
# A quick scan (#39) runs ONLY the discovery pass; a deep scan runs both.
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

# #39: the mode values travel through ScanResult -> store -> API -> UI, so they
# are constants instead of bare strings scattered over four layers.
MODE_QUICK = "quick"
MODE_DEEP = "deep"


class NmapScanner:
    """Two-pass scan: `-sn` discovery on the subnet, then `-sV` (optionally
    `-O`) port/service and OS fingerprinting on hosts that responded.

    A quick scan (#39) stops after discovery: it answers "who is on the
    network" in seconds instead of minutes, because the expensive part is the
    per-host service/OS probing and the port timeouts. It stores the same
    presence data (sightings) as a deep scan, just without ports or OS.

    Before the service pass, a quick `-O` probe on localhost determines
    whether OS fingerprinting is available without privileges.  If the
    probe fails the service pass retries without `-O` so the scan still
    completes (just without OS guesses).

    The TargetGuard runs before the runner is ever touched, so an illegal
    target never reaches nmap.
    """

    def __init__(
        self,
        runner: NmapRunner,
        resolver: NameResolver | None = None,
        netbios: NetbiosNameResolver | None = None,
    ) -> None:
        self.runner = runner
        # #41: optional name sources. None keeps every existing caller (and
        # every test) on the pure-nmap behaviour. mDNS is host-agnostic and
        # runs in the background; NetBIOS needs the discovered addresses, so
        # it runs after the discovery pass.
        self.resolver = resolver
        self.netbios = netbios

    def scan(
        self,
        target: str,
        progress: ProgressCallback | None = None,
        deep: bool = True,
    ) -> ScanResult:
        net = validate_target(target)  # raises IllegalTargetError before any run()
        target_str = str(net)
        mode = MODE_DEEP if deep else MODE_QUICK
        # mDNS takes a few seconds, so it runs while nmap works (#41). Nothing
        # waits for it until a scan has hosts to attach names to.
        lookup = _NameLookup(self.resolver)

        if progress is not None:
            progress(PHASE_DISCOVERY, None)  # entering the discovery pass

        discovery_xml = self.runner.run(["-sn", "-oX", "-", target_str])
        discovered_hosts = [h for h in parse_nmap_xml(discovery_xml, target_str).hosts if h.up]

        if progress is not None:
            for host in discovered_hosts:
                progress(PHASE_DISCOVERY, host)

        # NetBIOS needs the addresses, so it starts once discovery is parsed;
        # its queries are parallel and short (1 s), so it costs little.
        netbios_names = self._netbios_names([h.ip for h in discovered_hosts])

        if not deep:
            # Quick scan: discovery IS the result. No probe, no service pass —
            # `probe_os()` would itself run nmap and cost seconds.
            names = {**netbios_names, **lookup.names()}  # mDNS wins on a clash
            hosts = self._with_names(tuple(discovered_hosts), names)
            return ScanResult(target=target_str, hosts=hosts, mode=mode)

        discovered = [h.ip for h in discovered_hosts]

        if not discovered:
            return ScanResult(target=target_str, hosts=(), mode=mode)

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
            hosts=self._with_names(result.hosts, {**netbios_names, **lookup.names()}),
            os_detection_available=os_available,
            mode=mode,
        )

    def _netbios_names(self, ips: list[str]) -> dict[str, str]:
        """NetBIOS workstation names for the discovered hosts (#41 part 2).

        Best-effort like every other name source: a blocked UDP 137, a timeout
        or a device answering nonsense yields no names, never an error.
        """
        if self.netbios is None or not ips:
            return {}
        try:
            return dict(self.netbios.names_by_ip(ips))
        except Exception:  # noqa: BLE001 - names must never fail a scan
            return {}

    def _with_names(
        self,
        hosts: tuple[HostResult, ...],
        names: Mapping[str, str],
    ) -> tuple[HostResult, ...]:
        """Fill hostnames from mDNS/NetBIOS where PTR gave nothing useful (#41).

        Two cases use the learned name:

        * the host has no PTR name at all;
        * the PTR name is shared by several hosts in THIS scan — that is the
          sinkhole signature (`blocked.local` for every address on Falco's
          LAN), and the store suppresses such names at read time anyway, so
          the device would otherwise show as "vendor device (ip)".

        A unique PTR name always wins: it is what the network says, and
        overwriting it with a self-reported name would be a downgrade.
        """
        counts = Counter(h.hostname for h in hosts if h.hostname)
        out: list[HostResult] = []
        for host in hosts:
            proposed = names.get(host.ip)
            if proposed and (not host.hostname or counts[host.hostname] > 1):
                host = replace(host, hostname=proposed)
            out.append(host)
        return tuple(out)


class _NameLookup:
    """Run a name lookup in the background while nmap scans.

    The resolver has its own timeout; this class only guarantees that a wedged
    lookup cannot hold a scan hostage (`JOIN_TIMEOUT`) and that an exception
    inside it never escapes (a name is a nicety, not a scan result).
    """

    JOIN_TIMEOUT = 10.0

    def __init__(self, resolver: NameResolver | None) -> None:
        self._names: dict[str, str] = {}
        self._thread: threading.Thread | None = None
        if resolver is not None:
            self._thread = threading.Thread(
                target=self._run,
                args=(resolver,),
                daemon=True,
                name="netscope-mdns",
            )
            self._thread.start()

    def _run(self, resolver: NameResolver) -> None:
        try:
            self._names = dict(resolver.names_by_ip())
        except Exception:  # noqa: BLE001 - a name lookup must never fail a scan
            self._names = {}

    def names(self) -> dict[str, str]:
        if self._thread is not None:
            self._thread.join(timeout=self.JOIN_TIMEOUT)
        return self._names
