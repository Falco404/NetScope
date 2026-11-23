"""Scanner package: nmap behind an interface (M3).

Design rule (AGENTS.md): subprocess invocation must be separable from XML
parsing so tests replay recorded XML fixtures with zero network. Every scan
goes through TargetGuard (netscope.target) before the runner is touched.
"""

from netscope.scanner.engine import NmapScanner, ScanResult
from netscope.scanner.models import HostResult, PortResult
from netscope.scanner.parser import parse_nmap_xml
from netscope.scanner.runner import NmapRunner, SubprocessNmapRunner

__all__ = [
    "HostResult",
    "NmapRunner",
    "NmapScanner",
    "PortResult",
    "ScanResult",
    "SubprocessNmapRunner",
    "parse_nmap_xml",
]
