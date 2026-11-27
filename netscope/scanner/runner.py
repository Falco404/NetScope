"""nmap subprocess behind an interface — the only place real nmap runs."""

from __future__ import annotations

import logging
import subprocess
from typing import Protocol

NMAP_TIMEOUT_SECONDS = 300

logger = logging.getLogger(__name__)


class NmapRunner(Protocol):
    """Runs nmap with the given args and returns its XML output.

    Tests substitute a fake runner that replays recorded fixtures, so the
    engine/parser are testable with zero network (AGENTS.md).
    """

    def run(self, args: list[str]) -> str: ...
    def probe_os(self) -> bool: ...


class SubprocessNmapRunner:
    """Real runner: invokes the nmap binary, XML to stdout (`-oX -`)."""

    def __init__(self, binary: str = "nmap", timeout: float = NMAP_TIMEOUT_SECONDS) -> None:
        self.binary = binary
        self.timeout = timeout

    def run(self, args: list[str]) -> str:
        try:
            proc = subprocess.run(
                [self.binary, *args],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError:
            # Surfaced as the scan error in the UI, so make it actionable.
            raise RuntimeError(
                f"nmap binary '{self.binary}' not found — install it "
                "(Linux/WSL: apt install nmap; Windows: winget install nmap)"
            ) from None
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"nmap timed out after {self.timeout}s") from None
        if proc.returncode != 0:
            # The UI shows this string, so it carries the actionable part only:
            # nmap's stderr names absolute paths (/root/.nmap/scripts, cached
            # databases) and internal tool state. Full text goes to the log.
            stderr = proc.stderr.strip()
            logger.warning("nmap exited %s: %s", proc.returncode, stderr)
            raise RuntimeError(
                f"nmap failed (exit {proc.returncode}) — see the server log for the details"
            )
        return proc.stdout

    def probe_os(self) -> bool:
        """Check whether nmap can do OS fingerprinting (-O) without privileges.

        Runs a quick scan of localhost with -O; returns True on success,
        False if nmap refuses (e.g. "requires root privileged" on Linux).
        """
        try:
            self.run(["-sV", "-O", "-oX", "-", "127.0.0.1"])
            return True
        except RuntimeError:
            return False
