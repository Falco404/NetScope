"""nmap subprocess behind an interface — the only place real nmap runs."""

from __future__ import annotations

import subprocess
from typing import Protocol

NMAP_TIMEOUT_SECONDS = 300


class NmapRunner(Protocol):
    """Runs nmap with the given args and returns its XML output.

    Tests substitute a fake runner that replays recorded fixtures, so the
    engine/parser are testable with zero network (AGENTS.md).
    """

    def run(self, args: list[str]) -> str: ...


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
            raise RuntimeError(f"nmap failed (exit {proc.returncode}): {proc.stderr.strip()}")
        return proc.stdout
