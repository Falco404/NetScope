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
        proc = subprocess.run(
            [self.binary, *args],
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"nmap failed (exit {proc.returncode}): {proc.stderr.strip()}")
        return proc.stdout
