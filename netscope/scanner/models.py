"""Structured scan results parsed from nmap XML."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PortResult:
    port: int
    protocol: str
    state: str
    service: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class HostResult:
    ip: str
    up: bool
    hostname: str | None = None
    mac: str | None = None
    mac_vendor: str | None = None
    os_match: str | None = None
    ports: tuple[PortResult, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ScanResult:
    target: str
    hosts: tuple[HostResult, ...]
