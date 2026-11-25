"""FastAPI app: JSON API + static frontend for the NetScope web UI.

All scan logic stays server-side (TargetGuard, engine, store); the frontend is
dumb — it fetches JSON and renders. Server binding is configured by env vars
in netscope/__main__.py: localhost by default, LAN only on explicit request.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.trustedhost import TrustedHostMiddleware

from netscope.device import Device
from netscope.local_subnet import local_subnet as _detect_local_subnet
from netscope.scanner.engine import NmapScanner
from netscope.store import SQLiteStore
from netscope.target import IllegalTargetError, validate_target

STATIC_DIR = Path(__file__).parent / "static"

# #36: the UI only answers requests whose Host header is a trusted name.
# Loopback by default; a LAN bind must name the hosts clients actually use
# (0.0.0.0 is a bind address, never a Host header). Starlette compares the
# hostname with the port stripped and case-insensitively, and answers 400
# "Invalid host header" on a mismatch.
DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1")


@dataclass
class ScanJob:
    """State of the single background scan the server can run at a time.

    Progress state is IN-PROCESS only (#37): it is transient telemetry of
    the running scan — once the scan is done, the final inventory is already
    in the store, so persisting per-phase counters would add schema churn
    for no readable history.
    """

    state: str = "idle"  # idle | running | done | error
    target: str | None = None
    hosts_found: int = 0  # cumulative sightings across both passes
    phase: str | None = None  # "discovery" | "services" while running
    hosts_in_phase: int = 0  # sightings reported by the CURRENT pass
    scan_id: int | None = None
    error: str | None = None
    duration_seconds: float | None = None
    started_at: float | None = None
    os_detection_available: bool = True


class ScanRequest(BaseModel):
    target: str


class DeviceNameRequest(BaseModel):
    name: str


class NetScopeAPI:
    """Owns the store, the scanner and one scan job; build_app() exposes it."""

    def __init__(
        self,
        store: SQLiteStore,
        scanner: NmapScanner,
        subnet_fn: Callable[[], str | None] = _detect_local_subnet,
    ) -> None:
        self.store = store
        self.scanner = scanner
        self.subnet_fn = subnet_fn
        self.job = ScanJob()
        self._lock = threading.Lock()

    def local_subnet(self) -> str | None:
        """Server's own subnet guess (injectable in tests)."""
        return self.subnet_fn()

    def device_map(self) -> dict[str, Device]:
        return {d.identity: d for d in self.store.load_devices()}

    def start_scan(self, target: str) -> ScanJob:
        # Guard FIRST: an illegal target never reaches the scanner or store.
        try:
            net = validate_target(target)
        except IllegalTargetError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        with self._lock:
            if self.job.state == "running":
                raise HTTPException(status_code=409, detail="a scan is already running")
            self.job = ScanJob(state="running", target=str(net), started_at=time.monotonic())
        thread = threading.Thread(target=self._run_scan, args=(str(net),), daemon=True)
        thread.start()
        return self.job

    def _run_scan(self, target: str) -> None:
        started = time.monotonic()
        try:
            result = self.scanner.scan(target, progress=self._on_host)
            duration = round(time.monotonic() - started, 2)
            scan_id, _ = self.store.save_scan(result, self.device_map(), duration_seconds=duration)
            with self._lock:
                self.job.state = "done"
                self.job.scan_id = scan_id
                self.job.duration_seconds = duration
                self.job.os_detection_available = result.os_detection_available
        except Exception as exc:  # nmap failure etc. -> reported to the UI
            with self._lock:
                self.job.state = "error"
                self.job.error = str(exc)

    def _on_host(self, phase: str, host: Any) -> None:
        # host is None on the engine's phase-start sentinel: flip the phase
        # and reset the per-phase counter, count nothing.
        # A discovered host (discovery pass) bumps BOTH counters — hosts_found
        # is "hosts discovered", the denominator the service pass later uses.
        # A service-pass host bumps ONLY hosts_in_phase: the service pass
        # fingerprints hosts discovery already found, it does not discover
        # new ones, so hosts_found stays at the discovery total.
        with self._lock:
            if host is None:
                self.job.phase = phase
                self.job.hosts_in_phase = 0
            elif phase == "services":
                self.job.phase = phase
                self.job.hosts_in_phase += 1
            else:
                self.job.phase = phase
                self.job.hosts_found += 1
                self.job.hosts_in_phase += 1

    def status(self) -> dict[str, Any]:
        with self._lock:
            elapsed = (
                round(time.monotonic() - self.job.started_at, 1)
                if self.job.state == "running" and self.job.started_at is not None
                else None
            )
            return {
                "state": self.job.state,
                "target": self.job.target,
                "hosts_found": self.job.hosts_found,
                "phase": self.job.phase,
                "hosts_in_phase": self.job.hosts_in_phase,
                "scan_id": self.job.scan_id,
                "error": self.job.error,
                "duration_seconds": self.job.duration_seconds,
                "elapsed_seconds": elapsed,
                # Per nmap call limit; the scan runs two passes (discovery, services).
                "timeout_seconds": getattr(self.scanner.runner, "timeout", None),
                "os_detection_available": self.job.os_detection_available,
            }


def build_app(api: NetScopeAPI, extra_hosts: tuple[str, ...] = ()) -> FastAPI:
    app = FastAPI(title="NetScope", docs_url=None, redoc_url=None)
    # Outermost middleware: a foreign Host header never reaches a route, so
    # DNS rebinding cannot drive the unauthenticated localhost UI (#36).
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[*DEFAULT_ALLOWED_HOSTS, *extra_hosts])

    @app.get("/api/scans")
    def scans() -> list[dict[str, Any]]:
        return [
            {
                "id": s.id,
                "ts": s.ts,
                "target": s.target,
                "duration_seconds": s.duration_seconds,
            }
            for s in api.store.list_scans()
        ]

    @app.get("/api/devices")
    def devices() -> list[dict[str, Any]]:
        sightings_cache: dict[int, dict[str, str]] = {}

        def sightings_for(scan_id: int) -> dict[str, str]:
            if scan_id not in sightings_cache:
                sightings_cache[scan_id] = api.store.sightings(scan_id)
            return sightings_cache[scan_id]

        out = []
        for d in api.store.load_devices():
            # Presence is judged against the latest scan that could have seen
            # this device (#31): a single-IP scan of another device must not
            # mark every other device absent, and an up host with zero open
            # ports is still seen.
            cover = api.store.latest_scan_covering(d.ip)
            seen = sightings_for(cover) if cover is not None else {}
            ports = api.store.scan_ports(cover) if cover is not None else {}
            open_ports = sorted(ports.get(d.identity, ()))
            out.append(
                {
                    "identity": d.identity,
                    "ip": d.ip,
                    "name": d.display_name,
                    "manual_name": d.name,
                    "hostname": d.hostname,
                    "vendor": d.vendor,
                    "os_guess": d.os_guess,
                    "status": "seen" if d.identity in seen else "absent",
                    "open_ports": [f"{p}/{proto}" for p, proto in open_ports],
                    "last_seen_scan": d.last_seen_scan,
                }
            )
        return out

    @app.get("/api/devices/{identity}")
    def device_detail(identity: str) -> dict[str, Any]:
        devices = {d.identity: d for d in api.store.load_devices()}
        device = devices.get(identity)
        if device is None:
            raise HTTPException(status_code=404, detail="unknown device")
        latest = api.store.latest_scan_id()
        rows = api.store.port_history(identity)
        return {
            "identity": device.identity,
            "ip": device.ip,
            "name": device.display_name,
            "manual_name": device.name,
            "hostname": device.hostname,
            "mac": device.mac,
            "vendor": device.vendor,
            "os_guess": device.os_guess,
            "last_seen_scan": device.last_seen_scan,
            "latest_scan_id": latest,
            "ports": [
                {
                    "scan_id": r[0],
                    "port": r[1],
                    "protocol": r[2],
                    "service": r[3],
                    "version": r[4],
                }
                for r in rows
            ],
        }

    @app.put("/api/devices/{identity}/name")
    def set_device_name(identity: str, req: DeviceNameRequest) -> dict[str, Any]:
        # Manual label (M8): survives later scans and beats hostname/vendor.
        try:
            name = api.store.set_device_name(identity, req.name)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="unknown device") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"identity": identity, "name": name}

    @app.delete("/api/devices/{identity}/name")
    def clear_device_name(identity: str) -> dict[str, Any]:
        try:
            api.store.clear_device_name(identity)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="unknown device") from exc
        return {"identity": identity, "name": None}

    @app.get("/api/diff")
    def diff(from_id: int | None = None, to_id: int | None = None) -> dict[str, Any]:
        scans = api.store.list_scans()  # newest first
        if to_id is None:
            if not scans:
                raise HTTPException(status_code=404, detail="no scans stored")
            to_id = scans[0].id
        elif not api.store.scan_exists(to_id):
            raise HTTPException(status_code=404, detail=f"unknown scan id: {to_id}")
        if from_id is None:
            # Default previous scan must share the target (#31): comparing a
            # single-IP scan against a /24 scan of unrelated devices is noise.
            target_to = api.store.scan_target(to_id)
            prev = [s.id for s in scans if s.id < to_id and s.target == target_to]
            if not prev:
                raise HTTPException(
                    status_code=404, detail="no earlier scan with the same target to compare"
                )
            from_id = prev[0]
        elif not api.store.scan_exists(from_id):
            raise HTTPException(status_code=404, detail=f"unknown scan id: {from_id}")
        d = api.store.diff_scans(from_id, to_id)
        names = {x.identity: x.display_name for x in api.store.load_devices()}
        return {
            "from_scan": from_id,
            "to_scan": to_id,
            "appeared": [{"identity": i, "name": names.get(i, i)} for i in d.new_devices],
            "disappeared": [{"identity": i, "name": names.get(i, i)} for i in d.gone_devices],
            "changed": [{"identity": i, "name": names.get(i, i)} for i in d.changed_devices],
        }

    @app.get("/api/local-subnet")
    def local_subnet() -> dict[str, Any]:
        """Best guess at the server's own subnet, for the UI's default target.
        Null when the machine sits on a public or unusual network."""
        return {"target": api.local_subnet()}

    @app.post("/api/scan")
    def start_scan(req: ScanRequest) -> dict[str, Any]:
        api.start_scan(req.target)
        return api.status()

    @app.get("/api/scan/status")
    def scan_status() -> dict[str, Any]:
        return api.status()

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")

    return app
