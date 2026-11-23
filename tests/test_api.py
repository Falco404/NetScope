"""API endpoint tests via TestClient + fake runner + temp DB — no network."""

import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from netscope.api import NetScopeAPI, build_app
from netscope.scanner.engine import NmapScanner
from netscope.scanner.parser import parse_nmap_xml
from netscope.store import SQLiteStore

FIXTURES = Path(__file__).parent / "fixtures"


class FakeRunner:
    def __init__(self, block: threading.Event | None = None) -> None:
        self.block = block
        self.calls: list[list[str]] = []

    def run(self, args: list[str]) -> str:
        self.calls.append(args)
        if self.block is not None:
            self.block.wait(timeout=5)
        name = "nmap_discovery.xml" if "-sn" in args else "nmap_service.xml"
        return (FIXTURES / name).read_text()


def make_client(tmp_path, block=None, subnet=None):
    store = SQLiteStore(tmp_path / "test.db")
    api = NetScopeAPI(store, NmapScanner(FakeRunner(block)), subnet_fn=lambda: subnet)
    client = TestClient(build_app(api))
    return client, api, store


def wait_done(api, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if api.status()["state"] != "running":
            return api.status()
        time.sleep(0.05)
    raise AssertionError("scan never finished")


def test_index_serves_html(tmp_path):
    client, _, store = make_client(tmp_path)
    res = client.get("/")
    assert res.status_code == 200
    assert "NetScope" in res.text
    store.close()


def test_illegal_target_rejected_before_scanning(tmp_path):
    client, api, store = make_client(tmp_path)
    res = client.post("/api/scan", json={"target": "8.8.8.8"})
    assert res.status_code == 400
    assert "private" in res.json()["detail"].lower() or "8.8.8.8" in res.json()["detail"]
    assert api.store.list_scans() == []  # guard: nothing stored, runner untouched
    assert api.status()["state"] == "idle"
    store.close()


def test_scan_flow_and_devices(tmp_path):
    client, api, store = make_client(tmp_path)
    res = client.post("/api/scan", json={"target": "192.168.1.0/24"})
    assert res.status_code == 200
    assert res.json()["state"] == "running"

    status = wait_done(api)
    assert status["state"] == "done"
    assert status["scan_id"] == 1
    assert status["hosts_found"] == 2  # progress callback counted both up hosts

    devices = client.get("/api/devices").json()
    names = {d["name"] for d in devices}
    assert names == {"atom", "apollo"}
    atom = next(d for d in devices if d["name"] == "atom")
    assert atom["status"] == "seen"
    assert atom["open_ports"] == ["22/tcp", "80/tcp"]
    assert atom["os_guess"] == "Linux"

    detail = client.get("/api/devices/AA:BB:CC:DD:EE:01").json()
    assert detail["hostname"] == "atom"
    assert detail["mac"] == "AA:BB:CC:DD:EE:01"
    ssh = next(p for p in detail["ports"] if p["port"] == 22)
    assert ssh["service"] == "ssh"
    assert ssh["version"] == "8.4p1 Debian"

    assert client.get("/api/devices/does-not-exist").status_code == 404

    scans = client.get("/api/scans").json()
    assert scans[0]["target"] == "192.168.1.0/24"
    assert scans[0]["duration_seconds"] is not None
    store.close()


def test_manual_name_roundtrip(tmp_path):
    client, api, store = make_client(tmp_path)
    client.post("/api/scan", json={"target": "192.168.1.0/24"})
    wait_done(api)
    identity = "AA:BB:CC:DD:EE:01"

    res = client.put(f"/api/devices/{identity}/name", json={"name": "Atom homeserver"})
    assert res.status_code == 200
    assert res.json() == {"identity": identity, "name": "Atom homeserver"}

    devices = client.get("/api/devices").json()
    atom = next(d for d in devices if d["identity"] == identity)
    assert atom["name"] == "Atom homeserver"  # list shows the manual label
    assert atom["manual_name"] == "Atom homeserver"
    assert atom["hostname"] == "atom"  # scan-learned hostname still there

    detail = client.get(f"/api/devices/{identity}").json()
    assert detail["name"] == "Atom homeserver"
    assert detail["manual_name"] == "Atom homeserver"

    # Overwrite, then run another scan: the manual label survives.
    client.put(f"/api/devices/{identity}/name", json={"name": "atom-server"})
    client.post("/api/scan", json={"target": "192.168.1.0/24"})
    wait_done(api)
    assert client.get(f"/api/devices/{identity}").json()["name"] == "atom-server"

    res = client.delete(f"/api/devices/{identity}/name")
    assert res.status_code == 200
    assert client.get(f"/api/devices/{identity}").json()["name"] == "atom"  # fallback

    assert client.put("/api/devices/no-such-device/name", json={"name": "x"}).status_code == 404
    assert client.delete("/api/devices/no-such-device/name").status_code == 404
    assert client.put(f"/api/devices/{identity}/name", json={"name": "   "}).status_code == 400
    store.close()


def test_second_scan_diff(tmp_path):
    client, api, store = make_client(tmp_path)
    client.post("/api/scan", json={"target": "192.168.1.0/24"})
    wait_done(api)
    # second scan with an empty discovery -> everything disappeared
    api.scanner.runner = FakeRunner()  # keep fixtures; empty via direct store save instead
    store.save_scan(parse_nmap_xml((FIXTURES / "nmap_empty.xml").read_text(), "192.168.1.0/24"), {})

    diff = client.get("/api/diff").json()
    assert diff["from_scan"] == 1
    assert diff["to_scan"] == 2
    names = {x["name"] for x in diff["disappeared"]}
    assert names == {"atom", "apollo"}
    store.close()


def test_diff_without_history(tmp_path):
    client, _, store = make_client(tmp_path)
    assert client.get("/api/diff").status_code == 404
    store.close()


def test_runner_failure_surfaces_error_message(tmp_path):
    class BrokenRunner:
        def run(self, args: list[str]) -> str:
            raise RuntimeError("nmap binary 'nmap' not found — install it")

    store = SQLiteStore(tmp_path / "test.db")
    api = NetScopeAPI(store, NmapScanner(BrokenRunner()))
    client = TestClient(build_app(api))
    client.post("/api/scan", json={"target": "192.168.1.0/24"})
    status = wait_done(api)
    assert status["state"] == "error"
    assert "not found" in status["error"]
    assert api.store.list_scans() == []
    store.close()


def test_status_reports_elapsed_and_limit(tmp_path):
    block = threading.Event()
    client, api, store = make_client(tmp_path, block=block)
    client.post("/api/scan", json={"target": "192.168.1.0/24"})
    running = client.get("/api/scan/status").json()
    assert running["state"] == "running"
    assert running["elapsed_seconds"] is not None and running["elapsed_seconds"] >= 0
    # Fake runner has no timeout attribute -> the limit is unknown (null),
    # which the UI omits instead of inventing a number.
    assert running["timeout_seconds"] is None
    block.set()
    assert wait_done(api)["state"] == "done"
    assert client.get("/api/scan/status").json()["elapsed_seconds"] is None
    store.close()


def test_busy_scan_returns_409(tmp_path):
    block = threading.Event()
    client, api, store = make_client(tmp_path, block=block)
    assert client.post("/api/scan", json={"target": "192.168.1.0/24"}).status_code == 200
    second = client.post("/api/scan", json={"target": "10.0.0.0/24"})
    assert second.status_code == 409

    block.set()
    assert wait_done(api)["state"] == "done"
    store.close()


def test_local_subnet_endpoint_reports_detected_subnet(tmp_path):
    client, _, store = make_client(tmp_path, subnet="192.168.0.0/24")
    assert client.get("/api/local-subnet").json() == {"target": "192.168.0.0/24"}
    store.close()


def test_local_subnet_endpoint_reports_null(tmp_path):
    client, _, store = make_client(tmp_path, subnet=None)
    assert client.get("/api/local-subnet").json() == {"target": None}
    store.close()
