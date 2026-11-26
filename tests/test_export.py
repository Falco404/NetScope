"""#43 export tests: `/api/export` CSV + JSON through TestClient — no network."""

import csv
import io
import json
import re
import time
from pathlib import Path

from fastapi.testclient import TestClient

from netscope.api import NetScopeAPI, build_app
from netscope.export import CSV_COLUMNS, csv_cell
from netscope.scanner.engine import NmapScanner
from netscope.scanner.models import HostResult, ScanResult
from netscope.store import SQLiteStore

FIXTURES = Path(__file__).parent / "fixtures"
STATIC = Path(__file__).parent.parent / "netscope" / "api" / "static"


class FakeRunner:
    """Replays the repo fixtures; `-sn` gets discovery, everything else services."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, args: list[str]) -> str:
        self.calls.append(args)
        name = "nmap_discovery.xml" if "-sn" in args else "nmap_service.xml"
        return (FIXTURES / name).read_text()

    def probe_os(self) -> bool:
        return True


def make_client(tmp_path):
    store = SQLiteStore(tmp_path / "test.db")
    scanner = NmapScanner(FakeRunner())
    api = NetScopeAPI(store, scanner, subnet_fn=lambda: None)
    client = TestClient(build_app(api, extra_hosts=("testserver",)))
    return client, api, store


def run_scan(client, api, mode="deep", target="192.168.1.0/24"):
    res = client.post("/api/scan", json={"target": target, "mode": mode})
    assert res.status_code == 200
    deadline = 500
    while api.status()["state"] == "running" and deadline:
        deadline -= 1
        time.sleep(0.02)
    status = api.status()
    assert status["state"] == "done", status
    return status


def read_csv(body: bytes) -> list[list[str]]:
    text = body.decode("utf-8-sig")
    return list(csv.reader(io.StringIO(text)))


def test_export_csv_one_row_per_device_with_service_and_version(tmp_path):
    client, api, store = make_client(tmp_path)
    run_scan(client, api)

    res = client.get("/api/export?format=csv")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert re.fullmatch(
        r'attachment; filename="netscope-inventory-\d{8}-\d{6}\.csv"',
        res.headers["content-disposition"],
    )
    # UTF-8 BOM for Windows Excel, then one header row + one row per device.
    assert res.content.startswith(b"\xef\xbb\xbf")
    rows = read_csv(res.content)
    assert rows[0] == list(CSV_COLUMNS)
    assert len(rows) == 3  # header + atom + apollo

    by_ip = {row[2]: dict(zip(CSV_COLUMNS, row, strict=True)) for row in rows[1:]}
    atom = by_ip["192.168.1.10"]
    assert atom["identity"] == "AA:BB:CC:DD:EE:01"
    assert atom["mac"] == "AA:BB:CC:DD:EE:01"
    assert atom["name"] == "atom"
    assert atom["status"] == "seen"
    assert atom["ports_probed"] == "true"
    # nmap's own service + version, flattened into one cell.
    assert atom["open_ports"] == "22/tcp ssh 8.4p1 Debian; 80/tcp http 1.22.1"
    store.close()


def test_export_csv_marks_quick_scan_ports_as_not_probed(tmp_path):
    """#39 rule in the export: a quick scan never measured ports."""
    client, api, store = make_client(tmp_path)
    run_scan(client, api, mode="quick")

    rows = read_csv(client.get("/api/export?format=csv").content)
    by_ip = {row[2]: dict(zip(CSV_COLUMNS, row, strict=True)) for row in rows[1:]}
    atom = by_ip["192.168.1.10"]
    assert atom["ports_probed"] == "false"
    assert atom["open_ports"] == "not probed"
    store.close()


def test_export_json_is_lossless_with_stamp_and_count(tmp_path):
    client, api, store = make_client(tmp_path)
    run_scan(client, api)

    res = client.get("/api/export?format=json")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/json")
    assert re.fullmatch(
        r'attachment; filename="netscope-inventory-\d{8}-\d{6}\.json"',
        res.headers["content-disposition"],
    )

    payload = json.loads(res.content)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", payload["generated_at"])
    assert payload["device_count"] == len(payload["devices"]) == 2

    atom = next(d for d in payload["devices"] if d["name"] == "atom")
    assert atom["mac"] == "AA:BB:CC:DD:EE:01"
    assert atom["os_guess"] == "Linux 2.6.32 - 3.x"
    assert atom["ports_probed"] is True
    ports = {p["port"]: p for p in atom["ports"]}
    assert ports[22] == {
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "version": "8.4p1 Debian",
    }
    store.close()


def test_export_neutralises_spreadsheet_formulas(tmp_path):
    """A LAN hostname is untrusted input: Excel must not execute it."""
    client, _, store = make_client(tmp_path)
    hostile = '=HYPERLINK("http://evil.example","click")'
    store.save_scan(
        ScanResult(
            target="192.168.5.0/24",
            hosts=(
                HostResult(
                    ip="192.168.5.5",
                    up=True,
                    hostname=hostile,
                    mac="02:00:00:00:00:99",
                    mac_vendor="@SUM(1+1)",
                ),
            ),
        ),
        {},
    )

    rows = read_csv(client.get("/api/export?format=csv").content)
    row = dict(zip(CSV_COLUMNS, rows[1], strict=True))
    assert row["hostname"] == "'" + hostile
    assert row["name"] == "'" + hostile  # display_name falls through to hostname
    assert row["vendor"] == "'@SUM(1+1)"

    # JSON is not a spreadsheet: it keeps the value verbatim.
    payload = json.loads(client.get("/api/export?format=json").content)
    assert payload["devices"][0]["hostname"] == hostile
    store.close()


def test_csv_cell_neutralises_after_leading_whitespace():
    # Excel trims before evaluating, so the check must ignore leading spaces.
    assert csv_cell(" =1+1") == "' =1+1"
    assert csv_cell("plain") == "plain"
    assert csv_cell(None) == ""
    assert csv_cell(22) == "22"


def test_export_empty_inventory(tmp_path):
    client, _, store = make_client(tmp_path)

    rows = read_csv(client.get("/api/export?format=csv").content)
    assert rows == [list(CSV_COLUMNS)]

    payload = json.loads(client.get("/api/export?format=json").content)
    assert payload["device_count"] == 0
    assert payload["devices"] == []
    store.close()


def test_export_rejects_an_unknown_format(tmp_path):
    client, _, store = make_client(tmp_path)
    assert client.get("/api/export?format=xml").status_code == 422
    store.close()


def test_export_agrees_with_the_devices_endpoint(tmp_path):
    """The file and the table must never disagree (#43: one shared inventory)."""
    client, api, store = make_client(tmp_path)
    run_scan(client, api)

    devices = {d["identity"]: d for d in client.get("/api/devices").json()}
    rows = read_csv(client.get("/api/export?format=csv").content)
    exported = {row[0]: dict(zip(CSV_COLUMNS, row, strict=True)) for row in rows[1:]}

    assert set(exported) == set(devices)
    for identity, device in devices.items():
        assert exported[identity]["status"] == device["status"]
        assert exported[identity]["ip"] == device["ip"]
        assert exported[identity]["name"] == device["name"]
        assert exported[identity]["ports_probed"] == ("true" if device["ports_probed"] else "false")
        if device["ports_probed"]:
            assert exported[identity]["open_ports"].split("; ")[0].startswith(
                device["open_ports"][0]
            )
    store.close()


def test_index_offers_both_export_downloads():
    """No JS involved: two plain links, so the UI stays dumb."""
    html = (STATIC / "index.html").read_text()
    assert 'href="/api/export?format=csv"' in html
    assert 'href="/api/export?format=json"' in html
    assert html.count('class="export-link"') >= 2
