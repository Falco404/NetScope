"""Frontend wiring for the two scan buttons (#39) — text inspection.

The behaviour (which nmap passes run) is covered by the engine and API tests;
these guards only pin that the page has both buttons, that the mode actually
travels in the POST body, and that no element id went stale in the rename.
"""

import re
from pathlib import Path

STATIC = Path(__file__).parent.parent / "netscope" / "api" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def test_page_has_a_quick_and_a_deep_button():
    html = _read("index.html")
    assert 'id="quick-btn"' in html, "quick scan button missing"
    assert 'id="deep-btn"' in html, "deep scan button missing"
    assert "Quick scan" in html and "Deep scan" in html
    assert 'id="scan-btn"' not in html, "the single #scan-btn is gone since #39"


def test_each_button_sends_its_own_mode():
    src = _read("app.js")
    assert '$("quick-btn").addEventListener("click", () => startScan("quick"))' in src
    assert '$("deep-btn").addEventListener("click", () => startScan("deep"))' in src
    assert 'body: JSON.stringify({ target: $("target").value.trim(), mode })' in src, (
        "the mode must travel to /api/scan; the server decides which passes run"
    )


def test_both_buttons_are_disabled_while_a_scan_runs():
    """One scan at a time is a server rule (409); the UI must not offer a
    second click that would fail."""
    src = _read("app.js")
    start = src.index("function setScanning(")
    body = src[start : src.index("}", start)]
    assert '$("quick-btn").disabled = busy' in body
    assert '$("deep-btn").disabled = busy' in body
    assert src.count("setScanning(") >= 3, "startScan/pollStatus must call setScanning"


def test_quick_scan_labels_one_pass_and_fills_the_whole_bar():
    src = _read("app.js")
    assert "pass 1/${quick ? 1 : 2} (discovery)" in src, (
        "a quick scan has ONE pass; the status line must not say 1/2"
    )
    assert "quick ? 100 : 50" in src, "the quick scan's single pass fills the whole bar"


def test_every_element_id_used_by_app_js_exists_in_the_page():
    """A renamed id would throw at load time in the browser and nowhere else."""
    src = _read("app.js")
    html = _read("index.html")
    used = set(re.findall(r'\$\("([\w-]+)"\)', src))
    missing = sorted(i for i in used if f'id="{i}"' not in html)
    assert not missing, f"app.js looks up ids that index.html does not define: {missing}"


def test_ports_column_distinguishes_not_probed_from_nothing_open():
    src = _read("app.js")
    assert 'd.ports_probed === false ? "not probed"' in src, (
        "an empty Open ports cell after a quick scan must read 'not probed'"
    )


def test_device_panel_has_a_deep_scan_button():
    html = _read("index.html")
    assert 'id="detail-scan"' in html and "Deep scan this device" in html
    # It lives in the detail aside, next to the manual-name controls.
    aside = html[html.index('<aside id="detail"') :]
    assert 'id="detail-scan"' in aside


def test_device_scan_posts_to_the_device_endpoint_by_identity():
    """#74: the UI sends the identity; the server resolves the current IP.
    Building an address in JavaScript would use a stale one after DHCP."""
    src = _read("app.js")
    target = "/api/devices/${encodeURIComponent(detailIdentity)}/scan"
    assert f"await api(`{target}`, {{ method: \"POST\" }})" in src
    assert 'detailIp = d.ip;' in src, "the running status line needs the device IP"


def test_device_scan_button_is_disabled_while_any_scan_runs():
    src = _read("app.js")
    start = src.index("function setScanning(")
    body = src[start : src.index("}", start)]
    assert '$("detail-scan").disabled = busy' in body


def test_open_detail_is_refreshed_after_a_scan():
    """#74: a per-device scan is started from the detail panel, so finishing
    must re-render that panel — the device table alone would leave stale
    ports inside the open dialog."""
    src = _read("app.js")
    assert 'if (detailIdentity && !$("detail").hidden) await openDetail(detailIdentity);' in src
