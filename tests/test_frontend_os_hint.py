"""Frontend wiring for the #34 OS hint (text inspection, runs anywhere).

The sentence itself is decided by the server (`GET /api/os-hint`, covered in
tests/test_api.py); these guards only pin that the UI has somewhere to put it,
hides it when there is nothing to say, and renders it as text, never markup.
"""

from pathlib import Path

STATIC = Path(__file__).parent.parent / "netscope" / "api" / "static"


def test_index_html_has_a_hidden_os_hint_placeholder():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert 'id="os-hint"' in html, "the Devices section needs a #os-hint element"
    assert 'id="os-hint" class="hint" hidden' in html, (
        "the hint must start hidden: an empty paragraph should not take space"
    )


def test_app_js_asks_the_server_for_the_hint_and_toggles_visibility():
    src = (STATIC / "app.js").read_text(encoding="utf-8")
    assert '"/api/os-hint"' in src, "app.js must read the hint from /api/os-hint"
    assert '$("os-hint").textContent = hint ?? ""' in src, (
        "the hint text must be assigned with textContent"
    )
    assert '$("os-hint").hidden = !hint' in src, "the hint must hide when there is none"
    assert "await loadOsHint();" in src, "loadAll() must refresh the hint after a scan"


def test_hint_failure_never_breaks_the_device_list():
    """A 404/500 on /api/os-hint (older server, broken DB) must not stop the
    device table from rendering — loadAll() awaits it before loading scans."""
    src = (STATIC / "app.js").read_text(encoding="utf-8")
    start = src.index("async function loadOsHint()")
    body = src[start : src.index("async function loadAll()")]
    assert "try {" in body and "catch" in body, "loadOsHint must swallow its own errors"
