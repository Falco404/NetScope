"""Frontend safety guards (issue #32).

Scan-derived strings (hostname, OS guess, vendor, service product) come from
the network and are stored in SQLite, so rendering them by interpolating into
HTML markup is stored XSS: a hostile LAN device could send
`<img src=x onerror=...>` as its reverse-DNS name and run script in the UI.

These checks are pure text inspection, so they run on Windows and Linux alike.
"""

from pathlib import Path

APP_JS = Path(__file__).parent.parent / "netscope" / "api" / "static" / "app.js"

FORBIDDEN = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"]


def test_no_markup_injection_apis():
    src = APP_JS.read_text(encoding="utf-8")
    for api in FORBIDDEN:
        assert api not in src, f"app.js must not use {api} to render scan data (#32)"


def test_scan_data_is_rendered_with_text_content():
    src = APP_JS.read_text(encoding="utf-8")
    assert "textContent" in src, "cells must be set with textContent"
    assert "createElement" in src, "cells must be created with createElement"
    assert "replaceChildren" in src, "lists must be rebuilt with replaceChildren"
