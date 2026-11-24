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


def test_replace_children_spreads_array_arguments():
    """A bare array passed to replaceChildren is coerced to a string.

    `replaceChildren(items)` renders "[object HTMLLIElement]" instead of the
    elements — the diff list bug seen in the live UI. Every call that passes
    a list must spread it with `...`; single-element calls pass el(...) directly.
    """
    src = APP_JS.read_text(encoding="utf-8")
    i = 0
    while (i := src.find("replaceChildren(", i)) != -1:
        j = i + len("replaceChildren(")
        depth = 1
        while depth:  # balance parens to find the end of the argument list
            if src[j] == "(":
                depth += 1
            elif src[j] == ")":
                depth -= 1
            j += 1
        args = src[i + len("replaceChildren(") : j - 1].strip()
        assert not args or args.startswith("...") or args.startswith("el("), (
            "replaceChildren() must spread array arguments with `...` "
            f"(a bare array renders as '[object HTMLLIElement]'): {args!r}"
        )
        i = j
