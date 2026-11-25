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


def test_progress_bar_is_not_a_hardcoded_fake():
    """#37: while a scan ran, the bar sat at a hardcoded 60% — a number with
    no relation to reality. The width must be computed from the status JSON
    (phase + host counts + elapsed/timeout), never a fixed percentage."""
    src = APP_JS.read_text(encoding="utf-8")
    # Every progress-bar width assignment must be computed, not a literal
    # percentage. The old code was `= s.state === "running" ? "60%" : ...`.
    i = 0
    saw_assignment = False
    while (i := src.find('$("progress-bar").style.width', i)) != -1:
        j = src.find(";", i)
        assert j != -1
        rhs = src[i + len('$("progress-bar").style.width') : j]
        assert "=" in rhs, "progress-bar width assignment malformed"
        rhs = rhs.split("=", 1)[1].strip()
        assert '"%' not in rhs and "'%" not in rhs, (
            f"#37: progress bar width must be computed from scan status, "
            f"not a hardcoded percentage: {rhs!r}"
        )
        saw_assignment = True
        i = j
    assert saw_assignment, "app.js must still drive the progress bar"

    # The width comes from a helper that reads the live progress fields.
    assert "function barWidth" in src, "bar width should come from a helper over the status JSON"
    start = src.find("function barWidth")
    body = src[start : start + 900]
    for field in ("phase", "hosts_in_phase", "hosts_found", "elapsed_seconds"):
        assert field in body, f"barWidth must use s.{field} to compute honest progress"


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
