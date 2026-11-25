"""Run the NetScope web server: `python -m netscope`.

Bind is localhost by default; expose on the LAN only by setting
NETSCOPE_HOST=0.0.0.0 explicitly. DB path via NETSCOPE_DB. The Host header
must be a trusted name (#36): loopback by default, plus NETSCOPE_HOST and
anything listed in NETSCOPE_ALLOWED_HOSTS (comma-separated).
"""

from __future__ import annotations

import math
import os

import uvicorn

from netscope.api import DEFAULT_ALLOWED_HOSTS, NetScopeAPI, build_app
from netscope.scanner import NmapScanner, SubprocessNmapRunner
from netscope.store import SQLiteStore
from netscope.vendor_registry import MAC_PREFIXES_FILENAME, OUI_VENDORS, load_default_mac_prefixes


def parse_port(value: str) -> int:
    """NETSCOPE_PORT: an integer between 1 and 65535 (#38).

    A typo used to surface as `ValueError: invalid literal for int() with
    base 10: '8000abc'` — a traceback that never says which variable was
    wrong, let alone what shape it wanted.
    """
    try:
        port = int(value)
    except ValueError:
        raise ValueError(
            f"NETSCOPE_PORT must be an integer port number (e.g. 8000), got {value!r}"
        ) from None
    if not 1 <= port <= 65535:
        raise ValueError(f"NETSCOPE_PORT must be between 1 and 65535, got {port}")
    return port


def parse_timeout(value: str) -> float:
    """NETSCOPE_NMAP_TIMEOUT: a finite number of seconds greater than 0 (#38).

    0 or a negative value would kill nmap the instant it starts; `nan`/`inf`
    would never kill it at all, so a hung scan would sit there forever.
    """
    try:
        timeout = float(value)
    except ValueError:
        raise ValueError(
            f"NETSCOPE_NMAP_TIMEOUT must be a number of seconds (e.g. 300), got {value!r}"
        ) from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(
            f"NETSCOPE_NMAP_TIMEOUT must be a finite number of seconds greater "
            f"than 0, got {value!r}"
        )
    return timeout


def main() -> None:
    host = os.environ.get("NETSCOPE_HOST", "127.0.0.1")
    # #38: validate the numeric config BEFORE anything is created — a bad
    # timeout used to be parsed only after SQLiteStore() had already written
    # a database file to the current directory, so the crash left one behind.
    try:
        port = parse_port(os.environ.get("NETSCOPE_PORT", "8000"))
        timeout = parse_timeout(os.environ.get("NETSCOPE_NMAP_TIMEOUT", "300"))
    except ValueError as exc:
        raise SystemExit(f"Bad configuration: {exc}") from None
    # #36: trusted Host header names. Loopback is always allowed; a LAN bind
    # must name the hosts clients actually use, because 0.0.0.0 is a bind
    # address and never appears as a Host header.
    extra_hosts = [
        h.strip() for h in os.environ.get("NETSCOPE_ALLOWED_HOSTS", "").split(",") if h.strip()
    ]
    if host not in ("0.0.0.0", "127.0.0.1"):
        extra_hosts.append(host)
    # #38: prefer nmap's own MAC->vendor data file over the built-in table, so
    # the vendor labels in the UI match what nmap itself prints. Done before the
    # store is created, like the config checks above.
    prefixes_path, prefixes_count = load_default_mac_prefixes()
    if prefixes_path:
        print(f"Vendor registry: {prefixes_count} MAC prefixes from {prefixes_path}")
    else:
        print(
            f"Vendor registry: {len(OUI_VENDORS)} built-in prefixes "
            f"(no {MAC_PREFIXES_FILENAME} found — install nmap or set NMAPDIR)"
        )
    store = SQLiteStore()
    api = NetScopeAPI(store, NmapScanner(SubprocessNmapRunner(timeout=timeout)))
    allowed = ", ".join((*DEFAULT_ALLOWED_HOSTS, *extra_hosts))
    print(f"NetScope on http://{host}:{port}  (db: {store.path}, nmap timeout: {timeout}s)")
    print(f"Trusted Host headers: {allowed}")
    uvicorn.run(
        build_app(api, extra_hosts=tuple(extra_hosts)),
        host=host,
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
