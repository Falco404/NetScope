"""Run the NetScope web server: `python -m netscope`.

Bind is localhost by default; expose on the LAN only by setting
NETSCOPE_HOST=0.0.0.0 explicitly. DB path via NETSCOPE_DB. The Host header
must be a trusted name (#36): loopback by default, plus NETSCOPE_HOST and
anything listed in NETSCOPE_ALLOWED_HOSTS (comma-separated).
"""

from __future__ import annotations

import os

import uvicorn

from netscope.api import DEFAULT_ALLOWED_HOSTS, NetScopeAPI, build_app
from netscope.scanner import NmapScanner, SubprocessNmapRunner
from netscope.store import SQLiteStore


def main() -> None:
    host = os.environ.get("NETSCOPE_HOST", "127.0.0.1")
    port = int(os.environ.get("NETSCOPE_PORT", "8000"))
    # #36: trusted Host header names. Loopback is always allowed; a LAN bind
    # must name the hosts clients actually use, because 0.0.0.0 is a bind
    # address and never appears as a Host header.
    extra_hosts = [
        h.strip() for h in os.environ.get("NETSCOPE_ALLOWED_HOSTS", "").split(",") if h.strip()
    ]
    if host not in ("0.0.0.0", "127.0.0.1"):
        extra_hosts.append(host)
    store = SQLiteStore()
    timeout = float(os.environ.get("NETSCOPE_NMAP_TIMEOUT", "300"))
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
