"""Run the NetScope web server: `python -m netscope`.

Bind is localhost by default; expose on the LAN only by setting
NETSCOPE_HOST=0.0.0.0 explicitly. DB path via NETSCOPE_DB.
"""

from __future__ import annotations

import os

import uvicorn

from netscope.api import NetScopeAPI, build_app
from netscope.scanner import NmapScanner, SubprocessNmapRunner
from netscope.store import SQLiteStore


def main() -> None:
    host = os.environ.get("NETSCOPE_HOST", "127.0.0.1")
    port = int(os.environ.get("NETSCOPE_PORT", "8000"))
    store = SQLiteStore()
    api = NetScopeAPI(store, NmapScanner(SubprocessNmapRunner()))
    print(f"NetScope on http://{host}:{port}  (db: {store.path})")
    uvicorn.run(build_app(api), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
