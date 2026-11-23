# NetScope

Local network discovery and mapping tool. Scans the local subnet (private
ranges only) to map active devices, open ports and service versions, shown
in a web UI.

## Status

M1–M6 done: target guard, scanner core (nmap behind an interface), device
model, SQLite store, and the web UI. M7 (lab integration pass) is open.
See `docs/architecture.md` and the milestone issues.

## Setup

```bash
uv sync            # installs the project + dev tools (pytest, ruff, httpx)
uv run pytest      # run tests
uv run ruff check  # lint
```

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). `nmap` must be
installed for real scans (`apt install nmap`, or on Windows: winget / nmap.org).

## Run the web UI

```bash
uv run python -m netscope        # http://127.0.0.1:8000
```

Env vars (all optional): `NETSCOPE_DB` (database path, default `netscope.db`),
`NETSCOPE_HOST` (default `127.0.0.1`; set `0.0.0.0` to expose on the LAN),
`NETSCOPE_PORT` (default 8000), `NETSCOPE_NMAP_TIMEOUT` (seconds per nmap
pass, default 300 — a `/24` with mostly silent hosts can take minutes).

### Does the scan need admin PowerShell?

**Unverified — remembered for later.** The first real scan on Atlas was run
from an **admin** PowerShell and took ~290 s for `192.168.0.0/24`. nmap can use
ARP for discovery only when it has raw-socket privileges, so a *normal*
PowerShell may discover fewer hosts and take longer. Nobody has compared the
two yet: if a scan misses devices, retry from an admin PowerShell before
blaming NetScope, and record the result here when someone actually tests it.

## Rules

See `AGENTS.md`. Scanning is restricted to RFC1918 ranges in code; config
goes in env vars or gitignored files; no secrets in the repo.
