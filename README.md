# NetScope

Local network discovery and mapping tool. Scans the local subnet (private
ranges only) to map active devices, open ports and service versions, shown
in a web UI.

## Status

M1–M8 done or in PR: target guard, scanner core (nmap behind an interface),
device model, SQLite store, web UI, lab integration (scan evidence recorded
on issue #10) and manual device naming (issue #23). See `docs/architecture.md`,
`docs/STATUS.md` and the milestone issues.

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

The target field is prefilled with the subnet this machine would route from
(assumed `/24`) — always editable, and the guess is wrong when the server runs
on a Docker or VPN bridge instead of the home LAN.

Scans fingerprint services **and OS** (`nmap -sV -O`). A **regular PowerShell
window is enough** — no admin required (verified 2026-11-23: two `/24` scans,
236–272 s). `nmap -O` needs raw-socket privileges, so without admin the OS
column stays empty; ports, vendors and device names still fill in.

## Rules

See `AGENTS.md`. Scanning is restricted to RFC1918 ranges in code; config
goes in env vars or gitignored files; no secrets in the repo. Current state:
`docs/STATUS.md`. Decisions: `docs/decisions.md`. Gotchas worth knowing before
touching nmap or the tests: `docs/gotchas.md`.
