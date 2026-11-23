# NetScope

Local network discovery and mapping tool. Scans the local subnet (private
ranges only) to map active devices, open ports and service versions, shown
in a web UI.

## Status

M1 — project skeleton. Scanner, store and web UI land in M2–M6
(see `docs/architecture.md` and the milestone issues).

## Setup

```bash
uv sync            # installs the project + dev tools (pytest, ruff)
uv run pytest      # run tests
uv run ruff check  # lint
```

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

## Rules

See `AGENTS.md`. Scanning is restricted to RFC1918 ranges in code; config
goes in env vars or gitignored files; no secrets in the repo.
