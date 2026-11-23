# Architecture & decisions

Last updated: 2026-11-23 (M1). Decisions below were approved before any code was written.

## Stack
- **Language:** Python 3.12+, managed with `uv` (`pyproject.toml`). Chosen because nmap integration is simple subprocess work, pytest keeps scanner logic testable without a network, and no build step is needed on Apollo (Fedora) or Atom (DietPi).
- **GUI:** **Web app** — FastAPI JSON API + static vanilla-JS frontend, no build step. Chosen over PyQt6: it runs anywhere (Windows browser -> WSL localhost, Fedora, phone on the LAN), and the interesting UI logic lives in tested API endpoints rather than untested widgets. Server binds localhost by default; LAN exposure only via explicit env var.
- **Scanning:** `nmap` subprocess behind a `Scanner` interface. Two passes: `-sn` host discovery on the subnet, then targeted `-sV` port/service version detection on discovered hosts only. XML output (`-oX`) parsed into structured data. Tests replay recorded XML fixtures — zero network.
- **Target safety:** a `TargetGuard` module accepts only RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and raises on anything else. Enforced in code at every scan entry point, not via config.
- **Storage:** SQLite (`netscope.db`, gitignored; path via `NETSCOPE_DB` env var). Tables for scans, devices, per-scan ports/services; supports history and diff-between-scans.

## Conventions (from AGENTS.md)
- Work on `hermes/<topic>` branches, PR to main; never push to main.
- Small PRs, one feature each, with tests.
- PR description: plain-language summary, how to try it (exact Windows commands), actual test output, decisions/uncertainties.
- No secrets in the repo; config via env vars or a gitignored file.

## Milestones
M1 scaffolding (#4) · M2 target guard (#5) · M3 scanner core (#6) · M4 device model (#7) · M5 store (#8) · M6 web GUI (#9) · M7 lab integration (#10).
