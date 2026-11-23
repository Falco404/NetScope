# Project Status (updated 2026-11-23)

## Summary
NetScope scans private LAN ranges with `nmap` and shows devices, open ports,
service versions and vendor in a web UI (FastAPI + static vanilla JS). All
eight milestones (M1–M8) are merged, and the README is rewritten as the
user-facing doc (#27, Windows/Linux/macOS). Falco considers the project
**DONE** as of 2026-11-23 — future work is bugfixes and the LAN-bind decision
only. 83 tests pass, ruff clean. The tool has produced real scans of the home
LAN (`192.168.0.0/24`); the latest one is recorded as acceptance evidence on
issue #10.

## Done
- **M1 scaffolding** (#12, `01d2ebb`): uv project, pytest, ruff, GitHub Actions CI (3.12/3.13), docs seed.
- **M2 target guard** (#13): `netscope/target.py` — RFC1918 only (10/8, 172.16/12, 192.168/16), `IllegalTargetError` on anything else, enforced at every scan entry point (API returns 400).
- **M3 scanner core** (#14): `NmapRunner` interface, `-sn` discovery then `-sV` on live hosts, XML parsed by `parser.py`, fixture-based tests (no network).
- **M4 device model** (#15): identity = MAC when known else IP, `merge_scan()`, vendor from nmap with a 7-prefix OUI fallback (`vendor_registry.py`).
- **M5 SQLite store** (#16): `scans` / `devices` / `device_ports`, `PRAGMA user_version = 1`, COALESCE upsert, `diff_scans()`.
- **M6 web app** (#17): API (`/api/scans`, `/api/devices`, `/api/devices/<identity>`, `/api/diff`, `POST /api/scan`, `/api/scan/status`, `/api/local-subnet`) + static UI, one scan at a time (409), error surfaced in UI, `elapsed_seconds`/`timeout_seconds`, `NETSCOPE_NMAP_TIMEOUT`.
- **Fix: real port numbers** (#18): parser reads nmap's `portid` attribute (was reading a non-existent `port` attribute, so every port showed as `0/tcp`); fixtures corrected; regression test added.
- **M7 lab integration** (#19): service pass now `nmap -sV -O` (OS guess), UI prefills the target from `GET /api/local-subnet` instead of the hardcoded `192.168.1.0/24`. **Acceptance evidence recorded** 2026-11-23: re-scan of `192.168.0.0/24` shows real port numbers (no `0/tcp`), vendors for Chromecast/TV/KVM, 11 devices — posted to issue #10 (comment 7108419834). Hostnames/OS still empty (no PTR; `-O` needs raw-socket privileges).
- **M8 device naming** (#23, merged `ddd4fc4`): manual `device_names` table (schema v2, v1 DBs upgraded in place), `PUT`/`DELETE /api/devices/<identity>/name`, editable name field in the device detail UI; manual name beats hostname/vendor/IP in the list and survives later scans. Acceptance evidence posted to #23.
- **IDEA.md** (#26): Hermes desktop project idea file is **gitignored** (repo `.gitignore` + global excludes file), never committed.
- **README rewrite** (#27): user-facing README — description, setup + run for Windows, Linux and macOS, UI usage guide, internals overview; Status and Rules sections removed (docs/ + AGENTS.md own that information).

## In progress
Nothing. Working tree clean on main (`a1c4e6d`); no open PRs or issues at
handoff time (this docs handoff is the only branch in flight).

## Next steps (in order)
1. Deploy on **Apollo** (Fedora laptop): follow README Linux setup
   (`dnf install nmap`, `uv sync`); first real LAN scan on Apollo is
   unverified — timings there unknown (Windows: 236–272 s per `/24`).
2. Decide whether `0.0.0.0` binding + any auth is wanted (UI currently has
   none; localhost-only by default). Tracked as issue #28.
3. Optional later: `nmap --script broadcast-nbname` as auto-fill for Windows hosts (manual names stay authoritative).
4. Docs upkeep: keep README, `docs/architecture.md`, `docs/gotchas.md`, this file and `docs/decisions.md` current in every PR (AGENTS.md rule).

## Known issues and gotchas
See `docs/gotchas.md` — the important ones: nmap's port attribute is `portid`;
tests must not assume POSIX binaries because CI is Linux-only while Falco runs
tests on Windows; the nmap timeout is per pass (default 300 s, two passes);
`-O` needs raw-socket privileges (admin PowerShell); this Hermes container sits
on the Docker bridge (`172.18.0.x`) and cannot scan the home LAN, so real scans
run only on the Windows PC or Apollo. macOS support is documented in the
README but **never executed on a Mac** (reasoned from portable code + Homebrew
nmap); `winget install nmap` package id likewise unverified from the container.

## How to run and test
Windows (PowerShell, in `C:\Users\Falco\Projects\NetScope`):
```powershell
git fetch origin
git pull --ff-only            # on main
uv sync --extra dev
uv run pytest                 # 83 passed
uv run ruff check .           # clean
uv run python -m netscope     # http://127.0.0.1:8000
```
`nmap` must be installed (`winget install nmap` on Windows). Env vars: `NETSCOPE_DB`,
`NETSCOPE_HOST` (default `127.0.0.1`), `NETSCOPE_PORT` (8000), `NETSCOPE_NMAP_TIMEOUT` (300 s per pass).

## Open questions for the human
- Bind on `0.0.0.0` for phone access + auth? Deferred — Falco has not decided yet; localhost-only stays.

## Resolved (2026-11-23, Falco ran in a regular PowerShell window on `hermes/device-naming`)
- **M7/M8 evidence recorded**: scans of `192.168.0.0/24` show real port numbers, vendor labels, and manual names (`.250` shown as "Atom Homeserver") that survive re-scans; diff/absent confirmed (`.19` and `.7` appeared, Chromecast/TV disappeared). Posted to issues #10 and #23.
- **Admin PowerShell NOT required**: two `/24` scans completed unprivileged (271.77 s and 236.08 s). Only the OS column stays empty without raw sockets (`-O`).
- **AGENTS.md stays silent** on the RFC1918 restriction (Falco decided): enforcement is in code via TargetGuard.
- Known flake: first scan can abort with a transient nmap Windows assertion (`exit 3221226505`, `Target.cc` line 503); retry succeeds, failed scans are not stored. See `docs/gotchas.md`.
