# Project Status (updated 2026-11-23)

## Summary
NetScope scans private LAN ranges with `nmap` and shows devices, open ports,
service versions and vendor in a web UI (FastAPI + static vanilla JS). All
seven milestones (M1–M7) are merged to `main`; 78 tests pass, ruff clean.
The tool has produced one real scan of the home LAN (`192.168.0.0/24`).

## Done
- **M1 scaffolding** (#12, `01d2ebb`): uv project, pytest, ruff, GitHub Actions CI (3.12/3.13), docs seed.
- **M2 target guard** (#13): `netscope/target.py` — RFC1918 only (10/8, 172.16/12, 192.168/16), `IllegalTargetError` on anything else, enforced at every scan entry point (API returns 400).
- **M3 scanner core** (#14): `NmapRunner` interface, `-sn` discovery then `-sV` on live hosts, XML parsed by `parser.py`, fixture-based tests (no network).
- **M4 device model** (#15): identity = MAC when known else IP, `merge_scan()`, vendor from nmap with a 7-prefix OUI fallback (`vendor_registry.py`).
- **M5 SQLite store** (#16): `scans` / `devices` / `device_ports`, `PRAGMA user_version = 1`, COALESCE upsert, `diff_scans()`.
- **M6 web app** (#17): API (`/api/scans`, `/api/devices`, `/api/devices/<identity>`, `/api/diff`, `POST /api/scan`, `/api/scan/status`, `/api/local-subnet`) + static UI, one scan at a time (409), error surfaced in UI, `elapsed_seconds`/`timeout_seconds`, `NETSCOPE_NMAP_TIMEOUT`.
- **Fix: real port numbers** (#18): parser reads nmap's `portid` attribute (was reading a non-existent `port` attribute, so every port showed as `0/tcp`); fixtures corrected; regression test added.
- **M7 lab integration** (#19): service pass now `nmap -sV -O` (OS guess), UI prefills the target from `GET /api/local-subnet` instead of the hardcoded `192.168.1.0/24`.
- First real scan on the LAN: 10 devices found, vendors resolved for Chromecast / TV / KVM; issue #10 closed by Falco.

## In progress
- This handoff PR only (docs updates). No feature work is in flight; working tree clean.

## Next steps (in order)
1. Re-run a scan on `192.168.0.0/24` after #18/#19 and record what the UI shows: real port numbers, OS column, hostname column. Paste the output into issue #10's follow-up (issue #23 if created) — no evidence has been recorded yet.
2. **M8 — device identification fallbacks**: the router answers no reverse DNS, so devices show as bare IPs. Add ARP alias / NetBIOS (`nmap --script broadcast-nbname`) or a hostname field from the ARP table so Atom and Apollo can be recognised by name, not guessed from vendor.
3. Decide whether `0.0.0.0` binding + any auth is wanted (UI currently has none; localhost-only by default).
4. Docs finalization: keep README, `docs/architecture.md`, `docs/gotchas.md`, this file and `docs/decisions.md` current in every PR (AGENTS.md rule).

## Known issues and gotchas
See `docs/gotchas.md` — the important ones: nmap's port attribute is `portid`;
tests must not assume POSIX binaries because CI is Linux-only while Falco runs
tests on Windows; the nmap timeout is per pass (default 300 s, two passes);
`-O` needs raw-socket privileges (admin PowerShell); this Hermes container sits
on the Docker bridge (`172.18.0.x`) and cannot scan the home LAN, so real scans
run only on the Windows PC or Apollo.

## How to run and test
Windows (PowerShell, in `C:\Users\Falco\Projects\NetScope`):
```powershell
git fetch origin
git pull --ff-only            # on main
uv sync --extra dev
uv run pytest                 # 78 passed
uv run ruff check .           # clean
uv run python -m netscope     # http://127.0.0.1:8000
```
`nmap` must be installed (`winget install nmap` on Windows). Env vars: `NETSCOPE_DB`,
`NETSCOPE_HOST` (default `127.0.0.1`), `NETSCOPE_PORT` (8000), `NETSCOPE_NMAP_TIMEOUT` (300 s per pass).

## Open questions for the human
- Did Atom and Apollo actually appear in the UI with ports/OS after the `portid` fix? Issue #10 was closed without recorded scan output.
- Is admin PowerShell actually required for discovery? Unverified — README records that only admin PowerShell has been tested (~290 s for the `/24`).
- Bind on `0.0.0.0` for phone access (no auth today) or keep localhost-only?
- AGENTS.md was rewritten (#20) and no longer states the private-range restriction; the guard still enforces it in code. Should the rule be restored in AGENTS.md?
