# Project Status (updated 2026-11-24)

## Summary
NetScope scans private LAN ranges with `nmap` and shows devices, open ports,
service versions and vendor in a web UI (FastAPI + static vanilla JS). All
eight milestones (M1–M8) are merged, and the README is rewritten as the
user-facing doc (#27, Windows/Linux/macOS). Falco considers the project
**DONE** as of 2026-11-23 — future work is a bugfix backlog from a Claude
Code review (issues #30–#38; ideas #39–#43). 97 tests pass, ruff clean.
The tool has produced real scans of the home LAN (`192.168.0.0/24`); the
latest one is recorded as acceptance evidence on issue #10.

## Done
- **M1 scaffolding** (#12, `01d2ebb`): uv project, pytest, ruff, GitHub Actions CI (3.12/3.13), docs seed.
- **M2 target guard** (#13): `netscope/target.py` — RFC1918 only (10/8, 172.16/12, 192.168/16), `IllegalTargetError` on anything else, enforced at every scan entry point (API returns 400).
- **M3 scanner core** (#14): `NmapRunner` interface, `-sn` discovery then `-sV` on live hosts, XML parsed by `parser.py`, fixture-based tests (no network).
- **M4 device model** (#15): identity = MAC when known else IP, `merge_scan()`, vendor from nmap with a 7-prefix OUI fallback (`vendor_registry.py`).
- **M5 SQLite store** (#16): `scans` / `devices` / `device_ports`, `PRAGMA user_version = 1`, COALESCE upsert, `diff_scans()`.
- **M6 web app** (#17): API (`/api/scans`, `/api/devices`, `/api/devices/<identity>`, `/api/diff`, `POST /api/scan`, `/api/scan/status`, `/api/local-subnet`) + static UI, one scan at a time (409), error surfaced in UI, `elapsed_seconds`/`timeout_seconds`, `NETSCOPE_NMAP_TIMEOUT`.
- **Fix: real port numbers** (#18): parser reads nmap's `portid` attribute (was reading a non-existent `port` attribute, so every port showed as `0/tcp`); fixtures corrected; regression test added.
- **M7 lab integration** (#19): service pass now `nmap -sV -O` (OS guess), UI prefills the target from `GET /api/local-subnet` instead of the hardcoded `192.168.1.0/24`. **Acceptance evidence recorded** 2026-11-23: re-scan of `192.168.0.0/24` shows real port numbers (no `0/tcp`), vendors for Chromecast/TV/KVM, 11 devices — posted to issue #10. Hostnames were empty then for two reasons (parser bug #30, fixed in PR #44; Pi-hole PTR answers now appear); the OS column stayed empty until the privileged run (see #34).
- **M8 device naming** (#23, merged `ddd4fc4`): manual `device_names` table (schema v2, v1 DBs upgraded in place), `PUT`/`DELETE /api/devices/<identity>/name`, editable name field in the device detail UI; manual name beats hostname/vendor/IP in the list and survives later scans. Acceptance evidence posted to #23.
- **IDEA.md** (#26): Hermes desktop project idea file is **gitignored** (repo `.gitignore` + global excludes file), never committed.
- **README rewrite** (#27): user-facing README — description, setup + run for Windows, Linux and macOS, UI usage guide, internals overview; Status and Rules sections removed (docs/ + AGENTS.md own that information).
- **Fix: README `uv sync`** (#33, PR #51): all three setup blocks now use `uv sync --extra dev` so pytest/ruff are installed. Plain `uv sync` only installs the project deps (FastAPI, uvicorn), not dev tools.
- **Fix: parser hostname/OS nesting** (#30, PR #44, `8ef0fe6`): real-shaped XML now yields hostname + OS; verified live by Falco's admin scan (OS column populated: `Linux 4.10`, `Microsoft Windows 10 1607`; PTR hostnames like `blocked.local`).
- **Fix: frontend XSS** (#32, PR #46, `390d6a9`): `app.js` renders every scan-derived string with `textContent`, and `tests/test_frontend_xss.py` blocks markup APIs. Fixture capture still pending (see Known issues).
- **Fix: presence from per-scan sightings** (#31, PR #49, `f47c9cd`): `scan_devices` table (schema v3, v2 DBs upgraded in place + backfilled from `device_ports`); seen/absent, `last_seen_scan` and `diff_scans()` now derive from explicit per-scan sightings, and the diff only compares devices inside both scans' targets (`/api/diff` default previous scan must share the target). 97 tests pass, ruff clean.
- **Windows `-O` evidence** (PR #48, `856ae9f`): privilege observations plus a verbatim interrupted-capture fixture with a `ParseError` regression test.
- **Handoff state** (PR #47, `14fbb6a`): restored doc rows dropped by stacked squash-merge.
- **Fix: diff list rendered `[object HTMLLIElement]`** (#53, branch `hermes/fix-diff-render`): `app.js` passed the `items` array to `replaceChildren` without spreading it, so the array was coerced to a string in the "Changes since previous scan" list. Fixed with `...` spread; `test_replace_children_spreads_array_arguments` in `tests/test_frontend_xss.py` now asserts every `replaceChildren(` call spreads array arguments (empty clear-calls allowed). 98 tests pass, ruff clean.

- **#31 presence from sightings** (#49, merged `f47c9cd` 2026-11-24): `scan_devices(scan_id, identity, ip)` table, `PRAGMA user_version = 3`, v2 DBs upgraded in place + backfilled from `device_ports`. Seen/absent, `last_seen_scan` and `diff_scans()` derive from explicit per-scan sightings; diff only compares devices inside both scans' targets; `/api/diff` default previous scan must share the target (404 otherwise). By design: historical sightings of portless up hosts can't be recovered from v2 DBs.
- **Windows `-O` evidence + verbatim interrupted-capture fixture** (#48, merged `856ae9f` 2026-11-24): `nmap --version` output, privilege observations in `docs/gotchas.md`; `tests/fixtures/atom_windows_admin.xml` kept byte-identical (sha256 `28a1230c…`) and asserted to raise `ParseError`.

## In progress
Nothing. All open work is merged to main (`f47c9cd`). **#34 was reopened** 2026-11-24: PR #48's body phrase "close #34 evidence gap" matched GitHub's closing keyword and auto-closed it, but only evidence shipped — `scanner/engine.py:36` still runs `-sV -O` unconditionally. The privilege probe is still to do.

## Next steps (in order, agreed with Falco 2026-11-24)
1. **#33** README setup: plain `uv sync` doesn't install pytest/ruff — smallest fix, do first.
2. **#34** Conditional `-O` (reopened — see In progress): privilege probe, retry without `-O` on the privilege error, UI explanation for the empty OS column; offline tests assert `-O` selection via fake runner.
3. **#35–#38** identity re-keying, Host-header hardening, SQLite threading/progress, cleanup bundle.
4. Name Atom, Apollo, the router etc. in the UI and re-scan to confirm labels (M8 follow-up polish).
5. Optional later: `nmap --script broadcast-nbname` / mDNS name suggestions (#41).
6. Docs upkeep: keep README, `docs/architecture.md`, `docs/gotchas.md`, this file and `docs/decisions.md` current in every PR (AGENTS.md rule).

## Known issues and gotchas
See `docs/gotchas.md` — the important ones: nmap's port attribute is `portid`;
hostname nests under `<hostnames>` and OS under `<os><osmatch>`; tests must
not assume POSIX binaries because CI is Linux-only while Falco runs
tests on Windows; the nmap timeout is per pass (default 300 s, two passes);
`-O` needs raw-socket privileges (admin PowerShell); this Hermes container sits
on the Docker bridge (`172.18.0.x`) and cannot scan the home LAN, so real scans
run only on the Windows PC or Apollo. macOS support is documented in the
README but **never executed on a Mac** (reasoned from portable code + Homebrew
nmap); `winget install nmap` package id likewise unverified from the container.
**Windows `-O` evidence recorded (2026-11-24)**: regular PowerShell `nmap --version` → Nmap 7.80, `i686-pc-windows-windows`, Npcap 0.9982 compiled in (full output in `docs/gotchas.md`). Unprivileged CLI with `-O` quits (exit 1, same as Apollo). The Nov-23 unprivileged NetScope scans surviving `-O` remain an open contradiction — one unprivileged NetScope scan would close it; #34's privilege probe covers both. **Fixture capture still pending**: the admin run `nmap -sV -O -oX atom.xml 192.168.0.250` was interrupted with Ctrl+C after a couple of seconds, so the file is preamble-only (no `<host>`, no closing tag) and raises `ParseError` — kept verbatim as `tests/fixtures/atom_windows_admin.xml` with a regression test asserting that. A usable fixture needs a scan that runs to completion.


## How to run and test
Windows (PowerShell, in `C:\Users\Falco\Projects\NetScope`):
```powershell
git fetch origin
git pull --ff-only            # on main
uv sync --extra dev
uv run pytest                 # 97 passed
uv run ruff check .           # clean
uv run python -m netscope     # http://127.0.0.1:8000
```
`nmap` must be installed (`winget install nmap` on Windows). Env vars: `NETSCOPE_DB`,
`NETSCOPE_HOST` (default `127.0.0.1`), `NETSCOPE_PORT` (8000), `NETSCOPE_NMAP_TIMEOUT` (300 s per pass).

## Open questions for the human
- **Fixture capture**: replace `tests/fixtures/*.xml` with real captured `nmap -oX -` output from the home LAN. The container cannot produce it (no nmap, Docker bridge) — a capture on Windows or Apollo is needed.
- #34 (`-O` privileges on Linux/macOS): **verified on Apollo by Falco** — root IS required (exit 1). Issue reopened; implementation pending. The Windows contradiction (unprivileged NetScope scans surviving `-O`) still needs one unprivileged NetScope scan to close.

## Resolved (2026-11-23, Falco ran in a regular PowerShell window on `hermes/device-naming`)
- **M7/M8 evidence recorded**: scans of `192.168.0.0/24` show real port numbers, vendor labels, and manual names (`.250` shown as "Atom Homeserver") that survive re-scans; diff/absent confirmed (`.19` and `.7` appeared, Chromecast/TV disappeared). Posted to issues #10 and #23.
- **Admin PowerShell NOT required**: two `/24` scans completed unprivileged (271.77 s and 236.08 s). Only the OS column stays empty without raw sockets (`-O`).
- **AGENTS.md stays silent** on the RFC1918 restriction (Falco decided): enforcement is in code via TargetGuard.
- Known flake: first scan can abort with a transient nmap Windows assertion (`exit 3221226505`, `Target.cc` line 503); retry succeeds, failed scans are not stored. See `docs/gotchas.md`.
