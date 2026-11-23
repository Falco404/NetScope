# Architecture & decisions

Last updated: 2026-11-23 (M1). Decisions below were approved before any code was written.

## Stack
- **Language:** Python 3.12+, managed with `uv` (`pyproject.toml`). Chosen because nmap integration is simple subprocess work, pytest keeps scanner logic testable without a network, and no build step is needed on Apollo (Fedora) or Atom (DietPi).
- **GUI:** **Web app** — FastAPI JSON API + static vanilla-JS frontend, no build step. Chosen over PyQt6: it runs anywhere (Windows browser -> WSL localhost, Fedora, phone on the LAN), and the interesting UI logic lives in tested API endpoints rather than untested widgets. Server binds localhost by default; LAN exposure only via explicit env var.
- **Scanning:** `nmap` subprocess behind an `NmapRunner` interface (`netscope/scanner/`). Two passes: `-sn` host discovery on the subnet, then `-sV` port/service version detection on discovered hosts only. XML output via `-oX -` parsed by `parse_nmap_xml()` into `HostResult`/`PortResult` (OS guess comes from `<osclass>`'s `osfamily` attribute). `TargetGuard` runs before the runner is ever called; tests replay recorded XML fixtures via a fake runner — zero network. Real runner times out at 300 s and raises on non-zero exit.
- **Target safety:** a `TargetGuard` module (`netscope/target.py`) accepts only RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and raises `IllegalTargetError` on anything else. Enforced in code at every scan entry point, not via config. Implementation decisions (M2): `ipaddress.IPv4Network(target, strict=False)` so single IPs and CIDRs both parse and IPv6 raises; both ends of the CIDR host range are checked against the allowed ranges, so a CIDR that spills outside (e.g. `172.31.0.0/11`) is refused even when its network address looks valid.
- **Storage:** SQLite (`netscope.db`, gitignored; path via `NETSCOPE_DB` env var — `netscope/store/store.py`). Tables: `scans` (id, ISO timestamp, target, duration), `devices` (identity PK, latest known fields, `last_seen_scan`), `device_ports` (per scan: identity, port, protocol, service, version). Store API: `save_scan` (scan + device upsert with COALESCE so empty fields never blank known ones), `list_scans`, `load_devices`, `devices_in_scan`, `diff_scans` (appeared/disappeared/changed port sets). Schema version via `PRAGMA user_version` — bump `_SCHEMA` + version when the shape changes; no migration framework at this stage. Device identity is stable once assigned (MAC-learned-later fills the field, never renames the key).
- **Device identity (M4):** devices are keyed by MAC when known (stable across DHCP leases), else IP — a machine seen in two scans never forks into two rows. `merge_scan()` updates fields in place (latest non-empty hostname/OS wins, ports are a fresh snapshot, down hosts ignored). Vendor comes from nmap's XML, with a small offline OUI registry (`vendor_registry.py`) as fallback — no runtime network calls. OS guess is only present if a scan runs with `-O`/`-A`.

## Conventions (from AGENTS.md)
- Work on `hermes/<topic>` branches, PR to main; never push to main.
- Small PRs, one feature each, with tests.
- PR description: plain-language summary, how to try it (exact Windows commands), actual test output, decisions/uncertainties.
- No secrets in the repo; config via env vars or a gitignored file.

## Milestones
M1 scaffolding (#4) · M2 target guard (#5) · M3 scanner core (#6) · M4 device model (#7) · M5 store (#8) · M6 web GUI (#9) · M7 lab integration (#10).
