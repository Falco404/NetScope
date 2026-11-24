# NetScope

Local network discovery and mapping tool. Scans the local subnet (private
ranges only) to map active devices, open ports and service versions, shown
in a web UI.

NetScope runs `nmap` for you, parses its XML output into device records, and
remembers every scan in a SQLite database — so you can see what is on your
network now, what was there before, and what appeared or disappeared between
scans.

## Setup

NetScope needs **Python 3.12+**, **[uv](https://docs.astral.sh/uv/)**, and
**nmap** (only for real scans; tests run without it).

### Windows

```powershell
winget install astral-sh.uv          # uv
winget install nmap                  # or run the installer from nmap.org
git clone https://github.com/Falco404/NetScope.git
cd NetScope
uv sync --extra dev                  # installs the project + dev tools (pytest, ruff)
uv run pytest                        # verify: all tests pass, no network needed
```

### Linux (Fedora / Debian / DietPi)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # uv
sudo dnf install nmap                             # Fedora
# or: sudo apt install nmap                       # Debian/Ubuntu/DietPi

git clone https://github.com/Falco404/NetScope.git
cd NetScope
uv sync --extra dev
uv run pytest
```

### macOS

```bash
brew install uv nmap    # uv downloads a Python 3.12+ interpreter itself if the system Python is older
git clone https://github.com/Falco404/NetScope.git
cd NetScope
uv sync --extra dev
uv run pytest
```

## Run the web UI

```bash
uv run python -m netscope          # then open http://127.0.0.1:8000
```

Same command on Windows (regular PowerShell — **no admin required**), Linux and
macOS. Settings are env vars, all optional:

| Env var | Default | Meaning |
|---|---|---|
| `NETSCOPE_DB` | `netscope.db` | SQLite database path |
| `NETSCOPE_HOST` | `127.0.0.1` | Bind address; `0.0.0.0` exposes the UI on the LAN |
| `NETSCOPE_PORT` | `8000` | HTTP port |
| `NETSCOPE_NMAP_TIMEOUT` | `300` | Seconds per nmap pass; a `/24` with silent hosts can take minutes |

On Windows PowerShell: `$env:NETSCOPE_PORT = "8000"` before the run command.
On Linux or macOS (bash/zsh): `NETSCOPE_PORT=8000 uv run python -m netscope`.

Without admin/root, scans work but the **OS column stays empty** (`nmap -O`
needs raw-socket privileges). On Linux and macOS, run the same command with
`sudo` to fill it in. On macOS, exposing the UI on the LAN
(`NETSCOPE_HOST=0.0.0.0`) may trigger a firewall prompt for incoming
connections — allow it.

## Using the web UI

- **Target** is prefilled with the subnet this machine routes from (assumed
  `/24`) and is always editable — the guess is wrong if the server runs on a
  Docker or VPN bridge. Only private ranges are accepted (see Internals);
  anything else is refused with a clear error.
- **Start scan** runs discovery + service detection (~4 minutes for a `/24`
  on a normal PC). Only one scan runs at a time; a second request while one
  is running is refused. Progress/errors show in the UI; a finished scan is
  stored permanently.
- **Device list**: name, IP, status (`seen`/`absent`), OS guess, vendor, open
  ports per latest scan. Devices that vanish from a scan are kept and shown
  as absent.
- **Manual naming**: open a device and type a name. Your name beats any
  hostname/vendor label and survives every later scan. Names are stored in
  their own table, so scans never overwrite them.
- **Changes since previous scan** lists appeared/disappeared devices;
  **scan history** lists past scans with target and duration.

## How it works under the hood

Python + `uv` project, FastAPI backend, plain vanilla-JS frontend (no build
step), SQLite via the stdlib, `nmap` as a subprocess.

- **`netscope/target.py` — TargetGuard.** Every scan entry point checks the
  target first: only RFC1918 ranges (10/8, 172.16/12, 192.168/16) are
  accepted; single IPs and CIDRs parse via `ipaddress`, IPv6 and anything
  outside private ranges raises `IllegalTargetError` (HTTP 400). A CIDR that
  spills outside private space is refused even if its network address looks
  valid.
- **`netscope/scanner/` — engine + runner + parser.** Two passes: `nmap -sn`
  host discovery on the subnet, then `nmap -sV -O` port/service/OS detection
  on discovered hosts only. Output comes back as XML (`-oX -`), parsed into
  `HostResult`/`PortResult` (ports from the `<port portid=...>` attribute, OS
  from `<osclass osfamily=...>`). The runner is behind an interface, so tests
  replay recorded XML fixtures with a fake runner — scanner logic is fully
  testable offline, on any OS.
- **`netscope/device.py` + `vendor_registry.py` — device model.** Identity is
  the MAC when known (stable across DHCP leases), else the IP, so a device
  never forks into two rows. `merge_scan()` keeps the latest non-empty
  hostname/OS and snapshots ports per scan. Vendor comes from nmap's own
  OUI data, with a small offline registry as fallback — no runtime network
  calls. Display priority: manual name → hostname → vendor label → bare IP.
- **`netscope/store/store.py` — SQLite store.** Tables `scans`, `devices`,
  `device_ports`, `device_names` (schema v2; v1 databases upgrade in place).
  Upserts use COALESCE so empty scan fields never blank known ones.
  `diff_scans()` computes appeared/disappeared/changed between two scans.
- **`netscope/api/app.py` + `static/` — web app.** JSON endpoints
  (`/api/scans`, `/api/devices`, `/api/devices/<identity>`, `/api/diff`,
  `POST /api/scan`, `/api/scan/status`, `/api/local-subnet`). Scans run in a
  background thread; the UI stays dumb — it fetches JSON, renders, and polls
  status. `/api/local-subnet` asks the OS which local IP it would route from
  (UDP `connect()`, no packet sent) and assumes `/24` — detection, never a
  scan.
- **`tests/` — 83 tests**, fixture-driven (recorded nmap XML), API tested via
  `TestClient`, store tests on temp databases. No test assumes POSIX
  binaries; CI runs Linux, Windows developers run the same suite.

More detail: `docs/architecture.md` (design), `docs/decisions.md` (why each
choice was made), `docs/gotchas.md` (nmap quirks worth knowing).
