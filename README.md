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
uv sync                  # installs the project + dev tools (pytest, ruff)
uv run pytest                        # verify: all tests pass, no network needed
```

`uv sync` installs pytest and ruff as well — they are a default dependency
group. Older instructions said `uv sync --extra dev`; that extra no longer
exists, and worse, a plain `uv sync` against the old layout *removed* the dev
tools from an environment that already had them.

### Linux (Fedora / Debian / DietPi)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # uv
sudo dnf install nmap                             # Fedora
# or: sudo apt install nmap                       # Debian/Ubuntu/DietPi

git clone https://github.com/Falco404/NetScope.git
cd NetScope
uv sync
uv run pytest
```

### macOS

```bash
brew install uv nmap    # uv downloads a Python 3.12+ interpreter itself if the system Python is older
git clone https://github.com/Falco404/NetScope.git
cd NetScope
uv sync
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
| `NETSCOPE_ALLOWED_HOSTS` | *(empty)* | Extra Host header names to trust (comma-separated) |
| `NETSCOPE_NMAP_TIMEOUT` | `300` | Seconds per nmap pass; a `/24` with silent hosts can take minutes |
| `NETSCOPE_MDNS` | `1` | Name suggestions over mDNS; `0` turns the lookup off |
| `NETSCOPE_NETBIOS` | `1` | NetBIOS workstation names (UDP 137); `0` turns the lookup off |

On Windows PowerShell: `$env:NETSCOPE_PORT = "8000"` before the run command.
On Linux or macOS (bash/zsh): `NETSCOPE_PORT=8000 uv run python -m netscope`.

The server only answers requests whose `Host` header is a name it trusts:
`localhost` and `127.0.0.1` always, plus `NETSCOPE_HOST` when you set one.
Anything else gets `400 Invalid host header`, so a page reached through a
rebound hostname cannot drive the scanner. If you bind `0.0.0.0` so a device
on the LAN can open the UI, name the address that device uses in
`NETSCOPE_ALLOWED_HOSTS` (e.g. `192.168.0.14`), because `0.0.0.0` is a bind
address and never arrives as a `Host` header.

Without admin/root, scans work but the **OS column stays empty** (`nmap -O`
needs raw-socket privileges). On Windows a regular PowerShell is enough —
Npcap handles it — so there is nothing to do. On **Linux and macOS** you have
three options, cheapest first:

- **Check whether `-O` works at all.** This is the exact probe NetScope runs
  before a scan, so its result is the answer:

  ```bash
  sudo nmap -sV -O 127.0.0.1
  ```

  A *successful* run does not have to name an OS: nmap prints
  `No exact OS matches for host` when its fingerprint database has no entry —
  localhost is the typical case (the output is still proof that raw sockets
  work). To see the OS column actually fill, scan a real device: run a
  **Deep scan**, or open one device and press *Deep scan this device*.

- **Run NetScope as root without uv.** uv is a per-user install, so
  `sudo uv …` ends in `sudo: uv: command not found` — and even with the right
  `PATH`, `uv run` as root leaves root-owned files in `.venv` and then breaks
  your normal `uv sync`. Run the already-built interpreter instead:

  ```bash
  sudo NETSCOPE_DB=/tmp/netscope-root.db .venv/bin/python -m netscope
  ```

  (The `/tmp` database keeps the repo free of a root-owned `netscope.db`;
  drop that variable to use your normal database.)

- **Give the nmap binary the capability once — Linux only** — then keep
  running as your normal user:

  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"
  getcap "$(command -v nmap)"          # verify
  uv run python -m netscope            # -O now works without sudo
  ```

  Undo with `sudo setcap -r "$(command -v nmap)"`. Trade-off: every local user
  can then use raw sockets through nmap. macOS has no `setcap`; use the second
  option there.

On macOS, exposing the UI on the LAN (`NETSCOPE_HOST=0.0.0.0`) may trigger a
firewall prompt for incoming connections — allow it.

## Using the web UI

- **Target** is prefilled with the subnet this machine routes from (assumed
  `/24`) and is always editable — the guess is wrong if the server runs on a
  Docker or VPN bridge. Only private ranges are accepted (see Internals);
  anything else is refused with a clear error.
- **Quick scan** runs nmap's discovery pass only (`-sn`) and answers "who is
  on the network" in seconds. Devices show up as `seen`; the Open ports column
  reads `not probed`.
- **Deep scan** follows discovery with port, service and OS detection
  (`-sV -O`) on every host that answered — a few minutes for a `/24` on a
  normal PC. Use it when you want ports, versions and OS guesses.
- Only one scan runs at a time (both buttons disable while one is running); a
  second request while one is running is refused. Progress/errors show in the
  UI; every finished scan is stored permanently and labelled `quick` or
  `deep`.
- **Device list**: name, IP, status (`seen`/`absent`), OS guess, vendor, open
  ports per latest scan. Devices that vanish from a scan are kept and shown
  as absent. Hostname, OS and vendor are learned values and survive later
  scans that do not see them again.
- **Names** come from reverse DNS first, then from mDNS/Bonjour, then from
  NetBIOS: every scan (quick or deep) listens to what devices announce about
  themselves (mDNS) and asks each discovered host for its NetBIOS workstation
  name. A learned name fills in when DNS gave none — or when DNS gave the
  *same* name to several devices (a sinkhole/Pi-hole answer such as
  `blocked.local`). A unique DNS name is never overridden, and mDNS wins over
  NetBIOS on the same host. Devices that announce nothing keep the vendor/IP
  label. Turn the lookups off with `NETSCOPE_MDNS=0` / `NETSCOPE_NETBIOS=0`.
- **Manual naming**: open a device and type a name. Your name beats any
  hostname/vendor label and survives every later scan. Names are stored in
  their own table, so scans never overwrite them.
- **Deep scan a single device**: open a device and press *Deep scan this
  device* — it runs the deep scan against just that device's current IP
  (`<ip>/32`) instead of the whole subnet, so a host that only ever got a
  quick scan has its ports and OS filled in within seconds. It is a normal
  scan in the history (with the `/32` target).
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
  on discovered hosts only — a quick scan stops after the first pass. Output
  comes back as XML (`-oX -`), parsed into `HostResult`/`PortResult` (ports
  from the `<port portid=...>` attribute, OS from `<os>`/`<osmatch>`). The
  runner is behind an interface, so tests replay recorded XML fixtures with a
  fake runner — scanner logic is fully testable offline, on any OS.
- **`netscope/mdns.py` — name suggestions (#41).** Uses python-zeroconf
  (LGPL-2.1-or-later, imported as a library) to browse DNS-SD over multicast
  (UDP 5353, group `224.0.0.251`): the meta-query
  `_services._dns-sd._udp.local.` lists the service types on the LAN, each
  type lists its instances, and each instance resolves to a host name plus
  addresses. The lookup runs in a background thread **while nmap scans** (a
  few seconds, bounded by its timeout) and is best-effort: any failure just
  means no names.
- **`netscope/netbios.py` — NetBIOS names (#41 part 2).** After discovery, each
  discovered host is asked for its NetBIOS node status (NBSTAT) over UDP 137;
  the unique `<00>` workstation name becomes the hostname. The packet layout
  follows nmap's own `nselib/netbios.lua`. Queries run in parallel with a short
  timeout, and every failure means "no name". Linux hosts without Samba and
  Windows machines with NetBIOS disabled simply do not answer.
- **`netscope/device.py` + `vendor_registry.py` — device model.** Identity is
  the MAC when known (stable across DHCP leases), else the IP, so a device
  never forks into two rows. `merge_scan()` keeps the latest non-empty
  hostname/OS and snapshots ports per scan. Vendor comes from nmap's own
  OUI data: at startup NetScope reads nmap's `nmap-mac-prefixes` file
  (`$NMAPDIR`, else the folder holding `nmap.exe`) and falls back to a small
  built-in registry when nmap is not installed — no runtime network calls.
  Longest registered prefix wins, so a 28- or 36-bit registration beats a
  24-bit one. Display priority: manual name → hostname → vendor label → bare IP.
- **`netscope/store/store.py` — SQLite store.** Tables `scans` (with `mode`),
  `devices`, `device_ports`, `device_names`, `scan_devices` (schema v4; older
  databases upgrade in place). Upserts use COALESCE so empty scan fields never
  blank known ones. `diff_scans()` computes appeared/disappeared/changed
  between two scans; port changes are only compared when both scans were deep
  scans.
- **`netscope/api/app.py` + `static/` — web app.** JSON endpoints
  (`/api/scans`, `/api/devices`, `/api/devices/<identity>`, `/api/diff`,
  `/api/os-hint`, `POST /api/scan`, `POST /api/devices/<identity>/scan`,
  `/api/scan/status`, `/api/local-subnet`).
  Scans run in a background thread; the UI stays dumb — it fetches JSON,
  renders, and polls status. `/api/local-subnet` asks the OS which local IP it
  would route from (UDP `connect()`, no packet sent) and assumes `/24` —
  detection, never a scan.
- **`tests/` — 231 tests**, fixture-driven (recorded nmap XML), API tested via
  `TestClient`, store tests on temp databases. No test assumes POSIX
  binaries; CI runs the suite on both Linux and Windows.

More detail: `docs/architecture.md` (design), `docs/decisions.md` (why each
choice was made), `docs/gotchas.md` (nmap quirks worth knowing).

## License

MIT — see [LICENSE](LICENSE).
