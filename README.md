# NetScope

Know what is on your network — and what changed since last time.

NetScope runs `nmap` for you, parses its XML output into device records and
remembers every scan in a local SQLite database. You get a web page listing
each device with its name, IP, vendor, open ports and service versions, plus a
history of what appeared or disappeared between scans. Private networks only
(`10/8`, `172.16/12`, `192.168/16`) — anything else is refused.

**Contents:** [Quick start](#quick-start) · [Running it](#running-it) ·
[Using the web UI](#using-the-web-ui) · [Exporting](#exporting) ·
[The OS column is empty](#the-os-column-is-empty) ·
[Troubleshooting](#troubleshooting) · [How it works](#how-it-works)

## What you need

- **Python 3.12+** and **[uv](https://docs.astral.sh/uv/)** — uv downloads a
  suitable Python itself if yours is older.
- **nmap** — only for real scans. The test suite replays recorded nmap output
  and runs without it, on any OS.

## Quick start

### Windows

```powershell
winget install --id astral-sh.uv -e        # uv
winget install --id Insecure.Nmap -e       # nmap (its installer bundles Npcap)
git clone https://github.com/Falco404/NetScope.git
cd NetScope
uv sync                                    # project + dev tools (pytest, ruff)
uv run python -m netscope                  # then open http://127.0.0.1:8000
```

No admin rights needed: a normal PowerShell window is enough, because Npcap
gives nmap the raw-socket access that OS detection needs.

### Linux

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # uv
sudo dnf install nmap                            # Fedora
#   ...or on Debian / Ubuntu / DietPi:
sudo apt install nmap

git clone https://github.com/Falco404/NetScope.git
cd NetScope
uv sync
uv run python -m netscope                        # http://127.0.0.1:8000
```

### macOS

```bash
brew install uv nmap
git clone https://github.com/Falco404/NetScope.git
cd NetScope
uv sync
uv run python -m netscope                        # http://127.0.0.1:8000
```

Optional sanity check on any OS — no network traffic, about 7 seconds:

```bash
uv run pytest          # 241 tests
uv run ruff check .    # All checks passed!
```

## Running it

```bash
uv run python -m netscope
```

The same command on Windows, Linux and macOS. On start it prints the URL, the
database path, which name lookup is on and which `Host` names it trusts;
`Ctrl+C` stops it.

Settings are environment variables, all optional:

| Env var | Default | Meaning |
|---|---|---|
| `NETSCOPE_DB` | `netscope.db` | SQLite database path |
| `NETSCOPE_HOST` | `127.0.0.1` | Bind address; `0.0.0.0` exposes the UI on the LAN |
| `NETSCOPE_PORT` | `8000` | HTTP port |
| `NETSCOPE_ALLOWED_HOSTS` | *(empty)* | Extra `Host` header names to trust (comma-separated) |
| `NETSCOPE_NMAP_TIMEOUT` | `300` | Seconds per nmap pass; a `/24` with silent hosts can take minutes |
| `NETSCOPE_MDNS` | `1` | Name suggestions over mDNS; `0` turns the lookup off |
| `NETSCOPE_NETBIOS` | `1` | NetBIOS workstation names (UDP 137); `0` turns the lookup off |

Windows PowerShell: `$env:NETSCOPE_PORT = "9000"` before the run command.
Linux/macOS: `NETSCOPE_PORT=9000 uv run python -m netscope`.

**Where your data lives.** `netscope.db` in the folder you started from
(gitignored, and the start-up line prints the exact path). It holds every scan
and your manual device names. Delete the file to start from scratch;
`NETSCOPE_DB` puts it somewhere else.

**Opening the UI from another device** (optional). Bind `NETSCOPE_HOST=0.0.0.0`
and add the address that device types in its browser to
`NETSCOPE_ALLOWED_HOSTS` (e.g. `192.168.0.14`). The server answers only
`localhost`, `127.0.0.1`, and the names you list — anything else gets
`400 Invalid host header`, which is what stops a malicious page from driving
the scanner. `0.0.0.0` is a bind address and never arrives as a `Host` header,
so listing it does not help. There is no login: keep the UI on localhost
unless you trust everything on that network.

## Using the web UI

- **Target** is prefilled with the subnet this machine routes from (assumed
  `/24`) and is always editable — the guess is wrong if the server runs on a
  Docker or VPN bridge. Only private ranges are accepted; anything else is
  refused with a clear error.
- **Quick scan** runs nmap's discovery pass only (`-sn`) and answers "who is on
  the network" in seconds. Devices show up as `seen`; the Open ports column
  reads `not probed`.
- **Deep scan** follows discovery with port, service and OS detection
  (`-sV -O`) on every host that answered — a few minutes for a `/24` on a
  normal PC. Use it when you want ports, versions and OS guesses.
- Only one scan runs at a time (both buttons disable while one is running); a
  second request is refused. Progress and errors show in the UI, and every
  finished scan is stored permanently, labelled `quick` or `deep`.
- **Device list**: name, IP, status (`seen`/`absent`), OS guess, vendor and open
  ports per latest scan. Devices that vanish are kept and shown as absent;
  hostname, OS and vendor are learned values that survive scans which no longer
  see them.
- **Names** come from reverse DNS first, then mDNS/Bonjour, then NetBIOS: every
  scan listens to what devices announce about themselves and asks each
  discovered host for its NetBIOS workstation name. A learned name fills in
  when DNS gave none — or when DNS gave the *same* name to several devices (a
  sinkhole/Pi-hole answer such as `blocked.local`). A unique DNS name is never
  overridden, and mDNS wins over NetBIOS on the same host. Devices that
  announce nothing keep the vendor/IP label.
- **Manual naming**: open a device and type a name. It beats any
  hostname/vendor label and survives every later scan; scans never overwrite it.
- **Deep scan a single device**: open a device and press *Deep scan this
  device* — it deep-scans just that device's current IP (`<ip>/32`) instead of
  the whole subnet, so a host that only ever got a quick scan has its ports and
  OS within seconds. It appears in the history as a `/32` scan.
- **Changes since previous scan** lists appeared/disappeared devices;
  **scan history** lists past scans with target and duration.

## Exporting

Under the *Devices* heading, **CSV** and **JSON** download the current
inventory:

- **CSV** — one row per device (identity, MAC, IP, name, hostname, vendor, OS,
  status, whether ports were probed, last scan, open ports with nmap's service
  and version in one cell). Opens in Excel; written as UTF-8 with a BOM so
  accented vendor names survive.
- **JSON** — the same records, losslessly: nested port objects plus a
  `generated_at` stamp and a device count. The one to feed a script.

Both are built from the same rows as the table, so the file always matches the
screen. Two deliberate choices: a quick scan exports `not probed` rather than a
blank cell (it never measured the ports), and values that look like spreadsheet
formulas are neutralised so a hostile hostname cannot execute in Excel.

From a terminal: `curl -OJ "http://127.0.0.1:8000/api/export?format=csv"`.

## The OS column is empty

OS detection (`-O`) needs raw sockets. Without them every scan still works —
ports, services, names — only the OS column stays blank, and the UI says so.

- **Windows:** nothing to fix; Npcap provides it. A normal PowerShell is enough.
- **Linux and macOS:** root, or one of these. First check whether `-O` is
  blocked at all — this is the exact probe NetScope runs before a scan, so its
  result is the answer:

  ```bash
  sudo nmap -sV -O 127.0.0.1
  ```

  A *successful* run need not name an OS — `No exact OS matches for host` still
  proves raw sockets work (localhost is the usual case; deep-scan a real device
  to see the column fill), and `docs/gotchas.md` explains why.

- **Run as root without uv.** uv is a per-user install, so `sudo uv …` fails
  with `sudo: uv: command not found` — and with the right `PATH` it is worse:
  `uv run` as root leaves root-owned files in `.venv` that break your next
  `uv sync`. Run the already-built interpreter instead:

  ```bash
  sudo NETSCOPE_DB=/tmp/netscope-root.db .venv/bin/python -m netscope
  ```

  (The `/tmp` database keeps a root-owned `netscope.db` out of the repo; drop
  the variable to use your normal one.)

- **Give nmap the capability once (Linux only)** and keep running as yourself:

  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"
  uv run python -m netscope            # -O now works without sudo
  ```

  Undo with `sudo setcap -r "$(command -v nmap)"`. Trade-off: every local user
  can then use raw sockets through nmap. macOS has no `setcap` — use the
  previous option.

## Troubleshooting

| What you see | What it means |
|---|---|
| `400 Invalid host header` | You opened the UI by an address it does not trust. Add that name to `NETSCOPE_ALLOWED_HOSTS` (and bind `NETSCOPE_HOST=0.0.0.0` if it is another device). |
| `[Errno 98] address already in use` (Windows: `10048`) | Something else owns port 8000 — set `NETSCOPE_PORT` to another port. |
| A scan finds only `172.17.x`/`172.18.x` devices | You are running NetScope inside Docker or WSL, so it sees the container bridge, not your LAN. Run it on the host. |
| `nmap binary 'nmap' not found` | nmap is not on `PATH`; install it and restart NetScope. |
| macOS firewall prompt after binding `0.0.0.0` | Allow incoming connections, or the UI is unreachable from other devices. |
| The scan takes minutes with no progress | Expected on a `/24` with hosts that do not answer; raise `NETSCOPE_NMAP_TIMEOUT` only if nmap is being cut off. |

More nmap-specific quirks: `docs/gotchas.md`.

## How it works

Python + `uv`, a FastAPI backend, a plain vanilla-JS frontend (no build step),
SQLite from the standard library, and `nmap` as a subprocess:

- **Two nmap passes.** `nmap -sn` discovery on the subnet, then `nmap -sV -O`
  (ports, services, OS) on the hosts that answered. A quick scan stops after
  the first pass. nmap's XML output is parsed into device records; a fake
  runner replays recorded XML in the tests, so the suite needs no network.
- **Private ranges only, enforced in code.** `netscope/target.py` parses every
  target and refuses anything outside `10/8`, `172.16/12`, `192.168/16`
  (including a CIDR that spills out of them), before nmap or the database is
  touched.
- **Devices, not IP snapshots.** Identity is the MAC when known, else the IP, so
  a device keeps one row across DHCP changes; history and manual names follow
  it. Scans merge into the same rows with `COALESCE`, so an empty field never
  blanks a known one.
- **Names** come from reverse DNS, then mDNS, then NetBIOS, in that order of
  authority; a name is only ever *suggested*, never invented, and devices that
  say nothing keep the vendor/IP label.
- **Storage** is one SQLite file (schema v4, older databases upgrade in place)
  holding scans, devices, ports per scan, sightings and your manual names.
- **Export** renders the same inventory records the table shows, so the file
  and the screen cannot disagree.

**241 tests**, fixture-driven, CI on Linux and Windows × Python 3.12/3.13.

The design notes live in `docs/architecture.md` (module by module),
`docs/decisions.md` (why each choice was made), `docs/gotchas.md` (nmap quirks
worth knowing) and `docs/STATUS.md` (where the project stands).

## License

MIT — see [LICENSE](LICENSE).
