# Gotchas learned on this project

Written for the next session. Each one cost real debugging time.

## nmap XML
- **Ports use the `portid` attribute, not `port`.** `<port protocol="tcp" portid="443">`. Reading `port` returns `None` and produced `0/tcp` for every device in a real scan. A `<port>` with no `portid` is skipped — never default it to 0.
- **Hostnames nest under `<hostnames>`, not as a direct `<host>` child.** `<hostnames><hostname name="atom.lan" type="PTR"/></hostnames>`. `host.find("hostname[@type='PTR']")` finds nothing — hostname was always `None` on real scans until #30. Prefer `type="PTR"` (reverse DNS), then `user`, then any.
- **OS matches nest as `<os><osmatch name="Linux 5.0 - 5.14">`, not `<os><osclass>`.** The guess is the first `osmatch`'s `name`; `<osclass>` lives *inside* `osmatch` and only carries attributes (`osfamily`, e.g. "Linux") as fallback. `<osclass>` has no `osclass` attribute — reading one gives `None`.
- **ElementTree quirks:** `findall("a/@attr")` returns nothing (use `element.get("attr")`); `elem or elem` raises a truth-value `DeprecationWarning` — always compare with `is None`. Attribute predicates in paths **do** work: `find("hostnames/hostname[@type='PTR']")` returns the PTR entry, verified on Python 3.12, 3.13 and 3.14. An earlier note claiming they don't was wrong — the hostname bug (#30) was purely the missing `<hostnames>` nesting, so the parser's explicit `findall` + `get("type")` selection is a style choice, not a workaround.
- **A fixture may have its *values* mechanically redacted — never its structure invented.** The real-capture rule (AGENTS.md) is about XML shapes. A capture that would publish the owner's MAC addresses may have only the `addr` values of `<address addrtype="mac">` replaced, by a committed deterministic script (`scripts/redact_mac_addresses.py`) and with the original's sha256 plus a `diff` proof in `tests/fixtures/README.md`; a guard test asserts the committed fixture holds only placeholders. Never delete elements, rename attributes, or hand-edit values — if the provenance cannot be re-checked, do not ship the fixture.
- **Fixtures must mirror real nmap output.** `tests/fixtures/*.xml` are hand-written; ours invented `port="..."` **and** the hostname/OS nesting, so every test passed while real scans were broken (83 green, three parser bugs). When adding a fixture, copy real `-oX -` output, don't guess structure.
- **Capture XML with `-oX <file>`, not a shell redirect.** `nmap ... -oX - > atom.xml` in PowerShell writes **UTF-16-LE** (nmap's own output is UTF-8) and, when `-O` quits unprivileged, the file ends after the `<scaninfo>` line — no `<host>`, no closing tag (our 2026-11-24 capture did exactly that, 8762 bytes). Let nmap write the file itself: `nmap -sV -O -oX atom.xml 192.168.0.250`.
- **`nmap -O` on Windows: privilege behavior (Falco's evidence, 2026-11-24).**
    - `nmap --version` in regular PowerShell (same binary NetScope's runner calls):
      ```
      Nmap version 7.80 ( https://nmap.org )
      Platform: i686-pc-windows-windows
      Compiled with: nmap-liblua-5.3.5 openssl-1.0.2s nmap-libssh2-1.8.2 nmap-libz-1.2.11
      nmap-libpcre-7.6 Npcap-0.9982 nmap-libdnet-1.12 ipv6
      Compiled without:
      Available nsock engines: iocp poll select
      ```
    - Unprivileged CLI run with `-O`: quits with "TCP/IP fingerprinting (for OS scan) requires root privileged. QUITTING!" (exit 1) — same message as Apollo/Fedora.
    - **Contradiction resolved (2026-11-24, unprivileged NetScope scan):** Falco ran a full `/24` scan in a regular PowerShell window (no admin) on the #34 branch: scan completed in 275.1 s and the **OS column was populated** (`Linux 4.10` on Atom, `Microsoft Windows 10 1607`, several `Linux 2.6.x` guesses). So the `-O` probe succeeds unprivileged on Windows — Npcap 0.9982 compiled in is what lets it. The Nov-23 scans with empty OS were pre-#30 parser bugs (OS nesting), not privilege failures. Apollo/Linux still requires root (verified exit 1).
    - **Ctrl+C during a scan writes a preamble-only XML file.** The admin run `nmap -sV -O -oX atom.xml 192.168.0.250` interrupted after a couple of seconds produced 4440 bytes: XML header + `<scaninfo>` + verbose/debugging, **no `<host>` block and no closing `</nmaprun>`** — `ET.fromstring` raises `ParseError`. Reproduced again 2026-11-25 (regular PowerShell, `nmap -sV -O -oX falco-nmap-testrun.xml 192.168.0.0/24`, Ctrl+C after ~2 min): 4462 bytes, zero `<host>` blocks, same `ParseError: no element found` — nmap had not flushed a single host yet, so even two minutes is too early. Let a real scan **finish** (~4–5 min for a /24) before copying the XML. NetScope only stores finished scans (a runner error stores nothing), so this never reaches the parser in normal operation. The capture is kept verbatim as `tests/fixtures/atom_windows_admin.xml` and asserted to raise `ParseError` in `tests/test_scanner_parser.py` — do **not** hand-complete it to make it parse (AGENTS.md fixture rule).
- **`nmap` is not installed in the Hermes container.** Real scans only run on the Windows PC (`winget install nmap`) or on Apollo. Missing binary surfaces as the UI error line now, not a crash.
- **Admin PowerShell is NOT required for discovery + `-sV`** (verified 2026-11-23 in a regular PowerShell window: two `192.168.0.0/24` scans completed unprivileged, 271.77 s and 236.08 s; their empty OS column was the pre-#30 parser nesting bug, not a privilege failure — the 2026-11-24 unprivileged scan on the #34 branch populated OS). The 2026-11-24 admin run (`/24`, 236.1 s) shows the **OS column populated** (`Linux 4.10`, `Microsoft Windows 10 1607`, `Linux 2.6.32 - 3.10`) and PTR hostnames resolving via Pi-hole (`blocked.local` on several devices) — so on Windows admin changes nothing for `-O` (Npcap); only Linux/macOS need root.

- **Transient nmap crash on Windows**: the first scan of a session can abort with exit `3221226505` (`0xC0000409` STATUS_ASSERTION_FAILURE) and `Assertion failed: htn.toclock_running == true, file ..\Target.cc, line 503`. A retry succeeds immediately; NetScope shows the error line in the UI and stores nothing for the failed scan.
- **A `/24` is slow because silent addresses must time out.** ~290 s observed with 10 live hosts. The timeout is **per nmap pass** (`NETSCOPE_NMAP_TIMEOUT`, default 300 s) and there are two passes, so worst case ≈ 10 min before it errors with `nmap timed out after 300s`.
- **Reverse DNS is partial, not absent.** Pi-hole on Atom answers PTR for many devices, so real scans show hostnames like `blocked.local` (2026-11-24 admin scan). The parser reads hostnames correctly since #30 — an empty column now means the name genuinely isn't resolvable. M8 (#23) solved naming with a **manual `device_names` table**: `display_name` priority is manual name → hostname → vendor+IP → bare IP; names live in their own table, are never touched by scans, and survive a v1→v2 schema upgrade (`PRAGMA user_version = 2`).

## Store & presence semantics (since #31, schema v4 since #39)
- **Presence is a sighting, not a port row.** `scan_devices(scan_id, identity, ip)` records one row per host **up** in that scan. Seen/absent, `last_seen_scan` and `diff_scans()` all read this table. Never infer presence from `device_ports` again — that caused all three #31 bugs (portless up host invisible, `last_seen_scan` stamped for devices not in the scan, `/32` scan marking every other device gone).
- **`save_scan` upserts `devices` only for hosts present in the result**, so an absent device keeps its old `last_seen_scan`. A device up with zero open ports is still sighted (`status == "seen"`, `open_ports == []`).
- **Diffs are target-aware.** `diff_scans()` compares only devices whose IP falls inside **both** scans' targets; `/api/diff` without ids uses the latest earlier scan with the **same target** and 404s ("no earlier scan with the same target to compare") instead of pairing a `/32` against a `/24`. Explicit `from_id`/`to_id` still works across targets.
- **v2→v3 backfill is best effort**: it derives historical sightings from `device_ports`, so a historical up host with zero ports has no backfilled sighting. Only new scans capture that correctly.
- **Identity can change mid-life (#35).** An IP-keyed device that later reports a MAC re-keys to the MAC, so `identity` is NOT stable across scans — never cache an identity and write it back later. `merge_scan` returns `(merged, rekeys)`; the store's `_rekey_identity` must run BEFORE the upserts in `save_scan`. With `PRAGMA foreign_keys = ON` the order is forced: insert the new `devices` parent → update `device_ports`/`scan_devices` → move `device_names` → delete the old parent. Deleting the old parent first raises `sqlite3.IntegrityError: FOREIGN KEY constraint failed` and rolls the whole scan write back (verified by monkeypatching the naive order).
- **A MAC conflict means two machines, not one row.** If the stored row already carries a different MAC than the incoming host, they are different devices (DHCP change): do not overwrite the stored MAC.
- **Port data is a *measurement*, so it can't be compared across a quick scan (#39).** A quick scan (`-sn` only) stores no `device_ports` rows; comparing its empty port set against a deep scan reports every device as "changed open ports" or "opened everything". `diff_scans()` therefore only diffs ports when `scan_mode(a) == scan_mode(b) == "deep"`, while appeared/disappeared keep working in every mode. The same honesty rule produced `ports_probed` in `/api/devices` (the UI says `not probed`, never a blank cell) and the quick-scan variant of `/api/os-hint`. If you add a third scan mode, every "is this data comparable?" branch needs it too — check `scan_mode`, not the presence of port rows.

## Names: PTR vs mDNS (#38, #41)
- **Priority is unique PTR > mDNS > NetBIOS**, applied in `NmapScanner._with_names` (fill only when the PTR name is missing or shared by 2+ hosts in the same scan). The merge is `{**netbios_names, **mdns_names}` — mDNS overrides NetBIOS on the same address. `_with_names` is source-agnostic; add a source by feeding the dict, not by adding a branch.
- **The LAN's PTR answers are useless by themselves** — the resolver returns `blocked.local` for every address, so `devices.hostname` is often a name shared by 8 devices. The store suppresses shared names at read time (#38); mDNS (#41) is what actually names those devices.
- **The PTR name wins unless it is empty or ambiguous *in this scan*.** `NmapScanner._with_names` counts hostnames in the scan result and only fills from a learned name when the host has none or when its PTR name is shared by 2+ hosts. Overwriting a unique PTR name with a self-reported name would be a downgrade. Consequence to know: if 8 hosts share `blocked.local` and mDNS names 7 of them, the 8th keeps `blocked.local` — and the store's read-time suppression only kicks in while 2+ devices share it, so that one row can show `blocked.local` until its own answer arrives.
- **The PyPI distribution is `zeroconf`, not `python-zeroconf`.** `uv add python-zeroconf` fails with "not found in the package registry"; the GitHub repo is python-zeroconf/python-zeroconf but the package you import and depend on is `zeroconf` (version 0.154.0 added here; LGPL-2.1-or-later, imported unmodified).
- **DNS-SD browsing is two-stage, and the listener's `name` argument changes meaning.** Browsing `_services._dns-sd._udp.local.` calls `add_service(zc, "_services._dns-sd._udp.local.", "<type>.local.")` — the *name* is the service type, not an instance. Browsing `<type>.local.` then yields instance names, and `zc.get_service_info(type, instance)` resolves SRV/A. Feeding the meta type into `get_service_info` raises `BadTypeInNameException` (hit while prototyping).
- **Verify mDNS without a LAN**: `zeroconf` can register a fake service in the same machine/container (`ServiceInfo("_x._tcp.local.", "demo._x._tcp.local.", addresses=[inet_aton(ip)], server="demo.local.")`), so the resolver can be exercised against real multicast — no invented fixtures. Verified this way: `MdnsNameResolver().names_by_ip()` → `{'192.168.0.10': 'atom.local'}` in 3.5 s. Multicast (224.0.0.251:5353) works inside this container for that test, but the container still cannot see the home LAN — real hit rates need a scan on Atlas/Apollo.
- **The lookup must never fail a scan.** It runs in a daemon thread while nmap works (`_NameLookup`), every exception becomes `{}`, and `join` is capped at 10 s; the resolver itself is bounded by `DEFAULT_TIMEOUT` (3.5 s) + `INFO_BUDGET` (1.5 s). Tests inject a fake resolver — importing `netscope.mdns` must never open sockets at import time (it doesn't: `Zeroconf()` is constructed lazily inside `names_by_ip`).
- **NetBIOS (#41 part 2) is a hand-written NBSTAT client (`netscope/netbios.py`), implemented from nmap's `nselib/netbios.lua`** (`do_nbstat`, fetched from svn.nmap.org 2026-11-25), not from memory: 12-byte header (trn 0x1337, one question), the first-level encoded wildcard name, QTYPE 0x0021 / QCLASS 0x0001; the answer repeats name/type/class, then TTL, RDLENGTH, a 1-byte count and 18-byte entries (15-byte name, suffix, 2-byte flags). Two encoding details that are easy to get wrong: `*` is padded with **NULs** while every other name is padded with **spaces**, and the workstation name is the `<00>` entry **without** the group flag `0x8000` (a domain name is also `<00>`).
- **No NetBIOS-capable device exists in this container**, so the parser is tested against packets built to nmap's documented layout (`tests/test_netbios.py::nbstat_response`) and the client against a scratch responder over real UDP 137 — a real Windows reply is still unverified. It degrades to "no names" on any bad packet, so a wrong layout would be silent; the first real confirmation is a scan on Falco's LAN with a Windows box that has NetBIOS enabled (`nbtstat -A <ip>` on that box shows what it would answer).
- **NetBIOS queries are per-host and can be blocked**: Windows Firewall may drop UDP 137, and many modern Windows installs disable NetBIOS over TCP/IP entirely; Linux hosts without Samba never answer. That is why mDNS stays the primary source and the timeout is short (1 s, parallel across hosts).

## Frontend (app.js)
- **Never render scan/DB strings as markup.** Hostname, OS guess, vendor and
  service product come from the LAN and are stored in SQLite, so markup in them
  is stored XSS — a hostile device can answer PTR with
  `<img src=x onerror=...>` and run script in the UI. All cells go through
  `el(tag, className, text)` (`textContent` + `replaceChildren`);
  `tests/test_frontend_xss.py` fails the build if `innerHTML`, `outerHTML`,
  `insertAdjacentHTML` or `document.write` ever appear in `app.js`.
- **Verify frontend changes in a real DOM, not with `node --check`.** Syntax
  checking proves nothing about rendering. Reproduce offline: build the app with
  a fake runner whose `run()` returns XML carrying markup in hostname / product
  / osmatch, and point `netscope.api.app.STATIC_DIR` at a copy of the *old*
  `app.js` to get a RED baseline (jsdom with `runScripts: "dangerously"` works;
  jsdom has no `fetch`, so shim `window.fetch` before parse). Real-browser
  result 2026-11-24: old render executed the payload (`window.__xss == 1`, 2
  injected tags); fixed render shows literal text, 0 injected tags, no
  execution.
- **The browser harness's `js()` returns `{}` for some expressions** (flaky
  eval). Write results into `document.title` and read them with `page_info()`.
- **`replaceChildren(array)` renders `[object HTMLLIElement]`, not the elements.**
  A bare array argument is coerced to a DOMString — the "Changes since previous
  scan" list showed the literal string in a live scan (2026-11-24) while the
  scan-history call beside it spread correctly with `...`, so only one list broke
  and manual checks missed it. Spread every array: `replaceChildren(...items)`.
  `test_replace_children_spreads_array_arguments` walks each `replaceChildren(`
  call in app.js (paren-balanced) and requires `...`-spread, a direct `el(...)`,
  or an empty clear-call (`tbody.replaceChildren()` is legitimate).
- **Decide UI state server-side when it can be derived from data.** The #34 OS
  hint is a sentence, but *whether* to show it is a fact about the inventory
  ("devices exist and none has an `os_guess`"), so `GET /api/os-hint` decides and
  app.js only sets `textContent` + `hidden` (guards in
  `tests/test_frontend_os_hint.py`). This keeps the "frontend is dumb" rule and
  means the behaviour is covered by a real API test instead of a JS text grep.
  `loadOsHint()` swallows its own errors: a failed hint must never stop the
  device table from rendering.
- **Guard that every `$("id")` in app.js exists in index.html.** A renamed
  element id throws only in a browser at load time — no Python test sees it.
  `test_every_element_id_used_by_app_js_exists_in_the_page` extracts the ids
  with a regex and diffs them against the page; it was added with #39, where the
  single `#scan-btn` became `#quick-btn` + `#deep-btn`. The same file
  (`tests/test_frontend_scan_modes.py`) pins that both buttons send their own
  `mode` and that both disable together while a scan runs.

## Server & Host header (#36)
- **A foreign `Host` header must be rejected, and the test harness must not hide that.** `build_app` installs Starlette's `TrustedHostMiddleware`; it compares the hostname **with the port stripped and case-insensitively**, so allowing `127.0.0.1` also allows `127.0.0.1:8000`. Mismatch → `400 Invalid host header` before any route runs (GET *and* `POST /api/scan`).
- **`TestClient` sends `Host: testserver`**, so every app-level test needs `build_app(api, extra_hosts=("testserver",))` — `make_client` does it in one place. A test that builds its own `TestClient(build_app(api))` silently gets 400s and fails as "state idle", not as a host error.
- **`NETSCOPE_HOST=0.0.0.0` does not make LAN clients trusted** — `0.0.0.0` is a bind address and never arrives as a `Host` header. A LAN device reaching the UI must have its own address/name in `NETSCOPE_ALLOWED_HOSTS` (comma-separated, whitespace-tolerant). Verified live 2026-11-24: LAN bind allowed `192.168.0.14:8000`/`atom.local`, still 400'd `evil.example.com`.
- **IPv6 loopback `[::1]:8000` is rejected** by the default allowlist (Starlette's host parse of the bracketed literal doesn't match `::1`). If you ever open the UI that way, add it explicitly.

## Threading & SQLite (#37)
- **One connection per thread, not one shared connection.** `store.conn` is a `threading.local` property. A shared connection means every request thread reads *and commits* the scan thread's open transaction: `set_device_name`'s `commit()` used to publish a half-written `save_scan`, and readers could see a `scans` row with zero `scan_devices` rows.
- **`foreign_keys`, `journal_mode` and `busy_timeout` are per-connection pragmas.** Setting them once on one connection does nothing for the others — set them in the connection factory.
- **WAL is what lets the UI stay responsive during a scan write**: readers get a committed snapshot while the scan thread holds the write lock. Without WAL a writer blocks readers on the default `delete` journal.
- **A failed write must roll back explicitly** (`_write_txn()`): otherwise the thread's connection keeps an open transaction that blocks every other writer until `busy_timeout` gives up, and a later commit on that connection publishes the abandoned rows.
- **Deterministic race tests use a barrier at a real seam**, not sleeps: `merge_scan` is called inside `save_scan`'s transaction after the `scans` insert and before any device row, so monkeypatching it parks the writer at exactly the interesting moment. Remember to capture the original function *before* `monkeypatch.setattr`, or the wrapper recurses.
- **SQLite allows only one writer at a time**, so a test cannot have a second thread write while the first is parked mid-transaction — it deadlocks until `busy_timeout` raises `OperationalError: database is locked`. Park the writer with a barrier that *times out* so the writer gives up and the second write proceeds.

## Tests & CI
- **CI runs the suite on Linux *and* Windows (3.12/3.13 on each); Falco also runs it on Windows.** That is what the Windows job is for — it exists because a Windows-only failure (`nmap-mac-prefixes` leak) once passed here and failed on his box. Never use `false`, `sleep`, or other POSIX binaries in tests. For exit codes use `sys.executable` with `-c "raise SystemExit(3)"` and assert `"exit 3"`.
- **Expected harmless warning:** `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead` — ignore it, don't chase it.
- **Test count is a good health signal**: 1 → 37 → 46 → 52 → 59 → 65 → 68 → 70 → 71 → 78 → 83 → 87 → 89 → 96 (#31) → 97 (#48 ParseError fixture) → 101 (#52 probe + #53 guard tests) → 106 (#35 re-key: 3 merge_scan + 2 store migration tests) → 111 (#36 Host allowlist: 5 API tests) → 114 (#37 threading: 3 store race/connection tests) → 124 (#38 hostname ambiguity) → 127 (`/api/diff` unknown ids) → 137 (env-var validation) → 141 (vendor registry data) → 149 (nmap `nmap-mac-prefixes` loader) → 152 (packaging guard: `uv sync` must keep the dev tools) → 153 (registry test isolation) → 156 (Windows CI matrix guard, 3 tests) → 157 (LICENSE/packaging agreement guard) → 162 (real home-LAN fixture: 2 parser + 3 redaction-script tests) → 168 (#34 OS hint: 3 API + 3 frontend guard tests) → 189 (#39 scan modes: 4 engine + 4 store + 7 API + 6 frontend guards) as milestones landed; a sudden drop means a fixture or parser change broke coverage.
- In this container use `~/.local/bin/uv run pytest` (Python 3.14); `uv sync` first if deps are missing — pytest/ruff are a default dependency group, so plain `uv sync` installs them. Never `uv sync --extra dev`: that extra no longer exists, and against the old layout it made plain `uv sync` *remove* the dev tools.

## Merging workflow
- **GitHub closing keywords fire on prose too.** PR #48's body said "close #34 evidence gap" — GitHub matched `close #34` and auto-closed issue #34 even though only evidence (docs + a fixture) shipped, not the fix. #34 had to be reopened. Only write `closes #N`/`fixes #N` when the PR actually fixes the issue; for evidence-only PRs write "see #N" or "evidence for #N".
- **A squash-merge can silently drop doc hunks.** PR #46 was stacked on docs PR #45; after Falco merged both, `docs/decisions.md` lost three rows and `docs/STATUS.md` kept the old "next steps" order. Check every merge with `git diff <merged-branch> main` (the branch survives locally after the remote delete) and re-apply missing doc lines in a small docs PR. Same for stacked PRs touching the same doc files — verify both landed.
- After Falco squash-merges and deletes a branch, `git pull --ff-only` fails while you are still on that branch ("no such ref was fetched") — `git checkout main` first, then `git fetch --prune`.

## gh & git plumbing
- **`git push` can fail with `remote: Internal Server Error` / `[remote rejected]`.** That is a transient GitHub error, not a repo problem: the local commit is fine, so wait ~45s and push again. Never re-commit "because the push failed".
- **`gh pr create` / `gh issue comment` often print no URL** — the output is replaced by the `gh event listen` preview hint. Verify the write landed instead: `gh pr list --json number,title,url` and `gh issue view N --json state,comments --jq '{state, last: (.comments[-1].body | .[0:80])}'`.
- **Don't add `-q` on the command line: `addopts = "-q"` is already in `pyproject.toml`.** Two `-q` flags mean verbosity −2 (pytest 9.2), and **that** is what prints no final summary line — only the progress dots. A plain `uv run pytest` *does* end with `168 passed, 1 warning in 6.00s`; `uv run pytest -q` ends with silence, which is exactly the "no count for the PR body" trap. If you want file names *and* the summary, override the option instead: `uv run pytest -o addopts=""`. Always judge a run by its exit code (write output to a file and echo `$?`), never by an absence of text.
- **`ruff format --check netscope tests` always reports 2 files** (`tests/test_scanner_parser.py`, `tests/test_target_guard.py`) — pre-existing debt on `main`. Check only the files you touched (`ruff format --check <your files>`) and do not sweep the others.
- **A PR that covers half an issue must not use a closing keyword.** For #37 part 1 the body says "Part of #37" and the issue stays OPEN; link progress with an `gh issue comment` instead.

## Running as root (`sudo`) on Linux/macOS
- **`sudo uv …` can never work, and "fixing" the PATH makes it worse.** uv installs per user (`~/.local/bin`), while `sudo` uses the `secure_path` from `/etc/sudoers`, so root cannot find the binary — that is the `sudo: uv: command not found` Falco hit on Apollo (#79). Passing `PATH` through would run `uv run` as root, which writes root-owned `.venv`/cache entries and breaks the user's next `uv sync` (recovery is `chown -R`); the `netscope.db` in the repo would become root-owned too.
- **Answer the real question first**: `sudo nmap -sV -O 127.0.0.1` is exactly what `probe_os()` runs, so its success *is* "the OS column would populate".
- **To run the app as root**, skip uv: `sudo NETSCOPE_DB=/tmp/netscope-root.db .venv/bin/python -m netscope` (the interpreter is already built; `/tmp` keeps a root-owned DB out of the repo).
- **Better on a Linux desktop**: `sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"` once, then run unprivileged — `-O` works because nmap itself holds the capability. Undo with `sudo setcap -r`. Never do this in a container you do not trust (it grants raw sockets to every local user). macOS has no `setcap`; run as root there.

## Networking of this agent container
- The Hermes container is on the **Docker bridge** (`172.18.0.2`, gateway `172.18.0.1`), **not** the home LAN. It cannot scan `192.168.x.x`, and `GET /api/local-subnet` correctly reports `172.18.0.0/24` from inside it — that is not a bug, it is the documented `/24` + "machine's own subnet" caveat.
- Home LAN facts: subnet `192.168.0.0/24`, router `192.168.0.1`, Atlas (Windows PC) `192.168.0.14`. Atom (DietPi homeserver) and Apollo (Fedora laptop) must appear in scan results.
- Subnet/gateway come from `ipconfig` (Windows) or `ip -4 addr show` / `ip route` (Linux). WSL can reach the LAN only with `networkingMode=mirrored` in `/etc/wsl.conf`.

## Repo conventions
- Never push to main; branch `hermes/<topic>`; one feature per PR; Falco squash-merges and deletes the branch, then says "continue to the next step".
- `gh` is logged in as `Falco404` (`GH_CONFIG_DIR=/opt/data/.config/gh`); the token is **never** written into the repo, and other processes' environments/secrets are off-limits — ask instead of working around it.
- Every PR body needs: plain-language summary, exact Windows try-it commands, **pasted** test output, and anything decided/unsure. Every PR updates `docs/STATUS.md` and `docs/decisions.md`.
- `AGENTS.md` was rewritten (#20) and no longer spells out the RFC1918 restriction. **The guard still enforces private ranges in code — do not weaken it** because the doc no longer says so.
- Harmless 404s in server logs: `/favicon.ico` (no icon shipped) and `/api/diff` before the second scan exists.
- `GET /api/scan/status` is polled once per second while a scan runs — infinite `GET` lines in the log are normal, they stop on done/error.
- **The suite must pass whether or not the developer has nmap installed** — in both directions. `main()` reads nmap's `nmap-mac-prefixes` file at startup, and `tests/test_main_env.py` runs `main()`, so on a machine with nmap in `PATH` that test loads 52,085 real registrations into the process-wide `MAC_PREFIXES` dict and they leak into later test modules. That is exactly how `test_vendor_registry.py::test_comment_lines_are_not_entries` failed on a Windows box while passing here: `525400 QEMU virtual NIC` is a genuine entry in nmap's file, not a comment line that got parsed. `tests/test_main_env.py` pins `NMAPDIR` and `shutil.which`; `clean_registry` in `test_vendor_registry.py` resets the dict to the built-in seed before each test.
- `load_mac_prefixes()` **replaces** the registry. Do not "optimise" it back into merging into the existing dict: a loaded file is the registry, and merging keeps vendors from a file that is no longer in effect.
- **Never judge a test run from piped output.** `uv run pytest -q 2>&1 | tail -1` here printed the warnings-summary docs link and **no** `N passed` line, and the shell tool reports the exit code of the *last* command in a pipeline — not of pytest — so a failing run can look like exit 0 with no failures. Write the full output to a file and `echo "exit=$?"` after the run, or run pytest without `-q` and read the last line.
- **Old `hermes/*` branches are squash-merged, not ancestry-merged.** `git branch --merged main` lists nothing and `git branch -d` refuses them even though their PRs are merged (`git merge-base --is-ancestor <branch> main` → no). Delete one only after checking that its PR is merged (`gh pr list --state merged --head <branch>`); never blanket-delete.
