# Gotchas learned on this project

Written for the next session. Each one cost real debugging time.

## nmap XML
- **Ports use the `portid` attribute, not `port`.** `<port protocol="tcp" portid="443">`. Reading `port` returns `None` and produced `0/tcp` for every device in a real scan. A `<port>` with no `portid` is skipped — never default it to 0.
- **Hostnames nest under `<hostnames>`, not as a direct `<host>` child.** `<hostnames><hostname name="atom.lan" type="PTR"/></hostnames>`. `host.find("hostname[@type='PTR']")` finds nothing — hostname was always `None` on real scans until #30. Prefer `type="PTR"` (reverse DNS), then `user`, then any.
- **OS matches nest as `<os><osmatch name="Linux 5.0 - 5.14">`, not `<os><osclass>`.** The guess is the first `osmatch`'s `name`; `<osclass>` lives *inside* `osmatch` and only carries attributes (`osfamily`, e.g. "Linux") as fallback. `<osclass>` has no `osclass` attribute — reading one gives `None`.
- **ElementTree quirks:** `findall("a/@attr")` returns nothing (use `element.get("attr")`); `elem or elem` raises a truth-value `DeprecationWarning` — always compare with `is None`. Attribute predicates in paths **do** work: `find("hostnames/hostname[@type='PTR']")` returns the PTR entry, verified on Python 3.12, 3.13 and 3.14. An earlier note claiming they don't was wrong — the hostname bug (#30) was purely the missing `<hostnames>` nesting, so the parser's explicit `findall` + `get("type")` selection is a style choice, not a workaround.
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
    - **Unresolved contradiction:** two unprivileged NetScope scans on 2026-11-23 completed with `-O` in args (OS column empty). Npcap 0.9982 is compiled in, which may let scans survive without admin; needs one unprivileged NetScope scan to close. #34 makes `-O` conditional on a privilege probe so both behaviors are safe.
    - **Ctrl+C during a scan writes a preamble-only XML file.** The admin run `nmap -sV -O -oX atom.xml 192.168.0.250` interrupted after a couple of seconds produced 4440 bytes: XML header + `<scaninfo>` + verbose/debugging, **no `<host>` block and no closing `</nmaprun>`** — `ET.fromstring` raises `ParseError`. NetScope only stores finished scans (a runner error stores nothing), so this never reaches the parser in normal operation. The capture is kept verbatim as `tests/fixtures/atom_windows_admin.xml` and asserted to raise `ParseError` in `tests/test_scanner_parser.py` — do **not** hand-complete it to make it parse (AGENTS.md fixture rule).
- **`nmap` is not installed in the Hermes container.** Real scans only run on the Windows PC (`winget install nmap`) or on Apollo. Missing binary surfaces as the UI error line now, not a crash.
- **Admin PowerShell is NOT required for discovery + `-sV`** (verified 2026-11-23 in a regular PowerShell window: two `192.168.0.0/24` scans completed unprivileged, 271.77 s and 236.08 s, OS column empty). The 2026-11-24 admin run (`/24`, 236.1 s) shows the **OS column populated** (`Linux 4.10`, `Microsoft Windows 10 1607`, `Linux 2.6.32 - 3.10`) and PTR hostnames resolving via Pi-hole (`blocked.local` on several devices) — so admin only changes whether `-O` survives, per the line above.

- **Transient nmap crash on Windows**: the first scan of a session can abort with exit `3221226505` (`0xC0000409` STATUS_ASSERTION_FAILURE) and `Assertion failed: htn.toclock_running == true, file ..\Target.cc, line 503`. A retry succeeds immediately; NetScope shows the error line in the UI and stores nothing for the failed scan.
- **A `/24` is slow because silent addresses must time out.** ~290 s observed with 10 live hosts. The timeout is **per nmap pass** (`NETSCOPE_NMAP_TIMEOUT`, default 300 s) and there are two passes, so worst case ≈ 10 min before it errors with `nmap timed out after 300s`.
- **Reverse DNS is partial, not absent.** Pi-hole on Atom answers PTR for many devices, so real scans show hostnames like `blocked.local` (2026-11-24 admin scan). The parser reads hostnames correctly since #30 — an empty column now means the name genuinely isn't resolvable. M8 (#23) solved naming with a **manual `device_names` table**: `display_name` priority is manual name → hostname → vendor+IP → bare IP; names live in their own table, are never touched by scans, and survive a v1→v2 schema upgrade (`PRAGMA user_version = 2`).

## Store & presence semantics (since #31, schema v3)
- **Presence is a sighting, not a port row.** `scan_devices(scan_id, identity, ip)` records one row per host **up** in that scan. Seen/absent, `last_seen_scan` and `diff_scans()` all read this table. Never infer presence from `device_ports` again — that caused all three #31 bugs (portless up host invisible, `last_seen_scan` stamped for devices not in the scan, `/32` scan marking every other device gone).
- **`save_scan` upserts `devices` only for hosts present in the result**, so an absent device keeps its old `last_seen_scan`. A device up with zero open ports is still sighted (`status == "seen"`, `open_ports == []`).
- **Diffs are target-aware.** `diff_scans()` compares only devices whose IP falls inside **both** scans' targets; `/api/diff` without ids uses the latest earlier scan with the **same target** and 404s ("no earlier scan with the same target to compare") instead of pairing a `/32` against a `/24`. Explicit `from_id`/`to_id` still works across targets.
- **v2→v3 backfill is best effort**: it derives historical sightings from `device_ports`, so a historical up host with zero ports has no backfilled sighting. Only new scans capture that correctly.

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

## Tests & CI
- **CI is Linux-only (3.12/3.13), Falco runs tests on Windows.** Windows-only test bugs never show in CI: never use `false`, `sleep`, or other POSIX binaries in tests. For exit codes use `sys.executable` with `-c "raise SystemExit(3)"` and assert `"exit 3"`.
- **Expected harmless warning:** `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead` — ignore it, don't chase it.
- **Test count is a good health signal**: 1 → 37 → 46 → 52 → 59 → 65 → 68 → 70 → 71 → 78 → 83 → 87 → 89 → 96 (#31) → 97 (#48 ParseError fixture) as milestones landed; a sudden drop means a fixture or parser change broke coverage.
- In this container use `~/.local/bin/uv run pytest` (Python 3.14); `uv sync --extra dev` first if deps are missing.

## Merging workflow
- **GitHub closing keywords fire on prose too.** PR #48's body said "close #34 evidence gap" — GitHub matched `close #34` and auto-closed issue #34 even though only evidence (docs + a fixture) shipped, not the fix. #34 had to be reopened. Only write `closes #N`/`fixes #N` when the PR actually fixes the issue; for evidence-only PRs write "see #N" or "evidence for #N".
- **A squash-merge can silently drop doc hunks.** PR #46 was stacked on docs PR #45; after Falco merged both, `docs/decisions.md` lost three rows and `docs/STATUS.md` kept the old "next steps" order. Check every merge with `git diff <merged-branch> main` (the branch survives locally after the remote delete) and re-apply missing doc lines in a small docs PR. Same for stacked PRs touching the same doc files — verify both landed.
- After Falco squash-merges and deletes a branch, `git pull --ff-only` fails while you are still on that branch ("no such ref was fetched") — `git checkout main` first, then `git fetch --prune`.

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
