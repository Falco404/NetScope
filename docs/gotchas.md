# Gotchas learned on this project

Written for the next session. Each one cost real debugging time.

## nmap XML
- **Ports use the `portid` attribute, not `port`.** `<port protocol="tcp" portid="443">`. Reading `port` returns `None` and produced `0/tcp` for every device in a real scan. A `<port>` with no `portid` is skipped — never default it to 0.
- **`<osclass>` uses `osfamily`, not `osclass`.** `osclass` doesn't exist; reading it gave `None` and the OS column stayed empty.
- **`ElementTree.findall("a/@attr")` returns nothing.** Use `element.get("attr")`.
- **Fixtures must mirror real nmap output.** `tests/fixtures/*.xml` are hand-written; ours invented `port="..."` and every test passed while real scans were broken. When adding a fixture, copy real `-oX -` output, don't guess attribute names.
- **`nmap -O` needs raw-socket privileges** (admin PowerShell on Windows). Without them the OS guess is empty, not an error.
- **`nmap` is not installed in the Hermes container.** Real scans only run on the Windows PC (`winget install nmap`) or on Apollo. Missing binary surfaces as the UI error line now, not a crash.
- **Discovery needs privileges for ARP.** Whether admin PowerShell is *required* is **unverified**: only admin has been tested (~290 s for `192.168.0.0/24`). README records this.
- **A `/24` is slow because silent addresses must time out.** ~290 s observed with 10 live hosts. The timeout is **per nmap pass** (`NETSCOPE_NMAP_TIMEOUT`, default 300 s) and there are two passes, so worst case ≈ 10 min before it errors with `nmap timed out after 300s`.
- **No hostnames from the router.** Reverse DNS is unanswered on the home LAN, so devices show bare IPs plus vendor. NetBIOS/ARP-alias fallback is the M8 plan.

## Tests & CI
- **CI is Linux-only (3.12/3.13), Falco runs tests on Windows.** Windows-only test bugs never show in CI: never use `false`, `sleep`, or other POSIX binaries in tests. For exit codes use `sys.executable` with `-c "raise SystemExit(3)"` and assert `"exit 3"`.
- **Expected harmless warning:** `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead` — ignore it, don't chase it.
- **Test count is a good health signal**: 1 → 37 → 46 → 52 → 59 → 65 → 68 → 70 → 71 → 78 as milestones landed; a sudden drop means a fixture or parser change broke coverage.
- In this container use `~/.local/bin/uv run pytest` (Python 3.14); `uv sync --extra dev` first if deps are missing.

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
