# Test fixtures

`AGENTS.md`: fixtures must be captured from real tool output, never written from
memory. Where a real capture would publish something its owner does not want in
the repo, the change is a mechanical, reproducible value substitution,
documented below — the XML structure and every other value stay exactly as the
tool wrote them.

| File | Origin | Notes |
|---|---|---|
| `nmap_discovery.xml`, `nmap_service.xml`, `nmap_empty.xml` | hand-written (M3, before the capture rule) | Shapes were copied from nmap docs, not captured. The `port`/hostname/OS parsing bugs survived because these fixtures confirmed the invented shapes. Kept for the M3 tests, but new parser assertions belong on captured files. |
| `atom_windows_admin.xml` | real capture, admin PowerShell, 2026-11-24 | `nmap -sV -O -oX atom.xml 192.168.0.250`, interrupted with Ctrl+C after ~2 s. Preamble only (no `<host>`, no closing tag) — kept verbatim as a `ParseError` regression case. |
| `nmap-mac-prefixes-sample.txt` | byte-exact slice of nmap master's `nmap-mac-prefixes` | 52,091 lines, sha256 `ae8b132bb3471ea94055e111137f76e041f4a8f5df9799ac184cc1fbf23d508d`, captured 2026-11-25; every entry verified present verbatim upstream. |
| `home_lan_complete_2026-11-25.xml` | real completed capture, 2026-11-25 | See below. MAC addresses **redacted** with a committed script. |

## `home_lan_complete_2026-11-25.xml`

- **Capture**: regular (non-admin) PowerShell on the Windows PC, 2026-11-25:
  `"C:\Program Files (x86)\Nmap\nmap.exe" -sV -O -oX falco-nmap-testrun-finish.xml 192.168.0.0/24`
  nmap 7.80 (`i686-pc-windows-windows`, Npcap 0.9982). The scan **finished
  successfully** in 599.73 s: 12 hosts up, 244 down, 256 addresses, complete
  `</nmaprun>` and `<runstats>`.
- **Original** sha256 `54b8e530bc492d621460b4b5b08853714d944c64343eca7e0697427bb37aa2df`
  — kept by the owner and deliberately **not** published in the repo.
- **Redaction**: `python scripts/redact_mac_addresses.py <original> tests/fixtures/home_lan_complete_2026-11-25.xml`
  replaced the 11 `<address ... addrtype="mac">` values, in encounter order, with
  `02:00:00:00:00:01` … `02:00:00:00:00:0B` (locally-administered placeholders).
  Every other byte is identical, including the file size (76,787 bytes) and
  CRLF line endings. Fixture sha256
  `c3c8672181c9012719cfe3a18bb06fe425fef19a37a29748155e662257050f9f`.
- **Verify** the redaction yourself: `diff <original> tests/fixtures/home_lan_complete_2026-11-25.xml`
  shows exactly 22 changed lines (11 removed, 11 added), all of them MAC values.
- **Vendor attributes** in the file (`Google`, `Frontier Silicon`, `Magic
  Control Technology`) are nmap's own and do not correspond to the placeholder
  MACs. The parser takes the vendor from the XML; the MAC-prefix fallback is
  covered separately by `tests/test_vendor_registry.py`.
