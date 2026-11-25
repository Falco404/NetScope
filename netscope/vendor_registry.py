"""MAC prefix -> vendor: nmap's own data file when it is available, a small
built-in table otherwise. No runtime network calls.

nmap usually reports a vendor itself; this registry is the fallback for XML
that lacks a vendor attribute. Loading nmap's `nmap-mac-prefixes` file (#38)
replaces a hand-typed table that was mostly wrong: 411 of its 6-digit keys are
also the first 6 digits of a longer registration, so a fixed 3-octet lookup
mislabels those devices.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

# Built-in fallback for when nmap's data file is not on disk (nmap is optional:
# a container, CI or a pip-only install has no data directory). The vendor
# strings are nmap's own, so a device does not change name depending on which
# table answered. Every entry was checked against nmap's `nmap-mac-prefixes`
# (nmap master, sha256 ae8b132bb3471ea94055e111137f76e041f4a8f5df9799ac184cc1fbf23d508d)
# on 2026-11-25; the table previously shipped `AA:BB:CC -> MicroStar Intl`, a
# prefix that exists only in our recorded fixtures, plus three prefixes mapped
# to the wrong company (see docs/decisions.md).
OUI_VENDORS: dict[str, str] = {
    "00:0C:AC": "Citizen Watch",
    "A4:50:55": "BUSWARE.DE",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E0:37:BF": "WNC",
}

MAC_PREFIXES_FILENAME = "nmap-mac-prefixes"

# Every known prefix in hex-digit form (no colons) -> vendor, seeded from
# OUI_VENDORS and extended by load_mac_prefixes(). Keys are 6, 7 or 9 hex
# digits: nmap's file carries MA-S (24-bit), MA-M (28-bit) and MA-L (36-bit)
# registrations, so a lookup must try the longest prefix first.
MAC_PREFIXES: dict[str, str] = {
    prefix.replace(":", ""): name for prefix, name in OUI_VENDORS.items()
}

# Prefix lengths present in MAC_PREFIXES, longest first; recomputed on load.
_PREFIX_LENGTHS: tuple[int, ...] = tuple(sorted({len(k) for k in MAC_PREFIXES}, reverse=True))

_HEX_DIGITS = frozenset("0123456789ABCDEF")


def _normalize_hex(mac: str) -> str:
    """`b8-27:eb` -> `B827EB`: nmap writes MACs colon-separated, its data file
    keys are plain hex digits."""
    return "".join(char for char in mac.upper() if char in _HEX_DIGITS)


def load_mac_prefixes(path: Path) -> int:
    """Parse nmap's `nmap-mac-prefixes` file into MAC_PREFIXES.

    One registration per line: `<hex-prefix> <vendor name>`; `#` lines are
    comments (the header includes `# 525400, B0C420, DEADCA, ...` under
    "Nmap additions to this file", which are NOT registrations). Returns the
    number of entries loaded.
    """
    global _PREFIX_LENGTHS
    loaded: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, vendor = line.partition(" ")
        key = key.strip().upper()
        vendor = vendor.strip()
        if not vendor or not key or not set(key) <= _HEX_DIGITS:
            continue
        loaded[key] = vendor
    # Replace rather than merge: the file we just read *is* the registry, so
    # vendors from a previously loaded file must not keep answering. Swapping
    # only after the whole file parsed also keeps a file we fail to read
    # halfway from leaving a half-loaded table behind.
    MAC_PREFIXES.clear()
    MAC_PREFIXES.update(loaded)
    _PREFIX_LENGTHS = tuple(sorted({len(k) for k in MAC_PREFIXES}, reverse=True))
    return len(loaded)


def find_mac_prefixes_file() -> Path | None:
    """Locate nmap's data file, following nmap's own search order: `$NMAPDIR`
    first, then the directory containing the nmap executable (on Windows that
    is `C:\\Program Files (x86)\\Nmap`). nmap also honours `--datadir`, which
    we do not control, and a compiled-in default we cannot read.
    """
    candidates: list[Path] = []
    datadir = os.environ.get("NMAPDIR")
    if datadir:
        candidates.append(Path(datadir) / MAC_PREFIXES_FILENAME)
    exe = shutil.which("nmap")
    if exe:
        candidates.append(Path(exe).parent / MAC_PREFIXES_FILENAME)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def load_default_mac_prefixes() -> tuple[Path | None, int]:
    """Find nmap's file and load it. Returns `(path, entries)`; `(None, 0)`
    when nmap is not installed, which is when the built-in table is in effect."""
    path = find_mac_prefixes_file()
    if path is None:
        return None, 0
    return path, load_mac_prefixes(path)


def vendor_from_mac(mac: str) -> str | None:
    """Vendor for a MAC address, longest registered prefix first.

    Matching on the first 3 octets only would answer `Ieee Registration
    Authority` for `00:1B:C5:00:00:11`, where the 9-digit registration
    `001BC5000 Converging Systems` is the correct one.
    """
    hex_digits = _normalize_hex(mac)
    for length in _PREFIX_LENGTHS:
        if len(hex_digits) >= length:
            vendor = MAC_PREFIXES.get(hex_digits[:length])
            if vendor:
                return vendor
    return None
