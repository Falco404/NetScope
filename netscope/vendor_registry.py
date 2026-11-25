"""Tiny offline OUI registry — MAC prefix -> vendor, no runtime network calls.

nmap usually reports a vendor itself; this registry is the fallback for XML
that lacks a vendor attribute. Deliberately small (a few prefixes seen on
home/lab networks) — extend as needed, it is a data file, not logic.
"""

from __future__ import annotations

# First 3 octets of MAC -> vendor name.
# Every entry below was checked against the IEEE OUI registrations mirrored by
# uic.io on 2026-11-25 (nmap's own `nmap-mac-prefixes` file carries the same
# data — see issue #38 for loading that file at startup instead).
# The table previously shipped `AA:BB:CC -> MicroStar Intl`, a prefix that only
# exists in our recorded fixtures with a vendor name invented for it, plus three
# prefixes mapped to the wrong company (see docs/decisions.md).
OUI_VENDORS: dict[str, str] = {
    "00:0C:AC": "Citizen Watch Co., Ltd.",
    "A4:50:55": "BUSWARE.DE",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading Ltd",
    "E0:37:BF": "WNC Corporation",
}


def vendor_from_mac(mac: str) -> str | None:
    """Look up the vendor from the OUI prefix (first 3 octets)."""
    normalized = mac.upper().replace("-", ":")
    prefix = ":".join(normalized.split(":")[:3])
    return OUI_VENDORS.get(prefix)
