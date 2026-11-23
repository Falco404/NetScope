"""Tiny offline OUI registry — MAC prefix -> vendor, no runtime network calls.

nmap usually reports a vendor itself; this registry is the fallback for XML
that lacks a vendor attribute. Deliberately small (a few prefixes seen on
home/lab networks) — extend as needed, it is a data file, not logic.
"""

from __future__ import annotations

# First 3 octets of MAC -> vendor name.
OUI_VENDORS: dict[str, str] = {
    "AA:BB:CC": "MicroStar Intl",  # used by the lab fixture MACs
    "00:0C:AC": "Dell",
    "3C:07:59": "Intel",
    "A4:50:55": "Apple",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E0:37:BF": "Microsoft",
}


def vendor_from_mac(mac: str) -> str | None:
    """Look up the vendor from the OUI prefix (first 3 octets)."""
    normalized = mac.upper().replace("-", ":")
    prefix = ":".join(normalized.split(":")[:3])
    return OUI_VENDORS.get(prefix)
