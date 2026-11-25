#!/usr/bin/env python3
"""Rewrite the MAC addresses in a captured nmap XML file.

Why this exists: fixtures must come from real tool output (AGENTS.md), but a
home-LAN capture carries the owner's MAC addresses. This script performs the
smallest possible, reproducible edit: it replaces the ``addr`` value of every
``<address ... addrtype="mac" ...>`` element with a deterministic
``02:00:00:00:00:NN`` placeholder (locally-administered unicast, one per
distinct MAC, in encounter order). Every other byte — IPs, vendor attributes,
hostnames, ports, OS matches — is left untouched, so a reviewer can diff the
output against the capture and see only MAC values changed.

The script refuses to write a partially redacted file: it counts the MAC
elements, verifies each one was rewritten to a placeholder, and fails loudly
otherwise.

Usage:
    python scripts/redact_mac_addresses.py capture.xml fixtures/redacted.xml
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

MAC_TAG = re.compile(r'<address\b[^>]*?addrtype="mac"[^>]*>')
ADDR_ATTR = re.compile(
    r'addr="(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"'
)
PLACEHOLDER = re.compile(r"02:00:00:00:00:[0-9A-F]{2}")


def redact(text: str) -> tuple[str, dict[str, str], int]:
    """Return (redacted text, original->placeholder map, MAC elements seen)."""

    mapping: dict[str, str] = {}
    seen = 0

    def rewrite_tag(tag: str) -> str:
        nonlocal seen
        match = ADDR_ATTR.search(tag)
        if match is None:
            raise SystemExit(f"MAC element without a MAC addr attribute: {tag!r}")
        original = match.group(0)[len('addr="') : -1]
        mapping.setdefault(original, f"02:00:00:00:00:{len(mapping) + 1:02X}")
        seen += 1
        return tag.replace(match.group(0), f'addr="{mapping[original]}"')

    redacted = MAC_TAG.sub(lambda m: rewrite_tag(m.group(0)), text)
    return redacted, mapping, seen


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replace MAC values in a captured nmap XML file with placeholders."
    )
    parser.add_argument("input", type=Path, help="captured nmap XML file")
    parser.add_argument("output", type=Path, help="where to write the redacted copy")
    args = parser.parse_args(argv)

    raw = args.input.read_bytes()
    text = raw.decode("utf-8")
    redacted, mapping, seen = redact(text)

    if seen != len(MAC_TAG.findall(text)):
        raise SystemExit("internal error: MAC element count changed during redaction")
    for tag in MAC_TAG.findall(redacted):
        match = ADDR_ATTR.search(tag)
        value = match.group(0)[len('addr="') : -1] if match else ""
        if not PLACEHOLDER.fullmatch(value):
            raise SystemExit(f"refusing to write a partially redacted file: {tag!r}")

    out = redacted.encode("utf-8")
    args.output.write_bytes(out)
    print(f"MAC elements rewritten: {seen} (distinct: {len(mapping)})")
    for original, placeholder in mapping.items():
        print(f"  {original} -> {placeholder}")
    print(f"input  sha256: {hashlib.sha256(raw).hexdigest()}")
    print(f"output sha256: {hashlib.sha256(out).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
