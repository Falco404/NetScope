"""#43: export the current inventory as JSON or CSV.

The data is built by the API layer (`_inventory_records` in `netscope/api/app.py`)
from the same store reads the Devices table uses, so an export can never show a
device, a status or a port the UI does not. This module only renders: it takes
plain records and turns them into bytes. No dependency beyond the standard
library, no schema change, nothing written back.

Two formats, two audiences:

* **JSON** is the lossless one — nested ports with the service/version nmap
  found, stable keys, a `generated_at` stamp and a device count, so a script
  (or a future import) can rely on it.
* **CSV** is the spreadsheet view: one row per device, ports flattened into one
  cell. It is deliberately *not* lossless — that is what the JSON is for.

Two rules that are not cosmetic:

1. **Missing data is never exported as a negative fact** (#39). A quick scan
   stores no port rows, so a blank Open ports cell would read as "nothing is
   open". The `ports_probed` column says `false` and the cell says `not probed`.
2. **CSV cells are neutralised against formula injection.** Hostnames, vendor
   strings and OS guesses come off the LAN unauthenticated; a hostname like
   `=cmd|'/c calc'!A0` is inert text in JSON but executes when the CSV is opened
   in Excel/LibreOffice. Same class of bug as the stored XSS of #32, same
   answer: treat scan-derived strings as hostile.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import Any

# One column per device, in the order a human reads it.
CSV_COLUMNS = (
    "identity",
    "mac",
    "ip",
    "name",
    "hostname",
    "vendor",
    "os_guess",
    "status",
    "ports_probed",
    "last_seen_scan",
    "open_ports",
)

# Excel (and LibreOffice) evaluate a cell that starts with one of these as a
# formula even when it is quoted. Prefixing a single quote forces it to text;
# leading whitespace does not save us, Excel trims it, so test the stripped value.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: object) -> str:
    """Render one value as a CSV cell, never as a formula."""
    if value is None:
        return ""
    text = str(value)
    if text.lstrip().startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def ports_cell(record: dict[str, Any]) -> str:
    """Flatten a record's ports for the spreadsheet view.

    `not probed` and `none open` are different facts and stay different (#39):
    a quick scan never asked nmap, a deep scan found nothing listening.
    """
    if not record["ports_probed"]:
        return "not probed"
    parts = []
    for port in record["ports"]:
        bits = [f"{port['port']}/{port['protocol']}"]
        if port["service"]:
            bits.append(port["service"])
        if port["version"]:
            bits.append(port["version"])
        parts.append(" ".join(bits))
    return "; ".join(parts) if parts else "none open"


def to_csv(records: Sequence[dict[str, Any]]) -> bytes:
    """Header row + one row per device, UTF-8 **with BOM**.

    The BOM is for Windows Excel: without it, UTF-8 vendor names lose their
    accents. csv.writer quotes separators/newlines itself; `csv_cell` handles
    the formula case that quoting does not cover.
    """
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)
    for record in records:
        writer.writerow(
            [
                csv_cell(record["identity"]),
                csv_cell(record["mac"]),
                csv_cell(record["ip"]),
                csv_cell(record["name"]),
                csv_cell(record["hostname"]),
                csv_cell(record["vendor"]),
                csv_cell(record["os_guess"]),
                csv_cell(record["status"]),
                "true" if record["ports_probed"] else "false",
                csv_cell(record["last_seen_scan"]),
                csv_cell(ports_cell(record)),
            ]
        )
    return buffer.getvalue().encode("utf-8-sig")


def to_json(
    records: Iterable[dict[str, Any]], generated_at: datetime | None = None
) -> bytes:
    """The lossless form: a stamp, a count and the full nested records."""
    records = list(records)
    payload = {
        "generated_at": _iso_utc(generated_at),
        "device_count": len(records),
        "devices": records,
    }
    return (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def filename(fmt: str, generated_at: datetime | None = None) -> str:
    """`netscope-inventory-20261126-143205.csv` — sortable, no colons (Windows)."""
    stamp = _utc_now(generated_at).strftime("%Y%m%d-%H%M%S")
    return f"netscope-inventory-{stamp}.{fmt}"


def _utc_now(moment: datetime | None) -> datetime:
    if moment is None:
        return datetime.now(timezone.utc)
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _iso_utc(moment: datetime | None) -> str:
    return _utc_now(moment).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
