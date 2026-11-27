"""NetBIOS (NBNS) name suggestions (#41 part 2).

Windows machines that still speak NetBIOS over TCP/IP answer a **node status
query** (NBSTAT) on UDP 137 with a table of the names they own — the useful one
is the unique workstation name (``<00>``), e.g. ``DESKTOP-ABC123``. Linux hosts
without Samba do not answer at all, and modern Windows may have NBT disabled,
so this is a *best-effort* extra source after PTR and mDNS.

Wire format (RFC 1002 / RFC 1001): the layout implemented here is the one nmap's
own client uses — ``nselib/netbios.lua``, function ``do_nbstat`` (fetched from
svn.nmap.org on 2026-11-25). The query is a 12-byte header (transaction id
0x1337, no flags, one question), the first-level encoded wildcard name ``*``
padded with NULs, then QTYPE 0x0021 (NBSTAT) and QCLASS 0x0001 (IN). The answer
repeats the name/type/class, then TTL, RDLENGTH, a one-byte number of names and
one 18-byte entry per name (15-byte padded name, 1-byte suffix, 2-byte flags),
followed by the MAC address and 46 bytes of statistics.

Nothing here raises: a scan must never fail because NetBIOS is blocked or a
device answers nonsense — every failure means "no name".
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import Any

NETBIOS_PORT = 137
NBSTAT_QUERY_TYPE = 0x0021
CLASS_IN = 0x0001
TRANSACTION_ID = 0x1337  # same constant nmap's do_nbstat uses
DEFAULT_TIMEOUT = 1.0
MAX_WORKERS = 32
WORKSTATION_SUFFIX = 0x00
GROUP_FLAG = 0x8000  # set on group names (e.g. WORKGROUP<00>)
MAX_RESPONSE = 2048


def encode_name(name: str) -> bytes:
    """First-level encoding of a 16-byte NetBIOS name (nmap's ``name_encode``).

    ``*`` (the NBSTAT wildcard) is padded with NULs, every other name with
    spaces; each byte becomes two letters ``A``-``P``. The result is the
    length-prefixed encoded label plus the root terminator.
    """
    if len(name) >= 16:
        padded = name[:16]
    else:
        padding = "\0" if name == "*" else " "
        padded = name + padding * (16 - len(name))
    encoded = bytearray()
    for byte in padded.upper().encode("latin-1"):
        encoded.append(0x41 + (byte >> 4))
        encoded.append(0x41 + (byte & 0x0F))
    return bytes([len(encoded)]) + bytes(encoded) + b"\x00"


def build_nbstat_query(transaction_id: int = TRANSACTION_ID) -> bytes:
    """50-byte NBSTAT query: header + encoded ``*`` + type + class."""
    header = struct.pack(">HHHHHH", transaction_id, 0, 1, 0, 0, 0)
    return header + encode_name("*") + struct.pack(">HH", NBSTAT_QUERY_TYPE, CLASS_IN)


def parse_nbstat_response(data: bytes, transaction_id: int = TRANSACTION_ID) -> str | None:
    """Extract the unique workstation name from a node-status answer.

    Returns ``None`` for anything that is not a clean answer: wrong transaction
    id, not a response, a NetBIOS error code, a truncated packet, or a table
    whose only ``<00>`` entry is a group name.
    """
    if len(data) < 12:
        return None
    trn, flags, _qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", data[:12])
    if trn != transaction_id or ancount != 1:
        return None
    if not flags & 0x8000 or flags & 0x0007:  # must be a response, no error code
        return None

    pos = 12
    # The header is only 12 bytes; the label length is the 13th. Checking
    # `len(data) < 12` above let a 12-byte reply through and data[12] raised
    # IndexError, which escaped `_query` and silently disabled NetBIOS naming
    # for the whole scan (one hostile device is enough). Every later field is
    # bounds-checked, so this one byte-length guard makes the parser total.
    if len(data) < 13:
        return None
    label_len = data[pos]
    pos += 1 + label_len + 1  # encoded label + root terminator
    if pos + 10 > len(data):
        return None
    rtype, rclass, _ttl, _rdlength = struct.unpack(">HHIH", data[pos : pos + 10])
    pos += 10
    if rtype != NBSTAT_QUERY_TYPE or rclass != CLASS_IN or pos >= len(data):
        return None

    count = data[pos]
    pos += 1
    for _ in range(count):
        if pos + 18 > len(data):
            return None
        raw, suffix = data[pos : pos + 15], data[pos + 15]
        entry_flags = struct.unpack(">H", data[pos + 16 : pos + 18])[0]
        pos += 18
        if suffix != WORKSTATION_SUFFIX or entry_flags & GROUP_FLAG:
            continue
        name = "".join(ch for ch in raw.decode("latin-1") if ch.isprintable()).strip()
        if name:
            return name
    return None


class NetbiosNameResolver:
    """Ask each host for its NetBIOS workstation name (UDP 137, best-effort).

    ``sock_factory`` exists for tests; production uses ``socket.socket``.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        workers: int = MAX_WORKERS,
        sock_factory: Callable[..., Any] = socket.socket,
    ) -> None:
        self.timeout = timeout
        self.workers = workers
        self._sock_factory = sock_factory

    def names_by_ip(self, ips: Iterable[str]) -> Mapping[str, str]:
        hosts = list(dict.fromkeys(ips))  # dedupe, keep order
        if not hosts:
            return {}
        with ThreadPoolExecutor(max_workers=min(self.workers, len(hosts))) as pool:
            answers = list(pool.map(self._query, hosts))
        return {ip: name for ip, name in zip(hosts, answers, strict=True) if name}

    def _query(self, ip: str) -> str | None:
        try:
            sock = self._sock_factory(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(self.timeout)
                sock.sendto(build_nbstat_query(), (ip, NETBIOS_PORT))
                data, _ = sock.recvfrom(MAX_RESPONSE)
            finally:
                sock.close()
        except OSError:  # timeout, refused, unreachable, no route…
            return None
        return parse_nbstat_response(data)
