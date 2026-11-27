"""NetBIOS NBSTAT tests (#41 part 2) — no sockets to the network.

The packet layout here follows nmap's own client, `nselib/netbios.lua`
(`do_nbstat`), fetched from svn.nmap.org on 2026-11-25: 12-byte header, the
first-level encoded wildcard name, QTYPE 0x0021 / QCLASS 0x0001, then an answer
with TTL, RDLENGTH, a one-byte name count and 18-byte entries.

`nbstat_response()` builds answers in that layout so the parser is exercised
against every field; it is NOT a captured device packet — no NetBIOS-capable
device is reachable from this container. The real-device check is a scan on
Falco's LAN (see docs/STATUS.md).
"""

import socket
import struct

from netscope.netbios import (
    CLASS_IN,
    NBSTAT_QUERY_TYPE,
    TRANSACTION_ID,
    NetbiosNameResolver,
    build_nbstat_query,
    encode_name,
    parse_nbstat_response,
)


def nbstat_response(
    entries: list[tuple[bytes, int, int]],
    *,
    trn: int = TRANSACTION_ID,
    flags: int = 0x8400,
    ancount: int = 1,
) -> bytes:
    """Assemble a node-status answer in nmap's documented layout."""
    header = struct.pack(">HHHHHH", trn, flags, 0, ancount, 0, 0)
    body = bytearray()
    for raw_name, suffix, entry_flags in entries:
        body += raw_name.ljust(15)[:15] + bytes([suffix]) + struct.pack(">H", entry_flags)
    rdata = bytes([len(entries)]) + bytes(body) + b"\x00\x0c\x29\xc6\xda\xf5" + b"\x00" * 46
    answer = encode_name("*") + struct.pack(">HHIH", NBSTAT_QUERY_TYPE, CLASS_IN, 0, len(rdata))
    return header + answer + rdata


TYPICAL = [
    (b"WINDOWS2003", 0x00, 0x0400),  # unique workstation  <- the one we want
    (b"WINDOWS2003", 0x20, 0x0400),  # unique file server
    (b"SKULLSECURITY", 0x00, 0x8400),  # group (domain) name, same suffix
    (b"SKULLSECURITY", 0x1E, 0x8400),  # group browser election
    (b"\x01\x02__MSBROWSE__\x02", 0x01, 0x8400),
]


def test_encode_name_uses_the_first_level_encoding():
    # "*" is the NBSTAT wildcard and is padded with NULs, not spaces.
    assert encode_name("*") == b"\x20" + b"CK" + b"AA" * 15 + b"\x00"
    # Regular names are space-padded to 16 bytes before encoding.
    assert encode_name("foo") == b"\x20" + b"EGEPEP" + b"CA" * 13 + b"\x00"
    # Longer names are truncated to 16 bytes.
    assert encode_name("A" * 20) == encode_name("A" * 16)


def test_query_is_a_fifty_byte_nbstat_question():
    query = build_nbstat_query()
    assert len(query) == 50
    trn, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", query[:12])
    assert (trn, flags, qd, an, ns, ar) == (TRANSACTION_ID, 0, 1, 0, 0, 0)
    assert query[12:46] == encode_name("*")
    assert query[46:] == struct.pack(">HH", NBSTAT_QUERY_TYPE, CLASS_IN)


def test_parse_returns_the_unique_workstation_name():
    assert parse_nbstat_response(nbstat_response(TYPICAL)) == "WINDOWS2003"


def test_parse_ignores_group_names_with_the_workstation_suffix():
    """A domain name is also `<00>`; its group flag must disqualify it."""
    entries = [(b"WORKGROUP", 0x00, 0x8400), (b"DESKTOP-ABC123", 0x00, 0x0400)]
    assert parse_nbstat_response(nbstat_response(entries)) == "DESKTOP-ABC123"


def test_parse_returns_none_when_only_groups_and_other_suffixes_are_present():
    entries = [(b"WORKGROUP", 0x00, 0x8400), (b"DESKTOP-ABC123", 0x20, 0x0400)]
    assert parse_nbstat_response(nbstat_response(entries)) is None


def test_parse_rejects_foreign_or_malformed_answers():
    good = nbstat_response(TYPICAL)
    assert parse_nbstat_response(good, transaction_id=0x1338) is None  # other query
    assert parse_nbstat_response(nbstat_response(TYPICAL, flags=0x0400)) is None  # not a reply
    assert parse_nbstat_response(nbstat_response(TYPICAL, flags=0x8403)) is None  # error code
    assert parse_nbstat_response(nbstat_response(TYPICAL, ancount=2)) is None
    assert parse_nbstat_response(good[:20]) is None  # truncated mid-answer
    assert parse_nbstat_response(b"") is None


def test_parse_strips_padding_and_non_printable_bytes():
    """A hostile or broken device controls these bytes; only text survives."""
    entries = [(b"  BAD\x07BOX\x00  ", 0x00, 0x0400)]
    assert parse_nbstat_response(nbstat_response(entries)) == "BADBOX"


class FakeSock:
    def __init__(self, reply: bytes | None = None, error: Exception | None = None) -> None:
        self.reply = reply
        self.error = error
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        self.closed = False

    def settimeout(self, _seconds: float) -> None:
        pass

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        self.sent.append((data, addr))

    def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
        if self.error is not None:
            raise self.error
        assert self.reply is not None
        return self.reply, ("127.0.0.1", 137)

    def close(self) -> None:
        self.closed = True


def test_resolver_maps_answers_to_ips():
    reply = nbstat_response(TYPICAL)
    sock = FakeSock(reply=reply)
    resolver = NetbiosNameResolver(sock_factory=lambda *a, **k: sock)

    assert resolver.names_by_ip(["192.168.0.10"]) == {"192.168.0.10": "WINDOWS2003"}
    assert sock.sent[0][1] == ("192.168.0.10", 137)
    assert sock.sent[0][0] == build_nbstat_query()
    assert sock.closed is True


def test_resolver_ignores_timeouts_and_unreachable_hosts():
    sock = FakeSock(error=socket.timeout("timed out"))
    resolver = NetbiosNameResolver(sock_factory=lambda *a, **k: sock)
    assert resolver.names_by_ip(["192.168.0.11", "192.168.0.12"]) == {}


def test_resolver_queries_each_ip_once():
    socks: list[FakeSock] = []

    def factory(*_a, **_k):
        sock = FakeSock(reply=nbstat_response(TYPICAL))
        socks.append(sock)
        return sock

    resolver = NetbiosNameResolver(sock_factory=factory)
    names = resolver.names_by_ip(["192.168.0.10", "192.168.0.10", "192.168.0.11"])

    assert names == {"192.168.0.10": "WINDOWS2003", "192.168.0.11": "WINDOWS2003"}
    assert len(socks) == 2  # the duplicate address was collapsed


def test_resolver_with_no_hosts_opens_no_socket():
    def factory(*_a, **_k):
        raise AssertionError("must not create a socket without hosts")

    assert NetbiosNameResolver(sock_factory=factory).names_by_ip([]) == {}


# --- hostile replies must never raise (one device must not kill the scan) ---


def test_twelve_byte_reply_is_rejected_not_raised():
    """The exact bug from the security review: only `len(data) < 12` was
    checked, so the label-length byte read raised IndexError, the exception
    escaped `_query`, and `_netbios_names`' broad except turned it into "no
    names at all" for every host in the scan."""
    packet = b"\x13\x37\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"  # 12-byte header only
    assert parse_nbstat_response(packet) is None


def test_label_length_past_the_end_is_rejected():
    packet = struct.pack(">HHHHHH", TRANSACTION_ID, 0x8400, 0, 1, 0, 0) + b"\xc8"
    assert parse_nbstat_response(packet) is None


def test_parse_never_raises_on_any_truncation():
    """Every prefix of a valid answer, including one that ends exactly on the
    header — a property test, because the parser reads eight variable-length
    offsets and each one is a place to overrun."""
    full = nbstat_response(TYPICAL)
    for length in range(len(full) + 1):
        result = parse_nbstat_response(full[:length])
        assert result is None or isinstance(result, str), length


def test_one_hostile_host_does_not_lose_the_others_names():
    """The impact, not just the exception: a 12-byte reply from one device
    made `names_by_ip` return {} for the whole subnet."""
    replies = {
        "192.168.0.10": b"\x13\x37\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00",
        "192.168.0.11": nbstat_response(TYPICAL),
    }
    made: list[FakeSock] = []

    def factory(*_a, **_k):
        # The factory cannot know the destination, so route by call order is
        # unsafe; instead return a socket per address using the sendto address.
        sock = FakeSock()
        sock.recvfrom = lambda _size: (replies[sock.sent[-1][1][0]], ("", 137))
        made.append(sock)
        return sock

    names = NetbiosNameResolver(sock_factory=factory).names_by_ip(list(replies))
    assert names == {"192.168.0.11": "WINDOWS2003"}
