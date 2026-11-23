"""Best-effort local subnet for the UI's default target.

This never scans and never sends a packet: a UDP socket's `connect()` only
records a peer address, so `getsockname()` reveals which local IP the OS would
use for the default route. The mask is assumed /24 — correct for a home LAN,
wrong for odd subnet masks, so the UI prefills it and lets you edit it.
"""

from __future__ import annotations

import socket
from ipaddress import IPv4Network

from netscope.target import IllegalTargetError, validate_target

# Any address reachable via the default route; UDP connect sends nothing.
_PROBE_PEER = ("8.8.8.8", 80)


def default_local_ip() -> str | None:
    """The IPv4 address this machine would use for outbound traffic, or None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(_PROBE_PEER)
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def local_subnet() -> str | None:
    """Local subnet as CIDR, only if it is a legal private target."""
    ip = default_local_ip()
    if ip is None:
        return None
    try:
        net = IPv4Network(f"{ip}/24", strict=False)
        validate_target(str(net))
    except (IllegalTargetError, ValueError):
        return None  # public address or odd shape -> don't guess a target
    return str(net)
