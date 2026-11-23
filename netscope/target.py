"""TargetGuard: refuse any scan target outside RFC1918 private ranges.

Enforced in code (AGENTS.md), not via config: every scan entry point must
call validate_target() before touching the network.

Allowed IPv4 ranges:
  10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

Rejected: anything else — public IPs, loopback, link-local, multicast,
IPv6, hostnames, malformed input. The whole CIDR host range is checked,
not just the network address.
"""

from __future__ import annotations

import ipaddress

_ALLOWED_RANGES: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


class IllegalTargetError(ValueError):
    """Raised for any target outside the allowed private ranges."""


def validate_target(target: str) -> ipaddress.IPv4Network:
    """Parse a single IPv4 or CIDR target and return its network.

    Raises IllegalTargetError for anything outside 10/8, 172.16/12,
    192.168/16, including malformed input and IPv6.
    """
    if not isinstance(target, str) or not target.strip():
        raise IllegalTargetError("target must be a non-empty string")

    try:
        net = ipaddress.IPv4Network(target, strict=False)
    except ValueError as exc:
        # IPv4Network raises ValueError for IPv6 input and for garbage.
        raise IllegalTargetError(f"invalid target {target!r}: {exc}") from exc

    # Check BOTH ends of the host range: a CIDR that spills outside an
    # allowed range must be rejected even if its network address looks fine.
    first, last = net.network_address, net.broadcast_address
    for allowed in _ALLOWED_RANGES:
        if first in allowed and last in allowed:
            return net

    raise IllegalTargetError(
        f"target {target!r} is outside private ranges "
        "(allowed: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)"
    )


def is_allowed(target: str) -> bool:
    try:
        validate_target(target)
        return True
    except IllegalTargetError:
        return False
