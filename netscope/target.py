"""TargetGuard: refuse any scan target outside RFC1918 private ranges.

Enforced in code (AGENTS.md), not via config: every scan entry point must
call validate_target() before touching the network.

Allowed IPv4 ranges:
  10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

Rejected: anything else — public IPs, loopback, link-local, multicast,
IPv6, hostnames, malformed input. The whole CIDR host range is checked,
not just the network address.

Also rejected: a target bigger than the address limit (default 4096 = a
/20, override with NETSCOPE_MAX_TARGET_ADDRESSES). Containment alone let a
single `POST /api/scan {"target": "10.0.0.0/8"}` ask nmap to sweep 16.7
million addresses and buffer its whole XML in memory — one unauthenticated
request with no sensible use, since 10/8 is mostly not the caller's LAN.
"""

from __future__ import annotations

import ipaddress
import os

_ALLOWED_RANGES: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

# A /20 is 4096 addresses: room for any home or small-office LAN with a
# subnet to spare. Bigger ranges are a deliberate config choice.
DEFAULT_MAX_TARGET_ADDRESSES = 4096
MAX_TARGET_ADDRESSES_ENV = "NETSCOPE_MAX_TARGET_ADDRESSES"


def parse_max_addresses(value: str) -> int:
    """NETSCOPE_MAX_TARGET_ADDRESSES: a positive whole number of addresses."""
    try:
        limit = int(value)
    except ValueError:
        raise ValueError(
            f"{MAX_TARGET_ADDRESSES_ENV} must be a whole number of addresses "
            f"(e.g. 4096), got {value!r}"
        ) from None
    if limit < 1:
        raise ValueError(f"{MAX_TARGET_ADDRESSES_ENV} must be at least 1, got {limit}")
    return limit


def max_target_addresses() -> int:
    """The current address limit: the env override, else the /20 default."""
    raw = os.environ.get(MAX_TARGET_ADDRESSES_ENV)
    if raw is None or not raw.strip():
        return DEFAULT_MAX_TARGET_ADDRESSES
    return parse_max_addresses(raw.strip())


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
            limit = max_target_addresses()
            if net.num_addresses > limit:
                raise IllegalTargetError(
                    f"target {target!r} covers {net.num_addresses} addresses; "
                    f"the limit is {limit} (a /20 is {DEFAULT_MAX_TARGET_ADDRESSES}). "
                    f"Scan a smaller range or raise {MAX_TARGET_ADDRESSES_ENV}."
                )
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
