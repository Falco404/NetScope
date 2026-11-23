"""TargetGuard tests — pure logic, no network (AGENTS.md rule)."""

import ipaddress

import pytest

from netscope.target import IllegalTargetError, is_allowed, validate_target


@pytest.mark.parametrize("target", [
    "10.0.0.1",
    "10.255.255.255",
    "10.0.0.0/8",
    "10.5.6.0/24",
    "172.16.0.1",
    "172.31.255.255",
    "172.20.5.0/24",
    "192.168.0.1",
    "192.168.1.0/24",
    "192.168.1.5/32",
])
def test_allowed_targets_pass(target):
    net = validate_target(target)
    assert isinstance(net, ipaddress.IPv4Network)


@pytest.mark.parametrize("target", [
    "8.8.8.8",            # public
    "172.15.0.1",         # just below 172.16/12
    "172.32.0.1",         # just above 172.16/12
    "11.0.0.1",           # just above 10/8
    "9.255.255.255",      # just below 10/8
    "192.169.1.1",        # just outside 192.168/16
    "193.168.1.1",        # prefix lookalike
    "127.0.0.1",          # loopback
    "169.254.1.1",        # link-local
    "224.0.0.1",          # multicast
    "255.255.255.255",
    "fe80::1",            # IPv6 link-local
    "2001:db8::/32",      # IPv6 CIDR
    "not-an-ip",          # hostname / garbage
    "",
    "   ",
    "192.168.1.999",
    "10.0.0.0/33",        # impossible prefix
])
def test_refused_targets_raise(target):
    with pytest.raises(IllegalTargetError):
        validate_target(target)


@pytest.mark.parametrize("target", [
    "10.0.0.0/12",        # wholly inside 10/8
    "172.16.0.0/16",      # wholly inside 172.16/12
])
def test_cidr_fully_inside_allowed_range_passes(target):
    validate_target(target)


@pytest.mark.parametrize("target", [
    "172.15.0.0/16",      # starts outside an allowed range
    "172.31.0.0/11",      # network address inside, range spills to 172.32+
    "10.0.0.0/7",         # spills into 8.x
    "192.168.0.0/15",     # spills into 192.169+
])
def test_cidr_spilling_outside_is_refused(target):
    # The whole host range must be checked, not just the network address.
    with pytest.raises(IllegalTargetError):
        validate_target(target)


def test_is_allowed_predicate():
    assert is_allowed("192.168.1.0/24")
    assert not is_allowed("8.8.8.8")


def test_non_string_target_refused():
    # Deliberately runtime-typed: the isinstance() guard protects callers
    # that pass garbage despite the str annotation.
    for bad in (None, 8, b"10.0.0.1", ["10.0.0.1"]):
        with pytest.raises(IllegalTargetError):
            validate_target(bad)  # pyright: ignore[reportArgumentType]
