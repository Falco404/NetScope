"""TargetGuard tests — pure logic, no network (AGENTS.md rule)."""

import ipaddress

import pytest

from netscope.target import (
    MAX_TARGET_ADDRESSES_ENV,
    IllegalTargetError,
    is_allowed,
    parse_max_addresses,
    validate_target,
)


@pytest.fixture(autouse=True)
def _shipped_defaults(monkeypatch):
    """Run with the shipped limit whatever the developer's shell exports."""
    monkeypatch.delenv(MAX_TARGET_ADDRESSES_ENV, raising=False)


@pytest.mark.parametrize("target", [
    "10.0.0.1",
    "10.255.255.255",
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
    "10.0.0.0/20",        # wholly inside 10/8
    "172.16.0.0/21",      # wholly inside 172.16/12
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


# --- scan-size cap (one request must not sweep a /8) -----------------------


def test_target_exactly_at_the_limit_passes():
    # Default limit is 4096 addresses: a /20 is exactly that.
    assert validate_target("192.168.0.0/20").num_addresses == 4096


def test_target_one_bit_larger_is_refused():
    with pytest.raises(IllegalTargetError) as exc:
        validate_target("192.168.0.0/19")  # 8192 addresses
    message = str(exc.value)
    assert "8192" in message
    assert MAX_TARGET_ADDRESSES_ENV in message, "the error must name the override"


def test_10_slash_8_is_refused_by_default():
    """The exact request from the security review: 16.7M addresses in one call."""
    with pytest.raises(IllegalTargetError) as exc:
        validate_target("10.0.0.0/8")
    assert "16777216" in str(exc.value)


def test_env_override_raises_the_limit(monkeypatch):
    monkeypatch.setenv(MAX_TARGET_ADDRESSES_ENV, "8192")
    validate_target("192.168.0.0/19")


def test_env_override_can_lower_the_limit(monkeypatch):
    monkeypatch.setenv(MAX_TARGET_ADDRESSES_ENV, "256")
    validate_target("192.168.0.0/24")
    with pytest.raises(IllegalTargetError):
        validate_target("192.168.0.0/23")  # 512 addresses


def test_parse_max_addresses_rejects_garbage():
    for bad in ("abc", "0", "-5", "4.5", ""):
        with pytest.raises(ValueError) as exc:
            parse_max_addresses(bad)
        assert MAX_TARGET_ADDRESSES_ENV in str(exc.value), bad
