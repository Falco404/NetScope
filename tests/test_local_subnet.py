"""Local-subnet detection tests — socket behaviour patched, zero network."""

import netscope.local_subnet as ls


def patch_ip(monkeypatch, ip):
    monkeypatch.setattr(ls, "default_local_ip", lambda: ip)


def test_private_ip_becomes_a_24_cidr(monkeypatch):
    patch_ip(monkeypatch, "192.168.0.14")
    assert ls.local_subnet() == "192.168.0.0/24"


def test_10_and_172_ranges_are_accepted(monkeypatch):
    patch_ip(monkeypatch, "10.0.1.7")
    assert ls.local_subnet() == "10.0.1.0/24"
    patch_ip(monkeypatch, "172.18.0.2")  # e.g. a Docker bridge, not a home LAN
    assert ls.local_subnet() == "172.18.0.0/24"


def test_public_ip_returns_none(monkeypatch):
    patch_ip(monkeypatch, "8.8.4.4")
    assert ls.local_subnet() is None


def test_no_local_ip_returns_none(monkeypatch):
    patch_ip(monkeypatch, None)
    assert ls.local_subnet() is None


def test_detected_subnet_always_passes_the_guard(monkeypatch):
    from netscope.target import validate_target

    for ip in ("192.168.0.14", "10.0.1.7", "172.18.0.2", "8.8.4.4", None):
        patch_ip(monkeypatch, ip)
        subnet = ls.local_subnet()
        if subnet is not None:
            validate_target(subnet)  # never raises -> UI can always submit it
