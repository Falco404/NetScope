"""#38: load nmap's own `nmap-mac-prefixes` data file at startup.

The fixture is a byte-exact slice of the real file (provenance recorded in its
header), never a hand-typed stand-in — see tests/fixtures/nmap-mac-prefixes-sample.txt.
"""

from pathlib import Path

import pytest

from netscope import vendor_registry
from netscope.vendor_registry import (
    MAC_PREFIXES,
    OUI_VENDORS,
    find_mac_prefixes_file,
    load_default_mac_prefixes,
    load_mac_prefixes,
    vendor_from_mac,
)

FIXTURE = Path(__file__).parent / "fixtures" / "nmap-mac-prefixes-sample.txt"


@pytest.fixture
def clean_registry():
    """The loaded table is process-wide. Start every test from the built-in
    seed and leave the table as it was found: a startup test that runs
    `main()` on a machine where nmap IS installed loads 52k real registrations
    into this dict, and they used to leak into the tests below (that is what
    broke `test_comment_lines_are_not_entries` on a Windows box with nmap
    installed — `525400 QEMU virtual NIC` is a genuine entry in nmap's file).
    """
    original = dict(vendor_registry.MAC_PREFIXES)
    original_lengths = vendor_registry._PREFIX_LENGTHS
    vendor_registry.MAC_PREFIXES.clear()
    vendor_registry.MAC_PREFIXES.update(
        {p.replace(":", ""): n for p, n in vendor_registry.OUI_VENDORS.items()}
    )
    yield
    vendor_registry.MAC_PREFIXES.clear()
    vendor_registry.MAC_PREFIXES.update(original)
    vendor_registry._PREFIX_LENGTHS = original_lengths


def test_builtin_table_works_without_nmap():
    """Guard: with no nmap installed the built-in fallback still labels devices
    (this is what the container and CI rely on)."""
    assert vendor_from_mac("B8:27:EB:11:22:33") == "Raspberry Pi Foundation"


def test_load_mac_prefixes_reads_nmaps_file(clean_registry):
    assert load_mac_prefixes(FIXTURE) == 8  # the fixture's 8 entry lines
    assert vendor_from_mac("B8:27:EB:11:22:33") == "Raspberry Pi Foundation"
    assert vendor_from_mac("A4:50:55:11:22:33") == "BUSWARE.DE"


def test_comment_lines_are_not_entries(clean_registry):
    """The file's header includes `# Nmap additions to this file:` followed by
    `# 525400, B0C420, DEADCA, 00FFD1, 080027,`. Those are comments, not
    registrations: parsing them would invent vendors for those prefixes."""
    load_mac_prefixes(FIXTURE)
    assert "525400" not in MAC_PREFIXES
    assert vendor_from_mac("52:54:00:11:22:33") is None


def test_loading_a_file_replaces_the_registry(clean_registry, tmp_path):
    """A load must mean "this file is the registry", not "add to it". Pointing
    `NMAPDIR` at a different nmap install used to leave the previous file's
    vendors answering forever, so a device could be labelled by a registry
    that is no longer in effect."""
    load_mac_prefixes(FIXTURE)
    assert vendor_from_mac("B8:27:EB:11:22:33") == "Raspberry Pi Foundation"

    other = tmp_path / "nmap-mac-prefixes"
    other.write_text("525400 QEMU virtual NIC\n", encoding="utf-8")
    assert load_mac_prefixes(other) == 1
    assert vendor_from_mac("52:54:00:11:22:33") == "QEMU virtual NIC"
    assert vendor_from_mac("B8:27:EB:11:22:33") is None
    assert "A45055" not in MAC_PREFIXES


def test_longest_prefix_wins_over_three_octets(clean_registry):
    """nmap's file is not all 3-byte prefixes: 38,930 keys are 6 hex digits,
    6,262 are 7 (MA-M) and 6,893 are 9 (MA-L), and 411 of the 6-digit keys are
    also the first 6 digits of a longer key. Matching only the first 3 octets
    therefore reports the wrong vendor for those MACs: `00:1B:C5:...` is
    registered as `001BC5 Ieee Registration Authority`, but `001BC5000` is
    `Converging Systems` and must win for `00:1B:C5:00:00:11`."""
    load_mac_prefixes(FIXTURE)
    assert vendor_from_mac("00:1B:C5:AA:BB:CC") == "Ieee Registration Authority"
    assert vendor_from_mac("00:1B:C5:00:00:11") == "Converging Systems"


def test_28bit_prefix_matches(clean_registry):
    """A 7-digit (MA-M) registration must match too."""
    load_mac_prefixes(FIXTURE)
    assert vendor_from_mac("00:55:DA:01:22:33") == "Shinko Technos"


def test_find_mac_prefixes_file_uses_nmaps_search_order(clean_registry, tmp_path, monkeypatch):
    """nmap looks in $NMAPDIR first, then the directory holding the nmap
    executable; we follow the same order so the labels match what nmap prints."""
    monkeypatch.delenv("NMAPDIR", raising=False)
    monkeypatch.setattr(vendor_registry.shutil, "which", lambda name: None)
    assert find_mac_prefixes_file() is None

    found = tmp_path / "nmap-mac-prefixes"
    found.write_text("B827EB Raspberry Pi Foundation\n", encoding="utf-8")
    monkeypatch.setattr(vendor_registry.shutil, "which", lambda name: str(tmp_path / "nmap.exe"))
    assert find_mac_prefixes_file() == found

    other = tmp_path / "other"
    other.mkdir()
    (other / "nmap-mac-prefixes").write_text("A45055 BUSWARE.DE\n", encoding="utf-8")
    monkeypatch.setenv("NMAPDIR", str(other))
    assert find_mac_prefixes_file() == other / "nmap-mac-prefixes"


def test_load_default_mac_prefixes_reports_source(clean_registry, tmp_path, monkeypatch):
    """Startup tells the user which registry is in effect."""
    monkeypatch.delenv("NMAPDIR", raising=False)
    monkeypatch.setattr(vendor_registry.shutil, "which", lambda name: None)
    assert load_default_mac_prefixes() == (None, 0)

    monkeypatch.setenv("NMAPDIR", str(tmp_path))
    (tmp_path / "nmap-mac-prefixes").write_bytes(FIXTURE.read_bytes())
    path, count = load_default_mac_prefixes()
    assert path == tmp_path / "nmap-mac-prefixes"
    assert count == 8


def test_builtin_names_match_nmaps_strings(clean_registry):
    """The fallback table must use the same vendor strings as nmap's file, or
    the same device changes name depending on whether nmap is installed."""
    load_mac_prefixes(FIXTURE)
    for prefix, name in OUI_VENDORS.items():
        hex_key = prefix.replace(":", "")
        assert MAC_PREFIXES[hex_key] == name, f"{prefix}: {name!r}"
