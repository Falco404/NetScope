"""Tests for scripts/redact_mac_addresses.py — the fixture-redaction tool.

The tool must change MAC *values* and nothing else, deterministically, and it
must refuse to write a half-redacted file.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "redact_mac_addresses.py"

SAMPLE = (
    '<?xml version="1.0" encoding="UTF-8"?>\r\n'
    "<nmaprun>\r\n"
    '<host><address addr="192.168.0.5" addrtype="ipv4"/>\r\n'
    '<address addr="54:60:09:C1:CD:5C" addrtype="mac" vendor="Google"/></host>\r\n'
    '<host><address addr="192.168.0.6" addrtype="ipv4"/>\r\n'
    '<address addr="30:58:90:40:D3:7C" addrtype="mac"/></host>\r\n'
    "</nmaprun>\r\n"
)


def _run(tmp_path: Path, text: str) -> subprocess.CompletedProcess:
    src = tmp_path / "in.xml"
    src.write_bytes(text.encode("utf-8"))
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(src), str(tmp_path / "out.xml")],
        capture_output=True,
        text=True,
    )


def test_only_mac_values_change(tmp_path):
    proc = _run(tmp_path, SAMPLE)
    assert proc.returncode == 0, proc.stderr
    out = (tmp_path / "out.xml").read_bytes().decode("utf-8")

    assert "02:00:00:00:00:01" in out
    assert "02:00:00:00:00:02" in out
    assert 'vendor="Google"' in out  # vendor attribute untouched
    assert "54:60:09:C1:CD:5C" not in out
    assert "30:58:90:40:D3:7C" not in out
    assert "192.168.0.5" in out and "192.168.0.6" in out  # IPv4 untouched
    assert out.count("\r\n") == SAMPLE.count("\r\n")  # line endings preserved
    # Everything except the two addr values stays identical.
    assert out.replace("02:00:00:00:00:01", "X").replace("02:00:00:00:00:02", "X") == (
        SAMPLE.replace("54:60:09:C1:CD:5C", "X").replace("30:58:90:40:D3:7C", "X")
    )


def test_redaction_is_deterministic(tmp_path):
    first = _run(tmp_path, SAMPLE)
    assert first.returncode == 0
    out_first = (tmp_path / "out.xml").read_bytes()
    second = _run(tmp_path, SAMPLE)
    assert second.returncode == 0
    assert out_first == (tmp_path / "out.xml").read_bytes()


def test_refuses_mac_element_without_address(tmp_path):
    proc = _run(tmp_path, '<nmaprun><address addrtype="mac"/></nmaprun>')
    assert proc.returncode != 0
    assert "without a MAC addr attribute" in proc.stderr
    assert not (tmp_path / "out.xml").exists()
