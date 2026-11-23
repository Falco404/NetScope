"""SubprocessNmapRunner error messages — no nmap needed to test them."""

import sys

import pytest

from netscope.scanner.runner import NMAP_TIMEOUT_SECONDS, SubprocessNmapRunner


def test_missing_binary_is_actionable(tmp_path):
    runner = SubprocessNmapRunner(binary="definitely-not-installed-nmap-xyz")
    with pytest.raises(RuntimeError) as exc:
        runner.run(["-sn", "-oX", "-", "192.168.1.0/24"])
    assert "not found" in str(exc.value)
    assert "install it" in str(exc.value)


def test_default_timeout_is_the_module_constant():
    assert SubprocessNmapRunner().timeout == NMAP_TIMEOUT_SECONDS


def test_nonzero_exit_reports_code():
    # Portable non-zero exit: Python itself, so this works on Windows too
    # (`false` is not a Windows binary and would hit the "not found" path).
    runner = SubprocessNmapRunner(binary=sys.executable)
    with pytest.raises(RuntimeError) as exc:
        runner.run(["-c", "raise SystemExit(3)"])
    assert "exit 3" in str(exc.value)
