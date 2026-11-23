"""SubprocessNmapRunner error messages — no nmap needed to test them."""

import pytest

from netscope.scanner.runner import SubprocessNmapRunner


def test_missing_binary_is_actionable(tmp_path):
    runner = SubprocessNmapRunner(binary="definitely-not-installed-nmap-xyz")
    with pytest.raises(RuntimeError) as exc:
        runner.run(["-sn", "-oX", "-", "192.168.1.0/24"])
    assert "not found" in str(exc.value)
    assert "install it" in str(exc.value)


def test_nonzero_exit_reports_code():
    runner = SubprocessNmapRunner(binary="false")
    with pytest.raises(RuntimeError) as exc:
        runner.run(["-sn"])
    assert "exit 1" in str(exc.value)
