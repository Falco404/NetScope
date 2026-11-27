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


def test_probe_os_true_when_run_succeeds():
    # Deterministic: override run() to simulate nmap succeeding with -O.
    runner = SubprocessNmapRunner(binary=sys.executable)

    def _ok(args: list[str]) -> str:
        return "<nmaprun/>"

    runner.run = _ok  # type: ignore[method-assign]
    assert runner.probe_os() is True


def test_probe_os_false_when_run_fails():
    # Deterministic: override run() to simulate nmap refusing -O (exit 1).
    runner = SubprocessNmapRunner(binary=sys.executable)

    def _fail(args: list[str]) -> str:
        raise RuntimeError("nmap failed (exit 1): requires root")

    runner.run = _fail  # type: ignore[method-assign]
    assert runner.probe_os() is False


def test_stderr_is_logged_not_reflected(caplog):
    """nmap's stderr names absolute paths; the UI only gets the exit code."""
    runner = SubprocessNmapRunner(binary=sys.executable)
    script = "import sys; sys.stderr.write('/root/.nmap/scripts: boom'); raise SystemExit(3)"
    with caplog.at_level("WARNING", logger="netscope.scanner.runner"):
        with pytest.raises(RuntimeError) as exc:
            runner.run(["-c", script])
    message = str(exc.value)
    assert "exit 3" in message
    assert "/root/.nmap/scripts" not in message, "path must not reach the client string"
    assert "see the server log" in message
    assert "/root/.nmap/scripts" in caplog.text, "the full stderr must still be logged"
