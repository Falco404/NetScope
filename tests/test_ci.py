"""Guard: CI must exercise the suite on Windows as well as Linux.

The suite used to run on Linux only, so a Windows-only failure (the
``nmap-mac-prefixes`` environment leak: ``525400`` entered ``MAC_PREFIXES``
because ``main()`` read it from a real nmap install) reached Falco's Windows
machine before CI ever saw it. These tests pin the OS matrix and the steps it
runs, so the workflow cannot silently regress to a single-OS run.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_matrix_has_a_linux_and_a_windows_runner():
    text = _workflow_text()
    assert "ubuntu-latest" in text, "CI must keep a Linux runner"
    assert "windows-latest" in text, "CI must include a Windows runner (#38)"


def test_runs_on_reads_the_matrix_os():
    text = _workflow_text()
    assert "runs-on: ${{ matrix.os }}" in text, (
        "runs-on must read matrix.os, otherwise every job runs on one OS"
    )


def test_workflow_still_runs_install_lint_and_suite():
    text = _workflow_text()
    for command in ("uv sync", "uv run ruff check .", "uv run pytest"):
        assert command in text, f"CI lost its `{command}` step"


# --- least privilege + dependency updates (security review NS-13/NS-14) ----


def test_workflow_declares_read_only_permissions():
    """Without a `permissions:` block the job inherits the repo default token,
    which is often read/write; every action in the job runs with it."""
    text = _workflow_text()
    top_level = re.search(r"^permissions:\s*$", text, re.MULTILINE)
    assert top_level, "the workflow must declare a top-level `permissions:` block"
    assert re.search(r"^\s+contents:\s*read\s*$", text, re.MULTILINE), (
        "the token must be read-only for the checkout"
    )
    assert "write-all" not in text
    assert not re.search(r"contents:\s*write", text), "CI must not need write access"


def test_dependabot_covers_the_lock_file_and_the_actions():
    config = ROOT / ".github" / "dependabot.yml"
    assert config.is_file(), "Dependabot config is missing (NS-14)"
    text = config.read_text(encoding="utf-8")
    assert "version: 2" in text
    # `uv`, not `pip`: only the uv ecosystem keeps uv.lock (what CI installs)
    # in step with pyproject.toml. GitHub documents `uv` as the YAML value.
    assert re.search(r'package-ecosystem:\s*"uv"', text), "uv.lock must be watched"
    assert re.search(r'package-ecosystem:\s*"github-actions"', text), (
        "the workflow's actions must be watched too"
    )
