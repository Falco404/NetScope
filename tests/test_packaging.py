"""Guard for the packaging footgun: plain ``uv sync`` must install the dev tools.

``[project.optional-dependencies] dev`` is opt-in, and worse than that: ``uv
sync`` is declarative, so running it *without* ``--extra dev`` does not merely
skip pytest and ruff — it **uninstalls** them from a working environment, and
the next ``uv run pytest`` dies with ``error: Failed to spawn: pytest``.
``[dependency-groups] dev`` is synced by default, so the command in the README
can never break the toolchain. These tests keep the packaging file and the
docs in sync with that rule.
"""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"


def _names(requirements: list[str]) -> set[str]:
    return {re.split(r"[<>=!;\[\{]", r)[0].strip().lower() for r in requirements}


def test_dev_tools_are_a_default_dependency_group():
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    dev = data.get("dependency-groups", {}).get("dev", [])
    assert _names(dev) >= {"pytest", "ruff", "httpx"}, (
        "pytest/ruff/httpx must live in [dependency-groups] dev, otherwise "
        f"`uv sync` uninstalls them: {dev!r}"
    )


def test_dev_is_not_an_optional_extra():
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    extras = data.get("project", {}).get("optional-dependencies", {})
    assert "dev" not in extras, (
        "a `dev` extra makes plain `uv sync` remove pytest and ruff"
    )


def test_docs_never_install_with_the_dev_extra():
    # Prose may still *name* the old flag to explain the trap; what must never
    # come back is the command line itself, i.e. `uv sync --extra dev` as an
    # instruction (a code-block line, or a CI `run:` step).
    instruction = re.compile(r"^\s*(?:-+\s*)?(?:run:\s*)?uv sync\b.*--extra\s+dev")
    for doc in ("README.md", "docs/gotchas.md", "docs/STATUS.md", ".github/workflows/tests.yml"):
        lines = (ROOT / doc).read_text(encoding="utf-8").splitlines()
        for lineno, line in enumerate(lines, 1):
            assert not instruction.search(line), (
                f"{doc}:{lineno} still installs with the extra: {line.strip()}"
            )
