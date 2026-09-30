#!/usr/bin/env python3
"""Run the SRO test suite, finding a Python that has pytest.

`npm publish` runs this, so it cannot assume the maintainer happens to have
pytest on their default interpreter. It tries, in order:

  1. $SRO_PYTHON
  2. the project's .venv
  3. the interpreter running this script
  4. any python3.x on PATH

If none of them has pytest it fails with the exact command to fix it, rather
than passing the interpreter's own import error through. A publish gate that
fails for an unrelated reason teaches people to skip the gate.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

# Interpreters to try beyond this one, in preference order.
CANDIDATES: list[Path] = []


def collect_candidates() -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()

    def add(candidate: Path | None) -> None:
        if candidate is None or not candidate.is_file():
            return
        key = str(candidate.resolve())
        if key not in seen:
            seen.add(key)
            found.append(candidate)

    add(Path(os.environ["SRO_PYTHON"]) if os.environ.get("SRO_PYTHON") else None)
    add(ROOT / ".venv" / "bin" / "python")
    add(Path(sys.executable))

    for minor in range(9, 20):
        add(Path(f"/usr/bin/python3.{minor}"))
    add(Path("/usr/local/bin/python3"))

    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if entry:
            add(Path(entry) / "python3")

    return found


def has_pytest(interpreter: Path) -> bool:
    try:
        result = subprocess.run(
            [str(interpreter), "-c", "import pytest"],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def main() -> int:
    if not TESTS.is_dir():
        print(f"test: {TESTS} not found; run this from the repository root", file=sys.stderr)
        return 1

    for interpreter in collect_candidates():
        if not has_pytest(interpreter):
            continue
        print(f"test: using {interpreter}")
        return subprocess.run([str(interpreter), "-m", "pytest", str(TESTS), "-q"]).returncode

    print(
        "test: no Python with pytest was found.\n"
        "       Install it, then re-run `npm publish`:\n\n"
        "         python3 -m venv .venv && .venv/bin/pip install pytest\n"
        "         npm publish\n\n"
        "       Or point SRO_PYTHON at an interpreter that already has it:\n\n"
        "         SRO_PYTHON=/path/to/python npm publish",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
