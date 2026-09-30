#!/usr/bin/env python3
"""Parse every module in `sro/` without writing bytecode.

Used as a publish gate. `compileall` would be the obvious choice but it writes
__pycache__ into the tree, and those .pyc files then end up in the npm tarball
where they are useless to anyone on a different Python version.

Exits non-zero and prints every failure, so one bad module does not hide the
next.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "sro"


def main() -> int:
    if not ROOT.is_dir():
        print(f"lint: {ROOT} does not exist", file=sys.stderr)
        return 1

    failures: list[str] = []
    checked = 0

    for path in sorted(ROOT.rglob("*.py")):
        checked += 1
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            failures.append(f"{path}:{exc.lineno}: {exc.msg}")
        except (OSError, UnicodeDecodeError) as exc:
            failures.append(f"{path}: {exc}")

    for failure in failures:
        print(f"lint: {failure}", file=sys.stderr)
    print(f"lint: {checked} modules parsed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
