"""One version, three files. Derived constants drift; hard-coded ones do so silently."""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VERSION = json.loads((REPO / "package.json").read_text(encoding="utf-8"))["version"]


def test_pyproject_matches_package_json() -> None:
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    found = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert found, "no version in pyproject.toml"
    assert found.group(1) == VERSION, f"pyproject {found.group(1)} != package.json {VERSION}"


def test_mcp_server_reports_the_package_version() -> None:
    """An MCP client is told this and cannot check it."""
    from sro.connectors.mcp.server import SERVER_VERSION

    assert SERVER_VERSION == VERSION


def test_version_is_a_release_shape() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", VERSION), VERSION
