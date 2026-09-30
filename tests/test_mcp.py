"""MCP server and cross-surface consistency tests.

The MCP server is another door into the same readers, so it needs the same
guarantees: reads only, no vendor SDK, no write-shaped tool names.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from sro.connectors.mcp import server as mcp
from sro.core.config import Config
from sro.readers import SUPPORTED_PROVIDERS

MCP_PATH = Path(mcp.__file__)


# --- surface --------------------------------------------------------------


def test_surface_validates() -> None:
    mcp.validate_surface()


def test_every_tool_has_a_handler() -> None:
    assert set(mcp.TOOL_NAMES) == set(mcp.HANDLERS)


def test_no_write_shaped_tool_names() -> None:
    for name in mcp.TOOL_NAMES:
        lowered = name.lower()
        for fragment in ("create", "update", "delete", "comment", "submit", "post", "put", "patch", "modify"):
            assert fragment not in lowered, f"{name} looks write-capable"


def test_validate_surface_rejects_a_write_shaped_tool(monkeypatch) -> None:
    monkeypatch.setattr(
        mcp,
        "TOOLS",
        [{"name": "sro_submit_report", "description": "", "inputSchema": {"type": "object"}}],
    )
    with pytest.raises(RuntimeError) as excinfo:
        mcp.validate_surface()
    assert "read-only" in str(excinfo.value)


def test_server_source_has_no_urllib_post() -> None:
    source = MCP_PATH.read_text(encoding="utf-8")
    assert "urllib.request.Request(url=" not in source
    assert "method=\"POST\"" not in source


def test_server_imports_no_platform_sdk() -> None:
    tree = ast.parse(MCP_PATH.read_text(encoding="utf-8"))
    banned = {"bugcrowd", "h1", "hackerone", "intigriti", "requests", "httpx", "aiohttp"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in banned, alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            assert node.module.split(".")[0] not in banned, node.module


# --- protocol -------------------------------------------------------------


def test_initialize_reports_the_read_only_contract(config: Config) -> None:
    response = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, config)
    assert response is not None
    result = response["result"]
    assert result["serverInfo"]["name"] == "sro-readers"
    assert result["capabilities"] == {"tools": {}}
    assert "read-only" in result["instructions"].lower()
    assert "cannot" in result["instructions"].lower()


def test_tools_list(config: Config) -> None:
    response = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, config)
    assert response is not None
    tools = response["result"]["tools"]
    assert {t["name"] for t in tools} == set(mcp.TOOL_NAMES)
    for tool in tools:
        assert "read-only" in tool["description"].lower()


def test_notifications_return_nothing(config: Config) -> None:
    assert mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, config) is None


def test_ping(config: Config) -> None:
    assert mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "ping"}, config) is not None


def test_unknown_method(config: Config) -> None:
    response = mcp.handle({"jsonrpc": "2.0", "id": 4, "method": "nope"}, config)
    assert response is not None
    assert response["error"]["code"] == -32601


def test_unknown_tool_is_rejected(config: Config) -> None:
    response = mcp.handle(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "sro_submit_report"}},
        config,
    )
    assert response is not None
    assert "unknown tool" in response["error"]["message"]


def test_provider_capabilities_call(config: Config) -> None:
    response = mcp.handle(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "sro_provider_capabilities", "arguments": {}},
        },
        config,
    )
    assert response is not None
    payload = json.loads(response["result"]["content"][0]["text"])
    for provider in SUPPORTED_PROVIDERS:
        assert payload[provider]["writes"] == []


def test_read_failure_is_returned_as_output_not_a_protocol_error(config: Config) -> None:
    """A failed read is information for the researcher, not a crash.

    The provider is disabled so this exercises the error path without any
    network traffic: the test suite must never touch a live platform.
    """
    config.providers["bugcrowd"].mode = "off"
    response = mcp.handle(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "sro_get_scope", "arguments": {"provider": "bugcrowd", "program": "acme"}},
        },
        config,
    )
    assert response is not None
    assert response["result"]["isError"] is False
    payload = json.loads(response["result"]["content"][0]["text"])
    assert "error" in payload
    assert "disabled" in payload["error"]


# --- the server cannot authorize anything ---------------------------------


def test_server_exposes_no_scope_or_policy_operation() -> None:
    """Scope and policy decisions belong to the brokered tool surface only."""
    for name in mcp.TOOL_NAMES:
        assert "scope_check" not in name
        assert "policy" not in name
        assert "execute" not in name


def test_engagement_output_is_marked_inactive(config: Config) -> None:
    config.providers["bugcrowd"].mode = "off"
    response = mcp.handle(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "sro_get_engagement", "arguments": {"provider": "bugcrowd", "program": "acme"}},
        },
        config,
    )
    assert response is not None
    text = response["result"]["content"][0]["text"]
    assert "error" in text
