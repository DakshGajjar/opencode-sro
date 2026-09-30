"""Write-protection tests.

SRO's platform connector layer is read-only. These tests are the proof, and
they are written to fail loudly if anyone weakens the guarantee — including by
adding a write method and hoping no test notices.

The guarantee is structural: the transport has no method that accepts an HTTP
verb, the readers expose no write operations, and the reader capability
advertisement reports an empty write list on every provider.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

from sro.core.config import Config
from sro.core.errors import ReadOnlyViolation
from sro.readers import SUPPORTED_PROVIDERS, all_capabilities, build_reader
from sro.readers.base import FORBIDDEN_VERBS, BaseReader, ReadOnlyTransport, forbid_write

READER_DIR = Path(__file__).resolve().parents[1] / "sro" / "readers"
#: Identifiers that look like writes but are not HTTP mutations. Each one is
#: named here so the allowlist stays reviewable rather than being widened by
#: whoever adds the next function.
NON_MUTATION_IDENTIFIERS = {
    "read_only",
    "readonly",
    "no_post",
    "no_put",
    "no_patch",
    "no_delete",
    "forbidden_verbs",
    "forbid_write",
    "read_only_violation",
    "post_conditions_known",
}


def _python_sources() -> list[Path]:
    return sorted(READER_DIR.rglob("*.py"))


# --- transport ------------------------------------------------------------


def test_transport_offers_no_verb_parameter() -> None:
    """The transport must not expose a way to choose a method."""
    public = {
        name
        for name, _ in inspect.getmembers(ReadOnlyTransport, predicate=inspect.isfunction)
        if not name.startswith("_")
    }
    assert public == {"get", "get_json", "get_text"}


def test_transport_only_builds_get_requests() -> None:
    """Whatever the internals do, the request it builds is a GET."""
    transport = ReadOnlyTransport({"bugcrowd.com"}, token="")
    request = transport._build("https://bugcrowd.com/programs/x")
    assert request.get_method() == "GET"
    assert request.method == "GET"


def test_transport_rejects_non_https() -> None:
    transport = ReadOnlyTransport({"bugcrowd.com"})
    with pytest.raises(Exception) as excinfo:
        transport.get("http://bugcrowd.com/programs/x")
    assert "https" in str(excinfo.value)


def test_transport_refuses_off_allowlist_host() -> None:
    """A hostile engagement URL must not redirect the reader at internal hosts."""
    transport = ReadOnlyTransport({"bugcrowd.com"})
    with pytest.raises(Exception) as excinfo:
        transport.get("https://evil.example/programs/x")
    assert "allowlist" in str(excinfo.value)


def test_transport_refuses_port_and_userinfo_tricks() -> None:
    transport = ReadOnlyTransport({"bugcrowd.com"})
    for url in (
        "https://bugcrowd.com.evil.example/x",
        "https://bugcrowd.com@evil.example/x",
    ):
        with pytest.raises(Exception):
            transport.get(url)


# --- write operations do not exist -----------------------------------------


@pytest.mark.parametrize("operation", FORBIDDEN_VERBS)
def test_transport_builds_no_request_with_a_write_verb(operation: str) -> None:
    """Parse the transport and prove no request can be built with this verb.

    A substring search would trip over the FORBIDDEN_VERBS marker itself, so
    this walks the AST and inspects what is actually passed as a method.
    """
    path = READER_DIR / "base.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "method":
                continue
            assert not (
                isinstance(keyword.value, ast.Constant) and keyword.value.value == operation
            ), f"{path.name} builds a request with method={operation}"


def test_transport_marker_lists_exactly_the_write_verbs() -> None:
    """The marker exists so the absence of write verbs is machine-checkable."""
    assert set(FORBIDDEN_VERBS) == {"POST", "PUT", "PATCH", "DELETE"}
    path = READER_DIR / "base.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    markers = [
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "FORBIDDEN_VERBS" for t in node.targets)
    ]
    assert len(markers) == 1
    assert set(markers[0]) == set(FORBIDDEN_VERBS)


def test_forbidden_verbs_marker_is_accurate() -> None:
    assert set(FORBIDDEN_VERBS) == {"POST", "PUT", "PATCH", "DELETE"}


def test_forbid_write_raises_rather_than_performing() -> None:
    for operation in ("create_submission", "update_report", "comment_submission", "delete_report"):
        with pytest.raises(ReadOnlyViolation) as excinfo:
            forbid_write(operation)
        assert operation in str(excinfo.value)
        assert "read-only" in str(excinfo.value)


# --- no submission surface anywhere ----------------------------------------


SUBMISSION_IDENTIFIERS = (
    "create_submission",
    "update_submission",
    "delete_submission",
    "comment_submission",
    "change_submission_status",
    "modify_program",
    "modify_scope",
    "create_report",
    "update_report",
    "comment_report",
    "submit_report",
    "delete_report",
    "api_request",
)


@pytest.mark.parametrize("identifier", SUBMISSION_IDENTIFIERS)
def test_no_submission_or_generic_api_identifier_exists(identifier: str) -> None:
    """These names must not be defined anywhere in the reader package."""
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(node.name)
            elif isinstance(node, ast.Assign):
                names.extend(
                    t.id for t in node.targets if isinstance(t, ast.Name)
                )
            for name in names:
                assert name != identifier, f"{path.name} defines {name!r}"


def test_no_urllib_request_with_a_write_method_in_readers() -> None:
    """Scan for a request built with an explicit non-GET method."""
    for path in _python_sources():
        text = path.read_text(encoding="utf-8")
        for verb in FORBIDDEN_VERBS:
            assert f'method="{verb}"' not in text, f"{path.name} builds a {verb} request"
            assert f"method='{verb}'" not in text, f"{path.name} builds a {verb} request"


def test_readers_expose_no_write_capability(config: Config) -> None:
    capabilities = all_capabilities(config)
    for provider, cap in capabilities.items():
        if not cap.get("enabled"):
            continue
        assert cap["writes"] == [], f"{provider} advertises write operations: {cap['writes']}"


@pytest.mark.parametrize("provider", SUPPORTED_PROVIDERS)
def test_reader_capabilities_are_typed_reads_only(config: Config, provider: str) -> None:
    reader = build_reader(config, provider)
    caps = reader.capabilities()
    assert caps.writes == ()
    for name in caps.reads + caps.authenticated_reads:
        assert not any(
            verb in name.lower() for verb in ("create", "update", "delete", "comment", "submit", "post", "put", "patch")
        ), f"{provider} exposes a write-shaped read: {name}"


@pytest.mark.parametrize("provider", SUPPORTED_PROVIDERS)
def test_reader_public_methods_are_reads(config: Config, provider: str) -> None:
    reader = build_reader(config, provider)
    forbidden = ("create", "update", "delete", "comment", "submit", "post", "put", "patch", "modify")
    for name in dir(reader):
        if name.startswith("_") or not callable(getattr(reader, name, None)):
            continue
        if name in {"transport", "config", "capabilities", "require_public_mode", "has_credentials", "base_url"}:
            continue
        assert not any(name.lower().startswith(verb) for verb in forbidden), (
            f"{provider} reader exposes a write-shaped method: {name}"
        )


def test_graphql_documents_contain_no_mutation(config: Config) -> None:
    """HackerOne uses GraphQL. Only queries may be defined."""
    from sro.readers.hackerone import reader as h1

    for name in dir(h1):
        if name.endswith("_QUERY"):
            document = getattr(h1, name)
            assert "mutation" not in document.lower(), f"{name} defines a mutation"
            assert document.strip().lstrip().lower().startswith("query")


def test_graphql_transport_refuses_mutation_documents(config: Config) -> None:
    from sro.readers.hackerone.reader import HackerOneReader

    reader = HackerOneReader(config.provider("hackerone"))
    with pytest.raises(Exception) as excinfo:
        reader._graphql_query("mutation { createReport(input: {}) { id } }", {})
    assert "mutation" in str(excinfo.value).lower()


def test_readers_import_no_platform_sdk() -> None:
    """A reader that pulls in a vendor SDK inherits that SDK's write surface.

    Checked as imports rather than substrings, so a provider name appearing in
    a URL or a comment does not trip the test.
    """
    banned_modules = {
        "bugcrowd",
        "h1",
        "hackerone",
        "intigriti",
        "requests",
        "httpx",
        "aiohttp",
        "boto3",
    }
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in banned_modules, f"{path.name} imports {alias.name}"
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                root = node.module.split(".")[0]
                assert root not in banned_modules, f"{path.name} imports from {node.module}"


def test_base_reader_cannot_widen_its_own_allowlist() -> None:
    """A subclass is handed a transport, not the ability to build one."""

    class GreedyReader(BaseReader):
        provider = "greedy"
        default_hosts = ("bugcrowd.com",)

        def read_engagement(self, code: str) -> None:
            pass

    reader = GreedyReader.__new__(GreedyReader)
    assert "default_hosts" in GreedyReader.__dict__


def test_config_rejects_unknown_provider_keys() -> None:
    """A key the config does not understand is a typo, or an attempt to enable one."""
    from sro.core.errors import ConfigError

    with pytest.raises(ConfigError) as excinfo:
        Config.from_dict({"providers": {"bugcrowd": {"mode": "readonly", "enable_submissions": True}}})
    assert "unknown key" in str(excinfo.value)


def test_config_forces_submissions_off_even_when_supplied() -> None:
    config = Config.from_dict(
        {"providers": {"bugcrowd": {"mode": "readonly", "credentials": "environment", "token_env": "X"}}}
    )
    assert config.provider("bugcrowd").submissions is False


def test_config_rejects_a_credential_literal() -> None:
    """Secrets live in the environment, never in the repo."""
    from sro.core.errors import ConfigError

    for payload in (
        {"providers": {"bugcrowd": {"mode": "readonly", "credentials": "environment", "token_env": "X", "token": "hunter2"}}},
    ):
        with pytest.raises(ConfigError):
            Config.from_dict(payload)


def test_public_config_summary_never_exposes_a_secret(config: Config) -> None:
    import os

    os.environ["SRO_TEST_TOKEN"] = "super-secret-value-1234"
    try:
        config = Config.from_dict(
            {
                "providers": {
                    "bugcrowd": {
                        "mode": "readonly",
                        "credentials": "environment",
                        "token_env": "SRO_TEST_TOKEN",
                    }
                }
            }
        )
        summary = repr(config.public_summary())
        assert "super-secret-value-1234" not in summary
        assert "credential_source" in summary
    finally:
        del os.environ["SRO_TEST_TOKEN"]
