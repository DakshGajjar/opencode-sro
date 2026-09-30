"""Platform reader tests.

Readers are exercised against captured payloads and a stubbed transport, never
against a live platform. That keeps the suite deterministic and means no test
can generate traffic to a real program.

Covered: Bugcrowd GET, HackerOne GET, Intigriti public/import, authentication
failure, API failure, malformed response, and cross-provider normalization.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from sro.core.config import Config
from sro.core.engagement import Engagement
from sro.core.errors import (
    ConfigError,
    ProviderAuthError,
    ProviderError,
    ProviderSchemaError,
    ProviderUnavailableError,
)
from sro.readers import detect_provider
from sro.readers.base import RawResponse, ReadOnlyTransport
from sro.readers.bugcrowd.parser import classify_identifier, parse_restrictions, parse_targets
from sro.readers.bugcrowd.reader import BugcrowdReader, read_engagement_from_payload
from sro.readers.bugcrowd.scrape import extract_public_program
from sro.readers.hackerone.normalizer import normalize_hackerone_payload, parse_structured_scopes
from sro.readers.intigriti.reader import normalize_intigriti_payload

from .conftest import BUGCROWD_BRIEF, HACKERONE_PROGRAM, INTIGRITI_BRIEF


class StubTransport(ReadOnlyTransport):
    """Serves canned responses and records every URL that was requested.

    Every request is checked to be a GET, so a reader that tried to write would
    fail here before it reached the network.
    """

    def __init__(self, responses: dict[str, RawResponse], allowed: set[str] | None = None) -> None:
        self.responses = responses
        self.requested: list[str] = []
        self.verbs: list[str] = []
        super().__init__(allowed or {"bugcrowd.com", "api.bugcrowd.com", "hackerone.com", "api.hackerone.com"})

    def _get(self, url: str) -> RawResponse:
        self.requested.append(url)
        for pattern, response in self.responses.items():
            if pattern in url:
                return response
        raise ProviderUnavailableError(f"{url}: no stubbed response")


def _html(body: str, url: str = "https://bugcrowd.com/programs/acme") -> RawResponse:
    return RawResponse(url=url, status=200, headers={}, body=body)


# --- provider detection ---------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://bugcrowd.com/engagements/tesla", "bugcrowd"),
        ("https://bugcrowd.com/programs/shopify", "bugcrowd"),
        ("bugcrowd.com/engagements/tesla", "bugcrowd"),
        ("https://hackerone.com/shopify", "hackerone"),
        ("https://hackerone.com/shopify/policy", "hackerone"),
        ("https://intigriti.com/programs/initech", "intigriti"),
        ("https://example.com/nothing", None),
        ("", None),
        ("just-a-code", None),
    ],
)
def test_provider_detection(url: str, expected: str | None) -> None:
    assert detect_provider(url) == expected


def test_disabled_provider_is_refused(config: Config) -> None:
    config.providers["bugcrowd"].mode = "off"
    reader = BugcrowdReader(config.provider("bugcrowd"))
    with pytest.raises(ProviderError) as excinfo:
        reader.require_public_mode()
    assert "disabled" in str(excinfo.value)


# --- Bugcrowd: code extraction -------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://bugcrowd.com/engagements/tesla", "tesla"),
        ("https://bugcrowd.com/programs/shopify", "shopify"),
        ("https://bugcrowd.com/engagements/acme/payments", "acme"),
        ("bugcrowd.com/programs/acme", "acme"),
    ],
)
def test_bugcrowd_code_extraction(url: str, expected: str) -> None:
    assert BugcrowdReader.program_code_from_url(url) == expected


def test_bugcrowd_code_extraction_rejects_nonsense() -> None:
    for url in ("", "https://bugcrowd.com/", "https://bugcrowd.com/programs"):
        with pytest.raises(ProviderError):
            BugcrowdReader.program_code_from_url(url)


# --- Bugcrowd: public scraping (zero credentials) -------------------------


def test_public_page_extraction_without_credentials(config: Config) -> None:
    html = """<html><head><title>Acme Program | Bugcrowd</title>
    <script>window.__PRELOADED_STATE__ = {"program":{"name":"Acme Program","code":"acme",
    "description":"Report vulnerabilities in Acme web applications.","url":"https://bugcrowd.com/engagements/acme"},
    "in_scope":[{"name":"*.acme.test","category":"website"},{"name":"api.acme.test","category":"api"}],
    "out_of_scope":[{"name":"admin.acme.test","category":"website"}]};</script></head>
    <body><h1>Rules</h1><p>Do not perform denial of service testing. Social engineering is prohibited.</p>
    </body></html>"""
    reader = BugcrowdReader(config.provider("bugcrowd"))
    reader.transport = StubTransport({"bugcrowd.com/programs/acme": _html(html)})

    engagement = reader.read_engagement("acme")
    assert reader.has_credentials is False
    assert engagement.credentials_used is False
    assert engagement.retrieval_mode == "public"
    assert engagement.program_name == "Acme Program"
    identifiers = {t.identifier for t in engagement.in_scope_targets()}
    assert "*.acme.test" in identifiers
    assert "api.acme.test" in identifiers
    excluded = {t.identifier for t in engagement.excluded_targets()}
    assert "admin.acme.test" in excluded
    assert "denial_of_service" in engagement.forbidden_testing
    assert "social_engineering" in engagement.forbidden_testing


def test_public_scope_table_extraction(config: Config) -> None:
    html = """<html><head><title>Acme</title></head><body>
    <h2>Targets in scope</h2>
    <table><tr><th>Target</th><th>Category</th><th>Notes</th></tr>
    <tr><td>shop.acme.test</td><td>Website</td><td>Test cart only</td></tr>
    <tr><td>-</td><td></td><td></td></tr></table>
    <h2>Out of scope targets</h2>
    <table><tr><th>Target</th><th>Type</th></tr><tr><td>blog.acme.test</td><td>Website</td></tr></table>
    </body></html>"""
    reader = BugcrowdReader(config.provider("bugcrowd"))
    reader.transport = StubTransport({"/scope": _html(html)})
    scope = reader._get_public_scope("acme")
    assert [r["name"] for r in scope["in_scope"]] == ["shop.acme.test"]
    assert [r["name"] for r in scope["out_of_scope"]] == ["blog.acme.test"]
    assert scope["in_scope"][0]["instructions"] == "Test cart only"


def test_unrecognizable_page_raises_rather_than_inventing_scope(config: Config) -> None:
    reader = BugcrowdReader(config.provider("bugcrowd"))
    reader.transport = StubTransport({"/programs/acme": _html("<html><body>nothing here</body></html>")})
    with pytest.raises(ProviderSchemaError) as excinfo:
        reader.read_engagement("acme")
    assert "no recognizable program metadata" in str(excinfo.value)


def test_empty_payload_yields_nothing() -> None:
    assert extract_public_program("") == {}
    assert extract_public_program("<html></html>") == {}


# --- Bugcrowd: authentication behaviour ----------------------------------


def test_zero_credential_is_the_default(config: Config) -> None:
    """A public program must be readable with no setup at all."""
    assert config.provider("bugcrowd").credentials == "none"
    assert config.provider("bugcrowd").mode in ("public", "readonly")


def test_api_reads_refuse_without_credentials(config: Config) -> None:
    reader = BugcrowdReader(config.provider("bugcrowd"))
    with pytest.raises(ProviderAuthError) as excinfo:
        reader.get_engagement("acme")
    assert "read-only Bugcrowd API token" in str(excinfo.value)


def test_known_issues_are_empty_without_credentials(config: Config) -> None:
    reader = BugcrowdReader(config.provider("bugcrowd"))
    assert reader.get_known_issues("acme") == []


def _fail_with(status: int, monkeypatch) -> None:
    """Make the real transport raise an HTTP status, so the reader's own error
    conversion is what gets tested rather than a stubbed replacement."""
    import urllib.request
    from urllib.error import HTTPError

    class FailingOpener:
        def open(self, request, timeout=None):
            raise HTTPError(request.full_url, status, "stubbed failure", {}, None)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: FailingOpener())
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])


def test_authentication_failure_is_reported_clearly(config: Config, monkeypatch) -> None:
    config.providers["bugcrowd"].credentials = "environment"
    config.providers["bugcrowd"].token_env = "SRO_TEST_BC"
    config.providers["bugcrowd"].mode = "readonly"
    monkeypatch.setenv("SRO_TEST_BC", "fake-token")
    reader = BugcrowdReader(config.provider("bugcrowd"))
    assert reader.has_credentials

    _fail_with(401, monkeypatch)
    with pytest.raises(ProviderAuthError) as excinfo:
        reader.get_engagement("acme")
    assert "read-only credentials" in str(excinfo.value)


def test_authenticated_read_falls_back_to_the_public_page(config: Config, monkeypatch) -> None:
    """A configured token must not turn a public read into a hard failure."""
    config.providers["bugcrowd"].credentials = "environment"
    config.providers["bugcrowd"].token_env = "SRO_TEST_BC"
    config.providers["bugcrowd"].mode = "readonly"
    monkeypatch.setenv("SRO_TEST_BC", "fake-token")
    reader = BugcrowdReader(config.provider("bugcrowd"))

    html = (
        "<html><head><title>Acme Program | Bugcrowd</title><script>window.__PRELOADED_STATE__ = "
        '{"program":{"name":"Acme Program","code":"acme",'
        '"description":"Report vulnerabilities in Acme web applications."},'
        '"in_scope":[{"name":"*.acme.test","category":"website"},'
        '{"name":"api.acme.test","category":"api"}],'
        '"out_of_scope":[{"name":"admin.acme.test","category":"website"}]};</script>'
        "</head><body><h1>Rules</h1><p>Do not perform denial of service testing.</p></body></html>"
    )
    reader.transport = StubTransport({"bugcrowd.com/programs/acme": _html(html)})
    engagement = reader.read_engagement("acme")
    assert engagement.program_name == "Acme Program"


# --- Bugcrowd: failure modes ---------------------------------------------


def test_http_error_is_reported(config: Config, monkeypatch) -> None:
    reader = BugcrowdReader(config.provider("bugcrowd"))
    _fail_with(500, monkeypatch)
    with pytest.raises(ProviderUnavailableError) as excinfo:
        reader.get_program("acme")
    assert "500" in str(excinfo.value)


def test_network_failure_is_reported(config: Config, monkeypatch) -> None:
    import urllib.request

    reader = BugcrowdReader(config.provider("bugcrowd"))

    class DeadOpener:
        def open(self, request, timeout=None):
            raise urllib.error.URLError("name resolution failed")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: DeadOpener())
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    with pytest.raises(ProviderUnavailableError):
        reader.get_program("acme")


def test_malformed_json_is_reported(config: Config, monkeypatch) -> None:
    reader = BugcrowdReader(config.provider("bugcrowd"))
    reader.transport = StubTransport(
        {"bugcrowd.com/programs/acme": _html("<html><body>not json</body></html>")}
    )
    monkeypatch.setattr(
        reader.transport, "_get", lambda url: RawResponse(url=url, status=200, headers={}, body="{not json")
    )
    with pytest.raises(ProviderSchemaError):
        reader.transport.get_json("https://bugcrowd.com/programs/acme")


def test_malformed_api_payload_is_reported(config: Config, monkeypatch) -> None:
    config.providers["bugcrowd"].credentials = "environment"
    config.providers["bugcrowd"].token_env = "SRO_TEST_BC"
    monkeypatch.setenv("SRO_TEST_BC", "fake-token")
    reader = BugcrowdReader(config.provider("bugcrowd"))
    monkeypatch.setattr(
        reader.transport,
        "_get",
        lambda url: RawResponse(url=url, status=200, headers={}, body='["a","b"]'),
    )
    with pytest.raises(ProviderSchemaError) as excinfo:
        reader.get_engagement("acme")
    assert "expected an object" in str(excinfo.value)


def test_off_allowlist_operation_is_refused(config: Config) -> None:
    """A typed read that is not on the allowlist must fail closed."""
    reader = BugcrowdReader(config.provider("bugcrowd"))
    with pytest.raises(ProviderError) as excinfo:
        reader._api_get("delete_engagement", "/v1/engagements/acme")
    assert "allowlist" in str(excinfo.value)


# --- Bugcrowd: parsing ----------------------------------------------------


@pytest.mark.parametrize(
    "identifier,expected",
    [
        ("*.example.com", "wildcard_domain"),
        ("api.example.com", "domain"),
        ("example.com", "domain"),
        ("10.0.0.0/8", "cidr"),
        ("192.168.1.1", "ip"),
        ("https://api.example.com/v1", "url"),
        ("arn:aws:s3:::bucket", "cloud_resource"),
        ("github.com/acme/app", "repository"),
        ("com.acme.app", "domain"),
        ("", "other"),
        ("!!!", "other"),
    ],
)
def test_identifier_classification(identifier: str, expected: str) -> None:
    assert classify_identifier(identifier) == expected


def test_mobile_category_wins_for_a_bundle_id() -> None:
    assert classify_identifier("com.acme.app", "mobile_application") == "mobile_application"


def test_unclassifiable_target_produces_a_warning_not_a_guess() -> None:
    targets, warnings = parse_targets([{"name": "!!!", "category": "other"}], default_in_scope=True)
    assert targets[0].type == "other"
    assert any("could not classify" in w for w in warnings)


def test_non_list_targets_field_is_reported() -> None:
    targets, warnings = parse_targets("not-a-list", default_in_scope=True)
    assert targets == []
    assert warnings


def test_in_scope_flag_wins_over_container() -> None:
    targets, _ = parse_targets([{"name": "a.example.com", "in_scope": False}], default_in_scope=True)
    assert targets[0].in_scope is False


def test_state_field_is_honoured() -> None:
    targets, _ = parse_targets([{"name": "a.example.com", "state": "out_of_scope"}], default_in_scope=True)
    assert targets[0].in_scope is False


@pytest.mark.parametrize(
    "prose,expected",
    [
        ("Do not perform denial of service testing.", "denial_of_service"),
        ("Denial of service testing is not permitted.", "denial_of_service"),
        ("Social engineering is prohibited.", "social_engineering"),
        ("Phishing is forbidden.", "social_engineering"),
        ("Password spraying is not allowed.", "password_spraying"),
        ("Brute force attacks must not be performed.", "brute_force"),
        ("Physical testing is out of scope.", "physical_testing"),
        ("Do not test third-party services.", "third_party_systems"),
        ("Wiping the database will result in disqualification.", "data_destruction"),
        ("Automated scanning is permitted.", "automated_scanning"),
    ],
)
def test_restriction_recognition(prose: str, expected: str) -> None:
    restrictions = parse_restrictions(prose)
    assert expected in {r.name for r in restrictions}, [r.name for r in restrictions]


def test_no_restrictions_from_empty_prose() -> None:
    assert parse_restrictions("") == []
    assert parse_restrictions("Test the API thoroughly.") == []


def test_restriction_import_brief_round_trip() -> None:
    engagement = read_engagement_from_payload(BUGCROWD_BRIEF, code="acme")
    assert isinstance(engagement, Engagement)
    assert engagement.provider == "bugcrowd"
    assert engagement.credentials_used is False
    names = {t.identifier for t in engagement.in_scope_targets()}
    assert {"*.acme.test", "api.acme.test", "203.0.113.0/24", "com.acme.mobile", "github.com/acme/webapp"} <= names
    assert "denial_of_service" in engagement.forbidden_testing
    assert "automated_scanning" in engagement.allowed_testing
    assert "10 requests per second" in engagement.rate_limits
    assert "test account" in engagement.authentication_requirements.lower()
    assert engagement.is_complete()
    assert engagement.excluded_targets()


# --- HackerOne ------------------------------------------------------------


def test_hackerone_structured_scope(config: Config) -> None:
    in_scope, out_scope, warnings = parse_structured_scopes(
        HACKERONE_PROGRAM["data"]["attributes"]["structured_scopes"]
    )
    assert {t.identifier for t in in_scope} == {"*.globex.test", "api.globex.test", "10.20.0.0/16"}
    assert {t.identifier for t in out_scope} == {"admin.globex.test"}
    assert not warnings


def test_hackerone_normalization_produces_the_common_schema() -> None:
    engagement = normalize_hackerone_payload(HACKERONE_PROGRAM, code="globex")
    assert engagement.provider == "hackerone"
    assert engagement.program_name == "Globex Bug Bounty"
    assert "*.globex.test" in {t.identifier for t in engagement.in_scope_targets()}
    assert "admin.globex.test" in {t.identifier for t in engagement.excluded_targets()}
    assert "denial_of_service" in engagement.forbidden_testing
    assert engagement.is_complete()


def test_hackerone_without_structured_scope_warns() -> None:
    engagement = normalize_hackerone_payload(
        {"data": {"attributes": {"handle": "x", "name": "X", "description": "d"}}}, code="x"
    )
    assert not engagement.in_scope_targets()
    assert any("no structured scope" in w for w in engagement.warnings)
    assert engagement.is_complete() is False


def test_hackerone_legacy_targets_shape() -> None:
    payload = {
        "data": {
            "attributes": {
                "handle": "legacy",
                "name": "Legacy",
                "policy": "Do not perform denial of service testing.",
                "targets": {
                    "in_scope": {
                        "website": {
                            "*.legacy.test": {"description": "Main site", "bounty_eligible": True}
                        }
                    },
                    "out_of_scope": {"website": {"admin.legacy.test": {}}},
                },
            }
        }
    }
    engagement = normalize_hackerone_payload(payload, code="legacy")
    assert "*.legacy.test" in {t.identifier for t in engagement.in_scope_targets()}
    assert "admin.legacy.test" in {t.identifier for t in engagement.excluded_targets()}


def test_hackerone_handle_extraction() -> None:
    from sro.readers.hackerone.reader import HackerOneReader

    assert HackerOneReader.program_code_from_url("https://hackerone.com/shopify") == "shopify"
    assert HackerOneReader.program_code_from_url("hackerone.com/globex/policy") == "globex"
    with pytest.raises(ProviderError):
        HackerOneReader.program_code_from_url("https://hackerone.com/")


# --- Intigriti ------------------------------------------------------------


def test_intigriti_import_only_is_the_default(config: Config) -> None:
    assert config.provider("intigriti").mode == "import_only"


def test_intigriti_import_normalizes() -> None:
    engagement = normalize_intigriti_payload(INTIGRITI_BRIEF, handle="initech")
    assert engagement.provider == "intigriti"
    assert "*.initech.test" in {t.identifier for t in engagement.in_scope_targets()}
    assert "mail.initech.test" in {t.identifier for t in engagement.excluded_targets()}
    assert "denial_of_service" in engagement.forbidden_testing
    assert "brute_force" in engagement.forbidden_testing
    assert engagement.retrieval_mode == "import"
    assert engagement.credentials_used is False


def test_intigriti_without_scope_warns() -> None:
    engagement = normalize_intigriti_payload({"name": "Bare", "description": "d"}, handle="bare")
    assert not engagement.in_scope_targets()
    assert any("import" in w.lower() for w in engagement.warnings)
    assert engagement.is_complete() is False


def test_intigriti_handle_extraction() -> None:
    from sro.readers.intigriti.reader import IntigritiReader

    assert IntigritiReader.program_code_from_url("https://intigriti.com/programs/initech") == "initech"
    with pytest.raises(ProviderError):
        IntigritiReader.program_code_from_url("")


def test_intigriti_declares_no_submission_surface(config: Config) -> None:
    from sro.readers.intigriti.reader import IntigritiReader

    caps = IntigritiReader(config.provider("intigriti")).capabilities()
    assert caps.writes == ()
    assert "submit_report" not in caps.reads


# --- cross-provider normalization -----------------------------------------


@pytest.mark.parametrize(
    "payload,code,provider",
    [
        (BUGCROWD_BRIEF, "acme", "bugcrowd"),
        (HACKERONE_PROGRAM, "globex", "hackerone"),
        (INTIGRITI_BRIEF, "initech", "intigriti"),
    ],
)
def test_all_providers_produce_the_same_shape(
    payload: dict[str, Any], code: str, provider: str
) -> None:
    if provider == "bugcrowd":
        engagement = read_engagement_from_payload(payload, code=code)
    elif provider == "hackerone":
        engagement = normalize_hackerone_payload(payload, code=code)
    else:
        engagement = normalize_intigriti_payload(payload, handle=code)

    data = engagement.to_dict()
    required = {
        "provider", "engagement_id", "program_name", "program_url", "description",
        "rules", "disclosure_policy", "safe_harbor", "targets", "exclusions",
        "known_issues", "testing_restrictions", "rate_limits",
        "authentication_requirements", "allowed_testing", "forbidden_testing",
        "retrieved_at",
    }
    assert required <= set(data)
    for target in data["targets"] + data["exclusions"]:
        assert {"identifier", "type", "in_scope"} <= set(target)
    # Round-trips without loss, which is what makes a provider swappable.
    assert Engagement.from_dict(data).to_dict() == data


def test_json_serializable_round_trip() -> None:
    engagement = read_engagement_from_payload(BUGCROWD_BRIEF, code="acme")
    text = json.dumps(engagement.to_dict(), default=str)
    assert Engagement.from_dict(json.loads(text)).sro_id == engagement.sro_id
