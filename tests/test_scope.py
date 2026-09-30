"""Scope engine tests.

The scope engine is the authorization boundary, so these tests are written
exhaustively rather than illustratively. Each failure mode that could produce a
permissive verdict gets a case.
"""

from __future__ import annotations

import pytest

from sro.core.engagement import Engagement, Target
from sro.core.scope import (
    IN_SCOPE,
    OUT_OF_SCOPE,
    UNKNOWN,
    ScopeEngine,
    parse_target,
)


# --- exact domains --------------------------------------------------------


def test_exact_domain_match(scope_engine: ScopeEngine) -> None:
    decision = scope_engine.check("api.acme.test")
    assert decision.status == IN_SCOPE
    assert decision.match_kind == "exact"
    assert decision.allowed is True


def test_exact_domain_is_case_insensitive(scope_engine: ScopeEngine) -> None:
    assert scope_engine.check("API.Acme.TEST").status == IN_SCOPE


def test_exact_domain_trailing_dot(scope_engine: ScopeEngine) -> None:
    assert scope_engine.check("api.acme.test.").status == IN_SCOPE


def test_lookalike_domain_is_not_a_subdomain(scope_engine: ScopeEngine) -> None:
    """The classic suffix-confusion bug. evil-acme.test must never match *.acme.test."""
    for lookalike in ("evil-acme.test", "notacme.test", "acme.test.attacker.example", "xacme.test"):
        assert scope_engine.check(lookalike).status == UNKNOWN, lookalike


# --- wildcards ------------------------------------------------------------


def test_wildcard_matches_subdomain(scope_engine: ScopeEngine) -> None:
    assert scope_engine.check("shop.acme.test").status == IN_SCOPE


def test_wildcard_matches_deep_subdomain(scope_engine: ScopeEngine) -> None:
    assert scope_engine.check("a.b.c.acme.test").status == IN_SCOPE


def test_wildcard_includes_apex_by_default(scope_engine: ScopeEngine) -> None:
    assert scope_engine.check("acme.test").status == IN_SCOPE


def test_wildcard_can_exclude_apex(engagement: Engagement) -> None:
    engine = ScopeEngine.from_engagement(engagement, active=True, wildcard_includes_apex=False)
    assert engine.check("acme.test").status == UNKNOWN
    assert engine.check("shop.acme.test").status == IN_SCOPE


def test_wildcard_target_itself_is_not_a_probe_target(scope_engine: ScopeEngine) -> None:
    """Checking the scope rule is a no-op, not a match."""
    assert scope_engine.check("*.acme.test").status == UNKNOWN


# --- IP and CIDR ----------------------------------------------------------


def test_ip_inside_listed_cidr(scope_engine: ScopeEngine) -> None:
    decision = scope_engine.check("203.0.113.9")
    assert decision.status == IN_SCOPE
    assert decision.match_kind == "broad"


def test_ip_outside_listed_cidr(scope_engine: ScopeEngine) -> None:
    assert scope_engine.check("203.0.114.9").status == UNKNOWN


def test_documentation_ranges_are_usable_lab_targets(scope_engine: ScopeEngine) -> None:
    """RFC 5737 ranges are the normal CTF target and can never route internally."""
    assert scope_engine.check("203.0.113.9").status == IN_SCOPE


def test_private_addresses_are_refused_even_when_listed() -> None:
    engagement = Engagement(
        provider="lab",
        program_name="Internal lab",
        targets=[Target("10.0.0.0/8", "cidr"), Target("192.168.1.10", "ip")],
    )
    engine = ScopeEngine.from_engagement(engagement, active=True)
    assert engine.check("10.1.2.3").status == OUT_OF_SCOPE
    assert engine.check("192.168.1.10").status == OUT_OF_SCOPE


def test_private_networks_can_be_allowed_for_a_lab() -> None:
    engagement = Engagement(
        provider="lab", program_name="Internal lab", targets=[Target("10.0.0.0/8", "cidr")]
    )
    engine = ScopeEngine.from_engagement(
        engagement, active=True, deny_private_networks=False
    )
    assert engine.check("10.1.2.3").status == IN_SCOPE


def test_reserved_endpoints_are_always_refused(scope_engine: ScopeEngine) -> None:
    for address in ("127.0.0.1", "169.254.169.254", "0.0.0.0", "::1"):
        assert scope_engine.check(address).status == OUT_OF_SCOPE, address


def test_metadata_hostname_is_refused(scope_engine: ScopeEngine) -> None:
    assert scope_engine.check("metadata.google.internal").status == OUT_OF_SCOPE


# --- URLs -----------------------------------------------------------------


def test_url_resolves_by_host(scope_engine: ScopeEngine) -> None:
    assert scope_engine.check("https://api.acme.test/v1/users").status == IN_SCOPE


def test_url_on_excluded_host_is_out_of_scope(scope_engine: ScopeEngine) -> None:
    assert scope_engine.check("https://admin.acme.test/console").status == OUT_OF_SCOPE


def test_url_path_rule_matches_subpath() -> None:
    engagement = Engagement(
        provider="bugcrowd",
        program_name="P",
        targets=[Target("https://api.example.com/v2/", "url")],
    )
    engine = ScopeEngine.from_engagement(engagement, active=True)
    assert engine.check("https://api.example.com/v2/users").status == IN_SCOPE
    assert engine.check("https://api.example.com/v1/users").status == UNKNOWN


def test_scheme_is_preserved_in_the_parsed_target() -> None:
    ref = parse_target("http://api.acme.test/x")
    assert ref.scheme == "http"
    assert ref.host == "api.acme.test"
    assert ref.path == "/x"


# --- exclusions -----------------------------------------------------------


def test_exclusion_overrides_wildcard_inclusion(scope_engine: ScopeEngine) -> None:
    """The behaviour the spec calls out explicitly."""
    assert scope_engine.check("api.acme.test").status == IN_SCOPE
    assert scope_engine.check("admin.acme.test").status == OUT_OF_SCOPE


def test_exclusion_reports_a_conflict(scope_engine: ScopeEngine) -> None:
    decision = scope_engine.check("admin.acme.test")
    assert decision.conflict is True
    # The message has to name both sides and say which one won, otherwise a
    # researcher cannot tell a real exclusion from a scope-parsing mistake.
    assert "*.acme.test" in decision.conflict_detail
    assert "admin.acme.test" in decision.conflict_detail
    assert "exclusion takes precedence" in decision.conflict_detail


def test_exclusion_is_never_promoted_by_an_inclusion(scope_engine: ScopeEngine) -> None:
    """Even an exactly-listed inclusion cannot override an exclusion."""
    engagement = Engagement(
        provider="bugcrowd",
        program_name="P",
        targets=[Target("admin.acme.test", "domain"), Target("*.acme.test", "wildcard_domain")],
        exclusions=[Target("admin.acme.test", "domain", in_scope=False)],
    )
    engine = ScopeEngine.from_engagement(engagement, active=True)
    decision = engine.check("admin.acme.test")
    assert decision.status == OUT_OF_SCOPE
    assert decision.conflict is True


def test_out_of_scope_in_targets_list_is_honoured() -> None:
    engagement = Engagement(
        provider="bugcrowd",
        program_name="P",
        targets=[
            Target("*.acme.test", "wildcard_domain"),
            Target("admin.acme.test", "domain", in_scope=False),
        ],
    )
    engine = ScopeEngine.from_engagement(engagement, active=True)
    assert engine.check("admin.acme.test").status == OUT_OF_SCOPE


# --- repositories, mobile, cloud -------------------------------------------


def test_repository_and_subpath(scope_engine: ScopeEngine) -> None:
    assert scope_engine.check("github.com/acme/webapp").status == IN_SCOPE
    assert scope_engine.check("github.com/acme/webapp/src/api").status == IN_SCOPE


def test_unrelated_repository_is_unknown(scope_engine: ScopeEngine) -> None:
    assert scope_engine.check("github.com/attacker/repo").status == UNKNOWN


def test_mobile_app_identifier(scope_engine: Engagement) -> None:
    engagement = Engagement(
        provider="bugcrowd",
        program_name="P",
        targets=[Target("com.acme.mobile", "mobile_application")],
    )
    engine = ScopeEngine.from_engagement(engagement, active=True)
    assert engine.check("com.acme.mobile").status == IN_SCOPE
    assert engine.check("com.evil.mobile").status == UNKNOWN


def test_cloud_arn() -> None:
    engagement = Engagement(
        provider="bugcrowd", program_name="P", targets=[Target("arn:aws:s3:::acme-*", "cloud_resource")]
    )
    engine = ScopeEngine.from_engagement(engagement, active=True)
    assert engine.check("arn:aws:s3:::acme-prod").status == IN_SCOPE


# --- activation -----------------------------------------------------------


def test_inactive_engine_never_permits(inactive_scope_engine: ScopeEngine) -> None:
    """A loaded-but-unconfirmed manifest must not be usable."""
    for target in ("api.acme.test", "shop.acme.test", "203.0.113.9"):
        decision = inactive_scope_engine.check(target)
        assert decision.status == UNKNOWN
        assert decision.allowed is False
        assert "not activated" in decision.reason


def test_no_engagement_is_unknown() -> None:
    engine = ScopeEngine()
    assert engine.check("api.acme.test").status == UNKNOWN
    assert engine.check("api.acme.test").reason == "no engagement is loaded"


# --- malformed input ------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        None,
        "not a target!!",
        "http://",
        "ftp://api.acme.test",
        "api.acme.test\r\nX-Injected: 1",
        "api.acme.test\x00",
        "javascript:alert(1)",
        "api.acme.test:99999",
        "-badlabel.example.com",
        "a" * 3000 + ".acme.test",
        "../../etc/passwd",
        "localhost",
    ],
)
def test_malformed_targets_are_never_in_scope(scope_engine: ScopeEngine, target: object) -> None:
    decision = scope_engine.check(target)  # type: ignore[arg-type]
    assert decision.status in (OUT_OF_SCOPE, UNKNOWN)
    assert decision.allowed is False


def test_control_characters_are_rejected_not_silently_trimmed(scope_engine: ScopeEngine) -> None:
    """A newline in a target is a smuggling attempt, not a typo."""
    decision = scope_engine.check("api.acme.test\nGET /admin HTTP/1.1")
    assert decision.allowed is False


# --- determinism ----------------------------------------------------------


def test_engine_is_deterministic(scope_engine: ScopeEngine) -> None:
    verdicts = {t: scope_engine.check(t).status for t in ("api.acme.test", "admin.acme.test", "x.example.net")}
    for _ in range(50):
        assert {t: scope_engine.check(t).status for t in verdicts} == verdicts


def test_unknown_is_never_promoted_by_retrying_with_another_form(scope_engine: ScopeEngine) -> None:
    """Reformulating an unresolvable target must not launder it into scope."""
    # A host no rule covers, written four different ways. Reformatting an
    # unresolvable target must not launder it into scope.
    forms = [
        "unknown.example.net",
        "https://unknown.example.net/",
        "UNKNOWN.EXAMPLE.NET",
        "unknown.example.net:443",
    ]
    assert {scope_engine.check(form).status for form in forms} == {UNKNOWN}


def test_filter_in_scope_batches(scope_engine: ScopeEngine) -> None:
    results = scope_engine.filter_in_scope(["api.acme.test", "admin.acme.test", "nope.example.net"])
    assert results == {
        "api.acme.test": IN_SCOPE,
        "admin.acme.test": OUT_OF_SCOPE,
        "nope.example.net": UNKNOWN,
    }


def test_block_message_names_the_rule(scope_engine: ScopeEngine) -> None:
    message = scope_engine.check("admin.acme.test").block_message()
    assert "SRO POLICY DENIED" in message
    assert "admin.acme.test" in message
    assert "No network request was made." in message
