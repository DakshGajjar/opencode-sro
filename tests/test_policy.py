"""Policy engine tests.

The required mapping is IN_SCOPE -> ALLOW, OUT_OF_SCOPE -> DENY,
UNKNOWN -> DENY/ASK. Everything else in this file checks that the ladder cannot
be short-circuited by an agent, a config value, or a badly-worded tool call.
"""

from __future__ import annotations

import pytest

from sro.core.config import Config
from sro.core.engagement import Engagement, Restriction, Target
from sro.core.errors import ConfigError
from sro.core.policy import (
    AD,
    ALLOW,
    ASK,
    AUTH,
    CODE,
    DENY,
    WEB,
    PolicyEngine,
    PolicyRequest,
    RateLimiter,
)
from sro.core.scope import ScopeEngine


def _request(**overrides) -> PolicyRequest:
    base = {
        "tool": "http_request",
        "action": "http_get",
        "target": "api.acme.test",
        "capability": WEB,
    }
    base.update(overrides)
    return PolicyRequest(**base)


# --- the required mapping -------------------------------------------------


def test_in_scope_allows(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request())
    assert decision.result == ALLOW
    assert decision.scope_status == "IN_SCOPE"


def test_out_of_scope_denies(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request(target="admin.acme.test"))
    assert decision.result == DENY
    assert decision.code == "out_of_scope"
    assert decision.scope_status == "OUT_OF_SCOPE"


def test_unknown_denies(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request(target="nowhere.example.net"))
    assert decision.result == DENY
    assert decision.code == "scope_unknown"
    assert decision.scope_status == "UNKNOWN"


def test_unknown_can_ask_but_never_allow(config: Config, engagement: Engagement) -> None:
    """`unknown_scope: ask` is a UX choice. It must not become a bypass."""
    config.unknown_scope_action = "ask"
    engine = PolicyEngine(config, ScopeEngine.from_engagement(engagement, active=True), engagement, True)
    decision = engine.evaluate(_request(target="nowhere.example.net"))
    assert decision.result == ASK
    assert decision.allowed is False


def test_unknown_scope_cannot_be_configured_to_allow() -> None:
    with pytest.raises(ConfigError) as excinfo:
        Config.from_dict({"policy": {"unknown_scope": "allow"}})
    assert "never be set to allow" in str(excinfo.value)


def test_out_of_scope_cannot_be_relaxed() -> None:
    with pytest.raises(ConfigError):
        Config.from_dict({"policy": {"out_of_scope": "ask"}})


# --- the ladder -----------------------------------------------------------


def test_no_engagement_denies(config: Config) -> None:
    engine = PolicyEngine(config, None, None, False)
    decision = engine.evaluate(_request())
    assert decision.result == DENY
    assert decision.code == "no_engagement"


def test_inactive_engagement_denies(config: Config, engagement: Engagement) -> None:
    engine = PolicyEngine(config, ScopeEngine.from_engagement(engagement, active=True), engagement, False)
    decision = engine.evaluate(_request())
    assert decision.result == DENY
    assert decision.code == "engagement_not_active"


def test_undeclared_capability_denies(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request(capability="ROOT"))
    assert decision.result == DENY
    assert decision.code == "capability_mismatch"


def test_capability_cannot_be_claimed(policy_engine: PolicyEngine) -> None:
    """The capability field is a claim; the catalog is the authority.

    A caller that declares the local-only CODE capability for a network action
    would otherwise skip the scope check entirely.
    """
    decision = policy_engine.evaluate(_request(capability=CODE, action="http_get"))
    assert decision.result == DENY
    assert decision.code == "capability_mismatch"
    assert "belongs to capability WEB" in decision.reason


def test_capability_may_be_omitted_and_is_derived(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request(capability=""))
    assert decision.result == ALLOW
    assert decision.capability == WEB


def test_unknown_tool_is_denied(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request(tool="not_a_real_tool"))
    assert decision.result == DENY
    assert decision.code == "unknown_tool"


def test_network_capability_requires_a_target(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request(target=""))
    assert decision.result == DENY
    assert decision.code == "missing_target"


def test_local_capability_needs_no_target(config: Config, engagement: Engagement) -> None:
    engine = PolicyEngine(config, ScopeEngine.from_engagement(engagement, active=True), engagement, True)
    decision = engine.evaluate(
        _request(tool="code_search", action="search", capability=CODE, target="")
    )
    assert decision.result == ALLOW


# --- engagement restrictions ----------------------------------------------


def test_forbidden_technique_is_denied_even_in_scope(config: Config) -> None:
    engagement = Engagement(
        provider="bugcrowd",
        program_name="P",
        targets=[Target("api.acme.test", "domain")],
        testing_restrictions=[Restriction("denial_of_service", "forbidden", "DoS prohibited")],
        forbidden_testing=["denial_of_service"],
    )
    engine = PolicyEngine(config, ScopeEngine.from_engagement(engagement, active=True), engagement, True)
    # "dos" is a conditional action: it only exists as an action when the
    # engagement permits it, which is exactly what makes the refusal testable.
    decision = engine.evaluate(_request(tool="http_request", action="dos", capability=WEB))
    assert decision.result == DENY
    assert decision.code == "restriction_forbidden"
    assert decision.scope_status == ""  # refused before the scope check


def test_conditional_technique_needs_confirmation(config: Config) -> None:
    engagement = Engagement(
        provider="bugcrowd",
        program_name="P",
        targets=[Target("api.acme.test", "domain")],
        testing_restrictions=[Restriction("password_spraying", "conditional", "lab only")],
    )
    engine = PolicyEngine(config, ScopeEngine.from_engagement(engagement, active=True), engagement, True)
    decision = engine.evaluate(_request(tool="auth_session_test", action="password_spray", capability=AUTH))
    assert decision.result == ASK
    assert decision.code == "conditional_action_unconfirmed"


def test_permitted_technique_is_allowed(config: Config) -> None:
    engagement = Engagement(
        provider="bugcrowd",
        program_name="P",
        targets=[Target("api.acme.test", "domain")],
        testing_restrictions=[Restriction("password_spraying", "permitted", "3 accounts per hour")],
        allowed_testing=["password_spraying"],
    )
    engine = PolicyEngine(config, ScopeEngine.from_engagement(engagement, active=True), engagement, True)
    decision = engine.evaluate(_request(tool="auth_session_test", action="password_spray", capability=AUTH, destructive=True, user_approved=True))
    assert decision.result == ALLOW


def test_unstated_restriction_asks_rather_than_guessing(config: Config) -> None:
    engagement = Engagement(
        provider="bugcrowd",
        program_name="P",
        targets=[Target("api.acme.test", "domain")],
    )
    engine = PolicyEngine(config, ScopeEngine.from_engagement(engagement, active=True), engagement, True)
    decision = engine.evaluate(_request(tool="ad_query", action="social_engineering", capability=AD))
    assert decision.result in (ASK, DENY)
    assert decision.result is not ALLOW


# --- destructive actions --------------------------------------------------


def test_destructive_asks_without_approval(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request(action="http_post_test"))
    assert decision.result == ASK
    assert decision.code == "destructive_requires_approval"


def test_destructive_allowed_with_explicit_approval(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request(action="http_post_test", user_approved=True))
    assert decision.result == ALLOW


def test_destructive_cannot_be_disabled_into_silence(config: Config, engagement: Engagement) -> None:
    config.destructive_requires_ask = False
    engine = PolicyEngine(config, ScopeEngine.from_engagement(engagement, active=True), engagement, True)
    decision = engine.evaluate(_request(action="http_post_test"))
    assert decision.result == DENY
    assert decision.code == "destructive_disabled"


def test_approval_does_not_rescue_an_out_of_scope_target(policy_engine: PolicyEngine) -> None:
    """A researcher approving a destructive action does not authorize a target."""
    decision = policy_engine.evaluate(
        _request(action="http_post_test", target="admin.acme.test", user_approved=True)
    )
    assert decision.result == DENY
    assert decision.code == "out_of_scope"


# --- authentication -------------------------------------------------------


def test_auth_requirement_asks_when_unsatisfied(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request(tool="auth_session_test", action="auth_test", capability=AUTH, destructive=True, user_approved=True,
                          requires_auth=True, authenticated=False))
    assert decision.result == ASK
    assert decision.code == "auth_required"


def test_auth_requirement_passes_when_satisfied(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request(tool="auth_session_test", action="auth_test", capability=AUTH, destructive=True, user_approved=True,
                          requires_auth=True, authenticated=True))
    assert decision.result == ALLOW


# --- rate limiting --------------------------------------------------------


def test_rate_limit_blocks_after_the_per_host_cap(config: Config, engagement: Engagement) -> None:
    config.rate_limit_per_host_per_minute = 3
    config.rate_limit_per_minute = 100
    engine = PolicyEngine(config, ScopeEngine.from_engagement(engagement, active=True), engagement, True)
    results = [engine.evaluate(_request()).result for _ in range(5)]
    assert results[:3] == [ALLOW, ALLOW, ALLOW]
    assert results[3] == DENY
    assert results[4] == DENY


def test_rate_limit_is_per_host(config: Config, engagement: Engagement) -> None:
    engagement.targets.append(Target("other.acme.test", "domain"))
    config.rate_limit_per_host_per_minute = 2
    config.rate_limit_per_minute = 100
    engine = PolicyEngine(config, ScopeEngine.from_engagement(engagement, active=True), engagement, True)
    for _ in range(2):
        assert engine.evaluate(_request()).result == ALLOW
    assert engine.evaluate(_request()).result == DENY
    assert engine.evaluate(_request(target="other.acme.test")).result == ALLOW


def test_rate_limit_can_be_bypassed_only_by_disabling_it_explicitly(policy_engine: PolicyEngine) -> None:
    decision = policy_engine.evaluate(_request(rate_limited=False))
    assert decision.result == ALLOW
    assert "rate_limit" not in decision.detail


def test_rate_limiter_rolls_its_window() -> None:
    limiter = RateLimiter(global_per_minute=2, per_host_per_minute=2)
    assert limiter.check("h")[0] is True
    assert limiter.check("h")[0] is True
    assert limiter.check("h")[0] is False
    # Force the window open.
    limiter._global_events.clear()
    limiter._host_events["h"].clear()
    assert limiter.check("h")[0] is True


# --- rendering ------------------------------------------------------------


def test_denial_message_states_no_request_was_made(policy_engine: PolicyEngine) -> None:
    message = policy_engine.evaluate(_request(target="admin.acme.test")).render()
    assert "SRO POLICY DENIED" in message
    assert "admin.acme.test" in message
    assert "No network request was made." in message


def test_ask_message_distinguishes_itself_from_a_denial(policy_engine: PolicyEngine) -> None:
    message = policy_engine.evaluate(_request(action="http_post_test")).render()
    assert "SRO POLICY REQUIRES APPROVAL" in message
    assert "requires explicit" in message
    assert "No network request was made." not in message


def test_allow_message_is_informative(policy_engine: PolicyEngine) -> None:
    message = policy_engine.evaluate(_request()).render()
    assert "Policy: ALLOW" in message
    assert "IN_SCOPE" in message


def test_describe_exposes_the_surface_without_exposing_a_host(policy_engine: PolicyEngine) -> None:
    described = policy_engine.describe()
    assert WEB in described["capabilities"]
    assert "http_get" in described["permitted_actions"][WEB]
    assert "denial_of_service" in described["action_restriction_map"].values()


def test_describe_separates_permitted_from_available(policy_engine: PolicyEngine) -> None:
    """A model told it may `crawl` will try, and nothing implements `crawl`.

    The permission set and the availability set are reported separately so the
    distinction survives into the prompt.
    """
    described = policy_engine.describe()
    assert set(described["permitted_actions"]) >= set(described["available_actions"])
    for capability, actions in described["available_actions"].items():
        assert set(actions) <= set(described["permitted_actions"][capability])

    # Everything a catalog tool offers must be in the available set, or a tool
    # would advertise an action the surface says does not exist.
    from sro.core.tools import CATALOG

    for spec in CATALOG.values():
        for action in spec.actions:
            assert action in described["available_actions"][spec.capability], (spec.name, action)


def test_unimplemented_actions_are_named(policy_engine: PolicyEngine) -> None:
    """The honest list: permitted by policy, offered by no tool."""
    unimplemented = policy_engine.describe()["unimplemented_actions"]
    flat = {a for actions in unimplemented.values() for a in actions}
    # These are the ones the review flagged; none has a ToolSpec.
    for action in ("crawl", "scan", "discover", "fingerprint", "sast",
                   "form_interact", "session_replay", "token_inspect"):
        assert action in flat, action


# --- ordering: the cheapest decisive check comes first --------------------


def test_unknown_capability_is_rejected_before_scope_is_consulted(policy_engine: PolicyEngine) -> None:
    """An invalid capability is a programming error, not a scope question."""
    decision = policy_engine.evaluate(_request(capability="NOPE", target="admin.acme.test"))
    assert decision.code in {"capability_mismatch", "unknown_tool"}
