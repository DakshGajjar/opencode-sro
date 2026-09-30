"""Model routing tests.

The rule that matters: sensitive material never leaves the machine. Everything
else in this file checks that the cheap tasks land on the cheap model and that
the researcher, not the model, controls the external toggle.
"""

from __future__ import annotations

import pytest

from sro.core.config import Config
from sro.core.routing import (
    EXTERNAL,
    FAST_LOCAL,
    LOCAL_REASONING,
    SECURITY_LOCAL,
    ModelRouter,
    classify_sensitivity,
)

SENSITIVE_PAYLOADS = [
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.aaaa.bbbb",
    "password=hunter2",
    "api_key: sk-abcdefghijklmnop",
    "AWS AKIAIOSFODNN7EXAMPLE",
    "ghp_abcdefghijklmnopqrstuvwxyz012345",
    "-----BEGIN RSA PRIVATE KEY-----",
    "Set-Cookie: session=abc123def456",
    "customer data from the production database",
    "10.0.0.5 is the internal IP of the jump host",
    "192.168.1.1 gateway",
    "this is confidential and under NDA",
    "unpublished vulnerability details",
]

CLEAN_PAYLOADS = [
    "GET / 200 1.2ms",
    "the response body contained a stack trace",
    "analyze this nginx access log",
    "here is the public program description",
]


@pytest.mark.parametrize("payload", SENSITIVE_PAYLOADS)
def test_sensitive_payloads_are_detected(payload: str) -> None:
    assessment = classify_sensitivity(payload)
    assert assessment.is_sensitive, payload
    assert assessment.markers


@pytest.mark.parametrize("payload", CLEAN_PAYLOADS)
def test_clean_payloads_are_not_flagged(payload: str) -> None:
    assert not classify_sensitivity(payload).is_sensitive, payload


def test_a_declared_level_can_raise_but_never_lower_sensitivity() -> None:
    """An agent cannot declare a payload of tokens 'normal'."""
    assessment = classify_sensitivity("password=hunter2", declared="normal")
    assert assessment.is_sensitive


def test_declaring_secret_raises_the_level() -> None:
    assert classify_sensitivity("nothing special", declared="secret").level == "secret"


# --- task classes ---------------------------------------------------------


@pytest.mark.parametrize(
    "task,expected",
    [
        ("parse the scope table into target entries", FAST_LOCAL),
        ("extract the scope from this html", FAST_LOCAL),
        ("which tool should I pick for this", FAST_LOCAL),
        ("parse the json response body", FAST_LOCAL),
        ("classify these findings", FAST_LOCAL),
        ("analyze this stack trace from the gateway", LOCAL_REASONING),
        ("review the stack trace", LOCAL_REASONING),
        ("review the source code for injection bugs", LOCAL_REASONING),
        ("synthesize the evidence into a report", LOCAL_REASONING),
        ("generate a hypothesis about the attack surface", SECURITY_LOCAL),
    ],
)
def test_task_classes_route_as_configured(config: Config, task: str, expected: str) -> None:
    decision = ModelRouter(config).route(task=task)
    assert decision.route == expected
    assert decision.external is False


def test_cheap_work_goes_to_the_cheap_model(config: Config) -> None:
    decision = ModelRouter(config).route(task="classify these findings")
    assert decision.model_id == "ollama/lfm2.5"


# --- the sensitivity rule -------------------------------------------------


@pytest.mark.parametrize("payload", SENSITIVE_PAYLOADS)
def test_sensitive_payload_never_routes_external(config: Config, payload: str) -> None:
    config.allow_external = True
    decision = ModelRouter(config).route(task="analyse this", payload=payload, prefer_external=True)
    assert decision.external is False
    assert decision.sensitivity["level"] in ("sensitive", "secret")


def test_external_override_is_ignored_for_sensitive_material(config: Config) -> None:
    config.allow_external = True
    router = ModelRouter(config)
    router.set_mode("external")
    decision = router.route(task="analyse this", sensitivity="secret")
    assert decision.external is False
    assert "override was ignored" in decision.reason


def test_large_context_uses_a_reasoning_model_by_default(config: Config) -> None:
    decision = ModelRouter(config).route(task="review everything", context_size=500_000)
    assert decision.external is False


def test_large_context_can_go_external_when_permitted(config: Config) -> None:
    config.allow_external = True
    config.routes["external"] = type(config.routes["fast_local"])(
        "external", "openrouter", "some/model", external=True
    )
    decision = ModelRouter(config).route(task="review everything", context_size=500_000, prefer_external=True)
    assert decision.route == EXTERNAL
    assert decision.external is True


def test_external_refused_when_not_configured(config: Config) -> None:
    config.routes["external"] = type(config.routes["fast_local"])(
        "external", "openrouter", "some/model", external=True
    )
    decision = ModelRouter(config).route(task="review everything", prefer_external=True)
    assert decision.external is False
    assert "not permitted" in decision.reason


# --- researcher control ---------------------------------------------------


def test_set_mode_external_requires_config_permission(config: Config) -> None:
    with pytest.raises(PermissionError) as excinfo:
        ModelRouter(config).set_mode("external")
    assert "routing.allow_external" in str(excinfo.value)


def test_set_mode_accepts_aliases(config: Config) -> None:
    router = ModelRouter(config)
    assert router.set_mode("local")["mode"] == "local"
    assert router.set_mode("qwen")["mode"] == LOCAL_REASONING
    assert router.set_mode("spark")["mode"] == SECURITY_LOCAL
    assert router.set_mode("auto")["mode"] == "auto"


def test_unknown_mode_is_rejected(config: Config) -> None:
    with pytest.raises(ValueError):
        ModelRouter(config).set_mode("gpt-9000")


def test_local_pin_overrides_a_task_that_wants_external(config: Config) -> None:
    config.allow_external = True
    router = ModelRouter(config)
    router.set_mode("local")
    decision = router.route(task="review everything", context_size=500_000, prefer_external=True)
    assert decision.external is False
    assert decision.overridden is True


# --- egress guard ---------------------------------------------------------


def test_guard_redacts_a_sensitive_payload_on_an_external_route(config: Config) -> None:
    config.allow_external = True
    config.routes["external"] = type(config.routes["fast_local"])(
        "external", "openrouter", "some/model", external=True
    )
    router = ModelRouter(config)
    router.set_mode("external")
    decision = router.route(task="analyse this")
    assert decision.external is True
    payload = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.aaaa.bbbb"
    cleaned, info = router.guard(decision, payload)
    assert info["redacted"] is True
    assert "eyJhbGciOiJIUzI1NiJ9" not in cleaned


def test_guard_passes_a_clean_payload_through(config: Config) -> None:
    config.allow_external = True
    config.routes["external"] = type(config.routes["fast_local"])(
        "external", "openrouter", "some/model", external=True
    )
    router = ModelRouter(config)
    router.set_mode("external")
    decision = router.route(task="analyse this")
    assert decision.external is True
    payload = "GET / 200"
    cleaned, info = router.guard(decision, payload)
    assert cleaned == payload
    assert info["redacted"] is False


def test_guard_is_a_no_op_on_a_local_route(config: Config) -> None:
    router = ModelRouter(config)
    decision = router.route(task="analyse this")
    payload = "password=hunter2"
    cleaned, info = router.guard(decision, payload)
    assert cleaned == payload
    assert info["reason"] == "route is local"


def test_every_routed_model_is_configured(config: Config) -> None:
    """A route that resolves to nothing would silently fall back to a default."""
    router = ModelRouter(config)
    for task in ("parse the scope", "analyze the log", "review the code", "write a report"):
        decision = router.route(task=task)
        assert decision.model_id
        assert "/" in decision.model_id
        assert decision.decision_id.startswith("route_")
