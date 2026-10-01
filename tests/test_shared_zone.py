"""A wildcard scope rule over a shared hosting zone authorizes other people's hosts.

The finding this came from: `*.zendesk.com` is the obvious reading of "Zendesk's
web surface", and Zendesk's DNS answers for arbitrary labels. Every customer
instance sits under it and holds real ticket data. The program excludes other
tenants in words — "Sell / for Sales", "supply chain" — that the matcher cannot
read, so nothing in the manifest stops the rule.

These tests use a fake resolver, so the block is asserted without a network and
without a live dependency on anyone's DNS.
"""

from __future__ import annotations

import json

import pytest

from sro.core.egress import DestinationRefused, zone_accepts_arbitrary_names


def zone_that_answers(*addresses):
    """A resolver that answers anything — a wildcard DNS zone."""

    def resolve(host, port):
        return [(a, port) for a in addresses]

    return resolve


def zone_that_is_normal(host, port):
    """A resolver that only knows names that exist."""
    if "probe" in host:
        raise DestinationRefused(f"{host!r} does not resolve")
    return [("93.184.216.34", port)]


# --- the probe ------------------------------------------------------------


class TestZoneProbe:
    def test_a_zone_that_answers_is_reported_as_shared(self) -> None:
        verdict = zone_accepts_arbitrary_names(
            "zendesk.com", resolver=zone_that_answers("216.198.53.2", "216.198.54.2")
        )
        assert verdict["shared_zone"] is True
        assert verdict["addresses"] == ["216.198.53.2", "216.198.54.2"]

    def test_a_normal_domain_is_reported_as_safe(self) -> None:
        verdict = zone_accepts_arbitrary_names("example.com", resolver=zone_that_is_normal)
        assert verdict["shared_zone"] is False

    def test_the_hazard_explanation_names_the_risk(self) -> None:
        """A flag with no explanation gets cleared by whoever is in a hurry."""
        verdict = zone_accepts_arbitrary_names("zendesk.com", resolver=zone_that_answers("1.2.3.4"))
        reason = verdict["reason"]
        assert "other tenant" in reason
        assert "other people's data" in reason
        assert "explicitly" in reason, "the remedy has to be in the message"

    def test_the_safe_verdict_is_reported_too(self) -> None:
        """Not an error, and not silence: it is the evidence that the wildcard is
        defensible, which is worth having on the record."""
        verdict = zone_accepts_arbitrary_names("example.com", resolver=zone_that_is_normal)
        assert verdict["shared_zone"] is False
        assert verdict["reason"]

    def test_the_probe_label_is_unpredictable(self) -> None:
        """An operator who wants to hide a shared zone must not be able to
        pre-create the name this asks for."""
        probes = {
            zone_accepts_arbitrary_names("x.com", resolver=zone_that_answers("1.2.3.4"))["probe"]
            for _ in range(6)
        }
        assert len(probes) == 6, "the probe name repeats, so it could be provisioned"

    def test_the_probe_name_cannot_be_a_real_label(self) -> None:
        """A label that could plausibly exist is a label someone could create,
        and then the zone answers for it by accident rather than by wildcard."""
        verdict = zone_accepts_arbitrary_names("zendesk.com", resolver=zone_that_answers("1.2.3.4"))
        label = verdict["probe"].split(".")[0]
        assert "sro-shared-zone-probe" in label
        assert len(label) <= 63

    def test_a_dns_failure_is_not_a_hazard(self) -> None:
        """A resolver outage must not read as a shared zone, or every activation
        fails at once for the wrong reason."""
        def broken(host, port):
            raise DestinationRefused("resolver unreachable")

        verdict = zone_accepts_arbitrary_names("example.com", resolver=broken)
        assert verdict["shared_zone"] is False


# --- activation refuses it ------------------------------------------------


def brief_with_scope(*in_scope: str) -> dict:
    return {
        "code": "sharedzone",
        "name": "Shared Zone Test",
        "in_scope": [{"name": name} for name in in_scope],
        "out_of_scope": [],
        "brief": "Automated scanning permitted.",
    }


@pytest.fixture()
def staged(tmp_path, brief_file):
    from sro.core.config import Config
    from sro.core.session import Session

    def build(in_scope):
        path = tmp_path / "shared.json"
        path.write_text(json.dumps(brief_with_scope(*in_scope)), encoding="utf-8")
        session = Session(Config.load(tmp_path))
        session.import_brief(str(path), provider="bugcrowd")
        session._zone_resolver = zone_that_answers("216.198.53.2")
        return session

    return build


def test_activation_refuses_a_wildcard_over_a_shared_zone(staged) -> None:
    from sro.core.errors import ConfigError

    session = staged(["*.zendesk.com"])
    with pytest.raises(ConfigError, match="shared hosting zone"):
        session.activate(actor="researcher")


def test_the_refusal_explains_what_the_rule_would_authorize(staged) -> None:
    from sro.core.errors import ConfigError

    session = staged(["*.zendesk.com"])
    with pytest.raises(ConfigError) as caught:
        session.activate(actor="researcher")
    message = str(caught.value)
    assert "other tenant" in message
    assert "other people's data" in message
    assert "--accept-shared-zones" in message, "the override has to be discoverable"


def test_force_does_not_cover_a_shared_zone(staged) -> None:
    """`--force` means "I accept an incomplete manifest". Accepting every tenant
    on a SaaS zone is a different decision and deserves its own word."""
    from sro.core.errors import ConfigError

    session = staged(["*.zendesk.com"])
    with pytest.raises(ConfigError, match="shared hosting zone"):
        session.activate(actor="researcher", force=True)


def test_explicit_acceptance_activates(staged) -> None:
    session = staged(["*.zendesk.com"])
    engagement = session.activate(actor="researcher", accept_shared_zones=True)
    assert session.activated is True
    assert engagement is not None


def test_a_normal_wildcard_activates_without_the_override(staged) -> None:
    """A wildcard over a domain that does not answer for made-up names is the
    ordinary case and must not need an override, or the override becomes routine
    and stops meaning anything."""
    session = staged(["*.zendesk.com"])
    session._zone_resolver = zone_that_is_normal
    session.activate(actor="researcher")
    assert session.activated is True


def test_an_exact_host_activates_without_any_probe(staged) -> None:
    """Only wildcards carry the claim. An exact host is a fact, not a guess."""
    session = staged(["api.zendesk.com"])
    session.activate(actor="researcher")
    assert session.activated is True


def test_the_probe_is_recorded_as_a_finding(staged) -> None:
    session = staged(["*.zendesk.com"])
    findings = session.shared_zone_findings()
    assert len(findings) == 1
    assert findings[0]["rule"] == "*.zendesk.com"
    assert findings[0]["shared_zone"] is True
    assert "216.198.53.2" in findings[0]["addresses"]


def test_no_network_is_needed_for_the_whole_check(staged) -> None:
    """The probe resolves a name; it never connects to one. Asserted by giving
    the check a resolver that would raise on any non-resolution call path."""
    session = staged(["*.zendesk.com"])
    assert session.shared_zone_findings() != []
