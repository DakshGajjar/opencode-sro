"""Evidence store, verifier and report tests.

The separation between "an agent said so" and "a tool did it" is the property
under test. A researcher must not be able to write its own observation, and a
verifier must not be able to confirm a finding without citing one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sro.core.evidence import (
    HYPOTHESIS,
    INCONCLUSIVE,
    OBSERVED,
    REJECTED,
    VERIFIED,
    EvidenceIntegrityError,
    EvidenceStore,
)
from sro.core.report import generate_report
from sro.core.session import Session
from sro.core.tools import ToolBroker
from sro.core.verifier import Verifier


# --- observations ---------------------------------------------------------


def test_observation_requires_a_tool(evidence: EvidenceStore) -> None:
    with pytest.raises(EvidenceIntegrityError):
        evidence.record_observation(tool="", agent="web", result={"a": 1})


def test_observation_requires_actual_content(evidence: EvidenceStore) -> None:
    """An empty claim is not evidence."""
    with pytest.raises(EvidenceIntegrityError) as excinfo:
        evidence.record_observation(tool="http_request", agent="web", summary="I found a bug")
    assert "no request, response, command or artifact" in str(excinfo.value)


def test_observation_has_no_status_parameter(evidence: EvidenceStore) -> None:
    """The signature is the control: there is no way to declare your own status."""
    import inspect

    parameters = inspect.signature(evidence.record_observation).parameters
    assert "status" not in parameters
    assert "verification_status" not in parameters


def test_observation_stores_the_policy_that_permitted_it(evidence: EvidenceStore) -> None:
    record = evidence.record_observation(
        tool="http_request",
        agent="web",
        target="api.acme.test",
        response={"status_code": 200},
        policy={"result": "ALLOW", "scope_status": "IN_SCOPE"},
    )
    assert record.policy["result"] == "ALLOW"
    assert record.status == OBSERVED


def test_records_get_unique_ids(evidence: EvidenceStore) -> None:
    """Two identical calls in the same second must not collide, or a citation
    becomes ambiguous."""
    ids = {
        evidence.record_observation(
            tool="http_request", agent="web", target="api.acme.test", response={"status_code": 200}
        ).evidence_id
        for _ in range(25)
    }
    assert len(ids) == 25


def test_secrets_are_redacted_before_storage(evidence: EvidenceStore) -> None:
    record = evidence.record_observation(
        tool="http_request",
        agent="web",
        response={"headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.aaaa.bbbb"}},
    )
    assert "eyJhbGciOiJIUzI1NiJ9" not in json.dumps(record.to_dict())
    assert record.redacted is True


def test_oversized_payloads_are_bounded(evidence: EvidenceStore) -> None:
    record = evidence.record_observation(
        tool="http_request", agent="web", response={"body": "A" * 200_000}
    )
    assert len(json.dumps(record.to_dict())) < 40_000
    assert "truncated" in record.response["body"]


# --- hypotheses -----------------------------------------------------------


def test_hypothesis_is_not_an_observation(evidence: EvidenceStore) -> None:
    record = evidence.record_hypothesis(
        agent="web",
        title="Possible IDOR",
        reasoning="identifier looks user controlled",
        suggested_test="request another user's id",
        expected_evidence="200 with another user's data",
    )
    assert record.status == HYPOTHESIS
    assert evidence.observations() == []


def test_inference_requires_cited_basis(evidence: EvidenceStore) -> None:
    with pytest.raises(EvidenceIntegrityError) as excinfo:
        evidence.record_inference(agent="sro", summary="looks exploitable", basis=[])
    assert "at least one evidence id" in str(excinfo.value)


# --- verification ---------------------------------------------------------


def test_verification_cannot_be_written_directly(evidence: EvidenceStore) -> None:
    import inspect

    parameters = inspect.signature(evidence.record_observation).parameters
    assert "status" not in parameters


def test_confirmed_without_cited_evidence_is_impossible(evidence: EvidenceStore) -> None:
    with pytest.raises(EvidenceIntegrityError) as excinfo:
        evidence.record_verification(
            verifier="verifier", finding="F-1", status="CONFIRMED", reasoning="trust me", cited=[]
        )
    assert "no evidence means INCONCLUSIVE" in str(excinfo.value)


def test_verification_cannot_cite_a_nonexistent_artifact(evidence: EvidenceStore) -> None:
    with pytest.raises(EvidenceIntegrityError) as excinfo:
        evidence.record_verification(
            verifier="v", finding="F-1", status="CONFIRMED", reasoning="", cited=["ev_deadbeefdeadbeef"]
        )
    assert "does not exist" in str(excinfo.value)


def test_verification_rejects_an_unknown_verdict(evidence: EvidenceStore) -> None:
    observation = evidence.record_observation(tool="t", agent="a", response={"x": 1})
    with pytest.raises(EvidenceIntegrityError):
        evidence.record_verification(
            verifier="v", finding="F", status="PROBABLY_FINE", reasoning="", cited=[observation.evidence_id]
        )


def test_researcher_cannot_confirm_its_own_hypothesis(evidence: EvidenceStore) -> None:
    hypothesis = evidence.record_hypothesis(
        agent="web", title="Possible IDOR", reasoning="r", suggested_test="t", expected_evidence="e",
        finding="F-1",
    )
    result = Verifier(evidence).verify(
        finding="F-1", cited=[hypothesis.evidence_id], reproduced=True, reproducible=True,
        expected_evidence_present=True, independently_observed=True,
    )
    assert result.verdict == INCONCLUSIVE
    assert any("not OBSERVED" in w for w in result.warnings)


def test_observation_plus_reproduction_confirms(evidence: EvidenceStore) -> None:
    observation = evidence.record_observation(
        tool="http_request", agent="web", target="api.acme.test", response={"status_code": 200}
    )
    result = Verifier(evidence).verify(
        finding="F-1",
        cited=[observation.evidence_id],
        reproduced=True,
        reproducible=True,
        expected_evidence_present=True,
        independently_observed=True,
    )
    assert result.verdict == "CONFIRMED"
    assert result.confidence >= 0.7


def test_evidence_contradicting_the_hypothesis_rejects(evidence: EvidenceStore) -> None:
    observation = evidence.record_observation(
        tool="http_request", agent="web", target="api.acme.test", response={"status_code": 403}
    )
    result = Verifier(evidence).verify(
        finding="F-1", cited=[observation.evidence_id], contradicts_expected=True
    )
    assert result.verdict == REJECTED


def test_observation_without_reproduction_is_inconclusive(evidence: EvidenceStore) -> None:
    observation = evidence.record_observation(
        tool="http_request", agent="web", target="api.acme.test", response={"status_code": 200}
    )
    result = Verifier(evidence).verify(finding="F-1", cited=[observation.evidence_id])
    assert result.verdict == INCONCLUSIVE
    assert result.confidence < 0.7


def test_verdict_is_persisted(evidence: EvidenceStore) -> None:
    observation = evidence.record_observation(tool="t", agent="a", target="api.acme.test", response={"x": 1})
    result = Verifier(evidence).verify(
        finding="F-1", cited=[observation.evidence_id], reproduced=True, reproducible=True,
        expected_evidence_present=True, independently_observed=True,
    )
    statuses = {r.status for r in evidence.by_finding("F-1")}
    assert VERIFIED in statuses
    stored = evidence.get(result.evidence_id)
    assert stored is not None
    assert stored.verification_status == "CONFIRMED"


def test_evidence_from_another_finding_is_not_silently_accepted(evidence: EvidenceStore) -> None:
    observation = evidence.record_observation(
        tool="t", agent="a", target="api.acme.test", response={"x": 1}, finding="F-OTHER"
    )
    result = Verifier(evidence).verify(
        finding="F-1", cited=[observation.evidence_id], reproduced=True, reproducible=True,
        expected_evidence_present=True, independently_observed=True,
    )
    assert any("belongs to finding" in w for w in result.warnings)
    assert result.verdict == INCONCLUSIVE


# --- broker integration ---------------------------------------------------


def test_every_allowed_tool_call_produces_evidence(active_session: Session) -> None:
    broker = ToolBroker(active_session.policy_engine(), active_session.evidence_store())
    broker.register("http_request", lambda p, d: {"status_code": 200, "body": "{}"})
    before = active_session.evidence_store().count()
    result = broker.execute(
        tool="http_request",
        target="api.acme.test",
        parameters={"url": "https://api.acme.test/v1/me"},
        agent="web",
    )
    assert result.allowed is True
    assert result.evidence_id
    assert active_session.evidence_store().count() == before + 1


def test_a_denied_call_produces_no_observation(active_session: Session) -> None:
    broker = ToolBroker(active_session.policy_engine(), active_session.evidence_store())
    broker.register("http_request", lambda p, d: {"status_code": 200})
    before = active_session.evidence_store().count()
    result = broker.execute(
        tool="http_request", target="elsewhere.example.net",
        parameters={"url": "https://elsewhere.example.net/"}, agent="web",
    )
    assert result.allowed is False
    assert active_session.evidence_store().count() == before


def test_a_raising_handler_still_records_evidence(active_session: Session) -> None:
    """A tool failure is evidence, not a lost session."""
    broker = ToolBroker(active_session.policy_engine(), active_session.evidence_store())

    def explode(params, decision):
        raise TimeoutError("connection reset")

    broker.register("http_request", explode)
    result = broker.execute(
        tool="http_request", target="api.acme.test",
        parameters={"url": "https://api.acme.test/"}, agent="web",
    )
    assert "TimeoutError" in result.error
    records = active_session.evidence_store().observations()
    assert any("TimeoutError" in r.summary for r in records)


def test_unknown_tool_raises(active_session: Session) -> None:
    from sro.core.errors import UnknownToolError

    broker = ToolBroker(active_session.policy_engine(), active_session.evidence_store())
    with pytest.raises(UnknownToolError):
        broker.execute(tool="shell_exec", target="api.acme.test", parameters={}, agent="web")


def test_undeclared_parameter_is_rejected(active_session: Session) -> None:
    """Parameter smuggling: a caller cannot add a field the schema does not have."""
    broker = ToolBroker(active_session.policy_engine(), active_session.evidence_store())
    broker.register("http_request", lambda p, d: {"status_code": 200})
    with pytest.raises(ValueError) as excinfo:
        broker.execute(
            tool="http_request", target="api.acme.test",
            parameters={"url": "https://api.acme.test/", "extra": "payload"}, agent="web",
        )
    assert "does not accept parameter" in str(excinfo.value)


def test_verb_outside_the_declared_set_is_rejected(active_session: Session) -> None:
    """A parameter may only narrow the action within what the tool declares."""
    from sro.core.tools import CATALOG

    spec = CATALOG["http_request"]
    assert "http_delete" not in spec.actions


# --- reporting ------------------------------------------------------------


def test_report_cites_evidence(active_session: Session) -> None:
    store = active_session.evidence_store()
    broker = ToolBroker(active_session.policy_engine(), store)
    broker.register("http_request", lambda p, d: {"status_code": 200, "body": '{"order":2}'})
    observation = broker.execute(
        tool="http_request", target="api.acme.test",
        parameters={"url": "https://api.acme.test/v1/orders/2", "method": "GET"}, agent="api",
    )
    store.record_hypothesis(
        agent="api", title="IDOR on /v1/orders", reasoning="identifier is user controlled",
        suggested_test="request an order id belonging to another user",
        expected_evidence="200 response containing another user's order",
        target="api.acme.test", finding="F-1",
    )
    report = generate_report(active_session, finding="F-1")
    rendered = report.render()
    assert observation.evidence_id in rendered
    assert "https://api.acme.test/v1/orders/2" in rendered
    assert "has not submitted this" in rendered


def test_report_marks_unverified_sections_as_unproven(active_session: Session) -> None:
    store = active_session.evidence_store()
    store.record_hypothesis(
        agent="web", title="Possible XSS", reasoning="r", suggested_test="t", expected_evidence="e",
        target="api.acme.test", finding="F-2",
    )
    report = generate_report(active_session, finding="F-2")
    assert "UNPROVEN" in report.render()
    assert "Steps to reproduce" in report.unproven_sections or "Impact" in report.unproven_sections
    assert report.verification.get("verdict") in (None, "INCONCLUSIVE")


def test_report_is_written_locally(active_session: Session, tmp_path: Path) -> None:
    output = tmp_path / "report.md"
    report = generate_report(active_session, finding="F-1", output=str(output))
    assert output.exists()
    assert report.path == output
    assert "SRO has not submitted" in output.read_text(encoding="utf-8")


def test_report_quotes_program_rules_as_untrusted(active_session: Session) -> None:
    report = generate_report(active_session)
    rendered = report.render()
    assert "quoted as untrusted data" in rendered
    assert "UNTRUSTED_PLATFORM_CONTENT" in rendered


def test_report_json_output_is_serializable(active_session: Session, tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    generate_report(active_session, output=str(output))
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert "sections" in payload
    assert "citations" in payload


# --- timeline -------------------------------------------------------------


def test_timeline_records_every_action(active_session: Session) -> None:
    store = active_session.evidence_store()
    broker = ToolBroker(active_session.policy_engine(), store)
    broker.register("http_request", lambda p, d: {"status_code": 200})
    broker.execute(
        tool="http_request", target="api.acme.test",
        parameters={"url": "https://api.acme.test/"}, agent="web",
    )
    timeline = store.engagement_timeline()
    assert timeline
    assert any(entry["tool"] == "http_request" for entry in timeline)


def test_audit_log_is_append_only(active_session: Session) -> None:
    from sro.core.audit import EVENT_ENGAGEMENT_ACTIVATED, AuditLog

    log = AuditLog(active_session.config.data_dir)
    assert log.count(EVENT_ENGAGEMENT_ACTIVATED) == 1
    before = len(log.timeline())
    log.record("custom.event", detail="x")
    assert len(log.timeline()) == before + 1


def test_serialized_json_is_coerced_into_a_structure(evidence: EvidenceStore) -> None:
    """A model that sends a JSON object as a string still gets a usable record."""
    record = evidence.record_observation(
        tool="http_request",
        agent="web",
        target="api.acme.test",
        request='{"url": "https://api.acme.test/v1/orders/2", "method": "GET"}',
        response='{"status_code": 200, "body": "{\\"owner\\": \\"testuser-b\\"}"}',
    )
    assert record.request["url"] == "https://api.acme.test/v1/orders/2"
    assert record.request["method"] == "GET"
    assert record.response["status_code"] == 200


def test_non_json_string_content_is_left_alone(evidence: EvidenceStore) -> None:
    record = evidence.record_observation(
        tool="dns_resolve", agent="recon", result="NXDOMAIN for api.acme.test"
    )
    assert record.result == "NXDOMAIN for api.acme.test"


def test_malformed_json_string_is_left_alone(evidence: EvidenceStore) -> None:
    record = evidence.record_observation(tool="t", agent="a", result='{"broken": ')
    assert record.result == '{"broken": '


def test_report_renders_steps_from_a_serialized_request(active_session: Session) -> None:
    store = active_session.evidence_store()
    store.record_observation(
        tool="http_request",
        agent="api",
        target="api.acme.test",
        summary="GET /v1/orders/2 returned 200 with another account's order",
        request='{"url": "https://api.acme.test/v1/orders/2", "method": "GET"}',
        response='{"status_code": 200}',
        finding="F-1",
    )
    rendered = generate_report(active_session, finding="F-1").render()
    assert "https://api.acme.test/v1/orders/2" in rendered
    assert "HTTP 200" in rendered
