"""Evidence store.

Every meaningful action produces a record. The store is the substrate for both
verification and reporting: the reporter may only cite evidence, and the
verifier may only reach a conclusion from evidence.

Epistemic status is the important part. A record is exactly one of:

    OBSERVED    a tool returned this; it happened
    INFERRED    SRO derived this from observed records
    HYPOTHESIS  an agent proposed this; unproven
    VERIFIED    the verifier confirmed it against observed records

The distinction is enforced structurally. `record_observation` is the only way
to create an OBSERVED record, and it requires a tool result. An agent cannot
write itself an OBSERVED record.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from .audit import (
    EVENT_EVIDENCE_RECORDED,
    EVENT_FINDING_PROPOSED,
    EVENT_FINDING_VERIFIED,
    AuditLog,
)
from .errors import SROError
from .util import append_jsonl, read_jsonl, redact, stable_id, truncate, utcnow_iso

OBSERVED = "OBSERVED"
INFERRED = "INFERRED"
HYPOTHESIS = "HYPOTHESIS"
VERIFIED = "VERIFIED"
REJECTED = "REJECTED"
INCONCLUSIVE = "INCONCLUSIVE"

STATUSES = (OBSERVED, INFERRED, HYPOTHESIS, VERIFIED, REJECTED, INCONCLUSIVE)

#: Statuses only the verifier may write.
VERIFIER_ONLY = (VERIFIED, REJECTED, INCONCLUSIVE)

DEFAULT_LIMITS = {
    "request": 8000,
    "response": 16000,
    "result": 8000,
    "command": 4000,
}


class EvidenceIntegrityError(SROError):
    """A record claimed a status it was not entitled to.

    Subclasses SROError so the CLI returns it as a structured error rather
    than a traceback. A stack trace reaching a model is noise that hides the
    actual reason, and the reason is the whole point of the refusal.
    """


@dataclass(slots=True)
class EvidenceRecord:
    evidence_id: str
    timestamp: str
    status: str
    engagement: str
    agent: str
    tool: str
    target: str = ""
    capability: str = ""
    summary: str = ""
    request: Any = None
    response: Any = None
    command: str = ""
    result: Any = None
    screenshots: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    hypothesis: str = ""
    finding: str = ""
    verification_status: str = ""
    policy: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    redacted: bool = False
    actor: str = "tool"

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp,
            "status": self.status,
            "engagement": self.engagement,
            "agent": self.agent,
            "tool": self.tool,
            "capability": self.capability,
            "target": self.target,
            "summary": self.summary,
            "request": self.request,
            "response": self.response,
            "command": self.command,
            "result": self.result,
            "screenshots": list(self.screenshots),
            "artifacts": list(self.artifacts),
            "hypothesis": self.hypothesis,
            "finding": self.finding,
            "verification_status": self.verification_status,
            "policy": self.policy,
            "tags": list(self.tags),
            "redacted": self.redacted,
            "actor": self.actor,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceRecord":
        return cls(
            evidence_id=str(data.get("evidence_id", "")),
            timestamp=str(data.get("timestamp", "")),
            status=str(data.get("status", INFERRED)),
            engagement=str(data.get("engagement", "")),
            agent=str(data.get("agent", "")),
            tool=str(data.get("tool", "")),
            capability=str(data.get("capability", "")),
            target=str(data.get("target", "")),
            summary=str(data.get("summary", "")),
            request=data.get("request"),
            response=data.get("response"),
            command=str(data.get("command", "")),
            result=data.get("result"),
            screenshots=[str(s) for s in data.get("screenshots") or []],
            artifacts=[str(a) for a in data.get("artifacts") or []],
            hypothesis=str(data.get("hypothesis", "")),
            finding=str(data.get("finding", "")),
            verification_status=str(data.get("verification_status", "")),
            policy=dict(data.get("policy") or {}),
            tags=[str(t) for t in data.get("tags") or []],
            redacted=bool(data.get("redacted", False)),
            actor=str(data.get("actor", "tool")),
        )


def _coerce_structure(value: Any) -> Any:
    """Parse a serialized JSON payload into a structure.

    A model calling a tool with a free-form argument routinely sends a JSON
    object as a string. Storing that verbatim would make the record unreadable
    to the reporter, which looks for `request.url` and `response.status_code`.
    Anything that does not parse is left exactly as it was: a non-JSON string is
    legitimate content, not something to mangle.
    """
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or text[0] not in "{[":
        return value
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return value


class EvidenceStore:
    def __init__(self, config: Any) -> None:
        self.config = config
        self.root = Path(config.evidence_dir)
        self.index = self.root / "evidence.jsonl"
        self.timeline = self.root / "timeline.jsonl"
        self.audit = AuditLog(config.data_dir)
        self._engagement_id = ""
        self._secrets: list[str] = []
        for provider in getattr(config, "providers", {}).values():
            if provider.credentials != "none":
                token = provider.resolve_token()
                if token:
                    self._secrets.append(token)

    # -- paths -------------------------------------------------------------

    def engagement_id(self) -> str:
        return self._engagement_id or "no-engagement"

    def set_engagement(self, engagement_id: str) -> None:
        """Bind the store to an engagement so records carry provenance."""
        self._engagement_id = engagement_id or ""

    # -- creation ----------------------------------------------------------

    def record_observation(
        self,
        *,
        tool: str,
        agent: str,
        target: str = "",
        capability: str = "",
        summary: str = "",
        request: Any = None,
        response: Any = None,
        command: str = "",
        result: Any = None,
        screenshots: list[str] | None = None,
        artifacts: list[str] | None = None,
        policy: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        finding: str = "",
        engagement: str = "",
        actor: str = "tool",
    ) -> EvidenceRecord:
        """Record something a tool actually did.

        This is the only path to an OBSERVED record. There is deliberately no
        `status=` parameter: an agent cannot declare its own guess to be
        something that happened.
        """
        if not tool:
            raise EvidenceIntegrityError("an observation requires the name of the tool that produced it")
        if result is None and response is None and command == "" and not artifacts and not request:
            raise EvidenceIntegrityError(
                f"observation from {tool!r} carries no request, response, command or artifact; "
                "refusing to record an empty claim as evidence"
            )

        record = self._build(
            status=OBSERVED,
            tool=tool,
            agent=agent,
            target=target,
            capability=capability,
            summary=summary,
            request=request,
            response=response,
            command=command,
            result=result,
            screenshots=screenshots,
            artifacts=artifacts,
            policy=policy,
            tags=tags,
            finding=finding,
            engagement=engagement,
            actor=actor,
        )
        return self._append(record)

    def record_inference(
        self,
        *,
        agent: str,
        summary: str,
        basis: list[str],
        engagement: str = "",
    ) -> EvidenceRecord:
        """Record a conclusion SRO derived from existing observations."""
        if not basis:
            raise EvidenceIntegrityError(
                "an inference must cite at least one evidence id; uncited conclusions are not recorded"
            )
        record = self._build(
            status=INFERRED,
            tool="sro.inference",
            agent=agent,
            summary=summary,
            result={"basis": list(basis)},
            engagement=engagement,
            actor="sro",
        )
        return self._append(record)

    def record_hypothesis(
        self,
        *,
        agent: str,
        title: str,
        reasoning: str,
        suggested_test: str,
        expected_evidence: str,
        target: str = "",
        finding: str = "",
        engagement: str = "",
        tags: list[str] | None = None,
    ) -> EvidenceRecord:
        """Record an agent's proposal. Never an observation."""
        record = self._build(
            status=HYPOTHESIS,
            tool="sro.hypothesis",
            agent=agent,
            target=target,
            summary=title,
            result={
                "reasoning": reasoning,
                "suggested_test": suggested_test,
                "expected_evidence": expected_evidence,
            },
            hypothesis=title,
            finding=finding,
            tags=tags,
            engagement=engagement,
            actor=agent,
        )
        self._append(record)
        self.audit.record(
            EVENT_FINDING_PROPOSED,
            agent=agent,
            title=title,
            target=target,
            finding=finding,
        )
        return record

    def record_verification(
        self,
        *,
        verifier: str,
        finding: str,
        status: str,
        reasoning: str,
        cited: list[str],
        reproductions: list[dict[str, Any]] | None = None,
        engagement: str = "",
    ) -> EvidenceRecord:
        """Record the verifier's verdict on a finding.

        Only this function may write VERIFIED/REJECTED/INCONCLUSIVE, and it must
        cite the evidence it relied on. A CONFIRMED verdict with no cited
        observations is rejected outright.
        """
        # CONFIRMED and REJECTED are the verifier's vocabulary; VERIFIED and
        # REJECTED are the store's. Map across so the verdict and the record
        # status cannot drift apart.
        normalized = {
            "CONFIRMED": VERIFIED,
            "VERIFIED": VERIFIED,
            "REJECTED": REJECTED,
            "INCONCLUSIVE": INCONCLUSIVE,
        }.get(status)
        if normalized is None:
            raise EvidenceIntegrityError(
                f"verification status must be CONFIRMED, REJECTED or INCONCLUSIVE, got {status!r}"
            )
        if normalized == VERIFIED and not cited:
            raise EvidenceIntegrityError(
                "a finding cannot be verified without cited evidence; "
                "no evidence means INCONCLUSIVE, not CONFIRMED"
            )

        # Resolve the citations and check their status here, not in Verifier.
        # The CLI and the MCP server both call record_verification directly, so
        # a check that only lives in Verifier would be bypassed by the very path
        # a model uses.
        known: dict[str, EvidenceRecord] = {r.evidence_id: r for r in self.all()}
        missing = [eid for eid in cited if eid not in known]
        if missing:
            raise EvidenceIntegrityError(f"verification cites evidence that does not exist: {missing}")

        if normalized == VERIFIED:
            not_observed = [
                eid for eid in cited if known[eid].status != OBSERVED
            ]
            if not_observed:
                statuses = {eid: known[eid].status for eid in not_observed}
                raise EvidenceIntegrityError(
                    "a finding can only be confirmed from observed evidence; these citations are "
                    f"not observations: {statuses}. A hypothesis is a claim, not a confirmation. "
                    "Record the test result with record_observation first, or return INCONCLUSIVE."
                )

        record = self._build(
            status=normalized,
            tool="sro.verifier",
            agent=verifier,
            summary=f"{status}: {finding}",
            result={
                "reasoning": reasoning,
                "cited": list(cited),
                "reproductions": reproductions or [],
            },
            finding=finding,
            engagement=engagement,
            actor=verifier,
        )
        # Store the normalised verdict, not the caller's spelling, so the two
        # vocabularies cannot drift apart in the record.
        record.verification_status = {
            "CONFIRMED": "CONFIRMED",
            "VERIFIED": "CONFIRMED",
            "REJECTED": "REJECTED",
            "INCONCLUSIVE": "INCONCLUSIVE",
        }[status]
        self._append(record)
        self.audit.record(
            EVENT_FINDING_VERIFIED,
            verifier=verifier,
            finding=finding,
            status=status,
            cited=len(cited),
        )
        return record

    # -- internals ---------------------------------------------------------

    def _build(self, **kwargs: Any) -> EvidenceRecord:
        engagement = kwargs.pop("engagement", "") or self.engagement_id()
        tool = kwargs.get("tool", "")
        target = kwargs.get("target", "")
        # The fingerprint covers the payload, not just the summary. Two calls
        # in the same second that happen to summarise identically must still get
        # distinct ids, or a citation would be ambiguous.
        fingerprint = stable_id(
            "fp",
            engagement,
            tool,
            target,
            repr(kwargs.get("summary", "")),
            repr(kwargs.get("request")),
            repr(kwargs.get("response")),
            repr(kwargs.get("result")),
        )
        evidence_id = stable_id("ev", fingerprint, utcnow_iso(), str(uuid4()))

        redacted = False

        def _clean(value: Any, limit: int) -> Any:
            nonlocal redacted
            if isinstance(value, str):
                cleaned = redact(value, self._secrets)
                if cleaned != value:
                    redacted = True
                return truncate(cleaned, limit)
            if isinstance(value, dict):
                return {k: _clean(v, limit) for k, v in value.items()}
            if isinstance(value, list):
                return [_clean(v, limit) for v in value[:100]]
            return value

        request = _clean(_coerce_structure(kwargs.get("request")), DEFAULT_LIMITS["request"])
        response = _clean(_coerce_structure(kwargs.get("response")), DEFAULT_LIMITS["response"])
        result = _clean(_coerce_structure(kwargs.get("result")), DEFAULT_LIMITS["result"])
        command = _clean(kwargs.get("command") or "", DEFAULT_LIMITS["command"])

        return EvidenceRecord(
            evidence_id=evidence_id,
            timestamp=utcnow_iso(),
            status=str(kwargs.get("status", INFERRED)),
            engagement=engagement,
            agent=str(kwargs.get("agent", "")),
            tool=str(kwargs.get("tool", "")),
            capability=str(kwargs.get("capability", "")),
            target=str(kwargs.get("target", "")),
            summary=str(kwargs.get("summary", "")),
            request=request,
            response=response,
            command=command,
            result=result,
            screenshots=[str(s) for s in (kwargs.get("screenshots") or [])],
            artifacts=[str(a) for a in (kwargs.get("artifacts") or [])],
            hypothesis=str(kwargs.get("hypothesis", "")),
            finding=str(kwargs.get("finding", "")),
            verification_status=str(kwargs.get("verification_status", "")),
            policy=dict(kwargs.get("policy") or {}),
            tags=[str(t) for t in (kwargs.get("tags") or [])],
            redacted=redacted,
            actor=str(kwargs.get("actor", "tool")),
        )

    def _append(self, record: EvidenceRecord) -> EvidenceRecord:
        append_jsonl(self.index, record.to_dict())
        append_jsonl(
            self.timeline,
            {
                "ts": record.timestamp,
                "evidence_id": record.evidence_id,
                "status": record.status,
                "agent": record.agent,
                "tool": record.tool,
                "target": record.target,
                "summary": record.summary[:280],
                "finding": record.finding,
            },
        )
        self.audit.record(
            EVENT_EVIDENCE_RECORDED,
            evidence_id=record.evidence_id,
            status=record.status,
            tool=record.tool,
            agent=record.agent,
            target=record.target,
        )
        return record

    # -- queries -----------------------------------------------------------

    def all(self) -> list[EvidenceRecord]:
        """Every well-formed record. A corrupt line is skipped, not fatal.

        The store is a file a researcher can hand-edit, and the integrity checks
        call this. Crashing here would turn a corrupt line into a verifier that
        cannot refuse anything.
        """
        records: list[EvidenceRecord] = []
        for row in read_jsonl(self.index):
            if not isinstance(row, dict):
                continue
            try:
                records.append(EvidenceRecord.from_dict(row))
            except (TypeError, ValueError, AttributeError):
                continue
        return records

    def count(self) -> int:
        return len(read_jsonl(self.index))

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        for record in self.all():
            if record.evidence_id == evidence_id:
                return record
        return None

    def by_status(self, status: str) -> list[EvidenceRecord]:
        return [r for r in self.all() if r.status == status]

    def by_target(self, target: str) -> list[EvidenceRecord]:
        return [r for r in self.all() if r.target == target]

    def by_finding(self, finding: str) -> list[EvidenceRecord]:
        return [r for r in self.all() if r.finding == finding]

    def observations(self) -> list[EvidenceRecord]:
        return self.by_status(OBSERVED)

    def hypotheses(self) -> list[EvidenceRecord]:
        return self.by_status(HYPOTHESIS)

    def engagement_timeline(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = read_jsonl(self.timeline)
        return rows[-limit:] if limit > 0 else []

    def summary(self) -> dict[str, Any]:
        records = self.all()
        counts = {status: 0 for status in STATUSES}
        for record in records:
            counts[record.status] = counts.get(record.status, 0) + 1
        return {
            "total": len(records),
            "by_status": counts,
            "engagement": self.engagement_id(),
            "artifacts": sum(len(r.artifacts) for r in records),
            "targets": sorted({r.target for r in records if r.target}),
            "index": str(self.index),
        }
