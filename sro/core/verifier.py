"""Independent verifier.

The researcher proposes. The verifier decides. They are separate roles with
separate powers, and the split is enforced here rather than by asking an agent
to behave differently.

A verdict is one of:

    CONFIRMED       reproduced independently, with cited observed evidence
    REJECTED        the hypothesis did not hold, and the evidence says why
    INCONCLUSIVE    the evidence does not settle it

The one rule that cannot be bent: CONFIRMED requires cited OBSERVED evidence.
A verifier that calls something confirmed without evidence gets INCONCLUSIVE
and a loud note, because "an LLM said it is real" is not a vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .evidence import (
    HYPOTHESIS,
    INCONCLUSIVE,
    OBSERVED,
    VERIFIED,
    EvidenceStore,
)

CONFIRMED = "CONFIRMED"
REJECTED = "REJECTED"

VERDICTS = (CONFIRMED, REJECTED, INCONCLUSIVE)

#: A finding needs at least this much supporting evidence before a CONFIRMED
#: verdict is possible. One artifact is often a misconfiguration, a cached
#: response, or a single misread.
MIN_CITED_OBSERVATIONS = 1

#: Score needed for a CONFIRMED verdict. Below it the finding is INCONCLUSIVE.
#: There is deliberately no "reject" threshold: a thin evidence base means the
#: question is open, not that the hypothesis is wrong.
_CONFIRM_THRESHOLD = 0.7


@dataclass(slots=True)
class VerificationResult:
    verdict: str
    finding: str
    reasoning: str
    cited: list[str] = field(default_factory=list)
    reproduction_steps: list[dict[str, Any]] = field(default_factory=list)
    observations: int = 0
    confidence: float = 0.0
    warnings: list[str] = field(default_factory=list)
    evidence_id: str = ""

    @property
    def confirmed(self) -> bool:
        return self.verdict == CONFIRMED

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "finding": self.finding,
            "reasoning": self.reasoning,
            "cited": list(self.cited),
            "reproduction_steps": list(self.reproduction_steps),
            "observations": self.observations,
            "confidence": round(self.confidence, 2),
            "warnings": list(self.warnings),
            "evidence_id": self.evidence_id,
        }

    def render(self) -> str:
        mark = {CONFIRMED: "✓", REJECTED: "✗", INCONCLUSIVE: "?"}[self.verdict]
        lines = [
            f"{mark} {self.verdict}",
            "",
            f"Finding:     {self.finding}",
            f"Evidence:    {self.observations} observation(s) cited",
            f"Confidence:  {self.confidence:.2f}",
            "",
            "Reasoning:",
            f"  {self.reasoning}",
        ]
        if self.cited:
            lines += ["", "Cited evidence:"]
            lines += [f"  - {eid}" for eid in self.cited]
        if self.reproduction_steps:
            lines += ["", "Reproduction:"]
            for index, step in enumerate(self.reproduction_steps, 1):
                lines.append(f"  {index}. {step.get('step', '')}")
        if self.warnings:
            lines += ["", "Notes:"]
            lines += [f"  ! {w}" for w in self.warnings]
        return "\n".join(lines)


@dataclass(slots=True)
class FindingProposal:
    """What a researcher produced. Explicitly not a finding yet."""

    title: str
    reasoning: str
    suggested_test: str
    expected_evidence: str
    target: str = ""
    finding_id: str = ""
    evidence_id: str = ""


def new_finding_id(title: str, target: str) -> str:
    from .util import stable_id

    return stable_id("fnd", title, target)


class Verifier:
    """Deterministic verification, with the judgement left to a model that must
    cite its evidence.

    The scoring below is intentionally blunt. SRO is not trying to be clever
    about vulnerability semantics; it is trying to make it impossible for a
    confident-sounding paragraph to become a CONFIRMED finding with nothing
    behind it.
    """

    def __init__(self, store: EvidenceStore, *, name: str = "verifier") -> None:
        self.store = store
        self.name = name

    # -- helpers -----------------------------------------------------------

    def _observations_for(self, finding: str, cited: list[str]) -> tuple[list[str], list[str]]:
        """Resolve the cited ids, keeping only real observations."""
        warnings: list[str] = []
        valid: list[str] = []
        for evidence_id in cited:
            record = self.store.get(evidence_id)
            if record is None:
                warnings.append(f"cited evidence {evidence_id} does not exist and was ignored")
                continue
            if record.status != OBSERVED:
                warnings.append(
                    f"cited evidence {evidence_id} is {record.status}, not {OBSERVED}; "
                    "only observations can support a confirmation"
                )
                continue
            if finding and record.finding and record.finding != finding:
                warnings.append(
                    f"cited evidence {evidence_id} belongs to finding {record.finding!r}, "
                    f"not {finding!r}"
                )
                continue
            valid.append(evidence_id)
        return valid, warnings

    def score(
        self,
        *,
        observation_count: int,
        reproduced: bool,
        reproducible: bool = False,
        expected_evidence_present: bool = False,
        contradicts_expected: bool = False,
        independently_observed: bool = False,
    ) -> tuple[float, list[str]]:
        reasons: list[str] = []
        if observation_count <= 0:
            return 0.0, ["no observations were cited"]
        score = 0.2
        reasons.append(f"{observation_count} observation(s) cited")
        if observation_count >= 2:
            score += 0.15
            reasons.append("more than one independent observation")
        if reproduced:
            score += 0.3
            reasons.append("reproduced by the verifier")
        if reproducible:
            score += 0.15
            reasons.append("reproduction is repeatable")
        if expected_evidence_present:
            score += 0.1
            reasons.append("the expected evidence was found")
        if independently_observed:
            score += 0.1
            reasons.append("observed independently of the researcher")
        if contradicts_expected:
            score -= 0.4
            reasons.append("the observation contradicts the hypothesis")
        return max(0.0, min(1.0, score)), reasons

    # -- the verdict -------------------------------------------------------

    def verify(
        self,
        *,
        finding: str,
        cited: list[str],
        reasoning: str = "",
        reproduced: bool = False,
        reproducible: bool = False,
        expected_evidence_present: bool = False,
        contradicts_expected: bool = False,
        independently_observed: bool = False,
        reproduction_steps: list[dict[str, Any]] | None = None,
        engagement: str = "",
    ) -> VerificationResult:
        valid, warnings = self._observations_for(finding, cited)
        score, reasons = self.score(
            observation_count=len(valid),
            reproduced=reproduced,
            reproducible=reproducible,
            expected_evidence_present=expected_evidence_present,
            contradicts_expected=contradicts_expected,
            independently_observed=independently_observed,
        )

        if not valid:
            # No observations cited. There is nothing to confirm and nothing to
            # refute, so the question is open.
            verdict = INCONCLUSIVE
            summary = reasoning or (
                "no OBSERVED evidence was cited, so the hypothesis is neither confirmed nor refuted"
            )
            warnings.append(
                "a finding cannot be confirmed from an unreproduced hypothesis; "
                "run the suggested test and record the result as evidence"
            )
        elif contradicts_expected:
            # Only affirmative counter-evidence refutes a hypothesis. A thin
            # evidence base is inconclusive, never a rejection: absence of
            # proof is not proof of absence.
            verdict = REJECTED
            summary = reasoning or "the available evidence contradicts the hypothesis"
        elif score >= _CONFIRM_THRESHOLD:
            verdict = CONFIRMED
            summary = reasoning or "; ".join(reasons)
        else:
            verdict = INCONCLUSIVE
            summary = reasoning or (
                "the cited evidence is not sufficient to settle the question: " + "; ".join(reasons)
            )
            warnings.append(
                "more evidence is needed before this can move to CONFIRMED; "
                f"score {score:.2f} is below the {_CONFIRM_THRESHOLD} threshold"
            )

        result = VerificationResult(
            verdict=verdict,
            finding=finding,
            reasoning=summary,
            cited=valid,
            reproduction_steps=reproduction_steps or [],
            observations=len(valid),
            confidence=score,
            warnings=warnings,
        )

        record = self.store.record_verification(
            verifier=self.name,
            finding=finding,
            status=INCONCLUSIVE if verdict == INCONCLUSIVE else verdict,
            reasoning=summary,
            cited=valid,
            reproductions=reproduction_steps,
            engagement=engagement,
        )
        result.evidence_id = record.evidence_id
        return result

    def verify_proposal(
        self,
        proposal: FindingProposal,
        **kwargs: Any,
    ) -> VerificationResult:
        """Verify a researcher's proposal, auto-citing evidence tagged for it."""
        cited = list(kwargs.pop("cited", []) or [])
        if not cited:
            for record in self.store.by_finding(proposal.finding_id or proposal.title):
                if record.status == OBSERVED:
                    cited.append(record.evidence_id)
        kwargs.setdefault("reasoning", proposal.reasoning)
        return self.verify(finding=proposal.finding_id or proposal.title, cited=cited, **kwargs)

    def list_hypotheses(self) -> list[dict[str, Any]]:
        return [
            {
                "evidence_id": record.evidence_id,
                "title": record.hypothesis or record.summary,
                "finding": record.finding,
                "target": record.target,
                "agent": record.agent,
                "status": HYPOTHESIS,
                "verification_status": record.verification_status or "unverified",
            }
            for record in self.store.by_status(HYPOTHESIS)
        ]

    def status_of(self, finding: str) -> dict[str, Any]:
        records = self.store.by_finding(finding)
        if not records:
            return {"finding": finding, "status": "unknown", "verdict": None}
        verdicts = [r.verification_status for r in records if r.verification_status]
        observations = [r for r in records if r.status == OBSERVED]
        verdict = verdicts[-1] if verdicts else INCONCLUSIVE
        return {
            "finding": finding,
            "status": VERIFIED if verdict == CONFIRMED else verdict.lower(),
            "verdict": verdict,
            "observations": len(observations),
            "hypotheses": len([r for r in records if r.status == HYPOTHESIS]),
        }
