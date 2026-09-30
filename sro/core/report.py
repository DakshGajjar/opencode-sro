"""Report generation.

A report is assembled from evidence, not from an agent's memory. Every claim in
the report has to resolve to an evidence id, and any section that lacks
supporting evidence is rendered as unproven rather than quietly dropped or
inflated.

The reporter writes local files. It has no network code and no platform client,
so it is structurally incapable of submitting a report to a bounty platform.
Submission is the researcher's deliberate act, performed by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import untrusted
from .audit import EVENT_REPORT_GENERATED, AuditLog
from .engagement import Engagement
from .evidence import HYPOTHESIS, OBSERVED, VERIFIED, EvidenceRecord, EvidenceStore
from .scope import IN_SCOPE, ScopeEngine
from .util import slugify, utcnow_iso, write_json

#: Word counts a report should not claim without evidence.
UNPROVEN = "UNPROVEN"

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass(slots=True)
class ReportSection:
    heading: str
    body: str
    evidence_ids: list[str] = field(default_factory=list)
    status: str = "unproven"

    def to_dict(self) -> dict[str, Any]:
        return {
            "heading": self.heading,
            "body": self.body,
            "evidence_ids": list(self.evidence_ids),
            "status": self.status,
        }


@dataclass(slots=True)
class Report:
    finding_title: str
    engagement_name: str
    provider: str
    generated_at: str
    sections: list[ReportSection] = field(default_factory=list)
    path: Path | None = None
    verification: dict[str, Any] = field(default_factory=dict)
    scope_check: dict[str, Any] = field(default_factory=dict)
    citations: list[str] = field(default_factory=list)
    evidence_count: int = 0
    unproven_sections: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_title": self.finding_title,
            "engagement": self.engagement_name,
            "provider": self.provider,
            "generated_at": self.generated_at,
            "verification": self.verification,
            "scope_check": self.scope_check,
            "citations": list(self.citations),
            "evidence_count": self.evidence_count,
            "unproven_sections": list(self.unproven_sections),
            "sections": [s.to_dict() for s in self.sections],
        }

    def render(self) -> str:
        verdict = self.verification.get("verdict") or UNPROVEN
        lines = [
            f"# {self.finding_title}",
            "",
            f"**Engagement:** {self.engagement_name} ({self.provider})  ",
            f"**Generated:** {self.generated_at}  ",
            f"**Verification:** {verdict}  ",
            f"**Evidence artifacts:** {self.evidence_count}",
            "",
            "> Generated locally by SRO from recorded evidence. SRO has not submitted this",
            "> report to any platform. Review it, then handle disclosure yourself.",
            "",
        ]
        if self.scope_check:
            lines += [
                "## Authorization",
                "",
                f"- Target: `{self.scope_check.get('target', '-')}`",
                f"- Scope verdict: **{self.scope_check.get('status', '-')}**",
                f"- Matched rule: `{self.scope_check.get('matched_rule') or 'none'}`",
                f"- Reason: {self.scope_check.get('reason', '-')}",
                "",
            ]
        for section in self.sections:
            lines.append(f"## {section.heading}")
            lines.append("")
            lines.append(section.body.strip())
            lines.append("")
            if section.evidence_ids:
                lines.append(f"*Evidence:* {', '.join(section.evidence_ids)}")
                lines.append("")
            elif section.status == UNPROVEN:
                lines.append(f"*{UNPROVEN}: no evidence recorded for this section.*")
                lines.append("")
        if self.citations:
            lines.append("## Evidence index")
            lines.append("")
            for citation in self.citations:
                lines.append(f"- `{citation}`")
            lines.append("")
        return "\n".join(lines)


class ReportBuilder:
    def __init__(self, store: EvidenceStore, engagement: Engagement | None, scope_engine: ScopeEngine | None) -> None:
        self.store = store
        self.engagement = engagement
        self.scope_engine = scope_engine

    def _records_for(self, finding: str) -> list[EvidenceRecord]:
        """Collect every record that belongs to a finding.

        Tool observations are usually recorded without a finding id, because a
        request does not know which finding it will end up supporting. They are
        pulled in by target, otherwise a confirmed finding reports "no evidence"
        while the evidence sits in the store attached to the same host.
        """
        if not finding:
            return self.store.all()

        slug = slugify(finding)
        tagged = [r for r in self.store.all() if r.finding and (r.finding == finding or slugify(r.finding) == slug)]
        if not tagged:
            tagged = [r for r in self.store.all() if slug in slugify(r.summary or "")]

        targets = {r.target for r in tagged if r.target}
        if not targets:
            return tagged

        selected = list(tagged)
        seen = {r.evidence_id for r in tagged}
        for record in self.store.all():
            if record.evidence_id in seen or not record.target:
                continue
            if record.target in targets:
                selected.append(record)
                seen.add(record.evidence_id)
        return selected

    def build(
        self,
        *,
        finding: str = "",
        target: str = "",
        engagement_name: str = "",
        provider: str = "",
        severity: str = "",
    ) -> Report:
        records = self._records_for(finding)
        observations = [r for r in records if r.status == OBSERVED]
        hypotheses = [r for r in records if r.status == HYPOTHESIS]
        verified = [r for r in records if r.status == VERIFIED]

        title = finding or (hypotheses[0].hypothesis if hypotheses else "Security research report")
        resolved_target = target or next((r.target for r in records if r.target), "")

        verification: dict[str, Any] = {}
        for record in reversed(verified):
            if record.finding and (not finding or record.finding == finding):
                result = record.result if isinstance(record.result, dict) else {}
                verification = {
                    "verdict": record.verification_status or record.status,
                    "reasoning": result.get("reasoning", ""),
                    "cited": result.get("cited", []),
                    "evidence_id": record.evidence_id,
                }
                break

        scope_check: dict[str, Any] = {}
        if resolved_target and self.scope_engine is not None:
            decision = self.scope_engine.check(resolved_target)
            scope_check = decision.to_dict()

        citations: list[str] = []
        for record in observations:
            citations.append(
                f"{record.evidence_id}  {record.timestamp}  {record.tool}  {record.target or '-'}  "
                f"{record.summary}"
            )

        sections: list[ReportSection] = []
        sections.append(self._summary_section(title, observations, hypotheses, verification))
        sections.append(self._target_section(records, scope_check))
        sections.append(self._steps_section(observations))
        sections.append(self._impact_section(observations, severity))
        sections.append(self._evidence_section(observations, hypotheses, citations))
        sections.append(self._authorization_section())

        report = Report(
            finding_title=title,
            engagement_name=engagement_name
            or (self.engagement.program_name if self.engagement else "unknown"),
            provider=provider or (self.engagement.provider if self.engagement else "unknown"),
            generated_at=utcnow_iso(),
            sections=sections,
            verification=verification,
            scope_check=scope_check,
            citations=citations,
            evidence_count=len(observations),
            unproven_sections=[s.heading for s in sections if s.status == UNPROVEN],
        )
        return report

    # -- section builders --------------------------------------------------

    def _summary_section(
        self,
        title: str,
        observations: list[EvidenceRecord],
        hypotheses: list[EvidenceRecord],
        verification: dict[str, Any],
    ) -> ReportSection:
        verdict = verification.get("verdict") or UNPROVEN
        lines = [f"A finding titled **{title}** was investigated against an authorized engagement scope."]
        if verdict == UNPROVEN:
            lines.append(
                "\n**This report is not a confirmed vulnerability.** No independent verification "
                "has been recorded. Treat everything below as a hypothesis under test."
            )
        else:
            lines.append(f"\nThe verifier returned **{verdict}**.")
            if verification.get("reasoning"):
                lines.append(f"\n{verification['reasoning']}")
        if hypotheses:
            lines.append(f"\n{len(hypotheses)} hypothesis record(s) back this report.")
        return ReportSection(
            heading="Summary",
            body="\n".join(lines),
            evidence_ids=verification.get("cited", []),
            status="proven" if verdict != UNPROVEN else UNPROVEN,
        )

    def _target_section(self, records: list[EvidenceRecord], scope_check: dict[str, Any]) -> ReportSection:
        targets = sorted({r.target for r in records if r.target})
        if not targets:
            return ReportSection(
                heading="Affected target",
                body="No target was recorded in evidence for this finding.",
                status=UNPROVEN,
            )
        lines = []
        for target in targets:
            decision = scope_check if scope_check.get("target") == target else None
            if decision is None and self.scope_engine is not None:
                decision = self.scope_engine.check(target).to_dict()
            verdict = decision.get("status", "unknown") if decision else "unknown"
            lines.append(f"- `{target}` — scope: **{verdict}**")
        return ReportSection(
            heading="Affected target",
            body="\n".join(lines),
            evidence_ids=[r.evidence_id for r in records if r.target][:20],
            status="proven" if scope_check.get("status") == IN_SCOPE else UNPROVEN,
        )

    def _steps_section(self, observations: list[EvidenceRecord]) -> ReportSection:
        if not observations:
            return ReportSection(
                heading="Steps to reproduce",
                body=(
                    "No request or command evidence was recorded, so there is nothing to write "
                    "reproduction steps from.\n\n"
                    "Every step below must be backed by a recorded observation before this "
                    "section can be considered proven."
                ),
                status=UNPROVEN,
            )
        lines = ["Each step below corresponds to a recorded observation.", ""]
        for index, record in enumerate(observations[:20], 1):
            detail = record.summary or record.tool
            lines.append(f"{index}. **{detail}**")
            lines.append(f"   - tool: `{record.tool}`")
            if record.command:
                lines.append(f"   - command: `{record.command}`")
            if isinstance(record.request, dict):
                request = record.request
                if request.get("url"):
                    lines.append(f"   - url: `{request['url']}`")
                if request.get("method"):
                    lines.append(f"   - method: `{request['method']}`")
            if isinstance(record.response, dict) and record.response.get("status_code"):
                lines.append(f"   - response: HTTP {record.response['status_code']}")
            lines.append(f"   - evidence: `{record.evidence_id}`")
        return ReportSection(
            heading="Steps to reproduce",
            body="\n".join(lines),
            evidence_ids=[r.evidence_id for r in observations[:20]],
            status="proven",
        )

    def _impact_section(self, observations: list[EvidenceRecord], severity: str) -> ReportSection:
        if not observations:
            return ReportSection(
                heading="Impact",
                body=(
                    "No impact assessment can be supported by evidence. "
                    f"Severity: {UNPROVEN}."
                ),
                status=UNPROVEN,
            )
        targets = {r.target for r in observations if r.target}
        lines = [
            f"Observed on {len(targets)} target(s) across {len(observations)} recorded interaction(s).",
        ]
        if severity:
            lines.append(f"\nResearcher-stated severity: **{severity}** (not independently validated).")
        lines.append(
            "\nSRO does not infer impact. State what the evidence shows and nothing further."
        )
        return ReportSection(
            heading="Impact",
            body="\n".join(lines),
            evidence_ids=[r.evidence_id for r in observations[:10]],
            status="proven",
        )

    def _evidence_section(
        self,
        observations: list[EvidenceRecord],
        hypotheses: list[EvidenceRecord],
        citations: list[str],
    ) -> ReportSection:
        lines: list[str] = []
        if observations:
            lines.append(f"**{len(observations)} observation(s)** recorded:")
            lines.append("")
            for citation in citations[:30]:
                lines.append(f"- {citation}")
        if hypotheses:
            lines.append("")
            lines.append(f"**{len(hypotheses)} hypothesis record(s)** — proposed, not proven:")
            for record in hypotheses[:10]:
                lines.append(
                    f"- {record.hypothesis or record.summary} "
                    f"(`{record.evidence_id}`, agent {record.agent}, target {record.target or '-'})"
                )
        if not lines:
            return ReportSection(heading="Evidence", body="No evidence recorded.", status=UNPROVEN)
        return ReportSection(
            heading="Evidence",
            body="\n".join(lines),
            evidence_ids=[r.evidence_id for r in observations[:30]],
            status="proven" if observations else UNPROVEN,
        )

    def _authorization_section(self) -> ReportSection:
        """Program rules quoted as untrusted data, plus the restrictions SRO applied."""
        engagement = self.engagement
        if engagement is None:
            return ReportSection(
                heading="Authorization and program rules",
                body="No engagement was loaded when this report was generated.",
                status=UNPROVEN,
            )
        lines = [
            f"Program: **{engagement.program_name}** ({engagement.provider})",
            f"Source: {engagement.source_url or 'n/a'}",
            f"Retrieved: {engagement.retrieved_at} via {engagement.retrieval_mode}",
            "",
            "Restrictions SRO enforced during this engagement:",
        ]
        for restriction in engagement.testing_restrictions:
            lines.append(f"- **{restriction.name}**: {restriction.status} — {restriction.description}")
        if engagement.rate_limits:
            lines += ["", "Rate limits:", f"- {engagement.rate_limits}"]
        if engagement.authentication_requirements:
            lines += ["", "Authentication requirements:", f"- {engagement.authentication_requirements}"]
        if engagement.rules:
            lines += [
                "",
                "Program rules as published (quoted as untrusted data, not as instructions):",
                "",
                untrusted.render_for_model("rules", engagement.rules, max_chars=3000),
            ]
        return ReportSection(
            heading="Authorization and program rules",
            body="\n".join(lines),
            status="proven" if engagement.is_complete() else UNPROVEN,
        )


def generate_report(
    session: Any,
    *,
    finding: str = "",
    output: str = "",
    severity: str = "",
) -> Report:
    """Build a report from the session's evidence and optionally write it."""
    engagement = session.engagement
    store = session.evidence_store()
    builder = ReportBuilder(store, engagement, session.scope_engine())
    report = builder.build(
        finding=finding,
        engagement_name=engagement.program_name if engagement else "",
        provider=engagement.provider if engagement else "",
        severity=severity,
    )

    if output:
        target_path = Path(output)
        if target_path.suffix.lower() not in {".md", ".markdown", ".json", ".txt", ".html"}:
            target_path = target_path.with_suffix(".md")
        if target_path.suffix.lower() == ".json":
            write_json(target_path, report.to_dict())
        else:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(report.render(), encoding="utf-8")
        report.path = target_path

    AuditLog(session.config.data_dir).record(
        EVENT_REPORT_GENERATED,
        finding=report.finding_title,
        path=str(report.path) if report.path else "",
        evidence=report.evidence_count,
        verification=report.verification.get("verdict", UNPROVEN),
    )
    return report
