"""Security prompt translator.

Turns "check whether this endpoint has an auth bypass" into a structured
objective that the policy engine and the agents can reason about.

The translator's job is narrow and its refusals are firm. It may:

*   name an objective class
*   name the target the researcher supplied
*   suggest non-destructive methods already permitted by the engagement

It may not:

*   expand the target beyond what the researcher typed
*   invent or assume authorization
*   add a technique the engagement forbids
*   override engagement rules
*   resolve an ambiguous authorization question on the researcher's behalf

When authorization or intent is ambiguous the translation is `needs_clarification`
and SRO asks. It never guesses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .engagement import Engagement
from .scope import IN_SCOPE, ScopeEngine

OBJECTIVE_AUTH = "authentication_testing"
OBJECTIVE_AUTHZ = "authorization_testing"
OBJECTIVE_INJECTION = "injection_testing"
OBJECTIVE_XSS = "xss_testing"
OBJECTIVE_SSRF = "ssrf_testing"
OBJECTIVE_RECON = "authorized_attack_surface_mapping"
OBJECTIVE_CONFIG = "security_configuration_review"
OBJECTIVE_CLOUD = "cloud_misconfiguration_review"
OBJECTIVE_AD = "directory_security_review"
OBJECTIVE_CODE = "source_code_security_analysis"
OBJECTIVE_SCOPE_REVIEW = "scope_review"
OBJECTIVE_REPORT = "report_generation"
OBJECTIVE_VERIFY = "finding_verification"
OBJECTIVE_UNKNOWN = "unclassified_security_objective"

OBJECTIVES = (
    OBJECTIVE_AUTH,
    OBJECTIVE_AUTHZ,
    OBJECTIVE_INJECTION,
    OBJECTIVE_XSS,
    OBJECTIVE_SSRF,
    OBJECTIVE_RECON,
    OBJECTIVE_CONFIG,
    OBJECTIVE_CLOUD,
    OBJECTIVE_AD,
    OBJECTIVE_CODE,
    OBJECTIVE_SCOPE_REVIEW,
    OBJECTIVE_REPORT,
    OBJECTIVE_VERIFY,
    OBJECTIVE_UNKNOWN,
)

#: objective -> default agent
OBJECTIVE_AGENT: dict[str, str] = {
    OBJECTIVE_AUTH: "api",
    OBJECTIVE_AUTHZ: "api",
    OBJECTIVE_INJECTION: "web",
    OBJECTIVE_XSS: "web",
    OBJECTIVE_SSRF: "web",
    OBJECTIVE_RECON: "recon",
    OBJECTIVE_CONFIG: "web",
    OBJECTIVE_CLOUD: "cloud",
    OBJECTIVE_AD: "ad",
    OBJECTIVE_CODE: "code",
    OBJECTIVE_SCOPE_REVIEW: "sro",
    OBJECTIVE_REPORT: "reporter",
    OBJECTIVE_VERIFY: "verifier",
    OBJECTIVE_UNKNOWN: "researcher",
}

#: objective -> capability, used to constrain which tools the objective can use
OBJECTIVE_CAPABILITY: dict[str, str] = {
    OBJECTIVE_AUTH: "AUTH",
    OBJECTIVE_AUTHZ: "API",
    OBJECTIVE_INJECTION: "WEB",
    OBJECTIVE_XSS: "WEB",
    OBJECTIVE_SSRF: "WEB",
    OBJECTIVE_RECON: "RECON",
    OBJECTIVE_CONFIG: "WEB",
    OBJECTIVE_CLOUD: "CLOUD",
    OBJECTIVE_AD: "AD",
    OBJECTIVE_CODE: "CODE",
    OBJECTIVE_SCOPE_REVIEW: "RECON",
    OBJECTIVE_REPORT: "REPORTING",
    OBJECTIVE_VERIFY: "RECON",
    OBJECTIVE_UNKNOWN: "RECON",
}

#: Techniques that are only ever proposed when the engagement permits them.
#: An objective that implies a forbidden technique is downgraded to a
#: clarification request rather than executed.
#: Keys are written against normalised text (see `normalize_request`), so
#: "load test", "load_test" and "load-test" all match the same entry.
_TECHNIQUE_RESTRICTION: dict[str, str] = {
    "denial of service": "denial_of_service",
    r"\bdos\b": "denial_of_service",
    r"\bddos\b": "denial_of_service",
    "load test": "denial_of_service",
    "stress test": "denial_of_service",
    r"\bflood\w*": "denial_of_service",
    "social engineering": "social_engineering",
    r"\bphish\w*": "social_engineering",
    r"\bpretext\w*": "social_engineering",
    r"\bimpersonat\w*": "social_engineering",
    "password spray": "password_spraying",
    r"\bspray\w*": "password_spraying",
    "brute force": "brute_force",
    r"\bbruteforc\w*": "brute_force",
    "credential stuffing": "brute_force",
    r"\bdelete\b": "data_destruction",
    r"\bwipe\b": "data_destruction",
    "drop table": "data_destruction",
    r"\bexfiltrat\w*": "data_destruction",
}

_OBJECTIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"\b(?:review|check|list|show|map|confirm|display|print)\w*\b[^.]*?\b(?:scope|targets?|assets?|exclusions?)\b"
        r"|\b(?:scope|targets?|assets?|exclusions?)\w*\b[^.]*?\b(?:review|check|list|show|confirm)\b",
        OBJECTIVE_SCOPE_REVIEW,
    ),
    (r"\b(?:write|generate|produce|create|draft)\b[^.]*?\b(?:report|write ?up|disclosure)\b", OBJECTIVE_REPORT),
    (
        r"\b(?:verify|validate|confirm|reproduce|reproduce)\b[^.]*?\b(?:finding|vuln|report|issue|#\d+)",
        OBJECTIVE_VERIFY,
    ),
    (
        r"\b(?:auth|authentication|login|log in|signup|sign up|session|jwt|token|sso|oauth|password|2fa|mfa)\b",
        OBJECTIVE_AUTH,
    ),
    (
        r"\b(?:authorization|idor|access control|privilege\w*|escalat\w*|acl|permissi\w*|broken access)\b",
        OBJECTIVE_AUTHZ,
    ),
    (
        r"\b(?:sqli|sql injection|nosql|injection|rce|command injection|ldap injection|xxe|deserializ\w*)\b",
        OBJECTIVE_INJECTION,
    ),
    (r"\b(?:xss|cross site scripting|dom clobber\w*)\b", OBJECTIVE_XSS),
    (r"\b(?:ssrf|server side request|metadata service)\b", OBJECTIVE_SSRF),
    (
        r"\b(?:cloud|aws|azure|gcp|s3|iam|bucket|terraform|k8s|kubernetes|container)\b",
        OBJECTIVE_CLOUD,
    ),
    (
        r"\b(?:active directory|ad|ldap|kerberos|domain controller|smb)\b",
        OBJECTIVE_AD,
    ),
    (
        r"\b(?:source code|repo(?:sitory)?|code audit|static analysis|sast)\b",
        OBJECTIVE_CODE,
    ),
    (
        r"\b(?:recon|attack surface|map\w*|subdomain\w*|enumerat\w*|discover\w*)\b",
        OBJECTIVE_RECON,
    ),
    (
        r"\b(?:headers?|tls|ssl|cors|cookie flag|security header|config\w*)\b",
        OBJECTIVE_CONFIG,
    ),
)


def normalize_request(text: str) -> str:
    """Fold separators and case so patterns match how a human actually types.

    "in-scope", "in_scope" and "in scope" are the same word, and program prose
    and researcher prose disagree about which they use. Collapsing them here
    keeps every pattern below readable.
    """
    lowered = (text or "").lower()
    lowered = re.sub(r"[-_/]+", " ", lowered)
    lowered = lowered.replace("’", "'")
    return re.sub(r"\s+", " ", lowered).strip()

_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_HOST_RE = re.compile(
    r"\b((?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?::\d{1,5})?(?:/[^\s<>\"']*)?)\b",
    re.IGNORECASE,
)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b")
_FINDING_REF = re.compile(r"(?i)\b(?:finding|report|issue)\s*#?(\d+)\b")


@dataclass(slots=True)
class Translation:
    objective: str
    raw_request: str
    target: str = ""
    targets: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    scope: str = "existing_engagement_only"
    evidence_required: bool = True
    agent: str = "researcher"
    capability: str = "RECON"
    finding_ref: str = ""
    status: str = "ok"
    questions: list[str] = field(default_factory=list)
    blocked_techniques: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def needs_clarification(self) -> bool:
        return self.status == "needs_clarification"

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "raw_request": self.raw_request,
            "target": self.target,
            "targets": list(self.targets),
            "methods": list(self.methods),
            "scope": self.scope,
            "evidence_required": self.evidence_required,
            "agent": self.agent,
            "capability": self.capability,
            "finding_ref": self.finding_ref,
            "status": self.status,
            "questions": list(self.questions),
            "blocked_techniques": list(self.blocked_techniques),
            "notes": list(self.notes),
        }

    def render(self) -> str:
        lines = [
            f"objective:    {self.objective}",
            f"target:       {self.target or '(none supplied)'}",
            f"methods:      {', '.join(self.methods) or 'none'}",
            f"scope:        {self.scope}",
            f"evidence:     {'required' if self.evidence_required else 'optional'}",
            f"agent:        @{self.agent}",
            f"capability:   {self.capability}",
        ]
        if self.finding_ref:
            lines.append(f"finding:      {self.finding_ref}")
        if self.blocked_techniques:
            lines.append(f"blocked:      {', '.join(self.blocked_techniques)}")
        if self.notes:
            lines.append(f"notes:        {'; '.join(self.notes)}")
        if self.questions:
            lines.append("")
            lines.append("SRO needs clarification before proceeding:")
            for question in self.questions:
                lines.append(f"  ? {question}")
        return "\n".join(lines)


def classify_objective(request: str) -> str:
    normalized = normalize_request(request)
    for pattern, objective in _OBJECTIVE_PATTERNS:
        if re.search(pattern, normalized):
            return objective
    return OBJECTIVE_UNKNOWN


def extract_techniques(request: str) -> list[str]:
    """Map a request to the engagement restrictions its techniques implicate."""
    normalized = normalize_request(request)
    found: list[str] = []
    for token, restriction in _TECHNIQUE_RESTRICTION.items():
        if restriction in found:
            continue
        if re.search(token, normalized):
            found.append(restriction)
    return found


def extract_targets(request: str) -> list[str]:
    """Extract exactly the targets the researcher typed. Never more.

    Anything resembling a scope expansion phrase is a hard stop: if a request
    mentions other hosts, the translator records them but does not treat them as
    in scope.
    """
    found: list[str] = []
    for match in _URL_RE.finditer(request or ""):
        candidate = match.group(0).rstrip(".,;:)]}'\"")
        if candidate not in found:
            found.append(candidate)
    for match in _IP_RE.finditer(request or ""):
        if match.group(0) not in found:
            found.append(match.group(0))
    # Host regex runs on the request with URLs blanked so the same host is not
    # reported twice, once bare and once with a path.
    remainder = _URL_RE.sub(" ", request or "")
    for match in _HOST_RE.finditer(remainder):
        candidate = match.group(1).rstrip(".,;:)]}'\"")
        if candidate and candidate not in found:
            found.append(candidate)
    return found


def default_methods(objective: str) -> list[str]:
    return {
        OBJECTIVE_AUTH: ["non_destructive_authentication_tests", "session_control_observation"],
        OBJECTIVE_AUTHZ: ["authorization_boundary_comparison", "object_reference_identification"],
        OBJECTIVE_INJECTION: ["non_destructive_injection_tests", "input_handling_observation"],
        OBJECTIVE_XSS: ["reflected_input_observation", "context_identification"],
        OBJECTIVE_SSRF: ["input_handling_observation", "collaborator_validation"],
        OBJECTIVE_RECON: ["passive_asset_discovery", "service_identification"],
        OBJECTIVE_CONFIG: ["header_inspection", "tls_configuration_review"],
        OBJECTIVE_CLOUD: ["configuration_audit", "policy_review"],
        OBJECTIVE_AD: ["directory_enumeration", "acl_review"],
        OBJECTIVE_CODE: ["static_analysis", "dataflow_review"],
        OBJECTIVE_SCOPE_REVIEW: ["manifest_review"],
        OBJECTIVE_REPORT: ["evidence_citation", "impact_statement_drafting"],
        OBJECTIVE_VERIFY: ["independent_reproduction", "evidence_corroboration"],
        OBJECTIVE_UNKNOWN: ["researcher_clarification"],
    }.get(objective, ["researcher_clarification"])


class PromptTranslator:
    def __init__(self, engagement: Engagement | None = None, scope_engine: ScopeEngine | None = None, active: bool = False) -> None:
        self.engagement = engagement
        self.scope_engine = scope_engine
        self.active = active

    def translate(self, request: str) -> Translation:
        text = (request or "").strip()
        if not text:
            return Translation(
                objective=OBJECTIVE_UNKNOWN,
                raw_request="",
                status="needs_clarification",
                questions=["What would you like to investigate?"],
            )

        objective = classify_objective(text)
        targets = extract_targets(text)
        translation = Translation(
            objective=objective,
            raw_request=text,
            target=targets[0] if targets else "",
            targets=targets,
            methods=default_methods(objective),
            agent=OBJECTIVE_AGENT.get(objective, "researcher"),
            capability=OBJECTIVE_CAPABILITY.get(objective, "RECON"),
        )

        finding = _FINDING_REF.search(text)
        if finding:
            translation.finding_ref = f"#{finding.group(1)}"

        # --- 1. engagement must exist and be activated --------------------
        if self.engagement is None:
            translation.status = "needs_clarification"
            translation.questions.append(
                "No engagement is loaded. Which program are you working under? "
                "Run `sro load <program-url>` first — SRO will not assume authorization."
            )
            return translation

        if not self.active:
            translation.status = "needs_clarification"
            translation.questions.append(
                f"The engagement {self.engagement.program_name!r} is loaded but not activated. "
                "Run `sro review` and then `sro activate` so I can show you the scope I extracted."
            )
            return translation

        # --- 2. techniques the engagement forbids ------------------------
        implied = extract_techniques(text)
        translation.blocked_techniques = list(implied)
        forbidden = {name.strip().lower() for name in self.engagement.forbidden_testing}
        requested_forbidden = sorted(set(implied) & forbidden)
        if requested_forbidden:
            translation.blocked_techniques = requested_forbidden
            translation.status = "blocked"
            translation.notes.append(
                "the engagement prohibits "
                + ", ".join(requested_forbidden)
                + "; SRO will not add a prohibited technique to the plan"
            )
            return translation

        # --- 3. target must resolve to IN_SCOPE --------------------------
        if objective in (OBJECTIVE_SCOPE_REVIEW, OBJECTIVE_REPORT) and not targets:
            return translation

        if not targets:
            translation.status = "needs_clarification"
            translation.questions.append(
                "Which target should I investigate? Name it explicitly — I will not guess a "
                "target or widen one you did not give me."
            )
            return translation

        engine = self.scope_engine
        verdicts: list[str] = []
        in_scope: list[str] = []
        not_in_scope: list[str] = []
        for target in targets:
            if engine is None:
                verdicts.append("unknown")
                not_in_scope.append(target)
                continue
            decision = engine.check(target)
            verdicts.append(decision.status)
            if decision.status == IN_SCOPE:
                in_scope.append(target)
            else:
                not_in_scope.append(target)

        if not_in_scope:
            # Every named target has to resolve. Silently proceeding with the
            # subset that happens to be in scope would quietly narrow what the
            # researcher asked for, and they would have no idea a target was
            # dropped.
            translation.targets = in_scope
            if in_scope:
                translation.target = in_scope[0]
            translation.status = "needs_clarification"
            detail = ", ".join(f"{t} ({v})" for t, v in zip(not_in_scope, verdicts))
            translation.questions.append(
                f"I could not establish these as authorized: {detail}. "
                + (
                    f"I can proceed with {', '.join(in_scope)} if you like, but I will not "
                    "quietly drop the rest. "
                    if in_scope
                    else ""
                )
                + "Confirm they belong to this program, or add them to the manifest with "
                "`sro scope add <target>`. I will not send a request until scope is established."
            )
            translation.notes.append(
                "the translator did not substitute a different target; the request names targets "
                "outside confirmed scope"
            )
            return translation

        translation.target = in_scope[0]
        translation.targets = in_scope
        return translation
