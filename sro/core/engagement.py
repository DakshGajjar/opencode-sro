"""Provider-neutral engagement model.

Every platform reader normalizes into this shape. Security agents never see
Bugcrowd- or HackerOne-shaped data; they call the SRO accessors below.

Design notes
------------
*   `Engagement` is plain data. It carries no behaviour that could reach the
    network, so loading a hostile manifest cannot execute anything.
*   `retrieved_at` and `retrieval_mode` are mandatory provenance. A researcher
    must always be able to tell how fresh and how authorized the scope is.
*   Nothing in this module is allowed to mark an engagement active. Activation
    is a researcher decision handled by `sro.core.session`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .util import slugify, stable_id, utcnow_iso

# --- target taxonomy -------------------------------------------------------

TARGET_DOMAIN = "domain"
TARGET_WILDCARD_DOMAIN = "wildcard_domain"
TARGET_URL = "url"
TARGET_IP = "ip"
TARGET_CIDR = "cidr"
TARGET_REPOSITORY = "repository"
TARGET_MOBILE = "mobile_application"
TARGET_CLOUD = "cloud_resource"
TARGET_API = "api_endpoint"
TARGET_ASSET = "asset_identifier"
TARGET_OTHER = "other"

TARGET_TYPES = (
    TARGET_DOMAIN,
    TARGET_WILDCARD_DOMAIN,
    TARGET_URL,
    TARGET_IP,
    TARGET_CIDR,
    TARGET_REPOSITORY,
    TARGET_MOBILE,
    TARGET_CLOUD,
    TARGET_API,
    TARGET_ASSET,
    TARGET_OTHER,
)

# --- retrieval provenance --------------------------------------------------

RETRIEVAL_PUBLIC = "public"
RETRIEVAL_API = "api"
RETRIEVAL_IMPORT = "import"
RETRIEVAL_BROWSER = "browser_assisted"
RETRIEVAL_MODES = (RETRIEVAL_PUBLIC, RETRIEVAL_API, RETRIEVAL_IMPORT, RETRIEVAL_BROWSER)

# --- canonical restriction vocabulary --------------------------------------

RESTRICTION_DOS = "denial_of_service"
RESTRICTION_SOCIAL_ENGINEERING = "social_engineering"
RESTRICTION_PHYSICAL = "physical_testing"
RESTRICTION_THIRD_PARTY = "third_party_systems"
RESTRICTION_DATA_DESTRUCTION = "data_destruction"
RESTRICTION_AUTOMATED_SCANNING = "automated_scanning"
RESTRICTION_PASSWORD_SPRAY = "password_spraying"
RESTRICTION_BRUTE_FORCE = "brute_force"
RESTRICTION_PII = "pii_access"
RESTRICTION_OUT_OF_BAND = "out_of_band"
RESTRICTION_LIVE_CUSTOMERS = "live_customer_data"
RESTRICTION_CODE_EXECUTION = "code_execution_on_production"


@dataclass(slots=True)
class Target:
    """A single in-scope or out-of-scope asset."""

    identifier: str
    type: str = TARGET_OTHER
    in_scope: bool = True
    bounty_eligible: bool | None = None
    submission_eligible: bool | None = None
    instructions: str | None = None
    restrictions: list[str] = field(default_factory=list)
    raw: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self.identifier = (self.identifier or "").strip()
        if not self.identifier:
            raise ValueError("target identifier must not be empty")
        if self.type not in TARGET_TYPES:
            raise ValueError(f"unknown target type: {self.type!r}")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "identifier": self.identifier,
            "type": self.type,
            "in_scope": self.in_scope,
            "bounty_eligible": self.bounty_eligible,
            "submission_eligible": self.submission_eligible,
        }
        if self.instructions:
            data["instructions"] = self.instructions
        if self.restrictions:
            data["restrictions"] = list(self.restrictions)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Target":
        return cls(
            identifier=str(data.get("identifier", "")),
            type=str(data.get("type") or TARGET_OTHER),
            in_scope=bool(data.get("in_scope", True)),
            bounty_eligible=data.get("bounty_eligible"),
            submission_eligible=data.get("submission_eligible"),
            instructions=data.get("instructions"),
            restrictions=list(data.get("restrictions") or []),
            raw=data.get("raw"),
        )


@dataclass(slots=True)
class Restriction:
    """A named testing restriction extracted from the program rules."""

    name: str
    status: str = "permitted"  # permitted | forbidden | conditional | unknown
    description: str = ""
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "description": self.description,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Restriction":
        return cls(
            name=str(data.get("name", "unnamed")),
            status=str(data.get("status", "unknown")),
            description=str(data.get("description", "")),
            source=str(data.get("source", "")),
        )


@dataclass(slots=True)
class Engagement:
    """Normalized, provider-neutral engagement brief."""

    provider: str
    engagement_id: str = ""
    program_name: str = ""
    program_url: str = ""
    description: str = ""
    rules: str = ""
    disclosure_policy: str = ""
    safe_harbor: str = ""
    targets: list[Target] = field(default_factory=list)
    exclusions: list[Target] = field(default_factory=list)
    known_issues: list[str] = field(default_factory=list)
    testing_restrictions: list[Restriction] = field(default_factory=list)
    rate_limits: str = ""
    authentication_requirements: str = ""
    allowed_testing: list[str] = field(default_factory=list)
    forbidden_testing: list[str] = field(default_factory=list)
    retrieved_at: str = field(default_factory=utcnow_iso)
    retrieval_mode: str = RETRIEVAL_PUBLIC
    credentials_used: bool = False
    source_url: str = ""
    completeness: dict[str, bool] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    raw_reference: str = ""

    def __post_init__(self) -> None:
        self.provider = (self.provider or "").strip().lower()
        if not self.provider:
            raise ValueError("engagement provider is required")
        if self.retrieval_mode not in RETRIEVAL_MODES:
            raise ValueError(f"unknown retrieval_mode: {self.retrieval_mode!r}")

    # -- identity ----------------------------------------------------------

    @property
    def slug(self) -> str:
        return slugify(self.engagement_id or self.program_name or self.provider)

    @property
    def sro_id(self) -> str:
        return stable_id("eng", self.provider, self.engagement_id, self.program_url)

    # -- accessors used by security agents ---------------------------------

    def in_scope_targets(self) -> list[Target]:
        return [t for t in self.targets if t.in_scope]

    def excluded_targets(self) -> list[Target]:
        return [t for t in self.targets if not t.in_scope] + list(self.exclusions)

    def get_rules(self) -> str:
        return self.rules

    def get_restrictions(self) -> list[Restriction]:
        return list(self.testing_restrictions)

    def get_scope(self) -> dict[str, list[str]]:
        return {
            "in": [t.identifier for t in self.in_scope_targets()],
            "out": [t.identifier for t in self.excluded_targets()],
        }

    def is_complete(self) -> bool:
        """Complete means: a program name and at least one scope decision."""
        required = ("program_name", "targets")
        if not all(self.completeness.get(key, True) for key in required):
            return False
        if not self.program_name:
            return False
        return bool(self.targets or self.exclusions)

    # -- serialization -----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "engagement_id": self.engagement_id,
            "sro_id": self.sro_id,
            "program_name": self.program_name,
            "program_url": self.program_url,
            "description": self.description,
            "rules": self.rules,
            "disclosure_policy": self.disclosure_policy,
            "safe_harbor": self.safe_harbor,
            "targets": [t.to_dict() for t in self.targets],
            "exclusions": [t.to_dict() for t in self.exclusions],
            "known_issues": list(self.known_issues),
            "testing_restrictions": [r.to_dict() for r in self.testing_restrictions],
            "rate_limits": self.rate_limits,
            "authentication_requirements": self.authentication_requirements,
            "allowed_testing": list(self.allowed_testing),
            "forbidden_testing": list(self.forbidden_testing),
            "retrieved_at": self.retrieved_at,
            "retrieval_mode": self.retrieval_mode,
            "credentials_used": self.credentials_used,
            "source_url": self.source_url,
            "completeness": dict(self.completeness),
            "warnings": list(self.warnings),
            "raw_reference": self.raw_reference,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Engagement":
        targets = [Target.from_dict(t) for t in data.get("targets") or []]
        exclusions = [Target.from_dict(t) for t in data.get("exclusions") or []]
        restrictions = [Restriction.from_dict(r) for r in data.get("testing_restrictions") or []]
        known = data.get("known_issues") or []
        engagement = cls(
            provider=str(data.get("provider", "")),
            engagement_id=str(data.get("engagement_id", "")),
            program_name=str(data.get("program_name", "")),
            program_url=str(data.get("program_url", "")),
            description=str(data.get("description", "")),
            rules=str(data.get("rules", "")),
            disclosure_policy=str(data.get("disclosure_policy", "")),
            safe_harbor=str(data.get("safe_harbor", "")),
            targets=targets,
            exclusions=exclusions,
            known_issues=[str(k) for k in known],
            testing_restrictions=restrictions,
            rate_limits=str(data.get("rate_limits", "")),
            authentication_requirements=str(data.get("authentication_requirements", "")),
            allowed_testing=[str(a) for a in data.get("allowed_testing") or []],
            forbidden_testing=[str(f) for f in data.get("forbidden_testing") or []],
            retrieved_at=str(data.get("retrieved_at") or utcnow_iso()),
            retrieval_mode=str(data.get("retrieval_mode") or RETRIEVAL_PUBLIC),
            credentials_used=bool(data.get("credentials_used", False)),
            source_url=str(data.get("source_url", "")),
            completeness={str(k): bool(v) for k, v in (data.get("completeness") or {}).items()},
            warnings=[str(w) for w in data.get("warnings") or []],
            raw_reference=str(data.get("raw_reference", "")),
        )
        return engagement


@dataclass(slots=True)
class CandidateManifest:
    """A parsed engagement awaiting explicit researcher confirmation.

    The manifest is never active. `sro.core.session.Session.activate()` is the
    only transition to ACTIVE, and only in response to a researcher action.
    """

    engagement: Engagement
    status: str = "pending_user_confirmation"
    created_at: str = field(default_factory=utcnow_iso)
    confirmed_at: str = ""
    confirmed_by: str = ""
    diff_from_previous: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        engagement = self.engagement
        return {
            "status": self.status,
            "provider": engagement.provider,
            "program_name": engagement.program_name,
            "engagement_id": engagement.engagement_id,
            "in_scope_targets": len(engagement.in_scope_targets()),
            "exclusions": len(engagement.excluded_targets()),
            "restrictions": len(engagement.testing_restrictions),
            "credentials_used": engagement.credentials_used,
            "retrieval_mode": engagement.retrieval_mode,
            "complete": engagement.is_complete(),
            "created_at": self.created_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "created_at": self.created_at,
            "confirmed_at": self.confirmed_at,
            "confirmed_by": self.confirmed_by,
            "diff_from_previous": list(self.diff_from_previous),
            "summary": self.summary(),
            "engagement": self.engagement.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CandidateManifest":
        return cls(
            engagement=Engagement.from_dict(data.get("engagement") or {}),
            status=str(data.get("status", "pending_user_confirmation")),
            created_at=str(data.get("created_at") or utcnow_iso()),
            confirmed_at=str(data.get("confirmed_at", "")),
            confirmed_by=str(data.get("confirmed_by", "")),
            diff_from_previous=[str(d) for d in data.get("diff_from_previous") or []],
        )


def dedupe_targets(targets: Iterable[Target]) -> list[Target]:
    """Collapse duplicate identifiers, keeping the most restrictive entry.

    Programs routinely list the same asset in both the in-scope table and the
    exclusions table. When that happens the exclusion wins, because a manifest
    that is wrong in the permissive direction is the dangerous failure mode.
    """
    by_identifier: dict[str, Target] = {}
    for target in targets:
        key = target.identifier.strip().lower().rstrip(".")
        existing = by_identifier.get(key)
        if existing is None:
            by_identifier[key] = target
            continue
        merged = Target(
            identifier=target.identifier,
            type=target.type,
            in_scope=existing.in_scope and target.in_scope,
            bounty_eligible=(
                target.bounty_eligible
                if target.bounty_eligible is not None
                else existing.bounty_eligible
            ),
            submission_eligible=(
                target.submission_eligible
                if target.submission_eligible is not None
                else existing.submission_eligible
            ),
            instructions=target.instructions or existing.instructions,
            restrictions=sorted(set(existing.restrictions) | set(target.restrictions)),
        )
        by_identifier[key] = merged
    return list(by_identifier.values())
