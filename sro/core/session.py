"""Engagement session: the state machine a researcher drives.

    load(url)   -> candidate manifest, status=pending_user_confirmation
    review()    -> render the candidate for human inspection
    activate()  -> researcher explicitly confirms; status becomes ACTIVE

Two invariants live here:

*   `load` never activates. Parsed scope is inert until the researcher says so.
*   `activate` requires a non-empty scope. An engagement with no resolvable
    targets cannot be activated, because activating it would imply that
    something is authorized when SRO does not know what.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import untrusted
from .audit import (
    EVENT_ENGAGEMENT_ACTIVATED,
    EVENT_ENGAGEMENT_DEACTIVATED,
    EVENT_ENGAGEMENT_LOADED,
    EVENT_ENGAGEMENT_REVIEWED,
    EVENT_SCOPE_CHECKED,
    EVENT_UNTRUSTED_CONTENT,
    AuditLog,
)
from .config import Config
from .engagement import CandidateManifest, Engagement, Target
from .errors import ConfigError, NoEngagementError, NotActivatedError
from .evidence import EvidenceStore
from .policy import PolicyEngine
from ..readers import build_reader, detect_provider
from .scope import ScopeEngine
from .util import read_json, utcnow_iso, write_json

STATUS_EMPTY = "EMPTY"
STATUS_PENDING = "PENDING_CONFIRMATION"
STATUS_ACTIVE = "ACTIVE"

STATE_FILENAME = "session.json"
MANIFEST_FILENAME = "manifest.json"


@dataclass(slots=True)
class Session:
    """Holds the loaded engagement and everything derived from it."""

    config: Config
    manifest: CandidateManifest | None = None
    activated: bool = False
    audit: AuditLog = field(init=False)
    evidence: EvidenceStore = field(init=False)

    def __post_init__(self) -> None:
        self.config.ensure_dirs()
        self.audit = AuditLog(self.config.data_dir)
        self.evidence = EvidenceStore(self.config)
        self._load_persisted()

    # -- persistence -------------------------------------------------------

    @property
    def _state_path(self) -> Path:
        return self.config.data_dir / STATE_FILENAME

    @property
    def _state_dir(self) -> Path | None:
        if self.manifest is None:
            return None
        return self.config.engagements_dir / self.manifest.engagement.slug

    def _manifest_path(self) -> Path | None:
        directory = self._state_dir
        return (directory / MANIFEST_FILENAME) if directory else None

    def _load_persisted(self) -> None:
        """Restore a previously confirmed engagement.

        The manifest on disk is untrusted input, because it is: a workspace is a
        directory a researcher can clone, and `session.json` is a plain file that
        names a path and asserts `activated: true`. Restoring it verbatim would
        let anyone who can drop two files into a directory hand themselves an
        ACTIVE engagement with arbitrary scope.

        Restoration therefore requires all of:

        * the recorded path is inside SRO's own data directory
        * the manifest says it was confirmed, by someone, with a timestamp
        * the manifest hash matches the one recorded at confirmation time
        * a matching activation entry exists in the append-only audit log

        Any failure means the session starts empty, or at worst carries the
        manifest unactivated. The cost is re-confirming after a restart, which
        is the correct cost.
        """
        if not self._state_path.exists():
            return

        try:
            state = read_json(self._state_path)
        except (OSError, ValueError):
            return
        if not isinstance(state, dict):
            return

        manifest_path = state.get("manifest_path")
        if not isinstance(manifest_path, str) or not manifest_path:
            return
        try:
            resolved = Path(manifest_path).resolve()
            resolved.relative_to(self.config.data_dir.resolve())
        except (OSError, ValueError):
            self.audit.record(
                EVENT_ENGAGEMENT_DEACTIVATED,
                engagement=None,
                reason="refused to restore: manifest path is outside the SRO data directory",
            )
            return
        if not resolved.exists():
            return

        try:
            manifest = CandidateManifest.from_dict(read_json(resolved))
        except (OSError, ValueError, KeyError, TypeError):
            return

        self.manifest = manifest
        self.evidence.set_engagement(manifest.engagement.sro_id)

        if manifest.status != "confirmed" or not manifest.confirmed_at or not manifest.confirmed_by:
            self.activated = False
            return

        # An edited manifest is a scope change, and a scope change needs a human.
        recorded_hash = state.get("manifest_hash")
        if recorded_hash and recorded_hash != _manifest_hash(manifest):
            self.activated = False
            self.audit.record(
                EVENT_ENGAGEMENT_DEACTIVATED,
                engagement=manifest.engagement.sro_id,
                reason="refused to restore: manifest changed since it was confirmed",
            )
            return

        # The audit log is the only thing here an attacker editing session.json
        # cannot also edit invisibly.
        confirmed = any(
            entry.get("event") == EVENT_ENGAGEMENT_ACTIVATED
            and entry.get("engagement") == manifest.engagement.sro_id
            for entry in self.audit.entries(EVENT_ENGAGEMENT_ACTIVATED)
        )
        if not confirmed:
            self.activated = False
            self.audit.record(
                EVENT_ENGAGEMENT_DEACTIVATED,
                engagement=manifest.engagement.sro_id,
                reason="refused to restore: no activation record in the audit log",
            )
            return

        self.activated = bool(state.get("activated")) and confirmed

    def _persist(self) -> None:
        if self.manifest is None:
            return
        path = self._manifest_path()
        assert path is not None
        write_json(path, self.manifest.to_dict())
        write_json(
            self._state_path,
            {
                "activated": self.activated,
                "manifest_path": str(path),
                "manifest_hash": _manifest_hash(self.manifest),
                "engagement": self.manifest.engagement.sro_id,
                "updated_at": utcnow_iso(),
            },
        )

    # -- derived state -----------------------------------------------------

    @property
    def engagement(self) -> Engagement | None:
        return self.manifest.engagement if self.manifest else None

    def require_engagement(self) -> Engagement:
        if self.engagement is None:
            raise NoEngagementError(
                "no engagement is loaded. Start with: sro load <program-url>"
            )
        return self.engagement

    def require_active(self) -> Engagement:
        engagement = self.require_engagement()
        if not self.activated:
            raise NotActivatedError(
                f"engagement {engagement.program_name!r} is loaded but NOT active. "
                "Run `sro review` to inspect the extracted scope, then `sro activate` "
                "to confirm it. SRO will not act on a scope the researcher has not confirmed."
            )
        return engagement

    def check_scope(self, target: str) -> Any:
        """Scope verdict, recorded in the audit log.

        Every scope check is logged. A researcher reviewing their own engagement
        months later needs to be able to see not just what was authorized but
        every time something was asked for and refused.
        """
        decision = self.scope_engine().check(target)
        self.audit.record(
            EVENT_SCOPE_CHECKED,
            engagement=self.engagement.sro_id if self.engagement else None,
            target=target,
            status=decision.status,
            matched_rule=decision.matched_rule,
        )
        return decision

    def scope_engine(self) -> ScopeEngine:
        return ScopeEngine(
            engagement=self.engagement,
            active=self.activated,
            deny_private_networks=self.config.deny_private_networks,
            wildcard_includes_apex=self.config.wildcard_includes_apex,
        )

    def policy_engine(self) -> PolicyEngine:
        return PolicyEngine(
            self.config,
            scope_engine=self.scope_engine(),
            engagement=self.engagement,
            active=self.activated,
        )

    def evidence_store(self) -> EvidenceStore:
        return self.evidence

    @property
    def state(self) -> str:
        """The lifecycle state as a short string: EMPTY, PENDING_CONFIRMATION or ACTIVE."""
        if self.manifest is None:
            return STATUS_EMPTY
        return STATUS_ACTIVE if self.activated else STATUS_PENDING

    # -- the state machine -------------------------------------------------

    def load(
        self,
        source: str,
        *,
        provider: str = "",
        as_of: str = "",
    ) -> CandidateManifest:
        """Read an engagement and stage it as a candidate.

        `source` may be a platform URL, a local export file, or an inline
        program code. No credentials are required for the default path.
        """
        resolved_provider = (provider or detect_provider(source) or "").lower()
        if not resolved_provider:
            raise ConfigError(
                f"could not determine which platform {source!r} belongs to. "
                "Pass --provider bugcrowd|hackerone|intigriti explicitly."
            )

        reader = build_reader(self.config, resolved_provider)
        reader.require_public_mode()

        if resolved_provider == "bugcrowd" and _looks_like_file(source):
            payload = read_json(source)
            engagement = _normalize_import("bugcrowd", payload, source)
        else:
            code = _extract_code(reader, source)
            engagement = reader.read_engagement(code)

        if as_of:
            engagement.retrieved_at = as_of

        # Untrusted-content scan. A flag here does not change any permission;
        # it makes a prompt-injection attempt visible in the audit log.
        findings = untrusted.scan_engagement(engagement)
        summary = untrusted.summarize_findings(findings)
        if summary["fields_scanned_with_indicators"]:
            engagement.warnings.append(
                "engagement text contains instruction-like content; it is stored as untrusted "
                f"data and cannot modify scope, policy or permissions. indicators: "
                f"{summary['indicators']}"
            )
            self.audit.record(
                EVENT_UNTRUSTED_CONTENT,
                engagement=engagement.sro_id,
                provider=engagement.provider,
                **summary,
            )

        previous = self.manifest
        manifest = CandidateManifest(engagement=engagement, status="pending_user_confirmation")
        if previous is not None:
            manifest.diff_from_previous = _diff(previous.engagement, engagement)

        self.manifest = manifest
        self.activated = False
        self.evidence.set_engagement(engagement.sro_id)
        self._persist()

        self.audit.record(
            EVENT_ENGAGEMENT_LOADED,
            engagement=engagement.sro_id,
            provider=engagement.provider,
            program=engagement.program_name,
            targets=len(engagement.targets),
            exclusions=len(engagement.exclusions),
            restrictions=len(engagement.testing_restrictions),
            credentials_used=engagement.credentials_used,
            retrieval_mode=engagement.retrieval_mode,
            complete=engagement.is_complete(),
        )
        return manifest

    def import_brief(self, path: str | Path, *, provider: str = "") -> CandidateManifest:
        """Stage a researcher-supplied engagement brief."""
        resolved = (provider or "").lower()
        if not resolved:
            resolved = detect_provider(str(path)) or ""
        if not resolved:
            raise ConfigError("--provider is required when importing a brief")
        payload = read_json(path)
        engagement = _normalize_import(resolved, payload, str(path))
        manifest = CandidateManifest(engagement=engagement, status="pending_user_confirmation")
        # Importing a replacement brief is as much a change as re-reading a
        # public page, so it gets the same delta the researcher would want to see.
        if self.manifest is not None:
            manifest.diff_from_previous = _diff(self.manifest.engagement, engagement)
        self.manifest = manifest
        self.activated = False
        self.evidence.set_engagement(engagement.sro_id)
        self._persist()
        self.audit.record(
            EVENT_ENGAGEMENT_LOADED,
            engagement=engagement.sro_id,
            provider=engagement.provider,
            program=engagement.program_name,
            source="import",
        )
        return manifest

    def add_target(self, identifier: str, *, in_scope: bool = True, note: str = "") -> Target:
        """Add a target the researcher confirmed by hand.

        This is the supported way to resolve an UNKNOWN: the researcher asserts
        the relationship, and SRO records who asserted it.
        """
        engagement = self.require_engagement()
        from ..readers.bugcrowd.parser import classify_identifier

        if not (identifier or "").strip():
            raise ConfigError("a target identifier is required")

        target = Target(
            identifier=identifier.strip(),
            type=classify_identifier(identifier, ""),
            in_scope=in_scope,
            instructions=note or "added manually by the researcher",
        )
        engagement.targets.append(target)
        if not in_scope:
            engagement.exclusions.append(target)
        if self.manifest is not None:
            # Adding a target is a scope change, so an active engagement goes
            # back to needing confirmation. Otherwise a researcher could widen
            # scope on a live engagement without ever re-reading it.
            if self.activated:
                self.activated = False
                self.manifest.status = "pending_user_confirmation"
                self.manifest.confirmed_at = ""
                self.manifest.confirmed_by = ""
                self.audit.record(
                    EVENT_ENGAGEMENT_DEACTIVATED,
                    engagement=engagement.sro_id,
                    reason=f"scope changed by adding {identifier}",
                )
        self._persist()
        return target

    def review(self) -> str:
        """Render the candidate manifest for human inspection."""
        manifest = self.manifest
        if manifest is None:
            return render_status(self)

        engagement = manifest.engagement
        engine = self.scope_engine()
        restrictions = engagement.testing_restrictions

        width = 48
        inner = width - 2
        lines: list[str] = []
        lines.append("╭" + "─" * inner + "╮")
        lines.append("│" + " SRO ENGAGEMENT REVIEW".ljust(inner) + "│")
        lines.append("│" + " " * inner + "│")
        lines.append("│" + f" Provider: {engagement.provider}".ljust(inner) + "│")
        lines.append("│" + f" Program:  {engagement.program_name}".ljust(inner) + "│")
        lines.append("│" + f" Source:   {engagement.retrieval_mode}".ljust(inner) + "│")
        lines.append("│" + f" Retrieved: {engagement.retrieved_at}".ljust(inner) + "│")
        lines.append("│" + " " * inner + "│")
        lines.append("│" + f" In-scope targets: {len(engagement.in_scope_targets())}".ljust(inner) + "│")
        lines.append("│" + f" Explicit exclusions: {len(engagement.excluded_targets())}".ljust(inner) + "│")
        lines.append("│" + f" Restrictions: {len(restrictions)}".ljust(inner) + "│")
        lines.append("│" + " " * inner + "│")
        warning = " ⚠ Scope was automatically extracted."
        detail = "   It has not been activated."
        if engagement.warnings:
            warning = " ⚠ Scope was automatically extracted."
            detail = f"   {len(engagement.warnings)} warning(s) — run `sro warnings`."
        lines.append("│" + warning[:inner].ljust(inner) + "│")
        lines.append("│" + detail[:inner].ljust(inner) + "│")
        lines.append("╰" + "─" * inner + "╯")

        if engagement.in_scope_targets():
            lines.append("")
            lines.append("IN SCOPE")
            for target in engagement.in_scope_targets()[:60]:
                suffix = f"  [{target.type}]"
                lines.append(f"  {target.identifier}{suffix}")
            if len(engagement.in_scope_targets()) > 60:
                lines.append(f"  ... and {len(engagement.in_scope_targets()) - 60} more")
        if engagement.excluded_targets():
            lines.append("")
            lines.append("EXCLUDED")
            for target in engagement.excluded_targets()[:60]:
                lines.append(f"  {target.identifier}  [{target.type}]")
        if restrictions:
            lines.append("")
            lines.append("RESTRICTIONS")
            for restriction in restrictions:
                marker = {"forbidden": "✗", "permitted": "✓", "conditional": "?"}.get(
                    restriction.status, "-"
                )
                lines.append(f"  {marker} {restriction.name}: {restriction.description}")
        if engagement.warnings:
            lines.append("")
            lines.append("WARNINGS")
            for warning in engagement.warnings:
                for chunk in _wrap(warning, 74):
                    lines.append(f"  {chunk}")
        if manifest.diff_from_previous:
            lines.append("")
            lines.append("CHANGES SINCE LAST LOAD")
            for entry in manifest.diff_from_previous[:20]:
                lines.append(f"  {entry}")

        lines.append("")
        lines.append(f"  {len(engine.describe()['inclusion_rules'])} inclusion rule(s), "
                     f"{len(engine.describe()['exclusion_rules'])} exclusion rule(s)")
        lines.append("")
        lines.append("Review:   sro review --full")
        lines.append("Activate: sro activate")
        lines.append("")
        lines.append("This manifest is NOT active. No request will be made until you confirm.")

        rendered = "\n".join(lines)
        self.audit.record(
            EVENT_ENGAGEMENT_REVIEWED,
            engagement=engagement.sro_id,
            targets=len(engagement.targets),
        )
        return rendered

    def activate(self, *, actor: str = "researcher", force: bool = False) -> Engagement:
        """Activate the staged manifest. The only path to ACTIVE.

        Refuses when scope could not be established, unless the researcher
        explicitly overrides. There is no silent override and no timeout that
        auto-activates.
        """
        engagement = self.require_engagement()
        assert self.manifest is not None

        if not engagement.in_scope_targets() and not engagement.exclusions and not force:
            raise ConfigError(
                "refusing to activate: no scope entries were established, so SRO does not know "
                "what is authorized. Import the engagement brief, add targets manually with "
                "`sro scope add`, or re-run `sro load` with read-only credentials."
            )

        self.manifest.status = "confirmed"
        self.manifest.confirmed_at = utcnow_iso()
        self.manifest.confirmed_by = actor
        self.activated = True
        self._persist()

        self.audit.record(
            EVENT_ENGAGEMENT_ACTIVATED,
            engagement=engagement.sro_id,
            program=engagement.program_name,
            actor=actor,
            forced=bool(force),
            targets=len(engagement.in_scope_targets()),
            exclusions=len(engagement.excluded_targets()),
        )
        return engagement

    def deactivate(self, *, reason: str = "researcher request") -> None:
        if self.manifest is not None and self.activated:
            self.activated = False
            self.manifest.status = "pending_user_confirmation"
            self._persist()
            self.audit.record(
                EVENT_ENGAGEMENT_DEACTIVATED,
                engagement=self.manifest.engagement.sro_id,
                reason=reason,
            )

    def clear(self) -> None:
        self.manifest = None
        self.activated = False
        state = self._state_path
        if state.exists():
            state.unlink()
        self.audit.record(EVENT_ENGAGEMENT_DEACTIVATED, engagement=None, reason="cleared")

    def warnings(self) -> list[str]:
        return list(self.engagement.warnings) if self.engagement else []

    # -- reporting ---------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """The full status report shown to the researcher and to the model."""
        engagement = self.engagement
        evidence_count = self.evidence.count()
        external = bool(self.config.allow_external)
        return {
            "status": self.state,
            "engagement": engagement.program_name if engagement else None,
            "provider": engagement.provider if engagement else None,
            "engagement_id": engagement.engagement_id if engagement else None,
            "active": self.activated,
            "scope": len(engagement.in_scope_targets()) if engagement else 0,
            "exclusions": len(engagement.excluded_targets()) if engagement else 0,
            "restrictions": len(engagement.testing_restrictions) if engagement else 0,
            "policy": "ACTIVE" if self.activated else "INACTIVE",
            "external_model": "ENABLED" if external else "DISABLED",
            "evidence": evidence_count,
            "credentials_used": engagement.credentials_used if engagement else False,
            "retrieval_mode": engagement.retrieval_mode if engagement else None,
            "retrieved_at": engagement.retrieved_at if engagement else None,
            "complete": engagement.is_complete() if engagement else False,
            "workspace": str(self.config.data_dir),
        }


# -- helpers ---------------------------------------------------------------


def _manifest_hash(manifest: CandidateManifest) -> str:
    """Fingerprint of the scope a researcher actually confirmed.

    Covers the engagement's scope, exclusions and restrictions but not the
    timestamps, so re-persisting an unchanged manifest is stable.
    """
    from .util import stable_id

    engagement = manifest.engagement
    return stable_id(
        "mfst",
        engagement.provider,
        engagement.engagement_id,
        json.dumps(sorted(t.identifier for t in engagement.targets)),
        json.dumps(sorted(t.identifier for t in engagement.exclusions)),
        json.dumps(sorted(f"{r.name}={r.status}" for r in engagement.testing_restrictions)),
    )


def _looks_like_file(source: str) -> bool:
    candidate = Path(source)
    return candidate.suffix in {".json", ".yaml", ".yml"} and candidate.exists()


def _extract_code(reader: Any, source: str) -> str:
    extractor = getattr(reader, "program_code_from_url", None)
    if callable(extractor):
        return extractor(source)
    return source.strip()


def _normalize_import(provider: str, payload: Any, source: str) -> Engagement:
    """Normalize a researcher-supplied brief into an Engagement."""
    if isinstance(payload, list):
        payload = {"targets": payload}
    if not isinstance(payload, dict):
        raise ConfigError("imported brief must be a JSON object")

    if provider == "bugcrowd":
        from ..readers.bugcrowd.reader import read_engagement_from_payload

        return read_engagement_from_payload(payload, code=str(payload.get("code") or "imported"), source_url=source)

    from ..readers.hackerone.normalizer import normalize_hackerone_payload

    return normalize_hackerone_payload(payload, source_url=source)


def _diff(previous: Engagement, current: Engagement) -> list[str]:
    """Human-readable delta between two engagement reads."""
    changes: list[str] = []
    old_in = {t.identifier.lower() for t in previous.in_scope_targets()}
    new_in = {t.identifier.lower() for t in current.in_scope_targets()}
    old_out = {t.identifier.lower() for t in previous.excluded_targets()}
    new_out = {t.identifier.lower() for t in current.excluded_targets()}

    for identifier in sorted(new_in - old_in):
        changes.append(f"+ in scope: {identifier}")
    for identifier in sorted(old_in - new_in):
        changes.append(f"- in scope: {identifier}")
    for identifier in sorted(new_out - old_out):
        changes.append(f"+ excluded: {identifier}")
    for identifier in sorted(old_out - new_out):
        changes.append(f"- excluded: {identifier}")

    old_rules = {r.name for r in previous.testing_restrictions}
    new_rules = {r.name for r in current.testing_restrictions}
    for name in sorted(new_rules - old_rules):
        changes.append(f"+ restriction: {name}")
    for name in sorted(old_rules - new_rules):
        changes.append(f"- restriction: {name}")
    return changes


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def render_status(session: Session) -> str:
    state = session.state
    if state == STATUS_EMPTY:
        return (
            "No engagement loaded.\n\n"
            "  sro load https://bugcrowd.com/engagements/<code>\n"
            "  sro load https://hackerone.com/<code>\n"
            "  sro import <brief.json> --provider bugcrowd\n"
        )

    engagement = session.require_engagement()
    rows = [
        ("Engagement", engagement.program_name or "-"),
        ("Provider", engagement.provider),
        ("Status", state),
        ("Scope", f"{len(engagement.in_scope_targets())} targets"),
        ("Exclusions", f"{len(engagement.excluded_targets())}"),
        ("Policy", "ACTIVE" if session.activated else "INACTIVE"),
        ("External model", "ENABLED" if session.config.allow_external else "DISABLED"),
        ("Evidence", f"{session.evidence.count()} artifacts"),
        ("Credentials", "used" if engagement.credentials_used else "none required"),
        ("Retrieved", engagement.retrieved_at),
    ]
    width = max(len(label) for label, _ in rows)
    lines = [f"{label.ljust(width)}  {value}" for label, value in rows]
    if not session.activated:
        lines.append("")
        lines.append("This engagement is NOT active. Run `sro review`, then `sro activate`.")
    return "\n".join(lines)
