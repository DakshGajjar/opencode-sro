"""Append-only audit log.

Everything that changes authorization state or emits traffic is recorded. The
log is JSONL and append-only on purpose: a researcher reviewing their own
engagement months later needs to be able to trust that the history was not
rewritten.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .util import append_jsonl, read_jsonl, utcnow_iso

# Event types. Keep this closed so log analysis has a stable vocabulary.
EVENT_ENGAGEMENT_LOADED = "engagement.loaded"
EVENT_ENGAGEMENT_REVIEWED = "engagement.reviewed"
EVENT_ENGAGEMENT_ACTIVATED = "engagement.activated"
EVENT_ENGAGEMENT_DEACTIVATED = "engagement.deactivated"
EVENT_SCOPE_CHECKED = "scope.checked"
EVENT_POLICY_ALLOW = "policy.allow"
EVENT_POLICY_DENY = "policy.deny"
EVENT_POLICY_ASK = "policy.ask"
EVENT_TOOL_EXECUTED = "tool.executed"
EVENT_TOOL_BLOCKED = "tool.blocked"
EVENT_EVIDENCE_RECORDED = "evidence.recorded"
EVENT_FINDING_PROPOSED = "finding.proposed"
EVENT_FINDING_VERIFIED = "finding.verified"
EVENT_REPORT_GENERATED = "report.generated"
EVENT_MODEL_ROUTED = "model.routed"
EVENT_UNTRUSTED_CONTENT = "untrusted_content.detected"


class AuditLog:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.path = self.root / "audit" / "sro-audit.jsonl"

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        entry = {"ts": utcnow_iso(), "event": event}
        for key, value in fields.items():
            if value is not None:
                entry[key] = value
        append_jsonl(self.path, entry)
        return entry

    def entries(self, event: str | None = None) -> list[dict[str, Any]]:
        rows = read_jsonl(self.path)
        if event is None:
            return rows
        return [row for row in rows if row.get("event") == event]

    def timeline(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = read_jsonl(self.path)
        return rows[-limit:] if limit > 0 else []

    def count(self, event: str | None = None) -> int:
        return len(self.entries(event))
