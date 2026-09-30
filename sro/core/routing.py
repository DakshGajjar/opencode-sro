"""Model router.

SRO is local-first. The router decides which route a task should use, and it
applies one non-negotiable rule: material that is sensitive never goes to an
external provider.

    sensitive -> local, always
    normal    -> local by default
    complex   -> external only when the researcher has permitted it

"Permitted" means `routing.allow_external: true` in sro.json, or an explicit
`/model external` for the session. A model cannot grant itself that permission
and cannot widen the tier a task lands in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .config import Config, ModelRoute
from .util import stable_id, utcnow_iso

FAST_LOCAL = "fast_local"
LOCAL_REASONING = "local_reasoning"
SECURITY_LOCAL = "security_local"
EXTERNAL = "external"

ROUTES = (FAST_LOCAL, LOCAL_REASONING, SECURITY_LOCAL, EXTERNAL)

#: Task classes and the route each defaults to.
TASK_ROUTES: dict[str, str] = {
    "scope_parsing": FAST_LOCAL,
    "tool_selection": FAST_LOCAL,
    "output_parsing": FAST_LOCAL,
    "classification": FAST_LOCAL,
    "log_analysis": LOCAL_REASONING,
    "security_reasoning": LOCAL_REASONING,
    "vulnerability_analysis": LOCAL_REASONING,
    "code_analysis": LOCAL_REASONING,
    "evidence_synthesis": LOCAL_REASONING,
    "report_writing": LOCAL_REASONING,
    "large_context": EXTERNAL,
    "hypothesis_generation": SECURITY_LOCAL,
    "exploit_reasoning": SECURITY_LOCAL,
}
#: Character budget above which a task is treated as large-context work.
LARGE_CONTEXT_THRESHOLD = 120_000

NORMAL = "normal"
SENSITIVE = "sensitive"
SECRET = "secret"

#: Literal substrings that mark material as sensitive. Matching is
#: intentionally broad: a false positive costs a slower local model, a false
#: negative sends a customer's data to a third party.
SENSITIVE_LITERALS: tuple[str, ...] = (
    "password", "passwd", "secret", "api_key", "apikey", "access_key",
    "private_key", "-----begin", "session cookie", "set-cookie", "authorization:",
    "bearer ", "token", "credential", "cookie", "jwt", "client_secret",
    "internal ip", "customer data", "pii",
    "ssn", "social security", "confidential", "proprietary", "nda",
    "unpublished", "unreported",
)

#: Shapes that only a regex can express. These cover the well-known credential
#: prefixes, which are the payloads that most often end up in a log.
SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\beyJ[A-Za-z0-9._\-]{10,}"),            # JWT
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),                # OpenAI-style key
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),          # GitHub token
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                  # AWS access key id
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),                  # AWS temporary key id
    re.compile(r"\b0x[0-9a-fA-F]{40}\b"),                 # private key
    re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),     # RFC1918
    re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b10\.0\.0\.\d{1,3}\b"),
)


@dataclass(slots=True)
class Sensitivity:
    level: str
    reasons: list[str] = field(default_factory=list)
    markers: list[str] = field(default_factory=list)

    @property
    def is_sensitive(self) -> bool:
        return self.level in (SENSITIVE, SECRET)

    def to_dict(self) -> dict[str, Any]:
        return {"level": self.level, "reasons": list(self.reasons), "markers": list(self.markers)}


def classify_sensitivity(text: str, *, declared: str = "") -> Sensitivity:
    """Classify a payload for routing.

    A declared level can raise sensitivity but never lower it. An agent that
    declares "normal" on a payload full of bearer tokens does not get to route
    that payload externally.
    """
    raw = text or ""
    lowered = raw.lower()
    hits: list[str] = [marker for marker in SENSITIVE_LITERALS if marker in lowered]
    hits += [pattern.pattern for pattern in SENSITIVE_PATTERNS if pattern.search(raw)]

    level = NORMAL
    reasons: list[str] = []
    if hits:
        level = SENSITIVE
        reasons.append("payload matched sensitive-data markers")
    if declared == SECRET:
        level = SECRET
        reasons.append("caller declared the payload secret")
    elif declared == SENSITIVE and level == NORMAL:
        level = SENSITIVE
        reasons.append("caller declared the payload sensitive")
    return Sensitivity(level=level, reasons=reasons, markers=sorted(set(hits))[:20])


@dataclass(slots=True)
class RoutingDecision:
    route: str
    provider: str
    model: str
    model_id: str
    task_class: str
    reason: str
    external: bool
    sensitivity: dict[str, Any]
    redacted: bool = False
    overridden: bool = False
    decision_id: str = ""
    decided_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "route": self.route,
            "provider": self.provider,
            "model": self.model,
            "model_id": self.model_id,
            "task_class": self.task_class,
            "reason": self.reason,
            "external": self.external,
            "sensitivity": self.sensitivity,
            "redacted": self.redacted,
            "overridden": self.overridden,
            "decision_id": self.decision_id,
            "decided_at": self.decided_at,
        }


#: Task patterns, written against normalised text and matched in both word
#: orders. "parse the scope table" and "the scope table, parse it" are the same
#: request, and assuming one ordering silently pushes cheap work onto an
#: expensive model.
_TASK_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"\b(?:scope|target|domain|asset)s?\b[^.]*?\b(?:parse|classif|categor|extract|normaliz)\w*"
        r"|\b(?:parse|classif|categor|extract|normaliz)\w*[^.]*?\b(?:scope|target|domain|asset)s?\b",
        "scope_parsing",
    ),
    (
        r"\b(?:choos\w*|pick|select|decid\w*)\b[^.]*?\b(?:tool|approach|method|technique)"
        r"|\b(?:tool|approach|method|technique)\b[^.]*?\b(?:choos\w*|pick|select|decid\w*)\b",
        "tool_selection",
    ),
    (
        r"\b(?:parse|extract|normaliz)\w*[^.]*?\b(?:output|response|json|html|body|result)"
        r"|\b(?:output|response|json|html|body|result)\b[^.]*?\b(?:parse|extract|normaliz)\w*",
        "output_parsing",
    ),
    (r"\b(?:classif\w*|categor\w*|label\w*|tagg?\w*|group\w*)\b", "classification"),
    (
        r"\b(?:log|trace|stack ?trace|debug)\w*\b[^.]*?\b(?:analy\w*|review|read|inspect|examin\w*)\b"
        r"|\b(?:analy\w*|review|inspect|examin\w*)\b[^.]*?\b(?:log|trace|stack ?trace)\w*",
        "log_analysis",
    ),
    (r"\b(?:hypothes\w*|speculat\w*|attack ?surface|threat ?model|attack ?path)\b", "hypothesis_generation"),
    (r"\b(?:synthes\w*|correlat\w*|consolidat\w*)\w*|\bevidence\b", "evidence_synthesis"),
    (r"\b(?:report|write ?up|disclosure|executive summary)\b", "report_writing"),
    (
        r"\b(?:source|code|repo|function|module)\b[^.]*?\b(?:review|analy\w*|audit|read|inspect)\w*"
        r"|\b(?:review|analy\w*|audit|inspect)\w*[^.]*?\b(?:source|code|repo|function|module)\b",
        "code_analysis",
    ),
    (
        r"\b(?:vulnerab\w*|exploit\w*|privilege ?escalat\w*|injection|bypass|idor|access control)\b",
        "vulnerability_analysis",
    ),
    (r"\b(?:exploit\w*|payload|rce|reverse ?shell|lateral ?movement|privilege ?escalat\w*)\b", "exploit_reasoning"),
)


class ModelRouter:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._override: str | None = None

    # -- researcher-controlled override ------------------------------------

    def set_mode(self, mode: str) -> dict[str, Any]:
        """`/model auto|local|external|<route>` — the researcher controls this.

        `external` is refused unless `routing.allow_external` is set in sro.json,
        so a single slash command cannot quietly start shipping engagement data
        to a third party.
        """
        value = (mode or "").strip().lower()
        if value in {"auto", "reset", ""}:
            self._override = None
            return self.mode()
        if value == "local":
            self._override = "local"
        elif value == "external":
            if not self.config.allow_external:
                raise PermissionError(
                    "external inference is disabled. Set routing.allow_external=true in sro.json "
                    "to permit it, then run /model external. SRO will not send engagement data to "
                    "a third-party provider by default."
                )
            self._override = EXTERNAL
        elif value in ROUTES:
            self._override = value
        elif value in {"qwen", "spark"}:
            self._override = LOCAL_REASONING if value == "qwen" else SECURITY_LOCAL
        else:
            raise ValueError(
                f"unknown model mode {mode!r}. Use auto, local, external, or one of {list(ROUTES)}."
            )
        return self.mode()

    def mode(self) -> dict[str, Any]:
        return {
            "mode": self._override or "auto",
            "allow_external_configured": self.config.allow_external,
            "routes": {name: route.model_id for name, route in self.config.routes.items()},
            "external_available": any(r.external for r in self.config.routes.values()),
        }

    # -- classification ----------------------------------------------------

    @staticmethod
    def normalize(task: str) -> str:
        """Fold separators and case so patterns match human phrasing."""
        lowered = re.sub(r"[-_/]+", " ", (task or "").lower())
        return re.sub(r"\s+", " ", lowered).strip()

    @classmethod
    def classify_task(cls, task: str) -> str:
        normalized = cls.normalize(task)
        for pattern, task_class in _TASK_PATTERNS:
            if re.search(pattern, normalized):
                return task_class
        return "security_reasoning"

    def _is_local_model(self, model: ModelRoute) -> bool:
        """Whether a route actually resolves to a model on this machine.

        The route *name* is not evidence. A config can name a route
        "local_reasoning" and point it at a hosted provider, and then a
        sensitivity gate that only inspects the name waves the payload through.
        This asks the model, not the label.
        """
        return not model.external

    def _local_routes(self, candidates: list[str | None]) -> list[tuple[str, ModelRoute]]:
        """Candidates paired with their model, keeping only local ones."""
        out: list[tuple[str, ModelRoute]] = []
        seen: set[str] = set()
        for name in candidates:
            if not name or name in seen:
                continue
            seen.add(name)
            model = self._resolve(name)
            if not model.external:
                out.append((name, model))
        return out

    def _resolve(self, route: str) -> ModelRoute:
        if route in self.config.routes:
            return self.config.routes[route]
        # A route named in code but absent from sro.json still resolves, to a
        # local default, so a missing config degrades to local rather than
        # silently escalating to an external provider.
        if route == EXTERNAL:
            external = [r for r in self.config.routes.values() if r.external]
            if external:
                return external[0]
            return ModelRoute(EXTERNAL, "ollama", "qwen3:14b", external=False)
        fallback = self.config.routes.get(LOCAL_REASONING)
        if fallback is not None:
            return fallback
        return ModelRoute(route, "ollama", "qwen3:14b", external=False)

    # -- the decision ------------------------------------------------------

    def route(
        self,
        *,
        task: str,
        sensitivity: str = "",
        payload: str = "",
        task_class: str = "",
        prefer_external: bool = False,
        context_size: int = 0,
    ) -> RoutingDecision:
        assessment = classify_sensitivity(payload, declared=sensitivity)
        if not task_class:
            task_class = self.classify_task(task)

        override = self._override
        reasons: list[str] = []

        # Rule 1: sensitive material never leaves the machine.
        if assessment.is_sensitive:
            # Walk the candidate routes and take the first that resolves to a
            # model that is genuinely local. If none does, the payload does not
            # get sent anywhere; a refusal is a valid answer here.
            candidates = [
                override if override in {FAST_LOCAL, LOCAL_REASONING, SECURITY_LOCAL} else None,
                LOCAL_REASONING,
                FAST_LOCAL,
                SECURITY_LOCAL,
            ]
            local = self._local_routes(candidates)
            if local:
                name, model = local[0]
                reasons.append(
                    f"payload is {assessment.level}; routed to the local model {model.model_id}"
                )
                if override == EXTERNAL:
                    reasons.append("the external override was ignored for sensitive material")
                return self._finish(name, task_class, reasons, assessment, overridden=True)
            reasons.append(
                f"payload is {assessment.level} and no route resolves to a local model; "
                "refusing to route it anywhere"
            )
            decision = self._finish(LOCAL_REASONING, task_class, reasons, assessment, overridden=True)
            # Fail closed. The flag is the last line of defence for a caller
            # that checks `external` instead of reading the reason.
            decision.external = False
            decision.provider = "none"
            decision.model = "none"
            decision.model_id = "none/local-model-unavailable"
            return decision

        if override == "local":
            route = TASK_ROUTES.get(task_class, LOCAL_REASONING)
            reasons.append("researcher pinned routing to local")
            return self._finish(route, task_class, reasons, assessment, overridden=True)

        if override and override != EXTERNAL:
            reasons.append(f"researcher pinned routing to {override}")
            return self._finish(override, task_class, reasons, assessment, overridden=True)

        route = TASK_ROUTES.get(task_class, LOCAL_REASONING)
        if context_size >= LARGE_CONTEXT_THRESHOLD:
            route = EXTERNAL
            reasons.append(f"context is {context_size} characters, above the large-context threshold")

        external_requested = prefer_external or (override == EXTERNAL)
        if override == EXTERNAL:
            # The researcher pinned the session to an external model. Honour it
            # when sro.json permits it; the sensitivity gate above has already
            # had its chance to veto.
            if self.config.allow_external:
                route = EXTERNAL
                reasons.append("researcher pinned routing to external and sro.json permits it")
            else:
                reasons.append(
                    "external inference is not permitted: routing.allow_external is false in sro.json"
                )
        elif route == EXTERNAL and not external_requested:
            route = LOCAL_REASONING
            reasons.append(
                "large-context work defaults to a local reasoning model; "
                "external requires /model external or an explicit request"
            )
        elif route == EXTERNAL and external_requested and not self.config.allow_external:
            route = LOCAL_REASONING
            reasons.append(
                "external inference is not permitted: routing.allow_external is false in sro.json"
            )
        elif route == EXTERNAL:
            reasons.append("external route selected and permitted")

        # An external request that did not happen gets a reason. Silently
        # ignoring it would leave the researcher thinking engagement data left
        # the machine when it did not, or the reverse.
        if external_requested and route != EXTERNAL and not self.config.allow_external:
            reasons.insert(
                0,
                "external inference is not permitted: routing.allow_external is false in sro.json",
            )
            reasons.append("staying on a local model")

        decision = self._finish(route, task_class, reasons, assessment, overridden=override is not None)
        # One final reconciliation. Every branch above reasons about route
        # names, and only the resolved model knows whether anything leaves the
        # machine. A route that resolves to an external model is demoted to a
        # route that genuinely resolves locally, or refused if none exists.
        if decision.external and not (self.config.allow_external and external_requested):
            local = self._local_routes([LOCAL_REASONING, FAST_LOCAL, SECURITY_LOCAL])
            if local:
                name, model = local[0]
                decision = self._finish(
                    name, task_class,
                    [f"route {route!r} resolves to the external model {decision.model_id}, which is "
                     f"not permitted for this task; using the local model {model.model_id}",
                     *reasons],
                    assessment, overridden=True,
                )
            else:
                decision.external = False
                decision.provider = "none"
                decision.model = "none"
                decision.model_id = "none/local-model-unavailable"
                reasons.append(
                    "every route resolves to an external model and none is permitted; "
                    "no inference will be performed"
                )
        return decision

    def _finish(
        self,
        route: str,
        task_class: str,
        reasons: list[str],
        assessment: Sensitivity,
        *,
        overridden: bool,
    ) -> RoutingDecision:
        model = self._resolve(route)
        reason = "; ".join(reasons)
        return RoutingDecision(
            route=route,
            provider=model.provider,
            model=model.model,
            model_id=model.model_id,
            task_class=task_class,
            reason=reason,
            external=model.external,
            sensitivity=assessment.to_dict(),
            overridden=overridden,
            decision_id=stable_id("route", route, task_class, utcnow_iso()),
        )

    # -- redaction ---------------------------------------------------------

    @staticmethod
    def prepare_for_external(payload: str) -> tuple[str, bool]:
        """Redact a payload before it is considered for an external route.

        Applied even when the route ends up local, so a payload that is later
        re-routed externally has already been through redaction once.
        """
        from .util import redact

        cleaned = redact(payload)
        return cleaned, cleaned != payload

    def guard(self, decision: RoutingDecision, payload: str) -> tuple[str, dict[str, Any]]:
        """Last-mile check: refuse to hand sensitive text to an external route.

        Called immediately before a request leaves the process. If the router
        mis-classified and the payload turns out to contain credentials, the
        payload is redacted rather than sent.
        """
        if not decision.external:
            return payload, {"redacted": False, "reason": "route is local"}
        assessment = classify_sensitivity(payload)
        if not assessment.is_sensitive:
            return payload, {"redacted": False, "reason": "no sensitive markers in payload"}
        cleaned, changed = self.prepare_for_external(payload)
        if not changed:
            # The markers fired but redaction did not remove anything, so the
            # payload is still intact. Reporting a redaction that did not happen
            # would put a false assurance in the audit log.
            return payload, {
                "redacted": False,
                "blocked": True,
                "reason": (
                    "sensitive markers were detected in an external payload and redaction did not "
                    "remove them; the payload was not sent"
                ),
                "markers": assessment.markers,
            }
        return cleaned, {
            "redacted": True,
            "blocked": False,
            "reason": "sensitive markers found in an external payload; redacted before egress",
            "markers": assessment.markers,
        }
