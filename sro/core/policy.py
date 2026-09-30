"""Deterministic security policy engine.

The policy engine is code, not judgement. It never asks a model whether an
action is acceptable. Given a request it walks a fixed ladder of checks and
returns ALLOW, DENY or ASK with a machine-readable reason.

Ladder (first failure wins):

    1.  is an engagement loaded?
    2.  is it activated by the researcher?
    3.  is the tool known and does it declare a capability?
    4.  is the action allowed for that capability?
    5.  does the engagement's testing restrictions permit the action?
    6.  is the target IN_SCOPE per the deterministic scope engine?
    7.  is the operation destructive, and if so has the researcher approved?
    8.  are the engagement's authentication requirements satisfied?
    9.  is the rate limit satisfied?

`UNKNOWN` scope is never ALLOW. It is DENY by default, and can be configured
to ASK, but it can never be configured to allow.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque

from .config import Config
from .engagement import (
    RESTRICTION_BRUTE_FORCE,
    RESTRICTION_CODE_EXECUTION,
    RESTRICTION_DATA_DESTRUCTION,
    RESTRICTION_DOS,
    RESTRICTION_OUT_OF_BAND,
    RESTRICTION_PASSWORD_SPRAY,
    RESTRICTION_PHYSICAL,
    RESTRICTION_PII,
    RESTRICTION_SOCIAL_ENGINEERING,
    RESTRICTION_THIRD_PARTY,
    Engagement,
    Restriction,
)
from .scope import IN_SCOPE, OUT_OF_SCOPE, UNKNOWN, ScopeDecision, ScopeEngine

ALLOW = "ALLOW"
DENY = "DENY"
ASK = "ASK"

#: Tool capabilities. A tool declares exactly one; the model only ever sees
#: capability names, never a platform API.
RECON = "RECON"
WEB = "WEB"
API = "API"
AUTH = "AUTH"
CODE = "CODE"
CLOUD = "CLOUD"
AD = "AD"
BROWSER = "BROWSER"
NETWORK = "NETWORK"
REPORTING = "REPORTING"

CAPABILITIES = (RECON, WEB, API, AUTH, CODE, CLOUD, AD, BROWSER, NETWORK, REPORTING)

#: Capabilities that inherently require a network target. CODE and REPORTING
#: are local operations and skip the scope check.
NETWORK_CAPABILITIES = frozenset({RECON, WEB, API, AUTH, CLOUD, AD, BROWSER, NETWORK})

#: Actions each capability may perform. Anything outside this set is denied for
#: that capability, so a new tool cannot quietly gain a new action.
ALLOWED_ACTIONS: dict[str, frozenset[str]] = {
    RECON: frozenset({"resolve", "discover", "enumerate", "fingerprint", "fetch_metadata", "dns_query"}),
    WEB: frozenset({"http_get", "http_head", "http_post_test", "crawl", "scan", "fuzz_parameter"}),
    API: frozenset({"http_get", "http_post_test", "schema_fetch", "auth_test", "fuzz_parameter"}),
    AUTH: frozenset({"auth_test", "session_replay", "token_inspect"}),
    CODE: frozenset({"read", "search", "analyze", "sast"}),
    CLOUD: frozenset({"enumerate", "policy_read", "config_audit"}),
    AD: frozenset({"enumerate", "ldap_query", "auth_test", "acl_review"}),
    BROWSER: frozenset({"navigate", "screenshot", "dom_extract", "form_interact"}),
    NETWORK: frozenset({"tcp_connect", "dns_query", "tls_inspect"}),
    REPORTING: frozenset({"render", "export"}),
}

#: Techniques that are not SRO actions at all, and become actions only when the
#: engagement explicitly permits the matching restriction.
#:
#: Keeping them out of ALLOWED_ACTIONS is the primary control: an agent cannot
#: ask for a denial-of-service action and have it be merely "not implemented".
#: They appear here so that a program which genuinely permits, say, password
#: spraying can be honoured, and so that a program which forbids it produces a
#: clear DENY rather than a confusing "action not permitted".
CONDITIONAL_ACTIONS: dict[str, str] = {
    "dos": RESTRICTION_DOS,
    "load_test": RESTRICTION_DOS,
    "password_spray": RESTRICTION_PASSWORD_SPRAY,
    "brute_force": RESTRICTION_BRUTE_FORCE,
    "credential_stuffing": RESTRICTION_BRUTE_FORCE,
    "social_engineering": RESTRICTION_SOCIAL_ENGINEERING,
    "physical_test": RESTRICTION_PHYSICAL,
    "data_destruction": RESTRICTION_DATA_DESTRUCTION,
}

#: Which capability an activated conditional action belongs to.
CONDITIONAL_CAPABILITY: dict[str, str] = {
    "dos": WEB,
    "load_test": WEB,
    "password_spray": AUTH,
    "brute_force": AUTH,
    "credential_stuffing": AUTH,
    "social_engineering": AD,
    "physical_test": AD,
    "data_destruction": WEB,
}

#: Actions that change state on the target and always require explicit approval.
DESTRUCTIVE_ACTIONS = frozenset({"http_post_test", "fuzz_parameter", "auth_test", "form_interact"})

#: Map an action to the engagement restriction that governs it. The
#: engagement's `forbidden_testing` list is populated with these names by the
#: readers, so a program that forbids DoS blocks DoS without any model input.
ACTION_RESTRICTION_MAP: dict[str, str] = {
    "dos": RESTRICTION_DOS,
    "load_test": RESTRICTION_DOS,
    "flood": RESTRICTION_DOS,
    "social_engineering": RESTRICTION_SOCIAL_ENGINEERING,
    "pretexting": RESTRICTION_SOCIAL_ENGINEERING,
    "phishing": RESTRICTION_SOCIAL_ENGINEERING,
    "physical": RESTRICTION_PHYSICAL,
    "tailgating": RESTRICTION_PHYSICAL,
    "password_spray": RESTRICTION_PASSWORD_SPRAY,
    "password_spraying": RESTRICTION_PASSWORD_SPRAY,
    "brute_force": RESTRICTION_BRUTE_FORCE,
    "bruteforce": RESTRICTION_BRUTE_FORCE,
    "credential_stuffing": RESTRICTION_BRUTE_FORCE,
    "data_destruction": RESTRICTION_DATA_DESTRUCTION,
    "delete_data": RESTRICTION_DATA_DESTRUCTION,
    "third_party": RESTRICTION_THIRD_PARTY,
    "vendor_scan": RESTRICTION_THIRD_PARTY,
    "pii": RESTRICTION_PII,
    "customer_data": RESTRICTION_PII,
    "out_of_band": RESTRICTION_OUT_OF_BAND,
    "rce": RESTRICTION_CODE_EXECUTION,
    "command_execution": RESTRICTION_CODE_EXECUTION,
    "ldap_injection": "",
    "acl_review": "",
    "schema_fetch": "",
    "tcp_connect": "",
    "tls_inspect": "",
}

#: Canonical restriction names the readers emit into `forbidden_testing` /
#: `allowed_testing` so a plain-text brief can still drive the policy engine.
_RESTRICTION_TOKENS = frozenset(
    {
        RESTRICTION_DOS,
        RESTRICTION_SOCIAL_ENGINEERING,
        RESTRICTION_PHYSICAL,
        RESTRICTION_THIRD_PARTY,
        RESTRICTION_DATA_DESTRUCTION,
        RESTRICTION_PASSWORD_SPRAY,
        RESTRICTION_BRUTE_FORCE,
        RESTRICTION_PII,
        RESTRICTION_OUT_OF_BAND,
        RESTRICTION_CODE_EXECUTION,
        "automated_scanning",
        "live_customer_data",
    }
)


@dataclass(slots=True)
class RateLimiter:
    """Sliding-window limiter, per host and global.

    Thread-safe because OpenCode can run tool calls concurrently within a
    session and a rate limit that races is not a rate limit.
    """

    global_per_minute: int = 60
    per_host_per_minute: int = 20
    _global_events: Deque[float] = field(default_factory=deque)
    _host_events: dict[str, Deque[float]] = field(default_factory=lambda: defaultdict(deque))
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def check(self, host: str = "*") -> tuple[bool, dict[str, Any]]:
        now = time.monotonic()
        with self._lock:
            self._prune(self._global_events, now, self.global_per_minute)
            self._prune(self._host_events[host], now, self.per_host_per_minute)
            global_ok = len(self._global_events) < self.global_per_minute
            host_ok = len(self._host_events[host]) < self.per_host_per_minute
            if not global_ok or not host_ok:
                return False, {
                    "global_count": len(self._global_events),
                    "global_limit": self.global_per_minute,
                    "host_count": len(self._host_events[host]),
                    "host_limit": self.per_host_per_minute,
                    "host": host,
                }
            self._global_events.append(now)
            self._host_events[host].append(now)
        return True, {
            "global_count": len(self._global_events),
            "global_limit": self.global_per_minute,
            "host_count": len(self._host_events[host]),
            "host_limit": self.per_host_per_minute,
            "host": host,
        }

    def _prune(self, events: Deque[float], now: float, limit: int) -> None:
        window = 60.0
        while events and now - events[0] > window:
            events.popleft()
        # Keep memory bounded even if a limit is configured absurdly high.
        while len(events) > max(limit * 2, 1000):
            events.popleft()


@dataclass(slots=True)
class PolicyRequest:
    """Everything the policy engine needs. Nothing else is consulted.

    `capability` is a claim, not a fact. The engine reconciles it against the
    tool catalog, because a caller that declares its own capability could claim
    the local-only CODE capability for a network action and skip the scope check
    entirely. A declared capability that disagrees with the catalog is denied.
    """

    tool: str
    action: str
    target: str = ""
    capability: str = ""
    destructive: bool = False
    requires_auth: bool = False
    authenticated: bool = False
    user_approved: bool = False
    rate_limited: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PolicyDecision:
    result: str
    reason: str
    code: str
    target: str = ""
    capability: str = ""
    tool: str = ""
    scope_status: str = ""
    scope: dict[str, Any] | None = None
    restrictions: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.result == ALLOW

    @property
    def needs_approval(self) -> bool:
        return self.result == ASK

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "reason": self.reason,
            "code": self.code,
            "target": self.target,
            "tool": self.tool,
            "capability": self.capability,
            "scope_status": self.scope_status,
            "scope": self.scope,
            "restrictions": list(self.restrictions),
            "detail": self.detail,
        }

    def render(self) -> str:
        if self.result == ALLOW:
            return (
                f"Policy: ALLOW\n"
                f"  Tool:      {self.tool} ({self.capability})\n"
                f"  Action:    {self.action_label()}\n"
                f"  Target:    {self.target or '(local)'}\n"
                f"  Scope:     {self.scope_status or 'n/a'}\n"
                f"  Reason:    {self.reason}"
            )
        head = "SRO POLICY DENIED" if self.result == DENY else "SRO POLICY REQUIRES APPROVAL"
        lines = [
            head,
            "",
            "Tool:",
            f"  {self.tool} ({self.capability})",
            "",
            "Action:",
            f"  {self.action_label()}",
        ]
        if self.target:
            lines += ["", "Target:", f"  {self.target}"]
        lines += ["", "Reason:", f"  {self.reason}"]
        if self.scope_status:
            lines += ["", f"Scope: {self.scope_status}"]
        if self.result == DENY:
            lines += ["", "No network request was made."]
        else:
            lines += [
                "",
                "This action is permitted by the engagement but requires explicit",
                "researcher approval before it will run.",
            ]
        return "\n".join(lines)

    def action_label(self) -> str:
        return str(self.detail.get("action") or self.code)


class PolicyEngine:
    def __init__(
        self,
        config: Config,
        scope_engine: ScopeEngine | None = None,
        engagement: Engagement | None = None,
        active: bool = False,
    ) -> None:
        self.config = config
        self.engagement = engagement
        self.scope_engine = scope_engine or ScopeEngine(engagement=engagement, active=active)
        self.rate_limiter = RateLimiter(
            global_per_minute=config.rate_limit_per_minute,
            per_host_per_minute=config.rate_limit_per_host_per_minute,
        )
        self.active = active

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _catalog_capability(tool: str) -> str | None:
        """The capability the tool catalog assigns to a tool, or None."""
        from .tools import CATALOG

        spec = CATALOG.get(tool)
        return spec.capability if spec else None

    def _restriction_status(self, name: str) -> str:
        """Look up a restriction across the structured and text representations."""
        if self.engagement is None:
            return "unknown"
        needle = name.strip().lower().replace("-", "_")
        for restriction in self.engagement.testing_restrictions:
            if restriction.name.strip().lower().replace("-", "_") == needle:
                return restriction.status
        for item in self.engagement.forbidden_testing:
            if item.strip().lower().replace("-", "_") in {needle, name}:
                return "forbidden"
        for item in self.engagement.allowed_testing:
            if item.strip().lower().replace("-", "_") in {needle, name}:
                return "permitted"
        return "unknown"

    @staticmethod
    def _collect_restrictions(engagement: Engagement | None) -> list[str]:
        if engagement is None:
            return []
        return [f"{r.name}={r.status}" for r in engagement.testing_restrictions]

    # -- the ladder --------------------------------------------------------

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        detail: dict[str, Any] = {"action": request.action}

        # 1. engagement loaded
        if self.engagement is None:
            return PolicyDecision(
                result=DENY,
                reason="no engagement is loaded; load and activate an engagement first",
                code="no_engagement",
                target=request.target,
                tool=request.tool,
                capability=request.capability,
                detail=detail,
            )

        # 2. activated
        if not self.active:
            return PolicyDecision(
                result=DENY,
                reason="engagement is loaded but not activated; the researcher has not confirmed scope",
                code="engagement_not_active",
                target=request.target,
                tool=request.tool,
                capability=request.capability,
                detail=detail,
            )

        # 3. known tool + declared capability.
        #
        # The tool catalog is the authority on which capability a tool belongs
        # to. Without this reconciliation the capability field is attacker-
        # controlled: a caller declaring CODE (local, no scope check) for an
        # http_get would sail past step 6.
        catalog_capability = self._catalog_capability(request.tool)
        if catalog_capability is None:
            return PolicyDecision(
                result=DENY,
                reason=(
                    f"tool {request.tool!r} is not in the SRO tool catalog; "
                    "SRO has no capability for an unrecognised tool"
                ),
                code="unknown_tool",
                target=request.target,
                tool=request.tool,
                capability=request.capability,
                detail=detail,
            )
        if request.capability and request.capability != catalog_capability:
            return PolicyDecision(
                result=DENY,
                reason=(
                    f"tool {request.tool!r} belongs to capability {catalog_capability}, not "
                    f"{request.capability}; the declared capability was rejected"
                ),
                code="capability_mismatch",
                target=request.target,
                tool=request.tool,
                capability=request.capability,
                detail=detail,
            )
        request.capability = catalog_capability

        if request.capability not in CAPABILITIES:
            return PolicyDecision(
                result=DENY,
                reason=(
                    f"tool {request.tool!r} did not declare a valid capability; "
                    "the model may only select from declared capabilities"
                ),
                code="invalid_capability",
                target=request.target,
                tool=request.tool,
                capability=request.capability,
                detail=detail,
            )
        allowed_actions = set(ALLOWED_ACTIONS.get(request.capability, frozenset()))
        conditional_for_capability = {
            action
            for action, capability in CONDITIONAL_CAPABILITY.items()
            if capability == request.capability
        }
        is_conditional = request.action in CONDITIONAL_ACTIONS

        if request.action not in allowed_actions:
            if not is_conditional or request.action not in conditional_for_capability:
                return PolicyDecision(
                    result=DENY,
                    reason=(
                        f"action {request.action!r} is not permitted for capability "
                        f"{request.capability}; permitted: {sorted(allowed_actions)}"
                    ),
                    code="action_not_permitted",
                    target=request.target,
                    tool=request.tool,
                    capability=request.capability,
                    detail=detail,
                )

        # 4/5. engagement restrictions on this action
        restriction_name = ACTION_RESTRICTION_MAP.get(
            request.action, CONDITIONAL_ACTIONS.get(request.action, "")
        )
        if restriction_name:
            status = self._restriction_status(restriction_name)
            if status == "forbidden":
                return PolicyDecision(
                    result=DENY,
                    reason=(
                        f"the engagement forbids {restriction_name} and the requested action "
                        f"({request.action}) maps to it"
                    ),
                    code="restriction_forbidden",
                    target=request.target,
                    tool=request.tool,
                    capability=request.capability,
                    restrictions=self._collect_restrictions(self.engagement),
                    detail=detail,
                )
            if is_conditional and status != "permitted":
                # A conditional technique is not an action SRO performs merely
                # because it was requested. It requires the program to have
                # said yes.
                return PolicyDecision(
                    result=ASK,
                    reason=(
                        f"{request.action!r} is a {restriction_name} technique and the engagement "
                        f"does not state that {restriction_name} is permitted. This is a "
                        "destructive technique; confirm the program rules before running it."
                    ),
                    code="conditional_action_unconfirmed",
                    target=request.target,
                    tool=request.tool,
                    capability=request.capability,
                    restrictions=self._collect_restrictions(self.engagement),
                    detail=detail,
                )
            if status == "conditional":
                return PolicyDecision(
                    result=ASK,
                    reason=(
                        f"the engagement makes {restriction_name} conditional, and the requested "
                        f"action ({request.action}) depends on it; confirm the condition is met"
                    ),
                    code="restriction_conditional",
                    target=request.target,
                    tool=request.tool,
                    capability=request.capability,
                    restrictions=self._collect_restrictions(self.engagement),
                    detail=detail,
                )
            if status == "unknown":
                return PolicyDecision(
                    result=ASK,
                    reason=(
                        f"the engagement does not state whether {restriction_name} is permitted; "
                        "confirm the program rules before performing this action"
                    ),
                    code="restriction_unstated",
                    target=request.target,
                    tool=request.tool,
                    capability=request.capability,
                    restrictions=self._collect_restrictions(self.engagement),
                    detail=detail,
                )

        # 6. scope
        scope_decision: ScopeDecision | None = None
        if request.capability in NETWORK_CAPABILITIES:
            if not request.target:
                return PolicyDecision(
                    result=DENY,
                    reason="a network capability requires an explicit target",
                    code="missing_target",
                    tool=request.tool,
                    capability=request.capability,
                    detail=detail,
                )
            scope_decision = self.scope_engine.check(request.target)
            if scope_decision.status == OUT_OF_SCOPE:
                return PolicyDecision(
                    result=DENY,
                    reason=scope_decision.reason,
                    code="out_of_scope",
                    target=request.target,
                    tool=request.tool,
                    capability=request.capability,
                    scope_status=OUT_OF_SCOPE,
                    scope=scope_decision.to_dict(),
                    detail=detail,
                )
            if scope_decision.status == UNKNOWN:
                # Never ALLOW. Deny by default, or ask if the operator prefers.
                result = ASK if self.config.unknown_scope_action == "ask" else DENY
                return PolicyDecision(
                    result=result,
                    reason=(
                        f"target is not established as authorized: {scope_decision.reason}"
                        + (
                            "; clarify with the program or add the target to the manifest"
                            if result == ASK
                            else ""
                        )
                    ),
                    code="scope_unknown",
                    target=request.target,
                    tool=request.tool,
                    capability=request.capability,
                    scope_status=UNKNOWN,
                    scope=scope_decision.to_dict(),
                    detail=detail,
                )

        # 7. destructive operations
        is_destructive = request.destructive or request.action in DESTRUCTIVE_ACTIONS
        if is_destructive and not request.user_approved:
            if self.config.destructive_requires_ask:
                return PolicyDecision(
                    result=ASK,
                    reason=(
                        f"action {request.action!r} changes state on the target; "
                        "explicit researcher approval is required"
                    ),
                    code="destructive_requires_approval",
                    target=request.target,
                    tool=request.tool,
                    capability=request.capability,
                    scope_status=scope_decision.status if scope_decision else "",
                    scope=scope_decision.to_dict() if scope_decision else None,
                    restrictions=self._collect_restrictions(self.engagement),
                    detail=detail,
                )
            return PolicyDecision(
                result=DENY,
                reason=f"destructive action {request.action!r} is disabled by policy",
                code="destructive_disabled",
                target=request.target,
                tool=request.tool,
                capability=request.capability,
                detail=detail,
            )

        # 8. authentication requirements
        if request.requires_auth and not request.authenticated:
            requirements = (self.engagement.authentication_requirements or "").strip()
            return PolicyDecision(
                result=ASK,
                reason=(
                    "this target requires authenticated testing per the engagement but no "
                    "authenticated session was supplied"
                    + (f": {requirements}" if requirements else "")
                ),
                code="auth_required",
                target=request.target,
                tool=request.tool,
                capability=request.capability,
                scope_status=scope_decision.status if scope_decision else "",
                scope=scope_decision.to_dict() if scope_decision else None,
                detail=detail,
            )

        # 9. rate limit
        if request.rate_limited and request.capability in NETWORK_CAPABILITIES:
            host = scope_decision.target_ref.get("host") or scope_decision.target_ref.get("ip") or "*"
            ok, rate_info = self.rate_limiter.check(str(host))
            detail["rate_limit"] = rate_info
            if not ok:
                return PolicyDecision(
                    result=DENY,
                    reason=(
                        f"engagement rate limit reached for {host} "
                        f"({rate_info['host_count']}/{rate_info['host_limit']} per minute)"
                    ),
                    code="rate_limited",
                    target=request.target,
                    tool=request.tool,
                    capability=request.capability,
                    scope_status=scope_decision.status if scope_decision else "",
                    scope=scope_decision.to_dict() if scope_decision else None,
                    detail=detail,
                )

        return PolicyDecision(
            result=ALLOW,
            reason=(
                f"target resolved {scope_decision.status if scope_decision else 'n/a'} and the "
                "engagement permits this action"
            ),
            code="allowed",
            target=request.target,
            tool=request.tool,
            capability=request.capability,
            scope_status=scope_decision.status if scope_decision else "",
            scope=scope_decision.to_dict() if scope_decision else None,
            restrictions=self._collect_restrictions(self.engagement),
            detail=detail,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "engagement_loaded": self.engagement is not None,
            "engagement_active": self.active,
            "capabilities": list(CAPABILITIES),
            "actions_by_capability": {k: sorted(v) for k, v in ALLOWED_ACTIONS.items()},
            "destructive_actions": sorted(DESTRUCTIVE_ACTIONS),
            "action_restriction_map": {k: v for k, v in ACTION_RESTRICTION_MAP.items() if v},
            "rate_limits": {
                "global_per_minute": self.config.rate_limit_per_minute,
                "per_host_per_minute": self.config.rate_limit_per_host_per_minute,
            },
            "unknown_scope_action": self.config.unknown_scope_action,
            "out_of_scope_action": self.config.out_of_scope_action,
        }


def restrictions_to_engagement_fields(
    restrictions: list[Restriction],
) -> tuple[list[str], list[str]]:
    """Split structured restrictions into the engine's allow/deny lists."""
    allowed: list[str] = []
    forbidden: list[str] = []
    for restriction in restrictions:
        if restriction.status == "forbidden":
            forbidden.append(restriction.name)
        elif restriction.status == "permitted":
            allowed.append(restriction.name)
    return allowed, forbidden
