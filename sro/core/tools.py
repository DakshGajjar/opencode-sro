"""Security tool broker and catalog.

Agents do not get shell access and they do not get a platform API. They get a
closed catalog of typed tools, each declaring a capability, and every call goes
through the broker:

    execute_tool(tool, target, parameters)
        -> policy evaluation
        -> deny / ask / allow
        -> run the registered handler
        -> evidence record

A tool that is not in the catalog does not exist. A tool that runs an action
its capability does not permit is denied by the policy engine, not by the model
remembering to be careful.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .errors import UnknownCapabilityError, UnknownToolError
from .policy import (
    AD,
    ALLOW,
    API,
    ASK,
    AUTH,
    BROWSER,
    CAPABILITIES,
    CLOUD,
    CODE,
    DENY,
    NETWORK,
    RECON,
    REPORTING,
    WEB,
    PolicyDecision,
    PolicyEngine,
    PolicyRequest,
)

#: Parameter schemas are declared, not inferred. A handler receives a
#: dictionary that has already been shape-checked here, so a handler never has
#: to trust its own arguments.
PARAM_STRS = "str"
PARAM_INT = "int"
PARAM_BOOL = "bool"
PARAM_STR_LIST = "str_list"
PARAM_STR_MAP = "str_map"


@dataclass(slots=True)
class ToolSpec:
    name: str
    capability: str
    description: str
    actions: tuple[str, ...]
    parameters: dict[str, dict[str, Any]] = field(default_factory=dict)
    destructive: bool = False
    requires_target: bool = True
    requires_auth: bool = False
    rate_limited: bool = True
    examples: tuple[str, ...] = ()

    def validate(self, parameters: dict[str, Any]) -> dict[str, Any]:
        """Shape-check parameters against the declared schema."""
        unknown = set(parameters) - set(self.parameters)
        if unknown:
            raise ValueError(
                f"tool {self.name!r} does not accept parameter(s): {sorted(unknown)}; "
                f"accepted: {sorted(self.parameters)}"
            )
        cleaned: dict[str, Any] = {}
        for key, spec in self.parameters.items():
            if key not in parameters or parameters[key] is None:
                if spec.get("required"):
                    raise ValueError(f"tool {self.name!r} requires parameter {key!r}")
                cleaned[key] = spec.get("default")
                continue
            value = parameters[key]
            kind = spec.get("type", PARAM_STRS)
            if kind == PARAM_INT:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(f"parameter {key!r} of {self.name!r} must be an integer")
                value = int(value)
            elif kind == PARAM_BOOL:
                if not isinstance(value, bool):
                    raise ValueError(f"parameter {key!r} of {self.name!r} must be true or false")
            elif kind == PARAM_STR_LIST:
                if isinstance(value, str):
                    value = [value]
                if not isinstance(value, (list, tuple)):
                    raise ValueError(f"parameter {key!r} of {self.name!r} must be a list of strings")
                value = [str(v) for v in value]
            elif kind == PARAM_STR_MAP:
                if not isinstance(value, dict):
                    raise ValueError(f"parameter {key!r} of {self.name!r} must be an object")
                value = {str(k): str(v) for k, v in value.items()}
            else:
                if not isinstance(value, str):
                    raise ValueError(f"parameter {key!r} of {self.name!r} must be a string")
            maximum = spec.get("max_length")
            if isinstance(value, str) and maximum and len(value) > maximum:
                raise ValueError(
                    f"parameter {key!r} of {self.name!r} exceeds {maximum} characters"
                )
            choices = spec.get("choices")
            if choices and value not in choices:
                raise ValueError(
                    f"parameter {key!r} of {self.name!r} must be one of {choices}"
                )
            cleaned[key] = value
        return cleaned


# -- the catalog -----------------------------------------------------------
#
# Every tool SRO can run is listed here. Adding a tool means adding a spec and
# a handler; there is no dynamic registration path an agent could reach.

CATALOG: dict[str, ToolSpec] = {}


def _register(spec: ToolSpec) -> ToolSpec:
    if spec.capability not in CAPABILITIES:
        raise UnknownCapabilityError(
            f"tool {spec.name!r} declared unknown capability {spec.capability!r}"
        )
    # A tool that declares an action the policy engine will not permit is a
    # latent denial: the tool looks available in the catalog and then always
    # fails at the broker. Catch it at import time instead.
    from .policy import ALLOWED_ACTIONS, CONDITIONAL_ACTIONS, CONDITIONAL_CAPABILITY

    permitted = ALLOWED_ACTIONS.get(spec.capability, frozenset())
    for action in spec.actions:
        if action in permitted:
            continue
        if CONDITIONAL_ACTIONS.get(action) and CONDITIONAL_CAPABILITY.get(action) == spec.capability:
            continue
        raise UnknownCapabilityError(
            f"tool {spec.name!r} declares action {action!r}, which the policy engine does not "
            f"permit for capability {spec.capability}. Permitted: {sorted(permitted)}"
        )
    CATALOG[spec.name] = spec
    return spec


_register(
    ToolSpec(
        name="http_request",
        capability=WEB,
        description=(
            "Issue a single HTTP request to an in-scope target and record the full "
            "request and response as evidence. Use this for endpoint-level web testing."
        ),
        actions=("http_get", "http_head", "http_post_test"),
        parameters={
            "url": {"type": PARAM_STRS, "required": True, "max_length": 2048},
            "method": {
                "type": PARAM_STRS,
                "default": "GET",
                "choices": ["GET", "HEAD", "POST"],
            },
            "headers": {"type": PARAM_STR_MAP, "default": {}},
            "body": {"type": PARAM_STRS, "default": "", "max_length": 65536},
            "follow_redirects": {"type": PARAM_BOOL, "default": False},
        },
        destructive=False,
        examples=("http_request(url='https://api.example.com/v1/me')",),
    )
)

_register(
    ToolSpec(
        name="scope_check",
        capability=RECON,
        description=(
            "Ask the deterministic scope engine whether a target is authorized. "
            "Always call this before proposing a test; it never performs network activity."
        ),
        actions=("resolve", "enumerate"),
        parameters={"target": {"type": PARAM_STRS, "required": True, "max_length": 2048}},
        requires_target=False,
        rate_limited=False,
        examples=("scope_check(target='api.example.com')",),
    )
)

_register(
    ToolSpec(
        name="dns_resolve",
        capability=RECON,
        description="Resolve an in-scope hostname and record the answers as evidence.",
        actions=("dns_query",),
        parameters={
            "host": {"type": PARAM_STRS, "required": True, "max_length": 253},
            "record_type": {
                "type": PARAM_STRS,
                "default": "A",
                "choices": ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "PTR"],
            },
        },
        examples=("dns_resolve(host='api.example.com', record_type='A')",),
    )
)

_register(
    ToolSpec(
        name="endpoint_inventory",
        capability=RECON,
        description=(
            "Collect previously observed endpoints for an in-scope target from the local "
            "evidence store. Local read only; performs no network activity."
        ),
        actions=("fetch_metadata",),
        parameters={"target": {"type": PARAM_STRS, "required": True, "max_length": 2048}},
    )
)

_register(
    ToolSpec(
        name="api_schema_fetch",
        capability=API,
        description="Fetch an API specification document (OpenAPI, GraphQL schema) from an in-scope target.",
        actions=("schema_fetch",),
        parameters={
            "url": {"type": PARAM_STRS, "required": True, "max_length": 2048},
            "format": {"type": PARAM_STRS, "default": "auto", "choices": ["auto", "openapi", "graphql", "swagger"]},
        },
    )
)

_register(
    ToolSpec(
        name="auth_session_test",
        capability=AUTH,
        description=(
            "Test an authentication or session control on an in-scope endpoint. "
            "Requires explicit researcher approval before it runs."
        ),
        actions=("auth_test",),
        parameters={
            "url": {"type": PARAM_STRS, "required": True, "max_length": 2048},
            "method": {"type": PARAM_STRS, "default": "GET"},
            "test_case": {"type": PARAM_STRS, "required": True, "max_length": 256},
            "headers": {"type": PARAM_STR_MAP, "default": {}},
            "body": {"type": PARAM_STRS, "default": "", "max_length": 65536},
        },
        destructive=True,
        examples=(
            "auth_session_test(url='https://api.example.com/v1/me', test_case='unauthenticated access')",
        ),
    )
)

_register(
    ToolSpec(
        name="parameter_probe",
        capability=WEB,
        description=(
            "Send a controlled, single-variable request variation to an in-scope endpoint to "
            "observe input handling. Requires explicit researcher approval."
        ),
        actions=("fuzz_parameter", "http_post_test"),
        parameters={
            "url": {"type": PARAM_STRS, "required": True, "max_length": 2048},
            "parameter": {"type": PARAM_STRS, "required": True, "max_length": 128},
            "value": {"type": PARAM_STRS, "default": "", "max_length": 4096},
            "method": {"type": PARAM_STRS, "default": "GET", "choices": ["GET", "POST"]},
        },
        destructive=True,
    )
)

_register(
    ToolSpec(
        name="code_search",
        capability=CODE,
        description=(
            "Search the local source tree for security-relevant patterns. Local operation; "
            "no network activity and no engagement scope check required."
        ),
        actions=("search", "read", "analyze"),
        parameters={
            "pattern": {"type": PARAM_STRS, "required": True, "max_length": 512},
            "path": {"type": PARAM_STRS, "default": ".", "max_length": 1024},
            "max_results": {"type": PARAM_INT, "default": 200},
        },
        requires_target=False,
        rate_limited=False,
    )
)

_register(
    ToolSpec(
        name="cloud_asset_query",
        capability=CLOUD,
        description=(
            "Query a cloud asset inventory provider for in-scope cloud resources. "
            "Requires locally configured cloud credentials and an in-scope account."
        ),
        actions=("enumerate", "policy_read", "config_audit"),
        parameters={
            "provider": {"type": PARAM_STRS, "required": True, "choices": ["aws", "azure", "gcp"]},
            "query": {"type": PARAM_STRS, "default": "", "max_length": 2048},
            "account": {"type": PARAM_STRS, "default": "", "max_length": 128},
        },
        examples=("cloud_asset_query(provider='aws', query='s3 buckets')",),
    )
)

_register(
    ToolSpec(
        name="ad_query",
        capability=AD,
        description=(
            "Query an in-scope directory for users, groups, ACLs or configuration. "
            "Lab and internal environments only unless the engagement names the domain."
        ),
        actions=("enumerate", "ldap_query", "acl_review"),
        parameters={
            "domain": {"type": PARAM_STRS, "default": "", "max_length": 128},
            "query": {"type": PARAM_STR_LIST, "default": []},
            "base_dn": {"type": PARAM_STR_LIST, "default": []},
        },
        examples=("ad_query(domain='lab.example.com', query=['(objectClass=user)'])",),
    )
)

_register(
    ToolSpec(
        name="browser_navigate",
        capability=BROWSER,
        description="Navigate a headless browser to an in-scope URL and capture a screenshot.",
        actions=("navigate", "screenshot", "dom_extract"),
        parameters={
            "url": {"type": PARAM_STRS, "required": True, "max_length": 2048},
            "capture": {"type": PARAM_STR_LIST, "default": ["screenshot"]},
            "wait_ms": {"type": PARAM_INT, "default": 1000},
        },
    )
)

_register(
    ToolSpec(
        name="tls_inspect",
        capability=NETWORK,
        description="Inspect the TLS configuration of an in-scope host: protocol, cipher, chain, expiry.",
        actions=("tls_inspect", "tcp_connect"),
        parameters={
            "host": {"type": PARAM_STRS, "required": True, "max_length": 253},
            "port": {"type": PARAM_INT, "default": 443},
        },
    )
)

_register(
    ToolSpec(
        name="render_report",
        capability=REPORTING,
        description=(
            "Render a report for a finding from recorded evidence. Local operation. "
            "This never submits anything to a platform."
        ),
        actions=("render", "export"),
        parameters={
            "finding": {"type": PARAM_STRS, "default": "", "max_length": 256},
            "format": {"type": PARAM_STRS, "default": "markdown", "choices": ["markdown", "html", "json"]},
            "output": {"type": PARAM_STR_LIST, "default": []},
        },
        requires_target=False,
        rate_limited=False,
    )
)

_register(
    ToolSpec(
        name="record_hypothesis",
        capability=REPORTING,
        description=(
            "Record an investigative hypothesis with its reasoning, suggested test and expected "
            "evidence. A hypothesis is never a finding; the verifier decides that."
        ),
        actions=("render", "export"),
        parameters={
            "title": {"type": PARAM_STRS, "required": True, "max_length": 256},
            "reasoning": {"type": PARAM_STRS, "required": True, "max_length": 8000},
            "suggested_test": {"type": PARAM_STRS, "required": True, "max_length": 4000},
            "expected_evidence": {"type": PARAM_STRS, "required": True, "max_length": 4000},
            "target": {"type": PARAM_STRS, "default": "", "max_length": 2048},
            "finding": {"type": PARAM_STRS, "default": "", "max_length": 256},
        },
        requires_target=False,
        rate_limited=False,
    )
)


def catalog(implemented: set[str] | None = None) -> list[dict[str, Any]]:
    """The tool surface, as advertised to a model.

    No hostnames, no API endpoints, no shell. Just typed tools and the
    capability each one belongs to.

    `implemented` is the set of tools with a registered handler. Where it is
    supplied, each entry carries `implemented`, because a model told a tool
    exists will call it, and calling one that has no handler wastes a turn and
    teaches the model the catalog is unreliable.
    """
    def row(spec: ToolSpec) -> dict[str, Any]:
        data = {
            "name": spec.name,
            "capability": spec.capability,
            "description": spec.description,
            "actions": list(spec.actions),
            "parameters": {
                key: {
                    "type": value.get("type", PARAM_STRS),
                    **({"required": True} if value.get("required") else {}),
                    **({"choices": value["choices"]} if value.get("choices") else {}),
                    **({"default": value["default"]} if "default" in value else {}),
                }
                for key, value in spec.parameters.items()
            },
            "destructive": spec.destructive,
            "requires_target": spec.requires_target,
            "requires_auth": spec.requires_auth,
            "examples": list(spec.examples),
        }
        if implemented is not None:
            data["implemented"] = spec.name in implemented
        return data

    return [row(spec) for spec in sorted(CATALOG.values(), key=lambda s: (s.capability, s.name))]


def capabilities_summary() -> dict[str, list[str]]:
    summary: dict[str, list[str]] = {}
    for spec in sorted(CATALOG.values(), key=lambda s: s.name):
        summary.setdefault(spec.capability, []).append(spec.name)
    return summary


# The broker --------------------------------------------------------------

#: Actions that write to the target. Imported from the policy engine rather than
#: copied, so the broker and the engine cannot disagree about what is
#: destructive and let an action through that the engine would have asked about.
from .policy import DESTRUCTIVE_ACTIONS as _STATE_CHANGING_ACTIONS  # noqa: E402

Handler = Callable[[dict[str, Any], PolicyDecision], Any]


@dataclass(slots=True)
class BrokerResult:
    allowed: bool
    policy: dict[str, Any]
    result: Any = None
    error: str = ""
    evidence_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "policy": self.policy,
            "result": self.result,
            "error": self.error,
            "evidence_id": self.evidence_id,
        }


#: HTTP verbs map to the action names the policy engine knows. A verb is never
#: passed through to the policy layer verbatim, so a method name can never be
#: mistaken for an action the capability permits.
METHOD_ACTIONS = {"GET": "http_get", "HEAD": "http_head", "POST": "http_post_test"}

#: Tools whose action depends on a parameter rather than on the tool itself.
_PARAMETRIC_ACTIONS = {"http_request": "method"}

#: Parameter names that can carry the target, in priority order. `target` comes
#: first because the RECON tools name it that way and omitting it made them
#: permanently unusable through the broker.
_TARGET_PARAMS = ("target", "url", "host", "domain", "base_dn")


def _first_str(parameters: dict[str, Any], names: tuple[str, ...]) -> str:
    for name in names:
        value = parameters.get(name)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, list) and value:
            return str(value[0])
    return ""


class ToolBroker:
    """Gatekeeper between an agent and a security tool.

    The broker owns three things the agent cannot influence: the catalog, the
    policy engine, and the evidence record. A handler is a pure implementation
    detail; it is never reached without a policy ALLOW.
    """

    def __init__(
        self,
        policy: PolicyEngine,
        evidence: Any,
        handlers: dict[str, Handler] | None = None,
    ) -> None:
        self.policy = policy
        self.evidence = evidence
        self.handlers: dict[str, Handler] = dict(handlers or {})

    def register(self, name: str, handler: Handler) -> None:
        if name not in CATALOG:
            raise UnknownToolError(
                f"cannot register handler for unknown tool {name!r}; "
                "add a ToolSpec to the catalog first"
            )
        self.handlers[name] = handler

    @staticmethod
    def _action_for(spec: ToolSpec, parameters: dict[str, Any]) -> str:
        """Derive the policy action for a call.

        A parameter may only narrow the action within the set the spec
        declares, so a caller cannot reach an action the tool does not claim.
        """
        parameter = _PARAMETRIC_ACTIONS.get(spec.name)
        if not parameter:
            return spec.actions[0]
        verb = str(parameters.get(parameter) or "GET").upper()
        action = METHOD_ACTIONS.get(verb)
        if action is None or action not in spec.actions:
            raise ValueError(
                f"tool {spec.name!r} cannot perform {verb!r}; declared actions: {list(spec.actions)}"
            )
        return action

    def describe(self) -> dict[str, Any]:
        return {
            "tools": catalog(),
            "capabilities": self.policy.describe(),
            "note": (
                "Every call is evaluated by the policy engine before a handler runs. "
                "A handler that exists in this process cannot be reached without an ALLOW."
            ),
        }

    def execute(
        self,
        *,
        tool: str,
        target: str = "",
        parameters: dict[str, Any] | None = None,
        agent: str = "unknown",
        user_approved: bool = False,
        authenticated: bool = False,
    ) -> BrokerResult:
        spec = CATALOG.get(tool)
        if spec is None:
            raise UnknownToolError(
                f"unknown tool {tool!r}. Available: {sorted(CATALOG)}. "
                "SRO does not provide arbitrary command execution."
            )

        parameters = spec.validate(dict(parameters or {}))
        action = self._action_for(spec, parameters)
        request = PolicyRequest(
            tool=spec.name,
            action=action,
            target=target or _first_str(parameters, _TARGET_PARAMS),
            capability=spec.capability,
            destructive=spec.destructive or action in _STATE_CHANGING_ACTIONS,
            requires_auth=spec.requires_auth,
            authenticated=authenticated,
            user_approved=user_approved,
            rate_limited=spec.rate_limited,
        )

        decision = self.policy.evaluate(request)
        if decision.result != ALLOW:
            return BrokerResult(
                allowed=False,
                policy=decision.to_dict(),
                error=decision.render(),
            )

        handler = self.handlers.get(spec.name)
        if handler is None:
            message = (
                f"tool {spec.name!r} passed policy but has no handler registered in this "
                "installation. The capability exists; the implementation is not installed."
            )
            return BrokerResult(allowed=False, policy=decision.to_dict(), error=message)

        effective_target = request.target
        try:
            raw = handler(parameters, decision)
        except Exception as exc:  # noqa: BLE001 - a tool failure must be evidence, not a crash
            self.evidence.record_observation(
                tool=spec.name,
                agent=agent,
                target=effective_target,
                capability=spec.capability,
                summary=f"{spec.name} raised {type(exc).__name__}",
                request=parameters,
                result={"error": f"{type(exc).__name__}: {exc}"},
                policy=decision.to_dict(),
            )
            return BrokerResult(
                allowed=True,
                policy=decision.to_dict(),
                error=f"{type(exc).__name__}: {exc}",
            )

        record = self.evidence.record_observation(
            tool=spec.name,
            agent=agent,
            target=effective_target,
            capability=spec.capability,
            summary=_summarize(spec.name, raw),
            request=parameters,
            response=raw if raw is not None else "",
            command=f"{spec.name} completed",
            policy=decision.to_dict(),
        )
        return BrokerResult(
            allowed=True,
            policy=decision.to_dict(),
            result=raw,
            evidence_id=record.evidence_id,
        )


def _summarize(tool: str, raw: Any) -> str:
    if isinstance(raw, dict):
        if "status_code" in raw:
            return f"{tool} -> HTTP {raw.get('status_code')}"
        if "decisions" in raw:
            return f"{tool} -> {len(raw['decisions'])} decision(s)"
        if "records" in raw:
            return f"{tool} -> {len(raw['records'])} record(s)"
        keys = ", ".join(sorted(raw)[:5])
        return f"{tool} -> {keys}"
    return f"{tool} -> {type(raw).__name__}"
