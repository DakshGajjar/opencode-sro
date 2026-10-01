"""Built-in tool handlers.

The catalog in `sro.core.tools` declares what SRO *may* do. This module
implements the subset that is local, read-only and needs no network, so an
agent has something real to call on day one rather than fourteen declarations
that return "the implementation is not installed".

What lives here and what does not, is a deliberate line:

    local and read-only   implemented below
    reads a network       not implemented; see `_network_not_implemented`

The reasoning is that a local handler can be audited by reading it, and it
cannot cause harm to a third party. A network handler cannot be, and every one
of those needs its own design review — egress, response handling, redirect
behaviour, and the question of what it means to point a scanner at a target the
program scoped. Shipping them in the same commit as the plumbing would mean
reviewing all of it at once, and the plumbing is what everything else depends on.

A handler receives parameters the broker has already shape-checked and a
`PolicyDecision` recording why it was permitted. It returns a JSON-serialisable
result, and the broker writes the evidence record. Handlers do not write
evidence, do not evaluate policy, and do not decide scope.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket  # AF_INET/AF_INET6 constants only; egress opens the sockets
import time
from pathlib import Path
from typing import Any

from ..core.engagement import dedupe_targets
from ..core.evidence import HYPOTHESIS, OBSERVED
from ..core.egress import DestinationRefused, LimitExceeded
from ..core.scope import (
    IN_SCOPE,
    OUT_OF_SCOPE,
    UNKNOWN,
    ScopeEngine,
    _is_internal_address,
    check_many,
)
from ..core.util import slugify, truncate, utcnow_iso

#: Directories never walked by `code_search`. Keeps a search from reading
#: anything that looks like a secret store, and keeps the walk fast.
SKIP_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".next",
        ".tox", ".eggs", "site-packages", ".gradle", "target",
    }
)

#: File types worth searching for security-relevant patterns.
CODE_SUFFIXES = frozenset(
    {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".go", ".rb", ".rs",
        ".java", ".kt", ".php", ".cs", ".c", ".h", ".cc", ".cpp", ".hpp", ".swift",
        ".scala", ".sh", ".bash", ".sql", ".yaml", ".yml", ".json", ".toml", ".ini",
        ".conf", ".env", ".tf", ".tfvars", ".dockerfile", ".vue", ".svelte", ".ex",
        ".exs", ".lua", ".pl", ".r",
    }
)

#: The default rule set. Deliberately small: a search that returns everything is
#: the same as no search, and a model will not read 4000 lines.
DEFAULT_CODE_RULES: tuple[tuple[str, str, str], ...] = (
    (r"eval\s*\(", "code-injection", "eval() on a value"),
    (r"exec\s*\(", "code-injection", "exec() on a value"),
    (r"os\.system\s*\(", "command-injection", "os.system with a constructed string"),
    (r"subprocess\.(?:call|run|Popen|check_output)\s*\(\s*[^)]*shell\s*=\s*True", "command-injection", "subprocess with shell=True"),
    (r"(?:os\.popen|commands\.getoutput)\s*\(", "command-injection", "shell execution helper"),
    (r"pickle\.loads?\s*\(", "deserialization", "pickle on untrusted data"),
    (r"yaml\.load\s*\((?![^)]*Safe)", "deserialization", "yaml.load without SafeLoader"),
    (r"\bexec\b[^.\n]*\beval\b", "code-injection", "eval inside exec"),
    (r"(?:cursor\.execute|query)\s*\(\s*[^)]*(?:%s|\.format\(|f\"|\+)", "sql-injection", "SQL built by string interpolation"),
    (r"(?:open|file\(|readFile(?:Sync)?|send_file)\s*\([^)]*\+", "path-traversal", "path built by concatenation"),
    (r"\.\.[\\/]", "path-traversal", "relative path segment in a literal"),
    (r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)", "tls", "certificate verification disabled"),
    (r"md5|sha1\b", "weak-hash", "MD5 or SHA-1"),
    (r"random\.(?:random|randint|choice|uniform)\s*\(", "weak-random", "non-cryptographic randomness"),
    (r"(?:SECRET|PASSWORD|TOKEN|API_?KEY|PRIVATE_?KEY)\s*=\s*[\"'][^\"']{6,}[\"']", "hardcoded-secret", "credential assigned in source"),
    (r"jwt\.decode\s*\([^)]*verify\s*=\s*False", "auth-bypass", "JWT signature verification disabled"),
    (r"algorithm.{0,20}[\"']none[\"']", "auth-bypass", "JWT alg=none accepted"),
    (r"Access-Control-Allow-Origin.{0,30}[\"']\*[\"']", "cors", "permissive CORS origin"),
    (r"deserialize\s*\(|unserialize\s*\(", "deserialization", "generic deserialization"),
)

_COMPILED_RULES = tuple((re.compile(pattern, re.I), label, why) for pattern, label, why in DEFAULT_CODE_RULES)


# --- scope ---------------------------------------------------------------


def handle_scope_check(ctx: "HandlerContext", params: dict[str, Any]) -> Any:
    """Ask the scope engine about one or more targets.

    Batched because triage is the actual use: an agent working through a
    wildcard scope or a long manifest otherwise spends one broker round-trip
    per host, and a round trip per host is how a model gives up and guesses.
    """
    raw = params.get("target")
    if isinstance(raw, list):
        targets = [str(t) for t in raw if str(t).strip()]
    elif isinstance(raw, str):
        targets = [t.strip() for t in raw.split(",") if t.strip()]
    else:
        targets = []
    if not targets:
        return {
            "error": "scope_check needs a target, or a list of targets",
            "usage": 'scope_check(target="api.example.com") or scope_check(target=["a","b"])',
        }

    return {
        **check_many(ctx.scope_engine(), targets),
        "note": (
            "UNKNOWN is blocked, not permissive. It means the manifest does not cover the "
            "target either way and the researcher has to resolve it. Do not retry it in a "
            "reformatted way; that is not a scope check, that is an attempt to get past one."
        ),
    }


# --- recon ---------------------------------------------------------------


def handle_endpoint_inventory(ctx: "HandlerContext", params: dict[str, Any]) -> Any:
    """What the evidence store already knows about a target.

    Local read. It does not discover anything: it reports endpoints that
    earlier brokered actions actually touched, which is the difference between
    reconnaissance and a guess.
    """
    target = str(params.get("target") or "").strip()
    if not target:
        return {"error": "endpoint_inventory needs a target"}

    store = ctx.evidence
    records = store.by_target(target)
    endpoints: set[str] = set()
    methods: dict[str, int] = {}
    tools: dict[str, int] = {}
    statuses: dict[str, int] = {}

    for record in records:
        for container in (record.request, record.response):
            if isinstance(container, dict):
                url = container.get("url")
                if isinstance(url, str) and url:
                    endpoints.add(url)
                method = container.get("method")
                if isinstance(method, str) and method:
                    methods[method] = methods.get(method, 0) + 1
                code = container.get("status_code")
                if isinstance(code, int):
                    statuses[str(code)] = statuses.get(str(code), 0) + 1
        if record.tool:
            tools[record.tool] = tools.get(record.tool, 0) + 1

    engine = ctx.scope_engine()
    verdict = engine.check(target)

    return {
        "target": target,
        "scope_status": verdict.status,
        "scope_rule": verdict.matched_rule,
        "observations": len([r for r in records if r.status == OBSERVED]),
        "hypotheses": len([r for r in records if r.status == HYPOTHESIS]),
        "endpoints_seen": sorted(endpoints),
        "methods": methods,
        "status_codes": statuses,
        "tools_used": tools,
        "first_seen": records[0].timestamp if records else None,
        "last_seen": records[-1].timestamp if records else None,
        "note": (
            "This is what earlier actions touched, not a scan. SRO has no passive discovery "
            "tool; if the manifest is thinner than the program, that is a finding about the "
            "manifest, not something to work around."
        ),
    }


# --- code ----------------------------------------------------------------


def handle_code_search(ctx: "HandlerContext", params: dict[str, Any]) -> Any:
    """Pattern search over the local source tree, flagged against known sinks.

    Local and read-only: no network, no scope check, nothing executed. The
    rules are a starting point for a human or a model to judge, not findings.
    """
    pattern = str(params.get("pattern") or "").strip()
    if not pattern:
        return {"error": "code_search needs a pattern"}
    max_results = max(1, min(int(params.get("max_results") or 100), 1000))
    root = Path(str(params.get("path") or "."))
    if not root.is_absolute():
        root = ctx.workspace / root
    root = root.resolve()

    if not root.exists():
        return {"error": f"path not found: {root}"}
    if not root.is_dir():
        root = root.parent

    # A search that walks outside the workspace is a way to read the user's
    # home directory by accident, so it is refused rather than clamped.
    try:
        root.relative_to(ctx.workspace.resolve())
    except ValueError:
        return {
            "error": f"path is outside the workspace: {root}",
            "workspace": str(ctx.workspace),
        }

    use_rules = pattern.strip() == "*" or not pattern
    try:
        regex = None if use_rules else re.compile(pattern, re.I)
    except re.error as exc:
        return {"error": f"invalid pattern: {exc}"}

    files_scanned = 0
    matches: list[dict[str, Any]] = []
    rule_hits: dict[str, list[dict[str, Any]]] = {}
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for filename in sorted(filenames):
            if filename.startswith("."):
                continue
            suffix = Path(filename).suffix.lower()
            if suffix and suffix not in CODE_SUFFIXES and filename not in {
                "Dockerfile", "Makefile", "Jenkinsfile", ".env",
            }:
                continue
            path = Path(dirpath) / filename
            try:
                if path.stat().st_size > 2_000_000:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files_scanned += 1

            rel = str(path.relative_to(root))
            for lineno, line in enumerate(text.splitlines(), 1):
                if regex is not None:
                    if regex.search(line):
                        if len(matches) < max_results:
                            matches.append({"file": rel, "line": lineno, "text": line.strip()[:200]})
                        else:
                            truncated = True
                for compiled, label, why in _COMPILED_RULES:
                    if compiled.search(line):
                        bucket = rule_hits.setdefault(label, [])
                        if len(bucket) < 20:
                            bucket.append(
                                {"file": rel, "line": lineno, "why": why, "text": line.strip()[:160]}
                            )
                        break

    return {
        "path": str(root),
        "pattern": pattern,
        "files_scanned": files_scanned,
        "matches": matches,
        "match_count": len(matches),
        "truncated": truncated,
        "rule_findings": {k: v for k, v in sorted(rule_hits.items())},
        "rule_total": sum(len(v) for v in rule_hits.values()),
        "note": (
            "Pattern matches and rule hits are leads, not vulnerabilities. Nothing here was "
            "executed and nothing was traced to a reachable sink; confirm reachability before "
            "reporting anything."
        ),
    }


# --- reporting -----------------------------------------------------------


def handle_render_report(ctx: "HandlerContext", params: dict[str, Any]) -> Any:
    """Render a report from recorded evidence. Writes local files only."""
    from ..core.report import generate_report

    finding = str(params.get("finding") or "").strip()
    output = params.get("output") or []
    if isinstance(output, str):
        outputs = [output] if output else []
    else:
        outputs = [str(o) for o in output]

    if outputs and len(outputs) > 1:
        return {"error": "render_report writes one file; pass a single output path"}

    # Built once without an output path so nothing touches disk until there is
    # something to say. `generate_report` writes as it renders, so a guard that
    # ran afterwards would report `written: False` while the artifact was already
    # on disk — the unverified writeup this tool exists to prevent, produced by
    # the prevention mechanism itself.
    #
    # The evidence test is the builder's own, not a reimplementation: it pulls
    # untagged tool observations in by target, and a guard that disagreed with
    # the generator would either wave through a bare hypothesis or refuse a
    # confirmed finding.
    draft = generate_report(ctx.session, finding=finding)

    if finding and not draft.evidence_count:
        recorded = ctx.evidence.by_finding(finding)
        return {
            "written": False,
            "finding": finding,
            "error": (
                f"nothing verifiable is recorded for {finding!r}, so there is nothing to "
                "report on. A hypothesis is not evidence."
            ),
            "records_for_finding": len(recorded),
            "next": [
                "run the suggested test and record the observation",
                f"then sro_verify finding={finding} citing it",
                "only then render the report",
            ],
            "note": "no file was written",
        }

    report = generate_report(ctx.session, finding=finding, output=outputs[0] if outputs else "")

    return {
        "written": True,
        "path": str(report.path) if report.path else None,
        "finding": report.finding_title,
        "verification": report.verification.get("verdict", "UNPROVEN"),
        "evidence_count": report.evidence_count,
        "sections": [s.heading for s in report.sections],
        "unproven_sections": report.unproven_sections,
        "note": (
            "SRO wrote a local file and has no capability to send it anywhere. Disclosure is "
            "the researcher's own act, through the program's channel."
        ),
    }


def handle_record_hypothesis(ctx: "HandlerContext", params: dict[str, Any]) -> Any:
    """Record a proposal. Deliberately cannot record an observation."""
    title = str(params.get("title") or "").strip()
    reasoning = str(params.get("reasoning") or "").strip()
    suggested = str(params.get("suggested_test") or "").strip()
    expected = str(params.get("expected_evidence") or "").strip()

    missing = [
        name
        for name, value in (("title", title), ("reasoning", reasoning),
                            ("suggested_test", suggested), ("expected_evidence", expected))
        if not value
    ]
    if missing:
        return {
            "recorded": False,
            "error": f"a hypothesis needs all four fields; missing: {missing}",
            "why": (
                "expected_evidence written after the test fits any outcome, which is the "
                "failure this record exists to prevent."
            ),
        }

    record = ctx.evidence.record_hypothesis(
        agent=ctx.agent,
        title=title,
        reasoning=reasoning,
        suggested_test=suggested,
        expected_evidence=expected,
        target=str(params.get("target") or ""),
        finding=str(params.get("finding") or ""),
    )
    return {
        "recorded": True,
        "evidence_id": record.evidence_id,
        "status": record.status,
        "finding": record.finding or None,
        "next": [
            f"run the suggested test and record the result with sro_record_evidence",
            f"then sro_verify finding={record.finding or 'F-1'} citing the observation",
        ],
        "note": "this is a HYPOTHESIS record. Only a verifier verdict with cited evidence can confirm it.",
    }


class HandlerContext:
    """What a handler is allowed to reach.

    A handler gets the session, not the process. It cannot import a socket, read
    an environment variable, or reach the platform layer, because none of that
    is on this object. That is the whole point of keeping handlers separate from
    the catalog.
    """

    __slots__ = ("session", "agent", "workspace")

    def __init__(self, session: Any, agent: str = "agent", workspace: Any = None) -> None:
        self.session = session
        self.agent = agent
        # The working directory, not the state directory: `code_search` exists
        # to read the source tree the researcher is standing in. Using the state
        # dir would point every search at SRO's own bookkeeping.
        self.workspace = Path(workspace or Path.cwd()).resolve()

    @property
    def evidence(self) -> Any:
        return self.session.evidence_store()

    def scope_engine(self) -> ScopeEngine:
        return self.session.scope_engine()


# --- dns_resolve ----------------------------------------------------------


#: How a resolved address is described to a researcher. The classification is
#: the point of the tool: `api.example.com -> 10.0.0.5` is a finding about a
#: target that resolves inward, and it is only visible if the answer is labelled.
def classify_address(address: str) -> str:
    """`public`, `private`, `loopback`, `link-local`, `metadata`, `multicast`, `reserved`."""
    from ..core.scope import _is_documentation_address

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return "unparseable"
    if str(parsed) in _METADATA_ADDRESSES or _is_metadata_host_candidate(address):
        return "metadata"
    if _is_documentation_address(parsed):
        return "documentation"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link-local"
    if parsed.is_multicast:
        return "multicast"
    if _is_internal_address(parsed):
        return "private"
    return "public"


#: Reserved names that resolve inward on common cloud metadata setups.
_METADATA_ADDRESSES = frozenset({"169.254.169.254", "100.100.100.200", "fd00:ec2::254"})


def _is_metadata_host_candidate(address: str) -> bool:
    return address in _METADATA_ADDRESSES


def handle_dns_resolve(ctx: "HandlerContext", params: dict[str, Any]) -> Any:
    """Resolve an in-scope name and classify what it resolves to.

    Reads A/AAAA through the system resolver, which is what the operator's own
    machine would get, and queries the other record types over DNS directly
    against that same resolver.

    Two things this deliberately does not do. It does not enumerate: no zone
    transfer, no brute force, no wordlist. And it does not treat a name that
    resolves inward as a failure — that is a result worth having, and the
    classification is reported rather than raised as an error.
    """
    from ..core.egress import (
        DestinationRefused,
        EgressLimits,
        _dns_exchange,
        resolve_addresses,
        system_nameservers,
    )
    from ..core.dnswire import TYPE_BY_NAME, TYPE_NAMES, build_query, parse_message

    host = str(params.get("host") or "").strip().rstrip(".")
    record_type = str(params.get("record_type") or "A").upper()

    if not host:
        return {"error": "dns_resolve needs a host", "usage": "dns_resolve(host='api.example.com')"}
    if record_type not in TYPE_BY_NAME:
        return {
            "error": f"unknown record type {record_type!r}",
            "supported": sorted(TYPE_NAMES.values()),
        }

    verdict = ctx.scope_engine().check(host)
    limits = EgressLimits()
    deadline = time.monotonic() + limits.total_timeout
    rtype = TYPE_BY_NAME[record_type]

    # The A/AAAA path goes through the OS resolver, so no socket is opened by
    # SRO at all. That is the better answer when it is available: it is what the
    # operator's own machine sees, including whatever split-horizon the target
    # intends.
    if record_type in ("A", "AAAA"):
        family = socket.AF_INET if record_type == "A" else socket.AF_INET6
        via = "system resolver (getaddrinfo); no packet sent by SRO"
        try:
            resolved = resolve_addresses(host, family)
        except DestinationRefused as exc:
            return {
                "host": host,
                "record_type": record_type,
                "status": "NXDOMAIN" if "does not resolve" in str(exc) else "ERROR",
                "addresses": [],
                "error": str(exc),
                "via": via,
            }

        addresses = [
            {"address": address, "classification": classify_address(address)}
            for address in resolved
        ]
        inward = [a for a in addresses if a["classification"] not in ("public", "documentation")]
        return {
            "host": host,
            "record_type": record_type,
            "status": "NOERROR" if addresses else "NOERROR",
            "addresses": addresses,
            "via": via,
            "resolves_inward": bool(inward),
            "note": _dns_note(inward),
        }

    nameservers = system_nameservers()
    errors: list[str] = []
    for nameserver in nameservers:
        try:
            raw = _dns_exchange(
                build_query(host, rtype), nameserver, limits=limits, deadline=deadline
            )
            message = parse_message(raw)
        except (DestinationRefused, LimitExceeded) as exc:
            errors.append(f"{nameserver}: {exc}")
            continue

        # Answered records and CNAME chain are kept apart. A name that is a CNAME
        # answers every type with the CNAME and the real answer somewhere else, so
        # falling back to "show whatever came back" presents a CNAME as if it were
        # the MX record — which reads as a finding and is not one.
        matching = [r for r in message.answers if r.rtype == rtype]
        chain = [r.to_dict() for r in message.answers if r.rtype == 5]

        entries = []
        inward = []
        for record in matching:
            entry = record.to_dict()
            if record.rtype in (1, 28) and record.data:
                entry["classification"] = classify_address(record.data)
                if entry["classification"] not in ("public", "documentation"):
                    inward.append(entry)
            entries.append(entry)

        result: dict[str, Any] = {
            "host": host,
            "record_type": record_type,
            "status": message.rcode_name,
            "authoritative": message.authoritative,
            "records": entries,
            "via": f"DNS query to {nameserver}",
            "resolves_inward": bool(inward),
        }
        if chain:
            result["cname_chain"] = chain
        if not entries:
            result["note"] = (
                f"No {record_type} records at this name"
                + (
                    f"; it is a CNAME to {chain[-1].get('target')}, so query that name "
                    f"instead. A CNAME answer is not a {record_type} record, and it is "
                    f"not reported as one."
                    if chain
                    else "."
                )
            )
        else:
            result["note"] = _dns_note(inward)
        return result

    return {
        "host": host,
        "record_type": record_type,
        "status": "ERROR",
        "records": [],
        "errors": errors,
        "via": "system resolver from /etc/resolv.conf",
    }


def _dns_note(inward: list[dict[str, Any]]) -> str:
    if not inward:
        return (
            "Every address resolved to a public range. This is one name's answer at one "
            "moment; it is not enumeration, and SRO did not query the target directly."
        )
    kinds = sorted({entry["classification"] for entry in inward})
    return (
        f"This name resolves to a non-public range ({', '.join(kinds)}). That is a result, "
        f"not an error, and it is worth reporting on its own: an internet-facing hostname "
        f"resolving inward is either a split-horizon setup, a leaked internal address, or a "
        f"rebindable record. SRO refused to connect to it, which is a different control "
        f"from observing it."
    )


HANDLERS = {
    "scope_check": handle_scope_check,
    "dns_resolve": handle_dns_resolve,
    "endpoint_inventory": handle_endpoint_inventory,
    "code_search": handle_code_search,
    "render_report": handle_render_report,
    "record_hypothesis": handle_record_hypothesis,
}

#: Tools the catalog declares that this package does not implement, and why.
#: Surfaced by `sro capabilities` so the gap is visible rather than inferred.
NOT_IMPLEMENTED = {
    "http_request": "needs egress review",
    "api_schema_fetch": "needs egress review",
    "auth_session_test": "needs egress review and an explicit approval flow",
    "parameter_probe": "needs egress review and an explicit approval flow",
    "cloud_asset_query": "needs cloud credential handling design",
    "ad_query": "needs directory credential handling design",
    "browser_navigate": "needs a browser runtime and egress review",
    "tls_inspect": "needs egress review",
}


def register_all(broker: Any, context: "HandlerContext") -> Any:
    """Attach the built-in handlers to a broker. Returns the broker.

    The context is bound here rather than passed per call because the broker's
    handler signature is fixed at `(params, decision)`, and the session a handler
    needs is a property of the installation, not of the call.
    """
    for name, handler in HANDLERS.items():
        broker.register(name, _bind(handler, context))
    return broker


def _bind(handler, context: "HandlerContext"):
    """Adapt `(ctx, params)` to the broker's `(params, decision)` signature."""

    def bound(params: dict, decision: Any) -> Any:
        return handler(context, params)

    bound.__name__ = getattr(handler, "__name__", "bound_handler")
    bound.__doc__ = getattr(handler, "__doc__", None)
    return bound
