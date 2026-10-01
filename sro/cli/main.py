"""SRO command line.

The CLI is the only interface between the OpenCode plugin (TypeScript) and the
deterministic core (Python). Every subcommand reads JSON on stdin or takes JSON
arguments and writes JSON on stdout, so the plugin never has to parse prose and
never has to reimplement a policy decision.

    sro load <url>            read an engagement, stage it for review
    sro review                render the staged manifest
    sro activate              researcher confirmation
    sro status                engagement and policy status
    sro scope check <target>  deterministic scope verdict
    sro policy check          evaluate a hypothetical action
    sro evidence ...          record and list evidence
    sro find                  findings, hypotheses and verification state
    sro report                render a report from evidence
    sro provider              reader capabilities
    sro route                 model routing decision

Exit codes: 0 allowed/success, 2 policy denial, 3 needs confirmation,
4 usage or configuration error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ..core.config import Config
from ..core.errors import SROError
from ..core.evidence import HYPOTHESIS, OBSERVED, VERIFIED
from ..core.policy import PolicyRequest
from ..core.session import Session
from ..readers import all_capabilities

EXIT_OK = 0
EXIT_DENIED = 2
EXIT_NEEDS_CONFIRMATION = 3
EXIT_ERROR = 4

BANNER = """SRO - Security Research Orchestrator
Security control plane for authorized research. Read-only by construction."""


def _emit(payload: Any, *, pretty: bool = True) -> None:
    print(json.dumps(payload, indent=2 if pretty else None, default=str))


def _read_stdin_json() -> dict[str, Any]:
    if sys.stdin.isatty():
        return {}
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SROError(f"stdin was not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SROError("stdin must be a JSON object")
    return data


def _session(args: argparse.Namespace) -> Session:
    config = Config.load(args.root, args.config)
    return Session(config)


# -- commands --------------------------------------------------------------


def cmd_load(args: argparse.Namespace) -> int:
    session = _session(args)
    payload = _read_stdin_json()
    source = args.source or payload.get("source", "")
    if not source:
        raise SROError("provide a program URL, code, or brief path")

    manifest = session.load(
        source,
        provider=args.provider or payload.get("provider", ""),
        as_of=args.as_of or payload.get("as_of", ""),
    )
    engagement = manifest.engagement

    if not engagement.is_complete() and not args.force:
        return _emit_incomplete(session, engagement, manifest)

    _emit(
        {
            "status": "pending_user_confirmation",
            "summary": manifest.summary(),
            "next": ["sro review", "sro activate"],
            "warnings": engagement.warnings,
        }
    )
    return EXIT_NEEDS_CONFIRMATION


def _emit_incomplete(session: Session, engagement: Any, manifest: Any) -> int:
    _emit(
        {
            "status": "incomplete",
            "summary": manifest.summary(),
            "message": (
                "I could not establish complete scope automatically. "
                "Security testing remains disabled until scope is established."
            ),
            "options": [
                {"id": 1, "label": "Continue with incomplete information"},
                {"id": 2, "label": "Import engagement brief", "command": "sro import <file>"},
                {
                    "id": 3,
                    "label": "Configure optional read-only credentials",
                    "hint": "set providers.%s.credentials=environment and token_env in sro.json"
                    % engagement.provider,
                },
                {"id": 4, "label": "Cancel"},
            ],
            "warnings": engagement.warnings,
            "retrieved": engagement.retrieval_mode,
            "credentials_used": engagement.credentials_used,
        }
    )
    return EXIT_NEEDS_CONFIRMATION


def cmd_import(args: argparse.Namespace) -> int:
    session = _session(args)
    # Relative paths resolve against the workspace, not the shell's cwd. The
    # plugin invokes the CLI with an explicit --root, so a brief named relative
    # to the project would otherwise be looked up somewhere else entirely.
    path = Path(args.path)
    if not path.is_absolute():
        path = session.config.data_dir / path
    if not path.exists():
        raise SROError(f"brief not found: {path}")
    manifest = session.import_brief(str(path), provider=args.provider or "")
    _emit(
        {
            "status": "pending_user_confirmation",
            "summary": manifest.summary(),
            "warnings": manifest.engagement.warnings,
            "next": ["sro review", "sro activate"],
        }
    )
    return EXIT_NEEDS_CONFIRMATION


def cmd_review(args: argparse.Namespace) -> int:
    session = _session(args)
    if args.json:
        _emit(session.review_data() if hasattr(session, "review_data") else _review_payload(session))
        return EXIT_OK
    print(session.review())
    return EXIT_OK


def _review_payload(session: Session) -> dict[str, Any]:
    engagement = session.require_engagement()
    return {
        "status": session.status,
        "engagement": engagement.to_dict(),
        "scope": engagement.get_scope(),
        "restrictions": [r.to_dict() for r in engagement.testing_restrictions],
        "warnings": engagement.warnings,
        "diff_from_previous": session.manifest.diff_from_previous if session.manifest else [],
    }


def cmd_activate(args: argparse.Namespace) -> int:
    session = _session(args)
    engagement = session.activate(actor=args.actor or "researcher", force=args.force)
    _emit(
        {
            "status": "ACTIVE",
            "engagement": engagement.program_name,
            "provider": engagement.provider,
            "scope": len(engagement.in_scope_targets()),
            "exclusions": len(engagement.excluded_targets()),
            "policy": "ACTIVE",
        }
    )
    return EXIT_OK


def cmd_deactivate(args: argparse.Namespace) -> int:
    session = _session(args)
    session.deactivate(reason=args.reason)
    _emit({"status": "PENDING_CONFIRMATION"})
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    session = _session(args)
    _emit(session.status())
    return EXIT_OK


def cmd_scope(args: argparse.Namespace) -> int:
    session = _session(args)
    engine = session.scope_engine()

    if args.targets:
        _emit({t: engine.check(t).to_dict() for t in args.targets})
        return EXIT_OK

    if not args.target:
        _emit(engine.describe())
        return EXIT_OK

    decision = engine.check(args.target)
    if args.json:
        _emit(decision.to_dict())
    else:
        print(f"{decision.status}: {decision.target}")
        print(f"  reason:   {decision.reason}")
        if decision.matched_rule:
            print(f"  matched:  {decision.matched_rule} ({decision.match_kind})")
        if decision.conflict:
            print(f"  CONFLICT: {decision.conflict_detail}")
    if decision.status == "IN_SCOPE":
        return EXIT_OK
    if decision.status == "UNKNOWN":
        return EXIT_NEEDS_CONFIRMATION
    return EXIT_DENIED


def cmd_translate(args: argparse.Namespace) -> int:
    from ..core.translator import PromptTranslator

    session = _session(args)
    payload = _read_stdin_json()
    request = args.request or payload.get("request", "")
    translator = PromptTranslator(session.engagement, session.scope_engine(), session.activated)
    translation = translator.translate(request)
    if args.json:
        _emit(translation.to_dict())
    else:
        print(translation.render())
    if translation.status == "blocked":
        return EXIT_DENIED
    if translation.needs_clarification:
        return EXIT_NEEDS_CONFIRMATION
    return EXIT_OK


def cmd_scope_add(args: argparse.Namespace) -> int:
    session = _session(args)
    target = session.add_target(args.target, in_scope=not args.exclude, note=args.note or "")
    _emit({"added": target.to_dict()})
    return EXIT_OK


def cmd_policy(args: argparse.Namespace) -> int:
    session = _session(args)
    payload = _read_stdin_json()
    request = PolicyRequest(
        tool=args.tool or payload.get("tool", "unknown"),
        action=args.action or payload.get("action", ""),
        target=args.target or payload.get("target", ""),
        capability=args.capability or payload.get("capability", ""),
        destructive=bool(args.destructive or payload.get("destructive", False)),
        requires_auth=bool(payload.get("requires_auth", False)),
        authenticated=bool(payload.get("authenticated", False)),
        user_approved=bool(args.approve or payload.get("user_approved", False)),
        rate_limited=bool(payload.get("rate_limited", True)),
        metadata=payload.get("metadata") or {},
    )
    decision = session.policy_engine().evaluate(request)
    if args.json:
        _emit(decision.to_dict())
    else:
        print(decision.render())
    if decision.result == "ALLOW":
        return EXIT_OK
    if decision.result == "ASK":
        return EXIT_NEEDS_CONFIRMATION
    return EXIT_DENIED


def cmd_policy_describe(args: argparse.Namespace) -> int:
    session = _session(args)
    _emit(session.policy_engine().describe())
    return EXIT_OK


def cmd_evidence(args: argparse.Namespace) -> int:
    session = _session(args)
    store = session.evidence_store()
    payload = _read_stdin_json()

    if args.evidence_action == "add":
        record = store.record_observation(
            tool=payload.get("tool", ""),
            agent=payload.get("agent", "unknown"),
            target=payload.get("target", ""),
            capability=payload.get("capability", ""),
            summary=payload.get("summary", ""),
            request=payload.get("request"),
            response=payload.get("response"),
            command=payload.get("command", ""),
            result=payload.get("result"),
            screenshots=payload.get("screenshots"),
            artifacts=payload.get("artifacts"),
            policy=payload.get("policy"),
            tags=payload.get("tags"),
        )
        _emit(record.to_dict())
        return EXIT_OK

    if args.evidence_action == "hypothesis":
        record = store.record_hypothesis(
            agent=payload.get("agent", "unknown"),
            title=payload.get("title", ""),
            reasoning=payload.get("reasoning", ""),
            suggested_test=payload.get("suggested_test", ""),
            expected_evidence=payload.get("expected_evidence", ""),
            target=payload.get("target", ""),
            finding=payload.get("finding", ""),
            tags=payload.get("tags"),
        )
        _emit(record.to_dict())
        return EXIT_OK

    if args.evidence_action == "verify":
        record = store.record_verification(
            verifier=payload.get("verifier", "verifier"),
            finding=payload.get("finding", ""),
            status=payload.get("status", "INCONCLUSIVE"),
            reasoning=payload.get("reasoning", ""),
            cited=payload.get("cited") or [],
            reproductions=payload.get("reproductions"),
        )
        _emit(record.to_dict())
        return EXIT_OK

    if args.evidence_action == "timeline":
        _emit(store.engagement_timeline(args.limit or 200))
        return EXIT_OK

    if args.evidence_action == "get":
        record = store.get(args.evidence_id or "")
        if record is None:
            _emit({"error": "evidence not found", "evidence_id": args.evidence_id})
            return EXIT_ERROR
        _emit(record.to_dict())
        return EXIT_OK

    _emit(store.summary())
    return EXIT_OK


def cmd_find(args: argparse.Namespace) -> int:
    session = _session(args)
    store = session.evidence_store()
    findings: dict[str, dict[str, Any]] = {}

    for record in store.all():
        if not record.finding:
            continue
        entry = findings.setdefault(
            record.finding,
            {
                "finding": record.finding,
                "status": record.status,
                "hypothesis": record.hypothesis,
                "target": record.target,
                "evidence": [],
                "verification": None,
            },
        )
        entry["evidence"].append(record.evidence_id)
        if record.status == VERIFIED:
            entry["status"] = VERIFIED
        elif record.status == HYPOTHESIS and entry["status"] == OBSERVED:
            entry["status"] = "UNCONFIRMED"
        if record.verification_status:
            entry["verification"] = {
                "status": record.verification_status,
                "reasoning": (record.result or {}).get("reasoning") if isinstance(record.result, dict) else "",
                "cited": (record.result or {}).get("cited", []) if isinstance(record.result, dict) else [],
            }
    _emit(list(findings.values()))
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    from ..core.report import generate_report

    session = _session(args)
    report = generate_report(session, finding=args.finding or "", output=args.output)
    if args.output:
        _emit({"written": str(report.path), "finding": report.finding_title, "sections": len(report.sections)})
    else:
        print(report.render())
    return EXIT_OK


def cmd_provider(args: argparse.Namespace) -> int:
    config = Config.load(args.root, args.config)
    _emit(all_capabilities(config))
    return EXIT_OK


def cmd_route(args: argparse.Namespace) -> int:
    from ..core.routing import ModelRouter

    config = Config.load(args.root, args.config)
    payload = _read_stdin_json()
    router = ModelRouter(config)
    decision = router.route(
        task=str(payload.get("task") or args.task or ""),
        sensitivity=str(payload.get("sensitivity") or args.sensitivity or "normal"),
        prefer_external=bool(payload.get("prefer_external", False)),
        context_size=int(payload.get("context_size") or 0),
    )
    _emit(decision.to_dict())
    return EXIT_OK


def cmd_audit(args: argparse.Namespace) -> int:
    from ..core.audit import AuditLog

    config = Config.load(args.root, args.config)
    log = AuditLog(config.data_dir)
    _emit(log.timeline(args.limit or 100))
    return EXIT_OK


def cmd_warnings(args: argparse.Namespace) -> int:
    session = _session(args)
    _emit({"warnings": session.warnings()})
    return EXIT_OK


def cmd_capabilities(args: argparse.Namespace) -> int:
    """What the model is allowed to know about tools and capabilities."""
    session = _session(args)
    engine = session.policy_engine()
    from ..core.tools import catalog

    from ..core.tools import ToolBroker

    # A tool with no handler is a dead end for the model, so the catalog says
    # which ones are actually runnable rather than leaving the agent to find
    # out by calling one.
    broker = ToolBroker(engine, session.evidence_store())
    _emit(
        {
            "capabilities": engine.describe(),
            "tools": catalog(implemented=set(broker.handlers)),
            "engagement": session.status(),
            "note": (
                "Only tools with implemented=true have a working handler. A tool with "
                "implemented=false is a declared capability with no implementation; calling it "
                "is refused with a message saying so."
            ),
        }
    )
    return EXIT_OK


# -- parser ----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sro", description=BANNER)
    parser.add_argument("--root", default=".", help="project root containing sro.json")
    parser.add_argument("--config", default=None, help="path to sro.json")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("load", help="read an engagement and stage it for review")
    p.add_argument("source", nargs="?")
    p.add_argument("--provider", default="")
    p.add_argument("--as-of", dest="as_of", default="", help="pin retrieved_at (ISO 8601)")
    p.add_argument("--force", action="store_true", help="stage even when scope is incomplete")
    p.set_defaults(func=cmd_load)

    p = sub.add_parser("import", help="stage a researcher-supplied brief")
    p.add_argument("path")
    p.add_argument("--provider", default="")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("review", help="render the staged manifest")
    p.set_defaults(func=cmd_review)

    p = sub.add_parser("activate", help="researcher confirmation")
    p.add_argument("--actor", default="researcher")
    p.add_argument("--force", action="store_true", help="activate despite an empty scope")
    p.set_defaults(func=cmd_activate)

    p = sub.add_parser("deactivate", help="revoke activation")
    p.add_argument("--reason", default="researcher request")
    p.set_defaults(func=cmd_deactivate)

    p = sub.add_parser("status", help="engagement and policy status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("scope", help="deterministic scope verdict")
    p.add_argument("target", nargs="?")
    p.add_argument("--targets", nargs="*", default=[])
    p.set_defaults(func=cmd_scope)

    p = sub.add_parser("translate", help="translate a request into a structured objective")
    p.add_argument("request", nargs="?")
    p.set_defaults(func=cmd_translate)

    p = sub.add_parser("scope-add", help="add a researcher-confirmed target")
    p.add_argument("target")
    p.add_argument("--exclude", action="store_true")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_scope_add)

    p = sub.add_parser("policy", help="evaluate an action against the policy engine")
    p.add_argument("--tool", default="")
    p.add_argument("--action", default="")
    p.add_argument("--target", default="")
    p.add_argument("--capability", default="")
    p.add_argument("--destructive", action="store_true")
    p.add_argument("--approve", action="store_true", help="record explicit researcher approval")
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("policy-describe", help="show the policy surface")
    p.set_defaults(func=cmd_policy_describe)

    p = sub.add_parser("evidence", help="record and query evidence")
    p.add_argument(
        "evidence_action",
        nargs="?",
        default="summary",
        choices=["summary", "add", "hypothesis", "verify", "timeline", "get"],
    )
    p.add_argument("--evidence-id", dest="evidence_id", default="")
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=cmd_evidence)

    p = sub.add_parser("find", help="findings, hypotheses and verification state")
    p.set_defaults(func=cmd_find)

    p = sub.add_parser("report", help="render a report from evidence")
    p.add_argument("--finding", default="")
    p.add_argument("--output", default="")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("provider", help="reader capabilities per provider")
    p.set_defaults(func=cmd_provider)

    p = sub.add_parser("route", help="model routing decision")
    p.add_argument("task", nargs="?")
    p.add_argument("--sensitivity", default="normal", choices=["normal", "sensitive", "secret"])
    p.set_defaults(func=cmd_route)

    p = sub.add_parser("audit", help="tail the audit log")
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("warnings", help="engagement read warnings")
    p.set_defaults(func=cmd_warnings)

    p = sub.add_parser("capabilities", help="tool and capability catalog for the model")
    p.set_defaults(func=cmd_capabilities)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except SROError as exc:
        _emit({"error": str(exc), "type": type(exc).__name__, "details": exc.details}, pretty=args.json)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - a model must never receive a traceback
        _emit(
            {
                "error": f"unhandled {type(exc).__name__}: {exc}",
                "type": type(exc).__name__,
                "hint": "this is an SRO bug; the command was refused and nothing was executed",
            },
            pretty=args.json,
        )
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
