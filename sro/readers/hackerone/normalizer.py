"""HackerOne payload normalization.

Shared by the HackerOne reader and by brief import, so an exported HackerOne
brief normalizes identically whether it arrived over the network or from a file.
"""

from __future__ import annotations

from typing import Any

from ...core.engagement import (
    RETRIEVAL_IMPORT,
    RETRIEVAL_PUBLIC,
    Engagement,
    Restriction,
    Target,
    dedupe_targets,
)
from ...core.scope import _CODE_HOSTS, _is_cidr, _is_ip_literal, _is_valid_host
from ..base import strip_html
from ..bugcrowd.parser import (
    classify_identifier,
    parse_auth_requirements,
    parse_rate_limits,
    parse_restrictions,
)

#: HackerOne structured-scope `attributes.type` values.
H1_TYPES = {
    "WILDCARD": "wildcard_domain",
    "DOMAIN": "domain",
    "IP": "ip",
    "CIDR": "cidr",
    "URL": "url",
    "API": "api_endpoint",
    "MOBILE": "mobile_application",
    "OTHER": "other",
    "REPOSITORY": "repository",
    "CLOUD": "cloud_resource",
    "HARDWARE": "asset_identifier",
}


def _h1_target(entry: Any, *, default_in_scope: bool) -> tuple[Target | None, list[str]]:
    """Parse one HackerOne `structured_scopes` entry.

    Shape:
        {"identifier": "*.example.com",
         "attributes": {"type": "WILDCARD", "cwe_ids": [...], "instructions": "..."}}
    """
    warnings: list[str] = []
    if isinstance(entry, str):
        entry = {"identifier": entry}
    if not isinstance(entry, dict):
        return None, [f"unrecognised structured scope entry of type {type(entry).__name__}"]

    attributes = entry.get("attributes")
    attributes = attributes if isinstance(attributes, dict) else {}
    identifier = str(
        entry.get("identifier")
        or attributes.get("identifier")
        or entry.get("name")
        or entry.get("target")
        or ""
    ).strip()
    if not identifier:
        return None, ["structured scope entry has no identifier"]

    raw_type = str(attributes.get("type") or entry.get("type") or "").strip().upper()
    target_type = H1_TYPES.get(raw_type) or classify_identifier(identifier, raw_type.lower())
    if target_type == "other":
        warnings.append(
            f"could not classify HackerOne target {identifier!r} (type={raw_type or 'unset'})"
        )

    in_scope = default_in_scope
    if "in_scope" in entry and entry["in_scope"] is not None:
        in_scope = bool(entry["in_scope"])
    if "eligible_for_bounty" in entry and entry["eligible_for_bounty"] is not None:
        in_scope = in_scope and bool(entry["eligible_for_bounty"])

    cwe_ids = attributes.get("cwe_ids") if isinstance(attributes.get("cwe_ids"), list) else []
    instructions = str(attributes.get("instructions") or entry.get("instructions") or "").strip() or None
    if cwe_ids and instructions:
        instructions = f"{instructions}\nCWEs: {', '.join(str(c) for c in cwe_ids)}"

    return (
        Target(
            identifier=identifier,
            type=target_type,
            in_scope=in_scope,
            bounty_eligible=entry.get("eligible_for_bounty"),
            submission_eligible=entry.get("submission_eligible"),
            instructions=instructions,
            restrictions=[str(attributes.get("notes"))] if attributes.get("notes") else [],
            raw=entry,
        ),
        warnings,
    )


def parse_structured_scopes(payload: Any) -> tuple[list[Target], list[Target], list[str]]:
    """Split `structured_scopes` into in-scope and excluded targets."""
    warnings: list[str] = []
    in_scope: list[Target] = []
    out_scope: list[Target] = []
    if not isinstance(payload, list):
        return in_scope, out_scope, warnings

    for entry in payload:
        bucket_is_exclusion = False
        if isinstance(entry, dict):
            attributes = entry.get("attributes")
            if isinstance(attributes, dict):
                if "in_scope" in attributes and attributes["in_scope"] is not None:
                    bucket_is_exclusion = not bool(attributes["in_scope"])
        target, entry_warnings = _h1_target(
            entry, default_in_scope=not bucket_is_exclusion
        )
        warnings.extend(entry_warnings)
        if target is None:
            continue
        if bucket_is_exclusion or not target.in_scope:
            out_scope.append(target)
        else:
            in_scope.append(target)
    return in_scope, out_scope, warnings


def normalize_hackerone_payload(
    payload: dict[str, Any],
    *,
    code: str = "",
    source_url: str = "",
    credentials_used: bool = False,
) -> Engagement:
    """Normalize a HackerOne program payload into the SRO engagement schema."""
    if not isinstance(payload, dict):
        raise ValueError("HackerOne payload must be an object")

    warnings: list[str] = []
    program = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    attributes = program.get("attributes") if isinstance(program.get("attributes"), dict) else {}

    program_handle = str(
        attributes.get("handle")
        or program.get("handle")
        or payload.get("handle")
        or code
        or ""
    )
    name = str(attributes.get("name") or program.get("name") or program_handle or code)
    url = str(attributes.get("submission_state") and "" or attributes.get("url") or program.get("url") or "")

    description = strip_html(str(attributes.get("description") or program.get("description") or ""))
    policy = str(attributes.get("policy") or program.get("policy") or "")
    policy_html = strip_html(policy)
    safe_harbor = strip_html(str(attributes.get("safe_harbor") or program.get("safe_harbor") or ""))
    disclosure = strip_html(str(attributes.get("disclosure_policy") or program.get("disclosure_policy") or ""))

    in_scope, out_scope, scope_warnings = parse_structured_scopes(
        attributes.get("structured_scopes") or program.get("structured_scopes")
    )
    warnings.extend(scope_warnings)

    # Programs without structured scope publish plain text instead.
    if not in_scope and not out_scope:
        legacy = attributes.get("targets") or {}
        if isinstance(legacy, dict):
            for key, bucket in (("in_scope", True), ("out_of_scope", False)):
                entries = legacy.get(key)
                if not isinstance(entries, dict):
                    continue
                for target_type, values in entries.items():
                    if not isinstance(values, dict):
                        continue
                    for identifier, meta in values.items():
                        record = meta if isinstance(meta, dict) else {}
                        bucket_list = in_scope if bucket else out_scope
                        bucket_list.append(
                            Target(
                                identifier=str(identifier),
                                type=classify_identifier(str(identifier), str(target_type)),
                                in_scope=bucket,
                                bounty_eligible=record.get("bounty_eligible"),
                                submission_eligible=record.get("submission_eligible"),
                                instructions=(str(record.get("description")) or None),
                            )
                        )
        if not in_scope and not out_scope:
            warnings.append(
                "HackerOne program publishes no structured scope; SRO will treat every target "
                "as UNKNOWN until the researcher supplies the scope"
            )

    blobs = [b for b in (policy_html, description, disclosure) if b]
    restrictions: list[Restriction] = parse_restrictions(*blobs)

    resolved_in = dedupe_targets(in_scope)
    resolved_out = dedupe_targets(out_scope)

    return Engagement(
        provider="hackerone",
        engagement_id=program_handle or code,
        program_name=name,
        program_url=str(attributes.get("url") or url or f"https://hackerone.com/{program_handle}"),
        description=description,
        rules=policy_html,
        disclosure_policy=disclosure,
        safe_harbor=safe_harbor,
        targets=resolved_in,
        exclusions=resolved_out,
        known_issues=[],
        testing_restrictions=restrictions,
        rate_limits=parse_rate_limits(blobs),
        authentication_requirements=parse_auth_requirements(blobs),
        allowed_testing=[r.name for r in restrictions if r.status == "permitted"],
        forbidden_testing=[r.name for r in restrictions if r.status == "forbidden"],
        retrieval_mode=RETRIEVAL_PUBLIC if not credentials_used else "api",
        credentials_used=credentials_used,
        source_url=source_url or f"https://hackerone.com/{program_handle}",
        completeness={
            "program_name": bool(name),
            "rules": bool(policy_html),
            "scope": bool(resolved_in or resolved_out),
        },
        warnings=warnings,
    )
