"""Bugcrowd scope/brief parser.

Turns raw Bugcrowd payloads into normalized SRO `Target` and `Restriction`
objects. This module is pure: it takes dictionaries in and returns objects out.
It performs no network calls and reaches no conclusion about authorization.

The parser is intentionally conservative. When a field is ambiguous it emits a
warning on the engagement rather than guessing, because a wrong "in scope" is
the failure mode that matters.
"""

from __future__ import annotations

import re
from typing import Any

from ...core.engagement import Restriction, Target
from ...core.scope import _CODE_HOSTS, _is_cidr, _is_ip_literal, _is_valid_host

#: Bugcrowd target categories, mapped to the SRO target taxonomy.
CATEGORY_TYPES: dict[str, str] = {
    "website": "domain",
    "api": "api_endpoint",
    "web_application": "domain",
    "mobile_application": "mobile_application",
    "android": "mobile_application",
    "ios": "mobile_application",
    "other": "other",
    "hardware": "asset_identifier",
    "smart_contract": "repository",
    "blockchain": "repository",
    "github": "repository",
    "source_code": "repository",
    "binary": "asset_identifier",
    "ip_address": "ip",
    "ip_range": "cidr",
    "network": "cidr",
    "domain": "domain",
    "wildcard": "wildcard_domain",
    "uri": "url",
    "url": "url",
    "other_device": "asset_identifier",
    "cloud_resource": "cloud_resource",
    "container_image": "asset_identifier",
    "repository": "repository",
    "saas": "domain",
    "windows_application": "mobile_application",
    "macos_application": "mobile_application",
}

#: Restriction phrases recognised in program prose. These map a free-text rule
#: to a canonical restriction name that the policy engine can act on. A phrase
#: that is not recognised stays prose and is surfaced to the researcher.
#:
#: Both word orders are matched. Programs write prohibitions as
#: "Do not perform denial of service testing" and as "Denial of service
#: testing is not permitted" roughly equally often, and only the first form is
#: a safe default to assume.
_TERM = {
    "dos": r"(?:denial[-\s]of[-\s]service|dos|ddos|flood(?:ing)?|load\s*test(?:ing)?|stress(?:ing)?)",
    "social": r"(?:social\s*engineering|phishing|pretext(?:ing)?|impersonat\w*)",
    "spray": r"(?:password\s*spray\w*|spraying)",
    "brute": r"(?:brute[-\s]?forc\w*|credential\s*stuffing)",
    "physical": r"(?:physical\w*|tailgat\w*|in[-\s]?person)",
    "third_party": r"(?:third[-\s]party|vendor|supplier)",
    "destruction": r"(?:delet\w*|destruct\w*|wip(?:e|ing)\s+(?:data|the\s+database)|drop\s+(?:table|database))",
    "scanning": r"(?:automated\s*scanning|scanners?|crawling|port\s*scanning)",
}
_NEG = (
    r"(?:do\s*n[o']?t|do\s+not|never|no|not\s+allowed|prohibited|forbidden|disallow(?:ed)?"
    r"|(?:is|are)\s+not\s+(?:permitted|allowed|acceptable)|not\s+permitted"
    r"|(?:is|are)\s+out\s+of\s+scope|must\s+not|avoid"
    r"|will\s+result\s+in\s+(?:disqualification|enforcement))"
)
_POS = r"(?:is\s+)?(?:permitted|allowed|acceptable|encouraged|welcome)"


def _rule(term: str, polarity: str) -> re.Pattern[str]:
    """Build a pattern matching a prohibition/permission adjacent to a term.

    `polarity` is "neg" for a prohibition or "pos" for an explicit permission.
    """
    if polarity == "neg":
        before = rf"{_NEG}[^.]{{0,60}}?(?:{term})"
        after = rf"(?:{term})[^.]{{0,60}}?{_NEG}"
        return re.compile(rf"(?i)(?:{before})|(?:{after})")
    before = rf"{term}[^.]{{0,40}}?{_POS}"
    after = rf"{_POS}[^.]{{0,40}}?(?:{term})"
    return re.compile(rf"(?i)(?:{before})|(?:{after})")


RESTRICTION_RULES: tuple[tuple[re.Pattern[str], str, str, str], ...] = (
    (_rule(_TERM["dos"], "neg"), "denial_of_service", "forbidden", "denial of service, flooding and load testing are prohibited"),
    (_rule(_TERM["social"], "neg"), "social_engineering", "forbidden", "social engineering, phishing and pretexting are prohibited"),
    (_rule(_TERM["spray"], "neg"), "password_spraying", "forbidden", "password spraying is prohibited"),
    (_rule(_TERM["brute"], "neg"), "brute_force", "forbidden", "brute force and credential stuffing are prohibited"),
    (_rule(_TERM["physical"], "neg"), "physical_testing", "forbidden", "physical and in-person testing is prohibited"),
    (_rule(_TERM["third_party"], "neg"), "third_party_systems", "forbidden", "testing third-party or vendor systems is prohibited"),
    (_rule(_TERM["destruction"], "neg"), "data_destruction", "forbidden", "deleting or destroying data is prohibited"),
    (
        re.compile(r"(?i)\b(?:oob|out[-\s]of[-\s]band)\b[^.]{0,60}\b(?:callback|interaction|acme|burpcollaborator|requestbin|interactsh)\b"),
        "out_of_band",
        "conditional",
        "out-of-band interaction depends on the program's listed collaborator domain",
    ),
    (_rule(_TERM["scanning"], "pos"), "automated_scanning", "permitted", "automated scanning is permitted"),
    (_rule(_TERM["scanning"], "neg"), "automated_scanning", "forbidden", "automated scanning is prohibited"),
)

_COMPILED_RESTRICTIONS = tuple((p, n, s, d) for p, n, s, d in RESTRICTION_RULES)

_CIDR_HINT = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*/\s*\d{1,2}\b")
_IP_HINT = re.compile(r"^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*$")
_DOMAIN_HINT = re.compile(r"^(?:\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_URL_HINT = re.compile(r"^https?://", re.I)
_APP_ID_HINT = re.compile(r"^(?:com|org|net|io|co|dev|app|me)\.[A-Za-z0-9_.\-]+$")
_ARN_HINT = re.compile(r"^arn:")


def classify_identifier(identifier: str, category: str = "") -> str:
    """Infer an SRO target type from an identifier and a platform category.

    The platform category is advisory; the shape of the identifier wins, because
    Bugcrowd's categories are frequently left unset or set inconsistently.
    """
    text = (identifier or "").strip().rstrip(".")
    if not text:
        return "other"

    if _CIDR_HINT.search(text):
        return "cidr"
    if _IP_HINT.match(text):
        return "ip"
    if _ARN_HINT.match(text):
        return "cloud_resource"
    if _URL_HINT.match(text):
        return "url"

    host_part = text
    path = ""
    if "/" in text and not _CIDR_HINT.search(text):
        head, _, rest = text.partition("/")
        if head.lower() in _CODE_HOSTS or (("." in head) and head.lower().endswith((".com", ".org", ".net", ".io", ".dev", ".sh")) and rest.count("/") >= 1 and not text.startswith("http")):
            # Only treat as a repository when the path looks like owner/repo.
            if len([p for p in rest.split("/") if p]) >= 1:
                return "repository"
        host_part = head
        path = rest

    if _APP_ID_HINT.match(text) and "/" not in text and category in {
        "mobile_application",
        "android",
        "ios",
    }:
        return "mobile_application"

    if _DOMAIN_HINT.match(host_part.lower()):
        if "*" in host_part:
            return "wildcard_domain"
        return "domain"

    mapped = CATEGORY_TYPES.get((category or "").strip().lower())
    if mapped:
        return mapped
    return "other"


def _normalize_instructions(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return "\n".join(str(v).strip() for v in value.values() if v)
    if isinstance(value, (list, tuple)):
        return "\n".join(str(v).strip() for v in value if v)
    return ""


def parse_target_entry(entry: Any, *, default_in_scope: bool) -> tuple[Target | None, list[str]]:
    """Parse one Bugcrowd `targets` / `target_groups` entry.

    Returns the parsed target plus any warnings. A None target with a warning
    means SRO refused to guess; the asset shows up as unclassified and therefore
    unresolvable, which is the correct outcome.
    """
    warnings: list[str] = []
    if isinstance(entry, str):
        entry = {"name": entry}

    if not isinstance(entry, dict):
        return None, [f"unrecognised target entry of type {type(entry).__name__}"]

    identifier = (
        entry.get("name")
        or entry.get("uri")
        or entry.get("target_identifier")
        or entry.get("identifier")
        or entry.get("value")
        or ""
    )
    identifier = str(identifier).strip()
    if not identifier:
        return None, ["target entry has no identifier"]

    category = str(entry.get("category") or entry.get("type") or "")
    target_type = classify_identifier(identifier, category)

    if target_type == "other":
        warnings.append(
            f"could not classify target {identifier!r} (category={category or 'unset'}); "
            "it is recorded but will resolve as UNKNOWN until the researcher categorises it"
        )

    in_scope = default_in_scope
    if "in_scope" in entry and entry["in_scope"] is not None:
        in_scope = bool(entry["in_scope"])
    elif "out_of_scope" in entry and entry["out_of_scope"] is not None:
        in_scope = not bool(entry["out_of_scope"])
    if "state" in entry and isinstance(entry["state"], str):
        state = entry["state"].strip().lower()
        if state in {"out_of_scope", "excluded", "removed"}:
            in_scope = False
        elif state in {"in_scope", "active", "valid"}:
            in_scope = True

    restrictions: list[str] = []
    for key in ("restrictions", "notes", "restrictions_text"):
        value = _normalize_instructions(entry.get(key))
        if value:
            restrictions.append(value)

    target = Target(
        identifier=identifier,
        type=target_type,
        in_scope=in_scope,
        bounty_eligible=entry.get("bounty_eligible"),
        submission_eligible=entry.get("submission_eligible"),
        instructions=_normalize_instructions(entry.get("instructions")) or None,
        restrictions=restrictions,
        raw=entry if not isinstance(entry, str) else None,
    )
    return target, warnings


def parse_targets(raw_targets: Any, *, default_in_scope: bool = True) -> tuple[list[Target], list[str]]:
    """Parse a Bugcrowd `targets` array (or the public HTML table shape)."""
    targets: list[Target] = []
    warnings: list[str] = []
    if not raw_targets:
        return targets, warnings
    if isinstance(raw_targets, dict):
        raw_targets = [raw_targets]
    if not isinstance(raw_targets, (list, tuple)):
        return targets, [f"targets field has unexpected type {type(raw_targets).__name__}"]

    for entry in raw_targets:
        target, entry_warnings = parse_target_entry(entry, default_in_scope=default_in_scope)
        warnings.extend(entry_warnings)
        if target is not None:
            targets.append(target)
    return targets, warnings


def parse_restrictions(*texts: str) -> list[Restriction]:
    """Derive structured restrictions from program prose.

    Recognition is additive and conservative: it only marks something
    "forbidden" when the prose contains an explicit prohibition next to the
    relevant term. Ambiguous phrasing produces no restriction, which means the
    policy engine will ask the researcher instead of guessing.
    """
    blob = "\n".join(t for t in texts if t)
    if not blob:
        return []

    found: dict[str, Restriction] = {}
    for pattern, name, status, description in _COMPILED_RESTRICTIONS:
        if not pattern.search(blob):
            continue
        existing = found.get(name)
        # A prohibition always beats a permission for the same restriction.
        if existing is not None and existing.status == "forbidden" and status != "forbidden":
            continue
        found[name] = Restriction(
            name=name,
            status=status,
            description=description,
            source="program prose",
        )
    return list(found.values())


def parse_known_issues(raw: Any) -> list[str]:
    if not raw:
        return []
    items: list[str] = []
    if isinstance(raw, (list, tuple)):
        for entry in raw:
            if isinstance(entry, dict):
                text = (
                    entry.get("title")
                    or entry.get("name")
                    or entry.get("summary")
                    or entry.get("description")
                    or ""
                )
                identifier = entry.get("id") or entry.get("reference") or ""
                if text and identifier:
                    items.append(f"{identifier}: {text}")
                elif text:
                    items.append(str(text))
            else:
                items.append(str(entry))
    return [item.strip() for item in items if str(item).strip()]


def parse_rate_limits(texts: list[str]) -> str:
    sentences = []
    for text in texts:
        if not text:
            continue
        for sentence in re.split(r"(?<=[.!?\n])\s+", text):
            if re.search(
                r"(?i)\b\d+\s*(?:requests?|reqs?|rps|qps|per\s+(?:second|minute|hour)"
                r"|concurrent|simultaneous|parallel)\b",
                sentence,
            ):
                sentences.append(sentence.strip())
    return " ".join(dict.fromkeys(s.strip() for s in sentences if s.strip()))[:2000]


def parse_auth_requirements(texts: list[str]) -> str:
    sentences = []
    for text in texts:
        if not text:
            continue
        for sentence in re.split(r"(?<=[.!?\n])\s+", text):
            if re.search(
                r"(?i)\b(?:test\s+account|test\s+user|test\s+credential|vpn|authenticated\s+testing|"
                r"requires?\s+(?:an?\s+)?account|sign\s?up|create\s+an?\s+account|whitelist(?:ed)?\s+ip|"
                r"source\s+ip|mfa|2fa)\b",
                sentence,
            ):
                sentences.append(sentence.strip())
    return " ".join(dict.fromkeys(s.strip() for s in sentences if s.strip()))[:2000]
