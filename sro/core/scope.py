"""Deterministic scope engine.

This module is the authorization boundary. It contains no model calls, no
network calls and no heuristics that depend on judgement. Given an engagement
manifest and a target string it returns exactly one of:

    IN_SCOPE      permitted subject to engagement restrictions
    OUT_OF_SCOPE  execution blocked
    UNKNOWN       execution blocked, researcher clarification required

Core rules
----------
1.  Explicit exclusions always beat inclusions.
2.  A more specific inclusion does NOT override a broader exclusion, but the
    resulting conflict is surfaced so a human can see the program is
    self-contradictory and correct the manifest.
3.  UNKNOWN is never promoted to IN_SCOPE. Not by this module, not by a model,
    not by an agent retrying with a different string.
4.  Malformed input is UNKNOWN, never an implicit match.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable
from urllib.parse import urlsplit

from .engagement import (
    TARGET_API,
    TARGET_ASSET,
    TARGET_CIDR,
    TARGET_CLOUD,
    TARGET_DOMAIN,
    TARGET_IP,
    TARGET_MOBILE,
    TARGET_OTHER,
    TARGET_REPOSITORY,
    TARGET_URL,
    TARGET_WILDCARD_DOMAIN,
    Engagement,
    Target,
)

IN_SCOPE = "IN_SCOPE"
OUT_OF_SCOPE = "OUT_OF_SCOPE"
UNKNOWN = "UNKNOWN"


class ScopeStatus(str, Enum):
    IN_SCOPE = IN_SCOPE
    OUT_OF_SCOPE = OUT_OF_SCOPE
    UNKNOWN = UNKNOWN


#: Reasons are stable strings so agents and tests can match on them exactly.
R_MALFORMED = "target is malformed or empty"
R_MALFORMED_URL = "target is not a valid URL"
R_EXCLUDED_EXACT = "explicitly excluded by engagement"
R_EXCLUDED_BROAD = "covered by a broader exclusion"
R_INCLUDED_EXACT = "explicitly listed as in scope"
R_INCLUDED_BROAD = "covered by an in-scope rule"
R_NO_RULE = "no scope rule matches this target"
R_NO_ENGAGEMENT = "no engagement is loaded"
R_CONFLICT = "inclusion and exclusion both match; exclusion wins"

#: Hostnames that can never be security-research targets. These are not policy
#: decisions about a program, they are non-negotiable safety constants.
FORBIDDEN_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.goog",
    }
)

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

#: Hosts whose path components name a repository rather than a web route.
_CODE_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht"})


def _is_valid_host(host: str) -> bool:
    """Validate a DNS hostname. Wildcards are checked separately."""
    if not host or len(host) > 253:
        return False
    host = host.strip().rstrip(".")
    if host.startswith("."):
        return False
    labels = host.split(".")
    if not labels or any(not label for label in labels):
        return False
    return all(_LABEL_RE.match(label) for label in labels)


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


#: RFC 5737 / RFC 3849 documentation ranges. Python's ipaddress module counts
#: these as "private", but they can never route to a real internal service and
#: they are the normal choice of target for a CTF or a security lab. Treating
#: them as internal would make SRO useless in exactly the environments it is
#: meant to support.
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _is_documentation_address(address: Any) -> bool:
    return any(address in network for network in _DOCUMENTATION_NETWORKS)


def _is_internal_address(address: Any) -> bool:
    """Private, loopback, link-local, multicast or reserved."""
    if _is_documentation_address(address):
        return False
    if getattr(address, "is_multicast", False):
        return True
    return bool(
        address.is_private or address.is_loopback or address.is_link_local or address.is_reserved
    )


def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


@dataclass(slots=True)
class TargetRef:
    """A parsed research target.

    `raw` is kept verbatim so the policy decision can quote exactly what the
    agent asked for. `hosts` lets one entry match a URL and its bare host.
    """

    raw: str
    kind: str
    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    path: str | None = None
    ip: str | None = None
    network: str | None = None
    repository: str | None = None
    app_id: str | None = None
    resource_id: str | None = None
    malformed: bool = False
    reason: str = ""

    @property
    def label(self) -> str:
        return self.raw


def parse_target(raw: str) -> TargetRef:
    """Parse an arbitrary agent-supplied string into a structured reference.

    This never raises. Anything it cannot understand comes back
    ``malformed=True`` so the caller can return UNKNOWN.
    """
    if raw is None:
        return TargetRef(raw="", kind="unknown", malformed=True, reason=R_MALFORMED)

    text = str(raw)
    if len(text) > 2048:
        return TargetRef(raw=text[:2048], kind="unknown", malformed=True, reason=R_MALFORMED)

    # Control characters are checked before strip(). A newline in a target is
    # either a parsing bug or an attempt to smuggle a second request past the
    # broker, and stripping first would quietly convert the second into a
    # harmless-looking single request.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        return TargetRef(raw=text.strip()[:200], kind="unknown", malformed=True, reason=R_MALFORMED)

    text = text.strip()
    if not text:
        return TargetRef(raw="", kind="unknown", malformed=True, reason=R_MALFORMED)

    lowered = text.lower()

    # scheme-qualified URL
    if "://" in lowered:
        return _parse_url(text)

    if "/" in text:
        head, _, tail = text.partition("/")

        # A bare CIDR. Checked before the host-with-path branch because
        # "10.0.0.0/8" is a network, not a URL with a path.
        if _is_cidr(text):
            return TargetRef(raw=text, kind="cidr", network=text)

        if head.lower() in _CODE_HOSTS:
            return TargetRef(
                raw=text,
                kind="repository",
                repository=text.rstrip("/"),
                host=head.lower(),
            )

        # "owner/repo": the first segment has no dot, so it is not a hostname.
        if "." not in head and ":" not in head and re.match(r"^[a-z0-9_.-]+$", head.lower()):
            return TargetRef(raw=text, kind="repository", repository=text.rstrip("/"))

        # scheme-less "host[:port]/path"
        if re.match(r"^[a-z0-9_.-]+(?::\d+)?$", lowered) and ("." in head or ":" in head):
            return _parse_url("https://" + text)

        return TargetRef(raw=text, kind="resource_id", resource_id=text)

    if lowered.startswith("arn:"):
        return TargetRef(raw=text, kind="cloud_resource", resource_id=text)

    # An IP literal is checked before the host:port branch, because an IPv6
    # address is mostly colons and would otherwise parse as a host and a port.
    if _is_ip_literal(text):
        return TargetRef(raw=text, kind="ip", ip=text)

    if ":" in text:
        maybe_host, _, maybe_port = text.rpartition(":")
        if maybe_port.isascii() and maybe_port.isdigit() and maybe_host:
            port = int(maybe_port)
            if not (0 < port < 65536):
                return TargetRef(raw=text, kind="unknown", malformed=True, reason=R_MALFORMED)
            return TargetRef(raw=text, kind="host_port", host=maybe_host.lower(), port=port)
        return TargetRef(raw=text, kind="unknown", malformed=True, reason=R_MALFORMED)

    if _is_cidr(text):
        return TargetRef(raw=text, kind="cidr", network=text)

    if "*" in text:
        if not _valid_pattern(text):
            return TargetRef(raw=text, kind="wildcard", malformed=True, reason=R_MALFORMED)
        return TargetRef(raw=text, kind="wildcard", host=lowered)

    if "." in lowered and _is_valid_host(lowered):
        return TargetRef(raw=text, kind="host", host=lowered)

    if re.match(r"^[a-z0-9_.-]+$", lowered) and "." not in lowered:
        # Single-label names are almost always a typo, a local file, or an
        # internal alias the program never published. Blocked as UNKNOWN.
        return TargetRef(raw=text, kind="unqualified_name", malformed=True, reason=R_MALFORMED)

    return TargetRef(raw=text, kind="unknown", malformed=True, reason=R_MALFORMED)


def _valid_pattern(pattern: str) -> bool:
    """Validate a wildcard host pattern without accepting regex metachars.

    A wildcard is only valid as a whole DNS label. `*acme.test` is rejected
    rather than treated as "any host ending in acme.test", because that reading
    also covers `notacme.test` and every other registration of the name, and a
    program that meant a wildcard would have written `*.acme.test`.
    """
    if re.search(r"[\\^$+?{}\[\]()|]", pattern):
        return False
    # A wildcard is only valid as a whole leading label: "*.example.com".
    for index, label in enumerate(pattern.split(".")):
        if "*" in label and (label != "*" or index != 0):
            return False
    stripped = pattern.replace("*", "").lstrip(".")
    if not stripped:
        return False
    return _is_valid_host(stripped)


def _parse_url(text: str) -> TargetRef:
    try:
        parts = urlsplit(text)
    except ValueError:
        return TargetRef(raw=text, kind="unknown", malformed=True, reason=R_MALFORMED_URL)
    if not parts.scheme or not parts.netloc:
        return TargetRef(raw=text, kind="url", malformed=True, reason=R_MALFORMED_URL)

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        return TargetRef(raw=text, kind="url", malformed=True, reason=R_MALFORMED_URL)

    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return TargetRef(raw=text, kind="url", malformed=True, reason=R_MALFORMED_URL)
    if not hostname:
        return TargetRef(raw=text, kind="url", malformed=True, reason=R_MALFORMED_URL)

    host = hostname.lower().rstrip(".")
    if "*" in host:
        if not _valid_pattern(host):
            return TargetRef(raw=text, kind="url", malformed=True, reason=R_MALFORMED_URL)
    elif not (_is_ip_literal(host) or _is_valid_host(host)):
        return TargetRef(raw=text, kind="url", malformed=True, reason=R_MALFORMED_URL)

    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    return TargetRef(
        raw=text,
        kind="url",
        scheme=scheme,
        host=host,
        port=port,
        path=path,
    )


@dataclass(slots=True)
class ScopeDecision:
    """The full reasoning behind a scope verdict."""

    target: str
    status: str
    reason: str
    matched_rule: str | None = None
    matched_kind: str | None = None
    matched_type: str | None = None
    match_kind: str | None = None  # exact | broad
    conflict: bool = False
    conflict_detail: str = ""
    restrictions: list[str] = field(default_factory=list)
    target_ref: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.status == IN_SCOPE

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "status": self.status,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "matched_type": self.matched_type,
            "match_kind": self.match_kind,
            "conflict": self.conflict,
            "conflict_detail": self.conflict_detail,
            "restrictions": list(self.restrictions),
            "allowed": self.allowed,
        }

    def block_message(self) -> str:
        if self.status == IN_SCOPE:
            return "target is in scope"
        lines = [
            "SRO POLICY DENIED",
            "",
            "Target:",
            f"  {self.target}",
            "",
            "Reason:",
            f"  {self.reason}",
            "",
            f"Verdict: {self.status}",
        ]
        if self.matched_rule:
            lines += ["", "Matched rule:", f"  {self.matched_rule}"]
        if self.status == UNKNOWN:
            lines += [
                "",
                "This target could not be resolved to a confirmed scope decision.",
                "Add it to the engagement manifest explicitly, or ask the program.",
            ]
        lines += ["", "No network request was made."]
        return "\n".join(lines)


def _wildcard_to_regex(pattern: str) -> re.Pattern[str]:
    escaped = re.escape(pattern)
    # '*' spans label boundaries so "*.example.com" covers "a.b.example.com",
    # while the literal dot before the domain keeps "evil-example.com" out.
    body = escaped.replace(r"\*", ".*")
    return re.compile(rf"^{body}$")


def _host_matches(rule: str, host: str) -> tuple[bool, str]:
    """Return (matched, match_kind) for a host against an inclusion/exclusion rule."""
    rule_norm = _rule_host(rule)
    host_norm = host.strip().lower().rstrip(".")

    if not rule_norm:
        return False, ""

    if "*" in rule_norm:
        if not _valid_pattern(rule_norm):
            # A malformed rule is not a permissive rule. Treating an invalid
            # pattern as a literal would quietly shrink scope, and treating it
            # as a broad glob would quietly widen it. Neither is correct.
            return False, ""
        pattern = _wildcard_to_regex(rule_norm)
        if pattern.match(host_norm):
            base = rule_norm.lstrip("*").lstrip(".")
            exact = host_norm == base
            return True, "exact" if exact else "broad"
        # "*.example.com" is read by nearly every program as "example.com and
        # its subdomains". The apex only matches through this branch so the
        # wildcard_includes_apex toggle can switch it off.
        if rule_norm.startswith("*."):
            if host_norm == rule_norm[2:]:
                return True, "exact"
        return False, ""

    if rule_norm == host_norm:
        return True, "exact"

    # A bare domain implies its subdomains unless the program says otherwise.
    if "." in rule_norm and host_norm.endswith("." + rule_norm):
        return True, "broad"

    return False, ""


def _rule_host(rule: str) -> str:
    """Reduce a manifest rule to the host it constrains.

    A rule may be a bare host, a wildcard, or a full URL pinning a path. Only
    the host part participates in host matching; comparing a URL rule against a
    bare host would never match and would silently drop a real scope entry.
    """
    text = (rule or "").strip()
    if "://" not in text:
        return text.lower().rstrip(".").rstrip("/")
    parts = urlsplit(text)
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.port:
        # A rule that names a port constrains it. Host matching compares against
        # ref.host, which _parse_url leaves port-free, so the port is checked by
        # _ref_matches_rule instead of being folded into the host string.
        return host
    return host


def normalize_path(path: str | None) -> str:
    """Resolve `.` and `..` so a path rule is a real containment boundary.

    Without this, a rule pinning `/v2/admin` would match
    `/v2/admin/../../etc/passwd`. Every HTTP stack the researcher will actually
    use normalises the path before sending, so the request that lands on the
    server is the one the rule was supposed to exclude.
    """
    raw = path or "/"
    if not raw.startswith("/"):
        raw = "/" + raw
    # A traversal that climbs above the root is not resolvable; keep the literal
    # so it fails to match rather than collapsing to "/".
    segments: list[str] = []
    for segment in raw.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            if not segments:
                return raw
            segments.pop()
            continue
        segments.append(segment)
    return "/" + "/".join(segments) if segments else "/"


def _path_matches(rule: str, path: str | None) -> tuple[bool, str]:
    """URL rules may pin a path prefix. Empty rule path matches any path."""
    if not rule or "://" not in rule and "/" not in rule:
        return True, "exact"
    rule_path = urlsplit(rule).path if "://" in rule else "/" + rule.strip("/")
    rule_path = normalize_path(rule_path)
    rule_path = rule_path.rstrip("/") or "/"
    if rule_path == "/":
        return True, "broad"
    target_path = normalize_path(path)
    if target_path == rule_path:
        return True, "exact"
    if target_path.startswith(rule_path + "/"):
        return True, "broad"
    return False, ""


def _rule_ref(rule: str) -> TargetRef:
    return parse_target(rule)


def _ref_matches_rule(ref: TargetRef, rule: str, target_type: str) -> tuple[bool, str]:
    """Match a parsed target against one manifest rule string."""
    rule_ref = _rule_ref(rule)

    # host / url / wildcard / domain rules
    if rule_ref.kind in {"host", "wildcard", "url", "host_port"} and ref.host:
        host_ok, host_kind = _host_matches(rule, ref.host)
        if not host_ok:
            return False, ""
        if rule_ref.kind == "url" or ("://" in rule):
            path_ok, path_kind = _path_matches(rule, ref.path)
            if not path_ok:
                return False, ""
            if host_kind == "exact" and path_kind == "exact":
                return True, "exact"
            return True, "broad"
        return True, host_kind

    # ip rules
    if rule_ref.kind == "ip" and ref.ip:
        try:
            return (ipaddress.ip_address(ref.ip) == ipaddress.ip_address(rule_ref.ip), "exact")
        except ValueError:
            return False, ""

    # cidr rules
    if rule_ref.kind == "cidr" and ref.ip:
        try:
            network = ipaddress.ip_network(rule_ref.network, strict=False)
            return (ipaddress.ip_address(ref.ip) in network, "broad")
        except ValueError:
            return False, ""
    if rule_ref.kind == "cidr" and ref.kind == "cidr":
        try:
            rule_net = ipaddress.ip_network(rule_ref.network, strict=False)
            ref_net = ipaddress.ip_network(ref.network, strict=False)
            return (ref_net.subnet_of(rule_net), "broad")
        except ValueError:
            return False, ""

    # repository rules
    if rule_ref.kind == "repository" and ref.repository:
        rule_repo = rule_ref.repository.rstrip("/").lower()
        if ref.repository.rstrip("/").lower() == rule_repo:
            return True, "exact"
        if ref.repository.rstrip("/").lower().startswith(rule_repo + "/"):
            return True, "broad"
        return False, ""

    # mobile / cloud / asset identifier rules are compared as strings
    if rule_ref.kind in {"resource_id", "unqualified_name", "cloud_resource"} and (
        ref.resource_id or ref.repository
    ):
        rule_norm = rule.strip().rstrip("/").lower()
        ref_norm = (ref.resource_id or ref.repository or "").rstrip("/").lower()
        if not ref_norm or not rule_norm:
            return False, ""
        # A trailing "*" is an explicit prefix wildcard, which is how ARNs and
        # asset families are published. "*" on its own has an empty prefix and
        # is rejected, so it cannot become a match-everything rule.
        if rule_norm.endswith("*"):
            prefix = rule_norm[:-1]
            if len(prefix) < 3:
                return False, ""
            return (ref_norm.startswith(prefix), "broad")
        if ref_norm == rule_norm:
            return True, "exact"
        if ref_norm.startswith(rule_norm + "/"):
            return True, "broad"
        return False, ""

    # cross-kind: a URL target can be matched by a bare host rule and vice versa
    if ref.host and rule_ref.kind in {"host", "wildcard"}:
        host_ok, host_kind = _host_matches(rule, ref.host)
        if host_ok:
            return True, host_kind
    if ref.ip and rule_ref.kind in {"ip", "cidr"}:
        return _ref_matches_rule(TargetRef(raw=ref.raw, kind="ip", ip=ref.ip), rule, target_type)

    # Deliberately no fnmatch fallback. It would be a second matching path that
    # bypasses _valid_pattern, and it honours glob metacharacters the pattern
    # validator rejects, so a rule of "*" would match every target. A rule the
    # engine cannot interpret exactly must not match at all.
    return False, ""


@dataclass(slots=True)
class ScopeEngine:
    """Evaluate targets against a confirmed engagement manifest.

    The engine is constructed from an engagement and its activated flag. When
    the engagement is not active every target resolves to UNKNOWN with a
    distinct reason, so a caller cannot accidentally get a permissive verdict
    out of a merely-loaded-but-unconfirmed manifest.
    """

    engagement: Engagement | None = None
    active: bool = False
    wildcard_includes_apex: bool = True
    deny_private_networks: bool = True
    _inclusion_rules: list[Target] = field(default_factory=list)
    _exclusion_rules: list[Target] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.rebuild()

    # -- construction ------------------------------------------------------

    def rebuild(self) -> None:
        self._inclusion_rules = []
        self._exclusion_rules = []
        engagement = self.engagement
        if engagement is None:
            return
        for target in engagement.targets:
            if target.in_scope:
                self._inclusion_rules.append(target)
            else:
                self._exclusion_rules.append(target)
        for target in engagement.exclusions:
            # An entry in `exclusions` is authoritative even if the raw payload
            # was ambiguous about the flag.
            target.in_scope = False
            self._exclusion_rules.append(target)

    @classmethod
    def from_engagement(cls, engagement: Engagement | None, active: bool = False, **kwargs: Any) -> "ScopeEngine":
        """Build an engine from an engagement.

        `active` defaults to False, matching `ScopeEngine(engagement=...)`. An
        unconfirmed engagement must never be usable by default, and two
        constructors with opposite defaults is how that gets forgotten.
        """
        return cls(engagement=engagement, active=bool(engagement is not None and active), **kwargs)

    # -- rules as plain strings -------------------------------------------

    def _exclusion_strings(self) -> list[tuple[str, Target]]:
        return [(t.identifier, t) for t in self._exclusion_rules]

    def _inclusion_strings(self) -> list[tuple[str, Target]]:
        return [(t.identifier, t) for t in self._inclusion_rules]

    def _apex_check(self, ref: TargetRef, rule: str) -> bool:
        """Decide whether a wildcard rule covers this particular target.

        Nearly every program that writes "*.example.com" means the apex too, so
        that is the default. The toggle exists for the programs that do not, and
        for the private lab where only the subdomains are authorized.
        """
        rule_host = _rule_host(rule)
        if not rule_host.startswith("*"):
            return True
        if self.wildcard_includes_apex:
            return True
        base = rule_host.lstrip("*").lstrip(".")
        return not (ref.host and ref.host.lower() == base)

    # -- public API --------------------------------------------------------

    def check(self, raw_target: str) -> ScopeDecision:
        ref = parse_target(raw_target)
        ref_dict = {
            "kind": ref.kind,
            "host": ref.host,
            "port": ref.port,
            "scheme": ref.scheme,
            "path": ref.path,
            "ip": ref.ip,
            "repository": ref.repository,
            "resource_id": ref.resource_id,
            "malformed": ref.malformed,
        }

        def _deny(reason: str, matched: str | None = None, **extra: Any) -> ScopeDecision:
            return ScopeDecision(
                target=str(raw_target),
                status=OUT_OF_SCOPE,
                reason=reason,
                matched_rule=matched,
                matched_type="exclusion",
                target_ref=ref_dict,
                **extra,
            )

        def _unknown(reason: str) -> ScopeDecision:
            return ScopeDecision(
                target=str(raw_target),
                status=UNKNOWN,
                reason=reason,
                target_ref=ref_dict,
            )

        if self.engagement is None or not self.active:
            return _unknown(R_NO_ENGAGEMENT if self.engagement is None else "engagement is not activated")

        if ref.malformed:
            return _unknown(ref.reason or R_MALFORMED)

        if ref.kind == "unqualified_name":
            return _unknown(R_NO_RULE)

        if ref.kind == "wildcard":
            # A wildcard is a rule in the manifest, not a host. Checking it is
            # a no-op, and treating it as a match would let an agent satisfy a
            # scope check with a pattern instead of a real target.
            return _unknown(
                "a wildcard is a scope rule, not a probeable target; "
                "name a specific host inside the wildcard"
            )

        host = ref.host or ref.ip
        if host and host.lower() in FORBIDDEN_HOSTS:
            return _deny("target is a reserved loopback or metadata endpoint", matched=host)
        if self.deny_private_networks and host and _is_ip_literal(host):
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if address is not None and _is_internal_address(address):
                return _deny("target is a private, loopback, link-local or reserved address", matched=host)

        # ---- 1. exclusions, always first --------------------------------
        exact_exclusion: tuple[str, Target] | None = None
        broad_exclusion: tuple[str, Target] | None = None
        for rule, target in self._exclusion_strings():
            if not self._apex_check(ref, rule):
                continue
            matched, kind = _ref_matches_rule(ref, rule, target.type)
            if not matched:
                continue
            if kind == "exact" and exact_exclusion is None:
                exact_exclusion = (rule, target)
            elif broad_exclusion is None:
                broad_exclusion = (rule, target)

        chosen_exclusion = exact_exclusion or broad_exclusion
        exclusion_reason = (
            R_EXCLUDED_EXACT
            if chosen_exclusion and chosen_exclusion == exact_exclusion
            else R_EXCLUDED_BROAD
        )

        # ---- 2. inclusions ----------------------------------------------
        exact_inclusion: tuple[str, Target] | None = None
        broad_inclusion: tuple[str, Target] | None = None
        for rule, target in self._inclusion_strings():
            if not self._apex_check(ref, rule):
                continue
            matched, kind = _ref_matches_rule(ref, rule, target.type)
            if not matched:
                continue
            if kind == "exact" and exact_inclusion is None:
                exact_inclusion = (rule, target)
            elif broad_inclusion is None:
                broad_inclusion = (rule, target)

        chosen_inclusion = exact_inclusion or broad_inclusion

        if chosen_exclusion is not None:
            rule, target = chosen_exclusion
            conflict = chosen_inclusion is not None
            detail = ""
            if conflict:
                inc_rule, inc_target = chosen_inclusion  # type: ignore[misc]
                inc_match = _ref_matches_rule(ref, inc_rule, inc_target.type)[1]
                if inc_match == "exact":
                    detail = (
                        f"target is listed in scope as {inc_rule!r} but also excluded as "
                        f"{rule!r}; the manifest is self-contradictory and the exclusion is applied"
                    )
                else:
                    detail = (
                        f"in-scope rule {inc_rule!r} also matches, but {rule!r} excludes it; "
                        "the exclusion takes precedence"
                    )
            return ScopeDecision(
                target=str(raw_target),
                status=OUT_OF_SCOPE,
                reason=exclusion_reason,
                matched_rule=rule,
                matched_type="exclusion",
                match_kind="exact" if chosen_exclusion == exact_exclusion else "broad",
                conflict=conflict,
                conflict_detail=detail,
                restrictions=list(target.restrictions),
                target_ref=ref_dict,
            )

        if chosen_inclusion is not None:
            rule, target = chosen_inclusion
            is_exact = chosen_inclusion == exact_inclusion
            restrictions = list(target.restrictions)
            reason = R_INCLUDED_EXACT if is_exact else R_INCLUDED_BROAD
            return ScopeDecision(
                target=str(raw_target),
                status=IN_SCOPE,
                reason=reason,
                matched_rule=rule,
                matched_type="inclusion",
                matched_kind=target.type,
                match_kind="exact" if is_exact else "broad",
                restrictions=restrictions,
                target_ref=ref_dict,
            )

        return _unknown(R_NO_RULE)

    def is_in_scope(self, raw_target: str) -> bool:
        return self.check(raw_target).status == IN_SCOPE

    def filter_in_scope(self, targets: Iterable[str]) -> dict[str, str]:
        """Batch helper for recon triage."""
        return {t: self.check(t).status for t in targets}

    def describe(self) -> dict[str, Any]:
        return {
            "active": self.active,
            "engagement": self.engagement.program_name if self.engagement else None,
            "provider": self.engagement.provider if self.engagement else None,
            "inclusion_rules": [t.identifier for t in self._inclusion_rules],
            "exclusion_rules": [t.identifier for t in self._exclusion_rules],
            "wildcard_includes_apex": self.wildcard_includes_apex,
            "deny_private_networks": self.deny_private_networks,
        }
