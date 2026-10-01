"""Bugcrowd dumb reader.

Reads. Returns data. Nothing else.

The reader exposes a fixed set of typed read operations. There is no generic
"call the Bugcrowd API" entry point, no method that accepts an HTTP verb, and
no submission, comment, program-modification or scope-modification capability.
Those operations do not exist in this file and cannot be reached through the
transport in `sro.readers.base`.

Typed operations (all GET):

    list_programs        public program directory
    get_program          one program's public metadata
    get_engagement       an engagement by code
    get_brief            engagement brief text
    get_scope            in-scope and out-of-scope target tables
    get_rules            testing rules and restrictions
    get_known_issues     duplicate / known-issue list

Authentication is optional. When no credential is configured the reader falls
back to the public program pages, which is the default and requires no setup.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urlsplit

from ...core.engagement import (
    RETRIEVAL_API,
    RETRIEVAL_PUBLIC,
    Engagement,
    dedupe_targets,
)
from ...core.errors import (
    ProviderAuthError,
    ProviderError,
    ProviderSchemaError,
    ProviderUnavailableError,
)
from ..base import BaseReader, RawResponse, ReaderCapabilities, extract_program_code, normalize_url, strip_html
from .parser import (
    parse_auth_requirements,
    parse_known_issues,
    parse_rate_limits,
    parse_restrictions,
    parse_targets,
)
from .scrape import extract_public_program

API_BASE = "https://api.bugcrowd.com"
WEB_BASE = "https://bugcrowd.com"

#: Bugcrowd moved program pages from /programs/<code> to /engagements/<code>.
#: The old path still 404s, so a reader pinned to it fails on every program for a
#: reason that has nothing to do with the researcher or the program. Both are
#: tried, newest first, and the one that answers is recorded as the source.
PUBLIC_PROGRAM_PATHS = ("/engagements/{code}", "/programs/{code}")

#: Sparse fieldsets. SRO asks for the engagement fields it actually needs so a
#: read does not pull report data or other researcher's submissions.
PROGRAM_FIELDS = "name,code,description,url,tags,submission_state,launch_date,closed_date"
ENGAGEMENT_FIELDS = "code,name,description,program,url,logo,submissions_state,launch_date"
SCOPE_FIELDS = "id,name,type,in_scope,bounty_eligible,description,target_groups"
TARGET_FIELDS = "id,name,category,uri,in_scope,type,state,bounty_eligible"

#: Everything the reader is allowed to request. A path outside this table is a
#: programming error, caught by the guard in `_api_get`. Only documented GET
#: paths appear here; nothing is guessed at.
ALLOWED_API_PATHS: dict[str, str] = {
    "list_programs": "/v1/programs",
    "get_program": "/v1/programs/{code}",
    "get_engagement": "/v1/engagements/{code}",
    "get_scope": "/v1/engagements/{code}/scope",
    "get_rules": "/v1/engagements/{code}/instructions",
    "get_known_issues": "/v1/programs/{code}/known-issues",
}


class BugcrowdReader(BaseReader):
    """Read-only Bugcrowd accessor."""

    provider = "bugcrowd"
    default_hosts = ("api.bugcrowd.com", "bugcrowd.com")
    api_hosts = ("api.bugcrowd.com",)
    api_origin = API_BASE

    def capabilities(self) -> ReaderCapabilities:
        return ReaderCapabilities(
            provider=self.provider,
            reads=(
                "list_programs",
                "get_program",
                "get_engagement",
                "get_brief",
                "get_scope",
                "get_rules",
                "get_known_issues",
            ),
            authenticated_reads=(
                "get_engagement",
                "get_brief",
                "get_scope",
                "get_rules",
                "get_known_issues",
            ),
            writes=(),
            import_supported=True,
            notes=(
                "Zero-credential by default: public program pages are read first. "
                "Optional read-only credentials unlock the richer /v1 engagement API. "
                "No submission, comment or modification capability exists."
            ),
        )

    # -- URL / code resolution --------------------------------------------

    @staticmethod
    def program_code_from_url(url: str) -> str:
        """Pull the program code out of any Bugcrowd URL shape, or a bare code."""
        return extract_program_code(
            url,
            provider="Bugcrowd",
            kind="program",
            anchors=("programs", "engagements", "bug-bounty"),
            noise=frozenset({"bug-bounty", "programs", "engagements", "rules", "scope"}),
        )

    def _api_get(self, operation: str, path: str) -> RawResponse:
        if operation not in ALLOWED_API_PATHS:
            raise ProviderError(
                f"Bugcrowd read operation {operation!r} is not on the allowlist. "
                "SRO exposes typed reads only."
            )
        url = f"{self.base_url()}{path}"
        return self.transport.get(url)

    @staticmethod
    def _query(fields: str) -> str:
        return f"?fields={quote(fields, safe=',.')}"

    # -- typed read operations --------------------------------------------

    def list_programs(self, *, page: int = 1, per_page: int = 25) -> list[dict[str, Any]]:
        """Public program directory listing."""
        if self.has_credentials:
            path = "/v1/programs" + self._query(PROGRAM_FIELDS) + f"&page={page}&per_page={per_page}"
            try:
                payload = self._api_get("list_programs", path).json()
            except (ProviderAuthError, ProviderUnavailableError, ProviderSchemaError):
                payload = self._list_programs_public(page, per_page)
        else:
            payload = self._list_programs_public(page, per_page)
        return _coerce_list(payload)

    def _list_programs_public(self, page: int, per_page: int) -> list[dict[str, Any]]:
        last: Exception | None = None
        for path in ("/engagements", "/programs/index"):
            try:
                response = self.transport.get(normalize_url(f"{WEB_BASE}{path}?page={page}"))
            except (ProviderUnavailableError, ProviderAuthError) as exc:
                last = exc
                continue
            found = extract_public_program(response.body)
            if found:
                return found
        raise ProviderUnavailableError(
            f"Bugcrowd's public program listing did not return a readable index at "
            f"{WEB_BASE}/engagements or {WEB_BASE}/programs/index"
            + (f" ({last})" if last else "")
            + ". The listing is not published anonymously; use `sro import` with a "
            "hand-written brief, or supply read-only credentials."
        )

    def get_program(self, code: str) -> dict[str, Any]:
        """One program's public metadata."""
        if self.has_credentials:
            try:
                payload = self._api_get("get_program", f"/v1/programs/{quote(code)}" + self._query(PROGRAM_FIELDS))
                if isinstance(payload, dict):
                    return payload
            except (ProviderAuthError, ProviderUnavailableError, ProviderSchemaError):
                pass  # fall through to the public page
        return self._get_public_program(code)

    def _get_public_program(self, code: str) -> dict[str, Any]:
        response = None
        url = ""
        failures: list[str] = []
        for path in PUBLIC_PROGRAM_PATHS:
            candidate = normalize_url(f"{WEB_BASE}{path.format(code=quote(code))}")
            try:
                response = self.transport.get(candidate)
                url = candidate
                break
            except (ProviderUnavailableError, ProviderAuthError) as exc:
                # Kept, not swallowed: a 404 and a 500 are different problems and a
                # researcher needs to tell them apart to know whether to retry.
                failures.append(f"{candidate} ({exc})")
                continue
        if response is None:
            raise ProviderUnavailableError(
                f"Bugcrowd has no readable public page for {code!r}:\n  "
                + "\n  ".join(failures)
                + f"\n\nIf the code is right, the program is not published anonymously. "
                "Use `sro import <brief.json>` with a hand-written brief."
            )

        program = extract_public_program(response.body)
        if not program:
            # Reachable, but nothing machine-readable. This is the common case and
            # the old message blurred it with the auth case, so a researcher went
            # hunting for credentials when the real answer was that Bugcrowd does
            # not publish scope anonymously at all.
            raise ProviderSchemaError(
                f"{url} is reachable ({len(response.body)} bytes) but carries no "
                "machine-readable scope: no targets, categories or wildcard rules. "
                "Bugcrowd does not publish program scope anonymously — the page is "
                "rendered client-side or gated. This is not fixable by retrying, by a "
                "different URL, or with a program code.\n\n"
                f"Use `sro import <brief.json>` with a hand-translated brief, and keep "
                "product-level scope statements out of the manifest: a product string "
                "the matcher can store but cannot enforce reads as checked. "
                "See the shared-zone check before adding any wildcard rule."
            )
        program.setdefault("code", code)
        program["_retrieval_mode"] = RETRIEVAL_PUBLIC
        program["_source_url"] = url
        return program

    def get_engagement(self, code: str) -> dict[str, Any]:
        """Engagement metadata. Requires read-only credentials."""
        if not self.has_credentials:
            raise ProviderAuthError(
                "get_engagement needs a read-only Bugcrowd API token. "
                "Use the public program page instead, or configure "
                "providers.bugcrowd.credentials=environment with token_env."
            )
        payload = self._api_get("get_engagement", f"/v1/engagements/{quote(code)}" + self._query(ENGAGEMENT_FIELDS))
        if not isinstance(payload, dict):
            raise ProviderSchemaError(f"engagement {code}: expected an object, got {type(payload).__name__}")
        return payload

    def get_brief(self, code: str) -> dict[str, Any]:
        """Engagement brief text, from the API or the public page."""
        if self.has_credentials:
            try:
                payload = self._api_get(
                    "get_rules", f"/v1/engagements/{quote(code)}/instructions" + self._query("contents,updated_at")
                )
                if isinstance(payload, dict) and payload.get("contents"):
                    return {"contents": str(payload["contents"]), "source": "api"}
            except (ProviderAuthError, ProviderUnavailableError, ProviderSchemaError):
                pass
        return {"contents": "", "source": "none", "note": "brief requires read-only credentials"}

    def get_scope(self, code: str) -> dict[str, Any]:
        """In-scope and out-of-scope targets.

        Public pages carry a rendered scope table; the API returns structured
        groups. Either way the result is a plain dict for the parser.
        """
        if self.has_credentials:
            try:
                payload = self._api_get("get_scope", f"/v1/engagements/{quote(code)}/scope" + self._query(SCOPE_FIELDS))
                if isinstance(payload, dict) and payload:
                    return payload
            except (ProviderAuthError, ProviderUnavailableError, ProviderSchemaError):
                pass
        return self._get_public_scope(code)

    def _get_public_scope(self, code: str) -> dict[str, Any]:
        """Public scope. Measured in September 2026: there is none.

        Bugcrowd's public pages render scope client-side, so every path here
        returns a shell with no scope table in it — `/programs/<code>/scope` 404s,
        and `/engagements/<code>/scope` answers 200 with ~6KB of JavaScript
        bootstrap and no targets. Bugcrowd publishes scope through its API, which
        needs a read-only token.

        So this function exists to say that precisely, and to name the two paths
        that work, rather than to fail with a status code that sends the
        researcher looking for a URL problem that does not exist.
        """
        tried: list[str] = []
        for path in ("/engagements/{code}/scope", "/programs/{code}/scope"):
            url = normalize_url(f"{WEB_BASE}{path.format(code=quote(code))}")
            try:
                response = self.transport.get(url)
            except (ProviderUnavailableError, ProviderAuthError) as exc:
                tried.append(f"{url} ({exc})")
                continue
            scope = extract_public_program(response.body).get("scope") or {}
            if scope:
                return scope
            tried.append(f"{url} (reachable, {len(response.body)} bytes, no scope table)")

        raise ProviderSchemaError(
            "Bugcrowd does not publish program scope anonymously. Tried:\n  "
            + "\n  ".join(tried)
            + "\n\nThe pages are rendered client-side, so there is nothing to parse; this "
            "is not a wrong URL and retrying will not help. Two paths that do work:\n\n"
            f"  1. read-only credentials — set providers.bugcrowd.credentials to "
            f"\"environment\" and token_env in sro.json, which uses {API_BASE}/v1 "
            "and never writes.\n"
            "  2. `sro import <brief.json>` with a brief you have translated by hand.\n\n"
            "For a product-scoped program, keep product names out of the manifest: a "
            "product string the matcher can store but cannot enforce reads as checked."
        )

    def get_rules(self, code: str) -> dict[str, Any]:
        """Testing rules and restrictions as text."""
        brief = self.get_brief(code)
        if brief.get("contents"):
            return brief
        program = self._get_public_program(code)
        rules = program.get("rules") or program.get("description") or ""
        return {"contents": rules, "source": "public"}

    def get_known_issues(self, code: str) -> list[str]:
        """Known/duplicate issues. Disabled unless credentials are configured."""
        if not self.has_credentials:
            return []
        payload = self._api_get("get_known_issues", f"/v1/programs/{quote(code)}/known-issues" + self._query("id,title,reference"))
        return [str(item) for item in parse_known_issues(_coerce_list(payload))]

    # -- normalization -----------------------------------------------------

    def read_engagement(self, code: str) -> Engagement:
        """Assemble a normalized engagement from whatever is publicly available.

        Works in three tiers: public metadata, then public scope table, then
        optional authenticated reads. Whatever tier succeeded is recorded on the
        engagement so the researcher can see how much is actually known.
        """
        self.require_public_mode()

        program = self.get_program(code)
        engagement_id = str(program.get("code") or code)
        source_url = str(program.get("_source_url") or f"{WEB_BASE}/programs/{quote(code)}")

        text_blobs: list[str] = []
        warnings: list[str] = []

        rules_payload = self.get_rules(code) if self.config.mode in {"public", "readonly"} else {}
        rules_text = str(rules_payload.get("contents") or "")
        if rules_text:
            text_blobs.append(rules_text)
        elif not self.has_credentials:
            warnings.append(
                "engagement brief was not publicly available; testing restrictions were derived "
                "from the public description only and may be incomplete"
            )

        description = str(program.get("description") or "")
        if description:
            text_blobs.append(description)

        # --- scope ------------------------------------------------------
        targets: list[Any] = []
        try:
            scope_payload = self.get_scope(code)
        except (ProviderError, ProviderSchemaError) as exc:
            scope_payload = {}
            warnings.append(f"public scope could not be read: {exc}")

        for key, default_in_scope in (
            ("in_scope", True),
            ("out_of_scope", False),
            ("targets", True),
        ):
            entries = scope_payload.get(key) if isinstance(scope_payload, dict) else None
            if entries:
                parsed, parse_warnings = parse_targets(entries, default_in_scope=default_in_scope)
                targets.extend(parsed)
                warnings.extend(parse_warnings)

        if not targets:
            # A program page that publishes a plain "Domains" list rather than a
            # rendered table. Treat the listed domains as in-scope candidates.
            for raw in program.get("domains") or []:
                text = str(raw).strip()
                if text:
                    parsed, parse_warnings = parse_targets(
                        {"name": text, "category": "domain"}, default_in_scope=True
                    )
                    targets.extend(parsed)
                    warnings.extend(parse_warnings)

        if not targets:
            warnings.append(
                "no scope entries could be extracted; SRO will treat every target as UNKNOWN "
                "until the researcher imports the scope manually"
            )

        restrictions = parse_restrictions(*text_blobs)
        if not restrictions and text_blobs:
            warnings.append(
                "no machine-readable testing restrictions were recognised in the program text; "
                "the policy engine will ask before any action whose permission is unstated"
            )

        known_issues: list[str] = []
        if self.has_credentials and self.config.mode == "readonly":
            try:
                known_issues = self.get_known_issues(code)
            except (ProviderError, ProviderSchemaError):
                warnings.append("known issues could not be read with the configured credentials")

        engagement = Engagement(
            provider=self.provider,
            engagement_id=engagement_id,
            program_name=str(program.get("name") or code),
            program_url=str(program.get("url") or source_url),
            description=description,
            rules=rules_text,
            disclosure_policy=str(program.get("disclosure_policy") or ""),
            safe_harbor=str(program.get("safe_harbor") or ""),
            targets=dedupe_targets(targets),
            known_issues=known_issues,
            testing_restrictions=restrictions,
            rate_limits=parse_rate_limits(text_blobs),
            authentication_requirements=parse_auth_requirements(text_blobs),
            allowed_testing=[r.name for r in restrictions if r.status == "permitted"],
            forbidden_testing=[r.name for r in restrictions if r.status == "forbidden"],
            retrieval_mode=RETRIEVAL_API if self.has_credentials else RETRIEVAL_PUBLIC,
            credentials_used=self.has_credentials,
            source_url=source_url,
            completeness={
                "program_name": bool(program.get("name")),
                "rules": bool(rules_text),
                "scope": bool(targets),
                "known_issues": bool(known_issues) or not self.has_credentials,
            },
            warnings=warnings,
        )
        return engagement


def _coerce_list(payload: Any) -> list[dict[str, Any]]:
    """Normalize the several list shapes Bugcrowd APIs return."""
    if payload is None:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("programs", "engagements", "data", "results", "items", "target_groups"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def read_engagement_from_payload(
    payload: dict[str, Any],
    *,
    code: str,
    source_url: str = "",
    credentials_used: bool = False,
) -> Engagement:
    """Normalize an already-fetched Bugcrowd payload.

    Exposed separately so an MCP server, a test fixture or a researcher-supplied
    export can be normalized without SRO performing any network call.
    """
    warnings: list[str] = []
    rules_text = strip_html(str(payload.get("brief") or payload.get("instructions") or ""))
    description = strip_html(str(payload.get("description") or ""))

    in_scope, w1 = parse_targets(payload.get("in_scope") or payload.get("targets"), default_in_scope=True)
    out_scope, w2 = parse_targets(payload.get("out_of_scope") or payload.get("exclusions"), default_in_scope=False)
    warnings.extend(w1 + w2)

    blobs = [t for t in (rules_text, description) if t]
    restrictions = parse_restrictions(*blobs)

    targets = dedupe_targets(in_scope)
    exclusions = dedupe_targets(out_scope)
    if not targets and not exclusions:
        warnings.append(
            "the imported brief contains no scope entries; SRO will treat every target as "
            "UNKNOWN. Supply a brief with an 'in_scope' or 'targets' list."
        )
    # dedupe_targets folds in_scope=False entries together, so split afterwards.
    final_in = [t for t in targets if t.in_scope]
    final_out = [t for t in targets if not t.in_scope] + [t for t in exclusions if t not in targets]

    return Engagement(
        provider="bugcrowd",
        engagement_id=str(payload.get("code") or code),
        program_name=str(payload.get("name") or code),
        program_url=str(payload.get("program_url") or payload.get("url") or source_url),
        description=description,
        rules=rules_text,
        disclosure_policy=strip_html(str(payload.get("disclosure_policy") or "")),
        safe_harbor=strip_html(str(payload.get("safe_harbor") or "")),
        targets=final_in,
        exclusions=final_out,
        known_issues=parse_known_issues(payload.get("known_issues")),
        testing_restrictions=restrictions,
        rate_limits=parse_rate_limits(blobs),
        authentication_requirements=parse_auth_requirements(blobs),
        allowed_testing=[r.name for r in restrictions if r.status == "permitted"],
        forbidden_testing=[r.name for r in restrictions if r.status == "forbidden"],
        retrieval_mode=RETRIEVAL_API if credentials_used else RETRIEVAL_PUBLIC,
        credentials_used=credentials_used,
        source_url=source_url or str(payload.get("url") or ""),
        completeness={
            "program_name": bool(payload.get("name")),
            "rules": bool(rules_text),
            "scope": bool(in_scope or out_scope),
        },
        warnings=warnings,
    )
