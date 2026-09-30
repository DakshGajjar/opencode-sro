"""Intigriti reader.

Intigriti is an optional provider and is configured `import_only` by default.

SRO does not invent undocumented endpoints for a platform. The reader only
speaks documented read APIs, and only when one exists. Everything else falls
back to the public program page, and then to a researcher-supplied brief.

Reading the user's own reports is not implemented. The endpoint is known to
exist, but SRO does not call it, because report contents are the researcher's
unpublished work and pulling them into a local evidence store is a decision for
the researcher to make deliberately, not a default.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urlsplit

from ...core.engagement import RETRIEVAL_IMPORT, Engagement
from ...core.errors import (
    ProviderError,
    ProviderSchemaError,
)
from ...core.scope import _CODE_HOSTS
from ..base import BaseReader, ReaderCapabilities, normalize_url, strip_html
from ..bugcrowd.parser import (
    classify_identifier,
    parse_auth_requirements,
    parse_rate_limits,
    parse_restrictions,
    parse_targets,
)
from .scrape import extract_public_intigriti

API_BASE = "https://api.intigriti.com"

#: Documented read paths only. Intigriti has no documented public program
#: scope API, so the public-page path is the primary route and this table is
#: reserved for a future documented endpoint rather than guessed at now.
ALLOWED_API_PATHS: dict[str, str] = {
    "get_program": "/core/programs/{handle}",
}


class IntigritiReader(BaseReader):
    provider = "intigriti"
    default_hosts = ("api.intigriti.com", "intigriti.com")
    api_hosts = ("api.intigriti.com",)
    api_origin = API_BASE

    def capabilities(self) -> ReaderCapabilities:
        return ReaderCapabilities(
            provider=self.provider,
            reads=("get_program", "get_public_page", "import_brief"),
            authenticated_reads=(),
            writes=(),
            import_supported=True,
            notes=(
                "No documented public scope API. Reads the public program page when reachable, "
                "otherwise requires a researcher-supplied brief (mode=import_only). "
                "No submission or report capability exists."
            ),
        )

    @staticmethod
    def program_code_from_url(url: str) -> str:
        text = (url or "").strip()
        if not text:
            raise ProviderError("no Intigriti URL supplied")
        parts = urlsplit(text if "://" in text else "https://" + text)
        segments = [s for s in parts.path.split("/") if s]
        noise = {"programs", "directory", "policies", "about", "researchers"}
        for segment in segments:
            if segment.lower() in noise:
                continue
            if re.match(r"^[a-z0-9][a-z0-9_\-]{1,64}$", segment, re.IGNORECASE):
                return segment
        raise ProviderError(f"could not determine an Intigriti program handle from {url!r}")

    # -- reads -------------------------------------------------------------

    def get_public_page(self, handle: str) -> dict[str, Any]:
        url = normalize_url(f"https://intigriti.com/programs/{quote(handle)}")
        extracted = extract_public_intigriti(self.transport.get(url).body)
        if not extracted:
            raise ProviderSchemaError(
                f"{url}: no recognizable public program data. Intigriti program pages are "
                "heavily client-rendered; import the brief with `sro import <file> "
                "--provider intigriti` instead."
            )
        extracted.setdefault("handle", handle)
        extracted["_source_url"] = url
        return extracted

    def get_program(self, handle: str) -> dict[str, Any]:
        # Only a documented path is ever requested. An undocumented endpoint is
        # not guessed at, so this currently resolves to the public page.
        if handle and ALLOWED_API_PATHS.get("get_program"):
            path = ALLOWED_API_PATHS["get_program"].format(handle=quote(handle))
            if self.has_credentials:
                try:
                    payload = self.transport.get_json(f"{self.base_url() or API_BASE}{path}")
                    if isinstance(payload, dict):
                        return payload
                except ProviderError:
                    pass
        return self.get_public_page(handle)

    def read_engagement(self, handle: str) -> Engagement:
        self.require_public_mode()
        program = self.get_program(handle)
        return normalize_intigriti_payload(
            program,
            handle=handle,
            source_url=str(program.get("_source_url") or f"https://intigriti.com/programs/{handle}"),
        )


def normalize_intigriti_payload(
    payload: dict[str, Any],
    *,
    handle: str = "",
    source_url: str = "",
    retrieval_mode: str = "import",
) -> Engagement:
    """Normalize an Intigriti brief (public page or imported file)."""
    if not isinstance(payload, dict):
        raise ValueError("Intigriti payload must be an object")

    warnings: list[str] = []
    body = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    name = str(body.get("name") or body.get("program_name") or handle or "unknown")

    description = strip_html(str(body.get("description") or ""))
    policy = strip_html(str(body.get("policy") or body.get("rules") or ""))
    safe_harbor = strip_html(str(body.get("safe_harbor") or ""))
    disclosure = strip_html(str(body.get("disclosure_policy") or ""))

    targets: list[Any] = []
    exclusions: list[Any] = []

    for key, bucket in (
        ("in_scope", targets),
        ("targets", targets),
        ("out_of_scope", exclusions),
        ("exclusions", exclusions),
    ):
        entries = body.get(key)
        if not entries:
            continue
        parsed, parse_warnings = parse_targets(entries, default_in_scope=bucket is targets)
        bucket.extend(parsed)
        warnings.extend(parse_warnings)

    if not targets and not exclusions:
        warnings.append(
            "no scope entries were found in the Intigriti brief; SRO will treat every target as "
            "UNKNOWN. Import a brief containing an 'in_scope' or 'targets' list: "
            "sro import <file> --provider intigriti"
        )

    blobs = [b for b in (policy, description, disclosure) if b]
    restrictions = parse_restrictions(*blobs)

    return Engagement(
        provider="intigriti",
        engagement_id=str(body.get("handle") or handle or "imported"),
        program_name=name,
        program_url=str(body.get("url") or source_url or f"https://intigriti.com/programs/{handle}"),
        description=description,
        rules=policy,
        disclosure_policy=disclosure,
        safe_harbor=safe_harbor,
        targets=targets,
        exclusions=exclusions,
        testing_restrictions=restrictions,
        rate_limits=parse_rate_limits(blobs),
        authentication_requirements=parse_auth_requirements(blobs),
        allowed_testing=[r.name for r in restrictions if r.status == "permitted"],
        forbidden_testing=[r.name for r in restrictions if r.status == "forbidden"],
        retrieval_mode=retrieval_mode if retrieval_mode in {"public", "api", "import", "browser_assisted"} else RETRIEVAL_IMPORT,
        credentials_used=False,
        source_url=source_url,
        completeness={
            "program_name": bool(name),
            "rules": bool(policy),
            "scope": bool(targets or exclusions),
        },
        warnings=warnings,
    )
