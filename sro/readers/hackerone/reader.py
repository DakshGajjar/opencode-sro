"""HackerOne dumb reader.

Read-only, same typed-operation shape as the Bugcrowd reader. HackerOne's
GraphQL endpoint is used exclusively for read queries. There is no mutation
anywhere in this file, and the transport cannot carry one.

Retrieval strategy, in order:

1.  Structured scope from the public program page (embedded JSON). This is the
    zero-credential path and is enough for scope in most cases.
2.  Public `policy` text for rules and restrictions.
3.  Optional read-only GraphQL for richer detail when a token is configured.

Reading the user's own reports is supported only behind
`providers.hackerone.submissions: false` semantics — it is off by default and
SRO ships it off, because report contents are the researcher's unpublished work.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote, urlsplit

from ...core.config import ProviderConfig
from ...core.engagement import Engagement
from ...core.errors import (
    ProviderAuthError,
    ProviderError,
    ProviderSchemaError,
    ProviderUnavailableError,
)
from ..base import BaseReader, ReaderCapabilities, extract_program_code, normalize_url, strip_html
from .normalizer import normalize_hackerone_payload
from .scrape import extract_public_hackerone

GRAPHQL_URL = "https://api.hackerone.com/v1/graphql"

#: Read-only GraphQL documents. Every one of these is a query. There is no
#: mutation string in this file, and the test suite asserts that.
PROGRAM_QUERY = """
query SroProgram($handle: String!) {
  program(handle: $handle) {
    id
    handle
    name
    url
    description
    policy
    safe_harbor
    disclosure_policy
    submission_state
    structured_scopes(first: 200) {
      nodes {
        identifier
        attributes { type instructions cwe_ids notes in_scope }
        eligible_for_bounty
      }
    }
  }
}
"""

#: Program listing. `max_payout` and `submission_count` are included because a
#: reward range is legitimate scoping information for a researcher.
PROGRAMS_QUERY = """
query SroPrograms($after: String) {
  programs(first: 50, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges {
      cursor
      node { id handle name url }
    }
  }
}
"""


class HackerOneReader(BaseReader):
    provider = "hackerone"
    default_hosts = ("api.hackerone.com", "hackerone.com")
    api_hosts = ("api.hackerone.com",)
    api_origin = "https://api.hackerone.com"

    def capabilities(self) -> ReaderCapabilities:
        return ReaderCapabilities(
            provider=self.provider,
            reads=(
                "list_programs",
                "get_program",
                "get_structured_scope",
                "get_scope_exclusions",
                "get_program_details",
            ),
            authenticated_reads=("get_structured_scope", "get_scope_exclusions", "get_program_details"),
            writes=(),
            import_supported=True,
            notes=(
                "Public program pages are read first, so no credentials are required. "
                "Optional read-only GraphQL for richer structured scope. "
                "Reading your own reports is disabled by default. "
                "No report creation, update, comment or submission capability exists."
            ),
        )

    # -- URL / handle ------------------------------------------------------

    @staticmethod
    def program_code_from_url(url: str) -> str:
        """Pull the HackerOne handle out of any URL shape, or a bare handle."""
        return extract_program_code(
            url,
            provider="HackerOne",
            kind="program",
            anchors=(),
            noise=frozenset({"programs", "directory", "policies", "scope", "security", "about"}),
        )

    # -- GraphQL (read-only) ----------------------------------------------

    def _graphql_query(self, document: str, variables: dict[str, Any]) -> dict[str, Any]:
        """Send a read-only GraphQL query.

        Two independent guarantees stack here. The transport is GET-only, so
        the query travels as a URL-encoded `query=` parameter, which GraphQL
        servers accept for queries and refuse for mutations. And the mutation
        check below runs before the credential check, so a mutation is rejected
        whether or not a token happens to be configured.
        """
        if "mutation" in document.lower():
            raise ProviderError(
                "SRO refuses to send a GraphQL mutation; the HackerOne reader is read-only "
                "and report creation, updates and comments do not exist in this codebase"
            )
        if not self.has_credentials:
            raise ProviderAuthError(
                "HackerOne GraphQL reads need a read-only API token. "
                "Public program pages are read without credentials; to use GraphQL set "
                "providers.hackerone.credentials=environment with token_env."
            )
        from urllib.parse import urlencode

        url = f"{GRAPHQL_URL}?" + urlencode({"query": document, "variables": json.dumps(variables)})
        payload = self.transport.get_json(url)
        if not isinstance(payload, dict):
            raise ProviderSchemaError("GraphQL response was not an object")
        if payload.get("errors"):
            messages = "; ".join(
                str(e.get("message", e)) for e in payload["errors"] if isinstance(e, dict)
            )
            raise ProviderSchemaError(f"HackerOne GraphQL returned errors: {messages}")
        return payload.get("data") or {}

    # -- typed read operations --------------------------------------------

    def list_programs(self) -> list[dict[str, Any]]:
        if self.has_credentials:
            try:
                data = self._graphql_query(PROGRAMS_QUERY, {})
                edges = ((data.get("programs") or {}).get("edges")) or []
                return [edge["node"] for edge in edges if isinstance(edge, dict) and isinstance(edge.get("node"), dict)]
            except (ProviderAuthError, ProviderUnavailableError, ProviderSchemaError):
                pass
        return extract_public_hackerone(self.transport.get(f"{self.base_url()}/directory").body).get(
            "programs", []
        )

    def get_program(self, handle: str) -> dict[str, Any]:
        """Program metadata. Public first, GraphQL when a token is configured."""
        if self.has_credentials:
            try:
                data = self._graphql_query(PROGRAM_QUERY, {"handle": handle})
                program = data.get("program")
                if isinstance(program, dict):
                    return program
            except (ProviderAuthError, ProviderUnavailableError, ProviderSchemaError):
                pass
        return self.get_program_details(handle)

    def get_program_details(self, handle: str) -> dict[str, Any]:
        """Read the public program page. Zero credentials."""
        url = normalize_url(f"https://hackerone.com/{quote(handle)}")
        extracted = extract_public_hackerone(self.transport.get(url).body)
        if not extracted:
            raise ProviderSchemaError(
                f"{url}: no recognizable program data; the program may be private or the page "
                "layout may have changed"
            )
        extracted.setdefault("handle", handle)
        extracted["_source_url"] = url
        return extracted

    def get_structured_scope(self, handle: str) -> list[dict[str, Any]]:
        """In-scope structured scope entries."""
        scope = self.get_scope(handle)
        return list(scope.get("in_scope") or [])

    def get_scope_exclusions(self, handle: str) -> list[dict[str, Any]]:
        """Explicitly excluded scope entries."""
        scope = self.get_scope(handle)
        return list(scope.get("out_of_scope") or [])

    def get_scope(self, handle: str) -> dict[str, Any]:
        """Combined in-scope / out-of-scope view, from GraphQL or the public page."""
        if self.has_credentials:
            try:
                data = self._graphql_query(PROGRAM_QUERY, {"handle": handle})
                program = data.get("program")
                if isinstance(program, dict):
                    attributes = program.get("attributes")
                    attributes = attributes if isinstance(attributes, dict) else {}
                    nodes = ((program.get("structured_scopes") or {}).get("nodes")) or []
                    scope: dict[str, list[dict[str, Any]]] = {"in_scope": [], "out_of_scope": []}
                    for node in nodes:
                        if not isinstance(node, dict):
                            continue
                        node_attributes = node.get("attributes")
                        node_attributes = node_attributes if isinstance(node_attributes, dict) else {}
                        if node_attributes.get("in_scope") is False:
                            scope["out_of_scope"].append(node)
                        else:
                            scope["in_scope"].append(node)
                    if attributes.get("structured_scopes") is not None or scope["in_scope"] or scope["out_of_scope"]:
                        return scope
            except (ProviderAuthError, ProviderUnavailableError, ProviderSchemaError):
                pass

        extracted = self.get_program_details(handle)
        scope = extracted.get("scope") or {}
        if not scope:
            raise ProviderSchemaError(
                f"{handle}: no structured scope is published on the public program page"
            )
        return scope

    def get_policy(self, handle: str) -> str:
        program = self.get_program_details(handle)
        return strip_html(str(program.get("policy") or ""))

    # -- normalization -----------------------------------------------------

    def read_engagement(self, handle: str) -> Engagement:
        self.require_public_mode()
        program = self.get_program(handle)
        payload = dict(program)
        payload.setdefault("handle", handle)
        engagement = normalize_hackerone_payload(
            payload,
            code=handle,
            source_url=str(program.get("_source_url") or f"https://hackerone.com/{handle}"),
            credentials_used=self.has_credentials,
        )
        return engagement
