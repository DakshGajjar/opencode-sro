"""Public Bugcrowd page extraction.

This is the zero-credential path. Bugcrowd renders program pages server-side and
embeds the payload as JSON in the HTML, so a reader with no credentials can
still recover the program name, description, rules, scope table and known issues.

The extractor is defensive on purpose. It looks for structured JSON first and
falls back to HTML table parsing. When it cannot find something it returns an
empty value and says so, rather than inventing a scope entry. A missing target
resolves to UNKNOWN, which is blocked; a hallucinated target resolves to
IN_SCOPE, which is not.

Nothing in this file executes page content, follows instructions in it, or
sends it anywhere. It returns strings and the parser turns strings into typed
targets.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from html import unescape
from typing import Any

from ..base import is_program_shell, strip_html

__all__ = ["extract_public_program", "strip_html"]

#: JSON blobs Bugcrowd has used for embedded page data. Each entry is a
#: candidate key inside a `<script>` payload.
_EMBED_KEYS = ("program", "engagement", "initialState", "props", "data")

_JSON_BLOCK = re.compile(
    r"<script[^>]*type=[\"']application/(?:json|ld\+json)[\"'][^>]*>(.*?)</script>",
    re.DOTALL | re.IGNORECASE,
)
_TAG_SCRIPT = re.compile(r"(?is)<(script|style)[^>]*>.*?</\1>")
_TAG = re.compile(r"(?s)<[^>]+>")
_WS = re.compile(r"\s+")

_HEADING = re.compile(r"(?is)<h[1-4][^>]*>(.*?)</h[1-4]>")
_ROW = re.compile(r"(?is)<tr[^>]*>(.*?)</tr>")
_CELL = re.compile(r"(?is)<t[dh][^>]*>(.*?)</t[dh]>")
_SECTION = re.compile(
    r"(?is)<(section|div)[^>]*(?:id|class)=[\"'][^\"']*(?:scope|target|program|rules|policy|instruction)[^\"']*[\"'][^>]*>(.*?)</\1>"
)

_SCOPE_SECTIONS = {
    "in_scope": re.compile(r"(?i)\b(?:in[-\s]?scope|included|targets?\b)"),
    "out_of_scope": re.compile(r"(?i)\b(?:out[-\s]?of[-\s]?scope|excluded|exclusions|not\s+eligible)"),
}

#: Column headers that mark a row as an out-of-scope row.
_EXCLUSION_HEADER = re.compile(r"(?i)out[-\s]of[-\s]?scope|excluded|not\s+eligible|disqualif")

_DOMAIN_RE = re.compile(
    r"\b((?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b"
)
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>\\]+", re.IGNORECASE)
_IP_CIDR_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*/\s*\d{1,2}\b")


def _iter_json_payloads(html: str):
    """Yield every JSON object embedded in the page, largest first."""
    payloads: list[Any] = []
    for match in _JSON_BLOCK.finditer(html):
        body = match.group(1).strip()
        if not body:
            continue
        try:
            payloads.append(json.loads(body))
        except json.JSONDecodeError:
            continue

    # Bugcrowd also inlines a JS assignment such as
    # `window.__PRELOADED_STATE__ = {...};`
    for match in re.finditer(
        r"(?:window\.)?(?:__[A-Z_]+__|__NEXT_DATA__|__INITIAL_STATE__)\s*=\s*(\{.*?\})\s*[;<]",
        html,
        re.DOTALL,
    ):
        try:
            payloads.append(json.loads(match.group(1)))
        except json.JSONDecodeError:
            continue

    payloads.sort(key=lambda item: len(json.dumps(item, default=str)) if item is not None else 0, reverse=True)
    return payloads


def _walk_for(node: Any, keys: set[str]) -> Iterator[Any]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in keys:
                yield value
            yield from _walk_for(value, keys)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_for(item, keys)


def _as_target_rows(value: Any) -> list[dict[str, Any]]:
    """Coerce an embedded scope blob into target-ish dicts."""
    rows: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, default_in_scope in (("in_scope", True), ("out_of_scope", False)):
            items = value.get(key)
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, str):
                        rows.append({"name": item, "in_scope": default_in_scope})
                    elif isinstance(item, dict):
                        item.setdefault("in_scope", default_in_scope)
                        rows.append(item)
        if not rows:
            for key in ("targets", "target_groups", "items", "data"):
                items = value.get(key)
                if isinstance(items, list):
                    rows.extend(x for x in items if isinstance(x, (dict, str)))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                rows.append({"name": item})
            elif isinstance(item, dict):
                rows.append(item)
    return rows


def _extract_tables(html: str) -> dict[str, list[dict[str, Any]]]:
    """Parse scope tables out of rendered HTML.

    A table's bucket comes from the nearest preceding heading, because program
    pages routinely put "In scope" and "Out of scope" tables side by side with
    identical column headers. Falling back to the column header, then to
    in-scope, keeps a table from being misfiled as out-of-scope by accident.
    """
    result: dict[str, list[dict[str, Any]]] = {"in_scope": [], "out_of_scope": []}

    headings = [(m.start(), strip_html(m.group(1))) for m in _HEADING.finditer(html)]
    tables = [(m.start(), m.group(0)) for m in re.finditer(r"(?is)<table[^>]*>.*?</table>", html)]

    for position, table_html in tables:
        rows = _ROW.findall(table_html)
        if not rows:
            continue
        header_cells = [strip_html(c) for c in _CELL.findall(rows[0])]
        if not header_cells:
            continue
        # A scope table has a target/asset column and a type or category column.
        joined = " ".join(header_cells).lower()
        if not any(
            token in joined
            for token in ("target", "asset", "uri", "domain", "category", "type", "endpoint", "application")
        ):
            continue

        context = ""
        for heading_pos, heading_text in headings:
            if heading_pos < position:
                context = heading_text.lower()
            else:
                break

        out_of_scope_table = bool(_EXCLUSION_HEADER.search(joined)) or bool(
            _EXCLUSION_HEADER.search(context)
        )

        for row in rows[1:]:
            cells = [strip_html(c) for c in _CELL.findall(row)]
            cells = [c for c in cells if c]
            if not cells:
                continue
            # Skip "no data" placeholders and pagination rows.
            if len(cells) < 1 or cells[0].lower() in {"-", "none", "n/a", "no results", "1", "2", "3"}:
                continue
            identifier = cells[0]
            if not _looks_like_asset(identifier):
                continue
            row_data: dict[str, Any] = {"name": identifier, "in_scope": not out_of_scope_table}
            if len(cells) > 1:
                row_data["category"] = cells[1]
            if len(cells) > 2:
                row_data["instructions"] = cells[2]
            result["out_of_scope" if out_of_scope_table else "in_scope"].append(row_data)
    return result


def _looks_like_asset(value: str) -> bool:
    text = (value or "").strip()
    if not text or len(text) > 512:
        return False
    return bool(
        _IP_CIDR_RE.search(text)
        or _URL_RE.match(text)
        or _DOMAIN_RE.fullmatch(text)
        or re.match(r"^(?:com|org|net|io)\.[A-Za-z0-9_.\-]+$", text)
        or text.startswith("arn:")
    )


def _extract_prose(html: str) -> dict[str, str]:
    """Recover the narrative sections: description, rules, safe harbor, policy."""
    text = strip_html(html)
    out: dict[str, str] = {}

    # Prefer headings as delimiters so rules can be separated from boilerplate.
    headings = [strip_html(h) for h in _HEADING.findall(html)]
    for index, heading in enumerate(headings):
        start = html.lower().find(heading.lower()) if heading else -1
        if start == -1:
            continue
        end = html.lower().find(headings[index + 1].lower(), start + 1) if index + 1 < len(headings) else -1
        chunk = html[start : end if end != -1 else len(html)]
        body = strip_html(chunk)
        if not body or body.lower() == heading.lower():
            continue
        lowered = heading.lower()
        if "scope" in lowered or "target" in lowered:
            out.setdefault("scope_text", body)
        elif any(word in lowered for word in ("rule", "instruction", "testing", "guideline", "prohibit")):
            out.setdefault("rules", body)
        elif "safe harbor" in lowered or "safe-harbour" in lowered:
            out.setdefault("safe_harbor", body)
        elif "disclosure" in lowered or "policy" in lowered:
            out.setdefault("disclosure_policy", body)
        elif "known issue" in lowered or "duplicate" in lowered or "previously" in lowered:
            out.setdefault("known_issues", body)
        elif "description" in lowered or "overview" in lowered or "about" in lowered:
            out.setdefault("description", body)
    out.setdefault("full_text", text)
    return out


def _title(html: str) -> str:
    match = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    if match:
        title = strip_html(match.group(1))
        title = re.split(r"\s*[|\-–—]\s*", title)[0].strip()
        if title:
            return title
    og = re.search(r"(?is)<meta[^>]+property=[\"']og:title[\"'][^>]+content=[\"']([^\"']+)[\"']", html)
    if og:
        return unescape(og.group(1)).strip()
    return ""


def extract_public_program(html: str) -> dict[str, Any]:
    """Extract a program dictionary from a public Bugcrowd page.

    Returns an empty dict rather than raising when nothing is recognized, so
    the caller can decide between falling back to the API or reporting an
    incomplete read.
    """
    if not html or len(html) < 200:
        return {}

    program: dict[str, Any] = {}

    payloads = _iter_json_payloads(html)
    for payload in payloads:
        for key in _EMBED_KEYS:
            candidates = list(_walk_for(payload, {key}))
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                name = candidate.get("name") or candidate.get("title")
                if not name:
                    continue
                for field_name in (
                    "name",
                    "code",
                    "description",
                    "url",
                    "logo",
                    "brief",
                    "instructions",
                    "program_url",
                    "safe_harbor",
                    "disclosure_policy",
                    "launch_date",
                    "submission_state",
                ):
                    value = candidate.get(field_name)
                    if value not in (None, "", [], {}) and field_name not in program:
                        program[field_name] = value
                break
            if program.get("name"):
                break
        if program.get("name"):
            break

    prose = _extract_prose(html)

    # A client-rendered shell is not a program. Shared with the other two readers
    # so the rule is one implementation and not three that can drift.
    if is_program_shell({**program, **prose}):
        return {}

    if not program.get("name"):
        program["name"] = _title(html)
    if not program.get("description"):
        program["description"] = prose.get("description") or prose.get("full_text", "")[:2000]
    if not program.get("rules"):
        program["rules"] = prose.get("rules", "")
    if not program.get("safe_harbor"):
        program["safe_harbor"] = prose.get("safe_harbor", "")
    if not program.get("disclosure_policy"):
        program["disclosure_policy"] = prose.get("disclosure_policy", "")

    # ---- scope ---------------------------------------------------------
    scope: dict[str, list[dict[str, Any]]] = {"in_scope": [], "out_of_scope": []}

    for payload in payloads:
        for key, default_in_scope in (
            ("in_scope", True),
            ("out_of_scope", False),
            ("targets", None),
            ("target_groups", None),
            ("scope", None),
        ):
            for value in _walk_for(payload, {key}):
                rows = _as_target_rows(value)
                if not rows:
                    continue
                for row in rows:
                    if default_in_scope is not None:
                        # The key that held the list is authoritative. A row's
                        # own flag wins only when it is explicitly present, so
                        # an "out_of_scope" array can never be filed as
                        # in-scope by a missing field.
                        if row.get("in_scope") is None:
                            row["in_scope"] = default_in_scope
                        else:
                            row["in_scope"] = bool(row["in_scope"]) and default_in_scope
                    bucket = "out_of_scope" if row.get("in_scope") is False else "in_scope"
                    scope[bucket].append(row)

    tables = _extract_tables(html)
    for bucket, rows in tables.items():
        scope[bucket].extend(rows)

    # Last resort: domains named in the prose of a section that reads like scope.
    if not scope["in_scope"] and prose.get("scope_text"):
        blob = prose["scope_text"]
        for match in _URL_RE.finditer(blob):
            scope["in_scope"].append({"name": match.group(0).rstrip(".,;)")})
        for match in _IP_CIDR_RE.finditer(blob):
            scope["in_scope"].append({"name": match.group(0)})
        for match in _DOMAIN_RE.finditer(blob):
            name = match.group(1)
            if name.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".webp")):
                continue
            scope["in_scope"].append({"name": name})

    if scope["in_scope"] or scope["out_of_scope"]:
        program["scope"] = scope
        if not program.get("domains"):
            program["domains"] = [
                row["name"] for row in scope["in_scope"] if isinstance(row.get("name"), str)
            ][:100]

    if prose.get("known_issues"):
        program["known_issues_text"] = prose["known_issues"][:2000]

    if not program.get("name"):
        return {}
    return program
