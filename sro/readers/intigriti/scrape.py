"""Public Intigriti page extraction.

Intigriti program pages render scope client-side, so extraction succeeds only
when the page happens to carry readable content. When it does not, the reader
says so and asks for an imported brief rather than guessing a scope.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..base import strip_html

__all__ = ["extract_public_intigriti"]

_JSON_LD = re.compile(
    r"<script[^>]+type=[\"']application/(?:ld\+)?json[\"'][^>]*>(.*?)</script>",
    re.DOTALL | re.IGNORECASE,
)
_STATE = re.compile(
    r"(?:window\.)?(?:__NUXT__|__INITIAL_STATE__|__PRELOADED_STATE__|__APOLLO_STATE__)\s*=\s*(\{.*?\})\s*[;<]",
    re.DOTALL,
)
_ROW = re.compile(r"(?is)<tr[^>]*>(.*?)</tr>")
_CELL = re.compile(r"(?is)<t[dh][^>]*>(.*?)</t[dh]>")
_HEADING = re.compile(r"(?is)<h[1-4][^>]*>(.*?)</h[1-4]>")

_ASSET = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"
    r"|^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$"
    r"|^https?://"
    r"|^arn:"
    r"|^(?:com|org|net|io|co)\.[A-Za-z0-9_.\-]+$",
    re.IGNORECASE,
)
_EXCLUSION = re.compile(r"(?i)out[-\s]of[-\s]?scope|excluded|not\s+eligible|disallow")
_SCOPE_HEADER = re.compile(r"(?i)target|asset|identifier|scope|domain|uri|endpoint|api|application|category|type")
_SKIP = {"-", "none", "n/a", "no results", "loading", "1", "2", "3", "4", "5"}


def _walk(node: Any, wanted: set[str]):
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in wanted:
                yield value
            yield from _walk(value, wanted)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item, wanted)


def _payloads(html: str) -> list[Any]:
    found: list[Any] = []
    for match in _JSON_LD.finditer(html):
        try:
            found.append(json.loads(match.group(1)))
        except json.JSONDecodeError:
            continue
    for match in _STATE.finditer(html):
        try:
            found.append(json.loads(match.group(1)))
        except json.JSONDecodeError:
            continue
    return found


def _tables(html: str) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {"in_scope": [], "out_of_scope": []}
    headings = [(m.start(), strip_html(m.group(1))) for m in _HEADING.finditer(html)]
    for match in re.finditer(r"(?is)<table[^>]*>.*?</table>", html):
        position, table = match.start(), match.group(0)
        rows = _ROW.findall(table)
        if not rows:
            continue
        header = " ".join(strip_html(c) for c in _CELL.findall(rows[0])).lower()
        if not _SCOPE_HEADER.search(header):
            continue
        context = ""
        for heading_pos, heading_text in headings:
            if heading_pos < position:
                context = heading_text.lower()
            else:
                break
        excluded = bool(_EXCLUSION.search(header)) or bool(_EXCLUSION.search(context))
        for row in rows[1:]:
            cells = [strip_html(c) for c in _CELL.findall(row)]
            cells = [c for c in cells if c]
            if not cells or cells[0].lower() in _SKIP:
                continue
            if not _ASSET.match(cells[0].strip()):
                continue
            entry: dict[str, Any] = {"name": cells[0], "in_scope": not excluded}
            if len(cells) > 1:
                entry["category"] = cells[1]
            if len(cells) > 2:
                entry["instructions"] = cells[2]
            result["out_of_scope" if excluded else "in_scope"].append(entry)
    return result


def extract_public_intigriti(html: str) -> dict[str, Any]:
    """Best-effort public extraction. Returns {} when nothing is readable."""
    if not html or len(html) < 400:
        return {}

    out: dict[str, Any] = {}
    scope: dict[str, list[dict[str, Any]]] = {"in_scope": [], "out_of_scope": []}

    for payload in _payloads(html):
        for key in ("program", "programs", "assets", "scope", "in_scope", "out_of_scope"):
            for value in _walk(payload, {key}):
                if isinstance(value, dict) and key in {"program", "programs"}:
                    attributes = value.get("attributes")
                    attributes = attributes if isinstance(attributes, dict) else {}
                    for field in ("name", "handle", "description", "policy", "url", "safe_harbor"):
                        if field not in out and (attributes.get(field) or value.get(field)):
                            out[field] = attributes.get(field) or value.get(field)
                elif isinstance(value, list):
                    bucket = "out_of_scope" if key == "out_of_scope" else "in_scope"
                    for item in value:
                        if isinstance(item, str) and _ASSET.match(item.strip()):
                            scope[bucket].append(
                                {"name": item, "in_scope": bucket == "in_scope"}
                            )
                        elif isinstance(item, dict):
                            name = item.get("name") or item.get("identifier") or item.get("target")
                            if name and _ASSET.match(str(name).strip()):
                                scope[bucket].append(
                                    {
                                        "name": str(name).strip(),
                                        "category": item.get("category") or item.get("type"),
                                        "in_scope": item.get("in_scope", bucket == "in_scope"),
                                    }
                                )
        if out.get("name") and (scope["in_scope"] or scope["out_of_scope"]):
            break

    tables = _tables(html)
    for bucket, rows in tables.items():
        scope[bucket].extend(rows)

    if scope["in_scope"] or scope["out_of_scope"]:
        out["scope"] = scope

    if not out.get("name"):
        title = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
        if title:
            name = strip_html(title.group(1))
            out["name"] = re.split(r"\s*[|\-–—:]\s*", name)[0].strip() or name
    if not out.get("description"):
        text = strip_html(html)
        if len(text) > 400:
            out["description"] = text[:2000]

    if not out.get("name"):
        return {}
    return out
