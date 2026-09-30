"""Public HackerOne page extraction.

HackerOne renders program pages client-side but embeds the program payload in a
`__NEXT_DATA__` JSON island, so structured scope is readable without
credentials. This extractor targets that island and falls back to rendered
tables for older layouts.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..base import strip_html

__all__ = ["extract_public_hackerone"]

_NEXT_DATA = re.compile(
    r"<script[^>]+id=[\"']__NEXT_DATA__[\"'][^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE
)
_STATE = re.compile(
    r"(?:window\.)?(?:__INITIAL_STATE__|__PRELOADED_STATE__)\s*=\s*(\{.*?\})\s*[;<]", re.DOTALL
)
_ROW = re.compile(r"(?is)<tr[^>]*>(.*?)</tr>")
_CELL = re.compile(r"(?is)<t[dh][^>]*>(.*?)</t[dh]>")
_HEADING = re.compile(r"(?is)<h[1-4][^>]*>(.*?)</h[1-4]>")

_ASSET = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"
    r"|^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$"
    r"^https?://"
    r"|^arn:"
    r"|^(?:com|org|net|io|co)\.[A-Za-z0-9_.\-]+$",
    re.IGNORECASE,
)
_EXCLUSION = re.compile(r"(?i)out[-\s]of[-\s]?scope|excluded|not\s+eligible|disqualif|ineligible")
_SCOPE_HEADER = re.compile(
    r"(?i)target|asset|identifier|scope|domain|uri|endpoint|api|application|category|type"
)


def _walk(node: Any, wanted: set[str]):
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in wanted:
                yield value
            yield from _walk(value, wanted)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item, wanted)


def _json_payloads(html: str) -> list[Any]:
    payloads: list[Any] = []
    for match in _NEXT_DATA.finditer(html):
        try:
            payloads.append(json.loads(match.group(1)))
        except json.JSONDecodeError:
            continue
    for match in _STATE.finditer(html):
        try:
            payloads.append(json.loads(match.group(1)))
        except json.JSONDecodeError:
            continue
    return payloads


def _looks_like_asset(value: str) -> bool:
    text = (value or "").strip()
    return bool(text) and len(text) <= 512 and bool(_ASSET.match(text))


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
            if not cells or not _looks_like_asset(cells[0]):
                continue
            entry: dict[str, Any] = {"identifier": cells[0], "in_scope": not excluded}
            if len(cells) > 1:
                entry["attributes"] = {"type": cells[1]}
            if len(cells) > 2:
                entry["attributes"] = {**(entry.get("attributes") or {}), "instructions": cells[2]}
            result["out_of_scope" if excluded else "in_scope"].append(entry)
    return result


def extract_public_hackerone(html: str) -> dict[str, Any]:
    """Extract a program dictionary from a public HackerOne page."""
    if not html or len(html) < 200:
        return {}

    out: dict[str, Any] = {}
    scope: dict[str, list[dict[str, Any]]] = {"in_scope": [], "out_of_scope": []}

    for payload in _json_payloads(html):
        for key in ("program", "structured_scopes"):
            for value in _walk(payload, {key}):
                if not isinstance(value, dict):
                    continue
                if key == "program":
                    attributes = value.get("attributes")
                    attributes = attributes if isinstance(attributes, dict) else {}
                    for field in ("handle", "name", "url", "description", "policy", "safe_harbor", "disclosure_policy"):
                        if field not in out and attributes.get(field):
                            out[field] = attributes[field]
                    for field in ("handle", "name", "url", "description", "policy"):
                        if field not in out and value.get(field):
                            out[field] = value[field]
                else:
                    nodes = value.get("nodes") or value.get("edges") or value
                    if not isinstance(nodes, list):
                        continue
                    for node in nodes:
                        if not isinstance(node, dict):
                            continue
                        if "node" in node and isinstance(node["node"], dict):
                            node = node["node"]
                        attributes = node.get("attributes")
                        attributes = attributes if isinstance(attributes, dict) else {}
                        in_scope = attributes.get("in_scope")
                        bucket = "out_of_scope" if in_scope is False else "in_scope"
                        scope[bucket].append(node)
        if out.get("handle") and (scope["in_scope"] or scope["out_of_scope"]):
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
        out["description"] = strip_html(html)[:2000]
    if not out.get("policy"):
        out["policy"] = strip_html(html)[:4000]

    if not out.get("name") and not out.get("handle"):
        return {}
    return out
