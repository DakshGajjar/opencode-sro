"""Small shared helpers. No third-party dependencies by design.

SRO must be importable inside OpenCode's runtime and inside a bare Python
environment on a research laptop. Standard library only.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

_ISO = "%Y-%m-%dT%H:%M:%SZ"


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def utcnow_iso() -> str:
    return utcnow().strftime(_ISO)


def parse_iso(value: str | None) -> _dt.datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


def stable_id(prefix: str, *parts: str) -> str:
    """Deterministic id derived from content.

    Deterministic ids keep evidence records reproducible across runs, which
    matters when a report has to point at an artifact that was collected
    weeks earlier.
    """
    digest = hashlib.sha256("\x1f".join(p or "" for p in parts).encode("utf-8"))
    return f"{prefix}_{digest.hexdigest()[:16]}"


def slugify(value: str, max_len: int = 60) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", (value or "").strip().lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return (slug[:max_len].strip("-")) or "engagement"


def read_json(path: str | os.PathLike[str]) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str | os.PathLike[str], data: Any) -> Path:
    """Atomic write so an interrupted run never leaves a half-written manifest."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False, default=str)
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return target


def append_jsonl(path: str | os.PathLike[str], record: Any) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, default=str)
    with open(target, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    return target


def read_jsonl(path: str | os.PathLike[str]) -> list[Any]:
    target = Path(path)
    if not target.exists():
        return []
    records: list[Any] = []
    with open(target, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def truncate(value: Any, limit: int) -> Any:
    """Bound stored evidence so a large response cannot bloat the store."""
    if isinstance(value, str):
        if len(value) <= limit:
            return value
        return value[:limit] + f"\n...[truncated {len(value) - limit} chars]"
    if isinstance(value, dict):
        return {k: truncate(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [truncate(v, limit) for v in value[:200]]
    return value


def redact(value: str, secrets: list[str] | None = None) -> str:
    """Best-effort secret redaction before anything leaves the machine."""
    if not value:
        return value
    text = value
    for secret in secrets or []:
        if secret and len(secret) >= 8:
            text = text.replace(secret, "[REDACTED]")
    patterns = [
        (r"(?i)(authorization\s*:\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._\-+/=]{8,}", r"\1[REDACTED]"),
        (r"(?i)((?:api[_-]?key|apikey|secret|password|passwd|token|client_secret)\s*[=:]\s*)\S{6,}", r"\1[REDACTED]"),
        (r"\beyJ[A-Za-z0-9._\-]{10,}", "[REDACTED_JWT]"),
        (r"(?i)\b[A-Za-z0-9._%+\-]+:[^\s@]{4,}@[A-Za-z0-9.\-]+\b", "[REDACTED_URL_CREDS]"),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text
