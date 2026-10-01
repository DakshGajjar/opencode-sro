"""Agents must not be told to do things they structurally cannot do.

An agent file is prose, and prose does not fail loudly. If it tells a model to
run a scanner while the permission block denies `bash`, the model either fails
silently or, worse, works around the guard — and a guard that gets worked
around is worse than no guard, because it is no longer the boundary.

These tests treat agent instructions as a contract with the tool surface.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
AGENTS = REPO / ".opencode" / "agents"
PLUGIN = REPO / ".opencode" / "plugins" / "sro-plugin.ts"

AGENT_NAMES = (
    "sro", "researcher", "recon", "web", "api",
    "ad", "cloud", "code", "verifier", "reporter",
)

#: Actions that require something an SRO security agent does not have.
FORBIDDEN_IMPERATIVES = (
    r"\brun\s+(?:the\s+)?(?:subfinder|amass|httpx|nuclei|sqlmap|gau|sublist3r|naabu|katana|waybackurls|ffuf|dirsearch|gobuster|dalfox|interactsh-client)\b",
    r"\buse\s+the\s+(?:terminal|shell|command\s+line)\b",
    r"\bexecute\s+(?:the\s+)?(?:following\s+)?(?:command|shell|binary)\b",
    r"\bcertificate\s+transparency\b",
    r"\bcrt\.sh\b",
    r"\bvirustotal\b",
    r"\bwayback\b",
)


NEGATION = re.compile(
    r"(?:cannot|can'?t|not\s+allowed|do\s+not|don'?t|never|no\s+shell|refuse|forbidden|prohibited)",
    re.I,
)
#: A sentence terminator between a negation and the match means the negation
#: applies to something else. A period inside a token like "crt.sh" does not.
SENTENCE_BREAK = re.compile(r"[!?;]|\.\s|\.$|\n\s*\n")


def imperative_matches(body: str, pattern: str) -> list[str]:
    """Matches of `pattern` that are instructions rather than prohibitions.

    "You cannot run subfinder" is the rule working. "Run subfinder" is the bug.
    Matching both would make it impossible to write the prohibition down, so a
    hit is only a violation when no negation governs it within the same
    sentence.
    """
    found = []
    for match in re.finditer(pattern, body, re.I):
        prefix = body[max(0, match.start() - 160) : match.start()]
        governing = None
        for negation in NEGATION.finditer(prefix):
            if not SENTENCE_BREAK.search(prefix[negation.end() :]):
                governing = negation
        if governing is None:
            found.append(" ".join(body[match.start() - 45 : match.end() + 45].split()))
    return found


def _frontmatter(text: str) -> str:
    parts = text.split("---")
    return parts[1] if len(parts) > 2 else ""


def _defined_tools() -> set[str]:
    return set(re.findall(r"^    (sro_[a-z_]+): tool\(", PLUGIN.read_text(encoding="utf-8"), re.M))


@pytest.mark.parametrize("name", AGENT_NAMES)
def test_every_referenced_sro_tool_actually_exists(name: str) -> None:
    """A model that is told to call a tool which does not exist burns a turn,
    and worse, learns that the tool surface is unreliable."""
    defined = _defined_tools()
    referenced = set(re.findall(r"\bsro_[a-z_]+\b", (AGENTS / f"{name}.md").read_text(encoding="utf-8")))
    missing = sorted(referenced - defined)
    assert not missing, f"{name}.md references tools that do not exist: {missing}"


@pytest.mark.parametrize("name", AGENT_NAMES)
def test_no_agent_is_instructed_to_use_a_denied_capability(name: str) -> None:
    """No security agent may be told to use bash, webfetch, or a scanner binary.

    Every SRO agent denies bash and webfetch. An instruction that assumes them
    is a contradiction, and the contradiction is what produces a model quietly
    reaching for something else.
    """
    text = (AGENTS / f"{name}.md").read_text(encoding="utf-8")
    frontmatter = _frontmatter(text)
    body = text.split("---", 2)[-1]  # past the frontmatter

    if re.search(r"^\s*bash:\s*deny\s*$", frontmatter, re.M):
        for pattern in FORBIDDEN_IMPERATIVES:
            hits = imperative_matches(body, pattern)
            assert not hits, f"{name}.md instructs a denied capability: {hits}"

    if re.search(r"^\s*webfetch:\s*deny\s*$", frontmatter, re.M):
        for pattern in (r"\bfetch\s+(?:the\s+)?\w+\s+page\b", r"\bbrowse\s+to\b", r"\bvisit\s+https?://"):
            hits = imperative_matches(body, pattern)
            assert not hits, f"{name}.md instructs a denied capability: {hits}"


@pytest.mark.parametrize("name", AGENT_NAMES)
def test_agents_that_deny_everything_say_so(name: str) -> None:
    """An agent with no shell and no fetch has to tell the model that.

    Otherwise the model infers the capability from the task description
    instead of from the permission block, which is the failure being guarded
    against.
    """
    text = (AGENTS / f"{name}.md").read_text(encoding="utf-8")
    frontmatter = _frontmatter(text)
    denies_bash = bool(re.search(r"^\s*bash:\s*deny\s*$", frontmatter, re.M))
    denies_fetch = bool(re.search(r"^\s*webfetch:\s*deny\s*$", frontmatter, re.M))
    if denies_bash and denies_fetch:
        lowered = text.lower()
        assert (
            "no shell" in lowered
            or "do not have" in lowered
            or "do not tell the researcher" in lowered
            or "cannot do" in lowered
            or "do not run" in lowered
        ), f"{name}.md denies bash and webfetch but never tells the model what that means"


def test_policy_describe_separates_permitted_from_available() -> None:
    """The 8 actions no ToolSpec claims must not be advertised as available.

    The import-time check in tools.py only catches a spec declaring an action
    the engine will not permit. It cannot see an action nobody declares, so
    the surface has to be honest at the point the model reads it.
    """
    import sys

    sys.path.insert(0, str(REPO))
    from sro.core.config import Config
    from sro.core.engagement import Engagement
    from sro.core.policy import PolicyEngine
    from sro.core.scope import ScopeEngine

    engagement = Engagement(provider="bugcrowd", program_name="P")
    engine = PolicyEngine(
        Config(root=REPO),
        ScopeEngine.from_engagement(engagement, active=False),
        engagement,
        False,
    )
    described = engine.describe()
    for capability, available in described["available_actions"].items():
        assert set(available) <= set(described["permitted_actions"][capability])
    assert described["unimplemented_actions"], "should name at least one permitted-but-absent action"


def test_catalog_marks_whether_a_tool_is_implemented() -> None:
    import sys

    sys.path.insert(0, str(REPO))
    from sro.core.tools import catalog

    rows = catalog()
    assert "implemented" not in rows[0], "the bare catalog is for internal use"
    flagged = catalog(implemented=set())
    assert all(row["implemented"] is False for row in flagged)
    partial = catalog(implemented={"scope_check"})
    by_name = {row["name"]: row["implemented"] for row in partial}
    assert by_name["scope_check"] is True
    assert by_name["http_request"] is False
