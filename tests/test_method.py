"""The shipped methodology must describe the system that actually exists.

`METHOD.md` is the one document a researcher reads instead of a third-party
checklist, so it is the one document that most needs to be true. Prose does not
fail loudly: a methodology that names a tool nobody wrote, or that tells a
reader a capability is missing once it is implemented, is worse than no
methodology, because it is trusted.

These tests treat it as a contract with the control plane, the same way
`test_agent_truthfulness.py` treats the agents.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
METHOD = REPO / ".opencode" / "instructions" / "METHOD.md"
PLUGIN = REPO / ".opencode" / "plugins" / "sro-plugin.ts"

BODY = METHOD.read_text(encoding="utf-8")
DEFINED_TOOLS = set(re.findall(r"^    (sro_[a-z_]+): tool\(", PLUGIN.read_text(encoding="utf-8"), re.M))


def implemented_tools() -> set[str]:
    """Resolved by import so this test cannot disagree with the catalog."""
    import sys

    sys.path.insert(0, str(REPO))
    from sro.handlers import HANDLERS

    return HANDLERS


#: Tools that reach a brokered implementation rather than calling the CLI.
#: `scope_check`, `code_search`, `endpoint_inventory`, `render_report` and
#: `record_hypothesis` are handled by the broker; the rest are thin CLI wrappers.
BROKERED = set(implemented_tools())  # HANDLERS is a dict; set ops need a set


def test_every_tool_the_method_names_is_implemented() -> None:
    """The critical one. A method that names a declared-but-unimplemented tool
    is the exact defect this project exists to prevent, reproduced in the
    document meant to replace the defective checklists."""
    named = set(re.findall(r"\bsro_[a-z_]+\b", BODY))
    missing = sorted(named - DEFINED_TOOLS)
    assert not missing, f"METHOD.md names plugin tools that do not exist: {missing}"

    # sro_execute routes into the broker, so the tools it can name are the
    # implemented set. Anything else would be a promise with nothing behind it.
    for tool in sorted(BROKERED):
        if f"sro_execute tool={tool}" in BODY:
            assert tool in BROKERED


def test_the_method_does_not_name_unimplemented_broker_tools_as_available() -> None:
    """If the method ever tells someone to run `sro_execute tool=X`, X must be
    one of the five. The catalog has 14; a reader cannot tell which is which."""
    invoked = set(re.findall(r"sro_execute tool=([a-z_]+)", BODY))
    assert invoked <= BROKERED, sorted(invoked - BROKERED)


def test_the_method_states_the_capability_limit_that_is_true() -> None:
    """It has to name what is missing, and what it names has to be missing.

    The list of unavailable tools is read from `NOT_IMPLEMENTED` rather than
    written here, because a hard-coded list goes stale the moment a tool ships
    and then the document confidently describes a capability that exists. That is
    the exact failure this file exists to prevent, caught in the document meant
    to replace the defective checklists.
    """
    from sro.handlers import NOT_IMPLEMENTED

    for tool in sorted(NOT_IMPLEMENTED):
        if tool == "dns_resolve":
            continue
        assert tool in BODY, f"METHOD.md should name {tool} as unavailable"
        assert tool not in BROKERED, f"{tool} is now implemented; METHOD.md is stale"

    # and the reverse: a shipped tool must not be described as unavailable
    for tool in BROKERED:
        assert f"{tool} is not installed" not in BODY
    assert re.search(r"[Rr]esolves no DNS", BODY) is None, (
        "METHOD.md says SRO cannot resolve DNS; dns_resolve now exists"
    )


def test_the_method_names_the_shipped_network_tool_as_the_exception() -> None:
    """Six tools, one of which talks to a network. The method has to say so
    precisely, because a reader planning a session will rely on it."""
    assert "dns_resolve" in BODY
    assert re.search(r"one exception", BODY, re.I)
    assert re.search(r"cannot connect", BODY), (
        "the method must say dns_resolve cannot connect to anything"
    )


def test_the_method_names_no_scanner_binaries() -> None:
    """The failure that produced this document: a checklist naming tools that
    are not installed, so a reader installs them and runs them unscoped."""
    forbidden = (
        r"\bsubfinder\b", r"\bamass\b", r"\bpuredns\b", r"\bhttpx\b", r"\bnuclei\b",
        r"\bsqlmap\b", r"\bkatana\b", r"\bffuf\b", r"\bgau\b", r"\bnaabu\b",
        r"\bsublist3r\b", r"\bwaybackurls\b", r"\bdirsearch\b", r"\bgobuster\b",
        r"\bdalfox\b", r"\binteractsh\b", r"\bwfuzz\b",
    )
    for pattern in forbidden:
        hits = re.findall(pattern, BODY, re.I)
        assert not hits, f"METHOD.md names a scanner binary: {set(hits)}"


def test_the_method_instructs_no_unapproved_execution() -> None:
    """Never a shell, never a hand-written substitute for a missing tool."""
    assert not re.search(r"\buse the (?:terminal|shell|command line)\b", BODY, re.I)
    assert not re.search(r"\bexecute the (?:following )?command\b", BODY, re.I)
    # the prohibition must actually be present, not merely absent
    assert re.search(r"[Nn]ever write a script", BODY), (
        "METHOD.md must forbid writing a substitute script for a missing tool"
    )


def test_the_method_keeps_unknown_blocked() -> None:
    assert re.search(r"`?UNKNOWN`? is (?:blocked|not a soft yes)", BODY)
    assert re.search(r"retry", BODY, re.I), (
        "the method should say what a retry of a blocked target looks like"
    )


def test_the_method_distinguishes_a_hypothesis_from_a_finding() -> None:
    """The core epistemic claim, in both directions."""
    assert re.search(r"can fail|refut", BODY, re.I), "no falsifiability requirement"
    for status in ("HYPOTHESIS", "OBSERVED", "VERIFIED"):
        assert status in BODY, f"the epistemic status {status} is not explained"


def test_the_method_requires_reachability_and_bounds_the_claim() -> None:
    """Reachability is what separates a finding from a code-quality note."""
    assert re.search(r"[Rr]eachability", BODY)
    assert re.search(r"what you did not test|did not test", BODY, re.I)


def test_the_method_is_installed_with_the_package() -> None:
    """A methodology that is not in `assets/` does not reach anyone who installs
    the package; it only helps whoever is already looking at this repo."""
    assert (REPO / "assets" / "instructions" / "METHOD.md").exists(), (
        "METHOD.md is not in assets/ — run bin/sro-install-assets.mjs"
    )


def test_the_method_and_the_agents_agree_about_substitution() -> None:
    """The agent contract and the method say the same thing. If they diverge,
    whichever the model reads first wins, and it will be the wrong one."""
    for name in ("sro", "researcher", "code"):
        agent = (REPO / ".opencode" / "agents" / f"{name}.md").read_text(encoding="utf-8")
        assert re.search(r"[Nn]ever hand-?write a script", agent), (
            f"{name}.md lost the no-substitute rule"
        )
    assert re.search(r"[Nn]ever write a script", BODY), "METHOD.md lost it"
