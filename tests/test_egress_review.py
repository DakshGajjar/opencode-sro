"""The egress review is the gate on network capability, so it is checked too.

`NOT_IMPLEMENTED` is the list of things SRO cannot do. If that list and
`docs/EGRESS.md` disagree, one of them is lying to whoever reads it, and the
reader is usually a model deciding whether to go around the tool.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from sro.handlers import NOT_IMPLEMENTED  # noqa: E402

DOC = REPO / "docs" / "EGRESS.md"
BODY = DOC.read_text(encoding="utf-8")


def test_the_doc_ships_in_the_repo_and_the_tarball() -> None:
    assert DOC.exists()
    assert "docs/" in json.loads((REPO / "package.json").read_text(encoding="utf-8"))["files"]


def test_every_unimplemented_tool_has_a_verdict() -> None:
    """Nine tools are blocked. Each needs a row saying so, with a reason.

    A tool absent from the table is a tool nobody has looked at, which is
    indistinguishable from a tool nobody objected to.
    """
    for tool in sorted(NOT_IMPLEMENTED):
        assert re.search(rf"`{re.escape(tool)}`", BODY), f"{tool} has no row in EGRESS.md"


def test_the_table_claims_nothing_extra() -> None:
    """A tool named in the doc must be on the list, or the doc is out of date in
    the direction that is most confusing to a reader."""
    rows = set(re.findall(r"^\| `([a-z_]+)` \|", BODY, re.M))
    assert rows == set(NOT_IMPLEMENTED), {
        "in doc only": sorted(rows - set(NOT_IMPLEMENTED)),
        "in NOT_IMPLEMENTED only": sorted(set(NOT_IMPLEMENTED) - rows),
    }


def test_every_row_states_a_decision_and_a_tier() -> None:
    """A row without a decision is a note, and a note does not gate anything."""
    seen = 0
    for line in BODY.splitlines():
        if not re.match(r"^\| `[a-z_]+` \|", line):
            continue
        seen += 1
        cells = [c.strip() for c in line.strip("|").split("|")]
        assert len(cells) == 3, f"row is not tool/tier/decision: {line[:60]}"
        assert cells[2], f"{cells[0]} has an empty decision"
        assert re.search(r"Approve|Defer|Refer|Reject", cells[2]), (
            f"{cells[0]} decision is not one of the four: {cells[2][:40]}"
        )
    assert seen == len(NOT_IMPLEMENTED), f"only {seen} rows parsed"


def test_nothing_is_approved_yet() -> None:
    """Today the honest answer is that no network tool has been reviewed.

    This is what makes that a fact rather than a claim: the test fails the day
    the first tool ships, and the failure asks whether the doc changed in the
    same commit.
    """
    assert len(NOT_IMPLEMENTED) == 9, sorted(NOT_IMPLEMENTED)
    assert "nothing is approved" in BODY.lower()


def test_the_doc_names_the_bypass_that_already_happened() -> None:
    """A design document that omits the failure it was written because of is a
    document that will let it happen again."""
    for term in ("url_target_mismatch", "admin.acme.test", "169.254.169.254"):
        assert term in BODY, f"EGRESS.md does not mention {term}"


def test_the_doc_requires_fencing_response_bodies() -> None:
    """Attacker-controlled text entering a trusted context is the cheapest attack
    against an agent and needs no vulnerability in the target."""
    assert re.search(r"fence", BODY, re.I)
    assert re.search(r"response bod", BODY, re.I)
    assert "untrusted.py" in BODY, "the doc should point at the existing fence"


def test_the_doc_states_the_resolve_and_pin_requirement() -> None:
    """The scope engine tests IP literals, not resolved addresses, so a handler
    that resolves after approval can be steered inward."""
    assert re.search(r"[Pp]in the|pin, then|pinned", BODY), "no address pinning requirement"
    assert re.search(r"IP literal", BODY), "the IP-literal gap is not named"


def test_the_doc_rules_out_vendored_and_handwritten_scanners() -> None:
    for term in ("sqlmap", "LinkFinder", "vendored"):
        assert term.lower() in BODY.lower(), f"EGRESS.md does not address {term}"
    assert re.search(r"never approved", BODY, re.I)


def test_the_doc_has_test_obligations_not_just_a_verdict() -> None:
    """Approval without a test obligation is how a tool ships unreviewed."""
    assert re.search(r"## Obligations", BODY)
    numbered = re.findall(r"^\d+\. ", BODY, re.M)
    assert len(numbered) >= 4, "obligations are too thin to gate on"


def test_the_two_scope_gaps_the_transport_must_close_are_real() -> None:
    """The doc's two load-bearing technical claims, checked against the code.

    If the scope engine starts resolving hostnames, or the broker stops deriving
    the policy target from the URL, this fails — and the doc's reasoning about
    what the transport must cover needs rewriting at the same time.
    """
    from sro.core.tools import _same_authority

    assert _same_authority("api.acme.test", "https://admin.acme.test/x") is False

    # the IP-literal gap: an address literal is denied, a name is not
    source = (REPO / "sro" / "core" / "scope.py").read_text(encoding="utf-8")
    literal_only = "if self.deny_private_networks and host and _is_ip_literal(host):"
    assert literal_only in source, (
        "scope.py no longer tests IP literals the way EGRESS.md describes; "
        "update the doc"
    )
    assert "getaddrinfo" not in source, (
        "scope.py now resolves names; the IP-literal gap in EGRESS.md is stale"
    )


def test_the_doc_records_that_the_transport_exists_and_approves_nothing() -> None:
    """The transport being present is the precondition for tier 1, not an
    approval. Both halves have to stay written down, because the tempting
    misreading is that a reviewed transport means reviewed tools."""
    assert "sro/core/egress.py" in BODY
    assert re.search(r"[Nn]o network tool is approved", BODY)
    assert re.search(r"precondition.{0,40}not an approval|not an approval", BODY)


def test_the_doc_names_the_gaps_the_transport_leaves() -> None:
    """A component that fixed everything would not be believed on this point."""
    assert re.search(r"[Nn]o rate limiting", BODY)
    assert "policy engine" in BODY
    assert re.search(r"max_redirects.{0,80}default is 0|default is 0", BODY)


def test_the_transport_module_exists_and_ships() -> None:
    import json

    assert (REPO / "sro" / "core" / "egress.py").exists()
    files = json.loads((REPO / "package.json").read_text(encoding="utf-8"))["files"]
    assert "sro/" in files, "the transport has to ship or no tool can reach it"


def test_no_network_tool_is_wired_to_the_transport_yet() -> None:
    """The one assertion that makes the previous two mean something."""
    import inspect

    from sro.core import egress

    for name in ("send", "_one", "_redirect_target"):
        assert callable(getattr(egress.Transport, name, None))

    from sro.handlers import HANDLERS

    network = {
        "http_request", "dns_resolve", "tls_inspect", "api_schema_fetch",
        "auth_session_test", "parameter_probe", "browser_navigate",
        "cloud_asset_query", "ad_query",
    }
    assert not HANDLERS.keys() & network

    # and no handler imports the transport. Grepping for the word would match the
    # module docstring and the NOT_IMPLEMENTED reasons, so this looks at imports.
    import ast

    for handler in (REPO / "sro" / "handlers").glob("*.py"):
        tree = ast.parse(handler.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not any("egress" in name for name in imported), (
            f"{handler.name} imports the transport; a handler must be a caller, not a peer"
        )
