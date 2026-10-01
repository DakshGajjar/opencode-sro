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

#: Every network tool the review rules on: the eight still blocked, plus the one
#: approved and shipped. A tool appearing in the doc but not here is a tool the
#: doc has decided something about and nobody is tracking.
#: Approved and shipped: the three tier-1 tools. Named explicitly rather than
#: derived, so shipping a fourth one is a one-line edit that says which.
SHIPPED_NETWORK_TOOLS = frozenset({"dns_resolve", "http_request", "tls_inspect"})

RULED_ON = set(NOT_IMPLEMENTED) | set(SHIPPED_NETWORK_TOOLS)

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
    for tool in sorted(RULED_ON):
        assert re.search(rf"`{re.escape(tool)}`", BODY), f"{tool} has no row in EGRESS.md"


def test_the_table_claims_nothing_extra() -> None:
    """A tool named in the doc must be on the list, or the doc is out of date in
    the direction that is most confusing to a reader."""
    rows = set(re.findall(r"^\| `([a-z_]+)` \|", BODY, re.M))
    assert rows == RULED_ON, {
        "in doc only": sorted(rows - RULED_ON),
        "undecided": sorted(RULED_ON - rows),
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
    assert seen == len(RULED_ON), f"only {seen} rows parsed"


def test_only_the_three_tier_one_tools_are_shipped() -> None:
    """Exactly the tier-1 set is live, and nothing from tier 2 upward.

    Written as an explicit list rather than a count so that shipping a fourth one
    is a one-line edit that says which one, rather than a number bump that says
    nothing. The failure is the point: it asks whether the doc was updated in the
    same commit as the handler.
    """
    assert set(NOT_IMPLEMENTED) == {
        "api_schema_fetch", "auth_session_test", "parameter_probe",
        "cloud_asset_query", "ad_query", "browser_navigate",
    }, sorted(NOT_IMPLEMENTED)
    assert not set(NOT_IMPLEMENTED) & set(SHIPPED_NETWORK_TOOLS)
    assert "all of tier 1 is shipped" in BODY.lower()


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


def test_the_doc_records_the_transport_and_the_one_approval() -> None:
    """Both halves stay written down: the transport exists, and exactly one tool
    was approved on the strength of a verdict written before the handler."""
    assert "sro/core/egress.py" in BODY
    assert re.search(r"Approved and shipped", BODY)
    assert re.search(r"precondition.{0,40}not the approval|not the approval", BODY)


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


def test_only_the_approved_network_tools_are_wired() -> None:
    """The assertion that makes the doc's approval list mean something: the code
    and the verdicts have to agree about which tools exist."""
    from sro.handlers import HANDLERS

    network = set(NOT_IMPLEMENTED) | set(SHIPPED_NETWORK_TOOLS)
    assert set(HANDLERS) & network == set(SHIPPED_NETWORK_TOOLS), sorted(
        set(HANDLERS) & network
    )


def test_dns_resolve_takes_its_resolver_from_the_operating_system() -> None:
    """A caller-supplied nameserver is the attack.

    It lets the target under test decide where a query asking about the target is
    sent. So the parameter must not exist, and the doc has to say why.
    """
    from sro.core.egress import system_nameservers

    import inspect

    signature = inspect.signature(system_nameservers)
    assert "nameserver" not in signature.parameters
    source = inspect.getsource(system_nameservers)
    assert "/etc/resolv.conf" in source or "resolv" in source
    assert re.search(r"[Nn]ever from a parameter|never from a parameter", BODY)


def test_follow_redirects_is_resolved_not_merely_deferred() -> None:
    """Recorded here as debt to be paid when the handler landed.

    Paid by deleting the parameter: the transport already refuses redirects, and a
    `Location` header meaning "the request stopped here" is the honest result. A
    parameter a caller can set and a handler silently ignores is worse than no
    parameter, because it reads as a request that was followed.
    """
    from sro.core.tools import CATALOG

    assert "follow_redirects" not in CATALOG["http_request"].parameters
    assert re.search(r"follow_redirects", BODY), (
        "the review must record that the decision was taken, and which way"
    )
    assert re.search(r"[Rr]esolved debt", BODY)


def test_tls_inspect_does_not_verify_and_says_so() -> None:
    """The unverified handshake is the feature, so it has to be documented.

    A verifying handshake reports nothing for expired or self-signed
    certificates, which are the cases the tool exists to find. Anyone reading the
    result needs to know nothing was trusted, or they will read a clean parse as a
    clean certificate.
    """
    assert re.search(r"CERT_NONE", BODY), "the review must record the unverified handshake"
    assert re.search(r"pinning is unaffected|pinning is unaffected", BODY)
    assert re.search(r"no chain is built|no signature is checked", BODY, re.I)


def test_http_request_is_get_and_head_only() -> None:
    from sro.core.tools import CATALOG

    assert CATALOG["http_request"].parameters["method"]["choices"] == ["GET", "HEAD"]
    assert "http_post_test" not in CATALOG["http_request"].actions
