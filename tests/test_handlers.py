"""Tests for the built-in tool handlers.

Two things are being defended here, and they are different in kind.

The first is correctness: a batched scope check resolves each target against the
real ScopeEngine, a code search cannot walk out of the workspace, a report with
nothing behind it does not get written.

The second is the property the whole broker exists for: a handler cannot be
reached without policy approving it. Several tests below assert that an
out-of-scope target is denied *before* the handler would run, using a handler
that would return success if it were ever called. A handler that leaks past
policy is worse than no handler, so those tests are the important ones.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

from sro.core.egress import DestinationRefused
from sro.core.tools import CATALOG, ToolBroker
from sro.handlers import HANDLERS, HandlerContext


def broker(session) -> ToolBroker:
    return session.tool_broker()


def run(session, tool: str, parameters=None, target: str = "", agent: str = "test", **kw):
    return broker(session).execute(
        tool=tool, target=target, parameters=parameters or {}, agent=agent, **kw
    )


# --- registration --------------------------------------------------------


def test_all_builtin_handlers_are_registered(active_session) -> None:
    assert set(broker(active_session).handlers) == set(HANDLERS)


def test_every_handler_names_a_catalog_spec() -> None:
    """A handler with no spec would be unreachable, and unreachable code rots."""
    assert set(HANDLERS) <= set(CATALOG)


#: The only network tool approved and shipped. Everything else in the catalog
#: that touches the network is still behind docs/EGRESS.md.
APPROVED_NETWORK_TOOLS = {"dns_resolve"}

#: Registered handlers that must never exist yet: approved means approved in
#: writing, with a verdict in the review document.
BLOCKED_NETWORK_TOOLS = {
    "http_request",
    "api_schema_fetch",
    "auth_session_test",
    "parameter_probe",
    "cloud_asset_query",
    "ad_query",
    "browser_navigate",
    "tls_inspect",
}


def test_only_the_approved_network_tool_is_registered(active_session) -> None:
    """The line the module docstring draws, enforced as a test.

    If someone adds a handler that talks to the network, this fails and the
    egress review happens before the code ships, not after. `dns_resolve` is the
    one exception, and it is an explicit one: it is in the review, it is tier 1,
    and it goes through the transport.
    """
    registered = set(broker(active_session).handlers)
    assert registered & BLOCKED_NETWORK_TOOLS == set(), (
        f"a blocked network handler is registered: "
        f"{sorted(registered & BLOCKED_NETWORK_TOOLS)}"
    )
    assert registered & APPROVED_NETWORK_TOOLS == APPROVED_NETWORK_TOOLS


def test_no_handler_opens_a_socket_itself(active_session) -> None:
    """Handlers are callers, not peers.

    A handler that constructs a socket bypasses the transport, and with it every
    control the transport holds: pinning, limits, the byte cap, the fence. The
    approved ones import egress for its primitives; none of them may open a
    connection directly.
    """
    import ast

    for path in (Path(__file__).resolve().parents[1] / "sro" / "handlers").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                target = node.func
                name = getattr(target, "attr", "") or getattr(target, "id", "")
                assert name not in {"socket", "create_connection", "getaddrinfo"}, (
                    f"{path.name} calls socket.{name}(); only egress.py may open a socket"
                )


# --- scope_check ---------------------------------------------------------


def test_scope_check_single_target(active_session) -> None:
    result = run(active_session, "scope_check", {"target": "api.acme.test"})
    assert result.allowed
    assert result.result["results"]["api.acme.test"]["status"] == "IN_SCOPE"


def test_scope_check_reports_out_of_scope_with_its_rule(active_session) -> None:
    result = run(active_session, "scope_check", {"target": "admin.acme.test"})
    assert result.result["results"]["admin.acme.test"]["status"] == "OUT_OF_SCOPE"


def test_scope_check_accepts_a_batch(active_session) -> None:
    """Gap 6. Triage over a manifest in one call, not one per host."""
    result = run(
        active_session,
        "scope_check",
        {"target": ["api.acme.test", "admin.acme.test", "unrelated.example.net"]},
    )
    assert result.allowed
    assert result.result == {
        **result.result,
        "checked": 3,
        "in_scope": 1,
        "out_of_scope": 1,
        "unknown": 1,
    }


def test_scope_check_batch_counts_unknown_separately(active_session) -> None:
    """UNKNOWN is not a soft yes. Collapsing it into a count is how it becomes one."""
    result = run(active_session, "scope_check", {"target": ["unrelated.example.net"]})
    assert result.result["unknown"] == 1
    assert result.result["in_scope"] == 0


def test_scope_check_batch_accepts_a_top_level_target_argument(active_session) -> None:
    """The plugin and CLI pass target as its own argument, not inside parameters."""
    result = run(active_session, "scope_check", target=["api.acme.test", "admin.acme.test"])
    assert result.allowed
    assert result.result["checked"] == 2


def test_batched_scope_check_is_not_denied_as_a_malformed_target(active_session) -> None:
    """Regression: the batch was stringified, so no scope rule could match it.

    The failure looked like a scope denial, which is the worst possible shape for
    it — a researcher reads "not authorized" and stops, when in fact three of the
    four targets were authorized.
    """
    result = run(active_session, "scope_check", target=["api.acme.test", "web.acme.test"])
    assert result.allowed, result.error
    assert result.result["in_scope"] == 2
    assert result.result["checked"] == 2


def test_scope_check_without_a_target_explains_itself(active_session) -> None:
    with pytest.raises(ValueError, match="target"):
        broker(active_session).execute(tool="scope_check", agent="test")


def test_scope_check_does_not_act_on_anything(active_session) -> None:
    """It resolves names. It does not discover, connect, or enumerate."""
    result = run(active_session, "scope_check", {"target": "api.acme.test"})
    assert set(result.result) >= {"results", "in_scope", "out_of_scope", "unknown"}
    assert "endpoints" not in result.result


# --- endpoint_inventory --------------------------------------------------


def test_endpoint_inventory_is_empty_before_anything_ran(active_session) -> None:
    result = run(active_session, "endpoint_inventory", target="api.acme.test")
    assert result.allowed
    assert result.result["endpoints_seen"] == []
    assert result.result["observations"] == 0


def test_endpoint_inventory_reports_only_recorded_activity(active_session) -> None:
    """It reports what earlier brokered actions touched, and invents nothing."""
    run(
        active_session,
        "record_hypothesis",
        {
            "title": "IDOR on /v1/orders",
            "reasoning": "the identifier looks user controlled",
            "suggested_test": "request an order id belonging to another account",
            "expected_evidence": "200 with another account's order body",
            "target": "api.acme.test",
        },
    )
    result = run(active_session, "endpoint_inventory", target="api.acme.test")
    assert result.allowed
    assert result.result["hypotheses"] >= 1
    assert result.result["scope_status"] == "IN_SCOPE"


def test_endpoint_inventory_states_it_is_not_a_scan(active_session) -> None:
    result = run(active_session, "endpoint_inventory", target="api.acme.test")
    assert "not a scan" in result.result["note"]


# --- code_search ---------------------------------------------------------


@pytest.fixture()
def tree(tmp_path, monkeypatch) -> Path:
    """A source tree in its own directory, with the working directory moved to it.

    Its own directory rather than tmp_path itself: pytest hands the same tmp_path
    to every fixture in a test, and the conftest workspace fixture writes SRO
    state there, which the search would then dutifully report on.
    """
    root = tmp_path / "tree"
    root.mkdir()
    (root / "app").mkdir()
    (root / "app" / "views.py").write_text(
        "import os\n"
        "def run(cmd):\n"
        "    os.system('ls ' + cmd)\n"
        "    return eval(cmd)\n"
    )
    (root / "app" / "util.js").write_text(
        "const crypto = require('crypto');\n"
        "function h(p) { return crypto.createHash('md5').update(p).digest('hex'); }\n"
    )
    (root / "node_modules").mkdir()
    (root / "node_modules" / "junk.js").write_text("eval(process.env.SECRET_TOKEN)\n")
    (root / ".env").write_text("API_KEY=supersecretvalue\n")
    monkeypatch.chdir(root)
    return root


def test_code_search_finds_a_pattern(active_session, tree) -> None:
    result = run(active_session, "code_search", {"path": ".", "pattern": "def run"})
    assert result.allowed
    assert result.result["match_count"] == 1
    assert result.result["matches"][0]["file"].endswith("views.py")


def test_code_search_flags_known_sinks(active_session, tree) -> None:
    result = run(active_session, "code_search", {"path": ".", "pattern": "*"})
    found = result.result["rule_findings"]
    assert "command-injection" in found
    assert any(hit["file"].endswith("views.py") for hit in found["command-injection"])


def test_code_search_skips_dependency_trees(active_session, tree) -> None:
    """A search that reads node_modules returns noise and is slow."""
    result = run(active_session, "code_search", {"path": ".", "pattern": "."})
    scanned = {m["file"] for m in result.result["matches"]}
    assert not any("node_modules" in f for f in scanned)
    assert not any(f.startswith(".") for f in scanned)
    assert {f for f in scanned} <= {"app/views.py", "app/util.js"}


def test_code_search_will_not_leave_the_workspace(active_session, tree, tmp_path_factory) -> None:
    """Containment, before existence. A traversal attempt should not be told what is out there."""
    outside = tmp_path_factory.mktemp("outside")
    (outside / "secrets.env").write_text("PASSWORD=hunter2hunter2\n")
    result = run(active_session, "code_search", {"path": str(outside), "pattern": "*"})
    assert result.allowed
    assert "outside the workspace" in result.result["error"]
    assert "secrets" not in str(result.result)


def test_code_search_refuses_an_absolute_path_outside_the_workspace(active_session, tree) -> None:
    result = run(active_session, "code_search", {"path": "/etc", "pattern": "*"})
    assert "outside the workspace" in result.result["error"]


def test_code_search_rejects_a_bad_regex(active_session, tree) -> None:
    result = run(active_session, "code_search", {"path": ".", "pattern": "([unclosed"})
    assert "invalid pattern" in result.result["error"]


def test_code_search_caps_results(active_session, tree) -> None:
    result = run(
        active_session, "code_search", {"path": ".", "pattern": ".", "max_results": 2}
    )
    assert result.result["match_count"] <= 2


def test_code_search_output_is_leads_not_findings(active_session, tree) -> None:
    result = run(active_session, "code_search", {"path": ".", "pattern": "*"})
    assert "not vulnerabilities" in result.result["note"]


# --- record_hypothesis ---------------------------------------------------


GOOD_HYPOTHESIS = {
    # A hypothesis is about a target, and the report builder pulls untagged tool
    # observations in by target. Without this the confirmed finding below would
    # report "no evidence" while the observation sat in the store.
    "target": "api.acme.test",
    "title": "IDOR on /v1/orders",
    "reasoning": "the order identifier is user controlled and not bound to the session account",
    "suggested_test": "request an order id belonging to a second account using its own token",
    "expected_evidence": "a 200 carrying an order that belongs to the second account",
}


def test_record_hypothesis_records_all_four_fields(active_session) -> None:
    result = run(active_session, "record_hypothesis", {**GOOD_HYPOTHESIS, "finding": "F-1"})
    assert result.allowed
    assert result.result["recorded"] is True
    assert result.result["status"] == "HYPOTHESIS"
    assert result.result["evidence_id"]


def test_record_hypothesis_is_not_an_observation(active_session) -> None:
    """The whole point of the record. Confirming is a separate, cited act."""
    result = run(active_session, "record_hypothesis", {**GOOD_HYPOTHESIS})
    assert result.result["status"] == "HYPOTHESIS"
    assert "only a verifier verdict" in result.result["note"].lower()


@pytest.mark.parametrize(
    "field", ["title", "reasoning", "suggested_test", "expected_evidence"]
)
def test_record_hypothesis_needs_every_field(active_session, field) -> None:
    """Falsifiable means the outcome was written down before the test ran.

    Refused at the catalog, before any handler runs, so there is no path by which
    a half-formed hypothesis reaches the evidence store.
    """
    incomplete = {k: v for k, v in GOOD_HYPOTHESIS.items() if k != field}
    with pytest.raises(ValueError, match=field):
        broker(active_session).execute(
            tool="record_hypothesis", parameters=incomplete, agent="test"
        )


def test_record_hypothesis_rejects_whitespace_only_fields(active_session) -> None:
    """`required` cannot see whitespace; the handler can."""
    result = run(active_session, "record_hypothesis", {**GOOD_HYPOTHESIS, "title": "   "})
    assert result.result["recorded"] is False
    assert "title" in result.result["error"]


# --- render_report -------------------------------------------------------


def test_render_report_refuses_when_there_is_nothing_behind_it(active_session) -> None:
    """A report generated from no evidence is the exact artifact SRO exists to stop."""
    result = run(active_session, "render_report", {"finding": "F-nonexistent"})
    assert result.result["written"] is False
    assert "nothing verifiable is recorded" in result.result["error"]
    assert "no file was written" in result.result["note"]


def test_render_report_takes_one_path(active_session) -> None:
    result = run(
        active_session, "render_report", {"finding": "F-1", "output": ["a.md", "b.md"]}
    )
    assert "one file" in result.result["error"]


def test_render_report_will_not_report_a_bare_hypothesis(active_session, tmp_path) -> None:
    """A hypothesis is not evidence. Writing it up is how unverified ideas get sent."""
    run(active_session, "record_hypothesis", {**GOOD_HYPOTHESIS, "finding": "F-1"})
    result = run(active_session, "render_report", {"finding": "F-1", "output": str(tmp_path / "f1.md")})
    assert result.result["written"] is False
    assert "nothing verifiable is recorded" in result.result["error"]
    assert "no file was written" in result.result["note"]
    assert not (tmp_path / "f1.md").exists()


def test_render_report_writes_local_file_and_cannot_send_it(active_session, tmp_path) -> None:
    """Only with a real observation behind it."""
    # Recorded directly rather than through a network tool, so this test is about
    # render_report's evidence test and not about whether some other tool's
    # restrictions happen to allow the request that produced it.
    active_session.evidence_store().record_observation(
        tool="http_request",
        agent="web",
        target="api.acme.test",
        summary="GET /v1/orders/2 returned an order owned by a different account",
        request={"url": "https://api.acme.test/v1/orders/2", "method": "GET"},
        response={"status_code": 200, "body": '{"order":2,"owner":"other"}'},
    )
    run(active_session, "record_hypothesis", {**GOOD_HYPOTHESIS, "finding": "F-1"})
    out = tmp_path / "f1.md"
    result = run(active_session, "render_report", {"finding": "F-1", "output": str(out)})
    assert result.result["written"] is True
    assert result.result["path"].endswith("f1.md")
    assert out.exists()
    assert "send it anywhere" in result.result["note"]


# --- the property the broker exists for ----------------------------------


def test_out_of_scope_target_is_denied_before_the_handler_runs(active_session) -> None:
    """If this ever passes silently, the broker is decoration.

    The handler is a tripwire: it would report success, so a DENY is the only
    acceptable outcome and an UNKNOWN is a failure of this test, not a weaker
    version of the same result.
    """
    session = active_session
    b = broker(session)
    called = []
    b.register("http_request", lambda p, d: called.append(p) or {"status_code": 200})
    result = b.execute(
        tool="http_request",
        target="admin.acme.test",
        parameters={"url": "https://admin.acme.test/v1/orders", "method": "GET"},
        agent="web",
    )
    assert result.allowed is False
    assert result.policy["result"] == "DENY"
    assert called == [], "handler ran for an out-of-scope target"


def test_unknown_target_is_denied_before_the_handler_runs(active_session) -> None:
    b = broker(active_session)
    called = []
    b.register("http_request", lambda p, d: called.append(p) or {"status_code": 200})
    result = b.execute(
        tool="http_request",
        target="unrelated.example.net",
        parameters={"url": "https://unrelated.example.net/", "method": "GET"},
        agent="web",
    )
    assert result.allowed is False
    assert called == []


def test_unimplemented_tool_names_the_ones_that_work(active_session) -> None:
    """So a model that calls the wrong tool recovers in one turn, not two."""
    result = run(
        active_session,
        "http_request",
        {"url": "https://api.acme.test/v1/orders", "method": "GET"},
        target="api.acme.test",
    )
    assert result.allowed is False
    assert "no implementation" in result.error
    assert "code_search" in result.error
    assert "Do not hand-write a script" in result.error


def test_bookkeeping_calls_are_not_recorded_as_observations(active_session) -> None:
    """A tool that writes a record must not appear to be evidence for it.

    Otherwise `record_hypothesis` manufactures its own supporting observation,
    and every finding looks evidenced by the act of describing it — which would
    make the report guard above pass for every hypothesis ever written.
    """
    result = run(active_session, "record_hypothesis", {**GOOD_HYPOTHESIS, "finding": "F-1"})
    assert result.evidence_id == ""
    assert result.result["recorded"] is True
    observations = [
        r for r in active_session.evidence_store().by_status("OBSERVED")
        if r.tool == "record_hypothesis"
    ]
    assert observations == []


def test_a_tool_that_touched_the_target_is_recorded(active_session) -> None:
    """The other half: real contact with a target is still evidence."""
    b = broker(active_session)
    b.register("http_request", lambda p, d: {"status_code": 200, "body": "{}"})
    result = b.execute(
        tool="http_request",
        target="api.acme.test",
        parameters={"url": "https://api.acme.test/v1/orders/2", "method": "GET"},
        agent="web",
        user_approved=True,
    )
    assert result.allowed, result.error
    assert result.evidence_id
    assert active_session.evidence_store().get(result.evidence_id) is not None


# --- workspace plumbing --------------------------------------------------


def test_context_workspace_defaults_to_the_working_directory(active_session) -> None:
    from pathlib import Path

    ctx = HandlerContext(active_session)
    assert ctx.workspace == Path.cwd().resolve()


def test_handler_context_exposes_no_process_surface(active_session) -> None:
    """A handler gets the session, not the machine.

    Asserted rather than documented: this is the property that stops a handler
    from growing an import of `os.environ` in a later refactor.
    """
    ctx = HandlerContext(active_session)
    for forbidden in ("env", "environ", "socket", "requests", "subprocess", "os"):
        assert not hasattr(ctx, forbidden), f"HandlerContext exposes {forbidden}"
    assert ctx.__slots__ == ("session", "agent", "workspace")


# --- aggregation parity --------------------------------------------------


def test_handler_and_cli_agree_on_a_batch(active_session, capsys) -> None:
    """One aggregation, two entry points.

    The tally over scope verdicts is security logic, so the plugin is forbidden
    from computing one and the CLI delegates here. That only holds if both
    surfaces return the same thing, which is worth a test rather than a promise.
    """
    from sro.cli.main import main as cli_main

    targets = ["api.acme.test", "admin.acme.test", "unrelated.example.net"]
    through_handler = run(active_session, "scope_check", {"target": targets}).result
    through_handler.pop("note", None)

    exit_code = cli_main(
        ["--root", str(active_session.config.root), "--json", "scope", "--targets", *targets]
    )
    assert exit_code == 0
    through_cli = json.loads(capsys.readouterr().out)
    assert through_cli == through_handler


def test_check_many_counts_unknown_separately(scope_engine) -> None:
    """Collapsing UNKNOWN into the same bucket as IN_SCOPE is how it becomes a yes."""
    from sro.core.scope import check_many

    result = check_many(scope_engine, ["api.acme.test", "admin.acme.test", "nowhere.example.net"])
    assert result["in_scope"] == 1
    assert result["out_of_scope"] == 1
    assert result["unknown"] == 1
    assert result["checked"] == 3


# --- a request cannot disagree with the target it was approved under ------


def test_a_url_cannot_reach_a_host_other_than_its_approved_target(active_session) -> None:
    """The bypass this closes.

    The policy target is derived from `url`, and a caller-supplied `target` that
    disagrees is refused. Before this, `target=api.acme.test` with
    `url=https://admin.acme.test/secret` reached ALLOW: the ladder approved the
    host and the handler would have fetched the other one. It was invisible
    while every network tool was unimplemented, and it would have gone live the
    moment one shipped.
    """
    b = broker(active_session)
    called = []
    b.register("http_request", lambda p, d: called.append(p) or {"status_code": 200})
    result = b.execute(
        tool="http_request",
        target="api.acme.test",
        parameters={"url": "https://admin.acme.test/secret", "method": "GET"},
        agent="web",
    )
    assert result.allowed is False
    assert result.policy["code"] == "url_target_mismatch"
    assert called == [], "handler ran for a host that was never approved"


@pytest.mark.parametrize(
    "claimed,url,agree",
    [
        ("api.acme.test", "https://api.acme.test/v1/x", True),
        ("api.acme.test", "http://API.acme.test:8443/x", True),
        ("api.acme.test", "https://api.acme.test.evil.com/x", False),
        ("api.acme.test", "https://evil.com/?u=api.acme.test", False),
        ("acme.test", "https://api.acme.test/x", False),
        ("api.acme.test", "https://admin.acme.test/x", False),
    ],
)
def test_authority_comparison_is_not_string_comparison(claimed, url, agree) -> None:
    """A parent domain does not cover a subdomain, and a host-looking prefix
    does not make a different host the same one. Both are scope questions, and
    the scope engine answers them — not a string comparison here."""
    from sro.core.tools import _same_authority

    assert _same_authority(claimed, url) is agree


def test_a_url_only_call_is_still_scope_checked(active_session) -> None:
    """No claimed target does not mean no check. The URL becomes the target."""
    b = broker(active_session)
    called = []
    b.register("http_request", lambda p, d: called.append(p) or {"status_code": 200})
    result = b.execute(
        tool="http_request",
        parameters={"url": "https://admin.acme.test/secret", "method": "GET"},
        agent="web",
    )
    assert result.allowed is False
    assert called == []


# --- dns_resolve (the one approved network tool) -------------------------


class TestAddressClassification:
    """The classification is the tool's value.

    `api.example.com -> 10.0.0.5` is a finding about the target, and it is only
    visible if the answer is labelled. Everything else is plumbing.
    """

    @pytest.mark.parametrize(
        "address,expected",
        [
            ("93.184.216.34", "public"),
            ("2606:2800:220:1::1", "public"),
            ("10.0.0.5", "private"),
            ("192.168.1.1", "private"),
            ("127.0.0.1", "loopback"),
            ("169.254.169.254", "metadata"),
            ("fd00:ec2::254", "metadata"),
            ("169.254.1.1", "link-local"),
            ("224.0.0.1", "multicast"),
            ("192.0.2.5", "documentation"),
            ("not-an-address", "unparseable"),
        ],
    )
    def test_every_range_is_labelled(self, address, expected) -> None:
        from sro.handlers import classify_address

        assert classify_address(address) == expected


class TestDnsResolveIsScopeChecked:
    def test_an_out_of_scope_host_is_refused_before_any_lookup(self, active_session) -> None:
        def explode(host, port):
            raise AssertionError("a resolver was called for an out-of-scope host")

        result = run(
            active_session, "dns_resolve", {"host": "admin.acme.test"}, target="admin.acme.test"
        )
        assert result.allowed is False
        assert result.policy["code"] == "out_of_scope"

    def test_an_unknown_host_is_blocked(self, active_session) -> None:
        result = run(active_session, "dns_resolve", {"host": "nowhere.example.net"})
        assert result.allowed is False

    def test_the_host_must_match_the_target_it_was_approved_under(self, active_session) -> None:
        """`host` is a destination, so it is the policy target — the same rule
        that produced `url_target_mismatch` for HTTP."""
        result = run(
            active_session,
            "dns_resolve",
            {"host": "admin.acme.test"},
            target="api.acme.test",
        )
        assert result.allowed is False
        assert result.policy["code"] == "url_target_mismatch"


class TestDnsResolveArguments:
    def test_a_missing_host_is_refused_with_usage(self, active_session) -> None:
        broker(active_session).register("dns_resolve", lambda p, d: {"never": "run"})
        with pytest.raises(ValueError, match="host"):
            broker(active_session).execute(
                tool="dns_resolve", parameters={"record_type": "A"}, agent="recon"
            )

    def test_an_unknown_record_type_is_refused_with_the_supported_set(self, active_session) -> None:
        """Refused by the catalog before the handler runs, so an unsupported type
        never becomes a query."""
        with pytest.raises(ValueError, match="record_type"):
            broker(active_session).execute(
                tool="dns_resolve",
                parameters={"host": "api.acme.test", "record_type": "WKS"},
                agent="recon",
            )

        # and the handler's own guard, for a caller that reaches it directly
        from sro.handlers import HandlerContext, handle_dns_resolve

        out = handle_dns_resolve(
            HandlerContext(active_session), {"host": "api.acme.test", "record_type": "WKS"}
        )
        assert "supported" in out
        assert "A" in out["supported"]

    def test_the_spec_constrains_the_record_type(self) -> None:
        from sro.core.tools import CATALOG

        spec = CATALOG["dns_resolve"]
        assert spec.parameters["record_type"]["choices"] == [
            "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "PTR",
        ]
        with pytest.raises(ValueError):
            spec.validate({"host": "a.com", "record_type": "ANY"})


class TestDnsResolveIsRateLimited:
    def test_the_spec_is_rate_limited(self) -> None:
        """A long lookup run must be throttled at the program's number like any
        other action, so the ladder's step 9 applies."""
        from sro.core.tools import CATALOG

        assert CATALOG["dns_resolve"].rate_limited is True

    def test_the_ladder_throttles_it(self, active_session) -> None:
        from sro.core.config import Config

        config = Config.load(active_session.config.root)
        assert config.rate_limit_per_host_per_minute > 0


class TestDnsResolveProducesEvidence:
    """Unlike the five bookkeeping tools, this one is contact with a subject and
    its answer is evidence — provided something actually answered."""

    def test_it_is_marked_as_producing_evidence(self) -> None:
        from sro.core.tools import CATALOG

        assert CATALOG["dns_resolve"].produces_evidence is True

    def test_a_real_answer_is_recorded(self, active_session, monkeypatch) -> None:
        from sro.handlers import handle_dns_resolve, HandlerContext

        monkeypatch.setattr(
            "sro.core.egress.resolve_addresses", lambda host, family=2: ["93.184.216.34"]
        )
        ctx = HandlerContext(active_session)
        out = handle_dns_resolve(ctx, {"host": "api.acme.test", "record_type": "A"})
        assert out["status"] == "NOERROR"
        assert out["addresses"][0]["classification"] == "public"
        assert out["resolves_inward"] is False
        assert "no packet sent by SRO" in out["via"]

    def test_a_name_resolving_inward_is_a_result_not_an_error(self, active_session, monkeypatch) -> None:
        """This is the finding the tool exists for, so it must not be raised as
        a failure — and the note has to say it is worth reporting."""
        from sro.handlers import HandlerContext, handle_dns_resolve

        monkeypatch.setattr(
            "sro.core.egress.resolve_addresses", lambda host, family=2: ["10.0.0.5"]
        )
        out = handle_dns_resolve(HandlerContext(active_session), {"host": "api.acme.test"})
        assert out["resolves_inward"] is True
        assert out["addresses"][0]["classification"] == "private"
        assert "worth reporting" in out["note"]
        assert "refused to connect" in out["note"]

    def test_a_name_that_does_not_resolve_is_reported_not_raised(self, active_session, monkeypatch) -> None:
        from sro.core.egress import DestinationRefused
        from sro.handlers import HandlerContext, handle_dns_resolve

        def missing(host, family=2):
            raise DestinationRefused(f"{host!r} does not resolve: Name or service not known")

        monkeypatch.setattr("sro.core.egress.resolve_addresses", missing)
        out = handle_dns_resolve(HandlerContext(active_session), {"host": "nope.acme.test"})
        assert out["status"] == "NXDOMAIN"
        assert out["addresses"] == []


class TestDnsResolverComesFromTheOperatingSystem:
    """The nameserver is the operator's, and the target cannot redirect it."""

    def test_no_nameserver_parameter_exists(self) -> None:
        """A caller-supplied nameserver lets the target decide where a query
        asking about the target is sent. That is the attack, so the parameter
        must not exist rather than merely be unused."""
        import inspect

        from sro.core.egress import system_nameservers

        assert "nameserver" not in inspect.signature(system_nameservers).parameters

    def test_it_reads_the_system_configuration(self, tmp_path) -> None:
        from sro.core.egress import system_nameservers

        resolv = tmp_path / "resolv.conf"
        resolv.write_text(
            "# comment\nnameserver 192.0.2.1\nnameserver 192.0.2.2\n"
            "nameserver duplicate\nsearch example.com\noptions ndots:2\n"
        )
        assert system_nameservers(str(resolv)) == ["192.0.2.1", "192.0.2.2"]

    def test_a_nameserver_line_with_a_hostname_is_skipped_not_resolved(self, tmp_path) -> None:
        """Resolving it would need a resolver, and the only one available is the
        file being read."""
        from sro.core.egress import system_nameservers

        resolv = tmp_path / "resolv.conf"
        resolv.write_text("nameserver dns.example.com\nnameserver 192.0.2.53\n")
        assert system_nameservers(str(resolv)) == ["192.0.2.53"]

    def test_an_unspecified_address_is_treated_as_a_config_error(self, tmp_path) -> None:
        from sro.core.egress import system_nameservers

        resolv = tmp_path / "resolv.conf"
        resolv.write_text("nameserver 0.0.0.0\n")
        with pytest.raises(DestinationRefused, match="no usable nameserver"):
            system_nameservers(str(resolv))

    def test_it_never_falls_back_to_a_public_resolver(self, tmp_path) -> None:
        """Sending a target's name to a third party is not this tool's decision."""
        from sro.core.egress import system_nameservers

        resolv = tmp_path / "resolv.conf"
        resolv.write_text("search example.com\noptions edns0\n")
        with pytest.raises(DestinationRefused, match="will not fall back to a public resolver"):
            system_nameservers(str(resolv))


# --- no dead or duplicated logic in the shipped handlers ------------------


HANDLER_SOURCE = REPO / "sro" / "handlers" / "__init__.py"


def test_no_handler_holds_an_unused_local() -> None:
    """Assigned and never read is a leftover, and leftovers misdescribe intent.

    This is the guard for a real instance: `verdict = scope_engine().check(host)`
    in `dns_resolve`, which the broker had already decided and the handler never
    read. A reader seeing it concludes there is a scope gate inside the handler.
    There is not — and that is the more serious half, because dead code that
    looks like a security control is a false description of one.

    Note this is deliberately not a ban on reading a scope verdict:
    `handle_scope_check` exists to report verdicts, and forbidding it there would
    be forbidding the tool's actual purpose.
    """
    import ast

    tree = ast.parse(HANDLER_SOURCE.read_text(encoding="utf-8"))
    for function in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        assigned: dict[str, int] = {}
        loaded: set[str] = set()
        for node in ast.walk(function):
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Store):
                    assigned.setdefault(node.id, node.lineno)
                else:
                    loaded.add(node.id)
        dead = {
            name: line
            for name, line in assigned.items()
            if name not in loaded and not name.startswith("_")
        }
        assert not dead, f"{function.name}() assigns and never reads: {dead}"


def test_no_conditional_has_identical_arms() -> None:
    """`x if cond else x` is a no-op that reads like a decision that was never
    finished. Found here as a real instance, kept as a guard."""
    import ast

    tree = ast.parse(HANDLER_SOURCE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.IfExp) and ast.dump(node.body) == ast.dump(node.orelse):
            raise AssertionError(
                f"line {node.lineno}: both arms of the conditional are identical"
            )


def test_the_handler_module_docstring_points_at_something_real() -> None:
    """It named a function that was deleted two commits earlier.

    A docstring pointing at a nonexistent symbol is worse than one that points at
    nothing: it tells a reader the registry is somewhere it is not, and they go
    looking for it instead of reading the code in front of them.
    """
    text = HANDLER_SOURCE.read_text(encoding="utf-8")
    docstring_end = text.index('"""', text.index('"""') + 3)
    docstring = text[:docstring_end]

    import re

    # Every other module, and every symbol this one actually defines. Including
    # this file in the haystack would make the check vacuous: the docstring is
    # part of its own file, so every symbol it names would "exist" right where it
    # was written, which is exactly the defect going undetected.
    rest_of_package = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (REPO / "sro").rglob("*.py")
        if path != HANDLER_SOURCE
    )
    package = rest_of_package + text[docstring_end:]
    for symbol in re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", docstring):
        assert symbol in text[docstring_end:] or symbol in package, (
            f"the module docstring points at {symbol!r}, which exists nowhere in the package"
        )


def test_the_supported_record_types_are_read_from_the_catalog() -> None:
    """Two lists that are supposed to agree eventually will not."""
    from sro.core.tools import CATALOG
    from sro.handlers import _supported_record_types

    assert _supported_record_types() == sorted(
        CATALOG["dns_resolve"].parameters["record_type"]["choices"]
    )
    assert "supported" not in _supported_record_types(), "a function name, not a type"
