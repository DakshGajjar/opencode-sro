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


def test_no_network_handler_is_registered(active_session) -> None:
    """The line the module docstring draws, enforced as a test.

    If someone adds a handler that talks to the network, this fails and the
    egress review happens before the code ships, not after.
    """
    registered = set(broker(active_session).handlers)
    network = {
        "dns_resolve",
        "http_request",
        "api_schema_fetch",
        "auth_session_test",
        "parameter_probe",
        "cloud_asset_query",
        "ad_query",
        "browser_navigate",
        "tls_inspect",
    }
    assert registered & network == set()


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
