"""Session state-machine tests, plus the OpenCode surface tests.

The state machine is the thing a researcher interacts with directly, so its
transitions are tested exhaustively: load stages but never activates, activation
requires confirmation, and deactivation revokes policy immediately.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from sro.core.errors import ConfigError, NoEngagementError, NotActivatedError
from sro.core.session import STATUS_ACTIVE, STATUS_EMPTY, STATUS_PENDING, Session

from .conftest import BUGCROWD_BRIEF

#: The standard-library modules SRO is allowed to import. Duplicated inline in
#: two assertions once already, which is how the two copies drifted apart.
STDLIB_ALLOWED = frozenset(
    {
        "__future__", "abc", "argparse", "ast", "base64", "binascii", "collections",
        "contextlib", "copy", "csv", "dataclasses", "datetime", "email", "enum",
        "fnmatch", "hashlib", "html", "http", "inspect", "io", "ipaddress", "itertools",
        "json", "operator", "os", "pathlib", "re", "shutil", "socket", "ssl",
        "stat", "string", "struct", "subprocess", "sys", "tempfile", "textwrap", "threading",
        "time", "types", "typing", "unicodedata", "urllib", "uuid", "warnings",
    }
)

REPO = Path(__file__).resolve().parents[1]
OPENCODE = REPO / ".opencode"

#: The roster the spec requires.
REQUIRED_AGENTS = (
    "sro", "researcher", "recon", "web", "api", "ad", "cloud", "code", "verifier", "reporter",
)
REQUIRED_INSTRUCTIONS = ("SRO.md", "SCOPE.md", "EVIDENCE.md", "SAFETY.md", "PROVIDERS.md")
REQUIRED_COMMANDS = (
    "engagement", "scope", "evidence", "findings", "model", "agent",
    "policy", "status", "review", "activate",
)
#: Agents that must not be able to run a shell command.
NO_SHELL_AGENTS = REQUIRED_AGENTS


# --- the state machine ----------------------------------------------------


def test_empty_session(config) -> None:
    session = Session(config)
    assert session.state == STATUS_EMPTY
    assert session.status()["engagement"] is None
    with pytest.raises(NoEngagementError):
        session.require_engagement()


def test_load_stages_but_never_activates(config, brief_file) -> None:
    session = Session(config)
    manifest = session.import_brief(str(brief_file), provider="bugcrowd")
    assert manifest.status == "pending_user_confirmation"
    assert session.state == STATUS_PENDING
    assert session.activated is False


def test_unconfirmed_manifest_cannot_be_used(config, brief_file) -> None:
    session = Session(config)
    session.import_brief(str(brief_file), provider="bugcrowd")
    with pytest.raises(NotActivatedError) as excinfo:
        session.require_active()
    assert "NOT active" in str(excinfo.value)
    # The scope engine agrees.
    assert session.scope_engine().check("api.acme.test").status == "UNKNOWN"
    assert session.policy_engine().evaluate(
        __import__("sro.core.policy", fromlist=["PolicyRequest"]).PolicyRequest(
            tool="http_request", action="http_get", target="api.acme.test", capability="WEB"
        )
    ).result == "DENY"


def test_activate_requires_explicit_confirmation(config, brief_file) -> None:
    session = Session(config)
    session.import_brief(str(brief_file), provider="bugcrowd")
    engagement = session.activate(actor="researcher")
    assert session.state == STATUS_ACTIVE
    assert session.activated is True
    assert session.manifest.status == "confirmed"
    assert session.manifest.confirmed_by == "researcher"
    assert engagement.program_name == "Acme Corp Security Program"


def test_activation_is_persisted_across_processes(config, brief_file) -> None:
    first = Session(config)
    first.import_brief(str(brief_file), provider="bugcrowd")
    first.activate()

    second = Session(config)
    assert second.state == STATUS_ACTIVE
    assert second.activated is True
    assert second.require_engagement().program_name == "Acme Corp Security Program"


def test_activation_refuses_an_empty_scope(config) -> None:
    from sro.core.engagement import CandidateManifest, Engagement

    session = Session(config)
    session.manifest = CandidateManifest(
        engagement=Engagement(provider="bugcrowd", program_name="Empty")
    )
    with pytest.raises(ConfigError) as excinfo:
        session.activate()
    assert "no scope entries were established" in str(excinfo.value)


def test_activation_force_is_explicit(config) -> None:
    from sro.core.engagement import CandidateManifest, Engagement

    session = Session(config)
    session.manifest = CandidateManifest(
        engagement=Engagement(provider="bugcrowd", program_name="Empty")
    )
    session.activate(force=True)
    assert session.activated is True


def test_deactivate_revokes_policy_immediately(active_session: Session) -> None:
    assert active_session.scope_engine().check("api.acme.test").status == "IN_SCOPE"
    active_session.deactivate()
    assert active_session.state == STATUS_PENDING
    assert active_session.scope_engine().check("api.acme.test").status == "UNKNOWN"
    decision = active_session.policy_engine().evaluate(
        __import__("sro.core.policy", fromlist=["PolicyRequest"]).PolicyRequest(
            tool="http_request", action="http_get", target="api.acme.test", capability="WEB"
        )
    )
    assert decision.code == "engagement_not_active"


def test_reload_reports_the_diff(config, brief_file) -> None:
    session = Session(config)
    session.import_brief(str(brief_file), provider="bugcrowd")

    changed = dict(BUGCROWD_BRIEF)
    changed["in_scope"] = list(BUGCROWD_BRIEF["in_scope"]) + [
        {"name": "new.acme.test", "category": "website"}
    ]
    path = config.root / "changed.json"
    path.write_text(json.dumps(changed), encoding="utf-8")

    manifest = session.import_brief(str(path), provider="bugcrowd")
    assert any("new.acme.test" in d for d in manifest.diff_from_previous)
    # A reload never carries activation over from the previous manifest.
    assert session.activated is False


def test_review_output_warns_that_nothing_is_active(active_session: Session) -> None:
    review = active_session.review()
    assert "SRO ENGAGEMENT REVIEW" in review
    assert "*.acme.test" in review
    assert "admin.acme.test" in review
    assert "NOT active" in review


def test_review_on_an_empty_session(config) -> None:
    assert "No engagement loaded" in Session(config).review()


def test_add_target_resolves_an_unknown(config, brief_file) -> None:
    session = Session(config)
    session.import_brief(str(brief_file), provider="bugcrowd")
    session.activate()
    assert session.scope_engine().check("late.other.test").status == "UNKNOWN"
    session.add_target("late.other.test", note="confirmed with the program")
    session.activate()
    assert session.scope_engine().check("late.other.test").status == "IN_SCOPE"


def test_adding_a_target_to_an_active_engagement_requires_reconfirmation(
    config, brief_file
) -> None:
    """Widening scope on a live engagement is a scope change, so it is re-confirmed."""
    session = Session(config)
    session.import_brief(str(brief_file), provider="bugcrowd")
    session.activate()
    assert session.state == STATUS_ACTIVE
    session.add_target("late.other.test")
    assert session.state == STATUS_PENDING
    assert session.manifest.confirmed_at == ""
    # And the widened scope is not usable until confirmed again.
    assert session.scope_engine().check("late.other.test").status == "UNKNOWN"
    session.activate()
    assert session.scope_engine().check("late.other.test").status == "IN_SCOPE"


def test_status_reports_the_full_surface(active_session: Session) -> None:
    status = active_session.status()
    assert status["status"] == STATUS_ACTIVE
    assert status["policy"] == "ACTIVE"
    assert status["external_model"] == "DISABLED"
    assert status["scope"] == 6
    assert status["exclusions"] == 3
    assert status["credentials_used"] is False


def test_audit_trail_records_the_transitions(config, brief_file) -> None:
    from sro.core.audit import (
        EVENT_ENGAGEMENT_ACTIVATED,
        EVENT_ENGAGEMENT_LOADED,
        AuditLog,
    )

    session = Session(config)
    session.import_brief(str(brief_file), provider="bugcrowd")
    session.activate()
    log = AuditLog(config.data_dir)
    assert log.count(EVENT_ENGAGEMENT_LOADED) == 1
    assert log.count(EVENT_ENGAGEMENT_ACTIVATED) == 1


def test_warnings_surface_incomplete_reads(config, tmp_path) -> None:
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps({"code": "bare", "name": "Bare"}), encoding="utf-8")
    session = Session(config)
    session.import_brief(str(bare), provider="bugcrowd")
    assert any("UNKNOWN" in w for w in session.warnings())


# --- the OpenCode surface -------------------------------------------------


@pytest.mark.parametrize("name", REQUIRED_AGENTS)
def test_agent_exists(name: str) -> None:
    path = OPENCODE / "agents" / f"{name}.md"
    assert path.exists(), f"missing agent {name}"
    assert path.read_text(encoding="utf-8").strip()


def test_agents_declare_the_permissions_that_back_the_instructions() -> None:
    """A security agent that can run a shell command contradicts SAFETY.md."""
    for name in NO_SHELL_AGENTS:
        text = (OPENCODE / "agents" / f"{name}.md").read_text(encoding="utf-8")
        frontmatter = text.split("---")[1]
        assert re.search(r"^\s*bash:\s*deny\s*$", frontmatter, re.M), f"{name} can run bash"
        assert re.search(r"^\s*mode:\s*(subagent|primary)\s*$", frontmatter, re.M), name


def test_no_agent_is_granted_a_subagent_dispatch_loop() -> None:
    """An agent that can spawn agents can be made to bypass a role boundary."""
    for name in REQUIRED_AGENTS:
        text = (OPENCODE / "agents" / f"{name}.md").read_text(encoding="utf-8")
        frontmatter = text.split("---")[1]
        task_block = re.search(r"^\s*task:\s*$", frontmatter, re.M)
        if not task_block:
            continue
        assert re.search(r'task:[\s\S]*?"\*":\s*"?deny"?', frontmatter), f"{name} can spawn any agent"


def test_researcher_cannot_dispatch_agents() -> None:
    """The researcher proposes; the verifier decides. Neither should fan out."""
    for name in ("researcher", "verifier"):
        frontmatter = (OPENCODE / "agents" / f"{name}.md").read_text(encoding="utf-8").split("---")[1]
        assert re.search(r'"\*":\s*"?deny"?', frontmatter), f"{name} can dispatch subagents"


def test_researcher_and_verifier_are_documented_as_separate() -> None:
    researcher = (OPENCODE / "agents" / "researcher.md").read_text(encoding="utf-8")
    verifier = (OPENCODE / "agents" / "verifier.md").read_text(encoding="utf-8")
    assert "not a verifier" in researcher.lower() or "never confirms" in researcher.lower()
    assert "only role that may move a finding" in verifier.lower()


def test_sro_agent_refuses_to_self_activate() -> None:
    text = (OPENCODE / "agents" / "sro.md").read_text(encoding="utf-8")
    assert "never activate an engagement on your own initiative" in text.lower()


@pytest.mark.parametrize("name", REQUIRED_INSTRUCTIONS)
def test_instruction_exists(name: str) -> None:
    path = OPENCODE / "instructions" / name
    assert path.exists(), f"missing instruction {name}"
    assert len(path.read_text(encoding="utf-8")) > 400


def test_instructions_are_wired_into_the_config() -> None:
    config = json.loads((REPO / "opencode.json").read_text(encoding="utf-8"))
    for name in REQUIRED_INSTRUCTIONS:
        assert f".opencode/instructions/{name}" in config["instructions"]


@pytest.mark.parametrize("name", REQUIRED_COMMANDS)
def test_command_exists(name: str) -> None:
    path = OPENCODE / "commands" / f"{name}.md"
    assert path.exists(), f"missing command {name}"
    assert path.read_text(encoding="utf-8").strip()


def test_activate_command_never_activates_blind() -> None:
    text = (OPENCODE / "commands" / "activate.md").read_text(encoding="utf-8")
    assert "stop" in text.lower()
    assert "wrong" in text.lower()


def test_plugin_exists_and_defines_the_sro_tools() -> None:
    plugin = OPENCODE / "plugins" / "sro-plugin.ts"
    assert plugin.exists()
    text = plugin.read_text(encoding="utf-8")
    for tool in ("sro_load", "sro_review", "sro_activate", "sro_status",
                 "sro_check_scope", "sro_check_policy", "sro_verify", "sro_report"):
        assert f"{tool}: tool(" in text, f"missing tool {tool}"


def test_plugin_filename_is_not_sro_ts() -> None:
    """`sro.ts` is silently dropped by the plugin loader.

    The tools never register and there is no error, so this is pinned by a test
    rather than left to be rediscovered.
    """
    assert not (OPENCODE / "plugins" / "sro.ts").exists()
    assert (OPENCODE / "plugins" / "sro-plugin.ts").exists()


def test_plugin_shells_out_and_does_not_reimplement_policy() -> None:
    """Security logic must live in the Python core, not in the plugin."""
    text = (OPENCODE / "plugins" / "sro-plugin.ts").read_text(encoding="utf-8")
    # Verdicts may be named in tool descriptions, because the model has to know
    # what they mean. What must not exist is logic that branches on one.
    for pattern in (r'===\s*"IN_SCOPE"', r'===\s*"ALLOW"', r'===\s*"DENY"',
                    r'===\s*"OUT_OF_SCOPE"', r"\.includes\(\s*[\"']IN_SCOPE",
                    r"fetch\(", r"XMLHttpRequest", r"https?\.request"):
        assert not re.search(pattern, text), f"plugin contains security logic: {pattern}"
    assert "sro.cli.main" in text


def test_plugin_registers_a_bash_guard() -> None:
    text = (OPENCODE / "plugins" / "sro-plugin.ts").read_text(encoding="utf-8")
    assert '"tool.execute.before"' in text
    assert "no engagement is active" in text


def test_sro_json_declares_no_secret_and_no_write_setting() -> None:
    config = json.loads((REPO / "sro.json").read_text(encoding="utf-8"))
    for name, provider in (config.get("providers") or {}).items():
        assert "submissions" not in provider, f"{name} configures submissions"
        assert provider.get("credentials", "none") in {"none", "environment", "file"}
        assert "token" not in provider or provider.get("token_env")


def test_external_inference_is_off_by_default() -> None:
    config = json.loads((REPO / "sro.json").read_text(encoding="utf-8"))
    assert config["routing"]["allow_external"] is False
    assert config["routing"]["default"] == "auto"


def test_schemas_are_valid_json_and_declare_their_contract() -> None:
    for name in ("engagement", "scope", "evidence", "finding"):
        path = REPO / "sro" / "schemas" / f"{name}.json"
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema["$schema"].startswith("https://json-schema.org/")
        assert schema["title"]
        assert schema["description"]


def test_engagement_schema_documents_untrusted_fields() -> None:
    schema = json.loads((REPO / "sro" / "schemas" / "engagement.json").read_text(encoding="utf-8"))
    for field in ("description", "rules", "known_issues"):
        assert "UNTRUSTED" in schema["properties"][field]["description"]


def test_evidence_schema_forbids_self_declared_status() -> None:
    schema = json.loads((REPO / "sro" / "schemas" / "evidence.json").read_text(encoding="utf-8"))
    statuses = schema["properties"]["status"]["enum"]
    assert "OBSERVED" in statuses and "HYPOTHESIS" in statuses
    assert "cannot be self-assigned" in schema["description"] or "only creatable" in schema["description"]


def test_python_package_has_no_third_party_runtime_dependencies() -> None:
    """SRO runs on a bare Python 3.11+ install, with no install step.

    That is a deliberate property: a research laptop should not need a
    dependency resolution step before the control plane can enforce anything.
    """
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in pyproject
    for path in (REPO / "sro").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            roots = []
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots = [node.module.split(".")[0]]
            for root in roots:
                assert root in STDLIB_ALLOWED, f"{path.name} imports {root}"
