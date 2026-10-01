"""Packaging tests.

SRO is a two-language package: a TypeScript bridge and a Python control plane.
These tests guard the seam, because the failure mode there is silent — the
plugin loads, the tools register, and every call quietly finds nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PLUGIN = REPO / ".opencode" / "plugins" / "sro-plugin.ts"
PACKAGE = json.loads((REPO / "package.json").read_text(encoding="utf-8"))


def test_plugin_is_a_single_source_of_truth() -> None:
    """The file opencode loads is also the build entry point.

    An earlier layout re-exported the plugin from `src/` through
    `.opencode/plugins/`. OpenCode does not follow `export *` when locating a
    plugin, so the tools silently failed to register. One file, no indirection.
    """
    assert PLUGIN.exists()
    text = PLUGIN.read_text(encoding="utf-8")
    assert "export const SroPlugin" in text
    assert "export * from" not in text
    assert ".opencode/plugins/sro-plugin.ts" in PACKAGE["scripts"]["build"]
    assert not (REPO / "src").exists()


def test_everything_the_plugin_needs_is_in_the_published_files() -> None:
    published = PACKAGE["files"]
    assert "dist/" in published
    assert "sro/" in published, "the control plane must ship with the plugin"
    assert "assets/" in published, "agents and instructions must ship"


def test_the_control_plane_is_python_shipped_not_a_dependency() -> None:
    """There is no pip install step, so the Python has to be in the tarball."""
    assert "sro/core/scope.py" in [str(p.relative_to(REPO)) for p in REPO.glob("sro/core/*.py")]
    dependencies = PACKAGE.get("dependencies", {})
    assert not any("sro" in name for name in dependencies), dependencies


def test_assets_mirror_the_installed_agent_command_and_instruction_sets() -> None:
    """`assets/` is what the tarball ships, so it must not drift from what runs.

    The count is derived from the installed set rather than written down here. A
    hard-coded number turns adding a command into a test edit, which is how a
    command ships in the repo, fails to install, and nobody notices until a user
    types it and gets nothing.
    """
    for kind in ("agents", "commands", "instructions"):
        files = sorted((REPO / "assets" / kind).glob("*.md"))
        installed = sorted((REPO / ".opencode" / kind).glob("*.md"))
        assert files, f"no {kind} in assets/"
        assert [f.name for f in files] == [f.name for f in installed], (
            f"{kind}: assets and .opencode differ; run bin/sro-install-assets.mjs"
        )


def test_publish_readme_documents_the_python_requirement() -> None:
    readme = (REPO / "assets" / "README.md").read_text(encoding="utf-8")
    assert "Python 3.11" in readme
    assert "install-assets" in readme
    assert "SRO_PYTHON" in readme


def test_plugin_resolves_the_control_plane_rather_than_the_workspace() -> None:
    """A directory called `sro` in the user's project must not be able to
    shadow the shipped control plane. That would put the authorization
    boundary under the control of whatever is in the workspace."""
    text = PLUGIN.read_text(encoding="utf-8")
    assert "resolveControlPlane" in text
    assert "SRO_PYTHON_PATH" in text
    assert "sro/core/scope.py" in text
    # The workspace is the last resort, not the first choice.
    assert text.index("import.meta.url") < text.index('isControlPlane(worktree)')


def test_a_missing_control_plane_is_a_structured_error_not_a_crash() -> None:
    text = PLUGIN.read_text(encoding="utf-8")
    assert '"error" in located' in text
    assert "could not find its Python control plane" in text


def test_repository_does_not_ship_development_state() -> None:
    tracked_ignore = (REPO / ".gitignore").read_text(encoding="utf-8")
    for entry in ("engagements/", "evidence/", "reports/", "audit/", "node_modules", ".venv/"):
        assert entry in tracked_ignore, entry


def test_readme_promises_only_commands_that_exist() -> None:
    """The README is the install instructions, so a command it names has to
    exist. `sro doctor` was documented for a while before anything implemented
    it, which is the worst way for a first-time user's install to fail."""
    import re

    readme = (REPO / "assets" / "README.md").read_text(encoding="utf-8")
    installer = (REPO / "bin" / "sro-install-assets.mjs").read_text(encoding="utf-8")

    # Subcommands the README tells a user to run via npx.
    for command in set(re.findall(r"npx opencode-sro (\S+)", readme)):
        assert f'command === "{command}"' in installer, f"README names `npx opencode-sro {command}`, which the installer does not implement"
        assert f'"{command}"' in installer, command

    # The package must actually expose the binary the README invokes.
    assert PACKAGE["bin"]["opencode-sro"] == "bin/sro-install-assets.mjs"
    assert "bin/" in PACKAGE["files"]
    assert "examples/" in PACKAGE["files"], "README writes examples/practice-brief.json to stdout"
    assert (REPO / "examples" / "practice-brief.json").exists()


def test_installer_does_not_clobber_user_edits_by_default() -> None:
    """Compares content, not mtime.

    An mtime rule gets this wrong in the dangerous direction: a user edits an
    agent, a new version ships with a newer mtime, and the edit is destroyed
    silently. Content is the only reliable signal of "this is ours".
    """
    installer = (REPO / "bin" / "sro-install-assets.mjs").read_text(encoding="utf-8")
    assert "differs from ours" in installer
    assert "installed === shipped" in installer
    assert "statSync" not in installer, "mtime comparison is the bug this replaced"
    assert "--force" in installer
    assert "dryRun" in installer


def test_installer_prints_help_without_installing() -> None:
    """`--help` must not fall through to the default subcommand and write files."""
    installer = (REPO / "bin" / "sro-install-assets.mjs").read_text(encoding="utf-8")
    help_check = installer.index("flags.help")
    dispatch = installer.index('if (command === "install-assets")')
    assert help_check < dispatch, "help must be handled before the default command runs"
    assert 'const command = flags.command ?? "install-assets"' in installer


def test_publish_gates_are_runnable() -> None:
    """`prepublishOnly` is the last chance to catch a broken publish.

    Two mistakes lived here: the build emitted `sro-plugin.js` while
    `main` pointed at `dist/index.js`, so the published plugin would not have
    loaded at all; and `compileall` wrote __pycache__ into the tarball, which is
    35 platform-specific .pyc files that no user can use.
    """
    scripts = PACKAGE["scripts"]
    assert "--outfile dist/index.js" in scripts["build"], "build output must match package main"
    assert PACKAGE["main"] == "dist/index.js"
    assert "compileall" not in json.dumps(scripts), "must not write bytecode into the tarball"
    joined = " ".join(PACKAGE["files"])
    assert "!**/*.pyc" in PACKAGE["files"] or "!**/*.pyc" in joined
    assert "__pycache__" in joined
    for script in ("bin/lint-python.py", "bin/sro-install-assets.mjs"):
        assert (REPO / script).exists(), script
    assert "lint" in scripts and "test" in scripts
    assert scripts["prepublishOnly"] == "bun run build && npm run lint && npm test"


def test_state_goes_to_the_workspace_not_the_package() -> None:
    """`--root` and the Python location are different directories.

    Conflating them writes the engagement manifest, the evidence store and the
    audit log inside node_modules, where the next `npm install` deletes them.
    """
    text = PLUGIN.read_text(encoding="utf-8")
    assert 'makeBridge(controlPlane: string, workspace: string)' in text
    assert '"-m", "sro.cli.main", "--root", workspace' in text
    assert "PYTHONPATH: [controlPlane" in text
    assert "makeBridge(located.root, workspace)" in text


def test_readme_does_not_send_users_to_a_directory_without_node_modules() -> None:
    """OpenCode resolves the plugin from the local node_modules, so a playground
    in a subdirectory cannot see it. The README used to tell users to make one."""
    readme = (REPO / "assets" / "README.md").read_text(encoding="utf-8")
    assert "mkdir -p ~/sro-playground" not in readme
    assert "subdirectory" in readme
    assert "where you installed the package" in readme


def test_publish_gate_does_not_depend_on_the_publishers_python() -> None:
    """`npm test` used to call the system interpreter directly.

    On a machine whose default python has no pytest — which is the default on a
    fresh box, and was the case here — the publish gate could never pass. A
    gate that fails for an unrelated reason gets skipped.
    """
    script = (REPO / "bin" / "run-tests.py").read_text(encoding="utf-8")
    assert "import pytest" in script, "must probe for pytest, not assume it"
    assert "SRO_PYTHON" in script
    assert ".venv" in script
    assert "No module named pytest" not in script, "the bare error is not actionable"
    assert "npm publish" in script, "the failure must say what to do next"

    assert PACKAGE["scripts"]["test"] == "python3 bin/run-tests.py"
    assert PACKAGE["scripts"]["prepublishOnly"] == "bun run build && npm run lint && npm test"
    assert (REPO / "bin" / "run-tests.py").exists()


def test_security_policy_ships_and_points_somewhere_real() -> None:
    """A published security tool needs a disclosure route, and the policy has to
    say the things a reader would otherwise file a bug about."""
    import re

    policy = (REPO / "SECURITY.md").read_text(encoding="utf-8")
    assert "SECURITY.md" in PACKAGE["files"], "must ship in the package"
    assert re.search(r"security/advisories/new", policy), "must name a real report route"
    assert re.search(r"no platform submission capability", policy, re.I)
    assert re.search(r"cannot tell you whether you are authorized", policy, re.I)

    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "SECURITY.md" in readme, "the policy has to be findable from the README"

    # And the npm metadata should point somewhere real, not a placeholder.
    assert PACKAGE.get("homepage", "").startswith("https://github.com/")
    assert "github.com" in PACKAGE.get("bugs", {}).get("url", "")
    assert "YOUR_USERNAME" not in json.dumps(PACKAGE)


def test_the_shipped_bundle_is_not_stale() -> None:
    """`main` points at dist/index.js, so a stale bundle ships the old plugin.

    Skipped when there is no bundle, because dist/ is gitignored and a fresh
    clone legitimately has none — prepublishOnly builds it. This is the local
    check that would otherwise let a 0.4.0 tarball carry a 0.3.0 plugin.
    """
    bundle = REPO / "dist" / "index.js"
    source = REPO / ".opencode" / "plugins" / "sro-plugin.ts"
    if not bundle.exists():
        pytest.skip("no dist/ build in this checkout")
    assert bundle.stat().st_mtime >= source.stat().st_mtime, (
        "dist/index.js is older than the plugin source; run npm run build"
    )


def test_the_bundle_exposes_every_tool_in_the_source() -> None:
    """Catches a build that silently dropped tools, which no other check sees."""
    bundle = REPO / "dist" / "index.js"
    source = REPO / ".opencode" / "plugins" / "sro-plugin.ts"
    if not bundle.exists():
        pytest.skip("no dist/ build in this checkout")
    import re

    in_source = set(re.findall(r"^    (sro_[a-z_]+): tool\(", source.read_text(encoding="utf-8"), re.M))
    in_bundle = set(re.findall(r"\b(sro_[a-z_]+):", bundle.read_text(encoding="utf-8")))
    assert in_source, "no tools found in the source; the pattern is stale"
    assert in_source <= in_bundle, sorted(in_source - in_bundle)


def test_the_methodology_ships_and_is_declared() -> None:
    """METHOD.md is the document a user reads instead of a third-party
    checklist. Uninstalled or undeclared, it helps only this repo."""
    import json

    pkg = json.loads((REPO / "package.json").read_text(encoding="utf-8"))
    declared = pkg["opencode"]["provides"]["instructions"]
    assert "METHOD.md" in declared, declared
    assert (REPO / "assets" / "instructions" / "METHOD.md").exists()
    assert "assets/instructions/METHOD.md" in PACKAGE["files"] or "assets/" in PACKAGE["files"]
