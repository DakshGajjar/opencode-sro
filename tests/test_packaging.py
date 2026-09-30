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
    for kind, count in (("agents", 10), ("commands", 11), ("instructions", 5)):
        files = sorted((REPO / "assets" / kind).glob("*.md"))
        assert len(files) == count, f"{kind}: {len(files)} != {count}"
        installed = sorted((REPO / ".opencode" / kind).glob("*.md"))
        assert [f.name for f in files] == [f.name for f in installed], kind


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
