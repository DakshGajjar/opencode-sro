# Why the SRO tools live in the plugin

The project layout sketched in the design brief has both
`.opencode/plugins/sro.ts` and `.opencode/tools/`. SRO keeps its tool surface in
the plugin and leaves this directory empty, on purpose.

**One definition, one set of names.** Every SRO tool needs the same two things:
the resolved workspace root, and a bridge to the Python CLI. In `.opencode/tools/`
each file would re-derive both. In the plugin they are constructed once and
shared, so `sro_load`, `sro_check_scope` and the rest cannot drift apart in their
arguments or their naming.

**Security logic stays in one auditable place.** A tool file is a thin wrapper by
necessity, but nothing enforces that. A plugin that constructs the bridge once
makes "the plugin contains no security logic" checkable, and
`tests/test_session.py::test_plugin_shells_out_and_does_not_reimplement_policy`
enforces it: the plugin may name a verdict in a tool description, because the
model needs to know what `OUT_OF_SCOPE` means, but it may not branch on one.

**The plugin is also where the guards live.** The `tool.execute.before` hook that
refuses a shell escape from a security agent, and the system-prompt injection
that tells an agent what is currently authorized, both need the session
context. Hooks only exist on plugins.

If a future SRO version needs tools that are usable without the plugin — say, a
separate MCP surface for a different client — the right move is a new module
under `sro/connectors/`, not a duplicate definition here. Two definitions of the
same tool is how a scope check ends up being enforced in one place and skipped in
another.
