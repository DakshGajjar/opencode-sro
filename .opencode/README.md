# SRO OpenCode integration

Loads automatically when opencode starts in this directory. Nothing here
interferes with normal opencode use: agents are subagents, so they only appear
when invoked, and the plugin adds tools without replacing any built-in.

    agents/        @sro @researcher @recon @web @api @ad @cloud @code @verifier @reporter
    commands/      /engagement /scope /evidence /findings /model /agent /policy
                   /status /review /activate /load
    instructions/  SRO.md SCOPE.md EVIDENCE.md SAFETY.md PROVIDERS.md
                  (wired through opencode.json -> instructions[])
    plugins/       sro-plugin.ts, the only bridge to the Python control plane
    tools/         empty by design, see tools/README.md

## One naming trap

The plugin file must be named `sro-plugin.ts`, **not** `sro.ts`. opencode
silently drops a plugin called `sro.ts`: the module evaluates, the tools build,
and none of them register, with no error anywhere. This is pinned by
`tests/test_session.py::test_plugin_filename_is_not_sro_ts`.

## The plugin contains no security logic

It spawns the CLI and renders JSON. Scope verdicts, policy decisions, evidence
status and routing are all decided in `sro/core/`, which is Python, which is
auditable in one place and has 429 tests. A test asserts the plugin contains no
branch on a verdict value.

## Local dependencies

`.opencode/package.json` declares `@opencode-ai/plugin`. If `bun` is not
available, symlink an existing install:

    ln -s ~/.opencode/node_modules .opencode/node_modules
