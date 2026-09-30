# SRO — Security Research Orchestrator

An OpenCode-native harness for authorized security research: bug-bounty
programs, CTFs, security labs, defensive engineering and incident response.

SRO is not an AI that decides what to attack. It is a **security control plane**
that knows which engagement you are working under, what is in scope, what the
program's rules forbid, which tool may run, and what evidence exists — and it
enforces all of that in code rather than in a prompt.

```
USER
  ↓  security context
ENGAGEMENT READER      read-only, zero-credential by default
  ↓
SCOPE MANIFEST        candidate; not yet active
  ↓  explicit researcher confirmation
SECURITY AGENT         @web @api @recon @cloud @ad @code
  ↓
POLICY ENGINE          deterministic: ALLOW / DENY / ASK
  ↓
TOOL BROKER            closed catalog of typed tools
  ↓
SECURITY TOOL
  ↓
EVIDENCE STORE         OBSERVED / INFERRED / HYPOTHESIS / VERIFIED
  ↓
VERIFIER               independent: CONFIRMED / REJECTED / INCONCLUSIVE
  ↓
REPORT                 written locally; never submitted
```

## What makes it different

| Property | How it is enforced | Test |
|---|---|---|
| An LLM never decides authorization | `ScopeEngine` is pure Python; no model call exists in the module | `test_scope.py` |
| Platform content is never trusted | fenced before it reaches a model; policy reads structured fields, not prose | `test_prompt_injection.py` |
| The connector cannot write | the transport has no method that accepts a verb; readers import no vendor SDK | `test_write_protection.py` |
| A hypothesis is not a finding | `record_observation` has no `status` parameter | `test_evidence.py` |
| Researcher and verifier are separate | only `sro_verify` writes a verdict, and it needs cited evidence | `test_evidence.py` |
| Sensitive data stays local | sensitivity gate overrides every routing decision | `test_routing.py` |
| SRO never submits to a platform | no submission code exists anywhere in the package | `test_write_protection.py`, `test_mcp.py` |

390 tests. Standard library only at runtime.

## Quick start

```bash
$ ./bin/sro load https://bugcrowd.com/engagements/example

Reading engagement...

✓ Public engagement found
✓ Program identified
✓ Scope extracted
✓ Exclusions extracted
✓ Testing rules extracted

No credentials required.

14 candidate targets
6 exclusions
8 restrictions

⚠ Engagement is NOT ACTIVE.

$ ./bin/sro review          # inspect what was extracted
$ ./bin/sro activate        # your explicit confirmation
$ ./bin/sro status
```

Exit codes carry meaning, so the tooling can branch on them:
`0` ok, `2` policy denied, `3` needs confirmation, `4` usage error.

## In OpenCode

```bash
cd /path/to/your/engagement
opencode
```

Then:

```
> @sro load https://bugcrowd.com/engagements/example
> @sro investigate authentication on api.example.com
> @web inspect https://api.example.com/v1/me
> @recon map the authorized attack surface
> @verifier validate finding #4
> @reporter generate a report for finding #4
```

Slash commands: `/engagement` `/scope` `/evidence` `/findings` `/model`
`/agent` `/policy` `/status` `/review` `/activate`

Normal OpenCode work is unaffected. When SRO is not being used, nothing in this
project changes opencode's behaviour.

## Layout

```
sro/
├── sro/core/            the control plane — all security logic lives here
│   ├── scope.py         deterministic scope engine (IN_SCOPE/OUT_OF_SCOPE/UNKNOWN)
│   ├── policy.py        policy engine, action allowlists, rate limiter
│   ├── tools.py         tool catalog and the broker that gates every call
│   ├── evidence.py      evidence store, epistemic status enforced structurally
│   ├── verifier.py      independent verification
│   ├── routing.py       local-first model router with the sensitivity gate
│   ├── translator.py    natural language → structured objective
│   ├── untrusted.py     prompt-injection detection and fencing
│   ├── report.py        evidence-cited report generation
│   ├── engagement.py    provider-neutral schema
│   ├── session.py       load → review → activate state machine
│   ├── config.py        sro.json (secrets are never stored here)
│   └── audit.py         append-only audit log
├── sro/readers/         dumb readers: read, return data, nothing else
│   ├── base.py          GET-only transport, host allowlist
│   ├── bugcrowd/        public scraping + optional read-only API
│   ├── hackerone/       public scraping + read-only GraphQL
│   └── intigriti/       import_only; no undocumented endpoints are guessed at
├── sro/connectors/mcp/  read-only MCP server for the same readers
├── sro/schemas/         JSON Schema for engagement, scope, evidence, finding
├── sro/cli/             the single interface between Python and the plugin
├── .opencode/
│   ├── plugins/         sro-plugin.ts — thin bridge, no security logic
│   ├── agents/          sro, researcher, recon, web, api, ad, cloud, code,
│   │                    verifier, reporter
│   ├── instructions/    SRO, SCOPE, EVIDENCE, SAFETY, PROVIDERS
│   └── commands/        /engagement /scope /review /activate and friends
├── engagements/         staged manifests (gitignored)
├── evidence/            append-only evidence store (gitignored)
└── reports/             generated reports (gitignored)
```

## Design notes

**Why the policy engine is not a prompt.** A prompt says "please stay in scope".
A function decides. If the model is wrong, tired or injected, the function still
returns the same answer. That is the entire point of the project.

**Why `UNKNOWN` is not a soft yes.** It blocks exactly like `OUT_OF_SCOPE` and
additionally asks the researcher to resolve it. The one way out is
`sro scope add <target>`, which records a human assertion. There is deliberately
no configuration that turns `UNKNOWN` into an allow — the config parser rejects
it.

**Why exclusions always win.** A manifest that is wrong in the permissive
direction is the dangerous failure mode. When an inclusion and an exclusion both
match, the exclusion applies and the decision carries a `conflict` flag so the
researcher can see the program is self-contradictory and go ask.

**Why the readers are "dumb".** A reader reads and returns data. It does not
reason about security, decide authorization, run tools, or interact with bounty
workflows. `ReadOnlyTransport` has no method that accepts an HTTP verb, every
request is pinned to the provider's host allowlist, and off-host redirects are
refused. Writes are not discouraged — they are absent.

**Why the plugin file is `sro-plugin.ts`.** `sro.ts` is silently dropped by the
opencode plugin loader: the tools never register and no error is raised. This is
pinned by `test_session.py::test_plugin_filename_is_not_sro_ts` so it cannot be
rediscovered the hard way.

## Adding a provider

Implement a reader against `BaseReader`, normalise into `Engagement`, register it
in `sro/readers/__init__.py`. Non-negotiable: use the inherited transport, add
hosts to `default_hosts`, do not import a vendor SDK, do not define a method that
accepts a verb or a GraphQL mutation, and report `writes=()` in your
capabilities. `test_write_protection.py` enforces all of it.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/ -q
```

The suite never touches a live platform. Readers are exercised against captured
payloads and a stubbed transport, so no test can generate traffic to a real
program.

## Scope

This is for authorized research only. SRO enforces the engagement it is given;
it cannot tell you whether you have permission, and it will not help you find a
program to attack. Disclosure is yours to do: SRO writes the report to a file
and has no capability to send it anywhere.
