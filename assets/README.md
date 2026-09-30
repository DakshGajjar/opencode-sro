# opencode-sro

A security research control plane for OpenCode. It reads bug bounty engagements,
**enforces scope and policy in code rather than in a prompt**, separates
hypotheses from verified findings, and cannot submit to a bounty platform.

The premise: an LLM should be good at reasoning about security and bad at
deciding what it is allowed to touch. SRO takes the second job.

## What it does

```
/engagement  /scope  /evidence  /findings  /model  /agent  /policy
/status      /review /activate  /load
```

Agents: `@sro` `@researcher` `@recon` `@web` `@api` `@ad` `@cloud` `@code`
`@verifier` `@reporter`

```bash
> load https://bugcrowd.com/engagements/example
✓ Public engagement found. No credentials required.
14 candidate targets, 6 exclusions, 8 restrictions
⚠ Engagement is NOT ACTIVE.

> review          # inspect what was extracted
> activate        # your explicit confirmation
> @web inspect https://api.example.com/v1/me
```

## Why it is not a prompt

| Guarantee | How |
|---|---|
| An LLM cannot declare a target in scope | `scope.py` is pure Python; there is no model call in it |
| Injected program text cannot change anything | program text is fenced and labelled untrusted before it reaches a model |
| A hypothesis cannot become a finding | confirming requires cited observations; the store refuses otherwise |
| A discovered host is not an authorized host | `UNKNOWN` is blocked, and cannot be configured to allow |
| SRO cannot submit to a platform | the connector transport has no method that accepts an HTTP verb |
| Sensitive data stays local | the routing gate tests the resolved model, not the route name |

## Install

Requires **Python 3.11+**. The plugin is a thin bridge; the authorization
boundary is a Python package that ships with it.

```bash
# 1. the plugin
opencode plugin add opencode-sro

# 2. agents, commands and instructions
npx opencode-sro install-assets
```

Step 2 copies `assets/` into `~/.config/opencode/{agents,commands,instructions}`
and adds the instruction files to your `opencode.json` `instructions[]`.
The plugin cannot install these itself: OpenCode loads them from config
directories at startup, not from a plugin module.

Preview it first with `--dry-run`. It will not overwrite a file of yours that is
newer than the one it ships; `--force` overrides that.

If your Python is not on `PATH` as `python3`:

```bash
export SRO_PYTHON=/usr/bin/python3.12
```

## Try it without touching anything real

Run it in the directory where you installed the package. OpenCode resolves the
plugin from the local `node_modules`, so a subdirectory will not see it.

```bash
npx opencode-sro example > brief.json    # synthetic, .test TLD only
opencode
```

The practice brief contains a prompt injection, a wildcard that conflicts with
an exclusion, an out-of-scope third party, and a private range — so every rule
has something to bite on.

## Verify your install

```bash
npx opencode-sro example > brief.json
opencode
```

> load the brief in brief.json using bugcrowd

If a tool returns a message about a missing control plane, the Python package
did not arrive with the plugin. Set `SRO_PYTHON_PATH` to the directory that
contains `sro/core/scope.py`.

## Optional: read-only platform credentials

SRO reads public program pages with **no credentials** — that is the normal path.
For programs that gate their scope, configure a read-only token by naming where
it lives. Never put the token in a config file or in chat.

```json
{ "providers": { "bugcrowd": {
    "mode": "readonly",
    "credentials": "environment",
    "token_env": "BUGCROWD_API_TOKEN"
} } }
```

The token is used for `GET` requests to the platform's API host only, and is
never written to the manifest, the evidence store, a report or the audit log.

## Configuration

`sro.json` in your project root. Secrets never go here; the parser rejects any
key that would hold one or enable a write.

```json
{
  "providers": { "bugcrowd": { "mode": "public" } },
  "routing": { "allow_external": false },
  "policy": { "unknown_scope": "deny", "rate_limits": { "per_host_per_minute": 20 } },
  "scope": { "deny_private_networks": true }
}
```

Useful settings for a lab or CTF:

- `"scope": { "deny_private_networks": false }` — permits RFC1918 targets
- `"scope": { "wildcard_includes_apex": false }` — `*.example.com` covers subdomains only
- `"policy": { "unknown_scope": "ask" }` — prompt instead of refusing on unresolved targets

## Privacy

Local-first. Credentials, tokens, cookies, private source, internal IPs and
unpublished findings route to a local model. External inference is off unless
you set `routing.allow_external: true`, and even then a sensitive payload is
redacted before egress or blocked.

Engagement state, evidence and reports are written to `sro/../engagements`,
`evidence/` and `reports/` in the project. They are gitignored by the example
config; add them to yours if your project does not already.

## Scope

Authorized research only: bug bounty programs, CTFs, security labs, defensive
engineering, incident response. SRO enforces the engagement you give it. It
cannot tell you whether you have permission, and it will not help you find a
program to attack. Disclosure is yours: SRO writes the report to a file and has
no capability to send it anywhere.

## License

MIT
