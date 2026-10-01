# Changelog

## 1.0.0

The first release where the control plane, the documentation and the code agree
with each other, and where a finding cannot be produced by a path that was never
checked.

### What works

Six of fourteen catalog tools are implemented.

| Tool | What it does |
|---|---|
| `scope_check` | deterministic scope verdict; one target or a whole manifest in one call |
| `endpoint_inventory` | what the evidence store already knows about a target |
| `code_search` | pattern search plus built-in sink rules over the local tree |
| `record_hypothesis` | a hypothesis with all four fields required, the fourth being falsifiable |
| `render_report` | a report from recorded evidence, to a local file, or a refusal |
| `dns_resolve` | resolves a name and classifies every address it points at |

`dns_resolve` is the only one that touches a network. It is read-only, it goes
through the egress transport, and it cannot connect to anything.

### Security properties, and where each is enforced

| Property | Enforced by |
|---|---|
| A model cannot declare a target in scope | `sro/core/scope.py`, pure Python, no model call in it |
| A request cannot reach a host its approved target does not name | broker derives the policy target from the URL; `url_target_mismatch` |
| A hostname cannot be steered to an internal address | `sro/core/egress.py` resolves once, refuses private ranges, connects to the pinned address |
| An unbounded request is impossible | `EgressLimits` is frozen and `send()` accepts no overrides |
| A response body cannot instruct a model | `sro/core/untrusted.py`, with the target named as provenance |
| A hypothesis cannot confirm itself | `ToolSpec.produces_evidence` marks the bookkeeping tools |
| A confirmed finding needs cited evidence | the evidence store refuses the combination |
| A skill cannot grant a capability | all ten agents demote skills to guidance |
| A substituted scanner cannot be written in its place | agent contract, `METHOD.md`, and the egress review |

### Documentation that cannot drift

`METHOD.md` and `docs/EGRESS.md` are checked against the implementation by
`tests/test_method.py` and `tests/test_egress_review.py`. Every tool named in the
method must be implemented, not merely declared; every blocked tool must have a
verdict in the review; "nothing is approved" is asserted so the test fails the
day a second network tool ships.

### Fixed during this release

A scope bypass that was live in the tree. `target=api.acme.test` with
`url=https://admin.acme.test/secret` returned `ALLOW`: the ladder resolved the
supplied target and ignored the URL, which is what would have been fetched. It
was invisible while every network tool was unimplemented and would have gone live
with the first one.

### Not in this release

Eight network tools are declared and unimplemented, behind
`docs/EGRESS.md`. Credentials, an authenticated session, and anything that
submits a form are decisions rather than code. Vendored third-party scanners are
not adopted: they do their own networking outside the transport.
