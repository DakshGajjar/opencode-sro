# Method

This is how to work an engagement under SRO. It is not a checklist of techniques
and it is not a catalogue of tools. Techniques are a function of the target and
of what the program permits; the method below is the part that stays true
regardless.

The premise is uncomfortable: **most of what a security tool does, SRO does not
do for you.** Five tools are implemented and all five are local and read-only.
Every capability that touches a third party's system is something you do by
hand. What SRO contributes is not speed. It contributes the properties that
make a finding survive a verifier and a triage reviewer: authorization decided
by code, evidence recorded as it happens, and a hard line between what you
proved and what you suspect.

So this method optimises for **fewer findings that are real** over more findings
that are not. A run that produces three confirmed, reproducible findings and one
honest "this needs credentials we do not have" is a good run.

## The loop

Seven steps. Each names the gate it passes through, because a step without a
gate is where the discipline leaks out.

    1. scope        2. orient      3. read        4. hypothesize
    5. test         6. verify      7. report

### 1. Scope — before anything else, and again whenever the target changes

```
sro_check_scope   one target or a whole list; batch it
```

Gate: `IN_SCOPE`. `OUT_OF_SCOPE` stops the line of work, not just the call.
`UNKNOWN` is blocked — the manifest does not cover the target either way.

This is first because it is cheap and it is the only step that cannot be
retried into a different answer. Triage the whole manifest in one call; a
per-host loop is slow and is how a run ends up half-checked.

**Failure mode:** treating `UNKNOWN` as "probably fine". It is not a soft yes.
Resolving it is the researcher's — a scope addition, or a question to the
program. Retrying it with a reformatted hostname is not a second scope check, it is an
attempt to get past one, and in the log it is indistinguishable from one.

### 2. Orient — what has already happened

```
sro_endpoint_inventory   per in-scope target
```

Gate: none; this is a read.

Shows the endpoints earlier actions touched, methods, status codes, and which
tools ran. It **discovers nothing** — there is no discovery here. If the
manifest is thinner than the program actually is, that is a fact about the
manifest. Say so and ask; do not fill the gap by generating plausible hostnames.

**Failure mode:** reading this as a scan result. If the endpoint list is short,
that means little has happened yet, not that there is little there.

### 3. Read — the only way to get evidence without sending anything

```
sro_code_search   regex, or '*' for the built-in sink rules
```

Gate: none; local and read-only.

This is the highest-leverage tool you have, because it is the only one that
produces evidence about a vulnerability while touching nothing. Use it to
establish **reachability**: not "does this pattern exist" but "does an
unauthenticated request reach the handler that uses it".

Search for the authorization logic, not the vulnerable line. The guard is what
makes a bug a bug. Look for: a check that returns instead of denying, a check
that fails open, a comparison against a header or claim the client controls, a
role check that compares against request data, and a sibling path that skips the
guard.

Note the constraint: `code_search` reads a directory you already have. For a
remote target there is no local source, so this step yields nothing and you
should say so rather than reasoning from the framework's reputation.

**Failure mode:** reporting a rule hit. The built-in rules produce leads. A
pattern in a file nobody can reach is a code-quality note, not a finding.

### 4. Hypothesize — write the expectation before the test

```
sro_record_hypothesis
```

This writes a `HYPOTHESIS`. It is not an `OBSERVED` and it is not `VERIFIED`,
and no amount of confident reasoning moves it. It is a claim with a written-down
way to be wrong.

Gate: all four fields. `expected_evidence` is the one that matters and the one
that gets written badly.

A hypothesis is only useful if it can fail. "The endpoint is vulnerable" cannot
be refuted. "GET /v1/orders/8842 with a second account's token returns 200 with
an order body belonging to that account" can. If you cannot state the result
that would prove you wrong, you have a hunch, not a hypothesis — and the store
will not accept it.

If the expectation is written after the test, it fits any outcome and the record
is worthless. Write it first. If the researcher already tested and you are
writing the record afterwards, say that, and record what they actually expected
at the time rather than what the result turned out to be.

**Failure mode:** the retrofitted expectation. This is the single most common
way a false positive becomes a confirmed finding.

### 5. Test — you do this part, by hand

Whatever comes back is recorded as an `OBSERVED` carrying its evidence id. That
id is what a finding will have to cite.

There is no tool for this. `http_request`, `parameter_probe`,
`auth_session_test` and the rest are declared with `implemented: false`; calling
one returns a refusal naming the tools that do work.

So the request is yours to send, and that is a division of labour rather than a
gap:

- **You** produce the exact request — method, path, headers, body — and the
  expected and refuting outcomes, and you hand it over.
- **The researcher** sends it, on their connection, judging whether the
  engagement permits it, and tells you what happened.
- **You** record what actually happened, with the real request and response.

Never write a script to send it instead. A script you write is unscoped, runs at
a rate nobody approved, and turns "untested" into "tested" on the operator's
checklist while nothing was verified. If you catch yourself about to write a
scanner, that is the signal to hand the request over instead.

**Failure mode:** claiming a result you inferred. If you did not see the
response, it is not an observation. Say "predicted" or "unverified" and let the
verifier decide what that is worth.

### 6. Verify — a different agent, with a verdict

```
sro_verify   citing the observation's evidence id
```

Only an `OBSERVED` record — a real request and a real response — can support a
`VERIFIED` finding. A `HYPOTHESIS` citing another `HYPOTHESIS` confirms nothing,
and the store refuses the combination rather than letting it stand.

Gate: a cited observation. Confirming without one is refused by the store, not
by convention.

The verifier's job is to rule, and it can rule against you. `REFUTED` and
`INCONCLUSIVE` are answers, not failures of the process. Report them as they
came back. Do not retry the same test hoping for a different verdict — that is not
verification, it is sampling until you like the answer.

`INCONCLUSIVE` names what would move it. Say that, rather than escalating to
more tests of the same kind.

### 7. Report — local file, your disclosure

```
render_report   via sro_execute, or sro_report
```

Gate: verified evidence behind the finding.

`render_report` refuses to write a finding with nothing verifiable behind it, so
a report generated from a bare hypothesis will not produce a file. That refusal
is the point.

SRO writes a local file and has no capability to send it anywhere. Disclosure is
your act, through the program's channel, in their format, with their caveats.
Nothing you produce here is submitted by this tool.

## The discipline

The tools are thin. These are the parts that make a finding real, and they are
the whole reason to use this instead of a checklist.

**Reachability before impact.** Find the path from an unauthenticated entry
point to the sink. If you cannot describe it in one sentence, you have not
established it, and reporting the sink alone is how a triage reviewer closes it
as unreachable.

**Bound the claim.** Say what you tested, on what build, as whom, and when. "IDOR
on the orders endpoint" is a category. "IDOR on GET /v1/orders/{id} for
account B's order 8842, reproduced three times on 2026-10-01, no rate limit
observed" is a finding. Programs pay for the second kind and triage the first.

**Prefer the boring class.** A missing authorization check on one endpoint is
worth more than a speculative race condition you could not trigger. When you
have a choice, take the one you can reproduce on demand.

**Chain, but show every link.** `IDOR → reads PII` is a chain. Each link needs
its own evidence; a chain whose second link is assumed is one report with two
guesses in it. Say which links you proved.

**State what you did not test.** Out-of-scope areas, untested parameters, the
branch you did not read. A stated gap is information; an unstated one is what
makes a report quietly wrong.

**One engagement at a time.** Targets from a different program never appear in
this one, not even for a sanity check.

## When you are wrong

Say so early and specifically. "I could not reproduce it" with the request
attached is worth more than three more attempts, because the verifier needs to
know whether the observation was flaky or wrong. A `REFUTED` hypothesis that you
recorded is a useful artifact — it stops the next run from spending a day on it.

If the program's rules turn out to forbid something you have already done, stop
and tell the researcher immediately, with what was sent and when. That is not a
failure to be minimised; it is the information they need.

## What this method cannot do

Sends no requests. Resolves no DNS. Inspects no TLS. Enumerates nothing,
passively or actively. Loads no authenticated session. Fetches no schema.

Every one of those is a real limitation and every one of them is the operator's
to perform. What remains is the part that should not have been optional anyway:
deciding authorization by code, recording what happened, refusing to write up
what was never proved, and keeping the distance between a hypothesis and a
finding wide enough to be visible from the outside.
