# Evidence

Every meaningful action produces an evidence record. A finding is only ever as
good as the evidence behind it, and a report may only cite what exists.

## The epistemic statuses

    OBSERVED      a tool returned this. It happened.
    INFERRED      SRO derived this from observed records.
    HYPOTHESIS    an agent proposed this. Unproven.
    VERIFIED      the verifier confirmed it against cited observations.

These are not labels you choose. `record_evidence` has no status parameter at
all — it only creates `OBSERVED` records, and it refuses one that carries no
request, response, command or artifact. `record_hypothesis` creates `HYPOTHESIS`
records. Only `sro_verify` can write a verdict, and it requires cited evidence
ids that exist.

This means an agent cannot talk its way into a finding. A confident paragraph is
not a status.

## What counts as evidence

Good:

- the full request and response, headers and body, for the specific request that
  demonstrates the issue
- the exact query and the result count, for a directory or cloud finding
- a reproduction run by the verifier, distinct from the researcher's own test
- a response that shows the control *is* present, when that is the finding

Not evidence:

- a hypothesis, however plausible
- a status code without the body it came with
- a version banner on its own
- something you expect to be true but have not observed
- a screenshot with no request behind it
- the researcher's own description of what they saw, written from memory

## Researcher and verifier are separate

`@researcher` produces a hypothesis with its reasoning, a suggested test, and the
evidence it expects. `@verifier` independently tests it and returns `CONFIRMED`,
`REJECTED`, or `INCONCLUSIVE`.

A verifier may only return `CONFIRMED` with cited `OBSERVED` evidence. Without
that, the store refuses the confirmation. If you are the researcher, your job is
to make the finding easy to verify, not to assert it.

`REJECTED` requires affirmative counter-evidence. A thin evidence base is
`INCONCLUSIVE`. Absence of proof is not proof of absence, and recording a
rejection when the truth is "we did not check" poisons the record.

## Record honestly

Record what actually happened, including failures:

- a 403 that demonstrates the control works is evidence
- a timeout is evidence about the target's behaviour, and about your method
- a tool that raised an exception is recorded, not swallowed

Do not record an intent. Do not record a result you did not observe. Do not edit
an existing record to make it read better; the store is append-only for a reason.

Secrets are redacted before storage. If a response contains a live credential,
record the shape of the finding and not the value.

## Reports cite evidence

`sro_report` builds the report from the evidence store. Sections without
supporting evidence are rendered as `UNPROVEN` rather than quietly dropped or
filled in. Fix them with real evidence, or delete them.

Never write a sentence in a report that does not resolve to an evidence id. If a
sentence is important and unsourced, it is a hypothesis and belongs in a
different document.
