---
description: Settle whether a hypothesis holds, and record the outcome either way
---
Run `sro_evidence` for the finding, then state plainly what exists today: hypotheses,
observations, and any verification verdicts. Note whether there is a cited observation at
all, because without one the finding cannot be reported as confirmed no matter how good the
reasoning is.

Then take the hypothesis's suggested test and walk it through with the researcher, in order.
SRO sends no requests, so you are settling the test with them, not performing it:

1. State the test as a specific request or action, with the exact input.
2. State what result would confirm it and what result would refute it. If you cannot state
   the refuting result, the hypothesis is not falsifiable — say that and stop.
3. If the researcher ran it, record what actually happened with `sro_record_evidence`, using
   the real request and the real response.
4. Then run `sro_verify`, citing the evidence id.

Report the verdict as the verifier gave it. CONFIRMED, REFUTED and INCONCLUSIVE are three
different answers and INCONCLUSIVE is not a softer CONFIRMED. If it comes back INCONCLUSIVE,
say what would move it, rather than re-running the same test and hoping.

A refuted hypothesis is a useful result. Record it as one. Do not quietly drop a hypothesis
that did not pan out, and do not keep a confirmed one without the evidence id in hand.
