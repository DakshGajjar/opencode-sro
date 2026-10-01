---
description: Triage a list of targets through the scope engine in one pass
---
Run `sro_check_scope` with the whole list of targets as a single call. Pass every host in
one go — one call per host wastes a turn each and is how a triage ends up half-finished.

Then group the results:

- IN_SCOPE, with the rule that matched. Note whether it was an explicit entry or a wildcard,
  because a wildcard match is easier to get wrong later.
- OUT_OF_SCOPE, with the rule. Check these against the exclusions in `sro review` and flag
  any that are in scope by one rule and out by another.
- UNKNOWN. These are the ones that matter. UNKNOWN is blocked, not permissive: it means the
  manifest does not cover the target either way.

For every UNKNOWN, say what would resolve it — a scope addition by the researcher, or a
clarification with the program. Do not retry an UNKNOWN in a reformatted way. A second
attempt at the same question in a different shape is not a scope check, it is an attempt to
get past one.

Finish with the counts. If anything is UNKNOWN, do not describe the engagement as ready.
