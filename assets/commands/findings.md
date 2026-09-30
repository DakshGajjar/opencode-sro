---
description: List findings with their hypotheses and verification verdicts
---
Run `sro find`.

Group by finding id. For each one show the title, the target, whether it is still a
hypothesis, and the verifier's verdict. Make the distinction visible: a hypothesis is not a
finding, and INCONCLUSIVE is not CONFIRMED.

Flag any finding that has hypotheses but no cited evidence, because it cannot be reported
as confirmed.
