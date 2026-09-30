---
description: Show the loaded engagement, how it was retrieved, and whether it is active
---
Run `sro_status` and present the result as a short status block.

Include: engagement name, provider, status, how it was retrieved (public / api / import),
whether credentials were used, in-scope target count, exclusions, restrictions, policy state,
external model state, and the evidence artifact count.

If nothing is loaded, say so and give the researcher the three ways to start:
`sro load <program-url>`, `sro import <brief.json> --provider <name>`, or ask me for a URL.
