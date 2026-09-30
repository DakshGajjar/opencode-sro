---
description: Show or change the SRO model routing mode
---
Show the current routing mode and what each route maps to.

If I name a mode — `auto`, `local`, `external`, `qwen`, `spark` — explain what it changes
before applying it. `external` requires `routing.allow_external: true` in sro.json, and SRO
will refuse without it.

Remind me that sensitive material always routes local regardless of the mode, and that a
sensitive payload on an external route is redacted before egress.
