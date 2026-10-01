---
description: Assess what is in scope and what is already known, using only local tools
---
Run `sro_check_scope` on every target in the manifest first. Batch them — pass the whole
list in one call rather than one call per host.

Then run `sro_endpoint_inventory` for each target that came back IN_SCOPE.

Present, per target: the scope verdict and the rule that decided it, and what the evidence
store already knows about it — endpoints touched, methods, status codes, tools used.

Be explicit about what this did not do. SRO sends no requests. It has no passive discovery and
no active scanner, so nothing here enumerated anything. The inventory reports what earlier
brokered actions already touched; it does not find new surface. If the manifest is thinner
than the program actually is, that is a fact about the manifest — say so, and ask the
researcher to add the missing targets or clarify with the program. Do not fill the gap by
guessing at hostnames.

If `sro_capabilities` shows a tool you expected to use has `implemented: false`, name it
out loud as unavailable and continue with what is implemented. Do not hand-write a script to
substitute for it.
