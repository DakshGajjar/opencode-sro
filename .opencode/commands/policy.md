---
description: Show the policy engine surface and evaluate a proposed action
---
With no arguments, run `sro policy-describe` and summarise: the capabilities, which actions
each capability may perform, which actions are destructive, which techniques are conditional
on the engagement permitting them, and the rate limits.

If I name a tool, a target and an action, run `sro check_policy` with them and report the
ALLOW / DENY / ASK verdict verbatim, including the reason.
