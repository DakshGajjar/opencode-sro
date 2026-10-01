---
description: Assess a possible 403 bypass from the source, and record what is untested
---
I think there may be a 403 bypass here: <target and endpoint from the user>

Work in this order and do not skip ahead.

First run `sro_check_scope` on the target. If it is not IN_SCOPE, stop and say so — an
authorization bug on an out-of-scope host is still out of scope.

Then run `sro_code_search` for the authorization logic around that path. Search for the
handler, the middleware, the decorator or guard in front of it, and the way the decision is
made. Look specifically for: a check that returns rather than denies, a check that fails
open, a comparison against a header or a claim that a client can set, a role check that
compares against a value from the request, and a path that skips the guard that protects the
sibling path.

SRO sends no requests, so you cannot confirm anything here. Whatever you find, it is a
hypothesis. Record it with `sro_record_hypothesis` and write the expected evidence as a
result you could be wrong about — a status code and a body property, not "it is bypassable".
If the expected evidence could be satisfied by both a vulnerable and a patched server, it is
not a test, and it should be rewritten before it goes in the record.

Then tell the researcher the exact request they would need to send to settle it, and that
you did not send it. That request is their act, on their connection, under their judgment
about the engagement.
