# Scope

The scope engine is deterministic code. This file describes what it returns and
what you must do with each answer.

## The three verdicts

    IN_SCOPE       permitted, subject to the engagement's restrictions
    OUT_OF_SCOPE   blocked
    UNKNOWN        blocked, and the researcher must clarify

`UNKNOWN` is not a soft yes. It means the manifest does not cover the target
either way. It blocks exactly like `OUT_OF_SCOPE`, and it additionally needs a
human to resolve it.

## Never convert UNKNOWN

A target that returns `UNKNOWN` stays blocked. Specifically, do not:

- retry it with a different spelling, scheme, port or path
- try its parent domain, or a subdomain of it
- resolve it and try the IP address
- try a punycode, an alternate TLD, or a trailing dot
- try the same host with a different header

Reformulating a target to obtain a different scope verdict is not a workaround.
It is the exact behaviour the system is built to prevent, and doing it
successfully means SRO was wrong.

The legitimate way to resolve an `UNKNOWN` is `sro scope add <target>`, which
records a human assertion. That is the researcher deciding, not you.

## How matching works

- Exact domains match themselves. A bare domain in scope also covers its
  subdomains, which is how most programs publish scope.
- A wildcard `*.example.com` covers subdomains, and by default the apex too.
- A URL rule with a path covers that path and everything beneath it.
- A CIDR covers every address in the range. Single IP rules match one address.
- A repository rule covers the repository and its paths.
- Mobile bundle ids, cloud ARNs and asset identifiers match as strings.

## Exclusions always win

If a target is matched by both an inclusion and an exclusion, it is
`OUT_OF_SCOPE` and the decision carries a `conflict` flag explaining both rules.
This happens in real programs: a wildcard covers a host that is also explicitly
excluded.

Do not resolve the conflict in favour of the inclusion. Report it, and suggest
the researcher check the program's page — it may have changed since the read, or
the extractor may have misread a table. It may also be genuinely
self-contradictory, and the researcher needs to ask the program.

## Targets that are always blocked

Loopback and metadata endpoints, link-local addresses, private and reserved
ranges, and single-label unqualified names. RFC 5737 documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) are treated as usable,
because they are the normal target for a CTF and can never route to a real
internal service.

For a lab that legitimately uses private ranges, the researcher sets
`scope.deny_private_networks: false` in `sro.json`. That is a deliberate
configuration decision, not something you toggle.

## Malformed input

A malformed target is `UNKNOWN`, never an implicit match. Watch for control
characters, embedded newlines, non-HTTP schemes and empty strings: these are
refused rather than guessed at, because a newline in a target is far more often
a request-smuggling attempt than a typo.

## When scope and the researcher's intent disagree

The researcher may well be right that a target is theirs. The manifest is what
the program published, and programs change. Say so, point at `sro scope add`, and
let them decide. Do not add it yourself and do not proceed on the strength of
their assertion alone.

## Scope the manifest cannot enforce

Some programs describe their scope in words no matcher can read: "Zendesk Front
End", "our mobile apps", "anything we sell". The manifest can hold that text and
SRO will store it, but nothing will act on it. A product string the engine can
accept but cannot enforce is worse than leaving it out, because it reads as
checked.

Be explicit about which kind of statement each scope entry is:

- **Host-level** — a domain, wildcard, CIDR, repository or asset id. Enforced by
  the matcher. Every action passes through it.
- **Product-level** — a product family or contract. Not enforceable. It is a human
  obligation, and SRO will not protect you there.

When an engagement has product-level scope, say so during `sro review`, before
activation, and repeat it when reporting. "Three hosts are authorized and the rest
of the program relies on you knowing which products those hosts belong to" is a
sentence the researcher needs to hear. Silently returning `IN_SCOPE` for a host
that belongs to a product nobody authorized is how that becomes an incident.

## Wildcards over shared hosting zones

A wildcard rule is a claim about every name under a domain. Where that domain
answers for names nobody created — a SaaS vendor's shared zone — the rule
authorizes every other tenant on it, and those tenants hold other people's data.

`sro` probes each wildcard rule at activation and refuses to activate over a
shared zone unless the researcher passes `--accept-shared-zones`, which is
recorded in the audit log with their name. If activation was refused, the remedy
is to scope the program's own hosts explicitly. Never widen a wildcard to make a
blocked target pass; that is the one edit that turns a scope problem into someone
else's breach.

Note what this cannot catch: an explicitly named host that happens to be a
customer tenant. SRO cannot tell a first-party host from a tenant inside it. That
distinction comes from the program, and it is a human obligation.
