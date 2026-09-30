# Security Policy

## Reporting a vulnerability in SRO

Report it privately through **GitHub Security Advisories** on this repository:

    https://github.com/dakshgajjar/opencode-sro/security/advisories/new

Please do not open a public issue for a security problem. Give the maintainer a
chance to ship a fix before disclosing.

Useful to include: the version (`npm view opencode-sro version`), your Python
version (`python3 --version`), what an attacker could achieve, and a
reproduction if you have one. A failing test case is the most useful thing you
can bring.

### What is in scope

Anything that lets a request reach a target the engagement did not authorize, or
that misrepresents what a tool did:

- the scope engine returning `IN_SCOPE` for a target no engagement rule covers
- the policy engine returning `ALLOW` for a target the scope engine refused
- platform content (a program brief, target instruction, known-issue title)
  changing a scope verdict, a policy decision, or a model routing decision
- a researcher's hypothesis becoming a `CONFIRMED` finding without cited
  observed evidence
- a platform connector performing anything other than a `GET`
- engagement state or evidence being written outside the project workspace
- sensitive material reaching an external model provider

### What is not a vulnerability in SRO

**SRO has no platform submission capability.** It cannot create, edit, comment
on or submit a bounty report to Bugcrowd, HackerOne or Intigriti, and that
capability does not exist in its code. Disclosure is the researcher's own act,
performed by hand through the program's channel. A request to add one is a
feature request, not a bug.

**SRO cannot tell you whether you are authorized.** It enforces the engagement
you give it. Pointing it at a program you are not engaged in is misuse, not a
vulnerability.

**Destructive techniques stay blocked even if you want them.** SRO ships no
denial-of-service, brute-force or data-destruction tool. If you need one for an
engagement that explicitly permits it, that is a request, not a report.

## Trust boundaries

Worth knowing when assessing a finding, because several of these are load-bearing
by design rather than by accident:

- **The scope engine is deterministic code.** There is no model call in it. A
  model can request a verdict but cannot produce one.
- **`UNKNOWN` is blocked, not permissive.** It cannot be configured to allow; the
  config parser rejects the attempt.
- **Exclusions always beat inclusions.** When both match, the exclusion applies
  and the decision carries a conflict flag.
- **The connector transport has no method that accepts an HTTP verb.** Writes
  are absent, not disabled. A test walks the reader package's AST and fails if
  a write-shaped name or a vendor SDK appears.
- **Activation is a human decision.** A dropped `session.json` cannot forge an
  active engagement: restoring one requires a matching manifest hash and an
  activation record in the append-only audit log.
- **A caller cannot claim a capability its tool does not have.** The tool
  catalog is the authority; a declared capability that disagrees is denied.

## Data handling

SRO is local-first. Credentials, tokens, cookies, private source, internal IPs
and unpublished findings are routed to a local model. External inference is off
unless `routing.allow_external` is set, and even then a payload containing
sensitive markers is redacted before egress or blocked.

Optional platform credentials are used for authenticated `GET` requests to the
platform's API host only. They are never written to the engagement manifest, the
evidence store, the audit log or a report, and they are redacted from stored
evidence.

## Scope of support

SRO is for authorized research: bug bounty programs, CTFs, security labs,
defensive engineering and incident response. Using it against systems you are
not authorized to test is your responsibility and is not a bug in this tool.
