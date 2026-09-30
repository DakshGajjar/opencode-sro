# Providers

SRO reads engagement information from bug bounty platforms. It never writes to
them.

## Zero credentials is the default

    sro> load https://bugcrowd.com/engagements/example

SRO reads the public program page first. Most programs publish their scope,
their rules and their exclusions publicly, so a complete engagement is often
readable with no account and no token. That is the normal path, not a degraded
one, and SRO tells the researcher when it happened.

If the public read is incomplete, SRO says so and offers:

1. Continue with incomplete information
2. Import the engagement brief manually
3. Configure optional read-only credentials
4. Cancel

It does not proceed past an incomplete read silently. Security testing stays
disabled until scope is established.

## Optional read-only credentials

When a program's detail is gated, SRO can use a read-only API token. This is
optional, and it is the only credential SRO ever reads.

Configure it by naming where the token lives — never the token itself:

    {
      "providers": {
        "bugcrowd": {
          "mode": "readonly",
          "credentials": "environment",
          "token_env": "BUGCROWD_API_TOKEN"
        }
      }
    }

Then:

    export BUGCROWD_API_TOKEN=...

`token_file` is also supported for a local secret file. SRO does not read
credentials from chat, and `sro.json` rejects any key that would hold a secret
literal or enable a write.

The token is used for authenticated `GET` requests only. It is never written to
the manifest, the evidence store, the audit log, or a report. A test asserts that
a config summary containing a live token does not serialise it.

## Provider modes

    off           the provider is not registered
    public        read the public program page (default, no credentials)
    readonly      additionally use the documented read API with a token
    import_only   no platform access; the researcher supplies a brief

Intigriti ships as `import_only`. It has no documented public scope API, and SRO
does not guess at undocumented endpoints. If the public page is not readable,
import a brief.

## Bugcrowd

Typed reads, all `GET`:

    bugcrowd_list_programs
    bugcrowd_get_program
    bugcrowd_get_engagement
    bugcrowd_get_brief
    bugcrowd_get_scope
    bugcrowd_get_rules
    bugcrowd_get_known_issues

## HackerOne

Typed reads, all `GET`:

    hackerone_list_programs
    hackerone_get_program
    hackerone_get_structured_scope
    hackerone_get_scope_exclusions
    hackerone_get_program_details

Reading the researcher's own reports is off by default and SRO ships it off:
report contents are unpublished work, and pulling them into a local evidence
store is a decision for the researcher to make deliberately.

## Adding a provider

Implement a reader against `sro.readers.base.BaseReader`, normalise into
`sro.core.engagement.Engagement`, and register it in `sro/readers/__init__.py`.

The requirements are not negotiable:

- use the inherited `ReadOnlyTransport`, which only builds `GET`
- add the provider's hosts to `default_hosts`; the transport refuses anything else
- do not import a vendor SDK, since that imports its write surface
- do not define a method that accepts an HTTP verb or a GraphQL mutation
- list only typed read operations in `capabilities()`, with `writes=()`

A test walks the reader package and fails on any of these. A new provider that
cannot satisfy them does not belong in SRO.

## What SRO never does with a provider

- create, update or delete a submission
- comment on a submission
- change a submission's status
- modify a program or its scope
- submit a report

Disclosure is the researcher's own act, performed by hand through the program's
channel. SRO writes the report to a local file and stops there.
