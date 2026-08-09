# Security policy

gwaf is a web application firewall. A vulnerability here is not a bug in one
application — it is a bypass in whatever is behind every deployment that
embeds it. This document says how to report one and what happens next.

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through GitHub's advisory workflow:

<https://github.com/gsoultan/gwaf/security/advisories/new>

If that is unavailable to you, email **gembit.soultan@gmail.com** with `[gwaf
security]` in the subject.

A report is most useful with:

- the gwaf version, or the commit;
- the ruleset — `core.Default()`, a CRS import, or your own — and any options
  that differ from `gwaf.New()`;
- a request that reproduces it, verbatim, including the bytes that matter. A
  payload that only reproduces after a proxy has rewritten it is a different
  bug from one that reproduces at the library boundary, and saying which you
  observed saves a round trip;
- what you expected to be blocked, and what happened instead.

You do not need a working exploit chain. "This canonicalisation differs from
what PHP does, and here is the pair of inputs that shows it" is a complete
report.

## What counts

**In scope**

- **A bypass.** Input that reaches an origin unblocked when the configured
  ruleset should have stopped it. This is the important one, and encoding,
  canonicalisation and parser-differential bypasses are the class this project
  exists to be resistant to — CVE-2026-21876 broke CRS across three engines on
  exactly that, and a report of the same shape here is the most valuable thing
  you can send.
- **A false positive that is exploitable as denial of service** — input an
  attacker can put in someone else's traffic to get them blocked.
- **Resource exhaustion.** A request that defeats the fuel meter, the bounded
  buffers or the recursion limits. Every parser and canonicalisation function
  here takes hostile input by design, so anything that makes one of them
  unbounded is a vulnerability, not a performance report.
- **Memory unsafety or a panic in library code.** gwaf never panics in the
  request path; one that does is a crash in the embedder's process.
- A dependency vulnerability reachable through a module gwaf ships.

**Out of scope**

- False positives that are not attacker-controlled. Those are ordinary issues
  and very welcome as such — the benign corpus exists because of them.
- Anything requiring a ruleset the project does not ship, unless the finding
  is in the engine rather than the rule.
- Attacks needing cross-request state — rate limits, credential stuffing, bot
  behaviour. gwaf analyses one request in isolation and says so
  (CLAUDE.md §1); those belong to the embedder.
- Findings against the `proxy/` reference integration used as a production
  proxy. It is ~500 lines of glue and is documented as a reference, not a
  product.

## What happens next

| When | What |
|---|---|
| Within **3 working days** | Acknowledgement that the report arrived. |
| Within **10 working days** | An assessment: reproduced or not, severity, and whether a fix is planned. |
| Within **90 days** | A fix released, or an explanation of why it is taking longer. |

Severity uses CVSS 4.0. A bypass of a `Certain`-confidence rule in the default
ruleset is treated as high by default, because that ruleset is what
`gwaf.New()` loads and most embedders will never change it.

## Disclosure

Coordinated, with a **90-day** default from the acknowledgement date, and
earlier by agreement once a fix is out.

If a bypass is being exploited, the clock is not the point — say so in the
report and the fix is prioritised over the schedule.

Every fixed vulnerability gets:

- a GitHub Security Advisory with a CVE where one is warranted;
- a CHANGELOG entry naming the technique, not just the rule number;
- **a regression test in the evasion corpus.** This is not optional. A bypass
  that is fixed without a test that fails before and passes after is a bypass
  that comes back, and the corpus is how this project keeps its central claim
  honest.

Reporters are credited by name unless they ask not to be.

## Supported versions

Pre-v1.0, security fixes land on the latest minor and are released promptly.
There are no long-term support branches yet; that changes at v1.0.

| Version | Supported |
|---|---|
| latest minor | yes |
| anything older | upgrade |

## Hardening the deployment you run

Two settings decide what a bypass costs you, and both are the embedder's:

- **`FailMode`.** Fail-closed rejects a request that could not be analysed;
  fail-open lets it through. Fail-open is the right default for availability
  and the wrong one if the WAF is your only control.
- **Ruleset scoping.** `rules.Exception` and `ruleset/profiles` narrow a rule
  to a route and a field rather than turning it off. An exception with a
  `Note` is auditable; a disabled rule is not.

## Supply chain

The core module has **zero third-party dependencies** by design, so a
dependency vulnerability cannot reach it. That is not true of the adapter and
integration modules, which is exactly why `make check` runs `govulncheck`
across **all** modules and treats a missing scanner as a failure rather than a
skip. Releases ship an SBOM and SLSA provenance.
