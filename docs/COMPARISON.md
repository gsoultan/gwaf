# gwaf compared

Last checked: **August 2026**. Competitor facts move; re-verify before quoting.

This document exists because "how does it compare" is the first question anyone
asks, and the honest answer has a lot of "different category" in it. What
follows separates the claims that are **measured**, the ones that are
**structural** (true by construction, no measurement needed), and the ones that
are **unmeasured** — including several where gwaf is behind.

**Nothing here is a head-to-head benchmark.** gwaf has never been run against
another WAF on the same corpus and the same hardware. Every performance number
below is gwaf's own, reproducible with `make bench-publish`; no competitor
number is quoted as a comparison, because we have not earned one.
[docs/BENCHMARKS.md](BENCHMARKS.md) lists this as a known gap.

---

## 1. They are not all the same kind of thing

The single most useful distinction, and the one most comparison tables skip:

| | Shape | You deploy | Detection engine |
|---|---|---|---|
| **gwaf** | Go **library** | your binary, `import` | own (structural + schema) |
| **Coraza** | Go **library** | your binary, `import` | own (SecLang/CRS interpreter) |
| **CrowdSec** | agent + bouncer | a daemon beside your proxy | **Coraza**, plus its own rules |
| **SafeLine** | reverse proxy | a container in front | own (semantic, closed) |
| **open-appsec** | proxy attachment | nginx/Envoy/Kong add-on | own (ML) |
| **ModSecurity** | C module | web-server module | own (SecLang interpreter) |
| **Sophos Firewall WAF** | appliance | hardware/virtual firewall | own (closed) |

**gwaf competes directly with exactly one of these: Coraza.** Everything else is
a different deployment shape solving an overlapping problem. If you want a box
in front of your network, gwaf is the wrong tool and Sophos is a reasonable one.
If you want to embed detection *inside* a Go service, Coraza and gwaf are the
only two options and the rest are not in the running.

Worth stating plainly: **CrowdSec's AppSec module is powered by Coraza.** It is
not a competing detection engine — it is Coraza plus crowd-sourced reputation,
remediation, and a bouncer architecture. Comparing gwaf's detection to
CrowdSec's is comparing it to Coraza's.

---

## 2. Where gwaf is structurally different

These are true by construction and need no benchmark.

### Zero third-party dependencies in core

`gwaf` core imports only the standard library and `golang.org/x`. Coraza does
not, and cannot easily: SecLang parsing, its regex handling, and its
audit/logging paths pull in a dependency graph that every embedder inherits.

This is not aesthetic. Everything in your dependency graph is something you must
patch, audit, and answer for. gwaf's ten-module split exists to make this
enforceable rather than aspirational — SecLang, OpenAPI YAML, protobuf, and
every framework adapter live outside core, and `make deps` fails the build if a
third-party import appears in core. Verify it yourself:

```
make deps    # core module dependencies: 0 third-party
```

### Compiler, not interpreter

Every SecLang engine walks a rule list per request. gwaf compiles rules,
schemas, and route policies into an execution plan once, then a literal
prefilter decides what to evaluate before any rule runs.

The measurable consequence is **ruleset scaling**:

| Rules | Latency | Rules evaluated |
|---|---|---|
| 10 | 233 ns | 0 |
| 10,000 | **233 ns** | **0** |

A thousand-fold larger ruleset costs the same. This is gwaf's own measurement,
not a comparison — but it is the property that a per-request rule walk cannot
have by construction, whatever its constant factor.

### The CVE that motivated the design

**CVE-2026-21876** (CVSS 9.3, disclosed 6 January 2026) broke CRS 3.0.0–4.21.0
across **ModSecurity v2, ModSecurity v3, and Coraza simultaneously**. Rule
922110 validated the charset of only the *last* multipart part, because chained
rules overwrite capture variables on each iteration. An attacker put UTF-7
JavaScript in the first part and legitimate UTF-8 in the last.

That one bug hitting three independent engines is the argument: it was not an
implementation slip, it was the rule *language* making single-interpretation
matching the natural thing to write. gwaf's invariant — canonicalization is
multi-interpretation, every plausible backend decoding is evaluated, every
multipart part is inspected — exists specifically so this bug class has nowhere
to live. UTF-7 multipart evasion is in the evasion corpus and fails the build if
it ever stops being caught.

**The honest caveat:** gwaf has not survived the adversarial attention that CRS
has had for twenty years. Being immune to one known bug class is not the same as
being more secure overall.

### Typed, compile-checked rules

Rules are Go values. A typo in a target name is a build failure, not a rule that
silently never fires at 3 a.m. SecLang cannot offer this; it is a string
language parsed at runtime.

```go
rules.Rule{
    ID:         1_000_001,
    Phase:      types.PhaseRequestHeaders,
    Targets:    []types.Target{{Kind: types.TargetRequestPath}},
    Op:         op.HasPrefix("/internal/"),
    Confidence: types.Certain,
}
```

### Confidence is measured, not asserted

`gwaf calibrate` measures every rule's false-positive rate against a
10,430-request benign corpus and **fails the build** when a rule exceeds its
declared tier's ceiling. Paranoia levels in CRS are authored numbers; nothing
measures them.

The corpus also reports its own statistical power — it states the smallest
false-positive rate it is capable of observing (currently 0.0096%), so a clean
run cannot be mistaken for a stronger claim than it is.

---

## 3. Where gwaf is behind, and it is not close

Stated plainly, because a comparison that only lists wins is marketing.

| | gwaf | Mature alternatives |
|---|---|---|
| **Production deployments** | **none known** | Coraza, CrowdSec, Sophos all run in production at scale |
| **Version** | pre-1.0, API may break | Coraza v3 stable; Sophos shipping for years |
| **Ready-to-run proxy** | `proxy/` (reference, ~325 LOC) | SafeLine, CrowdSec, Sophos ship more featureful ones |
| **Rule ecosystem** | 66 first-party rules | CRS is thousands of rules, twenty years of tuning |
| **Managed rule updates** | none | CrowdSec ships crowd-sourced blocklists; vendors ship managed rules |
| **Commercial support** | none | Sophos, CrowdSec, Wallarm, Imperva |
| **Adversarial track record** | one session of self-testing | CRS has had two decades of public bypass research |
| **Non-Go embedding** | none | Coraza has WASM/Envoy/Caddy/Traefik connectors |

The proxy gap **has since been closed**: `proxy/` is a reference reverse proxy
that fronts a PHP, Python, or Node application, verified end to end against a
WordPress-shaped target. It is deliberately minimal — glue over the library, no
config format, no plugin system — so it is a starting point rather than a
competitor to SafeLine's or CrowdSec's deployment tooling.

What remains genuinely behind is everything around detection: no known
production deployments, a pre-1.0 API, 66 rules against twenty years of CRS
tuning, no managed rule updates, and no commercial support.

---

## 4. Capability matrix

Detection capability, as of August 2026. gwaf's column is verified by its own
corpus (`make corpus`); other columns are from vendor documentation and are
**not** independently tested here.

| | gwaf | Coraza + CRS | CrowdSec | SafeLine | open-appsec | Sophos |
|---|---|---|---|---|---|---|
| Embeddable Go library | **yes** | yes | no | no | no | no |
| Zero third-party deps | **yes** | no | no | n/a | n/a | n/a |
| Structural/semantic detection | **yes** | no (regex) | no (regex) | yes | ML | partial |
| Typed compile-checked rules | **yes** | no | no | no | no | no |
| Measured confidence tiers | **yes** | no | no | no | n/a | no |
| Per-request fuel budget | **yes** | no | no | no | no | no |
| OpenAPI positive security | **yes** | no | no | partial | partial | form/URL hardening |
| GraphQL depth/complexity | **yes** | no | no | partial | no | no |
| gRPC/protobuf inspection | **yes** | no | no | no | no | no |
| Explainable decisions | **yes** | yes | yes | partial | **weak (ML)** | partial |
| CRS/SecLang compatibility | adapter module | **native** | **native** | no | no | no |
| Cross-request reputation | **no — by design** | no | **yes** | partial | yes | yes |
| Rate limiting / bot mgmt | **no — by design** | no | **yes** | yes | yes | yes |
| Crowd-sourced threat intel | **no** | no | **yes** | no | no | yes |
| Managed rule updates | **no** | CRS releases | **yes** | yes | yes | yes |
| Deployable today, no code | **yes** (`proxy/`) | via connectors | **yes** | **yes** | **yes** | **yes** |

The "no — by design" rows are the scope line, not gaps. gwaf answers *"is this
request an attack?"* using one request and no memory. Rate limiting, reputation,
and bot scoring need state across requests and belong to the embedder — they
arrive back through the `Resolver` interface, so gwaf *consumes* a reputation
score it never maintains. CrowdSec is genuinely better at those things because
that is what CrowdSec is.

---

## 5. Which should you use

**Use Coraza if** you need CRS compatibility today, you are migrating from
ModSecurity, you want an engine with production mileage, or you need to embed in
something other than Go via WASM/Envoy.

**Use CrowdSec if** the threat you care about is distributed and behavioural —
credential stuffing, scanning, botnets — and you want crowd-sourced blocklists
and remediation. Its detection engine is Coraza; you are choosing the platform
around it.

**Use SafeLine or open-appsec if** you want a self-hosted reverse proxy you can
deploy this afternoon without writing code, and you are comfortable with a
closed engine (SafeLine) or with reduced explainability (open-appsec's ML).

**Use Sophos if** you are buying a network appliance and the WAF is one feature
among many — and note that no library on this page competes with it.

**Use gwaf if** you are building a Go service and want detection *inside* it
with zero inherited dependencies, you can describe your API and want positive
security to make the WAF both faster and stricter, you need per-request latency
you can put in an SLO, or you want every block explainable with a rule ID and a
matched byte span. **Do not use gwaf if** you need a drop-in proxy today, CRS
rule compatibility, commercial support, or a track record.

---

## 6. What would make this document better

The comparison this repository actually owes, and does not yet have:

1. **A head-to-head benchmark.** gwaf and Coraza, same corpus, same hardware,
   published methodology, re-runnable by a reader. Coraza's own benchmark page
   has been "under renovation" since April 2026; that vacuum is ours to fill,
   and only with numbers that survive scrutiny.
2. **A shared detection corpus.** Running gwaf's 216-case evasion corpus against
   Coraza + CRS and publishing both detection *and* false-positive rates. A
   detection number without an FP number beside it is not a result.
3. **An independent audit.** Everything in section 2 is self-reported.

Until those exist, treat this document as a map of the design space rather than
a scoreboard.

---

## Sources

- [OWASP Coraza](https://github.com/corazawaf/coraza) · [coraza.io](https://www.coraza.io/docs/tutorials/introduction/)
- [CrowdSec AppSec component](https://docs.crowdsec.net/docs/appsec/intro/) · [architecture](https://deepwiki.com/crowdsecurity/crowdsec/5.4-appsec-and-waf-module)
- [CVE-2026-21876, CRS project advisory](https://coreruleset.org/20260106/cve-2026-21876-critical-multipart-charset-bypass-fixed-in-crs-4.22.0-and-3.3.8/)
- [F5: NGINX ModSecurity WAF end-of-life](https://www.f5.com/company/blog/nginx/f5-nginx-modsecurity-waf-transitioning-to-eol)
- [Sophos Firewall WAF rules](https://docs.sophos.com/nsg/sophos-firewall/21.5/Help/en-us/webhelp/onlinehelp/AdministratorHelp/RulesAndPolicies/WebServerProtection/WAF/Rules/index.html)
- [open-appsec](https://www.openappsec.io/post/how-to-switch-to-a-modsecurity-waf-alternative-before-it-is-eol-in-march-2024)
