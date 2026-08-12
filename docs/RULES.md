# gwaf Rule System

How rules are authored, compiled, extended, and kept honest.

The governing constraint: **gwaf is a library, so most rules will be written by people who don't
work on gwaf.** Every design choice below follows from that. See [CLAUDE.md](../CLAUDE.md) for the
architecture the rule system plugs into.

---

## 1. Principles

1. **One IR, three frontends.** Go structs, declarative files, and SecLang all compile to the same
   `rules.IR`. Nothing the SecLang adapter can express is unreachable from Go. If a frontend needs
   IR the others can't produce, that's an IR gap, not a frontend feature.
2. **Rules are data, not code — until they aren't.** The canonical form is a plain struct: it
   serializes, diffs, generates, and tests. A raw Go predicate escape hatch exists, and carries
   explicit costs (§5, §6).
3. **A custom rule cannot silently break the latency SLO.** The performance contract is part of the
   rule API, not a doc footnote.
4. **Every rule is explainable and testable in isolation.** A rule that can't produce a matched span
   is not a rule.

---

## 2. The IR

```
Frontends                          Core
─────────────────────────────────  ──────────────────────────────
rules.Rule{...}      (Go)       ┐
gwaf.yaml            (ops)      ├──►  rules.IR  ──►  Compiler  ──►  Ruleset
SecLang / CRS        (adapter)  ┘                       │              │
                                                        │              ├─► prefilter automaton
                                                        │              ├─► phase-ordered plan
                                                        └─ validate    └─► literal/cost report
```

`Ruleset` is immutable and safe for concurrent use. Compilation is the only place rules are
validated, literals extracted, and cost estimated — so all three frontends get identical guarantees.

---

## 3. Authoring in Go

The canonical form is a struct literal. Not a fluent builder: structs compose, serialize, diff, and
codegen; builders do none of those well and add a state machine to get wrong.

```go
var scannerUA = rules.Rule{
    ID:    1_000_101,
    Phase: types.PhaseRequestHeaders,
    Targets: []rules.Target{
        rules.Header("User-Agent"),
    },
    Transforms: []rules.Transform{transform.Lowercase, transform.RemoveWhitespace},
    Op:         op.ContainsAny("sqlmap", "nikto", "acunetix"),
    Actions:    []rules.Action{action.Block},
    Severity:   types.SeverityCritical,
    Msg:        "Known scanner user-agent",
    Tags:       []string{"scanner", "reputation"},
}
```

Composition is ordinary Go — slices, loops, helper funcs:

```go
func denyHeaderValues(id types.RuleID, header string, vals ...string) rules.Rule { ... }

ruleset := rules.Set{
    scannerUA,
    denyHeaderValues(1_000_102, "X-Forwarded-Host", untrustedHosts...),
}
```

Wire it up:

```go
waf, err := gwaf.New(
    gwaf.WithRuleset(ruleset),
    gwaf.WithCoreRuleset(core.Default),      // first-party, embedded
    gwaf.WithBudget(gwaf.Budget{PerRequest: 200 * time.Microsecond}),
)
```

`gwaf.New` returns an error on any invalid rule. **Compilation is total** — there is no partially
loaded ruleset, and no rule is silently skipped.

### Declarative form

Isomorphic to the struct, for teams shipping rules without a rebuild:

```yaml
rules:
  - id: 1000101
    phase: request_headers
    targets: [{ header: User-Agent }]
    transforms: [lowercase, remove_whitespace]
    op: { contains_any: [sqlmap, nikto, acunetix] }
    actions: [block]
    severity: critical
    msg: Known scanner user-agent
    tags: [scanner, reputation]
```

Same validator, same compiler, same guarantees. The only thing this form cannot express is
`op.Func` (§5) — arbitrary Go can't come from a config file, by design.

---

## 4. Extension points

**Four interfaces.** Implement any of them in your own package; no fork, no `internal/` access —
and that second clause is load-bearing, so `test/extension` is a module declaring itself
`example.com/gwafvendor` that implements all four from outside the gwaf import path. Go's
internal-package rule is keyed on import path, so a public interface returning an unexported type
compiles for every in-tree implementation and is impossible for a vendor. That happened to
`Operator.Cost()` and nothing in the tree could see it.

```go
// Operator decides whether a transformed value matches.
type Operator interface {
    Name() string
    Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool)
    Literals() ([]string, bool)   // see §5 — the performance contract
    Cost() types.Fuel             // priced in the same units the engine meters
}

// Transform normalizes a value before evaluation. Must be pure and allocation-free
// when the value is already normalized (return the input slice unchanged).
type Transform interface {
    Name() string
    Apply(dst, src []byte) ([]byte, bool)   // bool: whether anything changed
    MaxOutputLen(n int) int                 // so the engine sizes scratch up front
}

// Action runs when a rule matches. The Outcome says whether evaluation stops.
type Action interface {
    Name() string
    Run(ctx *rules.EvalContext, m rules.Match) rules.Outcome
}

// Resolver supplies values gwaf deliberately does not compute.
type Resolver interface {
    Name() string
    Resolve() iter.Seq2[string, []byte]
}
```

`Action.Run` takes an `*EvalContext` rather than a `*gwaf.Transaction`: `rules` is imported *by*
`gwaf`, so the reverse would be an import cycle, and handing an action the whole transaction would
give it powers an action has no business having.

A runnable walk through all of it — a struct-literal rule, `op.Func` with and
without a hint, a custom `Operator`, `Transform`, `Action`, and `Resolver`, and
an `Exception` — is `examples/customrules`. It is a test as well as an example,
so the behaviour its comments describe is the behaviour CI checks.

### What an extension may trust

`EvalContext` is the only thing an `Operator` or `Action` sees beyond the value, and it mixes two
kinds of data that look identical in Go and are not the same at all. **Reading the wrong one turns
a rule into a bypass**, so the split is stated here rather than left to be inferred.

| Field | Source | Trust |
|---|---|---|
| `Target`, `Key` | engine | **Trustworthy.** Derived from how gwaf parsed the request, not from its bytes. |
| `Origins` | embedder, via `gwaf.WithOrigins` | **Trustworthy.** Configuration. The one field an attacker cannot reach. |
| `Method`, `RequestURI`, `Host` | the request | **Attacker-controlled.** |
| `Siblings` (names and values) | the request | **Attacker-controlled.** |

The rule that follows is short:

> Attacker-controlled context is **evidence**, never **ground truth**. It may raise suspicion. It
> may never be the thing that clears a value.

The difference is the direction the field points. `Siblings` used to *convict* — `path=/etc/` plus
`target=passwd` is worse than either alone, and an attacker gains nothing by supplying it — is
sound. `Host` used to *acquit* — "this destination matches the Host, so it is same-origin" — is a
bypass, because the attacker supplies both sides and simply sets them equal.

That is not hypothetical. `OffOriginURLRule` shipped in v0.4.0 doing exactly that, was enabled by
default on the strength of it, and `Host: evil.tld` with `redirect_to=https://evil.tld/` walked
through. It is fixed in v0.4.1 by comparing against `Origins` instead, and the rule now reports
nothing when no origins are declared — because a destination cannot be shown foreign without
something trustworthy to be foreign to, and silently falling back to `Host` would be a guarantee
the request can revoke.

Three consequences worth stating for anyone writing an extension:

- **Needing to acquit means needing configuration.** If a rule's decision requires knowing something
  about the deployment — which hosts are ours, which tenants exist, which routes are internal — that
  knowledge is the embedder's. Take it as an option, not from a header.
- **A rule with no trustworthy input should report nothing, not guess.** Absence of evidence is the
  safe direction for anything in the default set.
- **`Resolver` is where out-of-scope signals arrive** (§4 above), and the same rule applies to what
  it returns: a reputation score the embedder computed is trustworthy, one derived from a header the
  client sent is not.

These four interfaces freeze at v1.0. The table freezes with them, so a change to which column a
field sits in is a breaking change to the security model even when the type signature is untouched.

### Registration

`Operator`, `Transform`, and `Action` are values on a rule — a rule literal names the ones it uses,
so nothing needs registering and nothing can be registered twice:

```go
rules.Rule{
    Op:         myFuzzyOp{},
    Transforms: []rules.Transform{myNormalizer{}},
    Actions:    []rules.Action{myAuditAction{}},
}
```

`Resolver` is registered **per transaction**, because it almost always closes over data specific to
one request — the score *this* client got — and a `WAF` is shared by every goroutine:

```go
tx.AddResolver(myReputation{score: score, asn: asn})
```

It is called only if a rule in the phase reads its name, and at most once per request. That is why
it is an interface rather than a setter: a signal is usually outside gwaf's scope *because* getting
it is expensive, so paying for it when nothing reads it would undo the reason for keeping it out.

### Why `Resolver` matters more than it looks

It is the entire mechanism behind the scope line in §1 of CLAUDE.md. gwaf analyses one request with
no memory, so rate limits, reputation, bot scores, and TLS fingerprints belong to the embedder —
and that boundary only works if the *results* of the embedder's work have a way back in. Without a
Resolver, rules can only ever match bytes gwaf read off the wire, and "out-of-scope signals arrive
as Resolver inputs" is a sentence with no implementation behind it.

A rule reads them with `types.TargetResolved`. Keys are qualified by resolver name, so a rule can
select a whole collection or one value in it:

```go
Targets: []types.Target{{Kind: types.TargetResolved, Name: "reputation"}}      // all of it
Targets: []types.Target{{Kind: types.TargetResolved, Name: "reputation.asn"}}  // one value
```

### A note on semantic detectors

Earlier drafts of this document listed a fifth interface, `Detector`, "plugging into the L1 semantic
tier rather than the rule tier". There is no such tier in the engine: it dispatches through
`Operator.Eval` and nothing else, and all six first-party detectors — `detect/sqli`, `detect/xss`,
`detect/shelli`, `detect/ssti`, `detect/nosqli`, `detect/ldapi` — expose exactly that:

```go
func Operator() rules.Operator
```

A third party writing a semantic detector implements `Operator` the same way. Defining a second
interface that reaches the same dispatch would be describing an architecture nobody built, and
counting it would make this document claim five extension points while shipping four.

---

## 5. The prefilter contract

This is the part most rule APIs get wrong, and it's why `Literals()` is on the `Operator` interface
rather than inferred.

L0 builds one Aho-Corasick automaton over literals extracted from every rule. A rule is only
evaluated if its required literals appear in the request. That's what makes benign traffic cost
almost nothing.

```go
Literals() ([]string, bool)
```

The bool means **"these literals are required — if none appear, this operator cannot match."**

| Operator | Extraction | Cost |
|---|---|---|
| `op.Contains("sqlmap")` | `["sqlmap"], true` | prefiltered — free on benign traffic |
| `op.ContainsAny(a, b, c)` | `[a,b,c], true` | prefiltered |
| `op.Regex("(?i)union\\s+select")` | `["union"], true` (RE2 required-literal analysis) | prefiltered |
| `op.Regex(".*")` | `nil, false` | **unconditional — runs on every request** |
| `op.Func(myPredicate)` | `nil, false` | **unconditional** |
| `op.Func(name, f).WithLiterals("__schema")` | `["__schema"], true` | prefiltered, hint is a promise |

`WithLiterals` is an assertion you are making to the compiler: *if none of these bytes are present,
my predicate cannot match.* If that's wrong, your rule silently stops firing. It is the one place
in the API where you can lie to the engine, and it's marked as such.

**The assertion is fuzzed, not trusted.** Every first-party detector carries a
`FuzzLiteralsAreExhaustive`, and `ruleset/core` carries one over every rule: if an operator reports
on a value containing none of its declared literals, the build fails. Write the same harness for
your own rules — the failure it catches is invisible from every other direction, because the rule
compiles, lints, and `gwaf explain` describes it correctly right up until you notice it has never
fired.

Three real examples from this codebase, all found by that harness or by the hand-probing it replaces:

- `core.offOriginOp` declared `"://"` while its matcher accepted the protocol-relative `"//host"`.
  Every scheme-omitted open redirect was undetectable in a shipping core rule.
- `detect/xss` never declared `"("`, and `SignalScriptBreakout` requires a call on every path. A
  whole signal was dropped by the automaton before the detector ran.
- `detect/shelli` reasoned that its weak signals "never fire alone and always need a separator
  alongside" — true at the default threshold of 5, and false at the Medium tier's 3, where one
  weighs exactly enough. **A contract checked on one instance of a configurable thing is not
  checked.**

**The compiler reports this, and the linter enforces it:**

```
$ gwaf lint ./rules
ruleset: 214 rules, 209 prefiltered, 5 unconditional
  1000340  op.Func           unconditional  ~1.9µs/req  no literal hint
  1000341  op.Regex(".*")    unconditional  ~0.4µs/req  regex has no required literal
warn: unconditional rules add ~4.7µs to every request (budget: 200µs, 2.4%)
```

Unconditional rules are legitimate — rate limiting and reputation checks genuinely must run every
time. The point is that their cost is **visible at build time** rather than discovered in a p99
graph. `gwaf lint` fails CI above a configurable unconditional budget.

---

## 5b. Rules that ship exported rather than enabled

Some rules are right for most deployments and not all, and shipping them enabled would break a
working integration on somebody's first deploy. They are exported instead, with the trade measured
rather than asserted:

| Rule | Why it is not on by default |
|---|---|
| `core.SSRFParamRule` | handing a server a foreign URL *is* webhook registration, feed import, avatar fetch |
| `core.SQLSinkRule` | a reporting tool takes SQL by design; the benign corpus carries one |
| `core.PathSinkRule` | a file manager navigates with `../` because navigating is the product |
| `core.CommandSinkRule` | `cmd=` is a verb in half of all admin UIs, not always a shell |
| `core.LoopbackSSRFRule` | `localhost` is ordinary in CI, staging and tunnelled webhooks |
| `core.CRLFHeaderRule` | needs a transform chain no other rule shares — 8% of the latency budget |
| `core.WordPressHardeningRule` | a minority of plugins expose endpoints under `wp-content` |

Each is the **Ownership test** from CLAUDE.md §1: whether *this* application fetches user URLs,
resolves user paths, or shells out is something the embedder knows and gwaf cannot learn from one
request.

### Two ways to lose coverage silently

Both are reported by `(*gwaf.WAF).Diagnostics()`, which exists because both shipped and neither was
visible.

**An opt-in rule gets no request-body counterpart.** `core.Default()` mirrors its argument rules
into the body phase; a rule you add through `WithRuleset` is compiled exactly as written. Declared
at `PhaseRequestHeaders` it sees the query string and *never a JSON body* — which is where webhook
and import endpoints put everything. Wrap them:

```go
waf, err := gwaf.New(
    gwaf.WithOrigins("api.example.com"),
    gwaf.WithRuleset(core.WithBodyPhase(rules.Set{
        core.SSRFParamRule(1016),
        core.SQLSinkRule(2011),
        core.PathSinkRule(1017),
    })),
)
```

`CommandSinkRule` is the exception and needs no wrapper: it keys on the argument *name*, and the
body phase populates the same argument collection.

**The off-origin rules need to know who you are.** Without `WithOrigins` they compile, lint clean,
and report nothing — there is no "here" for a destination to be foreign to, and the request's own
`Host` header is attacker-supplied so it cannot stand in. That is the safe direction and a terrible
user experience, so `gwaf.New` says so once and `Diagnostics()` returns it as data:

```go
for _, d := range waf.Diagnostics() {
    log.Warn("coverage gap", "rule", d.ID, "reason", d.Reason, "fix", d.Fix)
}
```

An empty result is the healthy answer. A non-empty one is not an error — you may have declined a
capability deliberately — but every entry is coverage that is configured, believed to be active,
and silent.

---

## 6. Safety model

Custom rules are third-party code in our hot path. CLAUDE.md says the library never panics; user
predicates have no such discipline. Reconciliation:

**Panic containment is scoped, not blanket.** Built-in operators are provably panic-free and run
with no recovery overhead — `defer` is banned on the hot path for good reason. Only `op.Func` and
custom `Operator` implementations are invoked through a recovering boundary. You pay for isolation
only if you use the escape hatch.

**Per-rule budget + quarantine.** Every rule evaluation is charged against the transaction budget.
A rule that repeatedly exceeds `MaxRuleDuration`, or that panics, is quarantined:

```go
gwaf.WithRuleGuard(gwaf.RuleGuard{
    MaxRuleDuration: 20 * time.Microsecond,
    Strikes:         5,               // exceed N times → quarantine
    OnQuarantine: func(id types.RuleID, reason error) {
        slog.Error("rule quarantined", "rule", id, "reason", reason)
    },
})
```

Quarantine is loud: a metric, a callback, and an entry in the audit stream. A degraded WAF that
nobody knows about is worse than one that fails cleanly.

**Ordering is deterministic.** Rules evaluate in `(phase, ID)` order, always. No map iteration, no
registration-order dependence. Two runs of the same ruleset over the same request produce the same
decision, which is what makes rules testable and audit logs trustworthy.

---

## 7. ID namespaces

Numeric IDs, because CRS and the entire tooling ecosystem assume them.

| Range | Owner |
|---|---|
| `1 – 99,999` | gwaf core ruleset (reserved) |
| `100,000 – 899,999` | first-party optional bundles |
| `900,000 – 999,999` | OWASP CRS, preserved verbatim through the adapter |
| `1,000,000+` | **your rules** |

The compiler rejects collisions and rejects user rules in reserved ranges. Preserving CRS IDs
verbatim matters: it means every CRS tuning guide, blog post, and Stack Overflow answer on the
internet still applies after migration.

---

## 8. Confidence and policies (instead of paranoia levels)

**gwaf has no paranoia levels in the engine.** CRS's PL1–PL4 is not an engine feature even in
ModSecurity — it's a rule-tagging convention implemented by CRS rules testing a `tx.paranoia_level`
variable. Baking it into the engine would import a CRS-specific idea and, worse, a blunt one:

- **It's global, but false-positive tolerance is per-route.** `/api/search` and
  `/admin/query-console` need different strictness on the same deployment. One dial can't do that.
- **It conflates two orthogonal things:** how aggressive detection is, and how much evidence is
  needed to block.
- **It doesn't fit semantic detectors.** A parser returns a confidence from its parse result. "This
  is paranoia level 3" is a category error for a tokenizer.

The primitive instead: every rule declares a **confidence** — how likely a match is a true positive.

| Confidence | Meaning | CRS equivalent |
|---|---|---|
| `Certain` | No known false positives. Safe to block anywhere. | — |
| `High` | Rare FPs, well-understood. Default blocking tier. | PL1 |
| `Medium` | FPs on unusual-but-legitimate traffic. | PL2 |
| `Low` | Heuristic. Expect tuning. | PL3 |
| `Heuristic` | Research-grade. Detection-only unless you've tuned it. | PL4 |

Policies select rules by confidence, tag, and route — and carry their own threshold and mode:

```go
gwaf.WithPolicies(
    gwaf.Policy{
        Name:          "default",
        Match:         gwaf.Any(),
        MinConfidence: rules.High,
        Threshold:     5,
        Mode:          gwaf.Blocking,
    },
    gwaf.Policy{
        Name:          "admin-console",       // legitimately sends SQL
        Match:         gwaf.PathPrefix("/admin/query"),
        MinConfidence: rules.Certain,
        Mode:          gwaf.Blocking,
    },
    gwaf.Policy{
        Name:          "public-upload",       // hostile by assumption
        Match:         gwaf.PathPrefix("/upload"),
        MinConfidence: rules.Low,
        Threshold:     3,
        Mode:          gwaf.Blocking,
    },
)
```

This is strictly more expressive than PL: PL is the special case where one policy matches every
route. It's also *semantically meaningful* — "only run rules that are at least this trustworthy"
beats an arbitrary 1–4 scale nobody can define precisely.

**Paranoia levels still work, as a preset.** The CRS adapter maps `paranoia-level/N` tags onto
confidence, so existing CRS knowledge transfers:

```go
gwaf.WithPolicies(
    crs.ParanoiaLevel(1).On(gwaf.Any()),
    crs.ParanoiaLevel(3).On(gwaf.PathPrefix("/legacy")),
)
```

**Performance note:** policies are resolved at plan-compile time, not per request. Each policy gets
its own prefilter automaton and rule plan; route matching picks one, and the cost is a prefix-tree
lookup. Raising strictness on one route costs nothing on the others — unlike a global PL bump, which
taxes every request in the deployment.

---

## 9. Exceptions and tuning

False-positive tuning is where WAF teams actually spend their time, so it's a first-class API rather
than a "just disable the rule" afterthought.

```go
gwaf.WithExceptions(
    // Surgical: one rule, one path, one target.
    gwaf.Except(942100).
        On(gwaf.PathPrefix("/api/v1/markdown")).
        For(rules.Body()),

    // Whole tag, one route.
    gwaf.ExceptTag("sqli").On(gwaf.PathExact("/admin/query-console")),

    // Threshold override rather than a disable.
    gwaf.Threshold(gwaf.InboundAnomaly, 12).On(gwaf.HostSuffix(".internal")),
)
```

Three deliberate choices:

- **Exceptions are scoped by default.** `Except(942100)` alone is a compile error; you must say
  where. Global disables are how WAFs quietly become decorative.
- **Exceptions are data**, so they diff in review. A PR that widens an exception is visible.
- **Narrow the target, don't kill the rule.** `For(rules.Body())` keeps 942100 live on query
  strings and headers.

`gwaf explain` traces why a request was blocked and prints the narrowest exception that would have
allowed it — turning FP triage from archaeology into a command.

---

## 10. Lifecycle and hot reload

```go
rs, err := rules.CompileFile("rules/prod.yaml")   // validate off the hot path
if err != nil { return err }                       // reject bad rulesets before they go live
waf.SwapRuleset(rs)                                // atomic pointer swap
```

Compile and swap are separate on purpose. Validation happens before anything is live, and the swap
itself cannot fail. In-flight transactions finish on the ruleset they started with — **no request
ever sees a half-applied ruleset**, which would otherwise make audit logs unreconstructable.

---

## 11. Testing rules

Rules ship with tests or they don't ship.

```go
func TestScannerUA(t *testing.T) {
    rules.Test(t, scannerUA, []rules.Case{
        {Name: "sqlmap", Req: rules.Req().Header("User-Agent", "sqlmap/1.7"), Want: rules.Match},
        {Name: "spaced", Req: rules.Req().Header("User-Agent", "sql map"),   Want: rules.Match},
        {Name: "benign", Req: rules.Req().Header("User-Agent", "Mozilla/5"), Want: rules.NoMatch},
    })
}
```

Also available: `go-ftw`-compatible YAML tests (so CRS's existing suite runs against the adapter),
and `rules.Fuzz(f, rule)` to assert a rule never panics and never exceeds its duration budget on
arbitrary input.

**Every custom-rule test asserts both directions.** A rule with only true-positive cases is how FP
rates get discovered in production.

---

## 12. Distribution

Rulesets are distributable artifacts, not copy-paste:

- `rules.Bundle` — versioned set + metadata + tests, `go:embed`-able or loaded at runtime.
- Go module distribution for free: a rule pack is just a package exporting a `rules.Set`.
- OCI artifact push/pull for ops-managed bundles (`gwaf bundle push`).
- Signed bundles with signature verification at load. Rules are code paths in a security control;
  unsigned remote rules are a supply-chain hole.

---

## 13. Untrusted rules (Phase 6+)

For multi-tenant platforms where rules come from *customers*, `WithRuleGuard` isn't enough — it
contains accidents, not adversaries.

Planned: WASM-sandboxed operators via **wazero** (pure Go, preserves the zero-CGO invariant), with
per-tenant fuel limits and no host access. This is a real differentiator — it's the SaaS-platform
use case that no embeddable WAF library currently serves — but it is deliberately deferred until the
core detection story is proven.

---

## Summary: three tiers of custom rule

| Tier | Form | Prefiltered | Sandboxed | Use when |
|---|---|---|---|---|
| **Declarative** | YAML/JSON | yes | n/a | Ops-owned, hot-reloadable, no rebuild |
| **Typed Go** | `rules.Rule` struct | yes | n/a | App-specific logic, compile-checked — **the default** |
| **Predicate** | `op.Func` | only with hint | recovering boundary | Genuinely dynamic logic; costs latency and isolation overhead |

Reach for the lowest tier that works.
