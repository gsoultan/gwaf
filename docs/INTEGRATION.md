# Integrating gwaf

gwaf is imported, not deployed. There are three integration profiles, and they want genuinely
different things from the API.

| Profile | Who | Needs | Surface |
|---|---|---|---|
| **A. Protect my service** | ~95% of users | Drop it in, don't think about it | `gwaf.New()` + middleware |
| **B. Embed in my platform** | API gateways, PaaS, service meshes | Multi-tenancy, dynamic rulesets, own telemetry | + transaction API, overlays |
| **C. Build a WAF on gwaf** | Vendors building a product | Compiler API, custom detectors, their own control plane | + `rules.Compile`, extension interfaces, event stream |

---

## Profile A — protect my service

Three lines. This is the contract from CLAUDE.md §2b, and it's testable.

```go
package main

import (
	"log"
	"net/http"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/middleware"
)

func main() {
	waf, err := gwaf.New()          // core ruleset, blocking, safe defaults
	if err != nil {
		log.Fatal(err)
	}
	defer waf.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders", handleOrders)

	log.Fatal(http.ListenAndServe(":8080", middleware.HTTP(waf)(mux)))
}
```

`gwaf.New()` with no arguments is a working WAF: core ruleset loaded, `Blocking` mode, conservative
`Certain`/`High` confidence rules only. No config files, no ruleset downloads, no tuning phase.

### Turning the dials

```go
// Schemas are parsed, not loaded by path: the library never reads a file it
// was not handed. Report says what the document failed to specify.
sch, report, err := openapi.Parse(doc, openapi.Options{})
if err != nil {
	return err
}

waf, err := gwaf.New(
	gwaf.WithSchema(sch),                                // 70–90% plan reduction + positive security
	gwaf.WithRuleset(myAppRules),                        // your rules on top of core
	gwaf.WithMode(gwaf.DetectionOnly),                   // rollout: observe first
	gwaf.WithLogger(slog.Default()),                     // library never makes its own
	gwaf.WithFailMode(gwaf.FailOpen),                    // budget exhausted → allow, loudly
	gwaf.OnDecision(func(d gwaf.Decision) {              // your metrics, your format
		metrics.WAF.With("rule", d.RuleID(), "action", d.Action()).Inc()
	}),
)
```

The embedder decides four things the library refuses to decide for you: **fail mode**, **block
response**, **where logs go**, and **detection vs. blocking**. Everything else has a safe default.

### Custom block response

```go
middleware.HTTP(waf,
	middleware.WithBlockHandler(func(w http.ResponseWriter, r *http.Request, d gwaf.Decision) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(problem{
			Type:   "https://example.com/blocked",
			Detail: "Request blocked by security policy",
			Ref:    d.ID(),        // correlate with your logs; never leak the rule that fired
		})
	}),
)
```

### Frameworks

**`net/http` is the only adapter that ships.** `middleware.Chi`, `Echo`, `Gin`, `Fiber` and
`Connect` are *planned, not yet shipped* — `middleware/` contains `http.go` and nothing else in
v0.1.x. Each is intended to be its own module, so importing the chi adapter would not put echo in
your dependency graph.

Until they land, every one of those frameworks accepts a `func(http.Handler) http.Handler`, which
is exactly what `middleware.HTTP` returns:

```go
r.Use(middleware.HTTP(waf))                   // chi — stdlib middleware signature
e.Use(echo.WrapMiddleware(middleware.HTTP(waf)))
r.Use(gin.WrapH)                              // gin — wrap the handler, not the router
```

The adapters are sugar over this, not capability. Nothing is unreachable without them.

### Two traps the middleware handles for you

**Body double-read.** The handler still needs the body gwaf just inspected. The middleware buffers
up to `MaxBodySize` into the transaction arena and replaces `r.Body` with a reader over it — no
second allocation. Bodies over the limit are rejected, never half-inspected (PERFORMANCE.md §4).

**`ResponseWriter` interface loss.** Wrapping a `ResponseWriter` naively drops `http.Flusher`,
`http.Hijacker`, and `io.ReaderFrom` — which silently breaks SSE, WebSocket upgrades, and
`sendfile`. gwaf's wrapper preserves them by dynamic dispatch. This bug is in most WAF middleware
and it's why streaming endpoints mysteriously buffer.

---

## Profile B — embed in a platform

Skip the middleware; drive the transaction directly. This is the API for gateways, proxies, and
anything that isn't `net/http`.

```go
tx := waf.NewTransaction()
defer tx.Close()                                   // returns the arena to the pool

tx.SetRemoteAddr(remoteAddr)                       // "host:port"
tx.SetRequestLine(method, target, proto)           // target includes the query
for k, v := range headers {
	tx.AddRequestHeader(k, v)
}

// Anything the platform knows and gwaf cannot -- a reputation score, a tenant,
// a fingerprint -- is registered here, per transaction. The engine calls a
// resolver only when a rule in the phase actually reads it.
tx.AddResolver(myReputationResolver)

if d := tx.ProcessRequestHeaders(); d.Blocked() {
	return respond(d)                              // body never read, never parsed
}

// The request body is supplied whole, bounded by Limits.MaxBodySize. Read one
// byte past that bound and hand over what you read: a body truncated to exactly
// the limit is one the engine accepts and inspects, while the remainder reaches
// the origin uninspected.
tx.SetRequestBody(body)

// Run this phase even when there is no body. Query arguments are recorded by
// SetRequestLine and stay visible here, so a rule targeting ARGS only fires if
// the phase is evaluated.
if d := tx.ProcessRequestBody(); d.Blocked() {
	return respond(d)
}

resp := upstream.Do(req)

tx.SetResponseStatus(resp.StatusCode)
for k, v := range resp.Header {
	tx.AddResponseHeader(k, v)
}
if d := tx.ProcessResponseHeaders(); d.Blocked() {
	return respond(d)
}
```

`Decision` is a **value type**, not a nillable pointer — `d.Blocked()`, `d.Allowed()`,
`d.RuleID()`, `d.Confidence()`, `d.MatchedSpan()`. No nil checks, no interface assertions.

The phase order is the performance story from CONCEPT.md: blocking at `ProcessRequestHeaders` means
the body is never read off the socket, never parsed, never transformed.

### Multi-tenancy

Two shapes, and the right one depends on how much tenants differ.

**Shared base + per-tenant overlay** — *planned, not yet shipped.* `rules.Overlay` and
`gwaf.WithOverlay` do not exist in v0.1.x. The intent is that a base ruleset is compiled once and
shared while each tenant contributes a small delta, so 10,000 tenants cost one base plus 10,000
deltas rather than 10,000 rulesets. Until it lands, use separate instances.

**Separate `WAF` instances** — the shipped answer today, and the right one whenever tenants need
entirely different detectors or schemas. This is why "no global state" is a hard rule in
CLAUDE.md §2b: N instances in one process, fully isolated, is a supported configuration, not an
accident.

### Hot reload

```go
// Compile off the hot path. A ruleset that does not compile never goes live.
rs, err := waf.Compile(newRuleSet)                // newRuleSet is a rules.Set
if err != nil {
	return err
}
waf.SwapRuleset(rs)                               // atomic; cannot fail
```

Compilation is separate from installation on purpose: `Compile` is the fallible half and returns a
`*rules.Ruleset`, so `SwapRuleset` has nothing left to reject. A ruleset that does not compile can
never reach traffic.

The library never watches files or polls. *When* to reload is your decision — file watcher, control
plane push, SIGHUP, whatever your platform already does.

---

## Profile C — build a WAF product on gwaf

You get the compiler, not just the runtime.

```go
// Compile in CI and fail the build on what the report says, not at 3 a.m.
rs, err := rules.Compile(append(core.Default(), myVendorRules...), rules.Options{})
if err != nil {
	return err
}

report := rs.Report()
report.Rules            // total compiled
report.Prefiltered      // how many only run when their literals appear
report.Unconditional    // the ones that run on every request in their phase
report.Literals         // distinct prefilter literals
report.AutomatonStates  // prefilter memory proxy
```

`Unconditional` is the one to gate on. A rule that cannot be prefiltered runs on every request in
its phase, which is how a ruleset silently buys latency — CLAUDE.md §2 invariant 6 exists so that
cost is reported at compile time instead of discovered in production.

**Shipping the compiled artifact is *planned, not yet shipped*.** There is no `plan.WriteTo(w)` in
v0.1.x, so the flat, signable, mmap-able artifact described in CONCEPT.md §7 is a design, not an
API. Compile in-process at startup for now; `Compile` is off the hot path either way.

### Your own detectors and operators

The four extension interfaces (RULES.md §4) are the whole point of this profile — implement them in
your package, no fork. There is no registry to register them with, and that is deliberate: a
package-level registry is global state, which CLAUDE.md §2b rules out. An operator reaches the
engine by being *in a rule*, and a rule reaches the engine through `WithRuleset`.

```go
// Your Operator is an ordinary rules.Operator. So is every first-party
// detector -- there is no separate L1 tier for it to be second-class to.
waf, err := gwaf.New(
	gwaf.WithRuleset(rules.Set{
		{
			ID:         1_500_001,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetRequestHeaders, Name: "user-agent"}},
			Op:         myFeedOp{},          // your operator
			Confidence: types.High,
			Actions:    []rules.Action{rules.Block},
		},
		{
			ID:      1_500_002,
			Phase:   types.PhaseRequestBody,
			Targets: []types.Target{{Kind: types.TargetArgs}},
			Op:      sqli.Operator(),        // a first-party detector, same door
		},
	}),
)
```

A `Resolver` is per-transaction rather than per-WAF, because what it resolves — a tenant, a
reputation score, a fingerprint — is a property of the request, not of the engine:

```go
tx.AddResolver(myTenantResolver{})   // engine calls it only if a rule in the phase reads it
```

**Registering an operator under a name, so customers can write `op: { threat_intel: ... }` in YAML
against your operator, is *planned, not yet shipped*.** `gwaf.WithOperator`, `WithDetector` and
`WithResolver` do not exist in v0.1.x. Nothing above is blocked by their absence — the Go rule form
reaches everything; what is missing is the declarative frontend's route to a third-party operator.

### Feeding your control plane

**gwaf ships no UI — but every datum a UI would need is a library API.** That's the resolution of
the "no UI, ever" rule: we don't build the dashboard, we make yours possible.

```go
gwaf.OnDecision(func(d gwaf.Decision) {   // every decision, as it is reached
	myControlPlane.Record(d)              // d.LogValue() is slog-ready
})

exp := d.Explain()             // same data `gwaf explain` prints — as a struct
exp.RuleID()                   // what fired
exp.MatchedSpan()              // the exact bytes, with offsets
exp.MatchedBytes()             // a copy, so it outlives the transaction
exp.TransformChain()           // how the input was normalized to get there
exp.Interpretation()           // which decoding revealed it, if any
exp.NarrowestException()       // the FP fix, computed for you
```

It hangs off the `Decision` you already hold, not off the `WAF`. An earlier
draft of this document specified `waf.Explain(txID)`, and that API cannot exist:
looking a transaction up by ID means the WAF remembers transactions, which is
cross-request state and the first of the five ownership tests. gwaf keeps
nothing between requests, so the explanation travels with the decision.

`MatchedBytes()` is a copy rather than a view into the transaction arena. The
arena is recycled on `Close`, and an explanation that dangles into a reused
buffer would report a different request's bytes with total confidence — worse
than no explanation at all.

`exp.NarrowestException()` returns the tightest exception that would have allowed the request —
serialize it straight into a "suppress this finding" button. FP triage becomes a click instead of
archaeology, and you didn't write the analysis.

Feed it straight back:

```go
x, _ := d.Explain().NarrowestException()
waf, err := gwaf.New(gwaf.WithException(x))
```

The exception is scoped by rule, route, collection, and key, so it silences that
one finding and nothing else — not the same rule on another route, not another
argument on the same route. It also covers the rule's *generated counterparts*:
a body-phase mirror carries a different ID so audit logs stay unambiguous, and
an exception that did not follow the derivation would leave an operator blocked
one phase later by an ID they had never seen.

An exception with no field set is refused rather than honoured. It would disable
every rule everywhere, and that should not be expressible by accident.

If your product needs something the control plane can't get programmatically, that's a **library
API gap** — file it against tier 1 (CLAUDE.md §1). It is never a reason for gwaf to grow a UI.

---

## What the embedder always owns

The library deliberately refuses to decide these, because they're deployment policy, not security
logic:

| Decision | Why it's yours |
|---|---|
| `FailMode` (open/closed) | Availability vs. security is a business call |
| Block response body/status | Your API contract, your error format |
| Log destination and format | You already have one |
| Detection vs. blocking | Depends on where you are in rollout |
| When to reload rules | Your control plane owns lifecycle |
| Tenant → policy mapping | Only you know what a tenant is |

Everything else has a safe default, which is why `gwaf.New()` with zero arguments works.
