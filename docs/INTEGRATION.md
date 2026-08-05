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
waf, err := gwaf.New(
	gwaf.WithSchema(openapi.MustLoad("openapi.yaml")),   // 70–90% plan reduction + positive security
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

Each in its own module, so importing the chi adapter doesn't put echo in your dependency graph.

```go
r.Use(middleware.Chi(waf))                    // chi
e.Use(middleware.Echo(waf))                   // echo
r.Use(middleware.Gin(waf))                    // gin
app.Use(middleware.Fiber(waf))                // fiber
interceptor := middleware.Connect(waf)        // connect / gRPC
```

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
tx := waf.NewTransaction(ctx)
defer tx.Close()                                   // returns the arena to the pool

tx.SetClient(clientIP, clientPort)
tx.SetRequest(method, uri, proto)
for k, v := range headers {
	tx.AddRequestHeader(k, v)
}

if d := tx.ProcessRequestHeaders(); d.Blocked() {
	return respond(d)                              // body never read, never parsed
}

for chunk := range bodyChunks {
	if d, err := tx.WriteRequestBody(chunk); err != nil {
		return err
	} else if d.Blocked() {
		return respond(d)                          // stop reading from the client
	}
}
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

**Shared base + per-tenant overlay** — preferred. The base ruleset is compiled once, mmap'd, and
shared; each tenant contributes a small delta.

```go
base := rules.MustCompileFile("rulesets/base.gwafc")   // ~16 MB, one resident copy

tenant := rules.Overlay{
	Base:       base,
	Add:        tenantRules,
	Exceptions: tenantExceptions,
	Policies:   tenantPolicies,
}
waf, err := gwaf.New(gwaf.WithOverlay(tenant))
```

10,000 tenants cost one base ruleset plus 10,000 small deltas — not 10,000 rulesets. Because the
compiled plan is pointer-free and off-heap (CONCEPT.md §5, §7), the base contributes nothing to GC.

**Separate `WAF` instances** — when tenants need entirely different detectors or schemas. This is
why "no global state" is a hard rule in CLAUDE.md §2b: N instances in one process, fully isolated,
is a supported configuration, not an accident.

### Hot reload

```go
rs, err := rules.CompileFile("rules/prod.yaml")   // validate off the hot path
if err != nil {
	return err                                    // bad ruleset never goes live
}
waf.SwapRuleset(rs)                               // atomic; cannot fail
```

The library never watches files or polls. *When* to reload is your decision — file watcher, control
plane push, SIGHUP, whatever your platform already does.

---

## Profile C — build a WAF product on gwaf

You get the compiler, not just the runtime.

```go
// Compile in CI, ship the artifact.
plan, err := rules.Compile(rules.Input{
	Sets:     []rules.Set{core.Default, myVendorRules},
	Schemas:  []schema.Source{openapi.MustLoad("customer.yaml")},
	Policies: customerPolicies,
})
if err != nil {
	return err
}
report := plan.Report()   // rules, prefiltered count, unconditional cost, fuel estimates
if err := plan.WriteTo(w); err != nil {   // flat, signable, mmap-able artifact
	return err
}
```

### Your own detectors and operators

The five extension interfaces (RULES.md §4) are the whole point of this profile — implement them in
your package, no fork:

```go
waf, err := gwaf.New(
	gwaf.WithDetector(myProprietaryMLDetector{}),   // your L1 detector
	gwaf.WithOperator("threat_intel", myFeedOp{}),  // usable from YAML rules too
	gwaf.WithResolver(myTenantResolver{}),
)
```

Registering an operator by name makes it reachable from the declarative and SecLang frontends — so
your customers can write `op: { threat_intel: ... }` in YAML against *your* operator.

### Feeding your control plane

**gwaf ships no UI — but every datum a UI would need is a library API.** That's the resolution of
the "no UI, ever" rule: we don't build the dashboard, we make yours possible.

```go
gwaf.WithEventSink(mySink)     // structured decisions, matched spans, transform chains

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
