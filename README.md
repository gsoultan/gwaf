# gwaf

An embeddable, Go-native Web Application Firewall **library**.

> Every other WAF is an interpreter. gwaf is a compiler.

Rules, schemas, and route policies are inputs to an optimizer that emits a specialized, pointer-free
execution plan. A literal prefilter decides what to evaluate before any rule runs, transform chains
are computed once and shared by every rule that needs them, ambiguous input is evaluated *every*
plausible way rather than guessed at, and work is metered in deterministic fuel rather than
wall-clock.

**Status: M1 — compiler core.** The engine works and is tested; see
[docs/PLAN.md](docs/PLAN.md) for what is built and what is next.

```go
waf, _ := gwaf.New()          // working, blocking firewall — no configuration

mux := http.NewServeMux()
mux.HandleFunc("GET /api/orders", handleOrders)

http.ListenAndServe(":8080", middleware.HTTP(waf)(mux))
```

That is the whole integration. See [`examples/basic`](examples/basic) for one
with an API schema and decision logging, and
[INTEGRATION.md](docs/INTEGRATION.md) for the transaction API when you are
embedding into something that is not `net/http`.

## Measured, not claimed

darwin/arm64, Go 1.26.5, full core ruleset (66 rules), 200,000 samples per
workload. Reproduce with `make bench-publish`.

| Workload | p50 | p99 | Allocations |
|---|---|---|---|
| Benign `GET`, no body | **917 ns** | 1.29 µs | **0** |
| Benign `POST`, 1 KiB JSON | **13.5 µs** | 18.0 µs | **0** |
| Attack (blocked at header phase) | **708 ns** | 958 ns | **0** |

Percentiles rather than means, because a mean hides the request that took forty
times longer — and that request is the one an attacker is trying to produce.

Request bodies are **decompressed first** (gzip, deflate, zlib — stdlib only),
and an encoding gwaf cannot decode is reported rather than passed through: a
compressed body inspected as-is is opaque, which makes one header enough to
disable the whole firewall.

**Detectors only ever see text.** JSON, form, and multipart bodies are parsed
into fields; binary content has its printable runs extracted; base64 is decoded
first, because the origin decodes it too.

That is a performance decision and a correctness one. Reading encoded binary as
prose cost 20 M fuel for one 700 KiB upload and found nothing. And inspecting
raw bytes misses what the application actually receives: a
`\u003cscript\u003e` escape is inert on the wire and `<script>` after JSON
parsing, and **every multipart part is inspected** — checking only the final one
is precisely CVE-2026-21876.

**Detection, on a corpus of real bypass techniques:**

| | |
|---|---|
| Evasion corpus | **216/216 blocked (100%)** across 25 attack classes |
| False-positive corpus | **0/124 (0.00%)** |
| Calibration corpus | **10,430 benign requests**, every rule inside its declared tier |

The evasion corpus is organised as *attack class × evasion technique*, and a
class gwaf claims to detect with too few cases behind the claim **fails the
build**. That check exists because it was needed: a technique-only corpus once
reported 76/76 while template, NoSQL, and LDAP injection each scored 0/0 — and
0/0 does not appear in a percentage. The same blind spot reappeared later one
level up, when the class *list* was the thing with the hole.

**SQL injection and XSS are detected structurally**, by grammar rather than by
signature.

`1'/*!50000OR*/1=1--`, `1' XOR 1=1--`, `<svg/onload=alert(1)>`, `java\tscript:`,
and `x" onerror="alert(1)` are all caught with no rule written for any of them.
Meanwhile *"the union selected a new representative"* and *"the onerror callback
fires when loading fails"* are not — the keywords are present but the grammar is
not. Both of those were **false positives** under the literal rules this
replaced.

Seven literal rules were deleted and two structural detectors added. Detection
did not drop and two real false positives went away.

**What is covered**, beyond SQL injection and XSS: command, template, NoSQL,
LDAP, and expression-language injection; path traversal and local/remote file
inclusion; XXE; Log4Shell including the `${${lower:j}ndi:` nesting no substring
of `jndi` survives; Spring4Shell; PHP object injection and Java deserialization;
SSRF against cloud metadata; prototype pollution; GraphQL depth, complexity, and
alias amplification; gRPC and protobuf payloads; and **file upload in both
halves** — the web shell going in, and the request that would execute one
already on disk.

The evasion corpus covers case variation, whitespace splitting, single and
double percent-encoding, overlong UTF-8, NUL truncation, backslash separators,
HTML entities, and **UTF-7 (CVE-2026-21876)** — plus combinations, and payloads
delivered via headers and bodies. Detection rate is never reported without the
false-positive rate beside it.

**Schema as a compiler input — the flagship:**

| | With schema | Without |
|---|---|---|
| Latency | **950 ns** | 1.58 µs |
| Work performed (fuel) | **185** | 610 |

40% faster, 70% less work, *and* stricter — every out-of-spec request rejected
before a rule runs. A field declared an integer that validates as one cannot
contain `UNION SELECT`, so those rules are skipped soundly rather than
heuristically. **Specifying your API makes gwaf both faster and safer.**

**Ruleset scaling — the central claim:**

| Rules | Latency | Rules evaluated |
|---|---|---|
| 10 | 233 ns | 0 |
| 100 | 234 ns | 0 |
| 1,000 | 233 ns | 0 |
| 10,000 | **233 ns** | **0** |

A thousand-fold larger ruleset costs the same. Rules evaluated per request is
a small constant independent of ruleset size — zero for values containing no
attack vocabulary, and bounded above by a handful otherwise. Enforced as tests
(`TestSLO*`), not merely observed in benchmarks.

## What makes it different

| | |
|---|---|
| **Fast** | 0 rules evaluated and 0 allocations on benign traffic; flat in ruleset size |
| **Accurate** | **Structural** SQL detection — grammar, not signatures. One implementation covers the variant family a signature list enumerates one payload at a time. |
| **Secure** | Ambiguous input is evaluated *every* plausible way, not guessed at; provable DoS bound via fuel metering |
| **Embeddable** | Zero CGO, **zero dependencies**, zero global state, no daemon, no UI |
| **Compounding** | Specifying your API schema makes gwaf both *faster* and *more precise* |

## Documentation

| Doc | What |
|---|---|
| [CONCEPT.md](docs/CONCEPT.md) | The architectural thesis — 12 core concepts. **Start here.** |
| [COMPARISON.md](docs/COMPARISON.md) | gwaf vs Coraza, CrowdSec, SafeLine, open-appsec, Sophos — including where gwaf is behind |
| [PLAN.md](docs/PLAN.md) | Execution plan, milestones, gates, kill criteria |
| [ROADMAP.md](docs/ROADMAP.md) | Phase detail and risk register |
| [RULES.md](docs/RULES.md) | Rule authoring, extension interfaces, confidence & policies |
| [INTEGRATION.md](docs/INTEGRATION.md) | Three integration profiles with code |
| [PERFORMANCE.md](docs/PERFORMANCE.md) | How the SLOs are reached, and what's forbidden |
| [GATEON-MIGRATION.md](docs/GATEON-MIGRATION.md) | First adopter: replacing Coraza |
| [CLAUDE.md](CLAUDE.md) | Project guidelines, structure, standards |

## Positive security: what no signature can catch

A signature answers *"does this value look like an attack?"*. Some of the most
expensive attacks do not look like anything. A stake of `-5000` is a valid
number, `"BTC"` is a valid currency string, and `/phpmyadmin/index.php` is a
valid path — they are attacks only because *your* application does not accept
them, and only your application can say so.

```go
api, _ := schema.New(schema.Operation{
    Method: "POST", Path: "/api/v1/bets", Strict: true,
    Body: []schema.Field{
        {Name: "event_id", Kind: schema.KindString,
            Format: schema.FormatUUID, Required: true},
        {Name: "stake", Kind: schema.KindNumber, Required: true,
            Min: schema.Bound(0.01), Max: schema.Bound(10_000)},
        {Name: "currency", Kind: schema.KindEnum,
            Enum: []string{"USD", "EUR", "GBP"}},
    },
})
api.Closed()   // anything matching no operation is rejected

waf, _ := gwaf.New(gwaf.WithSchema(api))
```

That rejects a negative stake, an integer-overflow payout, an unsupported
currency, a smuggled `is_admin` field, a missing required field — and every
reconnaissance probe for a route this API does not have, without naming a single
product. [`examples/positivesecurity`](examples/positivesecurity) runs all of it
and is a test, so the claims stay true.

Read [`Schema.Closed`](schema/schema.go) before enabling it: a closed schema is
only correct once the schema is complete.

## Optional rules

Everything in the core ruleset is `Certain` or `High` confidence, so
`gwaf.New()` blocks without a tuning phase. Rules that are *right for most
deployments but not all* ship exported instead of enabled, with the trade
documented at the point of use:

| Rule | Why it is opt-in |
|---|---|
| `core.WordPressHardeningRule` | blocks all direct PHP under `wp-content`; a minority of plugins expose endpoints that way |
| `core.LoopbackSSRFRule` | `localhost` and `127.0.0.1` are ordinary in CI, staging, and webhook targets |
| `core.CRLFHeaderRule` | needs a transform chain no other rule shares — measured at 8% of the latency budget |
| `graphql.IntrospectionRule` | introspection is how every GraphQL development tool discovers a schema |

```go
waf, _ := gwaf.New(gwaf.WithRuleset(rules.Set{core.WordPressHardeningRule(1011)}))
```

`WithRuleset` *accumulates* onto the default set — pass only the extra rules.

Methodology, hardware, re-run instructions, and what the numbers **do not**
show: [docs/BENCHMARKS.md](docs/BENCHMARKS.md). One command reproduces them:

```
make bench-publish
```

## Framework integration

```go
waf, _ := gwaf.New()                       // blocking, core ruleset, no config

http.Handle("/", middleware.HTTP(waf)(mux))          // net/http, chi, gorilla
r.Use(gwafgin.Middleware(waf))                       // gin
e.Use(gwafecho.Middleware(waf))                      // echo
app.Use(gwaffiber.Middleware(waf))                   // fiber
```

chi, gorilla/mux, connect-go, and the standard library need **no adapter**:
`middleware.HTTP` is already a `func(http.Handler) http.Handler`.

Everything beyond core lives in its own module, so importing gwaf pulls in
nothing you did not ask for — **the core module has zero third-party
dependencies**, and that is the one property no competing WAF library offers.

| Module | Why it is separate |
|---|---|
| `middleware` | so a framework adapter never reaches core |
| `adapters/{gin,echo,fiber}` | your router is your choice, not gwaf's |
| `schema/openapi` | YAML needs a parser core will not carry |
| `schema/grpc` | protobuf descriptors need `google.golang.org/protobuf` |
| `seclang` | CRS migration links a regex engine |

`staticcheck` and `govulncheck` run over **every** module in `make check`, not
just core — core is the one module that cannot have a dependency CVE, so
scanning it alone would scan the wrong place.

## Writing your own rules

Rules are Go values, so they diff, code-review, and fail the build on a typo
rather than silently never firing:

```go
rules.Rule{
    ID:         1_000_001,
    Phase:      types.PhaseRequestHeaders,
    Targets:    []types.Target{{Kind: types.TargetRequestPath}},
    Transforms: []rules.Transform{transform.Lowercase, transform.NormalizePath},
    Op:         op.HasPrefix("/internal/"),
    Actions:    []rules.Action{rules.Block},
    Severity:   types.SeverityCritical,
    Confidence: types.Certain,
    Msg:        "internal-only path reached from outside",
}
```

`examples/customrules` walks the whole surface in one runnable program — built-in
operators, `op.Func` and what a literal hint buys back, a custom `Operator`,
`Transform`, `Action`, and `Resolver`, and an `Exception` for the day one of your
rules is wrong about one route:

```
go run ./customrules
```

It is a test as well as an example, so what its comments claim is what CI checks.
Reference: [docs/RULES.md](docs/RULES.md).

## Scope

gwaf analyzes **one request in isolation, with no memory**, and answers one
question: is this an attack? Anything needing state, connection ownership,
privilege, or policy belongs to the embedder — rate limiting, reputation, bot
scoring, eBPF, and the decision of what to *do* about a finding.

**gwaf never buffers.** Holding a response breaks streaming and
time-to-first-byte, and only whoever owns the connection can weigh that. Feed it
what you choose; feed it nothing and it says so rather than calling the response
clean.

```go
// Response inspection: what leaves, not what arrives.
tx.SetResponseStatus(200)
tx.AddResponseHeader("Content-Type", "application/json")
if d := tx.ProcessResponseHeaders(); d.Blocked() {
    return   // before the first byte — the only moment it can be stopped
}
tx.WriteResponseBody(chunk)      // as many times as you like
d := tx.ProcessResponseBody()

slog.Warn("blocked", "waf", d)   // Decision implements slog.LogValuer
```

Ownership is decided by five tests in [CLAUDE.md](CLAUDE.md#1-positioning-read-this-before-proposing-a-feature).
The last one — *needs a dependency the embedder did not choose* — is why SecLang,
OpenAPI-YAML, brotli, and framework adapters live in their own modules, and why
**core carries zero third-party dependencies**.

## License

Apache-2.0
