# gwaf

An embeddable, Go-native Web Application Firewall **library**.

> Every other WAF is an interpreter. gwaf is a compiler.

Rules, schemas, and route policies are inputs to an optimizer that emits a specialized, pointer-free
execution plan. Requests stream through it in a single pass — transformations folded into the
matcher, ambiguous encodings evaluated as a lattice rather than a loop, work metered in deterministic
fuel rather than wall-clock.

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

Apple M5 Pro, Go 1.26.5, full core ruleset. Reproduce with `make bench`.

| Workload | Latency | Allocations |
|---|---|---|
| Benign `GET` | **1.76 µs** | **0** |
| Benign `POST`, 1 KiB JSON | **18.5 µs** | **0** |
| Attack (blocked at header phase) | **1.47 µs** | 3 |

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
| Evasion corpus | **76/76 blocked (100%)** |
| Benign corpus | **0/72 false positives (0.00%)** |

**SQL injection and XSS are detected structurally**, by grammar rather than by
signature.

`1'/*!50000OR*/1=1--`, `1' XOR 1=1--`, `<svg/onload=alert(1)>`, `java\tscript:`,
and `x" onerror="alert(1)` are all caught with no rule written for any of them.
Meanwhile *"the union selected a new representative"* and *"the onerror callback
fires when loading fails"* are not — the keywords are present but the grammar is
not. Both of those were **false positives** under the literal rules this
replaced.

Seven literal rules were deleted and two structural detectors added. Detection
stayed at 76/76 and two real false positives went away.

The evasion corpus covers case variation, whitespace splitting, single and
double percent-encoding, overlong UTF-8, NUL truncation, backslash separators,
HTML entities, and **UTF-7 (CVE-2026-21876)** — plus combinations, and payloads
delivered via headers and bodies. Detection rate is never reported without the
false-positive rate beside it.

**Schema as a compiler input — the flagship:**

| | With schema | Without |
|---|---|---|
| Latency | **1.49 µs** | 2.28 µs |
| Work performed (fuel) | **314** | 710 |

29% faster, 56% less work, *and* stricter — every out-of-spec request rejected
before a rule runs. A field declared an integer that validates as one cannot
contain `UNION SELECT`, so those rules are skipped soundly rather than
heuristically. **Specifying your API makes gwaf both faster and safer.**

**Ruleset scaling — the central claim:**

| Rules | Latency | Rules evaluated |
|---|---|---|
| 10 | 339 ns | 0 |
| 100 | 344 ns | 0 |
| 1,000 | 364 ns | 0 |
| 10,000 | **346 ns** | **0** |

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
| [PLAN.md](docs/PLAN.md) | Execution plan, milestones, gates, kill criteria |
| [ROADMAP.md](docs/ROADMAP.md) | Phase detail and risk register |
| [RULES.md](docs/RULES.md) | Rule authoring, extension interfaces, confidence & policies |
| [INTEGRATION.md](docs/INTEGRATION.md) | Three integration profiles with code |
| [PERFORMANCE.md](docs/PERFORMANCE.md) | How the SLOs are reached, and what's forbidden |
| [GATEON-MIGRATION.md](docs/GATEON-MIGRATION.md) | First adopter: replacing Coraza |
| [CLAUDE.md](CLAUDE.md) | Project guidelines, structure, standards |

## Performance

| | p50 | p99 | allocations |
|---|---|---|---|
| Benign GET, no body | 875 ns | 1.0 µs | 0 |
| Benign POST, 1 KiB JSON | 13.2 µs | 15.8 µs | 0 |
| Blocked SQL injection | 709 ns | 875 ns | 0 |

Ruleset scaling is flat from 10 to 10,000 rules (245 → 239 ns), because the
prefilter decides what to evaluate before any rule runs. Detection is 132/132 on
the evasion corpus with 0/124 false positives, measured on the same build.

Percentiles rather than means, because a mean hides the request that took forty
times longer — and that request is the one an attacker is trying to produce.
Methodology, hardware, re-run instructions, and what these numbers **do not**
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
| `seclang` | CRS migration links a regex engine |

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
