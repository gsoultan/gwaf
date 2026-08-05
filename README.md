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

tx := waf.NewTransaction()
defer tx.Close()

tx.SetRequestLine(r.Method, r.RequestURI, r.Proto)
tx.AddRequestHeader("User-Agent", r.UserAgent())

if d := tx.ProcessRequestHeaders(); d.Blocked() {
    http.Error(w, "forbidden", d.Status())   // d.RuleID(), d.MatchedSpan() explain why
    return
}
```

## Measured, not claimed

Apple M5 Pro, Go 1.26.5, full core ruleset. Reproduce with `make bench`.

| Workload | Latency | Allocations |
|---|---|---|
| Benign `GET` | **1.22 µs** | **0** |
| Benign `POST`, 1 KiB JSON | **6.48 µs** | **0** |
| Attack (blocked at header phase) | **0.83 µs** | 1 |

**Detection, on a corpus of real bypass techniques:**

| | |
|---|---|
| Evasion corpus | **76/76 blocked (100%)** |
| Benign corpus | **0/72 false positives (0.00%)** |

The evasion corpus covers case variation, whitespace splitting, single and
double percent-encoding, overlong UTF-8, NUL truncation, backslash separators,
HTML entities, and **UTF-7 (CVE-2026-21876)** — plus combinations, and payloads
delivered via headers and bodies. Detection rate is never reported without the
false-positive rate beside it.

**Schema as a compiler input — the flagship:**

| | With schema | Without |
|---|---|---|
| Latency | **1.14 µs** | 1.59 µs |
| Work performed (fuel) | **314** | 710 |

29% faster, 56% less work, *and* stricter — every out-of-spec request rejected
before a rule runs. A field declared an integer that validates as one cannot
contain `UNION SELECT`, so those rules are skipped soundly rather than
heuristically. **Specifying your API makes gwaf both faster and safer.**

**Ruleset scaling — the central claim:**

| Rules | Latency | Rules evaluated |
|---|---|---|
| 10 | 277 ns | 0 |
| 100 | 277 ns | 0 |
| 1,000 | 275 ns | 0 |
| 10,000 | **276 ns** | **0** |

A thousand-fold larger ruleset costs the same, because on benign traffic the
prefilter yields no candidates and no operator runs. These are enforced as
tests (`TestSLO*`), not just observed in benchmarks.

## What makes it different

| | |
|---|---|
| **Fast** | 0 rules evaluated and 0 allocations on benign traffic; flat in ruleset size |
| **Accurate** | Semantic detection over signatures; confidence **measured on a corpus**, CI-gated |
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

## Scope

gwaf analyzes **one request in isolation, with no memory**. Anything requiring state, identity, time,
or infrastructure — rate limiting, IP reputation, bot scoring, eBPF — belongs to the embedder and
arrives as a `Resolver` input.

## License

Apache-2.0
