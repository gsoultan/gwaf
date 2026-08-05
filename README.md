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
| Benign `GET` | **2.00 µs** | **0** |
| Benign `POST`, 1 KiB JSON | 22.2 µs | **0** |
| Attack (blocked at header phase) | **1.40 µs** | 1 |

The JSON figure is the honest cost of inspecting a whole 1 KiB body with two
structural parsers. gwaf does not yet parse JSON into fields, so the entire body
is analysed as one value; field-level parsing is the next optimization and will
cut it substantially. It is still well inside the p99 < 100 µs budget.

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
| Latency | **1.36 µs** | 2.05 µs |
| Work performed (fuel) | **314** | 710 |

29% faster, 56% less work, *and* stricter — every out-of-spec request rejected
before a rule runs. A field declared an integer that validates as one cannot
contain `UNION SELECT`, so those rules are skipped soundly rather than
heuristically. **Specifying your API makes gwaf both faster and safer.**

**Ruleset scaling — the central claim:**

| Rules | Latency | Rules evaluated |
|---|---|---|
| 10 | 287 ns | 0 |
| 100 | 293 ns | 0 |
| 1,000 | 291 ns | 0 |
| 10,000 | **290 ns** | **0** |

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

## Scope

gwaf analyzes **one request in isolation, with no memory**. Anything requiring state, identity, time,
or infrastructure — rate limiting, IP reputation, bot scoring, eBPF — belongs to the embedder and
arrives as a `Resolver` input.

## License

Apache-2.0
