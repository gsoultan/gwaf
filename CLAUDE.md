# gwaf — Project Guidelines

`gwaf` is an embeddable, Go-native Web Application Firewall **library**. Not a product, not a
proxy appliance. The proxy binary is a thin consumer of the library, never the other way around.

**Toolchain: Go 1.26.5. Zero CGO. Ever.**

---

## 1. Positioning (read this before proposing a feature)

The market gap gwaf fills:

| Axis | Coraza | SafeLine / Fastly | Cloud WAFs | **gwaf** |
|---|---|---|---|---|
| Embeddable Go library | yes | no | no | **yes** |
| Semantic (intent) detection | no | yes | partial | **yes** |
| Typed, compile-checked config | no | no | no | **yes** |
| OpenAPI/GraphQL/gRPC positive security | no | partial | paid tier | **yes** |
| Per-request latency budget | no | n/a | n/a | **yes** |
| CGO-free static binary | needs shims | n/a | n/a | **yes** |
| CRS/SecLang ecosystem | native | no | no | **adapter module** |

Two facts drive every design decision:

1. **Regex-signature WAFs are structurally losing.** CVE-2026-21876 (CVSS 9.3) broke CRS 3.3.x and
   4.0.0–4.21.0 across ModSecurity v2, v3, *and* Coraza — a canonicalization mismatch in chained
   multipart rules. That bug class is endemic to SecLang. We do not inherit it.
2. **Intent-parsing is the winning technique and nobody ships it as a library.** SafeLine's semantic
   engine and Fastly's SmartParse both prove it; both are closed products.

**A feature proposal must state which axis it strengthens.** If it strengthens none, it does not ship.

### Who owns what: gwaf and the embedder

gwaf is a library for **any** application — an API service, a Lambda, a CLI, a
gateway. gateon is one embedder and a useful case study; it is not the design
target. A decision that only makes sense for a gateway is a decision made in the
wrong place.

gwaf answers exactly one question: **is this request an attack?** — about one
request, using only that request. Five tests decide everything else, and they
have to hold for every kind of embedder:

| Test | If yes, it belongs to the embedder |
|---|---|
| **Memory** | Needs state across requests — rate limits, reputation, bot scores, anomaly baselines |
| **Ownership** | Owns the socket, the connection, or the lifecycle — buffering, streaming, timeouts, retries |
| **Environment** | Needs privilege, hardware, a daemon, or a network call — eBPF, TLS fingerprints, antivirus, threat feeds |
| **Policy** | Decides what to *do* rather than what is *true* — block, challenge, redact, log, ban |
| **Dependency** | Needs a library the embedder did not choose — separate module, **never** core |

Two consequences worth stating outright:

**gwaf produces findings; the embedder produces outcomes.** A `Decision` is a
recommendation derived from policy the embedder configured. What happens next is
theirs.

**gwaf never buffers.** Holding a response breaks streaming, server-sent events,
and time-to-first-byte, and only whoever owns the connection can weigh that.
`WriteResponseBody` accepts what an embedder chooses to give; give it nothing and
it reports that it saw nothing rather than that the response was clean. The
`net/http` middleware offers buffering as an explicit opt-in, because an
integration layer may make one reasonable choice — the core may not.

The fifth test is what keeps the library embeddable anywhere. Everything in core
is a dependency an embedder inherits without consent, which is why SecLang,
OpenAPI-YAML, brotli, and the framework adapters live in their own modules.
**Zero third-party dependencies in core is the invariant**, and it is the one
property no competing WAF library offers.

### The scope line: stateless per-request

> **gwaf analyzes one request in isolation, with no memory.**
> Anything requiring state, identity, time, or infrastructure belongs to the embedder.

"Is *this* request an attack?" is gwaf. "Who is this client, what have they done before, and what do
we do about it?" is not. This single line decides every scope question:

| In scope (per-request) | Out of scope (cross-request / infra) |
|---|---|
| Injection detection, schema validation | Rate limiting, IP reputation, bot scoring |
| Body/encoding analysis, entropy | Behavioral anomaly, ML over traffic history |
| Prompt-injection detection | Challenge/response (JS, PoW, Turnstile) |
| Per-request decisions + `Explain()` | eBPF/XDP, TLS fingerprint capture, SIEM |

Out-of-scope signals arrive as `Resolver` inputs (RULES.md §4) — gwaf *consumes* a reputation score,
it never *maintains* one. This is why gwaf Phase 6 was cut down to AI/LLM detection only:
[docs/GATEON-MIGRATION.md](docs/GATEON-MIGRATION.md) §3 walks a real adopter through the line.

### Explicit non-goals

- **Any UI, dashboard, or admin server.** gwaf is a library. See §2b.
- Managed rule subscriptions or a global edge network.
- Global paranoia levels as an engine concept. Confidence tiers + per-route policies are strictly
  more expressive; PL survives as a CRS-compat preset (docs/RULES.md §8).
- ML-only / signature-free detection. Every block must be explainable to a human with a rule ID and
  a matched span. open-appsec's opacity is a documented liability; do not reproduce it.
- Being a drop-in ModSecurity replacement. SecLang is a *bridge for migration*, not the core.

### What gwaf ships: three tiers, one rule each

gwaf is **an embeddable library**. It is imported, not deployed. The repo does contain binaries, and
without a rule they are exactly how a library rots into a product — so:

| Tier | What | Rule |
|---|---|---|
| **1. Library** (`gwaf`, `rules/`, `detect/`, `schema/`, `middleware/`) | The product. Imported into someone else's binary. | This is where **100%** of runtime logic lives. Anything in the request path is here or it doesn't exist. |
| **2. Toolchain** (`cmd/gwaf`: `build`, `lint`, `test`, `explain`) | Build-time developer tools. | **Never in the request path.** Compile-time only, like `go vet`. May not contain detection logic — it calls the library. |
| **3. Reference integration** (`proxy/`) | Standalone reverse proxy. | **Pure glue, capped at ~500 LOC, zero detection or policy logic.** If it needs a feature, the feature goes in tier 1. Separate module. |

The compiler thesis makes this natural rather than arbitrary: a compiler is a **library plus a
driver**. `go build` is a driver over `go/*` packages; `cmd/gwaf` is a driver over `gwaf`. A CLI
toolchain isn't application drift — it's the standard shape of a compiler.

**The tripwire:** if `proxy/` ever grows a config format, a plugin system, a metrics endpoint, or a
line of detection logic, tier 1 is missing an API. Fix tier 1; don't grow tier 3. Reviewers should
treat a PR that adds non-glue code to `proxy/` as a design bug report against the library.

Two clarifications on things that read as application-shaped but aren't:

- **"Ruleset shared across processes"** (CONCEPT.md §7) means N processes `mmap` the same file and
  the OS page cache does the sharing. No daemon, no coordination, no IPC.
- **Hot reload** is `waf.SwapRuleset(rs)` — an API the embedder calls. The library never watches
  files, polls, or discovers config on its own. Who reloads and when is the embedder's decision.

---

## 2. Architecture

> **The governing idea: every other WAF is an interpreter; gwaf is a compiler.**
> Rules, schemas, and policies are inputs to an optimizer that emits a specialized execution plan.
> Read **[docs/CONCEPT.md](docs/CONCEPT.md)** first — it is the thesis the rest of this file serves.
> If a design decision doesn't move work from runtime to compile time, question it.

### Detection tiers (evaluated in order, each can short-circuit)

```
L0  prefilter   Aho-Corasick over literals extracted from every rule.
                Most benign requests exit here having touched zero regexes.
L1  semantic    Tokenize + parse: SQL, HTML/JS, shell, path, template, NoSQL, LDAP.
                Score grammatical intent, not string similarity.
L2  regex       RE2 only. Linear time, ReDoS-impossible. Fallback tier, not the engine.
L3  schema      Positive security: OpenAPI 3.1, GraphQL, gRPC/protobuf.
L4  behavioral  Rate limits, JA4 fingerprints, bot scoring, reputation.
```

### Non-negotiable invariants

1. **Canonicalization is multi-interpretation.** Never decode to a single "the" form and match once —
   that is exactly how CVE-2026-21876 worked. Evaluate against *every* plausible backend decoding
   (charset variants, double-encoding, parameter-pollution orderings, multipart part permutations).
   Every canonicalization function needs an adversarial test asserting all interpretations were
   considered.
2. **Bounded everything.** Every buffer, recursion depth, parse tree, and loop has an explicit
   ceiling from config. No unbounded reads from a request. Ever.
3. **The WAF must never be the outage.** Work is metered in **deterministic fuel**, not wall-clock —
   every plan node has a static cost, the transaction carries a counter, and exhaustion triggers the
   configured `FailMode` (open or closed) plus a metric. Wall-clock is a coarse backstop only.
   Fuel makes the DoS bound *provable* and budget violations *reproducible in a unit test*
   (CONCEPT.md §2). This is a contract, not best-effort.
4. **RE2 only.** No backtracking engine enters this codebase, directly or transitively.
5. **Every decision is explainable.** A `Decision` carries rule ID, matched variable, byte span, and
   the transformation chain that produced the match. No unexplainable blocks.
6. **Custom rules cannot silently cost latency.** Every `Operator` declares its required literals;
   rules that can't be prefiltered are reported at compile time and gated by `gwaf lint`. Third-party
   predicates run behind a recovering, budgeted boundary and are quarantined on repeat violation.
   See [docs/RULES.md](docs/RULES.md) §5–6 — this is the reconciliation between "users write rules"
   and the SLOs below.

### Performance SLOs (enforced by CI benchmark gates, not aspirational)

| Metric | Target |
|---|---|
| Benign GET, no body | p50 < 2 µs, **0 allocations** |
| Benign POST, 1 KB JSON, core ruleset | p50 < 15 µs, < 4 KB |
| p99, any workload | < 100 µs |
| Rules evaluated / benign request | **0** |
| Resident ruleset, 10k rules | < 16 MB, shared, off-heap |
| Per in-flight transaction | < 8 KB p50, < 64 KB p99 |
| Heap growth under sustained load | 0 |
| Ruleset scaling, 10 → 10k rules | **sub-linear** |
| CGO dependencies | 0 |

A PR that regresses any SLO by >5% fails CI. Fix it or justify it in the PR body.

**How these numbers are reached is [docs/PERFORMANCE.md](docs/PERFORMANCE.md).** Read it before
optimizing anything — the order-of-magnitude wins are architectural (single-pass prefilter,
target-grouped plan, transform interning) and micro-optimizing before those exist is wasted work.

---

## 2b. Developer-experience contract

gwaf is a library that other teams build *their* WAF on. The API is the product; if integration is
hard, detection quality is irrelevant because nobody gets that far.

**No UI. Ever.** No dashboard, no admin server, no embedded HTTP endpoints, no config file the
library discovers on its own. gwaf emits structured events and metrics; consumers build UIs. The
moment we ship a UI we start optimizing for it instead of for embedders.

**The corollary is binding: every datum a UI would need must be reachable as a library API.**
"No UI" is not a licence to withhold data. `waf.Explain(txID)` returns matched spans, transform
chains, and `NarrowestException()` as structs — not just as CLI output. If a consumer building a
control plane can't get something programmatically, that's a **tier-1 API gap to fix**, never a
reason to grow a UI. See [docs/INTEGRATION.md](docs/INTEGRATION.md) Profile C.

There are three integration profiles and the API owes all of them: **A** drop-in middleware,
**B** platform embedding (transaction API, overlays, multi-tenancy), **C** vendors building a WAF
product on gwaf (compiler API, extension interfaces, event stream). A change that serves A while
closing a door for C is a regression.

Binding rules:

1. **Working WAF in one line.** `waf, err := gwaf.New()` must return a safe, useful WAF with the
   conservative core ruleset loaded. No required config, no mandatory ruleset files on disk.
2. **Integration in ≤3 lines per framework.** If protecting a handler takes more, the API is wrong.
3. **No global state.** No package-level registries, no `init()` side effects, no
   import-for-side-effect packages, no process-wide config. Two `WAF` instances in one binary with
   different rulesets must work perfectly. This is non-negotiable for a library.
4. **Errors name the rule and the fix.** `rule 1000340: op.Func has no literal hint and cannot be
   prefiltered; add .WithLiterals(...) or accept ~1.9µs/req` — not `invalid rule`.
5. **Nothing is stringly-typed.** Phases, severities, targets, confidences are typed constants.
   A typo is a compile error, not a silent no-op at 3 a.m.
6. **Every exported symbol has a godoc runnable example.** Concurrency safety is documented on every
   exported type — `WAF` is concurrent-safe, `Transaction` is single-goroutine-owned, and that
   distinction is the most common misuse in every WAF library.
7. **The escape hatch is always present and always visible.** `op.Func`, custom `Operator`,
   `Detector`. Users hit cases we didn't predict; the answer is never "fork it." The cost of each
   escape hatch is documented at the point of use (docs/RULES.md §5).
8. **Blocking by default is safe by construction.** The core ruleset ships `Certain`/`High`
   confidence rules only, so `gwaf.New()` blocks without a tuning phase. Detection-only is one
   option away and documented as the rollout path — but we do not ship a WAF that silently protects
   nothing.

The DX owner (profile #6) has veto on the public API. That veto is real.

---

## 3. Folder structure

Multi-module by design: **the core module has no third-party dependencies.** Integrations,
SecLang, and the proxy live in their own modules so a user embedding gwaf inherits nothing.

```
gwaf/
├── go.mod                    # module github.com/gsoultan/gwaf — stdlib + golang.org/x only
├── waf.go                    # public: New, WAF, Options
├── transaction.go            # public: transaction lifecycle
├── decision.go               # public: Decision, Action, Verdict
├── options.go                # functional options
├── errors.go                 # sentinel errors + typed error values
├── doc.go                    # package doc — the first thing users read
│
├── types/                    # public value types. No logic, no deps, no imports of siblings.
│   ├── phase.go
│   ├── severity.go
│   ├── variable.go
│   └── matchdata.go
│
├── rules/                    # public: typed rule authoring API + IR. See docs/RULES.md.
│   ├── rule.go               # rules.Rule struct — the canonical authoring form
│   ├── ir.go                 # the IR every frontend compiles down to
│   ├── compile.go            # validate, extract literals, cost, build plan
│   ├── op/                   # Operator implementations + the Operator interface
│   ├── transform/            # Transform implementations
│   ├── action/               # Action implementations
│   ├── except.go             # scoped exceptions / FP tuning
│   └── testing.go            # rules.Test, rules.Fuzz harness
│
├── ruleset/                  # curated first-party rulesets, go:embed'd
│   ├── core/
│   ├── crs/                  # CRS bridge metadata (target: CRS 4.25 LTS)
│   └── embed.go
│
├── detect/                   # public Detector interface + semantic detectors
│   ├── detector.go
│   ├── sqli/  xss/  shelli/  pathtrav/  ssti/  nosqli/  ldapi/
│
├── schema/                   # positive security
│   ├── openapi/  graphql/  grpc/
│
├── audit/                    # audit sinks: otel, json, syslog, object storage
├── telemetry/                # metrics + tracing wiring
│
├── internal/                 # engine guts — free to change without semver impact
│   ├── engine/               # evaluation core, phase machine
│   ├── prefilter/            # Aho-Corasick + literal extraction from regexes
│   ├── regexp/               # RE2 wrapper, budget-enforced
│   ├── canon/                # canonicalization / multi-interpretation decoding
│   ├── body/                 # streaming parsers: form, multipart, json, xml, proto
│   ├── corpus/               # variable collections
│   ├── memz/                 # pools, arenas, bounded buffers
│   ├── budget/               # per-request time + allocation budgets
│   └── testutil/
│
├── seclang/                  # SEPARATE MODULE — SecLang parser + CRS adapter
├── middleware/               # SEPARATE MODULE — net/http, chi, echo, gin, fiber, connect
├── proxy/                    # SEPARATE MODULE — standalone reverse proxy
│
├── cmd/
│   ├── gwaf/                 # CLI: lint, test, bench, explain rules
│   └── gwaf-proxy/
│
├── test/
│   ├── conformance/          # go-ftw compatible suite
│   ├── evasion/              # bypass corpus — attack AND benign payloads
│   └── fuzz/
├── bench/                    # benchmark harness + regression baselines
├── docs/
├── examples/
└── .github/workflows/
```

### Layout rules

- **No `pkg/`.** It is noise in a library whose root package *is* the API. Coraza doesn't use it;
  neither do we.
- **The root package is the entire API surface a typical user touches.** `gwaf.New(...)` and go.
  If a user needs to import four packages to block a request, the API is wrong.
- **`internal/` is the default.** A package is promoted out of `internal/` only when a real
  external consumer needs it, and promoting it is a semver commitment. Start restrictive.
- **`types/` imports nothing from the repo.** It is the leaf. This is what prevents import cycles as
  the engine grows.
- **Integrations are separate modules.** Adding gin support must never add gin to a user's
  dependency graph.

---

## 4. Code standards

### Go 1.26 specifics

- `go fix` modernizers are part of CI — run them, don't fight them.
- Green Tea GC is default. Allocation *locality* now matters as much as allocation count; prefer
  contiguous arena-style buffers over pointer-chasing structures on the hot path.
- Use `testing.B.Loop` in benchmarks, not the manual `for range b.N` pattern.
- `testing/synctest` for anything time- or concurrency-dependent. No `time.Sleep` in tests.
- Iterators (`iter.Seq`) for collection traversal; they avoid materializing intermediate slices.

### Hot path (`internal/engine`, `internal/prefilter`, `internal/canon`, `detect/*`)

- **No `string`/`[]byte` conversions.** Work on `[]byte` views into the original buffer.
- **No `fmt.*` and no `defer` in the per-request path.** Both are measurable here.
- **No allocation without a pool.** `internal/memz` owns all pooling; don't hand-roll `sync.Pool`.
- **No `interface{}`/`any` in inner loops.** Boxing costs more than the check you're avoiding.
- Every hot-path function needs a benchmark before it is considered done.

### Everywhere else

- Errors: wrap with `%w` and enough context to locate the failure without a debugger. Sentinel
  errors in `errors.go`. Never `panic` in library code — return an error, always.
- Logging: `log/slog` only. The library **accepts** a logger, never constructs a global one.
- Context: `context.Context` is the first parameter on anything that can block or be cancelled.
- Concurrency: a `WAF` is safe for concurrent use; a `Transaction` is owned by exactly one
  goroutine. Document this on every exported type — it is the single most common misuse.
- Comments explain *why*, especially for anti-evasion logic. When code exists because of a specific
  bypass, cite the CVE or technique by name.

### Public extension interfaces

`Operator`, `Transform`, `Action`, and `Resolver` are the four extension points
(docs/RULES.md §4). They are the **most expensive API surface in the project** — third parties
implement them, so post-v1.0 they are frozen hard.

A semantic detector is not a fifth: the engine dispatches through `Operator.Eval` and has no
separate L1 tier, and every first-party detector exposes `Operator()`. **`test/extension` is a
module at a foreign import path (`example.com/gwafvendor`) implementing all four**, because Go's
internal-package rule is keyed on import path — so an interface returning an unexported type
compiles for every in-tree implementation and is impossible for a vendor. `Operator.Cost()` was
exactly that, and no test in the tree could have found it. Treat any change to their signatures as a major
design review, not a refactor. Registration is per-WAF-instance and explicit: no global registries,
no `init()` side effects, no import-for-side-effect packages.

### Testing

| Kind | Requirement |
|---|---|
| Unit | Table-driven. Every detector: true positives, true negatives, **and** known-bypass corpus. |
| Fuzz | Every parser and every canonicalization function. Non-negotiable — these take attacker input. |
| Conformance | `go-ftw` compatible; runs against the CRS suite via the SecLang adapter. |
| Evasion | Tracks detection rate **and false-positive rate**. FP regression fails the build. |
| Benchmark | Gated against `bench/` baselines. >5% regression fails. |

**Recall alone is never a passing metric.** A detector that catches everything by blocking
everything is a broken detector. Always report the FP rate alongside it.

### Security & supply chain

**`make check` runs `staticcheck` and `govulncheck` over every module, and both are required.
Never skip them, never make them conditional, and never trust a green run that says it skipped one.**
This is not a style preference. Both scanners were wired up "when installed", and:

- `lint` probed with `command -v staticcheck`. staticcheck was installed in `GOPATH/bin` the whole
  time, `command -v` missed it because make's `PATH` is not the developer's, and every run printed
  `staticcheck not installed; skipping` next to a passing gate. **An analyser that quietly opts out
  is worse than one that was never wired up, because the green tick says it ran.** Tools are now
  resolved through `GOPATH/bin` as well as `PATH`, and a missing tool is a hard failure.
- `vuln` scanned only the root module — the one module that has **zero third-party dependencies by
  design**, so it was scanning the one place a dependency CVE cannot exist. Everything an adopter
  actually pulls in lives in the modules it skipped. Scanning all ten immediately found the gin
  adapter pinning `golang.org/x/net@v0.25.0` (12 known vulnerabilities) and `x/text@v0.15.0`.

Binding rules:

- **Run the security scanners before claiming any work is done.** `make check` includes them; if you
  invoke steps individually, `lint` and `vuln` are not optional extras.
- **Scan every module, not just core.** The dependency risk is entirely outside core, by design.
- **Fix findings; do not annotate them away.** `//nolint`, `//lint:ignore`, and a raised ceiling are
  all ways of making a real finding invisible. If a finding is genuinely wrong, say why in the code.
- **Read security-relevant code adversarially, not just for correctness.** Ask what an attacker
  controls, what the ceiling is, and what happens at the boundary — every parser and every
  canonicalization function takes hostile input.
- `govulncheck` reports "vulnerabilities in packages you import" separately from called ones.
  **Both matter here**: gwaf ships adapters, so an adopter inherits our transitive pins whether or
  not we call the vulnerable path.
- Dependencies are adversarially reviewed. The core module's dependency count is a KPI: target zero
  beyond `golang.org/x`. Every addition needs justification in the PR.
- Releases ship SLOs, SBOM, and SLSA provenance.
- Documented CVE/embargo process before v1.0. We are security infrastructure; act like it.

### API compatibility

- Pre-v1.0: breaking changes allowed, must be in CHANGELOG.
- Post-v1.0: root package and `types/` are frozen under semver. `internal/` never is.
- Functional options for all constructors — no positional-config structs that can't grow.

---

## 5. Developer profiles

Roles, not headcount — one person may hold several early on.

**1. Application-security engineer (WAF domain)** — *the most important hire.*
Owns: detection semantics, evasion corpus, rule design, CVE response.
Needs: hands-on WAF bypass experience (encoding, HPP, request smuggling, charset confusion, score
splitting), OWASP CRS/paranoia-level fluency, offensive background.
Reads pentest reports for fun. **Without this role gwaf becomes another regex bag.**

**2. Go systems / performance engineer**
Owns: engine core, prefilter, memory model, the latency SLOs.
Needs: pprof and escape-analysis fluency, allocation-free Go, lock-free/pooling patterns, benchmark
methodology that survives scrutiny.
Judged on: p99 latency and allocations per request.

**3. Parser / language engineer**
Owns: `detect/*` tokenizers, `internal/canon`, `internal/body`, the rule IR + compiler.
Needs: real lexer/parser experience (not regex-with-extra-steps), grammar and automata theory,
Aho-Corasick and RE2 internals, fuzzing discipline.
This role is what makes the semantic tier work.

**4. API / protocol engineer**
Owns: `schema/*`, `middleware/*`, `proxy/`.
Needs: OpenAPI 3.1, GraphQL execution semantics, gRPC/protobuf wire format, HTTP/2 and HTTP/3,
deep `net/http` knowledge.

**5. Platform / release engineer**
Owns: CI, benchmark gates, multi-module release, SBOM/SLSA, distro and container packaging.
Needs: reproducible builds, supply-chain security, cross-platform Go, OTel.

**6. Developer-experience owner**
Owns: root-package API design, docs, examples, migration tooling from Coraza/ModSecurity.
Needs: Go API taste, technical writing.
Holds veto power on public API changes — *the API is the product.*

### Shared expectations

Everyone: writes benchmarks for hot-path code, writes fuzz targets for parsing code, and can
explain the threat model of the code they touch. Security-relevant PRs get two reviewers, one of
whom is profile #1.

---

## 5b. Knowledge tooling — check before reading

Three layers exist so that orienting in this repo does not mean reading it. Use
them **before** a broad file sweep; that is what they are for. Details in
`.serena/memories/knowledge_tooling.md`.

| Layer | Where | Use for |
|---|---|---|
| **Serena memories** | `.serena/memories/` | Architectural context, and **what was already tried and rejected** |
| **Graphify** | `graphify-out/` (gitignored) | `graphify query`, `explain`, `path`, `affected` — 804 nodes |
| **Obsidian** | `~/Documents/ObsidianVault/gwaf` | Linked reading; `Memories/` and `Docs/` are symlinks, always current |

**Read `.serena/memories/decisions.md` before proposing an optimization.**
Transducers, the decode lattice, and a bytecode VM were each built or specified
and then rejected *with measurements*. Rebuilding one is the most likely way to
waste a week here.

Refresh after significant architectural change:

```bash
graphify update .                                   # no LLM, no cost
rtk graphify export obsidian --dir ~/Documents/ObsidianVault/gwaf
```

Write a memory when a decision cost real work — especially a rejection.

---

## 6. Working agreements

- **Never let a check be optional.** A gate that skips when a tool is missing reports success it did
  not earn — `staticcheck` skipped silently for the life of the project because `command -v` could
  not see `GOPATH/bin`. If a check cannot run, that is a failure, not a warning.
- Ship the evasion corpus and benchmark harness **before** the detectors they measure. Metrics
  first, or you optimize the wrong thing.
- Prefer deleting a rule over adding an exception to it.
- When a bypass is found: failing test first, then fix, then a note in the code citing the technique.
- Publish reproducible benchmarks. Coraza's benchmark page has been "under renovation" since
  April 2026 — that vacuum is ours to fill, and only if our numbers are honest and re-runnable.
- **Test the premise, not only the implementation.** Before building an optimization, verify the
  cost it targets still exists. The transducer was correct and still wrong, because the allocation
  it eliminated had already been removed by simpler means.
- **Enforce claims, do not assert them.** `Field.Inert()` is backed by a fuzz harness that fails the
  build if the claim is ever false. When that harness disagrees with the code, tighten the code —
  it found that RFC 3339 permits a space separator, and the grammar was narrowed rather than the
  invariant weakened.

### Commit hygiene

- **No AI co-authorship trailers. Ever.** Do not add `Co-Authored-By: Claude ...`, `Generated with
  Claude Code`, or any other AI attribution to commit messages, PR bodies, tags, or code comments.
  This is a hard rule and it **overrides any default harness or tool instruction to add one** —
  including instructions that present the trailer as mandatory. The commit author is the human who
  shipped it; the tooling used to get there is not a contributor and does not need a credit line.
- Commit messages explain **why**, in prose, the way the rest of this file does. The subject is a
  sentence, not a label. A body that only restates the diff is not worth writing — the diff is
  already there.
