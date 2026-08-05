# gwaf Roadmap

Target: **v1.0 in ~40 weeks.** Phases overlap where marked. Every phase has an exit criterion that
is a measurement, not an opinion.

Read [CONCEPT.md](CONCEPT.md) first — it is the architectural thesis (gwaf is a compiler, not an
interpreter) and its §"Build order" is the technical sequencing that Phases 1–3 below implement.
See [CLAUDE.md](../CLAUDE.md) for structure and standards.

---

## Phase 0 — Foundations (weeks 1–3)

Nothing detects anything yet. This phase builds the instruments we will be judged by.

- Multi-module layout; core module with zero third-party dependencies.
- CI: build, `vet`, `staticcheck`, `govulncheck`, race detector, fuzz smoke runs.
- `bench/` harness with committed baselines and a >5% regression gate.
- `test/conformance/` — `go-ftw` compatible runner.
- `test/evasion/` — labelled corpus of attack **and** benign payloads. Reports detection rate and
  false-positive rate together.

**Exit:** CI green, benchmark gate demonstrably fails a deliberately regressed PR, evasion harness
reports both metrics on an empty ruleset (0% / 0%).

---

## Phase 1 — Core engine (weeks 4–10)

- `Transaction` lifecycle and phase machine.
- `internal/canon` — multi-interpretation canonicalization. Evaluates every plausible backend
  decoding rather than collapsing to one. This is the direct structural answer to CVE-2026-21876.
- `internal/body` — bounded streaming parsers: urlencoded, multipart, JSON, XML (XXE-safe).
- `rules/` — typed rule IR, compiler, and the five public extension interfaces (see
  [RULES.md](RULES.md)). Ship the Go struct frontend, `rules.Test` harness, scoped exceptions, and
  the literal-extraction contract together — the extension interfaces freeze at v1.0, so they need
  real external usage well before then.
- `internal/prefilter` — Aho-Corasick over literals extracted from every rule, candidate bitset.
- `internal/budget` — per-transaction wall-clock and allocation ceilings, `FailMode` open/closed.
- Policy model: confidence tiers + per-route policies with independent compiled plans
  ([RULES.md](RULES.md) §8). This replaces global paranoia levels.

Sequencing within the phase follows [CONCEPT.md](CONCEPT.md) "Build order" steps 1–3: IR + closure
plan + fuel first (no optimizations — establishes the compile/execute split), then prefilter and
target-grouped plan, then arena + `Span`. Materialized transforms stay in place through step 2 on
purpose: they are slow but obviously correct, and they become the differential-fuzz oracle for the
transducers in Phase 2.

**Exit:** benign 1 KB request completes on the prefilter path with **zero allocations**;
rules-evaluated/request is 0 on benign traffic; ruleset scaling from 10 → 10,000 rules is provably
sub-linear; budget exhaustion is deterministic under a synthetic hostile payload.

---

## Phase 2 — Transducers, lattice, semantic detectors (weeks 8–16, parallel with Phase 1)

CONCEPT.md build-order steps 4–5, then the detectors that sit on top:

- **Transducing transforms** (CONCEPT.md §3) — fold the 5 most common streamable transforms into the
  matcher so transformed buffers are never materialized. **Gated on a differential fuzz harness
  proving the transducer and the materialized path agree on 100% of inputs.** This is the highest-risk
  concept in the project; a subtle disagreement here *is* a bypass.
- **Decode lattice + NFA simulation** (CONCEPT.md §4) — multi-interpretation at ~1× cost, with a hard
  bound on simultaneous interpretations. Exceeding the bound is an explicit decision, never a silent
  truncation.
- **Semantic detectors**, ordered by attack frequency: **SQLi → XSS** first, then shell, path
  traversal, SSTI, NoSQL, LDAP.
- **SecLang parser** (pulled forward from Phase 5). gateon stores user-authored SecLang in its rule
  DB, so parsing is an adoption blocker; CRS conformance stays in Phase 5.

Each detector ships with a fuzz target, a labelled corpus, and a documented grammar.

**Exit per detector:** beats the RE2-only baseline on the evasion corpus at an equal-or-lower FP
rate. A detector that improves recall while raising FPs does not ship.

---

## Phase 3 — Positive security (weeks 14–20)

- OpenAPI 3.1 request/response validation (body, query, path, headers).
- GraphQL: depth, complexity, introspection controls.
- gRPC frame parsing + protobuf descriptor validation.
- **Schema-driven plan specialization** (CONCEPT.md §6) — the flagship feature. Treat the schema as a
  *compiler input*, not just a validator: an `int` field can't hold SQLi, so prune those rules from
  the plan entirely; an endpoint declaring no upload compiles out multipart handling. Target 70–90%
  plan reduction on well-specified endpoints.

Competitive note: cloud vendors gate schema validation behind premium tiers, and CrowdSec still has
OpenAPI validation on its roadmap rather than shipped. **No WAF on the market treats a schema as a
compiler input** — this is where "better-specified APIs get both faster and safer" comes from, and
it is the single strongest differentiator in the project.

**Exit:** a spec-conformant request passes; every out-of-spec mutation is rejected with an
explainable decision; a specialized plan is measurably cheaper than the general plan on the same
endpoint, with detection coverage proven identical on the evasion corpus.

---

## Phase 4 — Integration surface (weeks 18–24)

All three integration profiles ([INTEGRATION.md](INTEGRATION.md)) must work by the end of this phase.

- `net/http` middleware (the reference integration) — including the two traps: body double-read via
  the arena, and `ResponseWriter` interface preservation (`Flusher`/`Hijacker`/`ReaderFrom`).
- Adapters: chi, echo, gin, fiber, connect — each in its own module.
- Profile B: transaction API, `rules.Overlay` for multi-tenancy, `SwapRuleset`.
- Profile C: `waf.Explain()` returning structs (spans, transform chains, `NarrowestException()`),
  event sink interface.
- `cmd/gwaf-proxy` standalone reverse proxy — pure glue, ~500 LOC cap (CLAUDE.md §1).
- OTel-native audit sinks and metrics.

**Exit:** `examples/` shows a protected service in under 10 lines per framework; no adapter leaks
its framework dependency into the core module; a multi-tenant example runs 1,000 tenants off one
shared base ruleset; `Explain()` exposes everything `gwaf explain` prints.

---

## Phase 5 — Ecosystem bridge (weeks 22–30)

> **Note:** the SecLang *parser* is pulled forward to Phase 2 — see
> [GATEON-MIGRATION.md](GATEON-MIGRATION.md) §5. gateon (first adopter) stores user-authored SecLang
> in its rule database, so the parser is a Phase-2 dependency even though CRS conformance and
> migration tooling stay here.

- `seclang/` — CRS v4 adapter and conformance. Target **CRS 4.25 LTS** (first LTS track; legacy
  3.3.x support ends Q3 2026).
- Migration tooling from Coraza/ModSecurity configs.
- `cmd/gwaf lint` — rule linter and `explain` for decision tracing.

**Exit:** CRS conformance suite passes via the adapter, and the migration tool round-trips a real
Coraza config.

---

## Phase 6 — AI/LLM endpoint protection (weeks 28–36)

**Scope cut.** This phase originally included rate limiting, JA4 fingerprinting, bot scoring, and
reputation feeds. All four are **cross-request state**, which violates the stateless boundary in
[GATEON-MIGRATION.md](GATEON-MIGRATION.md) §3 — and gateon already implements all four. They are
**deleted from gwaf's scope, not deferred**; gwaf consumes them as `Resolver` inputs instead.

What remains is genuinely per-request content analysis:

- Prompt-injection detection (a semantic detector like SQLi, over natural language).
- Model-extraction and training-data-exfiltration patterns.
- AI-crawler identification from request-intrinsic signals only.

The AI category is where cloud vendors are actively expanding; entering it now is timing, not scope
creep.

**Exit:** each detector is independently toggleable and measured on the evasion corpus with an FP
rate, same gate as every other detector.

---

## Phase 7 — Hardening → v1.0 (weeks 34–40)

- Third-party security review.
- **Published, reproducible benchmarks** — methodology, hardware, and re-run instructions. Coraza's
  own benchmarks page has been "under renovation" since April 2026; that vacuum is the opportunity,
  and honest numbers are the only way to take it.
- SLSA-3 provenance, SBOM, signed releases.
- Documented CVE and embargo process.
- Public API freeze under semver.

**Exit:** external reviewer sign-off, and every SLO in CLAUDE.md §2 met on published hardware.

---

## Risk register

| Risk | Mitigation |
|---|---|
| Semantic detectors raise false positives vs. regex | FP rate is a hard CI gate from Phase 0, before any detector exists |
| Coraza's rule ecosystem is a moat | Phase 5 SecLang adapter neutralizes it for migration without adopting its bug class |
| Scope creep into being a product | Three-tier artifact rule in CLAUDE.md §1: all runtime logic in the library, toolchain is compile-time only, `proxy/` capped at ~500 LOC of pure glue. Non-glue code in `proxy/` is treated as a design bug report against the library. |
| Performance claims not believed | Publish reproducible methodology, not just numbers (Phase 7) |
| Single-maintainer bus factor | Two reviewers on security-relevant PRs; profile #1 (appsec) is the first hire |
| Extension interfaces frozen at v1.0 with too little real-world usage | Ship them in Phase 1, not Phase 5; recruit external rule authors during Phase 2–3 and treat their friction as blocking feedback |
| Users' custom rules blow the latency SLO and it reads as gwaf being slow | Literal-extraction contract + `gwaf lint` unconditional-rule budget make the cost visible at build time (RULES.md §5) |
| **Transducers silently introduce the bypass class we built the lattice to kill** | Differential fuzz vs. the materialized oracle is a ship-gate, not a nice-to-have. Ship 5 transforms, not 30. This is the project's top technical risk. |
| Closure-threaded plan doesn't beat a naive loop at small ruleset sizes | Benchmark at 10/100/1k rules in Phase 1; IR and executor are decoupled, so the executor is swappable without touching frontends |
| Schema specialization prunes real coverage when a schema is wrong | Fall back to the full plan when unspecified; recompile on schema change; never trust a runtime-supplied schema. Coverage equivalence is a Phase 3 exit gate. |
