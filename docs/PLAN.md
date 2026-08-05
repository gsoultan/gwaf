# gwaf Execution Plan

The decision document. [ROADMAP.md](ROADMAP.md) has phase detail; this has commitments, ordering,
gates, and kill criteria.

**Objective:** the best embeddable WAF library — developer-friendly, fastest, most accurate, most
secure, trivially integrated.

---

## The strategy in five lines

1. **Compile, don't interpret.** Move all work to build time (CONCEPT.md §1–7). That's the speed win.
2. **Parse intent, not strings.** Semantic detectors + decode lattice. That's the accuracy and
   anti-evasion win.
3. **Make the schema a compiler input.** Faster *and* more precise from one artifact (§6, §9). The
   flagship differentiator — nobody else does this.
4. **Measure confidence, don't declare it** (§8). FP rate becomes a build gate, not a production
   discovery.
5. **Stay stateless and library-shaped.** Everything cross-request belongs to the embedder.

Everything below serves those five. If a task doesn't, cut it.

---

## Milestones

Eight to ten months to v1.0 with a focused team. Ranges assume 2–3 engineers; see §Resourcing.

| # | Milestone | Weeks | Ships |
|---|---|---|---|
| **M0** | Instruments | 1–3 | Corpus, benchmark gates, CI, calibration harness. **No detection.** |
| **M1** | Compiler core | 3–10 | IR, closure plan, fuel, prefilter, arena, `Span` |
| **M2** | Detection | 8–18 | Transducers, decode lattice, SQLi/XSS + 5 more, SecLang parser |
| **M3** | Schema + integration | 14–24 | OpenAPI/GraphQL/gRPC, plan specialization, middleware, all 3 profiles |
| **M4** | Adoption | 20–32 | gateon shadow mode, `gwaf learn`, CRS conformance |
| **M5** | Hardening | 30–40 | Audit, published benchmarks, SLSA, API freeze, **v1.0** |

M0→M1→M2 is the critical path. M3 overlaps M2. M4 requires a real adopter, which you have.

---

## M0 — Instruments first (weeks 1–3)

**Nothing detects anything.** This is deliberate and it is the highest-ROI three weeks in the plan.

- [ ] Multi-module layout; core module with zero third-party deps
- [ ] CI: build, vet, staticcheck, `govulncheck`, race, fuzz smoke
- [ ] **Evasion corpus**: attack payloads *and* ≥5,000 benign requests. Both halves.
- [ ] **Benchmark harness** with committed baselines; >5% regression fails
- [ ] **Calibration harness** (`gwaf calibrate`) — measures per-rule FP against the benign corpus
- [ ] `go-ftw`-compatible conformance runner

**Gate:** a deliberately-regressed PR fails CI on both latency and FP. Prove the instruments work
before trusting them.

**Why first:** a detector that blocks everything passes any recall-only test. Without the FP gate
existing on day one, you optimize the wrong thing for three months and find out in production.

---

## M1 — Compiler core (weeks 3–10)

Order matters; it's CONCEPT.md build-order steps 1–3.

1. [ ] IR + **closure-threaded plan** + **fuel metering** — no optimizations yet
2. [ ] Prefilter (Aho-Corasick) + candidate bitset
3. [ ] Target-grouped evaluation plan
4. [ ] Transform interning (materialized — slow but correct; this is M2's fuzz oracle)
5. [ ] Arena + pointer-free `Span`
6. [ ] Bounded streaming body parsers (form, multipart, JSON, XML)
7. [ ] **Desync detection** (CONCEPT.md §11) — framing ambiguity rejected before rules run
8. [ ] Policy model: confidence tiers, per-route compiled plans

**Gates:**
- Benign GET: **0 allocations, 0 rules evaluated**
- Ruleset scaling 10 → 10,000 rules: **sub-linear**
- Fuel exhaustion reproducible in a unit test

**Decision point (week 6):** benchmark the closure plan against a naive loop at 10/100/1k rules. If
closures don't win at ≥100 rules, keep the IR and swap the executor. Don't defend the design.

---

## M2 — Detection (weeks 8–18)

1. [x] **Differential fuzz harness** — transducer vs. materialized path. *Built before transducers,
       exactly as sequenced, and it earned its keep on the first use.*
2. [x] ~~Transducing transforms~~ — **built, proven correct, measured 1.3–2.0× slower, removed.**
       Kill criterion invoked on performance rather than correctness. See CONCEPT.md §3 and
       `bench/transducer-experiment.txt`. The materialized path plus chain-level CSE already
       delivers the zero-allocation result the transducer was supposed to buy.
3. [ ] Decode lattice + NFA simulation, bounded interpretations ← **next**
4. [ ] Semantic detectors: **SQLi → XSS** first, then shell, path traversal, SSTI, NoSQL, LDAP
5. [ ] Cross-parameter joined view (CONCEPT.md §10), reduced confidence
6. [ ] **SecLang parser** (pulled forward — gateon's DB requires it)
7. [ ] Core ruleset with **calibrated** confidence

**Gates:**
- Every detector beats the RE2 baseline on the corpus at **equal-or-lower FP**
- Transducer and materialized paths agree on **100%** of fuzz inputs
- `gwaf calibrate` passes on the core ruleset

**Kill criterion — invoked.** The stated trigger was "no 100% differential agreement in 3 weeks."
Agreement was actually reached (38.6M fuzz executions, byte-for-byte and candidate-set identical),
but the benchmarks then showed the transducer 1.3–2.0× *slower* than the path it replaced, so it was
removed on that basis instead.

Two lessons worth keeping:

- **The kill criterion was aimed at the wrong risk.** It anticipated a correctness failure. The
  actual failure was that the premise had already been satisfied by simpler means: the materialized
  path reached zero allocations via buffer reuse and a no-change fast path, so the transducer was
  optimizing something that no longer cost anything. Future criteria should test the *premise*, not
  only the implementation.
- **Sequencing the harness first was what made this cheap.** The oracle existed before the
  optimization, so the answer arrived in one session rather than after the optimization had been
  wired into the engine and depended on.

---

## M3 — Schema + integration (weeks 14–24)

1. [ ] OpenAPI 3.1 validation (body, query, path, headers)
2. [ ] **Plan specialization from schema** (CONCEPT.md §6) — the flagship
3. [ ] **Context-aware confidence from schema** (§9)
4. [ ] GraphQL depth/complexity/introspection; gRPC frame + protobuf
5. [ ] `net/http` middleware — body double-read via arena, `ResponseWriter` interface preservation
6. [ ] Framework adapters (separate modules), transaction API, `rules.Overlay`, `Explain()`

**Gates:**
- Specialized plan measurably cheaper than general, **detection coverage provably identical**
- All three integration profiles working (INTEGRATION.md)
- Protected service in <10 lines per framework

---

## M4 — Adoption (weeks 20–32)

The most important milestone. A WAF library with no adopter is a benchmark, not a product.

1. [ ] gateon `wafengine` adapter
2. [ ] **Shadow mode in gateon production** — Coraza authoritative, gwaf observing
3. [ ] `gwaf learn` (CONCEPT.md §12)
4. [ ] `gwaf convert --from seclang`, `gwaf explain`, `gwaf doctor`
5. [ ] CRS v4.25 LTS conformance
6. [ ] Second adopter — **do not skip.** One adopter shapes the API around one use case.

**Gates:**
- Zero "Coraza blocks / gwaf allows" divergences for 2 weeks on production traffic
- FP rate ≤ Coraza's, p99 improved
- Second adopter integrates without a library change

---

## M5 — Hardening → v1.0 (weeks 30–40)

1. [ ] Third-party security review (budget for it; this is security infrastructure)
2. [ ] **Published reproducible benchmarks** — methodology, hardware, re-run instructions
3. [ ] SLSA-3 provenance, SBOM, signed releases, documented CVE process
4. [ ] Public API + five extension interfaces frozen under semver

**Gate:** external sign-off, and every SLO in CLAUDE.md §2 met on published hardware.

---

## First ten working days

Concrete, in order:

| Day | Task |
|---|---|
| 1 | `go mod init github.com/gsoultan/gwaf`; multi-module layout; CI skeleton |
| 2 | Benign corpus harvested from gateon access logs (≥5k real requests) |
| 3 | Attack corpus: CRS test suite + published bypass writeups + CVE-2026-21876 payloads |
| 4–5 | Benchmark harness + committed baselines; prove the regression gate fails a bad PR |
| 6–7 | `gwaf calibrate` skeleton — FP measurement against the benign corpus |
| 8–10 | IR + closure plan + fuel, no optimizations. First end-to-end: one literal rule, one request. |

**In parallel, in gateon (2 days, independent of gwaf):** extract `internal/security/wafengine` as
an interface over today's Coraza code. Kills the `GetCollection` type-assertion bug, makes 9 test
files mockable, and is the seam everything later depends on.

---

## Resourcing

| Priority | Profile | Why |
|---|---|---|
| **1st** | App-security engineer (CLAUDE.md §5 profile 1) | Without hands-on bypass experience, the semantic tier becomes a regex bag with extra steps |
| **2nd** | Parser/language engineer (profile 3) | Owns transducers, lattice, detectors — the differentiators and the top risk |
| **3rd** | Go performance engineer (profile 2) | Owns the SLOs |
| Later | API/protocol (4), platform (5), DX (6) | DX veto can be held by whoever owns the API early on |

At 1 engineer this is ~18 months and M2 becomes the bottleneck. At 2–3 it's 8–10 months. Below 2,
cut M3's GraphQL/gRPC and ship OpenAPI only.

---

## Decisions to make now

| Decision | Recommendation |
|---|---|
| Module path | `github.com/gsoultan/gwaf` — change now or never |
| gwaf Phase 6 overlap with gateon | **Already cut.** Rate limit / JA4 / bot / reputation stay in gateon permanently. |
| License | Apache-2.0, matching Coraza — removes a migration objection |
| Repo | Public from day one. Adopters won't build on a repo they can't read. |
| gateon cutover trigger | Shadow-mode gates in M4, not a date |

---

## Kill criteria — when to abandon a concept

Stated up front so they're decisions, not sunk-cost arguments.

| Concept | Kill if | Fallback |
|---|---|---|
| Transducers (§3) | No 100% differential agreement in 3 weeks | Materialized transforms; lose ~30% alloc win |
| Closure plan (§1) | Doesn't beat naive loop at ≥100 rules | Swap executor; IR is unaffected |
| Decode lattice (§4) | State explosion unfixable within the bound | Sequential multi-interpretation on high-risk targets only |
| Schema specialization (§6) | Coverage equivalence unprovable | Ship validation without pruning; keep the security win |
| mmap artifacts (§7) | Format/portability cost exceeds value | Parse at startup; it's an optimization |

Concepts 2, 5, 8, 10, 11, 12 have no kill criteria — they're low-risk and independently valuable.

---

## What success looks like

At v1.0, gwaf is the only library where all of these are true at once:

- `gwaf.New()` in one line, protected service in three
- **0 rules evaluated, 0 allocations** on benign traffic
- Multi-interpretation decoding at ~1× cost — security and speed from one mechanism
- **Confidence is measured, not claimed**, and CI enforces it
- Specifying your API makes the firewall faster *and* more precise
- Runs anywhere Go runs — zero CGO, no daemon, no UI, no global state
- Reproducible published benchmarks in a space where nobody currently publishes any

If you hit five of seven, gwaf is the best Go WAF library available. If you hit the schema one, it's
the best WAF library in any language.
