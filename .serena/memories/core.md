# gwaf Core

## What it is
An **embeddable Go WAF library**. Imported, not deployed. No daemon, no server,
no UI. Zero CGO, **zero third-party dependencies** (CI-enforced via `make deps`).

Module: `github.com/gsoultan/gwaf`. Go 1.26.5. Apache-2.0.

## The thesis
> Every other WAF is an interpreter. gwaf is a compiler.

Rules, transform chains, and schemas are inputs to a compiler that emits an
execution plan. A conventional WAF walks its ruleset per request — O(rules ×
values) transform-and-match ops. gwaf groups rules by transform chain, compiles
each group's required literals into one Aho-Corasick automaton, normalizes each
value once per chain, and evaluates only rules whose literals appeared.

**On benign traffic zero rules are evaluated.** 10 rules and 10,000 rules cost
the same (277 ns vs 276 ns, measured).

## Scope line (decides every question)
> gwaf analyses **one request in isolation, with no memory**.

Anything needing state, identity, time, or infrastructure — rate limiting, IP
reputation, bot scoring, eBPF — belongs to the embedder and arrives as a
`Resolver` input. This is why gwaf Phase 6 was cut. See [[boundaries]].

## Package map
| Package | Role |
|---|---|
| `gwaf` (root) | Public API: `New`, `WAF`, `Transaction`, `Decision`, options |
| `types` | Pointer-free `Span`, `Phase`, `Confidence`, `Severity`, `Target`, `RuleID` |
| `rules` | `Rule`, IR, compiler, the 5 extension interfaces |
| `rules/op` | Operators with required-literal extraction |
| `rules/transform` | Materialized transforms (also the differential oracle) |
| `ruleset/core` | First-party rules; Certain/High confidence only |
| `schema` | API description → validator **and** compiler input |
| `internal/prefilter` | Aho-Corasick, failure + dictionary links |
| `internal/engine` | Chain-grouped evaluator |
| `internal/interpret` | Multi-interpretation decoding (CVE-2026-21876) |
| `internal/budget` | Deterministic fuel metering |
| `internal/memz` | Per-transaction bump arena |
| `internal/bitset` | Candidate sets, touched-word Reset |

## Concurrency
`WAF` is concurrent-safe. `Transaction` is owned by exactly one goroutine.
**No global state** — N instances with different rulesets coexist. This is what
makes multi-tenant embedding and parallel tests work; it cannot be retrofitted.

## Docs
`docs/CONCEPT.md` is the thesis (start there). `PLAN.md` = execution + kill
criteria. `RULES.md`, `INTEGRATION.md`, `PERFORMANCE.md`, `GATEON-MIGRATION.md`.
`CLAUDE.md` = guidelines.

## Gotchas worth reading before optimizing
[[prefilter_literal_selectivity]] — a literal set can be sound and still filter
nothing. `detect_xss` declares `"`, so XSS evaluates on 100% of JSON traffic
while `gwaf lint` correctly reports it as prefiltered. Measure it with
`gwaf lint -corpus`.

[[rejected_literal_hints]] — and do not "fix" that by telling operators which
literals hit, or by tightening the broad ones. Built and reverted with a
counterexample: tolerant matching makes the detector match text its own literals
are absent from, so both are bypasses.

[[attack_corpus_50k]] — the 50k real-attack harness (test/attackgen/). gwaf is
94.6% on nuclei CVE traffic and 98.8% on CRS, 82.2% on the full adversarial
expansion, at 0 false positives. Records the recurring finding: a low-scoring
category is usually an operator that already matches sitting behind a prefilter
that never nominates it -- read the misses, fix the literal, not the signal.

[[coraza_comparison]] — the head-to-head, and the rule for reading it: Coraza
detects 80.6% on CRS's own corpus and false-positives on 36.30% of ordinary API
traffic, where gwaf is 26.3% and 0.00%. Most of the "gap" is CRS negative space
(it wants the number 4294967296 blocked). Read the payloads before chasing a
competitor's number.

[[redteam_round6_blueteam]] — the hardening pass: 92.6% detection at **0.00%**
false positives. Every FP was a sentence fragment scored as a whole imperative;
the fix is to require the fragment to be aimed at the model. Also the anchor
idea, which is how a widened match stays prefilterable.

[[redteam_round5]] — the statistics that mean something: 24.7% → 82.4% detection
on 85 novel adversarial payloads, FP rate flat. Also the measured reason to put
per-rule normalisation in an **operator** and not a transform chain (a chain cost
22% on benign GET for the benefit of two rules).

[[redteam_round4]] — the standing list of **reproduced bypasses that are still
open**, each with the reason it was not closed (long UTF-7 runs, the CHAR()
prefilter gap, sink operators reading siblings raw, inet_aton spellings of the
metadata address, CLI option injection, MongoDB aggregation stages). Read it
before hunting for bypasses, so a round starts from what is known. Also records
the trap that a new interpret reading is worthless if the value never reaches
the reading layer.
