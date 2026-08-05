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
