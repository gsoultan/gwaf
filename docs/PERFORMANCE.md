# gwaf Performance Architecture

How gwaf gets to **p50 < 15 µs / p99 < 100 µs** with a full ruleset, and why that's achievable
rather than aspirational.

The thesis in one sentence: **a WAF is slow because it evaluates rules; gwaf is fast because it
almost never does.**

---

## 0. The cost model

A naive WAF (this includes most SecLang engines) evaluates:

```
for each rule:              # ~200 rules
  for each target:          # ARGS, HEADERS, BODY...
    for each value:         # 20 args
      apply transforms      # lowercase, urldecode, ...
      run operator          # regex
```

That's `rules × targets × values` transform-and-match operations — **~4,000 regex executions per
request** at CRS scale. Every optimization below exists to collapse that product.

gwaf inverts the loop:

```
for each target value:      # 20 values, ONCE
  apply deduped transforms  # ~3 unique chains, memoized
  run prefilter automaton   # one pass, yields candidate rule bitset
  for each candidate rule:  # typically 0
    run operator
```

On benign traffic the candidate set is empty and **zero operators execute**. That's the whole game.

---

## 1. Tier 1 — architectural (the 10–100× wins)

### 1.1 Single-pass prefilter with a candidate bitset

One Aho-Corasick DFA over the required literals of every rule in the ruleset. One pass over each
target value yields a bitset of rule indices that could possibly match. Rules evaluated per request
drops from ~200 to typically 0–3.

Byte-indexed transition tables, compact rule indices (not sparse public IDs), bitset ops on
`[]uint64`. The automaton is built at compile time and is immutable and shared.

### 1.2 Target-grouped evaluation plan

The compiler groups rules by `(phase, target)`. `ARGS` is resolved once per transaction, each value
is scanned once, and the automaton pass is amortized across every rule that reads that target.

This is where most engines lose: they re-resolve and re-scan the same `ARGS` collection for each of
200 rules. The plan is a struct-of-arrays laid out in evaluation order, which also gives Green Tea
GC the locality it rewards.

### 1.3 Transform chain deduplication and memoization

40 rules sharing `t:lowercase,t:urlDecode` must compute it **once**. The compiler canonicalizes
transform ordering, hashes each chain, and interns it — so identical chains across unrelated rules
collapse to one node. Results are memoized per-target-value for the life of the transaction.

Coraza's v3 rework attributes a large part of its 700 → 70k events/s jump to transformation caching;
we do it at compile time rather than runtime, so the lookup is an array index rather than a map hit.

**Security constraint:** memoization is per-transaction and bounded. A global cache keyed on
attacker-controlled bytes is a memory-exhaustion and cache-poisoning vector. See §4.

### 1.4 Regex peephole optimization

Most "regex" rules aren't really regexes. At compile time, lower them to specialized matchers:

| Pattern | Lowered to | Speedup |
|---|---|---|
| `(?i)sqlmap` | case-folded AC literal | ~50× |
| `^/admin` | `bytes.HasPrefix` | ~100× |
| `foo\|bar\|baz` | AC alternation set | ~30× |
| `[a-z0-9_]+` | 256-bit bitmap scan | ~10× |
| `\d{1,4}` | bounded digit scan | ~15× |

Whatever survives lowering runs on RE2 — linear time, ReDoS-impossible. In a typical CRS-derived
ruleset this eliminates **60–70% of regex executions outright**. No SecLang engine does this,
because SecLang semantics force late binding; our IR doesn't.

### 1.5 Phase short-circuit and lazy body resolution

Block at `PhaseRequestHeaders` and the body is never read, parsed, or transformed. Body parsing is
the single most expensive thing a WAF does, and the cheapest rules run first by construction.

Body targets are resolved lazily: parse only if a rule in that phase actually reads a body target.
Limits (§4) are enforced *before* parsing, not during.

### 1.6 Fast path for trivial requests

`GET`, no query string, no body, known-good method — a handful of header checks and out. Detected at
plan-compile time, so the check is a couple of branches, not a scan.

---

## 2. Tier 2 — memory (2–5×)

**Per-transaction arena.** One pooled buffer per transaction. All intermediate transform output
bump-allocates from it; the whole thing resets on release. Steady-state GC pressure from the hot
path approaches zero — which matters more under Green Tea, where locality drives marking cost.

**Zero-copy throughout.** Every value is a `[]byte` view into the arena or the original buffer. No
`string(b)` conversion anywhere on the hot path, ever.

**Compact rule indices.** Public IDs are sparse (`1000101`, `942100`); internally rules are
`uint32` indices into flat arrays. Bitsets stay small, arrays stay cache-resident.

**Pooled transactions.** `sync.Pool` behind `waf.NewTransaction()`, with the arena attached. The
caller sees an opaque handle; `tx.Close()` returns everything.

**Interned names.** Header and argument names are interned with precomputed hashes at plan-compile
time; lookup is an integer compare, not `strings.EqualFold`.

---

## 3. Tier 3 — micro (10–30%, only after Tiers 1–2 are done)

- Bitmap character classes (256-bit lookup instead of range comparisons).
- No interface dispatch inside inner loops — operators are devirtualized into a switch over a small
  closed set of kernel types; only custom operators go through the interface.
- Lean on stdlib `bytes` primitives (`IndexByte`, `Contains`, `Index`) — already hand-written
  assembly on every platform Go supports. Free SIMD.
- **Optional asm kernels**, behind build tags with a pure-Go fallback, for the AC transition loop,
  case folding, and URL decoding. **Do not start here.** Portability and auditability are worth more
  than 15%, and a security library that can't be read is a liability. Revisit only with profiles
  proving these are top-3 in the flame graph.

---

## 4. Performance work that is forbidden

Speed that costs security is a bug. These are permanently off the table:

- **Sampling or skipping rules under load.** An attacker who can generate load can then choose which
  requests go uninspected. If we can't keep up, we apply `FailMode`, loudly.
- **Global caches keyed on attacker-controlled bytes.** Unbounded memory growth plus a poisoning
  oracle. Memoization is per-transaction and bounded, always.
- **Truncating input to hit a latency target.** Bodies exceeding limits are *rejected*, not silently
  half-inspected. Half-inspection is indistinguishable from a bypass.
- **Trusting `Content-Length` or a declared charset.** Both are attacker-controlled. This is
  precisely the CVE-2026-21876 failure mode.
- **Single-interpretation canonicalization as a fast path.** Multi-interpretation decoding is a
  correctness invariant, not a tunable.

**Limits are enforced before parsing, as a cheap pre-check:** max body size, arg count, header
count, nesting depth, multipart part count. This is both a DoS defense and a latency guarantee —
it bounds worst-case work per request independent of ruleset size.

---

## 5. What we measure

Benchmarks are only credible if the workload is. `bench/` covers:

| Workload | Why |
|---|---|
| Benign GET, no body | The 95% case. Should be near-free. |
| Benign POST, 1 KB JSON | Realistic API traffic. **The headline number.** |
| Benign POST, 1 MB JSON | Body-parser throughput and arena behavior. |
| Attack payloads (evasion corpus) | Detection path, not just the happy path. |
| Adversarial: 1,000 args | Limit enforcement and worst-case fan-out. |
| Adversarial: deep JSON nesting | Recursion bounds. |
| Adversarial: pathological regex bait | Proves RE2 linearity. |
| Ruleset scaling: 10 / 100 / 1k / 10k rules | **Must be sub-linear.** If it's linear, the prefilter is broken. |

Reported every run by `latency_test.go`: p50, p90, p99, p99.9, max, allocs/op,
bytes/op, and **rules-evaluated/request** — that
last one is the leading indicator. If it drifts up, latency is about to follow.

CI gates a >5% regression on any of them. Published benchmarks ship with hardware, methodology, and
re-run instructions — Coraza's benchmark page has been "under renovation" since April 2026, and
filling that vacuum is only worth anything if our numbers are reproducible.

---

## 6. Sequencing

Do not micro-optimize before the architecture is in place. In order:

1. Prefilter + candidate bitset (§1.1)
2. Target-grouped plan (§1.2)
3. Transform interning (§1.3)
4. Arena + zero-copy (§2)
5. Regex peephole (§1.4)
6. Everything in Tier 3, profile-driven only

Steps 1–3 are where the order-of-magnitude lives. Step 6 is where projects go to die.
