# gwaf: The Core Concept

> **Every other WAF is an interpreter. gwaf is a compiler.**

That is the whole thesis. Everything below is a consequence of it.

---

## The reframe

ModSecurity, Coraza, and every SecLang engine treat a ruleset as **a list to walk**. Per request:
load rule, resolve targets, apply transforms, run operator, repeat 200 times. All the work is at
runtime, all of it repeated, on every request, forever.

But a ruleset is **static**, and requests are **streams of bytes**. That is exactly the shape of a
compiler problem — and compilers solved this decades ago.

Reframed, gwaf is:

```
rules  ──►  IR  ──►  optimizer passes  ──►  executable plan  ──►  run over bytes
       frontend                  compile time  │  runtime
```

Every optimization in [PERFORMANCE.md](PERFORMANCE.md) stops being a trick and becomes a named
compiler pass:

| WAF optimization | Compiler name |
|---|---|
| Prefilter automaton | automaton construction |
| Transform chain interning | common subexpression elimination |
| Regex → literal/prefix matcher | instruction selection, strength reduction |
| Target grouping | loop fusion |
| Phase short-circuit | dead code elimination |
| Per-route policies | procedure cloning / specialization |
| Schema-driven pruning | constant propagation |

Once you see it this way, the roadmap writes itself and the performance ceiling moves by an order
of magnitude — because you're no longer optimizing a loop, you're eliminating it.

---

## The seven concepts

### 1. The plan is a program, not a list

Rules compile to a flat, serializable IR, then to a **closure-threaded execution plan** at load.

A note on the obvious alternative: a bytecode VM is the textbook answer, and in Go it is usually
*slower*. Go's interpreter loop pays bounds checks and has no computed `goto`. Closure threading —
each node a `func(*ctx) verdict` calling the next — lets the compiler inline and keeps branch
prediction happy.

So: **flat IR for storage and analysis, closures for execution.** Serializable like bytecode, fast
like native. Do not build the VM.

### 2. Fuel, not clocks

Budget enforcement via `time.Now()` per rule is self-defeating — a vDSO call per rule can cost more
than the rule.

Instead, meter **fuel**: every plan node declares a static cost, and the transaction carries a
counter. Exhaustion triggers `FailMode`.

```go
tx.fuel -= n            // one subtract, one predictable branch
if tx.fuel < 0 { ... }
```

This is what wasmtime and wazero do, and the properties are exactly what a security library needs:

- **Deterministic.** Same input, same fuel consumed. Every time.
- **Reproducible.** A budget violation reproduces in a unit test. Wall-clock ones don't.
- **Zero syscalls** on the hot path.
- **Provable DoS bound.** Max fuel per request = bounded work, *independent of input*. Not "we hope
  it's fast" — a ceiling you can state in the threat model.

Wall-clock remains as a coarse backstop for the pathological case (a custom operator blocking on
I/O it shouldn't be doing). Fuel is the primary mechanism.

### 3. Transduce, don't materialize

The single biggest allocation source in every WAF is materializing transformed copies:
`lowercase(urlDecode(arg))` allocates a new buffer, per rule, per argument.

**Don't produce the transformed bytes at all.** Fold streamable transforms into the matcher's
transition function — a transducer. The automaton matches `sqlmap` against `SQL%4dAP` by
case-folding and URL-decoding *during state transition*, reading the original buffer, writing
nothing.

```
classic:   [raw] → alloc → [urldecoded] → alloc → [lowercased] → match
gwaf:      [raw] ────────── transducing automaton ──────────────► match
```

Not every transform is streamable — base64 and HTML-entity decoding change lengths and need
lookahead. The compiler classifies them: streamable ones fold into the automaton, the rest
materialize into the arena once and are shared by every rule that needs them (concept 1's CSE).

Typical rulesets are dominated by streamable transforms. This is where "zero allocations on benign
traffic" actually comes from.

### 4. Multi-interpretation as a lattice, not a loop

The CVE-2026-21876 bug class comes from picking *one* decoding and matching against it, while the
backend picks another. The obvious fix — evaluate all N plausible decodings — costs N× and so nobody
ships it.

Represent the ambiguity as a **decode lattice**: a DAG over byte positions where ambiguous input
forks (`%2e` → `.` *or* literal `%2e`; a multipart part under charset A *or* charset B) and rejoins.

Then run the automaton over the lattice as an **NFA with a bitset of active states**. Shared prefixes
are evaluated once. Cost stays `O(|states| × |input|)` — linear, same as before.

```
        ┌─ "." ─┐
"..%2e" ┤       ├─ "/" ─►  matches path-traversal on branch 1 only
        └"%2e"──┘
```

This is the concept I'd defend hardest, because it collapses the usual tradeoff: multi-interpretation
is normally the *expensive, secure* choice, and here it's nearly free. Security and speed from the
same mechanism rather than in tension.

**Bounded, always.** Max simultaneous interpretations is a config parameter (default 8). Exceeding it
is a *decision*, not a silent truncation — ambiguity beyond the bound means the request is
un-analyzable, and un-analyzable is not the same as clean.

### 5. Pointer-free transaction state

Go's GC cost is driven by pointers traced, not bytes held. So the hot path holds no pointers.

Values are `types.Span{Off, Len uint32}` — offsets into the transaction's single arena — not
`[]byte`. Eight bytes, no pointer, **the GC never traces them**. A transaction's entire working
state becomes invisible to the collector.

```go
type Span struct{ Off, Len uint32 }   // GC-invisible
func (s Span) Bytes(a *Arena) []byte  // materialize only at the boundary
```

Under Go 1.26's Green Tea GC — which won its 10–40% by improving small-object marking locality —
data the collector never has to mark is the logical endpoint of that optimization. This also gets
enforcement for free: a `Span` *cannot* outlive its arena by accident, because it isn't a reference.

### 6. Positive security is a performance optimization

The idea I think is genuinely novel here.

An OpenAPI spec says `POST /orders` accepts exactly `{id: int, qty: int, note: string}`. That is
usually treated as a *validation* input. It is also a **compiler input**:

- `id` and `qty` are integers → no SQLi, XSS, SSTI, or shell rule can ever match. **Prune them from
  the plan entirely.** Not "run and fail fast" — never compiled in.
- Only `note` is a string → the full detection plan compiles for one field out of three.
- No file upload declared → multipart machinery is dead code for this route.
- No cookies read → cookie resolution is dead code.

Schema-driven specialization typically prunes **70–90% of the plan** for a well-specified API
endpoint, and the pruning is *provably safe* because anything outside the schema was already going
to be rejected.

So the two things you'd normally trade against each other compound instead: **the better your API is
specified, the faster AND safer gwaf gets.** No WAF on the market treats a schema as a compiler
input. This is the flagship feature.

### 7. Compile once, mmap everywhere

The compiled plan serializes to a flat, pointer-free artifact. Loading is `mmap` plus a handful of
fixups — no parsing.

- **Cold start ≈ 0.** Coraza parsing CRS at startup costs hundreds of milliseconds; that's brutal in
  Lambda/Cloud Run, and it's exactly where a zero-CGO static Go binary otherwise shines.
- **Shared across processes.** N processes `mmap` the same file; the OS page cache gives you one
  resident copy. No daemon, no IPC, no coordination — gwaf stays a library.
- **Off-heap.** A 10k-rule ruleset contributes nothing to GC pressure.
- **Reproducible.** `gwaf build` in CI produces a byte-identical, signable artifact. Rule
  deployment becomes an artifact promotion, not a config push.

---

---

## The accuracy concepts

Concepts 1–7 buy speed and anti-evasion. But **false positives are why WAFs get turned off**, and a
WAF in detection-only mode protects nothing. These five exist to attack FP rate directly — without
giving up the stateless boundary (CLAUDE.md §1).

### 8. Confidence is measured, not declared

Rules declare a `Confidence` (RULES.md §8). Letting the *author* pick it is how every ruleset drifts:
everyone believes their rule is precise.

So the corpus decides. CI runs every rule against the benign corpus, measures actual precision, and
**fails the build when declared confidence doesn't match measured**:

```
$ gwaf calibrate ./ruleset
  942100  declared=Certain  measured FP=0.41% (17/4,120 benign)   FAIL — max for Certain is 0.01%
  941110  declared=High     measured FP=0.02% (1/4,120)            ok
  1000340 declared=Medium   measured FP=0.00%                      note: promote to High?
```

Measured precision is then **stored in the compiled artifact**, so `Confidence` at runtime is an
empirical number, not an opinion. This is the single highest-leverage accuracy idea here: it turns
FP rate from something discovered in production into a build-time gate.

### 9. Context decides the verdict, not just the payload

`' OR 1=1--` in a `qty` field is an attack. In a `bug_report.body` field it's a user quoting an
attack. Signature WAFs cannot tell these apart and that is a large share of real-world FPs.

The schema already tells us (concept 6). Same mechanism, different payoff:

| Field context | `<script>` verdict |
|---|---|
| `qty: integer` | **Block** — cannot legitimately contain this |
| `email: string, format=email` | **Block** — fails format anyway |
| `comment: string` rendered as text | Score only |
| `content: string, x-gwaf-context: markdown` | Allow — expected |

Concept 6 said schema makes gwaf *faster*. Concept 9 says it makes gwaf *more accurate*, via the
same input. That's the compounding argument for specifying your API: one artifact, three wins
(security, speed, precision).

### 10. Cross-parameter correlation, still stateless

Splitting a payload across parameters (`a=UNI`, `b=ON SEL`, `c=ECT`) defeats per-value matching.
Real WAFs miss this; SafeLine markets resistance to it.

gwaf evaluates a **joined view** of a request's arguments as an additional target, in schema-declared
or wire order. This stays strictly within the stateless boundary — it's one request, no memory — and
it's cheap because the prefilter runs over the joined buffer in the same single pass (concept 3).

Guarded: joined-view rules run at reduced confidence by default, because concatenation invents
adjacency that wasn't in the original request. High FP risk if treated as equal evidence.

### 11. Protocol desync detection is engine-level, not a rule

Request smuggling (CL/TE conflict, duplicate `Content-Length`, obs-fold, chunked-extension abuse) is
how attackers get the WAF and the origin to disagree about where a request *ends*. No rule can catch
it, because by then the parse already happened.

gwaf's body reader treats framing ambiguity as a **first-class decision**, not a parse detail:
conflicting or duplicate framing headers, and any ambiguity the origin might resolve differently, is
rejected before rules run.

This is the same failure class as CVE-2026-21876 — WAF and backend disagreeing about interpretation —
one layer down. Concept 4 handles ambiguity *within* a request; concept 11 handles ambiguity about
*what the request is*.

### 12. Offline learning, compiled artifact, stateless runtime

The best FP-tuning input is your own traffic. But learning at runtime means state, adaptation, and an
attacker-influenceable model — everything the boundary forbids.

Resolution: **learn offline, ship an artifact.**

```
$ gwaf learn --from access-log.jsonl --ruleset ./rules
  analyzed 2.1M requests, 14 rules produced findings

  942100  /api/v1/markdown       412 hits, 0 confirmed attacks
          suggested: Except(942100).On(PathPrefix("/api/v1/markdown")).For(Body())
  920420  /grpc/*                 8.1k hits — all application/grpc
          suggested: Except(920420).On(ContentTypePrefix("application/grpc"))

  wrote exceptions.suggested.yaml — review before committing
```

Runtime stays memoryless. The output is reviewable, diffable, version-controlled code — not an opaque
model. It's also the honest answer to open-appsec's ML approach: same benefit, full explainability,
and a human approves every suppression.

---

## What this buys

| | Interpreter WAF | gwaf |
|---|---|---|
| Rules evaluated / benign request | ~200 | **0** |
| Regex executions / request | ~4,000 | **0–3** |
| Transform allocations / request | ~40 | **0** |
| Budget enforcement | wall clock, nondeterministic | **fuel, deterministic** |
| Multi-interpretation cost | N× (so: not shipped) | **~1×** |
| GC pressure from tx state | proportional to traffic | **~0 (pointer-free)** |
| Ruleset cold start | 100s of ms | **~0 (mmap)** |
| Schema effect on cost | none | **70–90% plan reduction** |
| Confidence rating | author's opinion | **measured on corpus, CI-gated** |
| Split-payload evasion | missed | joined-view target, same pass |
| FP tuning | production archaeology | **`gwaf learn` → reviewable diff** |

Target SLOs, all CI-gated:

| Metric | Target |
|---|---|
| Benign GET, no body | p50 < **2 µs**, 0 allocs |
| Benign POST, 1 KB JSON | p50 < **15 µs**, < 4 KB |
| p99, any workload | < **100 µs** |
| Resident ruleset, 10k rules | < **16 MB**, shared, off-heap |
| Per in-flight transaction | < **8 KB** p50, < 64 KB p99 |
| Heap growth under sustained load | **0** |
| Ruleset scaling 10 → 10k rules | **sub-linear** |

---

## Honest risk assessment

| Concept | Risk | Mitigation |
|---|---|---|
| 1. Closure plan | Closure-threading may not beat a naive loop until the ruleset is large | Benchmark both at 10/100/1k rules in Phase 1. Keep the IR; the executor is swappable. |
| 2. Fuel | Static cost estimates drift from reality | Calibrate costs from benchmarks; CI asserts fuel↔wall-clock correlation |
| 3. Transducers | Genuinely hard. Composing decode + case-fold in one transition table is subtle, and subtle is where bypasses live | Ship the 5 most common transforms only. Differential-fuzz transducer vs. materialized path — they must agree on 100% of inputs. |
| 4. Decode lattice | State explosion on adversarial input | Hard bound on simultaneous interpretations; exceeding it is an explicit decision |
| 5. Pointer-free | Ergonomic cost — `Span` is less pleasant than `[]byte` | Confine to `internal/`; the public API speaks `[]byte` |
| 6. Schema specialization | Only helps specified APIs; a wrong schema prunes real coverage | Fall back to the full plan when unspecified. Schema changes force recompile; never trust a runtime-supplied schema. |
| 7. mmap artifact | Format versioning, endianness, a new corruption surface | Version + checksum + signature; reject on mismatch, never "best effort" load |

**Concept 3 is the one I'd watch.** Transducers are where a clever optimization can silently
introduce the exact bypass class we built concept 4 to eliminate. The differential fuzz harness
against the materialized path is not optional — it is the feature.

---

## Build order

Sequenced so each step is independently valuable and de-risks the next.

1. **IR + closure plan + fuel** (concepts 1–2). No optimizations yet. Establishes the compile→execute
   split and deterministic budgets. Everything else is a pass over this.
2. **Prefilter + target-grouped plan.** The first order of magnitude. Materialized transforms — slow
   but obviously correct, and it becomes the differential-fuzz oracle for step 4.
3. **Arena + Span** (concept 5). Allocations to zero.
4. **Transducers** (concept 3), fuzzed against step 2's oracle.
5. **Decode lattice** (concept 4). Ship semantic detectors on top.
6. **Schema specialization** (concept 6), once OpenAPI validation exists.
7. **mmap artifacts** (concept 7). Pure win, no dependents — last.

Steps 1–3 deliver most of the performance. Steps 4–6 are what makes gwaf categorically different
rather than incrementally faster.

---

## The one-paragraph pitch

> gwaf compiles security policy the way a database compiles a query. Rules, schemas, and route
> policies are inputs to an optimizer that emits a specialized, pointer-free execution plan; requests
> are streamed through it in a single pass, with transformations folded into the matcher and
> ambiguous encodings evaluated as a lattice rather than a loop. Work is metered in deterministic
> fuel, not wall-clock, so the DoS bound is provable rather than hoped for. The result: zero rules
> evaluated on benign traffic, zero allocations on the hot path, near-free multi-interpretation
> decoding, and an API contract where **specifying your API makes the firewall both faster and
> safer.**
