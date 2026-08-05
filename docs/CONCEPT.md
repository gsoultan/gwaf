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

### 3. ~~Transduce, don't materialize~~ — BUILT, MEASURED, REJECTED

> **Status: rejected on evidence.** Implemented, proven correct against the materialized oracle by
> 38.6M differential fuzz executions, then measured **1.3–2.0× slower in every case** and removed.
> Raw numbers: [`bench/transducer-experiment.txt`](../bench/transducer-experiment.txt).

The original claim: materializing `lowercase(urlDecode(arg))` is the biggest allocation source in a
WAF, so fold streamable transforms into the matcher's transition function and read normalized bytes
straight from the request buffer, writing nothing.

It was wrong, for two reasons that only showed up once both paths existed side by side.

**The allocation it was meant to eliminate was already gone.** The materialized path reuses a
per-transaction scratch buffer and short-circuits when a transform changes nothing. Benign traffic
is already lowercase and already unencoded, so it performs *zero copies* and *zero allocations*
without any of this. The stated payoff had already been delivered by simpler means — the theory was
formed before the baseline existed.

**Per-byte pull costs more than the copy it avoids.** Materializing runs a tight, vectorizable loop
per transform and then hands the automaton a contiguous slice to `range` over. Transducing replaces
that with a function call and a per-step branch for every byte, and neither the transform loop nor
the scan can vectorize. In Go the copy is nearly free and the dispatch is not.

| Case | Materialized | Transduced | |
|---|---|---|---|
| benign, already normal | 112 ns | 212 ns | 1.89× slower |
| benign, mixed case | 115 ns | 211 ns | 1.84× slower |
| percent-encoded | 96 ns | 121 ns | 1.26× slower |
| attack payload | 160 ns | 268 ns | 1.68× slower |
| 4 KiB clean | 8.4 µs | 16.8 µs | 2.01× slower |

**What survives.** Concept 1's common-subexpression elimination — grouping rules by transform chain
so each chain is applied once per value rather than once per rule — is where the real win was, and
it shipped. The differential harness pattern (assert byte equality *and* identical prefilter
candidate sets against a deliberately simple oracle) is reusable and is the gate every future
transform optimization should pass.

**What would have to change to revisit this.** A transducer only wins if the transform is fused into
the automaton's own scan loop rather than pulled through a function call — one specialized loop per
chain shape. That is a large amount of hand-written, hard-to-audit code for, at best, parity with a
path that already allocates nothing. Not worth it.

This entry stays in the document rather than being deleted. The idea is attractive enough that
someone will propose it again, and the useful artifact of the experiment is the measurement.

### 4. Multi-interpretation: evaluate every reading — SHIPPED

> **Status: built and measured.** 76/76 evasion corpus, 0/72 false positives.
> Shipped as *conditional* multi-interpretation rather than the lattice
> originally specified; the reason is below.

The CVE-2026-21876 bug class comes from picking *one* decoding and matching
against it, while the origin picks another. The obvious fix — evaluate all N
plausible decodings — costs N×, so nobody ships it.

The original plan was a **decode lattice**: a DAG over byte positions where
ambiguous input forks and rejoins, walked as an NFA so shared prefixes are
evaluated once and cost stays ~1×.

**What shipped is simpler, and the transducer taught the lesson that made it
simpler.** The premise "N× is too expensive" only holds if every value is
ambiguous. Almost none are. So: one cheap pass detects whether a value contains
any ambiguity marker at all (`%`, `\`, `+…-`, `&`, NUL, an overlong lead byte),
and a value with none has exactly one reading and costs exactly what it cost
before. Only genuinely ambiguous input — which is precisely the input that
deserves scrutiny — pays for alternatives.

Measured: detection is 22 ns for a 57-byte clean value (2.5 GB/s), and building
readings for an unambiguous value is 1.7 ns.

Six readings, each grounded in a real disagreement rather than a theoretical
encoding:

| Class | Origin behaviour it models |
|---|---|
| `double_encoded` | Proxy and app server each decode once |
| `separator` | Windows, .NET, Java accept `\` as a path separator |
| `null_truncate` | C-backed handlers stop at NUL (matters for allowlists) |
| `overlong_utf8` | Permissive decoders resolve `%c0%ae` to `.` |
| `utf7` | **CVE-2026-21876** — `+ADw-script+AD4-` is `<script>` |
| `html_entity` | Value reflected into a document before use |

Detection is the **union over readings**, which is the safe direction: an extra
reading costs work, never coverage. Every decision reports which reading found
the payload, because an operator seeing inert bytes in an audit log and no
explanation concludes the firewall malfunctioned.

**Bounded, and the bound is a decision.** Readings are capped; exceeding the cap
yields `ReasonUndecidable`, not an allow. A value too ambiguous to enumerate has
not been shown to be clean — that assumption is exactly what CVE-2026-21876
turned into a bypass.

**Known limitation, stated rather than hidden.** UTF-7 detection requires the
explicit `-` terminator. Implicit termination is legal UTF-7 and is not
detected; covering it would mean reading every `+` in every query string two
ways, and `+`-as-space is most of the internet. Revisit if a payload in the wild
uses it.

**Is the lattice still worth building?** Only if profiles show ambiguous traffic
is common enough for N× to matter. On this corpus it is not. That is the
transducer lesson applied: test the premise before building the optimization.

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

### 6. Positive security is a performance optimization — SHIPPED

> **Status: built and measured.** 29% faster wall-clock, 56% less work, and
> stricter, from one artifact. Evasion coverage unchanged, false positives still
> zero.

An OpenAPI spec says `POST /orders` takes `{id: int, qty: int, note: string}`.
That is usually treated as a *validation* input. It is also a **compiler input**.

If a field is declared an integer and the value really is an integer, it
contains only digits and a sign. It cannot contain `UNION SELECT`. It cannot
contain `<script`. Running injection rules against it is not merely unlikely to
match — it is *provably incapable* of matching, so the rules are skipped and
skipping them is sound rather than heuristic.

Measured on a realistically specified endpoint — five constrained fields, one
free-text field:

| | With schema | Without |
|---|---|---|
| Latency | **1135 ns** | 1593 ns |
| Fuel (work performed) | **314** | 710 |

29% faster, 56% less work, *and* every out-of-spec request rejected before a
rule runs.

**The claim is enforced, not asserted.** `Field.Inert()` says a validated value
cannot carry a payload, and a fuzz harness fails the build if any inert field
ever validates a value containing a byte from the attack vocabulary. It found
one on the first run: RFC 3339 permits a space as the date/time separator, and a
space is a byte an attack can use. The grammar was tightened rather than the
invariant weakened.

**Guard rails that keep a partial schema from becoming a hole:**

- A route the schema does not describe gets full inspection, exactly as if no
  schema existed.
- A string field is never inert. Free text gets the whole pipeline, so a payload
  in `note` is still caught.
- A value that *fails* validation is the opposite of inert — it is the most
  suspicious value in the request and gets full inspection.
- Base64 is not inert: its alphabet includes `+` and `/`, and the decoded
  content is unknown to the schema.

**Compile-time plan specialization** — pruning rules per route rather than per
value — is the remaining half and is not built. The per-value form already
delivers most of the benefit; the transducer lesson says measure before adding
the machinery.

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

### 8. Confidence is measured, not declared — SHIPPED

> **Status: built and gated.** `gwaf calibrate` measures every rule against a
> committed benign corpus and fails the build when a rule's rate exceeds its
> declared tier. It also reports the corpus's own statistical power, so a clean
> run is not mistaken for a stronger guarantee than it is.


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

### 11. Protocol desync detection is engine-level, not a rule — SHIPPED

> **Status: built, after a probe showed it missing.** This concept was specified
> during design and never implemented; a CL.TE conflict passed cleanly for
> several months of commits. `ReasonDesync` is now checked before any rule runs,
> and is the one reason FailOpen does not soften — an ambiguously framed request
> is potentially two requests, the second of which no firewall has seen.


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
| Transform allocations / request | ~40 | **0** (via chain CSE, not transducers — §3) |
| Budget enforcement | wall clock, nondeterministic | **fuel, deterministic** |
| Multi-interpretation cost | N× (so: not shipped) | **1× on clean input, N× only when ambiguous** |
| GC pressure from tx state | proportional to traffic | **~0 (pointer-free)** |
| Ruleset cold start | 100s of ms | **~0 (mmap)** |
| Schema effect on cost | none | **56% less work, 29% faster (measured)** |
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
| ~~3. Transducers~~ | **Resolved: rejected.** Correct (38.6M fuzz execs agreed) but 1.3–2.0× slower. The harness caught it before it shipped. | Materialized transforms + chain CSE, already in production |
| ~~4. Decode lattice~~ | **Resolved: not needed.** Conditional multi-interpretation ships the same security property at 1× on clean input. | Reading cap; exceeding it yields ReasonUndecidable |
| 5. Pointer-free | Ergonomic cost — `Span` is less pleasant than `[]byte` | Confine to `internal/`; the public API speaks `[]byte` |
| ~~6. Schema specialization~~ | **Resolved.** Undescribed routes fall back to full inspection; strings are never inert; a fuzz harness enforces the Inert claim. | — |
| 7. mmap artifact | Format versioning, endianness, a new corruption surface | Version + checksum + signature; reject on mismatch, never "best effort" load |

**Concept 3 is the one I'd watch.** Transducers are where a clever optimization can silently
introduce the exact bypass class we built concept 4 to eliminate. The differential fuzz harness
against the materialized path is not optional — it is the feature.

---

## Build order

Sequenced so each step is independently valuable and de-risks the next.

1. ~~**IR + closure plan + fuel**~~ (concepts 1–2). **Done.** Compile→execute split, deterministic
   budgets.
2. ~~**Prefilter + chain-grouped plan.**~~ **Done** — the first order of magnitude. 10 → 10,000 rules
   costs the same. Materialized transforms kept deliberately: slow but obviously correct, and the
   oracle step 4 was measured against.
3. ~~**Arena + Span**~~ (concept 5). **Done.** Zero allocations on benign traffic.
4. ~~**Transducers**~~ (concept 3). **Rejected on measurement** — see §3. The step-2 oracle did its
   job.
5. ~~**Decode lattice**~~ (concept 4). **Done** as conditional multi-interpretation — 76/76 evasion, 0 false positives.
6. ~~**Schema specialization**~~ (concept 6). **Done** per-value: 29% faster, 56% less work, stricter. Compile-time per-route pruning remains, unbuilt pending measurement.
7. **mmap artifacts** (concept 7). Pure win, no dependents — last.

Steps 1–3 delivered most of the performance and are done. Steps 5–6 are what make gwaf
categorically different rather than incrementally faster; step 6 is the one to prioritize.

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
