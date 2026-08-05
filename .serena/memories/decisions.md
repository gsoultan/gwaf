# Decisions and Negative Results

The most valuable memories here are the things that were **built, measured, and
rejected**. They exist so nobody rebuilds them.

## REJECTED: transducers (CONCEPT.md §3)
Fold streamable transforms into the matcher so normalized bytes are read
straight from the request with no copy.

Built. Proven correct — 38.6M differential fuzz execs, byte-for-byte identical
to the materialized oracle, identical candidate sets. **Then measured 1.3–2.0×
SLOWER in every case** and removed.

Two reasons, visible only once both paths existed:
1. The allocation it targeted **was already gone** — the materialized path
   reuses scratch and short-circuits when a transform changes nothing.
2. Per-byte pull through a function call costs more than the copy it avoids;
   materialized loops vectorize, transduced ones cannot.

Numbers: `bench/transducer-experiment.txt`.

**The meta-lesson, which matters more:** the kill criterion anticipated a
*correctness* failure. The real failure was that the **premise** had already
been satisfied by simpler means. **Test the premise, not only the
implementation.**

## SIMPLIFIED: decode lattice → conditional multi-interpretation (§4)
The lattice (NFA over ambiguous byte positions) exists to make N readings cost
~1×. But that premise only holds if values are usually ambiguous, and almost
none are. Shipped instead: one cheap `Detect` pass; a value with no ambiguity
marker has exactly one reading and costs what it did before.

Result: 76/76 evasion, 0 false positives, 1× on clean input. The lattice is
**not needed** until profiles show ambiguous traffic is common.

## REJECTED: bytecode VM (§1)
Textbook answer, and in Go usually *slower* — no computed `goto`, bounds checks
in the dispatch loop. Flat IR for storage, closures for execution.

## NOT BUILT: compile-time per-route plan pruning (§6)
The per-value form already delivers most of the benefit. Measure before adding
the machinery. (Transducer lesson.)

## No paranoia levels
PL1–PL4 is a CRS *tagging convention*, not an engine feature — and it is global
where FP tolerance is per-route. Replaced by per-rule `Confidence` +
policies. `WithParanoiaLevel(n)` survives as a CRS-compat preset.

## Rules are structs, not a fluent builder
Structs serialize, diff in review, and codegen. Builders do none of those and
add a state machine to get wrong. It is also what keeps the Go and declarative
frontends isomorphic rather than merely similar.

## Blocking by default
`gwaf.New()` with zero args blocks. Defensible only because `ruleset/core`
ships Certain/High confidence rules only. A WAF that silently protects nothing
is worse than none — the operator believes they are covered.

## SHIPPED: structural SQL detection (`detect/sqli`)
Tokenize the value and score **grammar**, not strings. Four interpolation
contexts (bare, single-quote, double-quote, backtick) so quote-breaking is
visible: "1' OR 1=1--" read literally is a number and an unterminated string;
read as interpolated inside '...', the quote *closes* the literal and the rest
is a tautology plus a truncating comment.

48/48 payload variants, 0/56 false positives on prose.

**It replaced four literal rules rather than joining them.** Rule 2002
(`unionselect` after whitespace stripping) was an active false positive: "the
union selected a new representative" collapses to "unionselected". IDs 2001-2004
are **retired, not reused** — they appear in audit logs and any exception
already written.

Signals are weighted so that weak evidence needs corroboration: a trailing
comment or an apostrophe is ordinary in real text. Danger functions require
**attachment** to surrounding SQL, which is what keeps "sleep(8h) is the
recommendation" out.

Deliberate non-detection: `1'' OR ''1''=''1`. Doubled quotes are *correct SQL
escaping* — the origin parses it as one harmless string literal. Flagging it
would mean assuming a non-standard parser and would false-positive on every
correctly-escaped value.

**Cost, stated honestly.** The detector declares broad literals (`=`, `'`, `"`)
because payloads are built from them, so prose containing those is a prefilter
candidate. "Zero rules evaluated on benign traffic" is therefore no longer
literally true; the claim was **restated**, not quietly weakened, to: rules
evaluated is a small constant independent of ruleset size, zero when the value
has no attack vocabulary. Benign POST with a 1 KiB JSON body went 6.5us -> 17.6us
because the whole body is tokenized as one value; field-level JSON parsing will
cut that and is the next real optimization.
