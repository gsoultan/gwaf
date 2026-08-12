# Prefilter selectivity: a sound literal set can still be a useless one

`Operator.Literals()` returns an OR-set plus a soundness bool. The engine skips
evaluation when *none* of the literals appear. Soundness and selectivity are
different properties, and only the first one is checked anywhere.

## The finding (2026-08-12, during the v0.5.0 perf review)

`detect_xss` declares 19 literals. Four are single bytes: `<`, `"`, `'`, `(`.

A double quote appears in **every JSON body ever sent**. So for JSON traffic the
XSS prefilter never filters: rules 3010, 5011, 3910 and 5911 evaluate on 100% of
JSON requests. `gwaf lint` reports "101 rules, 101 prefiltered, 0 unconditional"
and is telling the truth — the rule *is* gated, on a literal that is always
present.

Measured on `BenchmarkBenignLargeBody` (1 MiB of `{"id":N,"sku":"SKU-000123",
"qty":N,"note":"standard delivery"}`, containing no `<` at all):

- `detect/xss/*` was ~47% of the CPU profile
- `prefilter.Scan` was 39%
- the body has zero markup and zero parens

This was invisible before v0.5.0 because the detectors truncated at
`maxScan = 8192` — they read the first 8 KiB of a 1 MiB body and stopped. The
truncation was itself the padding bypass that v0.5.0 fixed with
`internal/scan.Windows`, so closing the bypass made the pre-existing selectivity
problem *visible* as a 72% slowdown on large bodies. The slowdown is the price of
128x more coverage; it is not a regression to revert.

## Why `"` cannot simply be removed

It is load-bearing. Injection into an existing HTML attribute —
`" onmouseover=location=1` — carries no `<` and no `(`. Removing the quote would
make the prefilter skip the detector on a real attack class, which is the one
failure mode `Literals()`'s soundness contract exists to prevent, and
`FuzzLiteralsAreExhaustive` would catch it.

## What was done instead

Reduced the per-byte cost of running the detector, since it will keep running:

- `matchesScheme` dispatched on the lead byte, so only schemes that can start
  with the byte present are walked (was: all 7, per candidate byte). Control
  bytes, NUL and `&` still fall through to the exhaustive scan because the
  tolerant matcher skips/decodes them.
- the sink lookup gated on `isSinkLead`, derived from the `sinks` table, and
  `callFollows` moved ahead of the map probe. Previously every word in the
  document was walked, folded, hashed and probed — `mapaccess1_faststr` plus
  `aeshashbody` were 13% of the profile.

Both are guarded by equivalence tests against the exhaustive form, not just by
the existing detector tests.

## The open item

The real fix is selectivity, and it is a design change, not a tuning one. Options
considered and *not* taken before v0.5.0:

1. Let the engine tell the operator *which* literals hit, so the detector can
   skip scans only the missing ones could produce. Changes the `Operator`
   interface, which is frozen hard post-v1.0 — worth doing before then, not in a
   patch cycle.
2. Stop scanning the raw body when it was parsed structurally. The quotes that
   trigger the prefilter are JSON's own syntax, not user data; the parsed field
   values are already inspected individually. Needs a hard look at what the raw
   scan catches that the parser misses before anything is removed.

A literal's selectivity should be measurable at compile time — `gwaf lint` knows
the corpus and could report "this literal appears in 100% of benign requests".
That would have caught this years earlier than a profile did.

See [[measured_results]] for the numbers and [[decisions]] for what was rejected.
