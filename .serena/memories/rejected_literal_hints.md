# Rejected: telling operators which literals hit

Built, measured, proven unsound, reverted — 2026-08-13, during the v0.5.1 cycle.
Do not rebuild it without reading the counterexample.

## The idea

`Operator.Literals` is an OR-set: the engine skips the operator when *none* of
the literals appear. It says nothing about the usual case where *one* appears.
Measured on the 1 MiB benign JSON body from `BenchmarkBenignLargeBody`:

    rule 3910, 19 literals
      HIT  (1): ["\""]
      MISS (18): ["<" "javascript:" ... "eval" ... "'" "-->" "("]

Exactly one literal present, and the eighteen absent ones include every literal
`scanMarkup` keys on — while `scanMarkup` was 24% of that profile. So: report the
per-literal hit set to the operator, let it skip the scans only a missing literal
could satisfy.

The premise was real. The implementation worked. It is still wrong.

## Why it is unsound

`scanMarkup` reports a signal for input containing **none** of its trigger
literals:

    "jAvAsCrip t:"           scanMarkup=true   literals present: []
    "java\tscript:"          scanMarkup=true   literals present: []
    "j a v a s c r i p t :"  scanMarkup=true   literals present: []

`matchesSchemeFolded` skips whitespace, NUL and other control bytes, and decodes
HTML character references, because `java&Tab;script:` and `java\x00script:`
execute in a browser. That tolerance is the anti-evasion behaviour the detector
exists for — and it means the detector matches text its own literals are absent
from. Any gate of the form "literal L did not occur, so scan S cannot fire" is
therefore false for every tolerant scan.

Found by `FuzzLiteralHintIsSound` (evaluate with the honest hint, evaluate with
none, require the same verdict) on the *first* seed containing `-->`, and then
again on generated input. Neither the detector's own table tests nor
`FuzzLiteralsAreExhaustive` would have found it: every existing case contains the
literals, so they all take the un-skipped path and pass either way.

## The finding worth keeping

**The literals are broad because tolerant matching requires them to be.**

`detect_xss` declares `"`, `'` and `(`. Those look like sloppiness and they are
load-bearing: they are what nominates rule 3010 for `jAvAsCrip t:alert(1)`, whose
`javascript:` literal is not literally present. The shipped ruleset catches that
payload today precisely because the broad literals are there.

So the selectivity problem `gwaf lint -corpus` measures
([[prefilter_literal_selectivity]]) is not a set of mistakes to be tightened
away. It is the cost of tolerant matching, and tightening a literal to improve
selectivity is a bypass unless the matching it guards is byte-exact. Any future
selectivity work has to start there.

## If someone tries again

A hint is only sound for a scan that is byte-exact in the literal it keys on.
`scanMarkup`'s `case '<'` qualifies; its scheme, style and sink matching does
not, and they share one loop over the input, so gating the `<` branch alone saves
nothing — the loop is the cost.

What was actually built and reverted, in case the infrastructure is wanted for a
different consumer: `EvalContext.Literals` as a one-word `LiteralHits` whose
`Has` returns **true** when nothing is known (so a forgotten `Known()` check is
safe, not a total bypass); an optional `LiteralHinted` interface so `Operator`
itself never changes and non-participating groups do zero bookkeeping;
`prefilter.ScanLiterals` writing literal indices inside the emit loop only, which
runs on matches and so costs nothing on benign traffic. That part was clean. It
was reverted because shipping interface surface with no sound consumer means
freezing an API on speculation, and the four extension interfaces freeze hard at
v1.0.
