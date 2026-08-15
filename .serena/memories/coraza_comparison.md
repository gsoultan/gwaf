# gwaf vs Coraza+CRS: the measurement, and how to read it

Run 2026-08-16 (`75a91b2`) via `make headtohead`, which needs CRS cloned:

```
git clone --depth 1 https://github.com/coreruleset/coreruleset /tmp/crs
CRS_TESTS=/tmp/crs/tests/regression/tests CRS_RULES=/tmp/crs/rules make headtohead
```

## The two numbers, and why both are required

**OWASP CRS regression corpus, 4025 attack cases — CRS's home turf:**

| engine | detection |
|---|---|
| gwaf | 1059/4025 — 26.3% |
| gwaf+crs (SecLang bridge) | 2429/4025 — 60.3% |
| coraza+crs | 3246/4025 — **80.6%** |

**10,473 ordinary API requests (JSON, JWT, gRPC-Web, protobuf) — gwaf's corpus:**

| engine | false positives |
|---|---|
| gwaf | 0 — **0.00%** |
| gwaf+crs | 966 — 9.22% |
| coraza+crs | 3802 — **36.30%** |

Coraza detects 3x more on CRS's suite and blocks **more than one ordinary API
request in three**. Quoting either number alone is dishonest; the test file says
so itself and lists the caveats (each corpus is its own engine's home turf;
Coraza runs untuned CRS at PL1; the traffic is API-shaped).

## Where the 3000-case gap actually is

`TestCRSGapAnalysis` (test/headtohead/gap_test.go) groups misses by CRS family
and prints payloads with `GAP_FAMILY=932`. Three kinds, and only one is a defect:

1. **CRS negative space — most of it.** Family 942 (SQLi, 653 misses) wants
   `4294967296` blocked. A number. Also `2.2250738585072011e-308`, `' ', 10`,
   `pay=":["00`. Family 933 (PHP, 219) wants `engine=true`, `precision=true`,
   `smtp=true`. Family 941 (XSS, 122) is largely XHTML-namespace and legacy-IE
   constructs no current browser executes. **This is what the 36.30% buys.**
   Closing it would mean becoming CRS.
2. **Out of scope by construction.** 920 protocol enforcement (embedder's
   parser), 943 session state, 95x response-side.
3. **A real gap: family 932, command injection.** Genuine RCE with a separator
   and a command in position. Fixed in `75a91b2` by adding the command
   *vocabulary* (LOLBAS + GTFOBins); 16.7% → 21.5%.

**The lesson: a competitor's corpus measures agreement with that competitor's
policy, not security.** Read the payloads before chasing the number.

## The free-fix pattern worth reusing

Adding 34 commands cost **nothing**: `Literals()` was untouched, because a
command-position match already requires a separator and the separators are
declared literals. The automaton stays the same size, nomination is unchanged,
and a map lookup does not care how many keys it has. When adding vocabulary,
check first whether an existing structural literal already gates it.

## "rev" — the recall that did not cover its cost

`rev` had been in the command list. It reverses characters per line (the weakest
reader — an attacker uses `cat`) and is three letters engineering prose emits
constantly: `"the PR is ready; rev 3 is current"` was blocked. Removed.
`net`, `reg`, `sc`, `join`, `paste`, `expand`, `top`, `vi`, `ex` were declined
before being added, each with its reason in the code. `fold`, `column`, `bridge`
were kept: English words made safe by position, and none occurs after a
separator anywhere in the 10,473-request corpus.

## Standing state

Mythos corpus: **95/102 (93.1%) detection at 0.00% FP over 65 benign.**
Shipped evasion corpus: 334/334, 0/176. `make check` green end to end.

See [[redteam_round6_blueteam]], [[redteam_round5]], [[measured_results]].
