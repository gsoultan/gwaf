# Measured Results

Apple M5 Pro, Go 1.26.5, full core ruleset. `make bench`, `make corpus`.
**Never quote these from memory — re-run them.**

## Latency / allocation
| Workload | Latency | Allocs |
|---|---|---|
| Benign GET | 1.22 µs | **0** |
| Benign POST 1 KiB JSON | 6.48 µs | **0** |
| Attack (blocked at headers) | 0.83 µs | 1 |

## Ruleset scaling — the central claim
| Rules | Latency | Rules evaluated |
|---|---|---|
| 10 | 277 ns | 0 |
| 10,000 | **276 ns** | **0** |

## Schema specialization — the flagship
| | With schema | Without |
|---|---|---|
| Latency | 1135 ns | 1593 ns |
| Fuel | 314 | 710 |

29% faster, 56% less work, **and** stricter.

## Detection
- Evasion corpus: **76/76 (100%)**
- Benign corpus: **0/72 false positives (0.00%)**

Detection rate is never reported alone — a rule blocking everything scores 100%
on recall and gets the firewall disabled.

## OWASP CRS import (measured 2026-08-08)

Verified against real releases, not a fixture: **4.25.1 LTS** and **4.28.0**
(`coreruleset-<v>-minimal.tar.gz` from the GitHub releases page).

| | 4.25.1 LTS | 4.28.0 |
|---|---|---|
| Directives read | 786 | 788 |
| Rules imported | 221 | 225 |
| Prefiltered | 121 | 121 |
| Reported not translated | 278 | 276 |

Generated Go compiles and loads; 8/8 attack probes blocked, 0/4 benign blocked.

**The import was broken outright before this.** Two hand-maintained transform
tables drifted — the compiler emitted `transform.EscapeDecode` for `t:jsDecode`,
`generate.go` had no name for it — so `report` claimed success and `convert`
failed on CRS 932210. Every conversion of the actual CRS. No test caught it
because they all fed `Generate` a fixture that avoided the transform. One table
now, walked by a test.

Of the ~278 skips, roughly **104 are the scope line working as intended** (TX
anomaly-scoring state 52, `&ARGS` collection counting 31, `SecAction setvar` 7,
`@validateByteRange` 5, engine-internal variables 6, unexpanded `%{tx.*}` policy
macros 2) and roughly **174 are addressable gaps**: `SecRuleUpdateTargetById`
(55) and `!ARGS:x` exclusions (20) both want `rules.Exception`; cross-variable
chains (55) are a real IR limit; five transforms account for 43
(`t:cssDecode` 21, `t:cmdLine` 12, `t:replaceComments` 6, `t:base64Decode` 3,
`t:removeCommentsChar` 1).

Do not confuse the two halves when quoting a coverage number.

### Real-tool pentest, core vs converted CRS (`test/pentest/run.sh`)

Same target, same payloads, sqlmap + nikto + curl vectors, WAF-off control first.
Corpus after the protocol/robustness phases were added: 257 attacks, 104 benign.

| | gwaf core | converted CRS |
|---|---|---|
| Attacks blocked | **344/345 (99%)** | 185/257 (71%, older corpus) |
| False positives | **0/184** | 3/104 (older corpus) |
| Rules imported | n/a | 263 (4.25.1) / **267 (4.28.0, latest)** |

### Readings are enumerated *before* transforms — that is a whole bug class

The single most productive finding. `interpret.Detect` runs on the raw value, so
any class keyed on a literal character never sees the percent-encoded spelling a
query string actually delivers:

- `ClassHTMLEntity` looked for `&`, which on the wire is `%26`. **No entity
  payload a browser can send was ever detected.** It fired only for values passed
  to `AddArgument` directly — which is how every unit test exercised it.
- The same held for the fullwidth/best-fit reading.

Auditing the rest found **`ClassUTF7` blind the same way, and it is the
CVE-2026-21876 vector.** A bare `+` in a query string is a space, so every UTF-7
payload a client can send spells the shift `%2B` — the class had never fired on a
real request. `ClassSeparator` too (`%5C`), masked only because rule 1004 matches
the backslash form directly. Three of six classes had shipped inert.

All now read through one percent layer (`percentByteAt` / `percentRuneAt`), and
`hasRawMarkup` does too so the CMS suppression still works.
`TestEveryClassSurvivesPercentEncoding` is the standing guard: **a new class goes
in that table, and if it detects the raw spelling but not the encoded one it does
not work.**

**When adding a reading, test it over HTTP, not only through the library API** —
the two deliver different bytes, and the library path is the one that lies.

### The Medium tier: opt-in, +169 CRS stages, default untouched

`gwaf lint` showed the confidence axis was designed and left empty — 53 Certain,
29 High, nothing else — so `WithMinConfidence` selected nothing. Five Medium
rules (5010–5014) fixed that, each being the **same detector at a lower score**
rather than a new heuristic.

| | default | `WithMinConfidence(Medium)` |
|---|---|---|
| CRS corpus | 1853/5066 (36.6%) | **2022/5066 (39.9%)** |
| Benign gate | 0/51 blocked | (opt-in; FPs expected) |

`TestMediumTierIsOptInAndReachable` asserts both halves behaviourally: the
default must **not** block `1=1`, `javascript:foo`, `system('id')`, and the
Medium WAF must. A tier that changes no verdict is decoration.

### Retiring a rule: the corpus is not enough evidence

`TestRetirementCandidates` (env-gated, root package) removes a rule and re-runs
the evasion corpus. Six of ten candidates lost nothing. **Only four were actually
retirable**, and the difference is the lesson:

A corpus is the cases somebody thought of. After the corpus vote, each rule's own
*canonical* payloads were fired at a WAF built without it — and two "redundant"
rules turned out to carry real coverage:

- **4006** — `jndi:ldap://host/a` has no `${` for `javaser` to anchor on.
- **4016** — `preg_replace('/x/e', …)` scores 4, one short of `phpi`'s threshold.

Retired: 4003, 4004, 4008, 4009. Ruleset 92 → 84 rules, 825 → 813 literals,
8,947 → 8,757 automaton states, chains unchanged, still 0 unconditional. Evasion
corpus unchanged at 271/271; CRS corpus −2 of 5,066.

**Always run the canonical-payload check before deleting a rule.** The corpus
vote alone would have removed two rules that work.

### Two process failures worth not repeating

**I reported "gates clean" twice on a `make check` that never ran the tests.**
It failed at `fmt-check` (an unformatted file) in three lines, and I grepped for
`^FAIL` — which cannot match `make: *** [fmt-check] Error 1`. **Check the exit
code, never a log pattern.** This is the same class as the staticcheck skip in
CLAUDE.md §6, committed by the person who had been citing it all session.

**A real regression hid behind it**: `TestBenignTrafficBoundsRuleEvaluation` had
been failing since the detectors landed, because `phpi` declared `"$"` as a
literal. Benign traffic went 6 → 8 candidates, one case 10. Fixed by narrowing
the variable-function signal to superglobals.

### `gwaf lint` is the load-independent way to price a ruleset change

`bench-guard`'s own message points at it and it is the right tool when the
machine is busy: `go run ./cmd/gwaf lint` reports literals, automaton states,
transform chains and unconditional rules — all deterministic.

Cost of adding `detect/javaser` and `detect/phpi`, measured paired in a worktree:

| | before | after | Δ |
|---|---|---|---|
| Rules | 78 | 82 | +4 (each rule has a headers and a body variant) |
| **Unconditional** | 0 | **0** | every rule still prefilterable |
| Literals | 786 | 823 | +4.7% |
| Automaton states | 8,335 | 8,931 | +7.2% |
| **Transform chains** | 11 | **11** | unchanged — the expensive thing was avoided |

The chain count is the one to watch. A chain nobody else shares is materialised
over every value of every request; core.go records the CRLF rule costing 8% of
the latency budget for exactly that. Both new rules reuse
`[]rules.Transform{transform.URLDecode}`, so they add none.

Fuel unchanged at 10,031,189, allocations still 0/op.

**The confidence tiers are empty, confirmed by lint: certain 53, high 29, and
nothing else at all.** `WithMinConfidence` exists with nothing to select. That is
the largest unused lever in the project.

### Performance of the added readings: measured, no regression

Three classes added and `MaxReadings` 8 → 10, so this needed checking. The
machine was at load 54/15 cores, where `bench-guard` correctly refuses, so the
deterministic metrics carried it:

- **Fuel identical**: max fan-out 10,031,189 of 32,000,000 (31.3%) before and
  after — byte-for-byte the same, measured in a `git worktree` at the
  pre-change commit.
- **0 allocs/op preserved** on BenignGET, BenignPOSTJSON, ManyArgs,
  PrefilterOnly, Concurrent, RulesetScaling.
- **Ruleset scaling still flat**: 331→360 ns from 10 to 10,000 rules.
- Paired wall-clock, back to back: BenignGET 1940→1981 ns, BenignPOSTJSON
  32.9→32.2 µs. Both inside the noise at that load.

Absolute SLO numbers are still owed on a quiet machine with `benchstat`
installed (`make bench-check`); the above is a paired comparison, not a
certification.

### The zero-FP gate is the load-bearing test

`./run.sh benign` is a corpus built to *look* hostile: security prose, code shown
as documentation, SQL keywords doing English work, paths that are URLs. It found
three real false positives on its first run — gwaf firing on its own garrison —
and all three are fixed:

- `the UNION SELECT pattern is a classic injection example` (rule 2010)
- `cd ../.. then run make from the project root` (rule 1004)
- the UTF-8 spelling of the `%a0` separator, via the mutation fuzzer

**A fourth was my test being wrong, not gwaf.** A literal `<script>` in a value is
blocked by design, and the project writes benign prose as "script tags"; treating
that as an FP would have been the actual mistake. Distinguish "gwaf is wrong" from
"the test case is unreasonable" before weakening a detector.

### The mutation fuzzer needs a validity oracle

`./run.sh mutate` mutates payloads gwaf blocks and re-fires. Its first run
reported four bypasses; **only one was real** (UTF-8 NBSP). The other three were
mutations that broke the payload: `/**/` and NBSP are whitespace to a SQL lexer
and neither is to an HTML parser, so `<img/**/src=x/**/onerror=…>` never creates
an `onerror` attribute and does not execute. Mutators are now grouped by the
grammar they are sound in. A fuzzer that reports a broken payload as a bypass is
the harness lying.

The single core miss is `hpp/split-xss` — `q=<img src=x` and `q=onerror=alert(1)>`
as two values of the same parameter. Neither half is XSS alone, and gwaf
evaluates one value per rule; catching it needs a reading over *concatenated*
duplicates, which is ASP's behaviour and not Go's. Deliberate, not a bug. The
SQLi equivalent is caught because each half is independently suspicious.

**`t:cssDecode` was the highest-value gap, and implementing it proved it.**
CRS 941100 *is* the `@detectXSS` rule and carries `t:cssDecode`, so it was
skipped and every CRS XSS category scored 0 while `@detectSQLi` (942100, no such
transform) scored 3/3. After the five transforms landed: CRS imports 220 → **263
rules**, and CRS XSS went **0/18 → 18/18**.

CRS's three false positives are CRS's own, faithfully translated — and the third
appeared *because* coverage improved, which is the honest trade: 930120 blocks a
legitimate `web.config` upload (the filename is in `lfi-os-files.data`), 942151
blocks "use substring(0,5) to trim the prefix", and 942160 now blocks "sleep(8h)
is the recommendation for adults". gwaf's own ruleset passes all five prose
sentences. More CRS rules raises detection and false positives together.

### What the harness found that the unit suite could not

Every one of these was invisible to a passing test suite:

- **`; /usr/bin/id` bypassed shell detection** while `; id` was blocked —
  `commandWord` stops at the leading slash and `scanPaths` only knew interpreters.
- **`/static/js/node.min.js` was blocked** — `SignalInterpreterPath` fired on any
  `/interpreter` without checking what followed it, and is worth 5 alone.
- **Triple encoding walked through.** One reading pass plus a rule's `urlDecode`
  covers two decoders; a CDN → proxy → app chain is three.
- **`%uXXXX` was not decoded at all** — IIS's own encoding, still honoured.
- **`1%a0OR%a01=1` was missed** — MySQL's lexer takes 0xA0 as whitespace.

Point real tools at the artefact that ships, not only at the data structure
behind it.

### CRS's own regression corpus: 5,066 stages, 0 false positives

`CRS_TESTS=/tmp/crs/tests/regression/tests go test -run TestCRSGapReport -v ./test/conformance/`

**gwaf blocks nothing CRS's own suite calls clean — 0 false positives across all
5,066 stages.** That is the number worth quoting. The detection rate on the same
corpus is 35.9%, and quoting it without the breakdown below is misleading in
both directions.

The first run of the gap report claimed **72** false positives. It was wrong:
69 were CRS *rule-scoped negatives* — `no_expect_ids: [942160]` says one rule
must not fire, and the input is frequently still an attack, so gwaf blocking it
with a different rule is correct. The runner's `ruleScopedPass` disqualified
those whenever `status: 200` was set, which CRS puts on nearly every test as
boilerplate. Fixed; the three that remained were also correct behaviour:

- **920181** — gwaf rejects `Content-Length` + `Transfer-Encoding` together
  (`reason=framing_ambiguous`). Request smuggling, RFC 7230 §3.3.3. Stricter
  than CRS, which expects 200 only because Apache strips the header.
- **920640 ×2** — the body is `{"id_order":"select(sleep(10));"}`, a real
  injection. CRS only asserts rule 920640 must not claim it.

### detect/javaser and detect/phpi — what a structural detector buys, honestly

Added for the two biggest CRS miss families. Result: **+41 stages (35.9% →
36.7%), 0 false positives**, pentest battery 344→**346/347 with 0/184 FP**.

That is deliberately smaller than the family sizes suggest, and the reason is the
point: **748 of JAVA's 1,172 stages are 944130 and 944300** — `java-classes.data`
enumerated, and the same names base64-encoded. Implementing those means importing
CRS's false-positive profile, which the 0-FP requirement forbids. The +41 is the
*structural* share, and it is the share worth having.

Design rule both packages follow: **a name never carries a verdict, only
structure does.** A serialization header, a nested interpolation (Log4Shell's
obfuscation, no benign reading), a class-loader property walk, a stream wrapper
where a path belongs, a call whose target is data. `$_GET[0]($_GET[1])` names no
function at all, which is the case no list can ever reach.

`FuzzLiteralsAreExhaustive` earned its place immediately: it caught `.exec(`
firing the spawn signal with no literal able to cover it. Every new detector
needs that fuzz target.

### Where the 3,247 misses actually are — measured, not assumed

Do **not** repeat the guess that "it is all keyword lists". Checked:
944 has 1 `@pm` rule of 22, and **942 has none of 68**. The volume is in the
*stage counts*:

| Family | Missed | Shape |
|---|---|---|
| JAVA 944 | 852 | **64% is two files**: 944130 (418 stages, `@pmFromFile java-classes.data`) and 944300 (330, the same names base64-encoded) |
| SQLI 942 | 682 | **flat spread** across ~68 regex rules — many genuinely distinct variants |
| RCE 932 | 601 | mixed; some real evasions, some command-name enumeration |

So JAVA is largely enumeration, and importing it means importing CRS's
false-positive profile — which is the one thing the 0-FP requirement forbids.
**SQLI is the seam worth mining**: real, distinct variants with no keyword list
behind them. `SignalQuotedConnector` came from exactly there.

### Rule-ID mode: the real test of the seclang bridge

`CRS_TESTS=… CRS_RULES=… go test -run TestCRSBridgeFidelity -v ./test/conformance/`

Separates the only two reasons a converted rule fails its own test:

- **never imported** — a coverage number the report already carries (83 distinct)
- **imported and silent** — the rule is present and *wrong*, which no coverage
  percentage shows (154 distinct)

Rule-ID pass rate went **28.5% → 44.4%** in one session. Almost none of that was
detection work; three harness/converter defects were hiding it:

1. **`LoadCRS` never set `Options.DataFiles`**, so every `@pmFromFile` rule was
   dropped — 17 rules, including 930120's LFI list. It also parsed each file with
   `Parse` instead of `ParseSources`, so `SecDefaultAction` and
   `SecRuleRemoveById` did not carry across files. (250 → 267 rules, +64 stages.)
2. **ModSecurity hands rules *decoded* ARGS; gwaf does not.** `t:none` means "no
   *further* transforms" — the decoding already happened when ARGS was populated.
   Imported rules were reading percent-encoded bytes their author never expected.
   `seclang` now prepends `URLDecode` for the collections ModSecurity decodes
   (ARGS, cookies, body, filenames — *not* headers or REQUEST_URI, which are raw
   there too). (+56 stages.)
3. **The runner only ran phase 2 when a body existed.** `GET /x?foo=payload` has
   no body, so no `phase:2` rule could ever fire — and that is where CRS puts
   most of its detection. **(+587 stages, the single largest jump.)**

CRS 932140 is the worked example: it matched its own payload perfectly in
isolation and was counted silent across 153 stages, for reasons 2 and 3 together.

**Lesson, again: measure the harness before believing the number.** Every one of
these made gwaf look worse than it is, which is the safe direction — but the
earlier `ruleScopedPass` bug made it look *better*, and that one is the dangerous
direction.

### The road to dropping CRS

`./run.sh learn` runs a core target and a converted-CRS target on the same
payloads and prints only the disagreements. Anything CRS blocks and gwaf misses
is a gap gwaf must grow natively; that list is the roadmap.

First real run found two — `INTO OUTFILE` and `PROCEDURE ANALYSE()` — both now
absorbed into `detect/sqli` natively. Current state: **0 gaps, 3 gwaf wins**
(CRS misses `;id`, `php://filter`, and `&& wget`).

Its first *apparent* run reported zero gaps and was lying: it used `probe_raw`,
which sends URLs verbatim, so every payload containing a space failed with curl
error 000 and both targets "agreed". The phase now guards on 000 and says so.
Same failure class as the staticcheck skip in CLAUDE.md §6 — a check that reports
success it did not earn.

**The pentest harness found what the unit suite structurally could not.** The
negation-inversion bug lived in generated source; every unit test asserted on the
`rules.Set`, where negation was always correct. Point real tools at the artefact
that actually ships, not only at the data structure behind it.

## Quality
Coverage 83.6%. staticcheck + govulncheck clean. Race clean. Zero deps.

## Fuzz corpus blindness sweep — 2026-08-13

Run after the fold panic, whose root cause was a *corpus* gap rather than a code
one: `FuzzBuild` had covered `foldStringConcatInto` since the day it was written
and not one of its seeds contained a quote, so it took a fuzz run in another
module to reach the crash. The question this answers is whether any other target
is blind to a class it nominally handles.

Method: run each target for a fixed 25s and count `new interesting`. A corpus
that already covers its input classes finds few; one blind to a class finds
hundreds. `FuzzBuild` found **433** in 40s once quote seeds were added, which is
the reference for what blindness looks like.

Fifteen targets across `internal/body`, `internal/prefilter`, `rules/transform`,
`rules/op`, `detect/*`, `seclang`, `schema/openapi`:

| target | new (25s) | verdict |
|---|---|---|
| `schema/openapi` FuzzParseDocument | 126 | large input space |
| `seclang` FuzzParse | 55 | large input space |
| `internal/body` FuzzSniffMultipart | 33 | fine |
| `detect/sqli` FuzzAnalyze | 12 | fine |
| everything else | 0–7 | fine |

**No crashes, and no target shows blindness.** The two high counts converge under
longer runs, which is the distinguishing test: `schema/openapi` found 126 in the
first 25s and only 27 more in the next 65s; `seclang` went 55 → 103 over 3.6x the
time. Front-loaded and flattening is a fuzzer exploring a wide grammar. Blindness
looks different — a sustained rate, because a whole class is being discovered
from scratch.

Two entries came back CRASH in the first sweep and both were false positives: the
script grepped for "FAIL" in output that legitimately contains it. If this is
re-run, match on `panic:` or on the `Failing input written` line instead.

Worth re-running when a detector gains a new input class, which is the event that
created the gap the first time. Not worth re-running on a schedule.

## CRS conformance — first real measurement, 2026-08-13

`test/conformance` has existed since M0 and `TestCRSSuite` **skipped** without
`CRS_TESTS`, so "CRS conformance" was a checkbox with no number behind it for
the life of the project. The test's own comment said as much: "this is the run
that produces a real number."

Against CRS's own regression corpus (323 files, 5,066 cases, 31 skipped):

| run | result |
|---|---|
| SecLang adapter, **exact CRS rule IDs** | **2079/5066 (41.0%)** |
| gwaf core ruleset, rule IDs ignored | 1934/5066 (38.2%) |

Per-category, core ruleset. Sorted by what it says rather than by score:

| category | rate | reading |
|---|---|---|
| 999-COMMON-EXCEPTIONS | 94.6% | |
| 949-BLOCKING-EVALUATION | 80.0% | |
| 922-MULTIPART | 61.5% | |
| 941-XSS | 49.8% | |
| 921-PROTOCOL-ATTACK | 49.6% | |
| 920-PROTOCOL-ENFORCEMENT | 48.7% | much of this is policy, not detection |
| 933-PHP | 48.7% | |
| 932-RCE | 39.0% | known weak area; matches the nuclei gap |
| 930-LFI | 38.6% | |
| 942-SQLI | 35.3% | |
| 934-GENERIC | 35.1% | |
| 944-JAVA | 29.0% | **largest category at 1,172 cases, and the weakest in scope** |
| 931-RFI | 26.2% | |
| 943-SESSION-FIXATION | 12.8% | cross-request state — out of scope by design |
| RESPONSE-95x DATA-LEAKAGES | 0–58% | gwaf never buffers responses; out of scope by design |

**Do not read this as a detection score.** On 2,457 real CVE exploits from
nuclei-templates gwaf detects 93.1% against CRS 4.25's 89.7%. Both numbers are
correct because they ask different questions: nuclei asks whether real attacks
are caught, this asks whether gwaf agrees with CRS's ~900 specific rules, many
of which exist at paranoia levels gwaf deliberately does not reproduce and
several of which cover categories the scope line assigns to the embedder.

**What is actionable is the shape, not the total.** 944-JAVA at 29% over 1,172
cases is the largest in-scope gap and the obvious place to look. Chasing the
total would mean tuning against CRS's test suite rather than against attacks,
which is optimising for the benchmark — and the suite is not neutral ground,
because it was written to exercise the rules of the product it ships with.

Re-run:

    CRS_TESTS=/path/coreruleset/tests/regression/tests \
    CRS_RULES=/path/coreruleset/rules \
    go test -count=1 -v -run TestCRSSuite ./test/conformance/

## SecLang adapter: what it drops loading CRS 4.25 — 2026-08-13

Run after CRS conformance measured 41.0% (2079/5066), to find out whether that
number is ten missing operators or a hundred. It is neither: it is three
categories, and only two of them are gaps.

`ParseSources` over CRS's 27 rule files, with `DataFiles` supplied as the
conformance loader does — **788 directives → 267 rules, 234 skipped**.

| construct | skips | distinct rule IDs |
|---|---|---|
| `SecRule` variables | 107 | 107 |
| `SecRuleUpdateTargetById` | 55 | — |
| chained `SecRule` | 55 | 55 |
| `SecAction` | 7 | 7 |
| `@validatebyterange` | 5 | 5 |
| `@within`, `@gt`, `@pmfromfile`, `SecComponentSignature` | 5 | 5 |

### Deliberate, and correctly skipped (~85)

- **`TX` (51)** — CRS's anomaly-score collection. gwaf rejects global anomaly
  scoring as an engine concept in favour of confidence tiers (CLAUDE.md §1
  non-goals). Not a gap; a different model.
- **counting a collection `&ARGS` (29)** — a count is not a value; `Limits`
  bounds this instead.
- **`SecAction` (7)** — unconditional actions set variables or jump, both
  cross-request.
- **`@validatebyterange` (5)** — encoding validation is the canonicalization
  tier and runs before rules.

### Gap 1: CRS's own FP tuning is dropped (75)

`SecRuleUpdateTargetById` (55) and variable exclusions `!ARGS:x` (20). The 55
are **all active directives in REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf** — the
two in the SQLI file are commented-out examples. They are exclusions CRS ships
to keep itself precise: `SecRuleUpdateTargetById 932240 "!REQUEST_COOKIES:/^_ga.../"`
is "do not match Google Analytics cookies".

**Dropping them imports CRS's detection without CRS's tuning**, so a
gwaf-seclang import is strictly more false-positive-prone than CRS itself. On
the one axis gwaf actually wins (0/12 against CRS's 4/12) that is the wrong
direction to be wrong in.

It is a **translation** gap and not a capability gap: gwaf has `rules.Exception`
and the skip message already says so — "variable exclusions (!ARGS:x) are gwaf
exceptions; express them as ...". Nothing new has to be built.

### Gap 2: chained SecRules (55)

55 chains are produced and 55 more are skipped, so support is partial. ~20% of
the translated ruleset. A chain is a conjunction across several variables and
the engine evaluates one value at a time, so this is a real capability gap
rather than a translation one.

### Order

Gap 1 first: smaller, uses machinery that already exists, and fixes a
false-positive liability rather than a detection one. Gap 2 is the larger and
more interesting piece of work.

Re-run:

    cd /tmp/slscan && go run . /path/coreruleset/rules
    (ParseSources with DefaultConfidence + DataFiles; rank rep.Skipped by What/Why)

## Rejected: chained SecRule support — 2026-08-13

Measured before building, and the measurement says do not build it.

Chains looked like the largest remaining SecLang gap: 55 of them, none
imported, roughly 20% of what CRS would contribute. Implementing them means
teaching the engine to evaluate a conjunction across different collections,
which it deliberately does not do — it evaluates one value at a time. That is a
change to the hot path's evaluation model, so it needs to buy something.

Decomposing CRS 4.25's 55 chains:

| | count |
|---|---|
| reference a variable gwaf refuses by design | **37** |
| translatable, head only annotates (`pass`) | 2 |
| translatable, head blocks | 16 |

The 37 are blocked by decisions already made and still made after chains exist:
`TX` (22) is CRS's anomaly-score collection, which gwaf rejects as an engine
concept in favour of confidence tiers; `MATCHED_VARS` (10) is the same model.
Implementing chains does not reach any of them.

Of the 16 that would block:

- **920181, CL and TE both present, is already caught** — engine-level desync
  detection returns `framing_ambiguous` without any rule. That is the most
  valuable one in the set, the classic CL.TE request-smuggling signature, and
  chains would add nothing.
- Most of the rest are protocol *hygiene* rather than injection: "Request
  Missing an Accept Header", "Range: Too many fields", "Request Has an Empty
  Accept Header". CRS runs these at low paranoia feeding an anomaly score, so
  they contribute points rather than block. Imported into a model that blocks on
  a confidence tier they are false positives waiting to happen — curl and most
  API clients omit Accept.
- The genuinely valuable, low-FP remainder is **three**: GET/HEAD with a body
  (920170), GET/HEAD with Transfer-Encoding (920171), and POST with neither
  Content-Length nor Transfer-Encoding (920180). Verified missing.

**So the honest cost/benefit is: a change to the engine's evaluation model, for
three rules.** Each of those three is a two-condition check on the method and
one header — expressible as a native gwaf rule or as an extension of desync
detection, with no conjunction mechanism at all.

If chain support is ever built, build it for a reason other than CRS coverage.
The 55 is not 55; after the variables gwaf refuses and the one the engine
already catches, it is three.
