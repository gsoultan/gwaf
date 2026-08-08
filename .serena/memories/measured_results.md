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

Both now read through one percent layer (`percentByteAt` / `percentRuneAt`), and
`hasRawMarkup` does too so the CMS suppression still works. **When adding a
reading, test it over HTTP, not only through the library API** — the two deliver
different bytes, and the library path is the one that lies.

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
