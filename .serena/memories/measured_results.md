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

| | gwaf core | converted CRS 4.25.1 |
|---|---|---|
| Attacks blocked | **256/257 (99%)** | 185/257 (71%) |
| False positives | **0/104** | 3/104 |
| Rules imported | n/a | 263 of 786 directives |

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

**The pentest harness found what the unit suite structurally could not.** The
negation-inversion bug lived in generated source; every unit test asserted on the
`rules.Set`, where negation was always correct. Point real tools at the artefact
that actually ships, not only at the data structure behind it.

## Quality
Coverage 83.6%. staticcheck + govulncheck clean. Race clean. Zero deps.
