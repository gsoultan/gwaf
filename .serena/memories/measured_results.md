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

## Quality
Coverage 83.6%. staticcheck + govulncheck clean. Race clean. Zero deps.
