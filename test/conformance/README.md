# Conformance — go-ftw / OWASP CRS

Runs the Core Rule Set's own test format against gwaf.

```
make conformance                                    # bundled tests only

git clone --depth 1 https://github.com/coreruleset/coreruleset /tmp/crs
CRS_TESTS=/tmp/crs/tests/regression/tests make conformance     # the real corpus
CRS_TESTS=... CRS_RULES=/tmp/crs/rules make conformance        # exact rule IDs
```

## Why this exists

Every other detection number gwaf publishes is measured against a corpus gwaf
wrote. That is the right way to build a detector and the wrong way to prove one:
a suite written by the people who wrote the rules tests what they thought of.
The CRS corpus is ~5,000 stages written by other people over twenty years,
against rules gwaf never implemented — the least self-selecting evidence
available.

## The first result, stated plainly

Against CRS **4.x**, 323 test files, gwaf's own default ruleset:

```
conformance [detection (rule IDs ignored)]: 1598/5066 passed (31.5%), 31 skipped
  missed detections: 3416
  false positives:      52
```

**31.5% is the honest headline and it is not the whole story.** The split is what
matters: the failures are almost entirely *coverage*, not *precision* — 52 false
positives across ~5,000 stages, against 3,416 attacks CRS expects to be caught
that gwaf let through.

### Where the misses are

| CRS family | Missed / run | What it is |
|---|---|---|
| 944 Java | 1045 / 1172 | JNDI, deserialization, and a long tail of Java-specific patterns |
| 942 SQLi | 696 / 1033 | see below — the finding that matters |
| 932 RCE | 599 / 1006 | shell-specific payloads |
| 933 PHP | 254 / 437 | function-name enumeration |
| 934 Generic | 204 / 276 | SSRF, prototype pollution, template engines |
| 920 Protocol | 197 / 398 | protocol/method enforcement — schema tier, not injection |
| 941 XSS | 150 / 263 | |
| 943 Session fixation | 40 / 47 | needs cross-request state — **out of scope by design** |
| RESPONSE-95x | ~70 | response-phase — **the runner does not feed responses yet** |

Three honest qualifications, none of which rescue the number:

1. **Some families are not gwaf's job.** Session fixation needs memory; method
   and protocol enforcement are the schema tier, which is off in this run.
2. **The RESPONSE-95x misses are the runner's fault, not gwaf's** — it drives
   request phases only. gwaf has response-phase rules that never got a chance.
3. **Some CRS "attacks" are application-bug triggers.** `2.2250738585072011e-308`
   is the PHP float-parsing DoS; `4294967296` is an integer-overflow probe.
   These are rules for specific bugs in specific stacks, not injection, and gwaf
   does not have them by choice.

### The finding worth acting on

Sampling the missed 942 cases shows a clear class gwaf does not detect:
**DBMS-specific function-call injection**, with no `UNION`, no `OR 1=1`, and no
obvious keyword.

```
lo_import('/etc' || '/pass' || 'wd')            PostgreSQL file read
sqlite_compileoption_used(id)                    SQLite fingerprinting
starts_with(password,'a')::int                   PostgreSQL boolean extraction
jsonb_pretty(json_build_object(1,password))      PostgreSQL JSON exfiltration
FIND_IN_SET('22', Category)                      MySQL
```

gwaf reads SQL *grammar*, which is why it beats signature lists on encoding
evasion — and this is the flip side: a bare call to a dangerous built-in is
grammatically ordinary. CRS covers it by naming hundreds of functions, which is
exactly the enumeration gwaf avoids elsewhere, so the fix is a design question
rather than a list to paste in. **This is the highest-value open detection work.**

## The two modes

Running the same YAML two ways answers two questions that get conflated:

- **`ModeDetection`** — "does gwaf block what CRS says should be blocked?" Rule
  IDs are ignored, because gwaf's IDs are not CRS's and never will be.
- **`ModeRuleID`** (`CRS_RULES=…`) — "does gwaf *running CRS rules* fire the same
  IDs?" This tests the seclang bridge, not the detectors, and is stricter. The
  run prints how much of CRS the bridge translated beside the pass rate, because
  "98% pass" means something different when half the rules did not load.

## Runner notes

- **In-process, not over a socket.** go-ftw normally drives a live server; this
  builds the request and feeds it to gwaf directly. A test that goes over a
  socket measures the socket too — a 400 from `net/http` for a malformed
  encoding reads as "gwaf missed it" when gwaf never saw it, which this project
  has already hit once for real.
- **Skips are excluded from the denominator, never counted as passes.** A suite
  that skips what it cannot run and reports 100% is lying;
  `TestSkippedStagesAreNotCountedAsPasses` enforces it.
- **The benign controls are proven to assert something.**
  `TestFalsePositiveControlsFail` runs a block-everything configuration and
  requires the suite to fail, so the false-positive half cannot be decoration.
- Its own module, because YAML is a dependency core will not carry.
