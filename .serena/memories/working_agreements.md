# Working Agreements

## Instruments before implementation
Corpus, benchmarks, and calibration harness ship **before** what they measure.
A detector that blocks everything passes any recall-only test. Without the FP
gate on day one you optimize the wrong thing for months.

This is not theory: the differential harness was built before transducers and
killed them on first use, in one session.

## Test the premise, not only the implementation
The transducer's kill criterion anticipated a correctness failure; the real
failure was that its premise was already satisfied. Before building an
optimization, verify the cost it targets still exists.

## Detection rate is never reported alone
Always beside the false-positive rate. `make corpus` prints both.

## Every parser gets a fuzz target
Parsers and canonicalization take attacker input directly. Non-negotiable.
Current: `FuzzScan`, `FuzzTransforms`, `FuzzIndexFold`, `FuzzBuild`,
`FuzzValidateInert`. `make fuzz` runs all.

## Claims are enforced, not asserted
`Field.Inert()` ("this validated value cannot carry a payload") is backed by a
fuzz harness that fails the build if any inert field validates a value
containing an attack-vocabulary byte. It found a real one immediately: RFC 3339
permits a space separator. **The grammar was tightened, not the invariant
weakened.** Prefer that direction always.

## Bugs the instruments caught (the pattern to expect)
- Prefilter scanned raw bytes while operators declared post-transform literals
  → whitespace-stripping rules silently never matched. Fixed by chain grouping.
- `bitset.Grow` reset touched-word bounds → values set but invisible to
  iteration.
- `NormalizePath` transiently exceeded its own `MaxOutputLen` → allocated every
  request. Test now asserts `cap(out) <= bound`, not just length.
- Only 2 of 10 injection rules had body-phase counterparts → payload blocked in
  a query string sailed through in a JSON body. Body rules are now **generated**,
  removing the class of mistake.

## Corrections go to the code, not the test
Several times a failing test was **my expectation** being wrong (`%c0%ae` is
`.` not `<`; NUL truncation is caught by the verbatim reading; `a+b` is not
UTF-7). Verify which side is wrong before "fixing".

## Commit style
Explain the *why* and include measurements. Negative results are committed with
the same care as features — `perf: build, validate, and reject the transducer
optimization` is a real commit.
