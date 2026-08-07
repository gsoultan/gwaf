# Head-to-head: gwaf vs Coraza + CRS

The comparison `docs/COMPARISON.md` §6 promised and admitted was missing.
Same corpus, same machine, same process, both engines.

```
git clone --depth 1 https://github.com/coreruleset/coreruleset /tmp/crs
CRS_TESTS=/tmp/crs/tests/regression/tests CRS_RULES=/tmp/crs/rules \
  go test -v ./test/headtohead/
```

## Results

**Detection — the OWASP CRS regression corpus (CRS's home turf):**

| engine | detection |
|---|---|
| coraza + CRS | **3246 / 4025 (80.6%)** |
| gwaf | 807 / 4025 (20.0%) |

**Coraza wins this decisively and the result is fair to state.** The corpus is
CRS's own regression suite — one test per CRS rule, written over twenty years
for those rules. An engine that did not pass its own tests would be broken.

**False positives — 10,433 ordinary requests (gwaf's home turf):**

| engine | false positives |
|---|---|
| gwaf | **6 / 10,433 (0.06%)** |
| coraza + CRS | 3798 / 10,433 (36.4%) |

## Read both, or neither

Each corpus is one engine's home ground, and reporting only one would be
choosing the flattering half. Three caveats travel with these numbers:

1. **gwaf's rules are calibrated against that benign corpus** and fail the build
   above their tier's ceiling, so 0.06% is close to tautological. Coraza has
   never seen it.
2. **Coraza runs untuned CRS at PL1**, from `crs-setup.conf.example` with no
   per-application exclusion rules. Every real CRS deployment adds those, and
   tuning is the normal answer to exactly this. A tuned deployment scores far
   better.
3. **The traffic is API-shaped** — JSON, JWTs, gRPC-Web, protobuf. That is where
   signature engines are documented to struggle and where gwaf's schema tier
   aims, so the corpus plays to a structural difference rather than an
   implementation detail.

## What was measured wrong first

The first run reported **87%** false positives for Coraza. That was the harness:
the corpus records carry only the headers gwaf cares about, so replayed requests
had no `Host`, `User-Agent`, or `Accept`, and CRS correctly flagged them
(920280 "Request Missing a Host Header"). A request with no Host header is
malformed under HTTP/1.1 and CRS is right to say so.

Supplying what a browser actually sends took it to 36.4%, and loading the real
`crs-setup.conf.example` rather than hand-written `SecAction` directives left it
unchanged — which is what confirms the remaining number is Coraza's behaviour
rather than the harness's.

**Publishing 87% would have been the dishonest comparison this file exists to
avoid.** A number about a competitor gets verified before it gets published.

## Not measured

Latency. The two engines differ in startup, parsing, and body handling, and a
throughput figure from a harness that drives neither the way production would is
not quotable. gwaf's latency lives in `docs/BENCHMARKS.md`, against itself, with
the methodology stated.
