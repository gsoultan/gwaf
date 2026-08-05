# Benchmarks

Reproducible numbers, the method that produced them, and what they do not show.

Coraza's benchmark page has been "under renovation" since April 2026, and a
vacuum like that is only worth filling with numbers somebody else can re-run and
disagree with. Everything here regenerates from a clean checkout in one command.

```
make bench-publish
```

---

## 1. What is measured

| Workload | What it represents |
|---|---|
| Benign GET, no body | the 95% case: a request with nothing to inspect |
| Benign GET with query arguments | the same, with values a rule actually reads |
| Benign POST, 1 KiB JSON | realistic API traffic, fully parsed into fields |
| Blocked SQL injection | the attack path — a firewall slow to say no is an amplifier |
| Ruleset scaling, 10 → 10,000 rules | whether cost tracks ruleset size |
| Concurrent | one `WAF` across every core |
| Large body, 1 MiB | throughput rather than latency |

Latency is reported as **p50, p90, p99, p99.9, and max** over 200,000 samples per
workload. Not a mean: the mean hides the request that took forty times longer
than the rest, and that request is the entire reason a latency budget exists —
it is the one an attacker is trying to produce.

That distinction was not academic here. The SLO table in `CLAUDE.md` has always
been written in percentiles and `docs/PERFORMANCE.md` claimed they were "reported
every run", while nothing measured one: `go test -bench` reports means. Three
targets were unverified as written and p99 was unverified entirely until
`latency_test.go` was added.

---

## 2. Results

Apple M5 Pro, `darwin/arm64`, 15 usable cores, Go 1.26.5, core ruleset
(36 rules), no schema configured. Run-to-run variation on p50 is under 1%; the
maxima move a lot between runs, for the reason given below.

### Latency

| Workload | p50 | p90 | p99 | p99.9 | max |
|---|---|---|---|---|---|
| Benign GET, no body | 875 ns | 875 ns | 1.00 µs | 1.25 µs | 56.6 µs |
| Benign GET with query args | 2.96 µs | 3.04 µs | 3.38 µs | 11.1 µs | 82.0 µs |
| Benign POST, 1 KiB JSON | 13.2 µs | 13.5 µs | 15.8 µs | 33.0 µs | 139 µs |
| Blocked SQL injection | 709 ns | 750 ns | 875 ns | 2.04 µs | 80.5 µs |

**The maxima are garbage collection, not gwaf.** They are one sample in 200,000,
they move between 19 µs and 208 µs across runs while p50 moves by under 1%, and
gwaf allocates nothing on these paths — a run that hits a GC cycle started by
something else in the process pays for it. They are listed rather than trimmed
because a benchmark that subtracts GC is measuring a program nobody runs. The
SLO is stated at p99, and p99 has 6× headroom on the worst workload.

Blocking is *faster* than allowing, which is not a trick: a blocked request stops
at the first terminal rule and never reaches the body phase.

### Throughput and scaling

| Metric | Result |
|---|---|
| Ruleset scaling, 10 → 10,000 rules | 245 → 239 ns/op — **flat** |
| Concurrent, one WAF across all cores | 42.3 ns/op |
| Large body, 1 MiB JSON | 131 MB/s |
| Rules evaluated per benign request | **0** |

Flat scaling is the load-bearing number. A ruleset a thousand times larger costs
the same, because the Aho-Corasick prefilter decides what to evaluate before any
rule runs, and target and phase pruning discard whole groups before the transform
does.

### Memory

| Metric | Result |
|---|---|
| Allocations, benign GET | **0** |
| Allocations, benign POST 1 KiB JSON | **0** |
| Total allocated per transaction | 2.3 B |
| Heap growth over 20,000 transactions | **−37 KB** (shrank) |

Zero allocations on the request path is a property, not an optimisation: values
live in a per-transaction bump arena that is reset and reused, and the prefilter
works over `[]byte` views into the original buffer.

---

## 3. How to reproduce

```
git clone https://github.com/gsoultan/gwaf && cd gwaf
make bench-publish
```

That runs the latency distribution, the allocation SLOs, the scaling sweep, and
the throughput benchmarks, and prints the hardware and toolchain it used.

For a like-for-like comparison against another WAF, the honest requirements are:

- **the same ruleset**, or an explicit statement of what each one loaded;
- **the same request corpus** — `testdata/corpus/benign.jsonl` is 10,386 requests
  across eleven application archetypes and is in this repository;
- **percentiles, not means**;
- **the false-positive rate alongside**, because a firewall that inspects less is
  trivially faster.

That last point is why this document links to detection numbers rather than
standing alone. Latency without a detection rate is a claim about how fast
something can do nothing.

---

## 4. Detection, measured on the same build

| Metric | Result |
|---|---|
| Evasion corpus | 132/132 |
| False positives, benign corpus | 0/124 |
| Calibration corpus | 10,386 distinct requests |
| Smallest observable false-positive rate | 0.0096% (1 in 10,386) |
| Rules within their declared confidence tier | all 36 |

`make corpus` and `make calibrate` regenerate both.

---

## 5. What these numbers do not show

Stated plainly, because a benchmark page that only flatters is not evidence.

- **One machine, one architecture.** Everything here is `darwin/arm64` on a
  laptop. No `linux/amd64` figures, no cloud instance, no cross-architecture
  comparison. Absolute values will differ; the shapes should not.
- **The corpus is synthetic.** 10,386 requests modelled on real API surfaces,
  with plausible rather than captured values. It can falsify a performance or
  false-positive claim; it cannot confirm one against production traffic.
- **No comparison against another WAF.** Running Coraza or ModSecurity against
  the same corpus is the obvious next step and is not done here. Publishing a
  comparison would mean tuning somebody else's product to its best configuration,
  and a comparison where only one side was tuned is worse than none.
- **Sampling overhead is included.** `time.Now()` per operation costs roughly
  50–70 ns here, which is measurable against a sub-microsecond result. The
  latency figures are therefore pessimistic for the fast workloads, and the SLOs
  are asserted against them anyway.
- **No sustained-load or multi-hour run.** Heap growth is measured over 20,000
  transactions, not over a day.

---

## 6. SLO status

Every target in `CLAUDE.md` §2 is met on this hardware.

| SLO | Target | Measured |
|---|---|---|
| Benign GET, no body | p50 < 2 µs, 0 allocs | 875 ns, 0 allocs |
| Benign POST, 1 KiB JSON | p50 < 15 µs, < 4 KB | 13.2 µs, 0 B |
| p99, any workload | < 100 µs | 15.8 µs worst |
| Rules evaluated / benign request | 0 | 0 |
| Per in-flight transaction | < 8 KB p50 | 2.3 B |
| Heap growth under sustained load | 0 | −37 KB |
| Ruleset scaling, 10 → 10k | sub-linear | flat |
| CGO dependencies | 0 | 0 |

The POST JSON figure had never met its target before: `bench/baseline.txt`
recorded 30.3 µs at one point without flagging it, and the measurement before
plan pruning was 16.4 µs. It was closed by evaluating fewer rules rather than
making each one cheaper — transform-prefix reuse, phase pruning, and target
pruning.
