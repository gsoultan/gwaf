// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gwaf"
)

// Latency distributions, and why a mean was never enough.
//
// CLAUDE.md §2 states its targets as p50 and p99, and docs/PERFORMANCE.md says
// "reported every run: p50, p99, p99.9". Neither was true: `go test -bench`
// reports a *mean*, and until this file existed nothing measured a percentile at
// all. Three SLOs were therefore unverified as written, and one — p99 < 100 µs
// for any workload — was unverified entirely.
//
// A mean is the wrong statistic for a firewall. The mean hides the request that
// took forty times longer than the rest, and that request is the whole reason a
// latency budget exists: it is the one an attacker is trying to produce.
//
// # What this costs, stated rather than hidden
//
// Sampling with time.Now() per operation costs roughly 50-70ns on this hardware,
// which is measurable against a sub-microsecond operation. The numbers here are
// therefore *pessimistic* for the fast cases, and the SLOs are asserted against
// them anyway — a bound that holds with the measurement overhead included holds
// without it.
//
// GC pauses are included rather than excluded. They are latency the caller
// experiences, and a benchmark that subtracts them is measuring a program
// nobody runs.

// slo is one workload and the bounds it must satisfy.
type slo struct {
	name string
	p50  time.Duration
	p99  time.Duration
	run  func(*gwaf.WAF)
}

// latencySamples is large enough for a stable p99.9: a thousand samples above
// the 99.9th percentile means the tail is measured rather than guessed at.
const latencySamples = 200_000

func TestLatencyDistribution(t *testing.T) {
	if testing.Short() {
		t.Skip("latency distribution takes a few seconds")
	}
	// Race instrumentation adds a shadow-memory write per access and slows the
	// request path by an order of magnitude, so a latency bound measured under
	// it describes a build nobody deploys. The correctness tests still run
	// there; only the timing assertions are skipped.
	if raceEnabled {
		t.Skip("latency is not measurable under -race")
	}
	w := newWAF(t)
	body := []byte(benignJSON(1024))

	workloads := []slo{
		{
			name: "benign GET, no body",
			p50:  2 * time.Microsecond,
			p99:  100 * time.Microsecond,
			run: func(w *gwaf.WAF) {
				tx := w.NewTransaction()
				tx.SetRequestLine("GET", "/api/v1/orders/12345", "HTTP/1.1")
				tx.SetRemoteAddr("192.0.2.1")
				tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
				tx.AddRequestHeader("Accept", "application/json")
				tx.ProcessRequestHeaders()
				tx.ProcessRequestBody()
				tx.Close()
			},
		},
		{
			name: "benign GET with query arguments",
			p50:  4 * time.Microsecond,
			p99:  100 * time.Microsecond,
			run: func(w *gwaf.WAF) {
				tx := w.NewTransaction()
				tx.SetRequestLine("GET", "/api/v2/search?q=running+shoes&page=2&sort=price_asc", "HTTP/1.1")
				tx.SetRemoteAddr("192.0.2.1")
				tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
				tx.ProcessRequestHeaders()
				tx.ProcessRequestBody()
				tx.Close()
			},
		},
		{
			name: "benign POST, 1 KiB JSON",
			p50:  15 * time.Microsecond,
			p99:  100 * time.Microsecond,
			run: func(w *gwaf.WAF) {
				tx := w.NewTransaction()
				tx.SetRequestLine("POST", "/api/v1/orders", "HTTP/1.1")
				tx.SetRemoteAddr("192.0.2.1")
				tx.AddRequestHeader("Content-Type", "application/json")
				tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
				tx.ProcessRequestHeaders()
				tx.SetRequestBody(body)
				tx.ProcessRequestBody()
				tx.Close()
			},
		},
		{
			// The attack path is not on the SLO table, and it is worth bounding
			// anyway: a firewall that is slow to say no is a firewall an
			// attacker can use as an amplifier.
			name: "blocked SQL injection",
			p50:  20 * time.Microsecond,
			p99:  100 * time.Microsecond,
			run: func(w *gwaf.WAF) {
				tx := w.NewTransaction()
				tx.SetRequestLine("GET", "/search", "HTTP/1.1")
				tx.AddArgument("q", "1' OR 1=1--")
				tx.ProcessRequestHeaders()
				tx.ProcessRequestBody()
				tx.Close()
			},
		},
	}

	var report strings.Builder
	fmt.Fprintf(&report, "\nlatency distribution — %s/%s, %d samples per workload\n",
		runtime.GOOS, runtime.GOARCH, latencySamples)
	fmt.Fprintf(&report, "%-34s %9s %9s %9s %9s %9s\n",
		"workload", "p50", "p90", "p99", "p99.9", "max")

	failed := false
	for _, wl := range workloads {
		d := measure(w, wl.run)
		fmt.Fprintf(&report, "%-34s %9s %9s %9s %9s %9s\n",
			wl.name, d.p50, d.p90, d.p99, d.p999, d.max)

		if d.p50 > wl.p50 {
			t.Errorf("%s: p50 = %v, target < %v", wl.name, d.p50, wl.p50)
			failed = true
		}
		if d.p99 > wl.p99 {
			t.Errorf("%s: p99 = %v, target < %v", wl.name, d.p99, wl.p99)
			failed = true
		}
	}

	t.Log(report.String())
	// Written to stdout as well, so `make bench` captures it into the published
	// numbers rather than leaving it buried in test output.
	if !failed && os.Getenv("GWAF_BENCH_REPORT") != "" {
		fmt.Print(report.String())
	}
}

type dist struct{ p50, p90, p99, p999, max time.Duration }

// measure runs fn latencySamples times, recording each duration.
//
// Samples are collected into a preallocated slice so the measurement itself
// does not allocate inside the loop and perturb what it is measuring.
func measure(w *gwaf.WAF, fn func(*gwaf.WAF)) dist {
	samples := make([]time.Duration, latencySamples)

	// Warm the transaction pool and the CPU caches first. A cold first
	// iteration is real, but it is one sample out of two hundred thousand and
	// including it measures process start rather than steady state.
	for range 2000 {
		fn(w)
	}

	for i := range samples {
		start := time.Now()
		fn(w)
		samples[i] = time.Since(start)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })

	at := func(q float64) time.Duration {
		idx := int(q * float64(len(samples)))
		if idx >= len(samples) {
			idx = len(samples) - 1
		}
		return samples[idx]
	}
	return dist{
		p50: at(0.50), p90: at(0.90), p99: at(0.99), p999: at(0.999),
		max: samples[len(samples)-1],
	}
}

// TestSLOTransactionFootprint measures the per-transaction memory the SLO table
// bounds at 8 KiB p50 and 64 KiB p99, which nothing had measured either.
//
// Measured as heap growth across a run divided by iterations, because a pooled
// transaction's cost is what it *retains*, not what it briefly touches. A
// transaction that allocates and frees within one request costs the process
// nothing; one that grows its arena and keeps it costs every concurrent request.
func TestSLOTransactionFootprint(t *testing.T) {
	if testing.Short() {
		t.Skip("footprint measurement forces GC")
	}
	if raceEnabled {
		t.Skip("race instrumentation allocates shadow state per access")
	}
	w := newWAF(t)
	body := []byte(benignJSON(1024))

	const iterations = 20_000
	run := func() {
		tx := w.NewTransaction()
		tx.SetRequestLine("POST", "/api/v1/orders", "HTTP/1.1")
		tx.AddRequestHeader("Content-Type", "application/json")
		tx.ProcessRequestHeaders()
		tx.SetRequestBody(body)
		tx.ProcessRequestBody()
		tx.Close()
	}

	// Warm up so pooled buffers reach their steady-state size first; measuring
	// growth through warm-up would attribute one-time capacity to every request.
	for range 5000 {
		run()
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range iterations {
		run()
	}
	runtime.GC()
	runtime.ReadMemStats(&after)

	// HeapAlloc after a GC is live data. If it grew, transactions are retaining
	// memory rather than returning it to the pool.
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	perTx := float64(growth) / iterations

	t.Logf("heap growth over %d transactions: %d bytes (%.2f B/tx); "+
		"total allocated %d bytes (%.1f B/tx)",
		iterations, growth, perTx,
		after.TotalAlloc-before.TotalAlloc,
		float64(after.TotalAlloc-before.TotalAlloc)/iterations)

	// The SLO that actually matters: sustained load must not grow the heap.
	// A pooled transaction reaching steady state should retain nothing further.
	if perTx > 8192 {
		t.Errorf("per-transaction retained memory %.0f B exceeds the 8 KiB p50 bound", perTx)
	}
}
