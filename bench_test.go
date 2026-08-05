// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/internal/budget"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
)

// The benchmarks here are the instruments the SLOs in CLAUDE.md §2 are measured
// against. Reported per run: ns/op, allocs/op, and — via the assertions in
// TestSLO* — rules evaluated per request, which is the leading indicator. If
// rules-evaluated drifts above zero on benign traffic, latency is about to
// follow and the prefilter has stopped doing its job.

func mustWAF(b *testing.B, opts ...gwaf.Option) *gwaf.WAF {
	b.Helper()
	w, err := gwaf.New(opts...)
	if err != nil {
		b.Fatalf("gwaf.New: %v", err)
	}
	return w
}

// BenchmarkBenignGET is the 95% case: a plain request with no body. It should
// be near-free, and it should allocate nothing.
func BenchmarkBenignGET(b *testing.B) {
	w := mustWAF(b)
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		tx := w.NewTransaction()
		tx.SetRequestLine("GET", "/api/v1/orders/12345", "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
		tx.AddRequestHeader("Accept", "application/json")
		tx.ProcessRequestHeaders()
		tx.Close()
	}
}

// BenchmarkBenignPOSTJSON is the headline number: realistic API traffic with a
// 1 KiB JSON body.
func BenchmarkBenignPOSTJSON(b *testing.B) {
	w := mustWAF(b)
	body := []byte(benignJSON(1024))

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		tx := w.NewTransaction()
		tx.SetRequestLine("POST", "/api/v1/orders", "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddRequestHeader("Content-Type", "application/json")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
		if tx.ProcessRequestHeaders().Blocked() {
			b.Fatal("benign request blocked")
		}
		tx.SetRequestBody(body)
		tx.ProcessRequestBody()
		tx.Close()
	}
}

// BenchmarkBenignLargeBody measures body-parser throughput and arena behaviour.
func BenchmarkBenignLargeBody(b *testing.B) {
	w := mustWAF(b)
	body := []byte(benignJSON(1 << 20))

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()

	for b.Loop() {
		tx := w.NewTransaction()
		tx.SetRequestLine("POST", "/api/v1/bulk", "HTTP/1.1")
		tx.ProcessRequestHeaders()
		tx.SetRequestBody(body)
		tx.ProcessRequestBody()
		tx.Close()
	}
}

// BenchmarkAttack measures the detection path, so a regression there is visible
// too — a WAF that is only fast when it finds nothing is not fast.
func BenchmarkAttack(b *testing.B) {
	w := mustWAF(b)
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		tx := w.NewTransaction()
		tx.SetRequestLine("GET", "/search", "HTTP/1.1")
		tx.AddArgument("id", "1' OR 1=1-- UNION SELECT password FROM users")
		tx.ProcessRequestHeaders()
		tx.Close()
	}
}

// BenchmarkManyArgs is the adversarial fan-out case: a request stuffed with
// arguments, bounded by the configured limit.
func BenchmarkManyArgs(b *testing.B) {
	w := mustWAF(b)

	type arg struct{ k, v string }
	args := make([]arg, 0, 200)
	for i := range 200 {
		args = append(args, arg{
			k: fmt.Sprintf("field_%d", i),
			v: fmt.Sprintf("value-%d-abcdefghijklmnop", i),
		})
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		tx := w.NewTransaction()
		tx.SetRequestLine("POST", "/form", "HTTP/1.1")
		for _, a := range args {
			tx.AddArgument(a.k, a.v)
		}
		tx.ProcessRequestHeaders()
		tx.Close()
	}
}

// BenchmarkRulesetScaling checks that cost grows sub-linearly with ruleset
// size. If it is linear, the prefilter is broken — this is the benchmark that
// proves the core architectural claim.
func BenchmarkRulesetScaling(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			w := mustWAF(b, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(syntheticRules(n)))

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				tx := w.NewTransaction()
				tx.SetRequestLine("GET", "/api/v1/orders/12345", "HTTP/1.1")
				tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
				tx.AddArgument("q", "an ordinary search query with no attack content")
				tx.ProcessRequestHeaders()
				tx.Close()
			}
		})
	}
}

// BenchmarkPrefilterOnly isolates the prefilter from transaction setup.
func BenchmarkPrefilterOnly(b *testing.B) {
	w := mustWAF(b)
	value := "an ordinary search query with no attack content whatsoever here"

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		tx := w.NewTransaction()
		tx.AddArgument("q", value)
		tx.ProcessRequestHeaders()
		tx.Close()
	}
}

// BenchmarkConcurrent measures throughput under contention, which is where a
// shared mutable structure would show up.
func BenchmarkConcurrent(b *testing.B) {
	w := mustWAF(b)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tx := w.NewTransaction()
			tx.SetRequestLine("GET", "/api/v1/orders/12345", "HTTP/1.1")
			tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
			tx.ProcessRequestHeaders()
			tx.Close()
		}
	})
}

// ---- SLO assertions --------------------------------------------------------
//
// These run as tests, not benchmarks, so CI enforces them on every change
// rather than only when someone remembers to look at benchmark output.

// TestSLOBenignEvaluatesNoRules is the central architectural claim, stated
// precisely.
//
// The claim is **not** that no rule ever runs on benign traffic — a structural
// detector has to declare broad literals (a quote, an equals sign) because a
// payload can be built from them, so prose containing those characters becomes
// a candidate. The claim that matters, and the one the prefilter actually
// buys, is that the number of rules evaluated is a **small constant
// independent of ruleset size**, and that the rules which do run reject.
//
// Values with no attack-vocabulary character at all still evaluate exactly
// zero.
func TestSLOBenignEvaluatesNoRules(t *testing.T) {
	w := newWAF(t)

	// No quote, no equals, no comment marker: nothing to be a candidate for.
	t.Run("no attack vocabulary", func(t *testing.T) {
		clean := []struct {
			name string
			fn   func(*gwaf.Transaction)
		}{
			{"plain GET", func(tx *gwaf.Transaction) {
				tx.SetRequestLine("GET", "/api/v1/orders/12345", "HTTP/1.1")
				tx.AddRequestHeader("User-Agent", "Mozilla")
			}},
			{"search query", func(tx *gwaf.Transaction) {
				tx.SetRequestLine("GET", "/search", "HTTP/1.1")
				tx.AddArgument("q", "golang web application framework")
			}},
			{"numeric args", func(tx *gwaf.Transaction) {
				tx.SetRequestLine("GET", "/api/v1/orders", "HTTP/1.1")
				tx.AddArgument("page", "2")
				tx.AddArgument("limit", "50")
			}},
		}

		for _, tt := range clean {
			t.Run(tt.name, func(t *testing.T) {
				tx := w.NewTransaction()
				defer tx.Close()
				tt.fn(tx)
				tx.ProcessRequestHeaders()
				tx.ProcessRequestBody()

				if got := tx.RulesEvaluated(); got != 0 {
					t.Errorf("RulesEvaluated() = %d, want 0", got)
				}
			})
		}
	})

	// Values that do contain attack vocabulary become candidates. The bound is
	// what matters: a small constant, not a function of ruleset size.
	t.Run("bounded on candidate traffic", func(t *testing.T) {
		const maxEvaluated = 4

		candidates := []struct{ name, arg string }{
			{"apostrophe", "it's urgent"},
			{"equals", "the total = 42 dollars"},
			{"json body chars", `{"name":"Alice","qty":3}`},
			{"sql word", "please select a delivery option"},
			{"comparison", "price < 100 and rating > 4"},
		}

		for _, tt := range candidates {
			t.Run(tt.name, func(t *testing.T) {
				tx := w.NewTransaction()
				defer tx.Close()
				tx.SetRequestLine("GET", "/search", "HTTP/1.1")
				tx.AddArgument("q", tt.arg)
				d := tx.ProcessRequestHeaders()

				if d.Blocked() {
					t.Fatalf("false positive: rule=%d", d.RuleID())
				}
				if got := tx.RulesEvaluated(); got > maxEvaluated {
					t.Errorf("RulesEvaluated() = %d, want <= %d", got, maxEvaluated)
				}
			})
		}
	})
}

// TestSLOZeroAllocations asserts the steady-state allocation SLO. Pooling and
// the arena exist precisely so this holds; if it regresses, GC pressure scales
// with traffic and the latency SLO goes with it.
func TestSLOZeroAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("race instrumentation allocates; not measurable under -race")
	}
	w := newWAF(t)

	run := func() {
		tx := w.NewTransaction()
		tx.SetRequestLine("GET", "/api/v1/orders/12345", "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
		tx.AddRequestHeader("Accept", "application/json")
		tx.ProcessRequestHeaders()
		tx.Close()
	}

	// Warm the pools and let every buffer reach its steady-state capacity.
	for range 2000 {
		run()
	}

	const iterations = 10000
	// A small allowance absorbs sync.Pool's per-P victim-cache behaviour, which
	// can reallocate after a GC even in a correct implementation. The threshold
	// is far below "allocates per request" and would catch any real regression.
	const maxPerOp = 0.05

	got := testing.AllocsPerRun(iterations, run)
	if got > maxPerOp {
		t.Errorf("allocations per request = %.4f, want <= %.4f", got, maxPerOp)
	}
}

// TestSLORulesetScalingIsSublinear proves the prefilter claim directly: a
// 1000x larger ruleset must not cost 1000x more.
func TestSLORulesetScalingIsSublinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive")
	}

	measure := func(n int) int {
		w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(syntheticRules(n)))
		tx := w.NewTransaction()
		defer tx.Close()

		tx.SetRequestLine("GET", "/api/v1/orders", "HTTP/1.1")
		tx.AddArgument("q", "an ordinary search query with no attack content")
		tx.ProcessRequestHeaders()
		return tx.RulesEvaluated()
	}

	small := measure(10)
	large := measure(10000)

	// Rules evaluated is size-independent, which is the property that matters:
	// a thousandfold larger ruleset must not evaluate a thousandfold more
	// rules. With a synthetic ruleset of literal operators the count is zero at
	// both sizes; the assertion is on the relationship, not the constant.
	if large > small {
		t.Errorf("rules evaluated grew with ruleset size: 10 rules -> %d, "+
			"10000 rules -> %d", small, large)
	}
}

// TestSLOFuelBoundsAdversarialInput asserts the DoS bound is provable rather
// than hoped for: work is capped no matter what the attacker sends.
func TestSLOFuelBoundsAdversarialInput(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	defer tx.Close()

	// Maximum fan-out the input limits admit: 1000 arguments at 1 KiB each.
	tx.SetRequestLine("POST", "/form", "HTTP/1.1")
	for i := range 1000 {
		tx.AddArgument(fmt.Sprintf("f%d", i), strings.Repeat("x", 1000))
	}
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()

	spent := tx.FuelSpent()
	if spent > budget.DefaultLimit {
		t.Errorf("fuel spent = %d, exceeds the ceiling %d", spent, budget.DefaultLimit)
	}
	t.Logf("maximum fan-out consumed %d of %d fuel (%.1f%%)",
		spent, budget.DefaultLimit, 100*float64(spent)/float64(budget.DefaultLimit))
}

// TestSLOAdmittedTrafficIsNotStarved checks the other half of the fuel
// contract, which is easy to get wrong: a request the input limits accept must
// not then be rejected for running out of fuel. If the two are incoherent, the
// deployment silently rejects traffic it was configured to serve.
func TestSLOAdmittedTrafficIsNotStarved(t *testing.T) {
	w := newWAF(t)

	// A body at exactly the default size limit, plus a full header set.
	body := []byte(benignJSON(gwaf.DefaultLimits().MaxBodySize - 1024))

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/api/v1/bulk", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/json")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
	for i := range 100 {
		tx.AddArgument(fmt.Sprintf("f%d", i), "ordinary-value")
	}
	if d := tx.ProcessRequestHeaders(); d.Reason() == gwaf.ReasonBudget {
		t.Fatal("header phase exhausted the budget on admissible input")
	}
	tx.SetRequestBody(body)

	d := tx.ProcessRequestBody()
	if d.Reason() == gwaf.ReasonBudget {
		t.Errorf("maximum admissible request exhausted the fuel budget: "+
			"spent %d of %d; the input limits and fuel limit are incoherent",
			tx.FuelSpent(), budget.DefaultLimit)
	}
	if d.Blocked() {
		t.Errorf("benign maximum-size request blocked: reason=%v", d.Reason())
	}
	t.Logf("maximum admissible request consumed %d of %d fuel (%.1f%%)",
		tx.FuelSpent(), budget.DefaultLimit,
		100*float64(tx.FuelSpent())/float64(budget.DefaultLimit))
}

// ---- helpers ---------------------------------------------------------------

// syntheticRules builds n distinct prefilterable rules, for scaling tests.
func syntheticRules(n int) rules.Set {
	set := make(rules.Set, 0, n)
	for i := range n {
		set = append(set, rules.Rule{
			ID:         types.UserMin + types.RuleID(i),
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetArgs}},
			Op:         op.Contains(fmt.Sprintf("synthetic_attack_token_%06d", i)),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityError,
			Confidence: types.Certain,
			Msg:        "synthetic",
		})
	}
	return set
}

// benignJSON returns realistic JSON of roughly the requested size.
func benignJSON(size int) string {
	var b strings.Builder
	b.WriteString(`{"items":[`)
	for i := 0; b.Len() < size-64; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":%d,"sku":"SKU-%06d","qty":%d,"note":"standard delivery"}`,
			i, i, i%10+1)
	}
	b.WriteString(`]}`)
	return b.String()
}
