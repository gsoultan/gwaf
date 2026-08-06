// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
)

// newWAF builds a WAF for tests, failing fast on a compile error.
func newWAF(t *testing.T, opts ...gwaf.Option) *gwaf.WAF {
	t.Helper()
	w, err := gwaf.New(opts...)
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	return w
}

// req describes a request for the table tests.
type req struct {
	method  string
	target  string
	headers map[string]string
	args    map[string]string
	body    string
}

// run drives a full request through a transaction and returns the decision.
func run(t *testing.T, w *gwaf.WAF, r req) gwaf.Decision {
	t.Helper()

	tx := w.NewTransaction()
	defer tx.Close()

	method := r.method
	if method == "" {
		method = "GET"
	}
	target := r.target
	if target == "" {
		target = "/"
	}

	tx.SetRequestLine(method, target, "HTTP/1.1")
	tx.SetRemoteAddr("192.0.2.1")
	for k, v := range r.headers {
		tx.AddRequestHeader(k, v)
	}
	for k, v := range r.args {
		tx.AddArgument(k, v)
	}

	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return d
	}
	if r.body != "" {
		tx.SetRequestBody([]byte(r.body))
	}
	return tx.ProcessRequestBody()
}

// TestZeroConfigBlocksAttacks is the contract from CLAUDE.md §2b: gwaf.New()
// with no arguments must be a working, blocking firewall. A library that needs
// configuration before it protects anything ships inert.
func TestZeroConfigBlocksAttacks(t *testing.T) {
	w := newWAF(t)

	attacks := []struct {
		name string
		req  req
	}{
		{"sqli union in arg", req{args: map[string]string{"id": "1 UNION SELECT password FROM users"}}},
		{"sqli tautology", req{args: map[string]string{"id": "1' OR 1=1--"}}},
		{"sqli stacked drop", req{args: map[string]string{"q": "x'; DROP TABLE users"}}},
		{"xss script tag", req{args: map[string]string{"q": "<script>alert(1)</script>"}}},
		{"traversal encoded", req{target: "/files?path=..%2f..%2fetc%2fpasswd"}},
		{"traversal in path", req{target: "/static/../../etc/passwd"}},
		{"sensitive file", req{args: map[string]string{"f": "/etc/passwd"}}},
		{"shell injection", req{args: map[string]string{"host": "127.0.0.1; cat /etc/hosts"}}},
		{"php wrapper", req{args: map[string]string{"page": "php://filter/read=convert.base64-encode"}}},
		{"scanner ua", req{headers: map[string]string{"User-Agent": "sqlmap/1.7.2#stable"}}},
		{"sqli in body", req{method: "POST", body: "q=1 UNION ALL SELECT NULL"}},
		{"xss in body", req{method: "POST", body: `{"c":"<script>x</script>"}`}},
	}

	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			d := run(t, w, tt.req)
			if !d.Blocked() {
				t.Errorf("attack not blocked: verdict=%v score=%d rule=%d",
					d.Verdict(), d.Score(), d.RuleID())
			}
			// Every block must be explainable, or it is a block that gets
			// disabled the first time someone has to debug it.
			if d.RuleID() == 0 {
				t.Error("blocked without attributing a rule")
			}
			if d.Message() == "" {
				t.Error("blocked without a message")
			}
		})
	}
}

// TestBenignTrafficPasses is the other half of the contract. A detector that
// blocks everything passes any recall-only test, so false positives are checked
// with the same weight as detection.
func TestBenignTrafficPasses(t *testing.T) {
	w := newWAF(t)

	benign := []struct {
		name string
		req  req
	}{
		{"root", req{}},
		{"api path", req{target: "/api/v1/orders/12345"}},
		{"query args", req{target: "/search?q=golang+web+framework", args: map[string]string{"q": "golang web framework"}}},
		{"normal ua", req{headers: map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}}},
		{"json body", req{method: "POST", body: `{"name":"Alice","qty":3,"note":"please deliver before 5pm"}`}},
		{"form body", req{method: "POST", body: "email=user%40example.com&subject=Hello+there"}},
		{"relative link arg", req{args: map[string]string{"next": "/dashboard/settings"}}},
		{"uuid arg", req{args: map[string]string{"id": "550e8400-e29b-41d4-a716-446655440000"}}},
		{"iso timestamp", req{args: map[string]string{"since": "2026-08-05T07:38:00Z"}}},
		{"base64 arg", req{args: map[string]string{"t": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"}}},
		{"prose with apostrophe", req{method: "POST", body: `{"c":"it's a great product, I'd buy again"}`}},
		{"sql word in prose", req{method: "POST", body: `{"c":"we should select a new union representative"}`}},
		{"path with dots in filename", req{target: "/assets/app.min.v2.js"}},
		{"encoded space", req{args: map[string]string{"q": "hello%20world"}}},
		{"accept header", req{headers: map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9"}}},
	}

	for _, tt := range benign {
		t.Run(tt.name, func(t *testing.T) {
			d := run(t, w, tt.req)
			if d.Blocked() {
				t.Errorf("false positive: rule=%d msg=%q score=%d",
					d.RuleID(), d.Message(), d.Score())
			}
		})
	}
}

// TestBenignTrafficEvaluatesZeroRules is the performance thesis as a test. If
// the prefilter works, benign traffic reaches no operator at all; a drift above
// zero here is the leading indicator that latency is about to regress.
func TestBenignTrafficEvaluatesZeroRules(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/api/v1/orders/12345", "HTTP/1.1")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
	tx.AddRequestHeader("Accept", "application/json")
	tx.AddArgument("page", "2")

	d := tx.ProcessRequestHeaders()
	if d.Blocked() {
		t.Fatalf("benign request blocked: %v", d.Message())
	}
	if got := tx.RulesEvaluated(); got != 0 {
		t.Errorf("RulesEvaluated() = %d, want 0: the prefilter is not filtering", got)
	}
}

func TestDetectionOnlyDoesNotBlock(t *testing.T) {
	w := newWAF(t, gwaf.WithMode(gwaf.DetectionOnly))

	d := run(t, w, req{args: map[string]string{"id": "1 UNION SELECT x"}})
	if d.Blocked() {
		t.Error("detection-only mode blocked a request")
	}
	// The detection itself must still be reported, or the mode is useless for
	// the rollout it exists to support.
	if d.RuleID() == 0 {
		t.Error("detection-only mode lost the rule attribution")
	}
}

func TestPhaseShortCircuit(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/?x=1", "HTTP/1.1")
	tx.AddRequestHeader("User-Agent", "sqlmap/1.7")

	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		t.Fatal("scanner user-agent not blocked at header phase")
	}
	// Blocking at the header phase is what lets a caller skip reading the body
	// off the socket entirely.
	if d.Reason() != gwaf.ReasonRule {
		t.Errorf("Reason() = %v, want ReasonRule", d.Reason())
	}
}

func TestCustomRule(t *testing.T) {
	custom := rules.Set{{
		ID:         1_000_001,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetRequestHeaders, Name: "X-Api-Key"}},
		Op:         op.Equals("forbidden-key"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "Revoked API key",
	}}

	w := newWAF(t, gwaf.WithRuleset(custom))

	d := run(t, w, req{headers: map[string]string{"X-Api-Key": "forbidden-key"}})
	if !d.Blocked() {
		t.Fatal("custom rule did not block")
	}
	if d.RuleID() != 1_000_001 {
		t.Errorf("RuleID() = %d, want 1000001", d.RuleID())
	}

	if d := run(t, w, req{headers: map[string]string{"X-Api-Key": "valid-key"}}); d.Blocked() {
		t.Error("custom rule blocked a valid key")
	}
}

func TestAnomalyThreshold(t *testing.T) {
	// Two scoring rules, each below the threshold alone but blocking together.
	set := rules.Set{
		{
			ID:         1_000_010,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetArgs}},
			Op:         op.Contains("alpha"),
			Actions:    []rules.Action{rules.ScoreBy(3)},
			Severity:   types.SeverityWarning,
			Confidence: types.Certain,
			Msg:        "alpha",
		},
		{
			ID:         1_000_011,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetArgs}},
			Op:         op.Contains("beta"),
			Actions:    []rules.Action{rules.ScoreBy(3)},
			Severity:   types.SeverityWarning,
			Confidence: types.Certain,
			Msg:        "beta",
		},
	}

	w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set), gwaf.WithThreshold(5))

	if d := run(t, w, req{args: map[string]string{"q": "alpha"}}); d.Blocked() {
		t.Errorf("single hit (score 3) blocked below threshold 5")
	}
	d := run(t, w, req{args: map[string]string{"q": "alpha and beta"}})
	if !d.Blocked() {
		t.Errorf("two hits (score 6) did not reach threshold 5, score=%d", d.Score())
	}
	if d.Reason() != gwaf.ReasonThreshold {
		t.Errorf("Reason() = %v, want ReasonThreshold", d.Reason())
	}
}

func TestConfidenceSelection(t *testing.T) {
	set := rules.Set{{
		ID:         1_000_020,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         op.Contains("maybe-bad"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityError,
		Confidence: types.Low,
		Msg:        "low confidence heuristic",
	}}

	// A Low-confidence rule must not run under the default High policy.
	strict := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if d := run(t, strict, req{args: map[string]string{"q": "maybe-bad"}}); d.Blocked() {
		t.Error("Low confidence rule ran under the default High minimum")
	}

	// Lowering the minimum admits it.
	loose := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set),
		gwaf.WithMinConfidence(types.Low))
	if d := run(t, loose, req{args: map[string]string{"q": "maybe-bad"}}); !d.Blocked() {
		t.Error("Low confidence rule did not run at MinConfidence(Low)")
	}
}

// TestParanoiaLevelCompat checks the CRS compatibility mapping, which is what
// lets an existing deployment's paranoia setting carry over.
func TestParanoiaLevelCompat(t *testing.T) {
	set := rules.Set{{
		ID:         1_000_030,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         op.Contains("pl3-only"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityError,
		Confidence: types.Low, // PL3 tier
		Msg:        "pl3 rule",
	}}

	pl1 := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set), gwaf.WithParanoiaLevel(1))
	if d := run(t, pl1, req{args: map[string]string{"q": "pl3-only"}}); d.Blocked() {
		t.Error("PL3-tier rule ran at paranoia level 1")
	}

	pl3 := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set), gwaf.WithParanoiaLevel(3))
	if d := run(t, pl3, req{args: map[string]string{"q": "pl3-only"}}); !d.Blocked() {
		t.Error("PL3-tier rule did not run at paranoia level 3")
	}
}

func TestLimitsRejectOversizedBody(t *testing.T) {
	w := newWAF(t, gwaf.WithLimits(gwaf.Limits{MaxBodySize: 64}))

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/upload", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(strings.Repeat("a", 128)))

	d := tx.ProcessRequestBody()
	if !d.Blocked() {
		t.Error("oversized body not rejected under fail-closed")
	}
	if d.Reason() != gwaf.ReasonLimit {
		t.Errorf("Reason() = %v, want ReasonLimit", d.Reason())
	}
}

func TestFailOpenPermitsOnLimit(t *testing.T) {
	w := newWAF(t,
		gwaf.WithLimits(gwaf.Limits{MaxBodySize: 64}),
		gwaf.WithFailMode(gwaf.FailOpen),
	)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/upload", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(strings.Repeat("a", 128)))

	d := tx.ProcessRequestBody()
	if d.Blocked() {
		t.Error("fail-open still blocked on a limit breach")
	}
	// Fail-open must stay loud: the reason distinguishes "analysed and clean"
	// from "could not analyse and chose to allow".
	if d.Reason() != gwaf.ReasonLimit {
		t.Errorf("Reason() = %v, want ReasonLimit", d.Reason())
	}
}

func TestFuelExhaustionIsDeterministic(t *testing.T) {
	// A tiny budget guarantees exhaustion, and fuel being deterministic means
	// this reproduces identically every run — which a wall-clock budget could
	// not do.
	w := newWAF(t, gwaf.WithFuelLimit(1))

	var first gwaf.Decision
	for i := range 20 {
		tx := w.NewTransaction()
		tx.SetRequestLine("GET", "/?q=test", "HTTP/1.1")
		tx.AddArgument("q", strings.Repeat("payload ", 100))
		d := tx.ProcessRequestHeaders()
		tx.Close()

		if i == 0 {
			first = d
			if d.Reason() != gwaf.ReasonBudget {
				t.Fatalf("Reason() = %v, want ReasonBudget", d.Reason())
			}
			if !d.Blocked() {
				t.Fatal("fail-closed did not block on budget exhaustion")
			}
			continue
		}
		if d.Reason() != first.Reason() || d.Verdict() != first.Verdict() {
			t.Fatalf("run %d diverged: got (%v,%v), want (%v,%v)",
				i, d.Verdict(), d.Reason(), first.Verdict(), first.Reason())
		}
	}
}

func TestOnDecisionCallback(t *testing.T) {
	var got []gwaf.Decision
	w := newWAF(t, gwaf.OnDecision(func(d gwaf.Decision) { got = append(got, d) }))

	run(t, w, req{args: map[string]string{"id": "1 UNION SELECT x"}})

	if len(got) != 1 {
		t.Fatalf("callback invoked %d times, want 1", len(got))
	}
	if !got[0].Blocked() {
		t.Error("callback received a non-blocking decision")
	}
}

func TestSwapRuleset(t *testing.T) {
	w := newWAF(t, gwaf.WithoutCoreRuleset())

	if d := run(t, w, req{args: map[string]string{"q": "trigger"}}); d.Blocked() {
		t.Fatal("empty ruleset blocked a request")
	}

	rs, err := w.Compile(rules.Set{{
		ID:         1_000_040,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         op.Contains("trigger"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "swapped in",
	}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	w.SwapRuleset(rs)

	if d := run(t, w, req{args: map[string]string{"q": "trigger"}}); !d.Blocked() {
		t.Error("swapped ruleset did not take effect")
	}
}

// TestNoGlobalState verifies that independent instances stay independent. This
// is what makes multi-tenant embedding and parallel tests work, and it cannot
// be retrofitted once violated.
func TestNoGlobalState(t *testing.T) {
	strict := newWAF(t)
	permissive := newWAF(t, gwaf.WithoutCoreRuleset())

	attack := req{args: map[string]string{"id": "1 UNION SELECT x"}}

	if d := run(t, strict, attack); !d.Blocked() {
		t.Error("strict instance did not block")
	}
	if d := run(t, permissive, attack); d.Blocked() {
		t.Error("permissive instance blocked; instances are sharing state")
	}
	if d := run(t, strict, attack); !d.Blocked() {
		t.Error("strict instance stopped blocking after the permissive one ran")
	}
}

func TestConcurrentTransactions(t *testing.T) {
	w := newWAF(t)

	const goroutines = 32
	const iterations = 100

	errs := make(chan string, goroutines)
	done := make(chan struct{})

	for g := range goroutines {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for range iterations {
				// Alternate attack and benign traffic so a shared-state bug
				// shows up as a wrong verdict rather than only as a race.
				if g%2 == 0 {
					d := run(t, w, req{args: map[string]string{"id": "1 UNION SELECT x"}})
					if !d.Blocked() {
						errs <- "attack allowed under concurrency"
						return
					}
				} else {
					d := run(t, w, req{args: map[string]string{"q": "ordinary search text"}})
					if d.Blocked() {
						errs <- "benign blocked under concurrency"
						return
					}
				}
			}
		}(g)
	}

	for range goroutines {
		<-done
	}
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

func TestCompileReport(t *testing.T) {
	w := newWAF(t)
	r := w.Report()

	if r.Rules == 0 {
		t.Fatal("report has no rules")
	}
	if r.Literals == 0 {
		t.Error("report has no literals; the prefilter would be empty")
	}
	// The core ruleset is written to be fully prefilterable. If that stops
	// being true, every request pays for it and the report is where it shows.
	if len(r.Unconditional) != 0 {
		t.Errorf("core ruleset has %d unconditional rules: %+v",
			len(r.Unconditional), r.Unconditional)
	}
	if r.Prefiltered != r.Rules {
		t.Errorf("Prefiltered = %d, want %d (all rules)", r.Prefiltered, r.Rules)
	}
}

func TestUnconditionalRuleIsReported(t *testing.T) {
	w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{{
		ID:         1_000_050,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         op.Func("always", func([]byte) bool { return false }),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityNotice,
		Confidence: types.Certain,
		Msg:        "unconditional",
	}}))

	r := w.Report()
	if len(r.Unconditional) != 1 {
		t.Fatalf("Unconditional = %d, want 1", len(r.Unconditional))
	}
	u := r.Unconditional[0]
	if u.ID != 1_000_050 {
		t.Errorf("ID = %d, want 1000050", u.ID)
	}
	// The report must say why, or "unconditional" is not actionable.
	if u.Reason == "" {
		t.Error("unconditional rule reported without a reason")
	}
}

// TestFuncWithLiteralsIsPrefiltered verifies the documented escape hatch: a
// predicate that can honestly declare its required literals gets prefiltered
// like any built-in operator.
func TestFuncWithLiteralsIsPrefiltered(t *testing.T) {
	hinted := op.Func("graphql-introspection", func(v []byte) bool {
		return strings.Contains(string(v), "__schema")
	}).WithLiterals("__schema")

	w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{{
		ID:         1_000_060,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         hinted,
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityWarning,
		Confidence: types.Certain,
		Msg:        "introspection query",
	}}))

	if r := w.Report(); len(r.Unconditional) != 0 {
		t.Errorf("hinted Func should be prefiltered, got %+v", r.Unconditional)
	}

	if d := run(t, w, req{args: map[string]string{"q": "{__schema{types{name}}}"}}); !d.Blocked() {
		t.Error("hinted Func rule did not match")
	}
	if d := run(t, w, req{args: map[string]string{"q": "{user{name}}"}}); d.Blocked() {
		t.Error("hinted Func rule matched unrelated input")
	}
}

func TestTransactionReuseIsClean(t *testing.T) {
	w := newWAF(t)

	// An attack followed by benign traffic on a pooled transaction: residue
	// from the first would show up as a false positive on the second.
	for range 50 {
		if d := run(t, w, req{args: map[string]string{"id": "1 UNION SELECT x"}}); !d.Blocked() {
			t.Fatal("attack not blocked")
		}
		if d := run(t, w, req{args: map[string]string{"q": "ordinary text"}}); d.Blocked() {
			t.Fatalf("pooled transaction leaked state: rule=%d score=%d",
				d.RuleID(), d.Score())
		}
	}
}

func TestDecisionCarriesMatchSpan(t *testing.T) {
	w := newWAF(t)

	d := run(t, w, req{args: map[string]string{"id": "1 UNION SELECT x"}})
	if !d.Blocked() {
		t.Fatal("not blocked")
	}
	span, ok := d.MatchedSpan()
	if !ok {
		t.Fatal("blocked decision carries no match span")
	}
	if span.Len == 0 {
		t.Error("match span is empty")
	}
	if d.Target().Kind == types.TargetInvalid {
		t.Error("decision does not identify the matched target")
	}
}
