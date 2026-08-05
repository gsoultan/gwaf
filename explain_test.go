// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// TestExplainCarriesEveryDatumAUIWouldNeed is CLAUDE.md §2b as a test.
//
// gwaf ships no UI, and the corollary is binding: everything a control plane
// would draw has to be reachable programmatically, or the missing accessor is a
// tier-1 API gap rather than an argument for growing a UI.
func TestExplainCarriesEveryDatumAUIWouldNeed(t *testing.T) {
	w := newWAF(t)
	d := run(t, w, req{target: "/api/v1/search", args: map[string]string{"q": "1' OR 1=1--"}})
	if !d.Blocked() {
		t.Fatal("expected a block to explain")
	}

	e := d.Explain()

	if e.RuleID() == 0 {
		t.Error("RuleID is zero")
	}
	if e.Message() == "" {
		t.Error("Message is empty")
	}
	if e.Severity() == 0 {
		t.Error("Severity is zero")
	}
	if e.Confidence() == 0 {
		t.Error("Confidence is zero")
	}
	if len(e.Tags()) == 0 {
		t.Error("Tags are empty")
	}
	if e.Key() != "q" {
		t.Errorf("Key = %q, want %q", e.Key(), "q")
	}
	if _, ok := e.MatchedSpan(); !ok {
		t.Error("no matched span")
	}
	if len(e.MatchedBytes()) == 0 {
		t.Error("no matched bytes")
	}
	if len(e.TransformChain()) == 0 {
		t.Error("no transform chain: a finding nobody can reproduce")
	}
	if e.Verdict() != gwaf.VerdictBlock {
		t.Errorf("Verdict = %v", e.Verdict())
	}
	if e.RulesEvaluated() == 0 {
		t.Error("RulesEvaluated is zero on a request that blocked")
	}
}

// TestExplainSurvivesClose covers the sharpest failure mode of an explanation
// that borrows from the transaction arena: after Close the arena is recycled, so
// a borrowed slice would report a *different* request's bytes with total
// confidence. Worse than no explanation.
func TestExplainSurvivesClose(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	tx.SetRequestLine("GET", "/api/search", "HTTP/1.1")
	tx.AddArgument("q", "1' OR 1=1--")
	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		tx.Close()
		t.Fatal("expected a block")
	}
	e := d.Explain()
	before := string(e.MatchedBytes())
	tx.Close()

	// Churn the pool so a recycled arena would hold something else entirely.
	for range 32 {
		other := w.NewTransaction()
		other.SetRequestLine("GET", "/other", "HTTP/1.1")
		other.AddArgument("filler", strings.Repeat("z", 256))
		other.ProcessRequestHeaders()
		other.Close()
	}

	if after := string(e.MatchedBytes()); after != before {
		t.Errorf("MatchedBytes changed after Close: %q became %q", before, after)
	}
}

// TestNarrowestExceptionIsActuallyNarrow checks the promise in
// docs/INTEGRATION.md: the suggested exception silences this finding and
// nothing else.
func TestNarrowestExceptionIsActuallyNarrow(t *testing.T) {
	w := newWAF(t)
	d := run(t, w, req{target: "/api/v1/query", args: map[string]string{"q": "1' OR 1=1--"}})
	if !d.Blocked() {
		t.Fatal("expected a block")
	}

	x, ok := d.Explain().NarrowestException()
	if !ok {
		t.Fatal("no exception suggested for a rule-based block")
	}
	if x.RuleID == 0 || x.Path == "" || x.Key == "" || x.Target == types.TargetInvalid {
		t.Fatalf("exception is not narrow: %+v", x)
	}

	// It suppresses the finding it came from.
	tuned := newWAF(t, gwaf.WithException(x))
	if got := run(t, tuned, req{target: "/api/v1/query",
		args: map[string]string{"q": "1' OR 1=1--"}}); got.Blocked() {
		t.Errorf("the suggested exception did not suppress its own finding: rule=%d",
			got.RuleID())
	}

	// And nothing else: same payload, different route.
	if got := run(t, tuned, req{target: "/api/v1/other",
		args: map[string]string{"q": "1' OR 1=1--"}}); !got.Blocked() {
		t.Error("the exception leaked to another route")
	}
	// Same route, different argument.
	if got := run(t, tuned, req{target: "/api/v1/query",
		args: map[string]string{"other": "1' OR 1=1--"}}); !got.Blocked() {
		t.Error("the exception leaked to another argument")
	}
	// Same route and argument, a different attack class.
	if got := run(t, tuned, req{target: "/api/v1/query",
		args: map[string]string{"q": "<script>alert(1)</script>"}}); !got.Blocked() {
		t.Error("the exception leaked to another rule")
	}
}

// TestExceptionRemovesTheScoreToo covers the most confusing possible outcome of
// adding an exception: the finding is suppressed, its score is not, and the
// request is blocked one rule later by a rule the operator never excepted.
func TestExceptionRemovesTheScoreToo(t *testing.T) {
	w := newWAF(t, gwaf.WithException(rules.Exception{
		RuleID: 2010,
		Path:   "/api/v1/query",
		Target: types.TargetArgs,
		Key:    "q",
	}))

	d := run(t, w, req{target: "/api/v1/query", args: map[string]string{"q": "1' OR 1=1--"}})
	if d.Blocked() {
		t.Fatalf("still blocked: rule=%d msg=%q", d.RuleID(), d.Message())
	}
	if d.Score() != 0 {
		t.Errorf("Score() = %d, want 0: a suppressed finding still contributed", d.Score())
	}
}

// TestExceptionTooBroadIsRefused keeps the blunt instrument out of reach. A
// configuration that disables every rule everywhere should not be expressible
// by accident.
func TestExceptionTooBroadIsRefused(t *testing.T) {
	if _, err := gwaf.New(gwaf.WithException(rules.Exception{})); err == nil {
		t.Error("an exception matching everything was accepted")
	}
}

func TestExceptionScopes(t *testing.T) {
	cases := []struct {
		name string
		x    rules.Exception
		want bool
	}{
		{"rule only", rules.Exception{RuleID: 2010}, true},
		{"wrong rule", rules.Exception{RuleID: 9999}, false},
		{"exact path", rules.Exception{RuleID: 2010, Path: "/api/v1/query"}, true},
		{"wrong path", rules.Exception{RuleID: 2010, Path: "/other"}, false},
		{"prefix path", rules.Exception{RuleID: 2010, Path: "/api/*"}, true},
		{"prefix miss", rules.Exception{RuleID: 2010, Path: "/admin/*"}, false},
		{"exact key", rules.Exception{RuleID: 2010, Key: "q"}, true},
		{"wrong key", rules.Exception{RuleID: 2010, Key: "other"}, false},
		{"target", rules.Exception{RuleID: 2010, Target: types.TargetArgs}, true},
		{"wrong target", rules.Exception{RuleID: 2010, Target: types.TargetRequestHeaders}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWAF(t, gwaf.WithException(c.x))
			d := run(t, w, req{target: "/api/v1/query",
				args: map[string]string{"q": "1' OR 1=1--"}})
			if suppressed := !d.Blocked(); suppressed != c.want {
				t.Errorf("suppressed = %v, want %v", suppressed, c.want)
			}
		})
	}
}

// TestExplainOnAllowedRequest checks the accessor is safe on a decision that
// blocked nothing, which is the common case a control plane still charts.
func TestExplainOnAllowedRequest(t *testing.T) {
	w := newWAF(t)
	d := run(t, w, req{target: "/api/v1/orders", args: map[string]string{"page": "2"}})
	if d.Blocked() {
		t.Fatal("benign request blocked")
	}

	e := d.Explain()
	if e.RuleID() != 0 {
		t.Errorf("RuleID = %d on an allowed request", e.RuleID())
	}
	if _, ok := e.NarrowestException(); ok {
		t.Error("an exception was suggested for a request nothing blocked")
	}
	if e.Verdict() != gwaf.VerdictAllow {
		t.Errorf("Verdict = %v", e.Verdict())
	}
}

// TestExplainStringIsReadable checks the operator-facing rendering carries the
// three things needed to act: what fired, what matched, and how to suppress it.
func TestExplainStringIsReadable(t *testing.T) {
	w := newWAF(t)
	d := run(t, w, req{target: "/search", args: map[string]string{"q": "1' OR 1=1--"}})

	s := d.Explain().String()
	for _, want := range []string{"rule ", "severity:", "confidence:", "matched:", "rules.Exception{"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() is missing %q:\n%s", want, s)
		}
	}
}

// TestExplainReportsTheInterpretation covers the fact that is most confusing to
// meet in a log: a payload found only under an alternative decoding looks
// harmless on the wire, and without this the block reads as a malfunction.
func TestExplainReportsTheInterpretation(t *testing.T) {
	w := newWAF(t)
	// Double-encoded, so it is only visible under an alternative reading.
	d := run(t, w, req{args: map[string]string{"q": "1%2527%2520OR%25201%253D1--"}})
	if !d.Blocked() {
		t.Skip("payload not caught; interpretation reporting is what is under test")
	}
	if got := d.Explain().Interpretation(); got == "" {
		t.Error("Interpretation is empty")
	}
}
