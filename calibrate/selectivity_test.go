// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package calibrate_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/calibrate"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
)

// selCorpus is small and hand-countable on purpose. A selectivity tool whose
// own numbers cannot be checked by hand is a tool nobody should believe.
var selCorpus = []calibrate.Request{
	{Name: "1", Method: "GET", Target: "/a", Args: map[string]string{"q": "alpha"}},
	{Name: "2", Method: "GET", Target: "/b", Args: map[string]string{"q": "beta"}},
	{Name: "3", Method: "GET", Target: "/c", Args: map[string]string{"q": "gamma"}},
	{Name: "4", Method: "GET", Target: "/d", Args: map[string]string{"q": "delta"}},
}

func selRule(id types.RuleID, o rules.Operator, targets ...types.TargetKind) rules.Rule {
	ts := make([]types.Target, 0, len(targets))
	for _, k := range targets {
		ts = append(ts, types.Target{Kind: k})
	}
	return rules.Rule{
		ID:         id,
		Phase:      types.PhaseRequestHeaders,
		Targets:    ts,
		Op:         o,
		Actions:    []rules.Action{rules.Score},
		Severity:   types.SeverityNotice,
		Confidence: types.Certain,
		Msg:        "test rule",
	}
}

func selWAF(t *testing.T, rs ...rules.Rule) *gwaf.WAF {
	t.Helper()
	w, err := gwaf.New(gwaf.WithRuleset(rules.Set(rs)))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return w
}

func rateOf(t *testing.T, rep calibrate.SelectivityReport, id types.RuleID) calibrate.RuleSelectivity {
	t.Helper()
	for _, r := range rep.Rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %d absent from report", id)
	return calibrate.RuleSelectivity{}
}

// TestSelectivityCountsWhatItSays is the known-answer test.
//
// Four requests, arguments "alpha" "beta" "gamma" "delta":
//
//	"a"     — in all four                 → 100%
//	"lph"   — in "alpha" only             →  25%
//	"zzz"   — in none                     →   0%
func TestSelectivityCountsWhatItSays(t *testing.T) {
	const (
		all  = types.UserMin + 1
		one  = types.UserMin + 2
		none = types.UserMin + 3
	)
	w := selWAF(t,
		selRule(all, op.Contains("a"), types.TargetArgs),
		selRule(one, op.Contains("lph"), types.TargetArgs),
		selRule(none, op.Contains("zzz"), types.TargetArgs),
	)

	rep, err := calibrate.Selectivity(w, selCorpus)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Requests != len(selCorpus) {
		t.Fatalf("report covers %d requests, corpus has %d", rep.Requests, len(selCorpus))
	}

	for _, tc := range []struct {
		id   types.RuleID
		want float64
		why  string
	}{
		{all, 1.00, `"a" is in every argument`},
		{one, 0.25, `"lph" is in "alpha" only`},
		{none, 0.00, `"zzz" is in nothing`},
	} {
		got := rateOf(t, rep, tc.id)
		if got.Rate != tc.want {
			t.Errorf("rule %d: rate %.2f, want %.2f (%s)", tc.id, got.Rate, tc.want, tc.why)
		}
	}
}

// TestSelectivityIsNotDerivedFromScansReturnValue pins the first bug this tool
// had, because the shape of it will recur.
//
// Automaton.Scan returns the number of *bytes scanned*, so the caller can charge
// fuel. Reading it as a match count made every rule report 100% — including
// rules whose worst literal reported 0%, which is what made it obvious. A less
// absurd misreading would have shipped, and a selectivity number that is
// silently always 1.0 is worse than no number: it retires the real signal.
func TestSelectivityIsNotDerivedFromScansReturnValue(t *testing.T) {
	const id = types.UserMin + 1
	w := selWAF(t, selRule(id, op.Contains("zzz-absent"), types.TargetArgs))

	rep, err := calibrate.Selectivity(w, selCorpus)
	if err != nil {
		t.Fatal(err)
	}
	if r := rateOf(t, rep, id); r.Nominated != 0 {
		t.Errorf("a literal in none of the corpus was nominated on %d of %d requests; "+
			"nomination is being read from something other than the match set",
			r.Nominated, r.Requests)
	}
}

// TestSelectivityRespectsRuleTargets pins the second bug.
//
// The first version scanned every value against every rule, so a rule scoped to
// ARGS was credited with hits from the request URI and from headers it never
// reads. That overstates exactly the rules a reader is most likely to check by
// hand, and a diagnostic caught overstating once is a diagnostic nobody consults
// again.
func TestSelectivityRespectsRuleTargets(t *testing.T) {
	corpus := []calibrate.Request{
		// The needle is in the URI and in a header, and in no argument.
		{Name: "elsewhere", Method: "GET", Target: "/needle/here",
			Args:    map[string]string{"q": "clean"},
			Headers: map[string]string{"X-Thing": "needle"}},
	}

	const (
		argsOnly = types.UserMin + 1
		uriOnly  = types.UserMin + 2
	)
	w := selWAF(t,
		selRule(argsOnly, op.Contains("needle"), types.TargetArgs),
		selRule(uriOnly, op.Contains("needle"), types.TargetRequestURI),
	)

	rep, err := calibrate.Selectivity(w, corpus)
	if err != nil {
		t.Fatal(err)
	}
	if r := rateOf(t, rep, argsOnly); r.Nominated != 0 {
		t.Errorf("a rule targeting ARGS was nominated by a value it cannot read "+
			"(%d of %d requests)", r.Nominated, r.Requests)
	}
	if r := rateOf(t, rep, uriOnly); r.Nominated != 1 {
		t.Errorf("a rule targeting REQUEST_URI missed a needle in the URI "+
			"(%d of %d requests)", r.Nominated, r.Requests)
	}
}

// TestSelectivityMatchesTheEnginesCaseFolding keeps the tool and the prefilter
// from disagreeing.
//
// The automaton folds ASCII case, so "ALPHA" is a hit for the literal "alpha".
// A tool built on bytes.Contains would report 0% here and send a rule author to
// tighten a literal that was already doing its job.
func TestSelectivityMatchesTheEnginesCaseFolding(t *testing.T) {
	corpus := []calibrate.Request{
		{Name: "shouty", Method: "GET", Target: "/x", Args: map[string]string{"q": "ALPHA"}},
	}
	const id = types.UserMin + 1
	w := selWAF(t, selRule(id, op.Contains("alpha"), types.TargetArgs))

	rep, err := calibrate.Selectivity(w, corpus)
	if err != nil {
		t.Fatal(err)
	}
	if r := rateOf(t, rep, id); r.Nominated != 1 {
		t.Errorf("case-folded match missed: nominated %d of %d", r.Nominated, r.Requests)
	}
}

// TestSelectivityAttributesTheWorstLiteral checks the field an operator acts on.
//
// A rule is a set of literals ORed together; knowing the rule admits 90% of
// traffic is not actionable, and knowing *which* literal did it is.
func TestSelectivityAttributesTheWorstLiteral(t *testing.T) {
	const id = types.UserMin + 1
	// "a" is in every argument; "lph" is in one; "zzz" in none.
	w := selWAF(t, selRule(id, op.ContainsAny("zzz", "lph", "a"), types.TargetArgs))

	rep, err := calibrate.Selectivity(w, selCorpus)
	if err != nil {
		t.Fatal(err)
	}
	r := rateOf(t, rep, id)
	worst, ok := r.Worst()
	if !ok {
		t.Fatal("no literals reported")
	}
	if worst.Literal != "a" {
		t.Errorf("worst literal = %q, want %q -- the report is not sorted by "+
			"what admits the most traffic", worst.Literal, "a")
	}
	if worst.Rate != 1.0 {
		t.Errorf("worst literal rate = %.2f, want 1.00", worst.Rate)
	}
	if r.Rate != 1.0 {
		t.Errorf("rule rate = %.2f, want 1.00 (an OR-set is as unselective as its "+
			"worst member)", r.Rate)
	}
}

// TestSelectivityRejectsAnEmptyCorpus: a rate computed from nothing is a
// division by zero wearing a percentage sign.
func TestSelectivityRejectsAnEmptyCorpus(t *testing.T) {
	w := selWAF(t, selRule(types.UserMin+1, op.Contains("x"), types.TargetArgs))
	if _, err := calibrate.Selectivity(w, nil); err == nil {
		t.Error("empty corpus accepted")
	}
}
