// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package extension_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"

	vendor "example.com/gwafvendor"
)

// TestVendorRuleCompilesAndRuns is the end of the claim: an operator, a
// transform, and an action all written outside the gwaf module path, compiled
// into a ruleset, and blocking a request.
//
// If this file compiles, a vendor can implement the extension points. If it does
// not, they cannot — and no test inside the repo would have noticed, because
// Go's internal-package rule is keyed on import path and everything in the tree
// is on the right side of it.
func TestVendorRuleCompilesAndRuns(t *testing.T) {
	seen := 0

	set := rules.Set{{
		ID:         5000001,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Transforms: []rules.Transform{vendor.Transform{}},
		// The transform reverses the value, so the operator must look for the
		// reversed needle. That is not a quirk of the fixture: an operator
		// states its literals in terms of the value it will actually see, after
		// transformation, and a vendor has to get that right the same way a
		// first-party rule does.
		Op:         vendor.NewOperator("lave"),
		Actions:    []rules.Action{vendor.Action{Seen: &seen}},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "vendor rule matched",
		Tags:       []string{"vendor"},
	}}

	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatalf("gwaf.New with a vendor ruleset: %v", err)
	}

	// "eval" reversed is "lave".
	d := run(t, w, "/x", map[string]string{"q": "please eval this"})
	if !d.Blocked() {
		t.Fatalf("vendor rule did not fire: reason=%v evaluated=%d",
			d.Reason(), d.RulesEvaluated())
	}
	if d.RuleID() != 5000001 {
		t.Errorf("RuleID = %d, want 5000001", d.RuleID())
	}
	if seen != 1 {
		t.Errorf("vendor action ran %d times, want 1", seen)
	}

	// And a value the operator does not match passes.
	if d := run(t, w, "/x", map[string]string{"q": "nothing here"}); d.Blocked() {
		t.Errorf("benign value blocked: rule=%d", d.RuleID())
	}
}

// TestVendorOperatorIsPrefiltered checks that a third-party operator gets the
// same treatment as a first-party one rather than being quietly demoted to
// running against every value.
//
// This is the reconciliation CLAUDE.md §2 invariant 6 promises: custom rules
// cannot silently cost latency. If a vendor operator declaring literals were
// treated as unconditional, an embedder would discover it as a latency
// regression in production rather than as a line in a compile report.
func TestVendorOperatorIsPrefiltered(t *testing.T) {
	set := rules.Set{{
		ID:         5000002,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         vendor.NewOperator("verydistinctiveneedle"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "vendor rule",
	}}

	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatal(err)
	}

	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/x", "HTTP/1.1")
	tx.AddArgument("q", "an ordinary value with none of it")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()

	if n := tx.RulesEvaluated(); n != 0 {
		t.Errorf("RulesEvaluated() = %d, want 0: a vendor operator declaring "+
			"literals must be prefiltered like any other", n)
	}
}

// TestVendorCostIsMetered checks the reason Cost exists at all: a vendor
// operator's declared price is charged against the transaction budget, so a
// third-party rule cannot escape the fuel bound.
func TestVendorCostIsMetered(t *testing.T) {
	set := rules.Set{{
		ID:         5000003,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         vendor.NewOperator("needle"),
		Actions:    []rules.Action{rules.Log},
		Severity:   types.SeverityNotice,
		Confidence: types.Certain,
		Msg:        "vendor rule",
	}}

	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set),
		gwaf.WithFuelLimit(types.DefaultFuelLimit))
	if err != nil {
		t.Fatal(err)
	}

	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/x", "HTTP/1.1")
	tx.AddArgument("q", "a needle in here")
	tx.ProcessRequestHeaders()

	if tx.FuelSpent() <= 0 {
		t.Error("FuelSpent() is zero after evaluating a vendor rule")
	}
	// WithFuelLimit takes the public type, so an embedder can name it.
	var _ types.Fuel = tx.FuelSpent()
}

func run(t *testing.T, w *gwaf.WAF, target string, args map[string]string) gwaf.Decision {
	t.Helper()
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", target, "HTTP/1.1")
	for k, v := range args {
		tx.AddArgument(k, v)
	}
	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return d
	}
	return tx.ProcessRequestBody()
}

// TestVendorResolverSuppliesASignal is the mechanism behind the scope line in
// CLAUDE.md §1. gwaf analyses one request with no memory, so a reputation score
// is the embedder's to compute — and this is how the result reaches a rule.
func TestVendorResolverSuppliesASignal(t *testing.T) {
	calls := 0

	set := rules.Set{{
		ID:         5000004,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetResolved, Name: "reputation"}},
		Op:         vendor.NewOperator("99"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "reputation score above threshold",
	}}

	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatal(err)
	}

	// A bad score blocks.
	tx := w.NewTransaction()
	tx.AddResolver(vendor.Resolver{Score: "99", ASN: "AS64496", Calls: &calls})
	tx.SetRequestLine("GET", "/x", "HTTP/1.1")
	d := tx.ProcessRequestHeaders()
	tx.Close()
	if !d.Blocked() {
		t.Errorf("a resolved signal did not reach the rule: reason=%v", d.Reason())
	}
	if calls != 1 {
		t.Errorf("resolver called %d times, want 1", calls)
	}

	// A good score does not.
	calls = 0
	tx = w.NewTransaction()
	tx.AddResolver(vendor.Resolver{Score: "3", ASN: "AS64496", Calls: &calls})
	tx.SetRequestLine("GET", "/x", "HTTP/1.1")
	d = tx.ProcessRequestHeaders()
	tx.Close()
	if d.Blocked() {
		t.Errorf("a good score blocked: rule=%d", d.RuleID())
	}
}

// TestResolverIsNotCalledWhenNoRuleReadsIt is why Resolver is an interface
// rather than a setter. A signal is out of gwaf's scope usually because
// obtaining it is expensive — a reputation lookup, a fingerprint, a database
// read — so paying for it when nothing reads it would undo the reason for
// keeping it out.
func TestResolverIsNotCalledWhenNoRuleReadsIt(t *testing.T) {
	calls := 0

	// A ruleset that reads ordinary arguments and no resolved collection.
	set := rules.Set{{
		ID:         5000005,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         vendor.NewOperator("needle"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "unrelated rule",
	}}

	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatal(err)
	}

	tx := w.NewTransaction()
	defer tx.Close()
	tx.AddResolver(vendor.Resolver{Score: "99", Calls: &calls})
	tx.SetRequestLine("GET", "/x", "HTTP/1.1")
	tx.AddArgument("q", "ordinary")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()

	if calls != 0 {
		t.Errorf("resolver called %d times when no rule reads it; the whole "+
			"point is that an expensive signal is not paid for unread", calls)
	}
}

// TestResolverIsCalledAtMostOncePerRequest covers the other half: a resolver
// read by rules in several phases must not repeat an expensive lookup.
func TestResolverIsCalledAtMostOncePerRequest(t *testing.T) {
	calls := 0

	set := rules.Set{
		{
			ID:         5000006,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetResolved, Name: "reputation"}},
			Op:         vendor.NewOperator("zzz"),
			Actions:    []rules.Action{rules.Log},
			Severity:   types.SeverityNotice,
			Confidence: types.Certain,
			Msg:        "phase 1 reads reputation",
		},
		{
			ID:         5000007,
			Phase:      types.PhaseRequestBody,
			Targets:    []types.Target{{Kind: types.TargetResolved, Name: "reputation"}},
			Op:         vendor.NewOperator("zzz"),
			Actions:    []rules.Action{rules.Log},
			Severity:   types.SeverityNotice,
			Confidence: types.Certain,
			Msg:        "phase 2 reads reputation",
		},
	}

	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatal(err)
	}

	tx := w.NewTransaction()
	defer tx.Close()
	tx.AddResolver(vendor.Resolver{Score: "10", Calls: &calls})
	tx.SetRequestLine("POST", "/x", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(`{"a":1}`))
	tx.ProcessRequestBody()

	if calls != 1 {
		t.Errorf("resolver called %d times across two phases, want 1", calls)
	}
}

// TestResolvedValuesAreKeyed checks that a resolver may supply several values,
// the way a header collection does, and that a rule can select one.
func TestResolvedValuesAreKeyed(t *testing.T) {
	set := rules.Set{{
		ID:      5000008,
		Phase:   types.PhaseRequestHeaders,
		Targets: []types.Target{{Kind: types.TargetResolved, Name: "reputation"}},
		// AS64496 is in the "asn" value, not the "score" value: the rule only
		// fires if both keys were supplied.
		Op:         vendor.NewOperator("AS64496"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "hostile ASN",
	}}

	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatal(err)
	}

	tx := w.NewTransaction()
	defer tx.Close()
	tx.AddResolver(vendor.Resolver{Score: "3", ASN: "AS64496"})
	tx.SetRequestLine("GET", "/x", "HTTP/1.1")
	if d := tx.ProcessRequestHeaders(); !d.Blocked() {
		t.Error("the second resolved value never reached the rule")
	}
}

// TestNoResolverIsSafe: a rule reading a resolved collection nobody registered
// must not fire and must not panic. An embedder disabling a signal source
// should degrade to "no match", never to a crash or a false positive.
func TestNoResolverIsSafe(t *testing.T) {
	set := rules.Set{{
		ID:         5000009,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetResolved, Name: "reputation"}},
		Op:         vendor.NewOperator("99"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "reputation rule",
	}}

	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatal(err)
	}

	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/x", "HTTP/1.1")
	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		t.Errorf("blocked with no resolver registered: rule=%d", d.RuleID())
	}

	// A nil resolver is ignored rather than panicking on the request path.
	tx2 := w.NewTransaction()
	defer tx2.Close()
	tx2.AddResolver(nil)
	tx2.SetRequestLine("GET", "/x", "HTTP/1.1")
	tx2.ProcessRequestHeaders()
}
