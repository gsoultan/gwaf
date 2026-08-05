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
