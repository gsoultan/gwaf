// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package rules_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

// valid returns a minimal well-formed rule, for mutating in tests.
func valid(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:         id,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         op.Contains("needle"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityError,
		Confidence: types.High,
		Msg:        "test",
	}
}

func TestCompileValid(t *testing.T) {
	rs, err := rules.Compile(rules.Set{valid(1_000_001)}, rules.Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if rs.Len() != 1 {
		t.Errorf("Len() = %d, want 1", rs.Len())
	}
	if _, ok := rs.ByID(1_000_001); !ok {
		t.Error("ByID did not find the compiled rule")
	}
}

func TestCompileRejectsInvalidRules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*rules.Rule)
		want   error
	}{
		{"zero id", func(r *rules.Rule) { r.ID = 0 }, rules.ErrInvalidRule},
		{"invalid phase", func(r *rules.Rule) { r.Phase = 0 }, rules.ErrInvalidRule},
		{"no targets", func(r *rules.Rule) { r.Targets = nil }, rules.ErrInvalidRule},
		{"nil operator", func(r *rules.Rule) { r.Op = nil }, rules.ErrInvalidRule},
		{"invalid target kind", func(r *rules.Rule) {
			r.Targets = []types.Target{{Kind: types.TargetInvalid}}
		}, rules.ErrInvalidRule},
		{"nil transform", func(r *rules.Rule) {
			r.Transforms = []rules.Transform{nil}
		}, rules.ErrInvalidRule},
		{"nil action", func(r *rules.Rule) {
			r.Actions = []rules.Action{nil}
		}, rules.ErrInvalidRule},
		{"confidence out of range", func(r *rules.Rule) {
			r.Confidence = types.Confidence(99)
		}, rules.ErrInvalidRule},
		{"severity out of range", func(r *rules.Rule) {
			r.Severity = types.Severity(99)
		}, rules.ErrInvalidRule},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := valid(1_000_001)
			tt.mutate(&r)

			_, err := rules.Compile(rules.Set{r}, rules.Options{})
			if err == nil {
				t.Fatal("Compile accepted an invalid rule")
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestPhaseTargetMismatchRejected covers the check that caught a real modelling
// error in the core ruleset: a rule reading data its phase cannot have yet
// would silently never match, which is worse than failing to compile.
func TestPhaseTargetMismatchRejected(t *testing.T) {
	r := valid(1_000_001)
	r.Phase = types.PhaseRequestHeaders
	r.Targets = []types.Target{{Kind: types.TargetRequestBody}}

	_, err := rules.Compile(rules.Set{r}, rules.Options{})
	if err == nil {
		t.Fatal("Compile accepted a phase/target mismatch")
	}
	if !strings.Contains(err.Error(), "not available until phase") {
		t.Errorf("error does not explain the mismatch: %v", err)
	}
}

func TestDuplicateIDRejected(t *testing.T) {
	_, err := rules.Compile(rules.Set{valid(1_000_001), valid(1_000_001)}, rules.Options{})
	if !errors.Is(err, rules.ErrDuplicateID) {
		t.Errorf("error = %v, want ErrDuplicateID", err)
	}
}

func TestReservedIDRejectedForUserRules(t *testing.T) {
	// The CRS range must stay verbatim so existing tuning guides keep applying.
	_, err := rules.Compile(rules.Set{valid(942100)}, rules.Options{UserRulesOnly: true})
	if !errors.Is(err, rules.ErrReservedID) {
		t.Errorf("error = %v, want ErrReservedID", err)
	}

	// The same rule compiles when reserved ranges are permitted, which is how
	// the core ruleset and the CRS adapter load.
	if _, err := rules.Compile(rules.Set{valid(942100)}, rules.Options{}); err != nil {
		t.Errorf("Compile rejected a reserved ID without UserRulesOnly: %v", err)
	}
}

// TestAllErrorsReported checks that Compile does not stop at the first problem.
// Fixing a ruleset one error per run is a poor enough experience that people
// stop running the compiler.
func TestAllErrorsReported(t *testing.T) {
	bad := rules.Set{}
	for i := range 5 {
		r := valid(types.UserMin + types.RuleID(i))
		r.Op = nil
		bad = append(bad, r)
	}

	_, err := rules.Compile(bad, rules.Options{})
	if err == nil {
		t.Fatal("Compile accepted invalid rules")
	}
	msg := err.Error()
	for i := range 5 {
		id := types.UserMin + types.RuleID(i)
		if !strings.Contains(msg, id.String()) {
			t.Errorf("error does not mention rule %s", id)
		}
	}
}

// TestEvaluationOrderIsDeterministic verifies rules sort by (phase, ID)
// regardless of source order. Without it, a decision would depend on how the
// ruleset happened to be assembled, and audit logs could not be trusted.
func TestEvaluationOrderIsDeterministic(t *testing.T) {
	shuffled := rules.Set{
		valid(1_000_003), valid(1_000_001), valid(1_000_002),
	}
	shuffled[0].Phase = types.PhaseRequestBody
	shuffled[0].Targets = []types.Target{{Kind: types.TargetRequestBody}}

	rs, err := rules.Compile(shuffled, rules.Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	got := rs.PhaseRules(types.PhaseRequestHeaders)
	if len(got) != 2 {
		t.Fatalf("phase 1 has %d rules, want 2", len(got))
	}
	if got[0].Rule.ID != 1_000_001 || got[1].Rule.ID != 1_000_002 {
		t.Errorf("order = [%s %s], want [1000001 1000002]",
			got[0].Rule.ID, got[1].Rule.ID)
	}
}

// TestChainGrouping is the correctness property behind prefiltering: rules
// sharing a transform chain must land in one group, so the chain is applied
// once per value and the automaton scans the same bytes the operator will.
func TestChainGrouping(t *testing.T) {
	chainA := []rules.Transform{transform.Lowercase}
	chainB := []rules.Transform{transform.Lowercase, transform.RemoveWhitespace}

	set := rules.Set{}
	for i, chain := range [][]rules.Transform{chainA, chainA, chainA, chainB, chainB} {
		r := valid(types.UserMin + types.RuleID(i))
		r.Transforms = chain
		set = append(set, r)
	}

	rs, err := rules.Compile(set, rules.Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	groups := rs.Groups(types.PhaseRequestHeaders)
	if len(groups) != 2 {
		t.Fatalf("got %d chain groups, want 2", len(groups))
	}
	if rs.Report().ChainGroups != 2 {
		t.Errorf("Report().ChainGroups = %d, want 2", rs.Report().ChainGroups)
	}

	sizes := []int{len(groups[0].Rules), len(groups[1].Rules)}
	if !(sizes[0] == 3 && sizes[1] == 2) && !(sizes[0] == 2 && sizes[1] == 3) {
		t.Errorf("group sizes = %v, want 3 and 2", sizes)
	}
}

func TestUnconditionalReported(t *testing.T) {
	r := valid(1_000_001)
	r.Op = op.Func("nolit", func([]byte) bool { return false })

	rs, err := rules.Compile(rules.Set{r}, rules.Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	rep := rs.Report()
	if rep.Prefiltered != 0 {
		t.Errorf("Prefiltered = %d, want 0", rep.Prefiltered)
	}
	if len(rep.Unconditional) != 1 {
		t.Fatalf("Unconditional = %d, want 1", len(rep.Unconditional))
	}
	u := rep.Unconditional[0]
	if u.ID != 1_000_001 || u.Reason == "" || u.Operator == "" {
		t.Errorf("incomplete unconditional report: %+v", u)
	}
}

func TestEmptyRulesetCompiles(t *testing.T) {
	rs, err := rules.Compile(nil, rules.Options{})
	if err != nil {
		t.Fatalf("Compile(nil): %v", err)
	}
	if rs.Len() != 0 {
		t.Errorf("Len() = %d, want 0", rs.Len())
	}
	if got := rs.PhaseRules(types.PhaseRequestHeaders); len(got) != 0 {
		t.Errorf("PhaseRules returned %d rules", len(got))
	}
	// An invalid phase must be handled, not panic.
	if got := rs.Groups(types.Phase(0)); got != nil {
		t.Error("Groups(invalid) returned a non-nil slice")
	}
}

func TestDefaultActionIsScore(t *testing.T) {
	r := valid(1_000_001)
	r.Actions = nil

	rs, err := rules.Compile(rules.Set{r}, rules.Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cr, _ := rs.ByID(1_000_001)
	actions := cr.Actions()
	if len(actions) != 1 || actions[0].Name() != "score" {
		t.Errorf("default actions = %v, want [score]", actions)
	}
}
