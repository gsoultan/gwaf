// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package engine evaluates a compiled ruleset against transaction data.
//
// The loop is inverted relative to a conventional WAF. Instead of
//
//	for each rule { for each target { for each value { transform; match } } }
//
// which is O(rules × values) transform-and-match operations, the engine walks
// each value once per distinct transform chain, scans the transformed bytes
// through that chain's prefilter to obtain a candidate rule set, and evaluates
// only those. On benign traffic the candidate set is empty and no operator runs.
//
// Grouping by transform chain is what makes this correct as well as fast: an
// operator declares its literals in terms of the value it will actually see, so
// the prefilter has to scan the same normalized bytes the operator will. See
// docs/CONCEPT.md §1 and docs/PERFORMANCE.md §1.
package engine

import (
	"github.com/gsoultan/gwaf/internal/bitset"
	"github.com/gsoultan/gwaf/internal/budget"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Value is one target value presented to the engine.
//
// Data points into a buffer the caller owns for the duration of Eval. The
// engine does not retain it.
type Value struct {
	Target types.Target
	Key    string
	Data   []byte
}

// Hit records one rule match.
type Hit struct {
	Rule    *rules.CompiledRule
	Outcome rules.Outcome
	Target  types.Target
	Key     string
	// Match locates the matching bytes within the transformed value.
	Match rules.Match
	// Transformed reports whether Match refers to transformed rather than raw
	// bytes. Explain output has to say which, or someone reading the audit log
	// cannot reproduce the match.
	Transformed bool
}

// Result is the outcome of evaluating one phase.
type Result struct {
	// Hits are the matches, in evaluation order.
	Hits []Hit

	// Score is the accumulated anomaly score from scoring actions.
	Score int

	// Terminal is set when a rule demanded an immediate outcome.
	Terminal bool

	// TerminalOutcome is meaningful only when Terminal is set.
	TerminalOutcome rules.Outcome

	// TerminalRule identifies the rule that ended evaluation.
	TerminalRule *rules.CompiledRule

	// Exhausted reports that the fuel budget ran out. The caller must apply its
	// configured fail mode: the ruleset was only partially evaluated, and a
	// decision derived from partial evaluation is indistinguishable from a
	// bypass.
	Exhausted bool

	// RulesEvaluated counts operator invocations. It is the leading indicator
	// for latency and is asserted in tests and benchmarks: if it drifts above
	// zero on benign traffic, the prefilter has stopped working.
	RulesEvaluated int
}

// Reset clears r for reuse while keeping its capacity.
func (r *Result) Reset() {
	r.Hits = r.Hits[:0]
	r.Score = 0
	r.Terminal = false
	r.TerminalOutcome = rules.Outcome{}
	r.TerminalRule = nil
	r.Exhausted = false
	r.RulesEvaluated = 0
}

// Evaluator holds the per-transaction scratch state for evaluation.
//
// An Evaluator is owned by exactly one goroutine and is reused across
// transactions. Its buffers are retained between uses, which is what keeps
// steady-state allocation at zero.
type Evaluator struct {
	candidates bitset.Set

	// scratch and alt are the transform ping-pong buffers: a chain alternates
	// between them rather than allocating per step.
	scratch []byte
	alt     []byte

	ctx rules.EvalContext
}

// NewEvaluator returns an Evaluator sized for a ruleset.
func NewEvaluator(rs *rules.Ruleset) *Evaluator {
	e := &Evaluator{}
	e.sizeFor(rs)
	return e
}

// sizeFor grows the candidate set to cover the largest chain group in rs.
func (e *Evaluator) sizeFor(rs *rules.Ruleset) {
	maxRules := 0
	for p := types.PhaseRequestHeaders; p <= types.PhaseLogging; p++ {
		maxRules = max(maxRules, rs.MaxGroupRules(p))
	}
	e.candidates.Grow(maxRules)
}

// Eval runs one phase of rs over values and accumulates into out.
//
// Fuel is charged for every unit of work: bytes scanned, bytes transformed,
// rule dispatch, and operator cost. When the meter is exhausted evaluation
// stops and out.Exhausted is set; the caller decides what that means.
func (e *Evaluator) Eval(
	rs *rules.Ruleset,
	phase types.Phase,
	values []Value,
	meter *budget.Meter,
	out *Result,
) {
	groups := rs.Groups(phase)
	if len(groups) == 0 {
		return
	}
	e.sizeFor(rs)

	for i := range values {
		v := &values[i]

		for _, g := range groups {
			// The chain is applied once here and shared by every rule in the
			// group — the common-subexpression elimination from
			// docs/CONCEPT.md §1.3. A chain that changes nothing returns the
			// input slice, so already-normal traffic performs no copy at all.
			data, transformed, ok := e.applyChain(g.Transforms, v.Data, meter)
			if !ok {
				out.Exhausted = true
				return
			}

			e.candidates.Reset()
			if g.Automaton != nil && !g.Automaton.Empty() {
				n := g.Automaton.Scan(data, &e.candidates)
				if !meter.Spend(budget.Fuel(n) * budget.CostPerByteScanned) {
					out.Exhausted = true
					return
				}
			}

			// Unconditional rules have no literals to key on and must run for
			// every value. Their cost is reported at compile time, so it is a
			// budgeted expense rather than a surprise.
			for _, idx := range g.Unconditional {
				if !e.evalRule(g.Rules[idx], v, data, transformed, meter, out) {
					return
				}
				if out.Terminal {
					return
				}
			}

			stop := false
			e.candidates.All(func(idx int) bool {
				if idx >= len(g.Rules) {
					// Defensive: a stale automaton could name an index outside
					// the current group. Skipping is safe — the rule simply is
					// not treated as a candidate — and it must never panic on
					// the request path.
					return true
				}
				cr := g.Rules[idx]
				if cr.Unconditional() {
					return true // already evaluated above
				}
				if !e.evalRule(cr, v, data, transformed, meter, out) {
					stop = true
					return false
				}
				if out.Terminal {
					stop = true
					return false
				}
				return true
			})
			if stop {
				return
			}
		}
	}
}

// evalRule applies one rule to one already-transformed value. It reports
// whether evaluation may continue; false means the fuel budget was exhausted.
func (e *Evaluator) evalRule(
	cr *rules.CompiledRule,
	v *Value,
	data []byte,
	transformed bool,
	meter *budget.Meter,
	out *Result,
) bool {
	r := cr.Rule

	if !targetMatches(r.Targets, v) {
		return true
	}

	if !meter.Spend(budget.CostRuleDispatch) {
		out.Exhausted = true
		return false
	}
	if !meter.Spend(r.Op.Cost()) {
		out.Exhausted = true
		return false
	}

	e.ctx.Target = v.Target
	e.ctx.Key = v.Key

	out.RulesEvaluated++
	m, hit := r.Op.Eval(&e.ctx, data)
	if !hit {
		return true
	}

	for _, action := range cr.Actions() {
		outcome := action.Run(&e.ctx, m)
		out.Hits = append(out.Hits, Hit{
			Rule:        cr,
			Outcome:     outcome,
			Target:      v.Target,
			Key:         v.Key,
			Match:       m,
			Transformed: transformed,
		})

		if outcome.Kind == rules.ActionScore {
			score := outcome.Score
			if score == 0 {
				score = r.Severity.Score()
			}
			out.Score += score
		}

		if outcome.Terminal() {
			out.Terminal = true
			out.TerminalOutcome = outcome
			out.TerminalRule = cr
			return true
		}
	}
	return true
}

// applyChain runs a transform chain over src.
//
// Buffers ping-pong between scratch and alt rather than allocating per step,
// and a transform reporting no change is skipped entirely — the common case for
// already-normal traffic, and the reason a benign request performs no copies.
func (e *Evaluator) applyChain(chain []rules.Transform, src []byte, meter *budget.Meter) ([]byte, bool, bool) {
	if len(chain) == 0 {
		return src, false, true
	}

	cur := src
	transformed := false
	useScratch := true

	for _, t := range chain {
		need := t.MaxOutputLen(len(cur))

		var dst []byte
		if useScratch {
			e.scratch = growTo(e.scratch, need)
			dst = e.scratch
		} else {
			e.alt = growTo(e.alt, need)
			dst = e.alt
		}

		next, changed := t.Apply(dst[:0], cur)
		if !changed {
			continue
		}
		if !meter.Spend(budget.Fuel(len(next)) * budget.CostPerByteTransformed) {
			return nil, false, false
		}
		cur = next
		transformed = true
		useScratch = !useScratch
	}
	return cur, transformed, true
}

// growTo returns a buffer with at least n capacity, reusing b when possible.
func growTo(b []byte, n int) []byte {
	if cap(b) >= n {
		return b[:cap(b)]
	}
	return make([]byte, n)
}

// targetMatches reports whether a rule's target list selects this value.
func targetMatches(targets []types.Target, v *Value) bool {
	for _, t := range targets {
		if t.Kind != v.Target.Kind {
			continue
		}
		if t.Matches(v.Key) {
			return true
		}
	}
	return false
}
