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
	"github.com/gsoultan/gwaf/internal/interpret"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Value is one target value presented to the engine.
//
// Data points into a buffer the caller owns for the duration of Eval. The
// engine does not retain it.
type Value struct {
	Target types.Target

	// Key is the name within a keyed collection, as bytes. It is not a string
	// so that body fields, which arrive from the parser as bytes, never need a
	// per-field conversion on the request path.
	Key  []byte
	Data []byte

	// Inert marks a value that passed schema validation for a type whose
	// character set cannot express an injection payload — an integer, a UUID, a
	// value drawn from a declared enum.
	//
	// Such a value is skipped entirely: no ambiguity detection, no
	// normalization, no prefilter scan, no rule evaluation. This is not a
	// heuristic. A value that validates as an integer contains only digits and
	// a sign, so no content rule can match it, and running them would be work
	// with a provably empty result. See docs/CONCEPT.md §6.
	Inert bool
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

	// Reading names the ambiguity class whose interpretation produced this
	// match, or zero when it matched the value as sent. A non-zero value means
	// the payload was only visible under an alternative decoding, which is the
	// single most useful fact in the audit record for that request.
	Reading interpret.Class

	// Matched is a copy of the bytes Match points at.
	//
	// Copied rather than sliced, because the transformed buffer is recycled
	// with the transaction and an explanation that dangles into a reused buffer
	// reports a *different* request's bytes with total confidence. The cost is
	// one small allocation per hit, and a hit means an attack was found -- the
	// path where an allocation is affordable, unlike the benign one.
	Matched []byte
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

	// Undecidable reports that the value could not be fully analysed — too
	// many plausible readings to enumerate. It is distinct from Exhausted: the
	// budget was fine, the input was ambiguous beyond the point where any
	// verdict would be meaningful. The caller applies its fail mode.
	Undecidable bool

	// UndecidableReason explains Undecidable, for the audit record.
	UndecidableReason string

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
	r.Undecidable = false
	r.UndecidableReason = ""
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

	// readings holds the plausible interpretations of the value under
	// evaluation. It owns reusable buffers, so enumerating alternatives costs
	// no allocation after warm-up.
	readings interpret.Set

	ctx rules.EvalContext

	// stages applies transform chains, reusing the prefix shared with the
	// previous group's chain. See stages.go.
	stages stages
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

		// A schema-validated value of a constrained type cannot carry a
		// payload, so the entire pipeline is skipped for it. On a
		// well-specified API this removes most of the per-request work, and it
		// removes it soundly rather than probabilistically.
		if v.Inert {
			continue
		}

		// Enumerate the plausible readings of this value once, before the chain
		// groups, because ambiguity is a property of the value rather than of
		// any rule's normalization. A value with no ambiguity yields exactly one
		// reading and costs a single detection pass, so benign traffic is
		// unaffected; only genuinely ambiguous input pays for alternatives.
		classes := interpret.Detect(v.Data)
		e.readings.Build(v.Data, classes)
		if !meter.Spend(budget.Fuel(len(v.Data)) * budget.CostPerByteScanned) {
			out.Exhausted = true
			return
		}

		// A value with more plausible readings than the cap allows has not been
		// shown to be clean, so the caller must treat it as undecidable rather
		// than allow it on the strength of an incomplete enumeration.
		if e.readings.Truncated() {
			out.Undecidable = true
			out.UndecidableReason = "ambiguity exceeded the reading limit"
			return
		}

		// Readings outside, groups inside. Both orders evaluate exactly the same
		// (rule, reading) pairs — detection is the union over readings either
		// way — but this one lets a group resume from the previous group's
		// intermediate result, because reuse is only valid within a single
		// reading's bytes.
		//
		// Every reading is evaluated. An extra reading can cost work but can
		// never cost coverage; picking one and hoping the origin agrees is the
		// CVE-2026-21876 failure mode.
		for r := range e.readings.Len() {
			reading := e.readings.At(r)
			e.stages.reset(reading.Bytes)

			for _, g := range groups {
				// The chain is applied once per reading and shared by every
				// rule in the group — the common-subexpression elimination
				// from docs/CONCEPT.md §1.3 — and now also shared *across*
				// groups whose chains share a prefix. A chain that changes
				// nothing returns the input slice, so already-normal traffic
				// still performs no copy at all.
				data, transformed, ok := e.stages.apply(g.Transforms, meter)
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

				// Unconditional rules have no literals to key on and must run
				// for every value. Their cost is reported at compile time, so
				// it is a budgeted expense rather than a surprise. They run
				// only against the verbatim reading: an operator that inspects
				// everything does not gain from alternatives, and running it
				// per reading would multiply the one cost the compile report
				// warns about.
				if r == 0 {
					for _, idx := range g.Unconditional {
						if !e.evalRule(g.Rules[idx], v, data, transformed, reading.Class, meter, out) {
							return
						}
						if out.Terminal {
							return
						}
					}
				}

				stop := false
				e.candidates.All(func(idx int) bool {
					if idx >= len(g.Rules) {
						// Defensive: a stale automaton could name an index
						// outside the current group. Skipping is safe — the
						// rule simply is not treated as a candidate — and it
						// must never panic on the request path.
						return true
					}
					cr := g.Rules[idx]
					if cr.Unconditional() {
						return true // already evaluated above
					}
					if !e.evalRule(cr, v, data, transformed, reading.Class, meter, out) {
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
}

// evalRule applies one rule to one already-transformed value. It reports
// whether evaluation may continue; false means the fuel budget was exhausted.
func (e *Evaluator) evalRule(
	cr *rules.CompiledRule,
	v *Value,
	data []byte,
	transformed bool,
	reading interpret.Class,
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
	// The key is materialised as a string only for the operator's context,
	// which is reached solely for candidate rules -- rare on real traffic.
	e.ctx.Key = string(v.Key)

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
			Key:         string(v.Key),
			Match:       m,
			Transformed: transformed,
			Reading:     reading,
			Matched:     matchedBytes(data, m),
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
		if t.MatchesBytes(v.Key) {
			return true
		}
	}
	return false
}

// matchedBytes copies the span a match points at, bounded so a malformed span
// cannot read past the value.
func matchedBytes(data []byte, m rules.Match) []byte {
	if m.Span.Len == 0 {
		return nil
	}
	off, end := int(m.Span.Off), int(m.Span.Off)+int(m.Span.Len)
	if off < 0 || off > len(data) {
		return nil
	}
	if end > len(data) {
		end = len(data)
	}
	return append([]byte(nil), data[off:end]...)
}
