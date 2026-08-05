// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package rules

import (
	"github.com/gsoultan/gwaf/internal/budget"
	"github.com/gsoultan/gwaf/types"
)

// Match describes where inside an evaluated value an operator matched.
//
// The span makes every decision explainable: a block carries the exact bytes
// that caused it, which is what turns false-positive triage from archaeology
// into a diff. An operator that cannot report a span should report the whole
// value rather than a zero span.
type Match struct {
	// Span locates the match within the value passed to Eval, not within the
	// original request buffer. The engine translates it for reporting.
	Span types.Span
}

// WholeValue returns a Match covering all of value.
func WholeValue(value []byte) Match {
	return Match{Span: types.SpanOf(0, len(value))}
}

// EvalContext carries the context an operator may need beyond the value itself.
//
// It is passed by pointer and is owned by the engine; operators must not retain
// it or any slice reachable from it beyond the Eval call, because the backing
// arena is recycled when the transaction ends.
type EvalContext struct {
	// Target is the collection the value came from.
	Target types.Target

	// Key is the specific key within a keyed collection — a header name, an
	// argument name — or empty for unkeyed targets.
	Key string
}

// Operator decides whether a transformed value matches.
//
// Operator is one of the five public extension points (docs/RULES.md §4). It is
// frozen under semver at v1.0 because third parties implement it, so changes to
// this signature are a major design decision rather than a refactor.
//
// Implementations must be safe for concurrent use: one Operator instance is
// shared by every transaction evaluating the rule that holds it.
type Operator interface {
	// Name returns a stable identifier, used in compile reports, explain
	// output, and to reference the operator from declarative rule formats.
	Name() string

	// Eval reports whether value matches.
	Eval(ctx *EvalContext, value []byte) (Match, bool)

	// Literals returns the byte sequences that must be present for this
	// operator to have any chance of matching, and whether that requirement is
	// exact.
	//
	// When the bool is true the engine may skip evaluation entirely if none of
	// the literals appear in the input, which is what keeps benign traffic off
	// the evaluation path. When it is false the rule is unconditional and runs
	// on every request; the compiler reports those and `gwaf lint` budgets
	// them, so the cost is visible at build time rather than in a latency
	// graph. See docs/RULES.md §5.
	//
	// Returning true with literals that are not genuinely required is the one
	// way to make the engine silently miss matches. It is an assertion, and it
	// is the caller's to justify.
	Literals() ([]string, bool)

	// Cost returns the fuel charged per evaluation, excluding any per-byte
	// component the engine adds. It must not depend on the input.
	Cost() budget.Fuel
}
