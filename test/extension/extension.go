// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package extension implements gwaf's public extension points from outside the
// gwaf module path, which is the only place the claim can be tested.
//
// # Why this module exists and why its path is deliberately foreign
//
// docs/RULES.md §4 names five extension points and CLAUDE.md §4 calls them "the
// most expensive API surface in the project — third parties implement them, so
// post-v1.0 they are frozen hard."
//
// One of them could not be implemented at all. `Operator.Cost()` returned
// `budget.Fuel` from `internal/budget`, and Go's internal-package rule is keyed
// on *import path*: anything under `github.com/gsoultan/gwaf/...` may import it,
// and nothing else may. So every first-party detector compiled, the SecLang
// regex operator compiled, and a vendor at their own module path got:
//
//	myOp does not implement rules.Operator (missing method Cost)
//	use of internal package .../internal/budget not allowed
//
// A broken extension point that all the in-tree implementations satisfy is
// invisible to any test living in the tree. That is why this module declares
// itself as `example.com/gwafvendor` — it stands where a vendor stands, so the
// compiler enforces what a comment cannot.
//
// It is a conformance fixture, not example code. `examples/` is where an
// embedder should look.
package extension

import (
	"iter"
	"strings"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// ---- Operator ---------------------------------------------------------------

// Operator is a third-party operator: the interface that was impossible to
// implement, exercised in full.
type Operator struct {
	needle string
}

// NewOperator returns an operator matching a literal, case-insensitively.
func NewOperator(needle string) rules.Operator {
	return &Operator{needle: strings.ToLower(needle)}
}

func (o *Operator) Name() string { return "vendor_contains" }

func (o *Operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	i := strings.Index(strings.ToLower(string(value)), o.needle)
	if i < 0 {
		return rules.Match{}, false
	}
	// A rule that cannot produce a matched span is not a rule (docs/RULES.md
	// §1), so a third-party operator has to be able to report one.
	return rules.Match{Span: types.SpanOf(i, len(o.needle))}, true
}

func (o *Operator) Literals() ([]string, bool) { return []string{o.needle}, true }

// Cost is the method that could not be written from here. It needs the fuel type
// *and* a cost constant to price itself in the same units the engine uses — a
// number picked out of the air would make the DoS bound arithmetic wrong in a way
// nothing would catch.
func (o *Operator) Cost() types.Fuel { return types.CostLiteralMatch * 2 }

// ---- Transform --------------------------------------------------------------

// Transform is a third-party transform. It reverses the value, which is useless
// as normalization and ideal as a fixture: the output is a deterministic
// function of the input with the same length, so the engine's buffer accounting
// is exercised without the test asserting anything about detection.
type Transform struct{}

func (Transform) Name() string { return "vendor_reverse" }

func (Transform) Apply(dst, src []byte) ([]byte, bool) {
	if len(src) == 0 {
		return src, false
	}
	dst = dst[:0]
	for i := len(src) - 1; i >= 0; i-- {
		dst = append(dst, src[i])
	}
	return dst, true
}

func (Transform) MaxOutputLen(n int) int { return n }

// ---- Action -----------------------------------------------------------------

// Action is a third-party action that counts what it saw and then blocks.
//
// Counting is the point: an embedder's action is where metrics and audit get
// wired, so it has to be able to observe a match and still return an outcome.
type Action struct{ Seen *int }

func (a Action) Name() string { return "vendor_count_and_block" }

func (a Action) Run(_ *rules.EvalContext, _ rules.Match) rules.Outcome {
	if a.Seen != nil {
		*a.Seen++
	}
	return rules.Outcome{Kind: rules.ActionBlock}
}

// Compile-time assertions. These are the whole point of the module: if any of
// the three interfaces grows a method returning an unexported type, this stops
// compiling and CI says so.
var (
	_ rules.Operator  = (*Operator)(nil)
	_ rules.Transform = Transform{}
	_ rules.Action    = Action{}
)

// ---- Resolver ---------------------------------------------------------------

// Resolver is a third-party resolver: the mechanism by which a signal gwaf
// deliberately does not compute reaches a rule that wants to match on it.
//
// This one stands in for a reputation service. The interesting property is not
// what it returns but that it counts its own calls: the engine must not invoke
// it when no rule reads it, because a signal is usually out of gwaf's scope
// precisely because obtaining it is expensive.
type Resolver struct {
	Score string
	ASN   string
	Calls *int
}

func (r Resolver) Name() string { return "reputation" }

func (r Resolver) Resolve() iter.Seq2[string, []byte] {
	return func(yield func(string, []byte) bool) {
		if r.Calls != nil {
			*r.Calls++
		}
		if !yield("score", []byte(r.Score)) {
			return
		}
		yield("asn", []byte(r.ASN))
	}
}

var _ rules.Resolver = Resolver{}
