// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package rules defines how detection rules are authored, validated, and
// compiled into an executable plan.
//
// The canonical authoring form is a plain struct literal rather than a fluent
// builder. Structs serialize, diff in code review, and can be generated;
// builders do none of those well and add a state machine to get wrong. It is
// also what keeps the Go and declarative frontends isomorphic rather than
// merely similar — both produce the same Rule values and therefore the same
// compiled plan. See docs/RULES.md §2 and §3.
package rules

import (
	"github.com/gsoultan/gwaf/types"
)

// Rule is one detection rule.
//
// A Rule is immutable once compiled and is shared across every transaction that
// evaluates it, so it and everything reachable from it must be concurrent-safe.
type Rule struct {
	// ID is the stable public identifier. User rules must be in the range
	// types.UserMin..types.UserMax; the compiler rejects collisions and rules
	// placed in reserved ranges.
	ID types.RuleID

	// Phase selects when the rule runs. Zero is invalid.
	Phase types.Phase

	// Targets selects the values to inspect. At least one is required: a rule
	// with no targets inspects nothing and would silently never match.
	Targets []types.Target

	// Transforms normalize each value before Op sees it, applied in order.
	Transforms []Transform

	// Op decides whether a transformed value matches. Required.
	Op Operator

	// Actions run on a match, in order. Empty means Score, which is the safe
	// default: a rule that matches and does nothing is almost always an
	// authoring mistake, and scoring makes it visible without blocking.
	Actions []Action

	// Severity describes the impact of what this rule detects.
	Severity types.Severity

	// Confidence states how likely a match is a true positive.
	//
	// This is not an opinion: `gwaf calibrate` measures each rule's actual
	// false-positive rate against the benign corpus and fails the build when
	// the measurement exceeds the declared tier's ceiling. See
	// docs/CONCEPT.md §8.
	Confidence types.Confidence

	// Msg is a human-readable description shown in decisions and audit output.
	Msg string

	// Tags group rules for policy selection and exceptions.
	Tags []string
}

// Set is an ordered collection of rules.
//
// Order in the source does not affect evaluation order — the compiler sorts by
// (phase, ID) so that a decision is reproducible regardless of how rules were
// assembled. See docs/RULES.md §6.
type Set []Rule

// Concat returns the concatenation of sets. It is a convenience for assembling
// a ruleset from a core set plus application rules.
func Concat(sets ...Set) Set {
	n := 0
	for _, s := range sets {
		n += len(s)
	}
	out := make(Set, 0, n)
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// HasTag reports whether r carries tag.
func (r *Rule) HasTag(tag string) bool {
	for _, t := range r.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// effectiveActions returns r.Actions, defaulting to Score when unset.
func (r *Rule) effectiveActions() []Action {
	if len(r.Actions) == 0 {
		return defaultActions
	}
	return r.Actions
}

var defaultActions = []Action{Score}
