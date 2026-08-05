// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Verdict is what a transaction concluded.
type Verdict uint8

const (
	// VerdictAllow permits the request.
	VerdictAllow Verdict = iota

	// VerdictBlock rejects the request.
	VerdictBlock
)

// String implements fmt.Stringer.
func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "allow"
	case VerdictBlock:
		return "block"
	default:
		return "invalid"
	}
}

// Reason explains why a Decision reached its verdict.
type Reason uint8

const (
	// ReasonNoMatch means nothing matched.
	ReasonNoMatch Reason = iota

	// ReasonRule means a rule demanded a terminal outcome.
	ReasonRule

	// ReasonThreshold means the accumulated anomaly score crossed the policy
	// threshold.
	ReasonThreshold

	// ReasonBudget means the fuel budget was exhausted and the configured fail
	// mode decided the outcome. The ruleset was only partially evaluated, so
	// this verdict carries less information than the others — it says what the
	// deployment chose to do about not knowing, not that the request was clean.
	ReasonBudget

	// ReasonLimit means a hard input limit was exceeded before rules ran.
	ReasonLimit
)

// String implements fmt.Stringer.
func (r Reason) String() string {
	switch r {
	case ReasonNoMatch:
		return "no_match"
	case ReasonRule:
		return "rule"
	case ReasonThreshold:
		return "threshold"
	case ReasonBudget:
		return "budget_exhausted"
	case ReasonLimit:
		return "limit_exceeded"
	default:
		return "invalid"
	}
}

// Decision is the outcome of evaluating a phase.
//
// It is a value type rather than a nillable pointer: callers write
// `if d.Blocked()` with no nil check and no type assertion. Every decision is
// explainable — it carries the rule that caused it, the matched bytes, and the
// score that produced it, because a block nobody can explain is a block that
// gets disabled.
type Decision struct {
	verdict Verdict
	reason  Reason
	status  int
	score   int
	rule    *rules.CompiledRule
	hit     *rules.Match
	target  types.Target
	key     string

	// rulesEvaluated is the leading indicator for latency: on benign traffic it
	// must be zero, and a drift above zero means the prefilter has stopped
	// doing its job.
	rulesEvaluated int
}

// Blocked reports whether the request should be rejected.
func (d Decision) Blocked() bool { return d.verdict == VerdictBlock }

// Allowed reports whether the request may proceed.
func (d Decision) Allowed() bool { return d.verdict == VerdictAllow }

// Verdict returns the outcome.
func (d Decision) Verdict() Verdict { return d.verdict }

// Reason returns why the verdict was reached.
func (d Decision) Reason() Reason { return d.reason }

// Status returns the HTTP status to respond with when blocked. It is zero when
// the decision did not specify one and the caller's default applies.
func (d Decision) Status() int { return d.status }

// Score returns the accumulated anomaly score.
func (d Decision) Score() int { return d.score }

// RuleID returns the rule responsible, or zero when no single rule was.
func (d Decision) RuleID() types.RuleID {
	if d.rule == nil {
		return 0
	}
	return d.rule.Rule.ID
}

// Message returns the responsible rule's human-readable description.
func (d Decision) Message() string {
	if d.rule == nil {
		return ""
	}
	return d.rule.Rule.Msg
}

// Severity returns the responsible rule's severity.
func (d Decision) Severity() types.Severity {
	if d.rule == nil {
		return types.SeverityNotice
	}
	return d.rule.Rule.Severity
}

// Confidence returns the responsible rule's confidence tier.
func (d Decision) Confidence() types.Confidence {
	if d.rule == nil {
		return types.Heuristic
	}
	return d.rule.Rule.Confidence
}

// Target returns the collection the match came from.
func (d Decision) Target() types.Target { return d.target }

// Key returns the specific key within the matched collection, if any.
func (d Decision) Key() string { return d.key }

// MatchedSpan returns the byte range within the evaluated value that matched.
// The second result is false when the decision was not caused by a rule match.
func (d Decision) MatchedSpan() (types.Span, bool) {
	if d.hit == nil {
		return types.Span{}, false
	}
	return d.hit.Span, true
}

// RulesEvaluated returns how many operators actually ran.
func (d Decision) RulesEvaluated() int { return d.rulesEvaluated }

// allow returns a permitting decision.
func allow(reason Reason, score, evaluated int) Decision {
	return Decision{
		verdict:        VerdictAllow,
		reason:         reason,
		score:          score,
		rulesEvaluated: evaluated,
	}
}
