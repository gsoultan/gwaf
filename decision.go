// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/gsoultan/gwaf/internal/interpret"
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

	// ReasonSchema means the request fell outside the declared API description.
	//
	// This is positive security rather than signature matching: the request was
	// rejected for not being something the API accepts, without any claim about
	// what it was trying to do.
	ReasonSchema

	// ReasonDesync means the request's framing was ambiguous: Content-Length
	// and Transfer-Encoding disagreed, or one of them was malformed in a way
	// two parsers resolve differently.
	//
	// This is request smuggling, and it is the one reason FailOpen does not
	// soften: an ambiguously framed request is potentially two requests, the
	// second of which no firewall has seen.
	ReasonDesync

	// ReasonUndecidable means the input had more plausible interpretations than
	// gwaf will enumerate, so no verdict about it would be meaningful.
	//
	// This is deliberately distinct from ReasonNoMatch. A value too ambiguous
	// to analyse has not been shown to be clean, and reporting it as clean is
	// exactly the assumption that CVE-2026-21876 exploited.
	ReasonUndecidable
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
	case ReasonSchema:
		return "schema_violation"
	case ReasonDesync:
		return "framing_ambiguous"
	case ReasonUndecidable:
		return "undecidable"
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
	reading interpret.Class
	detail  string

	// path and matchedBytes exist for Explain, which needs to name the route an
	// exception should be scoped to and to show the bytes that matched.
	path         string
	matchedBytes []byte

	// derivedFrom is the authored rule this one was generated from, so Explain
	// can suggest an exception that covers both phases rather than one.
	derivedFrom types.RuleID

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

// Interpretation names the alternative decoding under which the match was
// found, or "none" when it matched the value exactly as sent.
//
// A non-"none" value is the most useful line in the audit record for that
// request: it says the payload was invisible in the bytes on the wire and only
// appeared once the value was read the way the origin would read it.
func (d Decision) Interpretation() string { return d.reading.String() }

// Detail returns extra context for decisions that have no responsible rule,
// such as why the input was undecidable. It is empty otherwise.
func (d Decision) Detail() string { return d.detail }

// RulesEvaluated returns how many operators actually ran.
func (d Decision) RulesEvaluated() int { return d.rulesEvaluated }

// String returns a compact, greppable summary.
//
// Deliberately one line and stable in shape, because the first thing anyone
// does with a Decision is print it while working out why a request was blocked.
func (d Decision) String() string {
	var b strings.Builder
	b.WriteString(d.verdict.String())
	b.WriteString(" reason=")
	b.WriteString(d.reason.String())

	if id := d.RuleID(); id != 0 {
		b.WriteString(" rule=")
		b.WriteString(id.String())
	}
	if d.score != 0 {
		b.WriteString(" score=")
		b.WriteString(strconv.Itoa(d.score))
	}
	if d.reading != 0 {
		b.WriteString(" via=")
		b.WriteString(d.reading.String())
	}
	if d.rule != nil && d.rule.Rule.Msg != "" {
		b.WriteString(" msg=")
		b.WriteString(strconv.Quote(d.rule.Rule.Msg))
	}
	if d.detail != "" {
		b.WriteString(" detail=")
		b.WriteString(strconv.Quote(d.detail))
	}
	return b.String()
}

// LogValue implements slog.LogValuer, so a Decision logs as structured fields
// rather than as a formatted string.
//
//	slog.Warn("request blocked", "waf", d)
//
// Every field an operator needs to triage is present, and the interpretation is
// included because a payload found only under an alternative decoding is the
// single most confusing thing to see in a log: the bytes on the wire look
// harmless, and without this field the firewall appears to have malfunctioned.
func (d Decision) LogValue() slog.Value {
	attrs := make([]slog.Attr, 0, 8)
	attrs = append(attrs,
		slog.String("verdict", d.verdict.String()),
		slog.String("reason", d.reason.String()),
	)
	if id := d.RuleID(); id != 0 {
		attrs = append(attrs,
			slog.String("rule", id.String()),
			slog.String("msg", d.rule.Rule.Msg),
			slog.String("severity", d.rule.Rule.Severity.String()),
			slog.String("confidence", d.rule.Rule.Confidence.String()),
		)
	}
	if d.score != 0 {
		attrs = append(attrs, slog.Int("score", d.score))
	}
	if d.target.Kind != types.TargetInvalid {
		attrs = append(attrs, slog.String("target", d.target.String()))
	}
	if d.key != "" {
		attrs = append(attrs, slog.String("field", d.key))
	}
	if d.reading != 0 {
		attrs = append(attrs, slog.String("interpretation", d.reading.String()))
	}
	if d.detail != "" {
		attrs = append(attrs, slog.String("detail", d.detail))
	}
	attrs = append(attrs, slog.Int("rules_evaluated", d.rulesEvaluated))
	return slog.GroupValue(attrs...)
}

// allow returns a permitting decision.
func allow(reason Reason, score, evaluated int) Decision {
	return Decision{
		verdict:        VerdictAllow,
		reason:         reason,
		score:          score,
		rulesEvaluated: evaluated,
	}
}
