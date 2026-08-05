// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package ldapi detects LDAP injection by reading filter syntax rather than by
// matching payload strings.
//
// # The attack is unbalanced structure
//
// An LDAP search filter is a fully parenthesised prefix expression (RFC 4515):
//
//	(&(uid=alice)(userPassword=hunter2))
//
// The application builds it by substituting user input into a template, so the
// payload's job is to close the parenthesis it was placed inside and open its
// own clauses:
//
//	uid = *)(uid=*))(|(uid=*
//	→  (&(uid=*)(uid=*))(|(uid=*)(userPassword=anything))
//
// The password clause is now in a branch of an OR that is already satisfied,
// and authentication is bypassed. What identifies this is not any keyword — it
// is that the value contains *unbalanced parentheses combined with filter
// operators*. A value that legitimately contains parentheses balances them.
//
// # Why the operator alone is not enough
//
// "(" and "&" and "|" and "*" are ordinary characters. "Smith & Sons (Ltd)" is
// a company name, "(see note)" is prose, "*" is a wildcard search a user typed
// on purpose, and "a|b" is a filter expression in half the query languages in
// existence. Any of them alone is nothing.
//
// So the detector requires *structure*: an unbalanced parenthesis, plus an
// attribute-comparison or logical operator in the position the filter grammar
// would put one. Both together are the shape of an injected clause and neither
// is common in text.
//
// # Attribute names are not enumerated
//
// A list of LDAP attributes — uid, cn, objectClass — would be the same losing
// game as a list of SQL keywords, since the schema is site-specific and an
// attacker can inject against any attribute the application already uses. The
// grammar is what is fixed, so the grammar is what is read.
package ldapi

import (
	"github.com/gsoultan/gwaf/internal/budget"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Signal is one piece of structural evidence.
type Signal uint8

// Signals.
const (
	// SignalUnbalancedParen is more closing than opening parentheses, or the
	// reverse, at some point in the value. Legitimate text balances; a payload
	// escaping a filter clause cannot.
	SignalUnbalancedParen Signal = 1 << iota

	// SignalInjectedClause is a parenthesis immediately followed by a filter
	// operator or an attribute comparison — "(|(", ")(uid=", "(&(". This is a
	// new clause being opened, which is what the payload is for.
	SignalInjectedClause

	// SignalAlwaysTrueFilter is a presence filter on a wildcard — "uid=*" or a
	// bare "*)" — which matches every entry. Weak alone: users type "*" as a
	// search wildcard on purpose.
	SignalAlwaysTrueFilter

	// SignalNullByte is an escaped or literal NUL, which truncates the filter
	// in some client libraries and drops whatever the application appended.
	SignalNullByte
)

// String implements fmt.Stringer so a decision can say what it saw.
func (s Signal) String() string {
	var out []byte
	add := func(n string) {
		if len(out) > 0 {
			out = append(out, '+')
		}
		out = append(out, n...)
	}
	if s&SignalUnbalancedParen != 0 {
		add("unbalanced_paren")
	}
	if s&SignalInjectedClause != 0 {
		add("injected_clause")
	}
	if s&SignalAlwaysTrueFilter != 0 {
		add("always_true_filter")
	}
	if s&SignalNullByte != 0 {
		add("null_byte")
	}
	if len(out) == 0 {
		return "none"
	}
	return string(out)
}

// Threshold is the score at or above which a value is reported.
const Threshold = 5

// weightOf prices each signal by what it means alone.
//
// Nothing fires alone except a NUL byte, and that is deliberate. Parentheses,
// wildcards, and ampersands are all ordinary in text; only their *combination*
// in filter position is evidence.
//
// The weights are chosen so that **reaching the threshold always requires an
// injected clause or a NUL byte**, which is what makes the declared literals
// exhaustive. An earlier version priced imbalance and the always-true filter at
// 3 and 2, and the fuzz harness immediately found "*)" — score 5, no literal
// covering it, so the prefilter would have dropped the value and the rule could
// never have fired on it. The weights were wrong, not the harness.
func weightOf(s Signal) int {
	switch s {
	case SignalNullByte:
		return 5
	case SignalInjectedClause:
		return 3
	case SignalUnbalancedParen, SignalAlwaysTrueFilter:
		return 2
	default:
		return 0
	}
}

// Verdict is the result of analysing one value.
type Verdict struct {
	Signals Signal
	Score   int
	Span    types.Span
}

// Detected reports whether the evidence reached the threshold.
func (v Verdict) Detected() bool { return v.Score >= Threshold }

// Detector analyses values for LDAP injection.
//
// A Detector is immutable and safe for concurrent use.
type Detector struct{}

// New returns a Detector.
func New() *Detector { return &Detector{} }

// Name implements the operator contract.
func (*Detector) Name() string { return "detect_ldapi" }

// maxScan bounds how much of a value is analysed. A filter clause is short, so
// a payload needing more than this does not exist.
const maxScan = 8 << 10

// Analyze scores value and returns the verdict.
func (d *Detector) Analyze(value []byte) Verdict {
	if len(value) == 0 {
		return Verdict{}
	}
	src := value
	if len(src) > maxScan {
		src = src[:maxScan]
	}

	var sigs Signal
	var span types.Span
	found := false

	mark := func(s Signal, off, n int) {
		sigs |= s
		if !found && weightOf(s) > 0 {
			span = types.SpanOf(off, n)
			found = true
		}
	}

	// Parenthesis balance. Tracked as a running depth so that ")(" is seen even
	// when the totals happen to match: "a)(b" is balanced by count and is still
	// a clause boundary the value had no business containing.
	depth := 0
	minDepth := 0
	for i := 0; i < len(src); i++ {
		switch src[i] {
		case '(':
			depth++
			// "(|", "(&", "(!" open a logical clause.
			if i+1 < len(src) && isLogicalOp(src[i+1]) {
				mark(SignalInjectedClause, i, 2)
			}
		case ')':
			depth--
			if depth < minDepth {
				minDepth = depth
			}
			// ")(" closes the clause the value sits in and opens another.
			if i+1 < len(src) && src[i+1] == '(' {
				mark(SignalInjectedClause, i, 2)
			}
			// "*)" is the always-true presence filter, closing early.
			if i > 0 && src[i-1] == '*' {
				mark(SignalAlwaysTrueFilter, i-1, 2)
			}
		case '\x00':
			mark(SignalNullByte, i, 1)
		case '\\':
			// "\00" is the escaped form, which several client libraries decode
			// before building the filter.
			if i+2 < len(src) && src[i+1] == '0' && src[i+2] == '0' {
				mark(SignalNullByte, i, 3)
			}
		case '=':
			// "=*" is a presence filter: true for every entry that has the
			// attribute at all.
			if i+1 < len(src) && src[i+1] == '*' {
				mark(SignalAlwaysTrueFilter, i, 2)
			}
		}
	}
	if depth != 0 || minDepth < 0 {
		mark(SignalUnbalancedParen, 0, len(src))
	}

	total := 0
	for bit := Signal(1); bit != 0; bit <<= 1 {
		if sigs&bit != 0 {
			total += weightOf(bit)
		}
	}
	return Verdict{Signals: sigs, Score: total, Span: span}
}

// isLogicalOp reports whether c is an LDAP filter logical operator.
func isLogicalOp(c byte) bool {
	return c == '&' || c == '|' || c == '!'
}

// ---- operator ---------------------------------------------------------------

// Operator adapts the detector to the rule engine, so it is prefiltered,
// metered, and reported like every other rule.
func Operator() rules.Operator { return &operator{d: New()} }

type operator struct{ d *Detector }

func (o *operator) Name() string { return "detect_ldapi" }

func (o *operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	v := o.d.Analyze(value)
	if !v.Detected() {
		return rules.Match{}, false
	}
	return rules.Match{Span: v.Span}, true
}

// Literals are the byte sequences without which no scoring combination can
// reach the threshold.
//
// Reaching 5 needs either a NUL byte or an injected clause, and an injected
// clause is always two adjacent bytes: ")(", "(|", "(&", "(!". Declaring those
// pairs rather than a bare "(" is what keeps the automaton selective — "(" on
// its own appears in a great deal of ordinary text.
// FuzzLiteralsAreExhaustive enforces that this stays true.
func (o *operator) Literals() ([]string, bool) {
	return []string{")(", "(|", "(&", "(!", "\x00", "\\00"}, true
}

// Cost prices one analysis: a single pass with one-byte lookahead.
func (o *operator) Cost() budget.Fuel { return budget.CostLiteralMatch * 2 }
