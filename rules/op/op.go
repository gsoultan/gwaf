// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package op provides the built-in operators.
//
// Every operator here reports required literals wherever it honestly can, which
// is what lets the prefilter skip it on benign traffic. Operators that cannot —
// Func, and anything genuinely input-independent — are unconditional, and the
// compile report says so by name. The cost of an unconditional rule is a
// build-time fact rather than a production surprise. See docs/RULES.md §5.
package op

import (
	"bytes"

	"github.com/gsoultan/gwaf/internal/budget"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Contains matches values containing needle, case-insensitively.
//
// The comparison is case-insensitive because the prefilter folds case, and an
// operator that were stricter than its own prefilter would be skipped for
// inputs it would have matched — a silent miss. Operators must never be
// narrower than the literals they declare.
func Contains(needle string) rules.Operator {
	return &containsAny{
		name:     "contains",
		needles:  []string{needle},
		lowered:  [][]byte{[]byte(toLower(needle))},
		literals: []string{needle},
	}
}

// ContainsAny matches values containing any of the needles, case-insensitively.
func ContainsAny(needles ...string) rules.Operator {
	lowered := make([][]byte, 0, len(needles))
	lits := make([]string, 0, len(needles))
	for _, n := range needles {
		if n == "" {
			continue
		}
		lowered = append(lowered, []byte(toLower(n)))
		lits = append(lits, n)
	}
	return &containsAny{
		name:     "contains_any",
		needles:  needles,
		lowered:  lowered,
		literals: lits,
	}
}

type containsAny struct {
	name     string
	needles  []string
	lowered  [][]byte
	literals []string
}

func (o *containsAny) Name() string { return o.name }

func (o *containsAny) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	for _, n := range o.lowered {
		if len(n) == 0 {
			continue
		}
		if i := indexFold(value, n); i >= 0 {
			return rules.Match{Span: types.SpanOf(i, len(n))}, true
		}
	}
	return rules.Match{}, false
}

// Literals reports every needle as required. Any single one occurring is enough
// for the operator to match, which is exactly the OR semantics the prefilter
// applies to a rule's literal set.
func (o *containsAny) Literals() ([]string, bool) {
	if len(o.literals) == 0 {
		// No usable needle: the operator can never match. Declaring it
		// unconditional would be wasteful but declaring an empty required set
		// would be wrong, so report honestly and let the compile report show it.
		return nil, false
	}
	return o.literals, true
}

func (o *containsAny) Cost() budget.Fuel { return budget.CostLiteralMatch }

// Equals matches values equal to want, case-sensitively.
func Equals(want string) rules.Operator {
	return &equals{want: []byte(want), literal: want}
}

type equals struct {
	want    []byte
	literal string
}

func (o *equals) Name() string { return "equals" }

func (o *equals) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	if bytes.Equal(value, o.want) {
		return rules.WholeValue(value), true
	}
	return rules.Match{}, false
}

// Literals reports want as required: a value equal to want necessarily contains
// it. The empty string is required by every value, so it prefilters nothing.
func (o *equals) Literals() ([]string, bool) {
	if o.literal == "" {
		return nil, false
	}
	return []string{o.literal}, true
}

func (o *equals) Cost() budget.Fuel { return budget.CostLiteralMatch }

// HasPrefix matches values beginning with prefix, case-insensitively.
func HasPrefix(prefix string) rules.Operator {
	return &hasPrefix{prefix: []byte(toLower(prefix)), literal: prefix}
}

type hasPrefix struct {
	prefix  []byte
	literal string
}

func (o *hasPrefix) Name() string { return "has_prefix" }

func (o *hasPrefix) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	if len(value) < len(o.prefix) {
		return rules.Match{}, false
	}
	if equalFold(value[:len(o.prefix)], o.prefix) {
		return rules.Match{Span: types.SpanOf(0, len(o.prefix))}, true
	}
	return rules.Match{}, false
}

func (o *hasPrefix) Literals() ([]string, bool) {
	if o.literal == "" {
		return nil, false
	}
	return []string{o.literal}, true
}

func (o *hasPrefix) Cost() budget.Fuel { return budget.CostLiteralMatch }

// Func wraps an arbitrary predicate.
//
// This is the escape hatch, and it is priced accordingly. The engine cannot
// extract literals from a Go function, so a Func rule is unconditional: it runs
// on every request in its phase and its cost shows up in the compile report.
// Third-party predicates also run behind a recovering boundary, which built-in
// operators do not need.
//
// Use WithLiterals when you can honestly assert what the predicate requires:
//
//	op.Func("graphql-introspection", isIntrospection).WithLiterals("__schema")
//
// It returns the concrete type rather than the interface so that chains like
// the one above compile. Returning rules.Operator made the documented form a
// type error and forced callers through a LiteralHinter assertion, which is not
// what an escape hatch should feel like -- CLAUDE.md §2b asks for one that is
// always present and always visible. *FuncOperator satisfies rules.Operator, so
// nothing that only stores the result had to change.
func Func(name string, fn func(value []byte) bool) *FuncOperator {
	return &FuncOperator{name: name, fn: fn}
}

// FuncOperator is the operator Func returns.
//
// Exported for its methods rather than for its fields: a caller builds one with
// Func and refines it with WithLiterals.
type FuncOperator = funcOp

type funcOp struct {
	name     string
	fn       func([]byte) bool
	literals []string
}

func (o *funcOp) Name() string { return "func:" + o.name }

func (o *funcOp) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	if o.fn(value) {
		return rules.WholeValue(value), true
	}
	return rules.Match{}, false
}

func (o *funcOp) Literals() ([]string, bool) {
	if len(o.literals) == 0 {
		return nil, false
	}
	return o.literals, true
}

func (o *funcOp) Cost() budget.Fuel { return budget.CostCustomOperator }

// WithLiterals asserts that the predicate cannot match unless at least one of
// these byte sequences is present, which lets the prefilter skip it.
//
// This is an assertion to the compiler, and it is the one place in the API
// where you can be wrong without being told: if the predicate can match input
// containing none of these literals, the rule will silently stop firing. State
// the literals the predicate actually looks for, not the ones you expect to see.
func (o *funcOp) WithLiterals(literals ...string) *FuncOperator {
	clone := *o
	clone.literals = append([]string(nil), literals...)
	return &clone
}

// LiteralHinter is implemented by operators that accept a required-literal
// assertion. It lets callers attach hints without knowing the concrete type.
type LiteralHinter interface {
	rules.Operator
	WithLiterals(literals ...string) *FuncOperator
}

var _ LiteralHinter = (*funcOp)(nil)

// toLower returns s with ASCII upper case folded to lower case. Only ASCII is
// folded, matching the prefilter: folding arbitrary UTF-8 can change byte
// length and would break the offset arithmetic spans depend on.
func toLower(s string) string {
	hasUpper := false
	for i := range len(s) {
		if s[i] >= 'A' && s[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// foldByte maps one ASCII upper-case byte to lower case.
func foldByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// equalFold reports whether a and b are equal ignoring ASCII case. b must
// already be lower-cased.
func equalFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if foldByte(a[i]) != b[i] {
			return false
		}
	}
	return true
}

// indexFold returns the index of the first case-insensitive occurrence of
// needle in haystack, or -1. needle must already be lower-cased.
//
// It anchors on the first byte using bytes.IndexByte, which is assembly-
// optimised on every platform Go supports, rather than scanning byte by byte in
// Go. When the first byte is a letter both cases are probed and the earlier hit
// wins.
func indexFold(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	if len(needle) > len(haystack) {
		return -1
	}

	first := needle[0]
	upper := first
	if first >= 'a' && first <= 'z' {
		upper = first - ('a' - 'A')
	}

	for off := 0; off <= len(haystack)-len(needle); {
		rest := haystack[off:]
		i := bytes.IndexByte(rest, first)
		if upper != first {
			if j := bytes.IndexByte(rest, upper); j >= 0 && (i < 0 || j < i) {
				i = j
			}
		}
		if i < 0 {
			return -1
		}
		pos := off + i
		if pos+len(needle) > len(haystack) {
			return -1
		}
		if equalFold(haystack[pos:pos+len(needle)], needle) {
			return pos
		}
		off = pos + 1
	}
	return -1
}
