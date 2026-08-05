// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package seclang

import (
	"regexp"
	"regexp/syntax"
	"strings"

	"github.com/gsoultan/gwaf/internal/budget"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// regexOperator implements @rx.
//
// It lives here rather than in core for two reasons. The obvious one is the
// fifth ownership test: an embedder writing gwaf.New() should not link a regex
// engine because somebody else is migrating from CRS. The better one is that it
// demonstrates the Operator extension point carrying real weight — if a
// third-party operator could not be prefiltered, metered, and explained exactly
// like a first-party one, the extension point would be decorative.
//
// Go's regexp is RE2: linear time, no backtracking, ReDoS-impossible. That is
// not merely a nice property here, it is what makes importing a stranger's
// regexes defensible at all. A CRS rule written against PCRE may behave
// differently under RE2 — backreferences and lookarounds do not compile — and
// the compiler reports each one rather than approximating it.
type regexOperator struct {
	re       *regexp.Regexp
	src      string
	literals []string
	negated  bool
}

func newRegexOperator(pattern string, negated bool) (rules.Operator, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	// Case-insensitivity is common in CRS via the (?i) flag, which RE2 handles;
	// nothing extra is needed here.
	return &regexOperator{
		re:       re,
		src:      pattern,
		literals: extractLiterals(pattern),
		negated:  negated,
	}, nil
}

func (o *regexOperator) Name() string { return "rx" }

func (o *regexOperator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	loc := o.re.FindIndex(value)
	if o.negated {
		if loc != nil {
			return rules.Match{}, false
		}
		// A negated match has no span: nothing matched, which is the point.
		// Reporting the whole value is the honest span for "this did not
		// contain what it had to".
		return rules.Match{Span: types.SpanOf(0, len(value))}, true
	}
	if loc == nil {
		return rules.Match{}, false
	}
	return rules.Match{Span: types.SpanOf(loc[0], loc[1]-loc[0])}, true
}

// Literals returns the byte sequences without which the pattern cannot match.
//
// This is what keeps an imported ruleset from destroying the latency SLO. Ten
// thousand CRS rules that all had to run against every value would be exactly
// the interpreter design gwaf exists not to be, so the extraction below is not
// an optimisation — it is the difference between a usable import and an
// unusable one.
//
// A negated pattern is unconditional by necessity: it matches when the value
// does *not* contain something, so no literal can be required.
func (o *regexOperator) Literals() ([]string, bool) {
	if o.negated || len(o.literals) == 0 {
		return nil, false
	}
	return o.literals, true
}

// Cost prices one match. RE2 is linear in the input, and the constant is
// well above a literal comparison.
func (o *regexOperator) Cost() budget.Fuel { return budget.CostLiteralMatch * 20 }

// extractLiterals finds strings that must appear for the pattern to match.
//
// It walks the parsed syntax tree rather than the pattern text, so it is exact
// about what the regex means rather than guessing from characters. The rules
// are the sound ones and no more:
//
//   - a concatenation contributes the literals of its parts;
//   - an alternation contributes only if *every* branch yields one, because a
//     branch with no literal can match without any of them;
//   - a repetition that may match zero times contributes nothing;
//   - a capture or a non-greedy wrapper is transparent.
//
// Anything else yields nothing, and yielding nothing is always safe: the rule
// becomes unconditional, which costs latency and is reported, never coverage.
func extractLiterals(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	lits := requiredLiterals(re.Simplify(), 0)

	// Very short literals are worse than none: a one-byte literal makes almost
	// every value a candidate, so the automaton does work and excludes nothing.
	out := make([]string, 0, len(lits))
	for _, l := range lits {
		if len(l) >= minLiteral {
			out = append(out, strings.ToLower(l))
		}
	}
	return out
}

// minLiteral is the shortest literal worth keying on.
//
// Three bytes is the point where a prefilter entry excludes more than it costs.
// Below it, the automaton grows and the candidate set stops being selective —
// which is the failure mode where a prefilter is present and buys nothing.
const minLiteral = 3

// maxLiteralDepth bounds the walk. A pathological pattern nests deeply, and
// this runs at compile time on input somebody else wrote.
const maxLiteralDepth = 24

// requiredLiterals returns literals that must be present for re to match.
func requiredLiterals(re *syntax.Regexp, depth int) []string {
	if depth > maxLiteralDepth {
		return nil
	}

	switch re.Op {
	case syntax.OpLiteral:
		if s := string(re.Rune); s != "" {
			return []string{s}
		}
		return nil

	case syntax.OpCapture:
		return requiredLiterals(re.Sub[0], depth+1)

	case syntax.OpConcat:
		// Every part is required, so every part's literals are required.
		// Adjacent literal runs are joined, which is what turns "f" "o" "o"
		// back into the "foo" a reader would expect.
		var out []string
		var run strings.Builder
		flush := func() {
			if run.Len() > 0 {
				out = append(out, run.String())
				run.Reset()
			}
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				run.WriteString(string(sub.Rune))
				continue
			}
			flush()
			out = append(out, requiredLiterals(sub, depth+1)...)
		}
		flush()
		return out

	case syntax.OpAlternate:
		// Only sound when every branch requires something: one branch with no
		// literal means the pattern can match without any of them.
		var all []string
		for _, sub := range re.Sub {
			lits := requiredLiterals(sub, depth+1)
			if len(lits) == 0 {
				return nil
			}
			// One literal per branch keeps the automaton small; the longest is
			// the most selective.
			all = append(all, longest(lits))
		}
		return all

	case syntax.OpPlus:
		// One or more: the body must appear at least once.
		return requiredLiterals(re.Sub[0], depth+1)

	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiterals(re.Sub[0], depth+1)
		}
		return nil

	default:
		// OpStar, OpQuest, character classes, anchors, empty matches: none of
		// them requires any particular byte.
		return nil
	}
}

func longest(ss []string) string {
	best := ""
	for _, s := range ss {
		if len(s) > len(best) {
			best = s
		}
	}
	return best
}
