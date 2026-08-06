// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package rx provides a regular-expression operator.
//
// It is a package of its own rather than part of rules/op because of the fifth
// ownership test: an embedder writing gwaf.New() should not link a regex engine
// because somebody else needed one. Go links per package, so the cost is paid
// only by code that imports this one — which is the same guarantee that kept
// this operator inside the seclang module, without the side effect of forcing
// an embedder who wants one regex rule to take a SecLang parser with it.
//
// Go's regexp is RE2: linear in the length of the input, no backtracking,
// ReDoS-impossible. That is what makes it safe to evaluate a pattern against
// attacker-controlled bytes at all, and it is why Cost can be a constant.
package rx

import (
	"regexp"
	"regexp/syntax"
	"strings"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Operator is a compiled regular-expression operator.
type Operator struct {
	re       *regexp.Regexp
	src      string
	literals []string
	negated  bool
}

// New returns an operator matching values the pattern matches.
func New(pattern string) (*Operator, error) { return compile(pattern, false) }

// NewNegated returns an operator matching values the pattern does *not* match.
//
// A negated pattern cannot be prefiltered — it matches on the absence of
// something, so no byte sequence is required — and is therefore evaluated on
// every value in its phase. The compile report lists it as unconditional.
func NewNegated(pattern string) (*Operator, error) { return compile(pattern, true) }

// MustNew is New for package-level rule definitions, where a pattern that does
// not compile is a build-time defect rather than a runtime condition.
func MustNew(pattern string) *Operator {
	o, err := New(pattern)
	if err != nil {
		panic("rx: pattern does not compile: " + err.Error())
	}
	return o
}

func compile(pattern string, negated bool) (*Operator, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	// Case-insensitivity via the (?i) flag is handled by RE2 itself, and the
	// prefilter folds ASCII case on both sides, so nothing extra is needed to
	// make a case-insensitive pattern prefilterable.
	return &Operator{
		re:       re,
		src:      pattern,
		literals: ExtractLiterals(pattern),
		negated:  negated,
	}, nil
}

// Pattern returns the source pattern, for compile reports and generated code.
func (o *Operator) Pattern() string { return o.src }

// Negated reports whether the operator matches on absence.
func (o *Operator) Negated() bool { return o.negated }

// Name implements rules.Operator.
func (o *Operator) Name() string { return "rx" }

// Eval implements rules.Operator.
func (o *Operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
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

// Literals implements rules.Operator, returning byte sequences without which
// the pattern cannot match.
//
// This is what keeps a large imported ruleset from destroying the latency
// budget: rules that all had to run against every value would be exactly the
// interpreter design gwaf exists not to be. The literals are derived from the
// pattern's syntax tree rather than asserted by a caller, which removes the one
// place in the Operator contract where being wrong is silent.
func (o *Operator) Literals() ([]string, bool) {
	if o.negated || len(o.literals) == 0 {
		return nil, false
	}
	return o.literals, true
}

// Cost implements rules.Operator. RE2 is linear in the input, and the engine
// already charges per byte scanned, so what remains is a constant well above a
// literal comparison.
func (o *Operator) Cost() types.Fuel { return types.CostLiteralMatch * 20 }

// ExtractLiterals finds strings without which the pattern cannot match.
//
// The returned set has *any-of* semantics, matching how the engine uses it:
// every string the pattern matches contains at least one element. An empty
// result means "unknown", which makes the rule unconditional — that costs
// latency and is reported, and it is always safe.
//
// It walks the parsed syntax tree rather than the pattern text, so it is exact
// about what the regex means rather than guessing from characters:
//
//   - a literal yields itself;
//   - a concatenation yields the set of any *one* of its parts, since every
//     part must appear; the most selective part is chosen;
//   - an alternation yields the union of its branches, and only if every branch
//     yields something, because a branch with no literal can match without any
//     of them;
//   - a repetition that may match zero times yields nothing;
//   - a capture or a non-greedy wrapper is transparent.
//
// It is exported because it is useful on its own — a tool that lints a ruleset
// wants to report which rules will be unconditional before they are compiled.
func ExtractLiterals(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	lits := requiredLiterals(re.Simplify(), 0)
	if len(lits) == 0 {
		return nil
	}

	// Very short literals are worse than none: a one-byte literal makes almost
	// every value a candidate, so the automaton does work and excludes nothing.
	//
	// Discarding them is all-or-nothing. The set is a disjunction, so dropping
	// one member asserts that the remaining ones cover every match — and they
	// do not. `foo|ab` would keep only "foo" and stop firing on "ab".
	out := make([]string, 0, len(lits))
	for _, l := range lits {
		if len(l) < minLiteral {
			return nil
		}
		out = append(out, strings.ToLower(l))
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

// requiredLiterals returns a disjunctive set: every string re matches contains
// at least one element. An empty result means no such set could be derived.
//
// The disjunctive reading is the whole correctness argument. An earlier version
// mixed it with a conjunctive one — a concatenation returned the literals of
// *all* its parts, including those of a nested alternation, and an alternation
// then picked the longest of that mixed list. For `\.(php[345]?|phtml|aspx?)$`
// the parser factors the shared "ph" prefix, and the longest surviving literal
// was "tml": a rule that no longer fired on ".php", silently, with nothing to
// indicate it. Keeping one semantics throughout is what prevents that.
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
		// Every part must appear, so the set of any single part is sound on its
		// own. Adjacent literal runs are joined first, which is what turns
		// "f" "o" "o" back into the "foo" a reader would expect, and then the
		// most selective candidate wins.
		var best []string
		var run strings.Builder
		consider := func(c []string) {
			if len(c) > 0 && (len(best) == 0 || selectivity(c) > selectivity(best)) {
				best = c
			}
		}
		// A literal run is extended with the prefixes of whatever follows it,
		// so `ph` followed by `(p[345]?|tml)` yields "php" and "phtml" rather
		// than the useless two-byte "ph". This matters because the parser
		// factors shared prefixes out of alternations by itself, which is
		// exactly how file-extension rules like `\.(php|phtml|aspx?)$` are
		// shaped after parsing — without it they extract nothing and run on
		// every request.
		flush := func(next *syntax.Regexp) {
			if run.Len() == 0 {
				return
			}
			prefix := run.String()
			run.Reset()
			if next != nil {
				if ext := extendAll(prefix, literalPrefixes(next, depth+1)); len(ext) > 0 {
					consider(ext)
					return
				}
			}
			consider([]string{prefix})
		}
		for i, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				run.WriteString(string(sub.Rune))
				continue
			}
			flush(re.Sub[i])
			consider(requiredLiterals(sub, depth+1))
		}
		flush(nil)
		return best

	case syntax.OpAlternate:
		// The union of every branch, and only when every branch contributes:
		// one branch with no literal means the pattern can match without any of
		// them.
		var all []string
		for _, sub := range re.Sub {
			lits := requiredLiterals(sub, depth+1)
			if len(lits) == 0 {
				return nil
			}
			all = append(all, lits...)
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

// maxPrefixSet bounds the cross product a literal run may expand into. An
// alternation of many branches would otherwise grow the prefilter automaton
// faster than it improves selectivity.
const maxPrefixSet = 16

// literalPrefixes returns a set such that every string re matches *begins* with
// one of them, or nil when no such set can be derived.
//
// This is a stronger claim than requiredLiterals makes — position matters — and
// it is what lets a preceding literal run be glued on soundly.
func literalPrefixes(re *syntax.Regexp, depth int) []string {
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
		return literalPrefixes(re.Sub[0], depth+1)

	case syntax.OpConcat:
		if len(re.Sub) == 0 {
			return nil
		}
		head := literalPrefixes(re.Sub[0], depth+1)
		// Only a leading literal is fully consumed by its own prefix, so only
		// then may the next element extend it. Anything else may match more
		// than the prefix describes, and gluing would invent a constraint.
		if re.Sub[0].Op == syntax.OpLiteral && len(re.Sub) > 1 {
			if tail := literalPrefixes(re.Sub[1], depth+1); len(tail) > 0 {
				if ext := extendAll(string(re.Sub[0].Rune), tail); len(ext) > 0 {
					return ext
				}
			}
		}
		return head

	case syntax.OpAlternate:
		var all []string
		for _, sub := range re.Sub {
			p := literalPrefixes(sub, depth+1)
			if len(p) == 0 {
				return nil
			}
			all = append(all, p...)
			if len(all) > maxPrefixSet {
				return nil
			}
		}
		return all

	case syntax.OpCharClass:
		// A small class is an alternation of single bytes, and the parser
		// produces one whenever branches differ by a single character: `py|pl`
		// is factored to `p[ly]`. Refusing to enumerate it is what made a
		// ten-branch extension list like `\.(exe|php|sh|py|pl|rb)$` extract
		// nothing at all, because one two-byte branch drags the whole
		// disjunction below the length floor.
		return classLiterals(re)

	case syntax.OpPlus:
		// One or more: the first repetition starts the match.
		return literalPrefixes(re.Sub[0], depth+1)

	case syntax.OpRepeat:
		if re.Min >= 1 {
			return literalPrefixes(re.Sub[0], depth+1)
		}
		return nil

	default:
		return nil
	}
}

// classLiterals enumerates a character class as one-byte strings, or returns
// nil when the class is too wide or not plain printable ASCII.
//
// The bound is what keeps this from being a footgun: enumerating `[a-z]` would
// add 26 automaton entries that between them match nearly every value, which is
// the failure mode where a prefilter exists and excludes nothing.
func classLiterals(re *syntax.Regexp) []string {
	out := make([]string, 0, maxPrefixSet)
	for i := 0; i+1 < len(re.Rune); i += 2 {
		lo, hi := re.Rune[i], re.Rune[i+1]
		if lo < 0x21 || hi > 0x7e {
			return nil
		}
		for r := lo; r <= hi; r++ {
			if len(out) >= maxPrefixSet {
				return nil
			}
			out = append(out, string(r))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// extendAll prefixes each element, returning nil if the result would be too
// large to be worth keying on.
func extendAll(prefix string, suffixes []string) []string {
	if len(suffixes) == 0 || len(suffixes) > maxPrefixSet {
		return nil
	}
	out := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		out = append(out, prefix+s)
	}
	return out
}

// selectivity scores a candidate set. A disjunction is only as selective as its
// weakest member — any one of them admits a value — so the shortest element
// decides, and a smaller set breaks the tie.
func selectivity(ss []string) int {
	shortest := -1
	for _, s := range ss {
		if shortest < 0 || len(s) < shortest {
			shortest = len(s)
		}
	}
	if shortest < 0 {
		return 0
	}
	return shortest*8 - len(ss)
}

var _ rules.Operator = (*Operator)(nil)
