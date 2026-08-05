// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package graphql detects abusive GraphQL documents by reading their shape.
//
// # A different kind of attack
//
// Every other detector here looks for a payload: bytes that mean something
// dangerous to a downstream interpreter. GraphQL abuse has no payload. The
// document is valid, the field names are real, and the damage is done by the
// *shape* of the request:
//
//	{a{b{c{d{ ...200 deep... }}}}}      one request, exponential resolver work
//	{a1:f a2:f a3:f ...×2000}           one request, two thousand resolutions
//	{__schema{types{fields{name}}}}      the entire API surface, in one call
//	fragment A on Q{...B}  B{...A}       a cycle some servers expand forever
//
// Measured before this package existed: all four passed gwaf untouched, because
// there is nothing in them a string matcher could object to.
//
// # Why this is in scope
//
// It looks like rate limiting and is not. Every property here is computed from
// *one document in isolation* — no memory, no identity, no history — which is
// exactly the scope line in CLAUDE.md §1. "How many requests has this client
// sent" belongs to the embedder; "how much work does this one request demand"
// does not.
//
// # Limits are policy, and policy has a default
//
// A depth of forty is abuse for most APIs and ordinary for a deeply nested
// content model. The defaults below are the ones the GraphQL ecosystem
// converged on, and every one is an Options field. What is not configurable is
// that they are *enforced*: an API with no limits is an API where one request
// can cost a thousand.
package graphql

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

// Signal is one piece of structural evidence.
type Signal uint8

// Signals.
const (
	// SignalExcessiveDepth is selection-set nesting past the limit. Depth is the
	// classic GraphQL denial of service: each level multiplies the resolvers the
	// server must run, so a linear document buys exponential work.
	SignalExcessiveDepth Signal = 1 << iota

	// SignalExcessiveComplexity is too many fields in one document, which costs
	// the server without needing any nesting at all.
	SignalExcessiveComplexity

	// SignalAliasAmplification is the same field requested many times under
	// different aliases. Aliases exist so a client can ask for one field twice;
	// asking for it two thousand times is the amplification the limit exists to
	// stop, and it defeats a naive per-field cost model completely.
	SignalAliasAmplification

	// SignalIntrospection is a query for the schema itself. Not an attack — it
	// is how every GraphQL development tool works — but in production it hands
	// an attacker the whole API surface, which is why it is reported and left
	// tunable rather than treated as certain.
	SignalIntrospection

	// SignalFragmentCycle is a fragment that spreads itself, directly or
	// transitively. The specification forbids it, so no legitimate client sends
	// one, and a server that expands before validating does not terminate.
	SignalFragmentCycle
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
	if s&SignalExcessiveDepth != 0 {
		add("excessive_depth")
	}
	if s&SignalExcessiveComplexity != 0 {
		add("excessive_complexity")
	}
	if s&SignalAliasAmplification != 0 {
		add("alias_amplification")
	}
	if s&SignalIntrospection != 0 {
		add("introspection")
	}
	if s&SignalFragmentCycle != 0 {
		add("fragment_cycle")
	}
	if len(out) == 0 {
		return "none"
	}
	return string(out)
}

// Limits bound what one document may demand.
//
// The defaults are what the ecosystem converged on. They are deliberately not
// generous: an API with a genuinely deep content model should raise them
// knowingly rather than inherit a limit that never fires.
type Limits struct {
	// MaxDepth is the deepest selection-set nesting permitted. Apollo and
	// friends suggest 10-15; real client queries sit around 5-8.
	MaxDepth int

	// MaxFields is the total field count across the document.
	MaxFields int

	// MaxAliases is how many times one field may be aliased. Twenty covers a
	// client fetching several variants of a thing; two thousand is an attack.
	MaxAliases int
}

// DefaultLimits returns the limits used when none are given.
func DefaultLimits() Limits {
	return Limits{MaxDepth: 15, MaxFields: 1000, MaxAliases: 20}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxFields <= 0 {
		l.MaxFields = d.MaxFields
	}
	if l.MaxAliases <= 0 {
		l.MaxAliases = d.MaxAliases
	}
	return l
}

// Verdict is the result of analysing one document.
type Verdict struct {
	Signals Signal

	// Depth, Fields, and MaxAlias are what was measured, so an operator tuning
	// a limit can see how far past it a request was rather than guessing.
	Depth    int
	Fields   int
	MaxAlias int

	Span types.Span
}

// Detected reports whether anything exceeded its limit.
func (v Verdict) Detected() bool { return v.Signals != 0 }

// Detector analyses GraphQL documents.
//
// A Detector is immutable and safe for concurrent use.
type Detector struct{ limits Limits }

// New returns a Detector with the given limits; zero fields take the default.
func New(l Limits) *Detector { return &Detector{limits: l.withDefaults()} }

// Name implements the operator contract.
func (*Detector) Name() string { return "detect_graphql" }

// maxScan bounds how much of a document is read.
const maxScan = 512 << 10

// maxFragments bounds fragment tracking, so a document declaring thousands of
// fragments cannot drive unbounded bookkeeping.
const maxFragments = 256

// Analyze reads a document and reports what it demands.
func (d *Detector) Analyze(doc []byte) Verdict {
	if len(doc) == 0 {
		return Verdict{}
	}
	src := doc
	if len(src) > maxScan {
		src = src[:maxScan]
	}

	var v Verdict
	s := scanner{src: src, limits: d.limits}
	s.run()

	v.Depth, v.Fields, v.MaxAlias = s.maxDepth, s.fields, s.maxAlias

	if s.maxDepth > d.limits.MaxDepth {
		v.Signals |= SignalExcessiveDepth
	}
	if s.fields > d.limits.MaxFields {
		v.Signals |= SignalExcessiveComplexity
	}
	if s.maxAlias > d.limits.MaxAliases {
		v.Signals |= SignalAliasAmplification
	}
	if s.introspection {
		v.Signals |= SignalIntrospection
	}
	if s.fragmentCycle() {
		v.Signals |= SignalFragmentCycle
	}
	if v.Signals != 0 {
		v.Span = types.SpanOf(0, len(doc))
	}
	return v
}

// scanner walks a document counting structure.
//
// Not a full GraphQL parser: nothing here needs to know a valid document from
// an invalid one, only how much work a server would do trying. It does have to
// respect string literals and comments, though — a '{' inside a string is not a
// selection set, and a naive brace count is defeated by one argument value.
type scanner struct {
	src    []byte
	limits Limits

	depth    int
	maxDepth int
	fields   int

	// aliasOf counts how many times each field name is selected. Aliases are
	// what make one field cost many, so the count is per target field rather
	// than per alias name.
	aliasOf  map[string]int
	maxAlias int

	introspection bool

	// spreads maps a fragment name to the fragments it spreads, for cycle
	// detection. Nil until a fragment is seen, since most documents have none.
	spreads map[string][]string
	current string
}

func (s *scanner) run() {
	i := 0
	for i < len(s.src) {
		c := s.src[i]

		switch {
		case c == '#':
			for i < len(s.src) && s.src[i] != '\n' {
				i++
			}
			continue

		case c == '"':
			i = skipString(s.src, i)
			continue

		case c == '{':
			s.depth++
			if s.depth > s.maxDepth {
				s.maxDepth = s.depth
			}
			i++
			continue

		case c == '}':
			if s.depth > 0 {
				s.depth--
			}
			i++
			continue

		case c == '(':
			// Arguments are not selections and their contents are not fields.
			// Skipping them is what stops "first: 10" being counted as depth.
			i = skipParens(s.src, i)
			continue

		case c == '.':
			// A fragment spread: "...Name".
			if i+2 < len(s.src) && s.src[i+1] == '.' && s.src[i+2] == '.' {
				i = s.readSpread(i + 3)
				continue
			}
			i++
			continue

		case isNameStart(c):
			i = s.readName(i)
			continue

		default:
			i++
		}
	}
}

// readName consumes an identifier and classifies it.
func (s *scanner) readName(i int) int {
	start := i
	for i < len(s.src) && isNameByte(s.src[i]) {
		i++
	}
	name := string(s.src[start:i])

	switch name {
	case "query", "mutation", "subscription", "on", "true", "false", "null":
		return i
	case "fragment":
		// "fragment Name on Type" — the name that follows owns the spreads
		// until the next fragment declaration.
		j := skipSpace(s.src, i)
		k := j
		for k < len(s.src) && isNameByte(s.src[k]) {
			k++
		}
		if k > j && len(s.spreads) < maxFragments {
			s.current = string(s.src[j:k])
			if s.spreads == nil {
				s.spreads = map[string][]string{}
			}
			if _, ok := s.spreads[s.current]; !ok {
				s.spreads[s.current] = nil
			}
		}
		return k
	}

	// A '__'-prefixed root field is introspection. "__typename" is excluded:
	// it is legal on every selection set and every GraphQL client sends it.
	if len(name) > 2 && name[0] == '_' && name[1] == '_' && name != "__typename" {
		s.introspection = true
	}

	// An alias is "alias: field"; the *field* is what costs the server, so the
	// count is keyed on it rather than on the alias.
	j := skipSpace(s.src, i)
	if j < len(s.src) && s.src[j] == ':' {
		k := skipSpace(s.src, j+1)
		start := k
		for k < len(s.src) && isNameByte(s.src[k]) {
			k++
		}
		if k > start {
			s.countField(string(s.src[start:k]))
			return k
		}
		return j + 1
	}

	s.countField(name)
	return i
}

func (s *scanner) countField(name string) {
	s.fields++
	// Alias counting is bounded: a document naming a million distinct fields
	// must not build a million-entry map.
	if len(s.aliasOf) > s.limits.MaxFields {
		return
	}
	if s.aliasOf == nil {
		s.aliasOf = map[string]int{}
	}
	s.aliasOf[name]++
	if n := s.aliasOf[name]; n > s.maxAlias {
		s.maxAlias = n
	}
}

// readSpread records "...Name" against the enclosing fragment.
func (s *scanner) readSpread(i int) int {
	i = skipSpace(s.src, i)
	start := i
	for i < len(s.src) && isNameByte(s.src[i]) {
		i++
	}
	if i == start || s.current == "" || s.spreads == nil {
		return i
	}
	if len(s.spreads[s.current]) < maxFragments {
		s.spreads[s.current] = append(s.spreads[s.current], string(s.src[start:i]))
	}
	return i
}

// fragmentCycle reports whether any fragment reaches itself.
//
// Depth-first with a colour marking, bounded by the fragment count, so a
// document declaring a cycle cannot make the *detector* the thing that fails to
// terminate.
func (s *scanner) fragmentCycle() bool {
	if len(s.spreads) == 0 {
		return false
	}
	const (
		white = 0
		grey  = 1
		black = 2
	)
	state := make(map[string]int, len(s.spreads))

	var visit func(string, int) bool
	visit = func(n string, depth int) bool {
		if depth > maxFragments {
			return true
		}
		switch state[n] {
		case grey:
			return true // reached a fragment already on the stack
		case black:
			return false
		}
		state[n] = grey
		for _, next := range s.spreads[n] {
			if visit(next, depth+1) {
				return true
			}
		}
		state[n] = black
		return false
	}

	for n := range s.spreads {
		if visit(n, 0) {
			return true
		}
	}
	return false
}

// ---- byte helpers -----------------------------------------------------------

// skipString steps over a GraphQL string, block or ordinary.
//
// Necessary rather than fastidious: an argument value like "{{{{" would
// otherwise register as four levels of nesting.
func skipString(src []byte, i int) int {
	if i+2 < len(src) && src[i+1] == '"' && src[i+2] == '"' {
		i += 3
		for i+2 < len(src) {
			if src[i] == '"' && src[i+1] == '"' && src[i+2] == '"' {
				return i + 3
			}
			i++
		}
		return len(src)
	}
	i++
	for i < len(src) {
		if src[i] == '\\' && i+1 < len(src) {
			i += 2
			continue
		}
		if src[i] == '"' {
			return i + 1
		}
		i++
	}
	return len(src)
}

// skipParens steps over an argument list, respecting nesting and strings.
func skipParens(src []byte, i int) int {
	depth := 0
	for i < len(src) {
		switch src[i] {
		case '"':
			i = skipString(src, i)
			continue
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return len(src)
}

func skipSpace(src []byte, i int) int {
	for i < len(src) {
		switch src[i] {
		case ' ', '\t', '\n', '\r', ',':
			i++
		default:
			return i
		}
	}
	return i
}

func isNameStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func isNameByte(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}

// ---- operator ---------------------------------------------------------------

// Operator adapts the detector to the rule engine, reporting only documents
// whose evidence includes at least one signal in accept.
//
// The mask splits limits from introspection, because they are not equally
// certain. A document past its depth limit is abusive whoever sent it; an
// introspection query is how every GraphQL development tool works, and blocking
// it in a staging environment is an outage rather than a defence.
func Operator(l Limits, accept Signal) rules.Operator {
	return &operator{d: New(l), accept: accept}
}

type operator struct {
	d      *Detector
	accept Signal
}

func (o *operator) Name() string { return "detect_graphql" }

func (o *operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	v := o.d.Analyze(value)
	if v.Signals&o.accept == 0 {
		return rules.Match{}, false
	}
	return rules.Match{Span: v.Span}, true
}

// Literals are the byte sequences without which no accepted signal can fire.
//
// Introspection needs its own field names, which are highly selective. The
// structural limits need only a selection set — a '{' — which is not selective
// at all, so those rules are scoped to the argument that carries a GraphQL
// document instead, and the target check runs before the operator does.
func (o *operator) Literals() ([]string, bool) {
	if o.accept == SignalIntrospection {
		return []string{"__schema", "__type"}, true
	}
	return []string{"{"}, true
}

// Cost prices one analysis: a single pass with bounded fragment bookkeeping.
func (o *operator) Cost() types.Fuel { return types.CostLiteralMatch * 8 }

// IntrospectionRule returns a rule that reports GraphQL introspection queries.
//
// Deliberately not part of the core ruleset, and the reason is the difference
// between a finding and an attack. Introspection is how GraphiQL, Apollo Studio,
// and every code generator discover a schema; blocking it by default would break
// them on the day somebody adopted gwaf, which is precisely how a firewall gets
// switched off in week one.
//
// Disabling introspection in production is a defensible posture, and it is the
// operator's posture to choose:
//
//	waf, err := gwaf.New(gwaf.WithRuleset(rules.Set{
//	    graphql.IntrospectionRule(10002),
//	}))
//
// The structural limits — depth, complexity, alias amplification, fragment
// cycles — are in the core ruleset, because a document past those is abusive
// whoever sent it.
func IntrospectionRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:      id,
		Phase:   types.PhaseRequestBody,
		Targets: []types.Target{{Kind: types.TargetArgs, Name: "query"}},
		// Percent-decoding, because the GraphQL-over-HTTP GET form carries the
		// whole document in the query string.
		Transforms: []rules.Transform{transform.URLDecode},
		Op:         Operator(Limits{}, SignalIntrospection),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityWarning,
		Confidence: types.High,
		Msg:        "GraphQL introspection query",
		Tags:       []string{"graphql", "recon", "owasp-a01"},
	}
}
