// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package nosqli detects NoSQL injection by reading where a name sits in a
// document rather than by matching strings in a value.
//
// # The attack is a key, not a value
//
// This is what makes NoSQL injection different from every other class gwaf
// detects, and why a value-scanning detector finds nothing. A login form sends:
//
//	{"username": "alice", "password": "hunter2"}
//
// and the injection sends:
//
//	{"username": "alice", "password": {"$ne": null}}
//
// Nothing dangerous appears in any *value*. The payload is the appearance of a
// key named "$ne" in a position where the application expected a scalar. The
// query then reads "password is not equal to null", which is true of every
// stored password, and authentication is bypassed without guessing anything.
//
// gwaf's body parsers already emit object member names as their own values
// under ARGS_NAMES — Kind KindKey, "an object member name, which is also
// attacker-controlled". So the detector analyses a *name*, and the prefilter
// gates it on the operator tokens exactly as it does for any other rule. No
// engine change was needed; the surface was already there.
//
// # Why an operator list rather than "any $-prefixed key"
//
// Because "$" leads plenty of legitimate keys, and blocking those breaks real
// APIs:
//
//   - JSON Schema: $schema, $ref, $id, $defs, $comment, $anchor, $vocabulary
//   - Json.NET reference preservation: $id, $ref, $values
//   - AngularJS internals that get round-tripped: $$hashKey
//
// So the dangerous operators are enumerated and the known-benign ones are
// listed explicitly rather than left to chance. The list is short and closed
// because MongoDB's query language is: unlike a signature list chasing payload
// variants, this enumerates a *grammar's keywords*, which is a bounded set the
// vendor publishes.
//
// # Bracket notation
//
// Express, PHP, and Rails all expand "user[$ne]=x" in a query string into a
// nested object before it reaches the database, so the same attack arrives
// without any JSON at all. Operators are therefore matched as tokens anywhere
// inside a name, not only as the whole of one.
package nosqli

import (
	"slices"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Signal is one piece of structural evidence.
type Signal uint8

// Signals.
const (
	// SignalQueryOperator is a comparison or logical operator in a key
	// position: $ne, $gt, $regex, $in and their relatives. These are the
	// authentication-bypass and data-extraction primitives, and none of them is
	// a plausible field name in any framework.
	SignalQueryOperator Signal = 1 << iota

	// SignalEvalOperator is an operator that makes the database execute code —
	// $where, $function, $accumulator, $expr. Strictly worse than the
	// comparison operators: this is remote code execution inside the database
	// engine, not merely a query the attacker shaped.
	SignalEvalOperator

	// SignalUpdateOperator is a document-mutation operator: $set, $inc, $push.
	// Weaker deliberately. An application that proxies a partial update to the
	// database sends these itself, so alone this is suspicious rather than
	// conclusive.
	SignalUpdateOperator

	// SignalAmbiguousOperator is a token that is a MongoDB operator *and* a
	// well-known serialisation key — $type is the case that matters, since
	// Json.NET writes it for polymorphic payloads. Corroborating, never
	// sufficient: blocking every .NET API that round-trips typed JSON would be
	// a far larger outage than the attack it prevents.
	SignalAmbiguousOperator
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
	if s&SignalQueryOperator != 0 {
		add("query_operator")
	}
	if s&SignalEvalOperator != 0 {
		add("eval_operator")
	}
	if s&SignalUpdateOperator != 0 {
		add("update_operator")
	}
	if s&SignalAmbiguousOperator != 0 {
		add("ambiguous_operator")
	}
	if len(out) == 0 {
		return "none"
	}
	return string(out)
}

// Threshold is the score at or above which a name is reported.
const Threshold = 5

// weightOf prices each signal by what it means alone.
func weightOf(s Signal) int {
	switch s {
	case SignalQueryOperator, SignalEvalOperator:
		return 5
	case SignalUpdateOperator:
		return 3
	case SignalAmbiguousOperator:
		return 2
	default:
		return 0
	}
}

// operatorTokens maps every recognised token onto its signal.
//
// This is the single source of truth: Literals() is derived from it, so a token
// cannot be classified without also being prefilterable. Keeping two hand-
// maintained lists in sync is exactly the drift that produces a rule which
// compiles, lints clean, and silently never fires.
//
// Case-sensitive on purpose. MongoDB rejects "$NE", so folding case would only
// widen the detector onto strings the database would never honour — surface
// with no corresponding attack.
var operatorTokens = map[string]Signal{
	// Code execution inside the database engine.
	"$where": SignalEvalOperator, "$function": SignalEvalOperator,
	"$accumulator": SignalEvalOperator, "$expr": SignalEvalOperator,

	// Comparison, element, array, and logical operators. These are what turn a
	// scalar field into a query the attacker controls.
	//
	// $text and $search are deliberately absent: "$search" is an OData system
	// query option, so it arrives as an ordinary parameter name from a large
	// installed base, and text-search injection grants far less than the
	// operators listed here. The collision is not worth the recall.
	"$ne": SignalQueryOperator, "$eq": SignalQueryOperator,
	"$gt": SignalQueryOperator, "$gte": SignalQueryOperator,
	"$lt": SignalQueryOperator, "$lte": SignalQueryOperator,
	"$in": SignalQueryOperator, "$nin": SignalQueryOperator,
	"$regex": SignalQueryOperator, "$options": SignalQueryOperator,
	"$exists": SignalQueryOperator, "$mod": SignalQueryOperator,
	"$all": SignalQueryOperator, "$size": SignalQueryOperator,
	"$elemMatch": SignalQueryOperator, "$not": SignalQueryOperator,
	"$or": SignalQueryOperator, "$and": SignalQueryOperator,
	"$nor": SignalQueryOperator, "$jsonSchema": SignalQueryOperator,
	"$bitsAllSet": SignalQueryOperator, "$bitsAnySet": SignalQueryOperator,
	"$bitsAllClear": SignalQueryOperator, "$bitsAnyClear": SignalQueryOperator,
	"$geoWithin": SignalQueryOperator, "$geoIntersects": SignalQueryOperator,
	"$near": SignalQueryOperator, "$nearSphere": SignalQueryOperator,

	// Mutation operators.
	"$set": SignalUpdateOperator, "$unset": SignalUpdateOperator,
	"$inc": SignalUpdateOperator, "$mul": SignalUpdateOperator,
	"$rename": SignalUpdateOperator, "$push": SignalUpdateOperator,
	"$pull": SignalUpdateOperator, "$pullAll": SignalUpdateOperator,
	"$addToSet": SignalUpdateOperator, "$pop": SignalUpdateOperator,
	"$each": SignalUpdateOperator, "$position": SignalUpdateOperator,
	"$slice": SignalUpdateOperator, "$sort": SignalUpdateOperator,
	"$currentDate": SignalUpdateOperator, "$setOnInsert": SignalUpdateOperator,
	"$bit": SignalUpdateOperator,

	// Both an operator and an ordinary serialisation key.
	"$type": SignalAmbiguousOperator,
}

// classify maps an operator token onto its signal, or zero if it is not one.
func classify(tok string) Signal { return operatorTokens[tok] }

// benign lists $-prefixed keys that are ordinary in real payloads.
//
// Checked before classify so that a token appearing in both lists resolves to
// benign. Two collisions are settled here deliberately:
//
//   - $comment is a MongoDB query modifier and a JSON Schema annotation. The
//     schema use is overwhelmingly more common and the MongoDB use grants an
//     attacker nothing.
//   - $filter, $count, and their relatives are MongoDB aggregation operators
//     *and* OData system query options. gwaf sees HTTP parameters, where the
//     OData reading is the common one by a wide margin.
//
// Resolving a collision toward benign costs recall on a low-value operator.
// Resolving it toward attack blocks a published, widely implemented standard,
// which is the larger outage.
var benign = map[string]bool{
	// JSON Schema and JSON reference.
	"$schema": true, "$ref": true, "$id": true, "$defs": true,
	"$comment": true, "$anchor": true, "$vocabulary": true,
	"$dynamicRef": true, "$dynamicAnchor": true, "$recursiveRef": true,
	"$recursiveAnchor": true,

	// OData system query options (OASIS OData 4.01, §11.2).
	"$filter": true, "$select": true, "$top": true, "$skip": true,
	"$orderby": true, "$expand": true, "$count": true, "$format": true,
	"$search": true, "$apply": true, "$compute": true, "$levels": true,
	"$inlinecount": true, "$skiptoken": true, "$deltatoken": true,
	"$index": true, "$schemaversion": true, "$value": true, "$batch": true,
	"$metadata": true, "$root": true, "$it": true, "$this": true,

	// Serialisation and framework internals that get round-tripped.
	"$values": true, "$$hashKey": true, "$async": true, "$meta": true,
}

// Verdict is the result of analysing one name.
type Verdict struct {
	Signals Signal
	Score   int
	Span    types.Span
}

// Detected reports whether the evidence reached the threshold.
func (v Verdict) Detected() bool { return v.Score >= Threshold }

// Detector analyses parameter names for NoSQL injection.
//
// A Detector is immutable and safe for concurrent use.
type Detector struct{}

// New returns a Detector.
func New() *Detector { return &Detector{} }

// Name implements the operator contract.
func (*Detector) Name() string { return "detect_nosqli" }

// maxScan bounds how much of a name is analysed.
//
// A name is a field path. Anything past this is not one, and the bound stops a
// pathological key from driving work proportional to its length.
const maxScan = 1 << 10

// maxTokenLen is the longest operator token. Nothing in the grammar is longer,
// so a candidate run past this cannot be one.
const maxTokenLen = 24

// Analyze scores a parameter name and returns the verdict.
func (d *Detector) Analyze(name []byte) Verdict {
	if len(name) == 0 {
		return Verdict{}
	}
	src := name
	if len(src) > maxScan {
		src = src[:maxScan]
	}

	var sigs Signal
	var span types.Span
	found := false

	for i := 0; i < len(src); i++ {
		if src[i] != '$' {
			continue
		}
		// Scan the operator token: '$' plus the identifier bytes after it.
		// "$$hashKey" is reached by allowing a second '$' only at the start.
		j := i + 1
		if j < len(src) && src[j] == '$' {
			j++
		}
		for j < len(src) && isNameByte(src[j]) {
			j++
		}
		if j-i > maxTokenLen {
			i = j - 1
			continue
		}

		tok := string(src[i:j])
		if benign[tok] {
			i = j - 1
			continue
		}
		if s := classify(tok); s != 0 {
			sigs |= s
			if !found {
				span = types.SpanOf(i, j-i)
				found = true
			}
		}
		i = j - 1
	}

	total := 0
	for bit := Signal(1); bit != 0; bit <<= 1 {
		if sigs&bit != 0 {
			total += weightOf(bit)
		}
	}
	return Verdict{Signals: sigs, Score: total, Span: span}
}

// isNameByte reports whether a byte continues an operator token.
func isNameByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// Operator adapts the detector to the rule engine, reporting only names whose
// evidence includes at least one signal in accept.
//
// The mask exists because these findings are not equally certain, and one rule
// cannot carry two confidences. Database code execution ($where and friends) is
// unambiguous; query-operator injection is very nearly so, but some APIs expose
// MongoDB operators as their filter DSL on purpose — "?price[$gt]=100" is a
// documented feature of more than one framework. Splitting the mask lets the
// first block at Certain while the second is tunable independently.
//
// The mask also narrows Literals to the accepted tokens, so the code-execution
// rule contributes four strings to the prefilter rather than fifty. That is the
// difference between a selective automaton and a busy one.
//
// Operator is safe for concurrent use.
func Operator(accept Signal) rules.Operator {
	lits := make([]string, 0, len(operatorTokens))
	for tok, sig := range operatorTokens {
		if sig&accept != 0 {
			lits = append(lits, tok)
		}
	}
	// Sorted so a compile report and an automaton are byte-identical between
	// builds; map order is not.
	slices.Sort(lits)
	return &operator{d: New(), accept: accept, literals: lits}
}

type operator struct {
	d        *Detector
	accept   Signal
	literals []string
}

func (o *operator) Name() string { return "detect_nosqli" }

func (o *operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	v := o.d.Analyze(value)
	if !v.Detected() || v.Signals&o.accept == 0 {
		return rules.Match{}, false
	}
	return rules.Match{Span: v.Span}, true
}

// Literals are the byte sequences without which no accepted signal can fire.
//
// Derived from operatorTokens rather than restated, so the list cannot drift
// from the classifier. A name containing none of them scores zero, so the
// prefilter excludes it without evaluating anything.
func (o *operator) Literals() ([]string, bool) { return o.literals, true }

// Cost prices one analysis: a single pass over a short name.
func (o *operator) Cost() types.Fuel { return types.CostLiteralMatch * 2 }
