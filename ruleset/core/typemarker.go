// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// typeMarkerKeys are the field names a deserializer reads to decide which class
// to instantiate.
//
// Each one is a specific library's polymorphic-typing feature, and every one of
// them is a documented remote-code-execution primitive when the type is
// attacker-chosen:
//
//   - "__class", "class"   PHP: Yii's AttributeBehavior chain, Guzzle's FnStream
//   - "@type", "$type"     Jackson's @JsonTypeInfo and Json.NET TypeNameHandling
//   - "__type"             .NET JavaScriptSerializer
//   - "javaClass"          XStream and the JSON-lib family
//   - "@class"             Jackson's default typing
//   - "py/object"          jsonpickle
//   - "rb/object"          Ruby's JSON additions
//
// These are field *names*, so the rule reads ctx.Key. That is the whole reason
// it can exist: "GuzzleHttp\Psr7\FnStream" appearing in a request is a string,
// and appearing as the value of "__class" is a gadget being selected.
//
// The value false marks a key that also has an ordinary reading, and those are
// held to a higher bar: "class" is a CSS class and "@type" is a schema.org type
// in far more traffic than it is a gadget. "__proto__" and "constructor" are
// deliberately absent -- they are prototype pollution, a different bug with a
// different shape, and putting them here would be a rule doing two jobs badly.
var typeMarkerKeys = map[string]bool{
	"__class": true, "@class": true, "javaclass": true,
	"py/object": true, "rb/object": true, "__type": true,

	"class": false, "@type": false, "$type": false,
}

// TypeMarkerRule reports a polymorphic type marker naming a class.
//
// This is the JSON form of object injection, and it is invisible to every other
// rule here. Rule 4007 reads PHP's serialize() grammar; detect/javaser reads
// Java's stream header. A gadget chain expressed as JSON has neither — it is
// well-formed JSON containing well-formed strings, and only the *field name*
// says the string will be turned into an object.
//
// It requires a namespaced or package-qualified name rather than any string,
// because "type" and "class" are ordinary words in ordinary APIs. A CSS class,
// a product type and a Java package are told apart by whether the value carries
// a separator that only a fully-qualified name carries.
func TypeMarkerRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:    id,
		Phase: types.PhaseRequestHeaders,
		// Arguments only: the field name is the evidence, so an unkeyed
		// collection can never match.
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Transforms: decodeChain,
		Op:         typeMarkerOp{},
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "Polymorphic type marker selecting a class",
		Tags:       []string{"rce", "deserialization", "owasp-a08"},
	}
}

// lastKeySegment returns the final component of a flattened field path.
//
// The body parser emits nested JSON fields as a path -- a gadget arriving as
// {"payload": {"__class": "..."}} is keyed "payload.__class", and an array
// element as "items[0].__class". Matching the whole path would miss every
// marker that is not at the top level, which is where they actually appear:
// a POP chain is a nested object by construction.
func lastKeySegment(key string) string {
	if len(key) > maxParamNameLen {
		return ""
	}
	for i := len(key) - 1; i >= 0; i-- {
		switch key[i] {
		case '.', ']', '[', '/':
			return lowerASCII(key[i+1:])
		}
	}
	return lowerASCII(key)
}

type typeMarkerOp struct{}

func (typeMarkerOp) Name() string { return "type_marker" }

func (typeMarkerOp) Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool) {
	if ctx == nil || ctx.Target.Kind == types.TargetArgNames {
		return rules.Match{}, false
	}
	unambiguous, ok := typeMarkerKeys[lastKeySegment(ctx.Key)]
	if !ok {
		return rules.Match{}, false
	}
	if isQualifiedClassName(value, unambiguous) {
		return rules.WholeValue(value), true
	}
	return rules.Match{}, false
}

// Literals is a backslash, and that is also the rule's stated limit.
//
// A dot would cover Java and .NET markers -- "java.lang.Runtime",
// "System.Diagnostics.Process" -- and a dot appears in almost every value in
// almost every request. Declaring it took benign rule evaluation from 6 to 8 on
// TestBenignTrafficBoundsRuleEvaluation's corpus, which is the guard that exists
// to stop precisely this: a rule whose prefilter cannot discriminate is a rule
// every request pays for.
//
// So this rule covers PHP namespaces, where the separator is rare enough to key
// an automaton on, and does not claim the dotted forms. Both gadget chains in
// the CVE corpus it was written for are PHP. Covering Java and .NET honestly
// needs a different anchor -- the marker *name* in the raw body, where
// `"@type"` is itself a selective literal -- and that is a rule of its own
// rather than a wider net here.
func (typeMarkerOp) Literals() ([]string, bool) {
	return []string{`\`}, true
}

func (typeMarkerOp) Cost() types.Fuel { return types.CostLiteralMatch * 2 }

// isQualifiedClassName reports whether v looks like a fully-qualified type name.
//
// The separator carries the evidence. "product" and "primary" are values an
// ordinary API puts in a field called "type" or "class"; `GuzzleHttp\Psr7\FnStream`
// and "java.lang.Runtime" are not names anything but a deserializer asks for.
//
// unambiguous relaxes the bar, and it comes from the *key* rather than the
// value. A field called "__class" or "py/object" has no reading other than
// "instantiate this", so two segments are enough and "subprocess.Popen" is
// caught. A field called "class" or "@type" is a CSS class and a schema.org type
// in far more traffic than it is a gadget, so a dotted value must be genuinely
// namespaced -- three segments -- or carry a backslash, which nothing but a PHP
// namespace does. That is what tells "java.lang.Runtime" from "photo.jpeg".
//
// .NET writes "Namespace.Type, Assembly"; only the part before the comma is the
// type name.
func isQualifiedClassName(v []byte, unambiguous bool) bool {
	if len(v) > maxClassNameLen {
		return false
	}
	for i, c := range v {
		if c == ',' {
			v = v[:i]
			break
		}
	}
	if len(v) < 3 {
		return false
	}

	segments, backslash := 0, false
	start := 0
	for i := 0; i <= len(v); i++ {
		if i < len(v) {
			if v[i] == '\\' {
				backslash = true
			} else if v[i] != '.' {
				continue
			}
		}
		seg := v[start:i]
		if len(seg) == 0 {
			return false
		}
		c := seg[0]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_') {
			return false
		}
		for _, b := range seg {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
				b >= '0' && b <= '9' || b == '_' || b == '$' || b == '-') {
				return false
			}
		}
		segments++
		start = i + 1
	}
	// A backslash is required, not merely sufficient: see Literals for why the
	// dotted forms are out of scope rather than merely unimplemented.
	if segments < 2 || !backslash {
		return false
	}
	// An ambiguous field name still has to carry a genuinely namespaced value.
	// PHP namespaces are at least vendor\package, so this costs nothing real.
	return unambiguous || segments >= 2
}

// maxClassNameLen bounds the scan. A fully-qualified name is long but not
// unbounded, and this reads attacker input.
const maxClassNameLen = 256
