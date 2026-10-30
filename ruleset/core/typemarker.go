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
//
// The nesting separators are '.', '[' and ']' -- the ones recordArgName writes.
// A '/' is deliberately NOT one, because '/' is a *character inside a marker
// name*: jsonpickle keys its class on "py/object" and the Ruby marshal-to-JSON
// form on "rb/object". Splitting on '/' reduced both to "object", which is in no
// marker table, so a jsonpickle or Ruby gadget -- backslashed or dotted -- was
// never matched by this rule at all. The body parser never uses '/' to join a
// nested path (recordArgName joins with '.'), so a '/' seen here is always part
// of a single field name and must be kept.
func lastKeySegment(key string) string {
	if len(key) > maxParamNameLen {
		return ""
	}
	for i := len(key) - 1; i >= 0; i-- {
		switch key[i] {
		case '.', ']', '[':
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
// is not a name anything but a deserializer asks for.
//
// A backslash is required, full stop -- it is the PHP namespace separator, and
// also the one thing Literals() can key the prefilter on without matching every
// request (see there for why a dot cannot). So the forms this catches are the
// backslashed ones: `vendor\package\Class`. A value that is only dot-separated
// -- "subprocess.Popen" under "py/object", "System.Diagnostics.Process" under
// "$type", bare "java.lang.Runtime" -- is NOT matched here. The prefilter never
// surfaces a backslash-free value to this operator in the first place, so this
// is a hard scope limit, not a tunable one; covering the dotted markers needs
// the separate marker-name-anchored rule that Literals() describes.
//
// unambiguous comes from the *key* (a field called "__class" or "py/object" has
// no reading other than "instantiate this", a field called "class" or "@type"
// is a CSS class and a schema.org type far more often than a gadget). It is kept
// so the marker-name rule can tighten the bar per key class, but because a
// backslash and two segments are already required of every value, it does not by
// itself change this function's verdict today.
//
// .NET writes "Namespace.Type, Assembly"; the comma is stripped below so only
// the type name is weighed -- though a purely dotted .NET name still falls under
// the backslash limit above.
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

// dottedMarkerKeys are the subset of unambiguous markers whose *dotted* value is
// an attack in its own right, not just the backslashed PHP form TypeMarkerRule
// already reads.
//
// jsonpickle keys its class on "py/object" and the Ruby marshal-to-JSON form on
// "rb/object", and both name the class as a dotted path -- "subprocess.Popen",
// "os.system" -- never as a PHP namespace, so TypeMarkerRule's backslash
// prefilter cannot reach them. These two keys also have no benign reading: a
// client has no reason to post a pickled Python or Ruby object to an API, and an
// endpoint that unpickles one is already the vulnerability. That is what makes
// blocking a dotted value under them safe where the same relaxation under
// "@class" or "$type" is not -- Jackson default typing and Json.NET legitimately
// carry dotted class names in those, so they stay backslash-only.
var dottedMarkerKeys = map[string]bool{
	"py/object": true,
	"rb/object": true,
}

// TypeMarkerDottedRule reports a Python or Ruby polymorphic marker whose value
// is a dotted class path -- the form TypeMarkerRule is structurally unable to
// see.
//
// TypeMarkerRule keys its prefilter on a backslash, so a backslash-free value --
// which is every Python and Ruby class name -- never reaches its operator. This
// rule keys instead on the marker *name* in the argument-name collection, which
// is the selective anchor the engine can afford: a dot appears in nearly every
// value and cannot be prefiltered without pricing every request, but "py/object"
// and "rb/object" appear in essentially no benign argument name. When the name
// fires, the operator reads the paired value through the sibling view and asks
// whether it is a dotted class path. This is the "rule of its own, anchored on
// the marker name" that TypeMarkerRule's Literals comment defers to.
func TypeMarkerDottedRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:    id,
		Phase: types.PhaseRequestHeaders,
		// The name collection, because the evidence is the name. The value is
		// read from the sibling view once the name has fired.
		Targets:    []types.Target{{Kind: types.TargetArgNames}},
		Transforms: decodeChain,
		Op:         typeMarkerDottedOp{},
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "Polymorphic type marker selecting a class (Python/Ruby)",
		Tags:       []string{"rce", "deserialization", "owasp-a08"},
	}
}

type typeMarkerDottedOp struct{}

func (typeMarkerDottedOp) Name() string { return "type_marker_dotted" }

func (typeMarkerDottedOp) Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool) {
	if ctx == nil {
		return rules.Match{}, false
	}
	// value is an argument *name*. Its leaf is the marker; the class name is in
	// the sibling argument that shares that name.
	leaf := lastKeySegment(string(value))
	if !dottedMarkerKeys[leaf] {
		return rules.Match{}, false
	}
	classVal, ok := siblingClassValue(ctx, value, leaf)
	if !ok {
		return rules.Match{}, false
	}
	if isDottedClassName(classVal) {
		return rules.WholeValue(value), true
	}
	return rules.Match{}, false
}

func (typeMarkerDottedOp) Literals() ([]string, bool) {
	// Both marker names, and nothing weaker. Each is a selective token absent
	// from benign argument names, so benign rule evaluation stays at zero --
	// which the dot this covers could never do.
	return []string{"py/object", "rb/object"}, true
}

func (typeMarkerDottedOp) Cost() types.Fuel { return types.CostLiteralMatch * 2 }

// siblingClassValue returns the value paired with an argument name whose leaf is
// a marker.
//
// The exact name is tried first -- the top-level case, where the name collection
// and the value collection share a key. Only on a miss does it scan by leaf,
// which covers a nested marker: the value collection keys it with its flattened
// path ("payload.py/object") while the name collection emits the bare leaf. The
// scan runs only after a selective marker literal has already fired, so it is
// off the benign path entirely, and its length is the argument count of a
// request that already carries a pickle marker.
func siblingClassValue(ctx *rules.EvalContext, name []byte, leaf string) ([]byte, bool) {
	if v, ok := ctx.SiblingValue(string(name)); ok {
		return v, true
	}
	for i, n := range ctx.Siblings.Names {
		if i >= len(ctx.Siblings.Values) {
			break
		}
		if lastKeySegment(string(n)) == leaf {
			return ctx.Siblings.Values[i], true
		}
	}
	return nil, false
}

// isDottedClassName reports whether v is a dotted or namespaced class path: at
// least two identifier segments joined by a separator. It mirrors
// isQualifiedClassName's per-segment validation but does not require a
// backslash, because Python and Ruby class paths are not written with one --
// Python joins with '.' ("subprocess.Popen"), Ruby with '::'
// ("Gem::Requirement"), and a backslash is accepted too so the same test covers
// a PHP namespace that arrives under one of these keys. A bare word, a number, a
// version and a media type all fail the two-segment-of-identifiers test; so does
// a value whose first segment character is not a letter or '_', and a lone ':'
// (which no class path contains) rejects outright.
func isDottedClassName(v []byte) bool {
	if len(v) > maxClassNameLen {
		return false
	}
	// .NET writes "Namespace.Type, Assembly"; weigh only the type name.
	for i, c := range v {
		if c == ',' {
			v = v[:i]
			break
		}
	}
	if len(v) < 3 {
		return false
	}
	segments := 0
	start := 0
	i := 0
	for i <= len(v) {
		sep := 0
		switch {
		case i == len(v):
			sep = 0 // end of input closes the final segment
		case v[i] == '.' || v[i] == '\\':
			sep = 1
		case v[i] == ':':
			// A class path uses '::' (Ruby); a single ':' belongs to no class
			// name and is a reason to reject the whole value.
			if i+1 < len(v) && v[i+1] == ':' {
				sep = 2
			} else {
				return false
			}
		default:
			i++
			continue
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
		if sep == 0 {
			break
		}
		i += sep
		start = i
	}
	return segments >= 2
}
