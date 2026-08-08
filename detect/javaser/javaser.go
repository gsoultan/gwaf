// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package javaser detects Java attacks by reading invocation structure rather
// than by listing class names.
//
// # Why not a class list
//
// The Core Rule Set answers this family with java-classes.data: several hundred
// package prefixes, blocked wherever they appear. It is the largest single test
// file in the CRS corpus and it is also why that rule sits behind a paranoia
// level — "com.sun.org.apache" in a bug report, a stack trace pasted into a
// support form, or a dependency named in a changelog are all ordinary text, and
// blocking them is how a WAF gets uninstalled.
//
// The list is also unbounded in the wrong direction. Gadget chains are found in
// libraries nobody has enumerated yet; ysoserial gained new ones for years. A
// detector that has to be told each class name is always behind.
//
// # What is actually invariant
//
// A Java attack is a *reference to executable machinery placed where data was
// expected*. The class name varies; the machinery does not:
//
//   - a serialized object stream begins with two magic bytes, and nothing else
//     does;
//   - a JNDI lookup is an interpolation whose head names a remote scheme;
//   - Log4Shell's obfuscation is *nested* interpolation — "${${lower:j}ndi:" —
//     and nesting is itself the tell, because no template engine emits it and no
//     author writes it;
//   - reaching a class loader is a property path — "class.module.classLoader" —
//     not a name;
//   - spawning a process is a call chain, "Runtime.getRuntime().exec(".
//
// So a class name on its own scores nothing here. It scores only in *invocation
// position*: followed by a call, inside an interpolation, or on a property path
// that ends somewhere dangerous. "We had to patch com.sun.org.apache" has a name
// and no structure, and is not an attack.
package javaser

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Signal is one piece of structural evidence.
type Signal uint16

// Signals.
const (
	// SignalSerializedStream is the header of a Java object stream: 0xACED
	// followed by a version, or its base64 spelling "rO0AB". Unambiguous —
	// nothing in text begins this way, which is why it carries a verdict alone.
	SignalSerializedStream Signal = 1 << iota

	// SignalNestedInterpolation is "${" appearing inside an unclosed "${".
	//
	// This is Log4Shell's obfuscation — "${${lower:j}ndi:" and "${${::-j}ndi:"
	// — and it is the strongest signal in the package precisely because it has
	// no benign reading. A template engine substitutes a name; it does not
	// compose one out of nested substitutions. An author writing "${total}" does
	// not nest.
	SignalNestedInterpolation

	// SignalLookupScheme is an interpolation whose head names a remote lookup:
	// jndi, ldap, ldaps, rmi, dns, iiop, corba, nis, nds. Fetching a value from
	// a network location while rendering a log line or a template is the whole
	// of Log4Shell.
	SignalLookupScheme

	// SignalClassLoaderPath is a property path that walks to a class loader:
	// "class.module.classLoader", "getClass().getClassLoader", "Class.forName".
	// Spring4Shell (CVE-2022-22965) is exactly this reached through data
	// binding, and the path is fixed even though the entry point is not.
	SignalClassLoaderPath

	// SignalProcessSpawn is a call chain that starts a process:
	// "Runtime.getRuntime().exec(", "new ProcessBuilder(", ".getRuntime().exec".
	// The chain is the evidence, not the word "Runtime".
	SignalProcessSpawn

	// SignalTypeInvocation is an expression-language type reference being
	// called: SpEL's "T(java.lang.Runtime)" or OGNL's "@java.lang.Runtime@".
	// Both name a type in order to invoke it, which ordinary text does not.
	SignalTypeInvocation

	// SignalScriptEngine is a scripting bridge being reached —
	// "ScriptEngineManager", "javax.script", "getEngineByName". Weaker: these
	// appear in documentation about scripting. Corroborating.
	SignalScriptEngine

	// SignalInterpolation is a bare "${...}". Weak by design and never enough
	// alone: every template language in existence uses it and half the shell
	// scripts on disk contain one. It exists to corroborate.
	SignalInterpolation
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
	if s&SignalSerializedStream != 0 {
		add("serialized_stream")
	}
	if s&SignalNestedInterpolation != 0 {
		add("nested_interpolation")
	}
	if s&SignalLookupScheme != 0 {
		add("lookup_scheme")
	}
	if s&SignalClassLoaderPath != 0 {
		add("class_loader_path")
	}
	if s&SignalProcessSpawn != 0 {
		add("process_spawn")
	}
	if s&SignalTypeInvocation != 0 {
		add("type_invocation")
	}
	if s&SignalScriptEngine != 0 {
		add("script_engine")
	}
	if s&SignalInterpolation != 0 {
		add("interpolation")
	}
	if len(out) == 0 {
		return "none"
	}
	return string(out)
}

// weightOf prices each signal by what it means alone.
//
// The strong ones reach the threshold by themselves because none has a benign
// reading: nobody types a serialization header, nests an interpolation, or walks
// to a class loader by accident. The weak ones are ordinary in documentation and
// only matter together.
func weightOf(s Signal) int {
	switch s {
	case SignalSerializedStream, SignalNestedInterpolation, SignalLookupScheme,
		SignalClassLoaderPath, SignalProcessSpawn:
		return 5
	case SignalTypeInvocation:
		return 4
	case SignalScriptEngine:
		return 2
	case SignalInterpolation:
		return 1
	default:
		return 0
	}
}

// Threshold is the score at or above which a value is reported.
const Threshold = 5

// Verdict is the result of analysing one value.
type Verdict struct {
	Signals Signal
	Score   int
	Span    types.Span
}

// Detected reports whether the evidence reached the threshold.
func (v Verdict) Detected() bool { return v.Score >= Threshold }

// Detector analyses values for Java injection.
//
// A Detector is immutable and safe for concurrent use.
type Detector struct{}

// New returns a Detector.
func New() *Detector { return &Detector{} }

// Name implements the operator contract.
func (*Detector) Name() string { return "detect_javaser" }

// maxScan bounds how far the structural scans look. A payload declares itself
// early; a value longer than this is bounded rather than refused, because the
// engine's fuel meter owns the overall ceiling.
const maxScan = 8192

// Analyze scores value and returns the verdict.
func (d *Detector) Analyze(value []byte) Verdict {
	src := value
	if len(src) > maxScan {
		src = src[:maxScan]
	}

	var sigs Signal
	if hasSerializedHeader(src) {
		sigs |= SignalSerializedStream
	}
	sigs |= scanInterpolation(src)
	sigs |= scanCallChains(src)

	total := 0
	for bit := Signal(1); bit != 0; bit <<= 1 {
		if sigs&bit != 0 {
			total += weightOf(bit)
		}
	}
	return Verdict{Signals: sigs, Score: total, Span: types.SpanOf(0, len(value))}
}

// hasSerializedHeader reports a Java object stream header.
//
// 0xAC 0xED is STREAM_MAGIC and is followed by a two-byte version, currently 5.
// "rO0AB" is the same bytes base64-encoded, which is how the header survives a
// JSON field or a cookie. Both are checked anywhere in the value rather than
// only at the start, because the stream is routinely embedded.
func hasSerializedHeader(v []byte) bool {
	for i := 0; i+3 < len(v); i++ {
		if v[i] == 0xac && v[i+1] == 0xed && v[i+2] == 0x00 {
			return true
		}
	}
	return indexFold(v, "ro0ab") >= 0
}

// lookupSchemes are the interpolation heads that reach the network.
var lookupSchemes = []string{
	"jndi", "ldap", "ldaps", "rmi", "dns", "iiop", "corba", "nis", "nds",
}

// scanInterpolation reads "${...}" structure.
//
// Three things are distinguished, and the ordering matters. A nested "${" is
// scored first and on its own, because obfuscation is the reason to nest and no
// template engine produces it. A scheme head is scored next. A plain
// interpolation is scored last and barely, because it is ubiquitous.
func scanInterpolation(v []byte) Signal {
	var sigs Signal
	for i := 0; i+1 < len(v); i++ {
		if v[i] != '$' || v[i+1] != '{' {
			continue
		}
		sigs |= SignalInterpolation

		// Everything up to the matching close, bounded.
		end := i + 2
		depth := 1
		nested := false
		for end < len(v) && depth > 0 {
			switch {
			case v[end] == '$' && end+1 < len(v) && v[end+1] == '{':
				depth++
				nested = true
				end++
			case v[end] == '}':
				depth--
			}
			end++
		}
		if nested {
			sigs |= SignalNestedInterpolation
		}

		body := v[i+2 : min(end, len(v))]
		if head, ok := interpolationHead(body); ok {
			for _, s := range lookupSchemes {
				if equalFold(head, s) {
					sigs |= SignalLookupScheme
					break
				}
			}
		}
		// A type reference being invoked inside the interpolation.
		if indexFold(body, "t(") >= 0 || indexByte(body, '@') >= 0 {
			if indexFold(body, "java.") >= 0 || indexFold(body, "javax.") >= 0 {
				sigs |= SignalTypeInvocation
			}
		}
	}
	return sigs
}

// interpolationHead returns the scheme name before the first ':' in an
// interpolation body, if the body has one.
func interpolationHead(body []byte) ([]byte, bool) {
	for i := 0; i < len(body); i++ {
		switch {
		case body[i] == ':':
			return body[:i], i > 0
		case isNameByte(body[i]):
		default:
			return nil, false
		}
	}
	return nil, false
}

// classLoaderPaths are property walks that end at machinery rather than data.
var classLoaderPaths = []string{
	"class.module.classloader", "class.classloader", "getclassloader",
	"class.forname", "forname(", "defineclass(",
}

// spawnChains are call chains that start a process.
//
// ".exec(" is deliberately absent. It looks like the obvious member and it is
// the wrong one: it fires on "0.eXeC(", it is a method name in half a dozen
// unrelated APIs, and no declared literal can cover it without making the rule a
// candidate for every value containing a dot and a parenthesis. The fuzz harness
// found it. Every real payload reaches a process through getRuntime() or
// ProcessBuilder, both of which are here.
var spawnChains = []string{
	"getruntime()", "processbuilder(",
}

// scanCallChains scores the call and property structure that reaches machinery.
//
// Each is a *chain*, not a name. "Runtime" alone is a word that appears in
// prose about the JVM; "getRuntime().exec(" is a sentence nobody writes about
// anything except running a command.
func scanCallChains(v []byte) Signal {
	var sigs Signal
	for _, p := range classLoaderPaths {
		if indexFold(v, p) >= 0 {
			sigs |= SignalClassLoaderPath
			break
		}
	}
	for _, p := range spawnChains {
		if indexFold(v, p) >= 0 {
			sigs |= SignalProcessSpawn
			break
		}
	}
	// SpEL and OGNL type references outside an interpolation.
	if indexFold(v, "@java.lang.") >= 0 || indexFold(v, "t(java.lang.") >= 0 {
		sigs |= SignalTypeInvocation
	}
	for _, p := range []string{"scriptenginemanager", "getenginebyname", "javax.script"} {
		if indexFold(v, p) >= 0 {
			sigs |= SignalScriptEngine
			break
		}
	}
	return sigs
}

// ---- byte helpers -----------------------------------------------------------

func isNameByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '-'
}

func fold(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func equalFold(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if fold(a[i]) != b[i] {
			return false
		}
	}
	return true
}

// indexFold finds a lowercase needle in v, folding v as it goes.
func indexFold(v []byte, needle string) int {
	if len(needle) == 0 || len(v) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(v); i++ {
		ok := true
		for j := 0; j < len(needle); j++ {
			if fold(v[i+j]) != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func indexByte(v []byte, c byte) int {
	for i := range v {
		if v[i] == c {
			return i
		}
	}
	return -1
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---- operator ---------------------------------------------------------------

// Operator adapts the detector to the rule engine.
//
// A semantic detector is an operator rather than a separate tier: the engine
// dispatches through Operator.Eval and has no L1 stage of its own.
func Operator() rules.Operator { return &operator{d: New(), threshold: Threshold} }

// OperatorAt returns an operator that reports at a caller-chosen score.
//
// This is how a rule earns a confidence tier below High out of the *same*
// evidence, rather than by writing a second, sloppier detector. Lower is more
// sensitive and less certain; a ruleset that lowers it is opting into false
// positives it has decided it can absorb, and that decision belongs to whoever
// runs the traffic.
func OperatorAt(threshold int) rules.Operator {
	return &operator{d: New(), threshold: threshold}
}

type operator struct {
	d         *Detector
	threshold int
}

func (o *operator) Name() string { return "detect_javaser" }

func (o *operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	v := o.d.Analyze(value)
	if v.Score < o.threshold {
		return rules.Match{}, false
	}
	return rules.Match{Span: v.Span}, true
}

// Literals are the byte sequences without which no scoring signal can fire.
//
// Every strong signal needs one of these: an interpolation opener, a
// serialization header, a class-loader walk, or a spawn chain. Declaring them
// keeps the rule prefilterable, so a benign request touches this detector only
// when one of them is present.
func (o *operator) Literals() ([]string, bool) {
	return []string{
		"${", "\xac\xed", "ro0ab", "classloader", "forname",
		"getruntime", "processbuilder", "javax.script", "scriptengine",
		"@java.lang.", "defineclass",
	}, true
}

func (o *operator) Cost() types.Fuel { return types.CostLiteralMatch * 12 }
