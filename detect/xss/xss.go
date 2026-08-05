// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package xss detects cross-site scripting by reading markup structure rather
// than matching strings.
//
// # Why this is harder than SQL
//
// A SQL parser rejects malformed input; an HTML parser never does. Browsers
// recover from anything, which means a payload does not have to be well formed
// to execute — "<svg/onload=alert(1)" has no closing bracket and works anyway.
// There is correspondingly more room for a detector to be wrong in both
// directions, so the signals here are narrower than the SQL ones and the
// false-positive corpus is larger.
//
// # What is actually dangerous
//
// Not "angle brackets". Not "the word script". Users write "<b>bold</b>" in
// comment fields and "if (a < b)" in bug reports, and a detector that blocks
// those gets switched off.
//
// What is dangerous is a small, enumerable set of structures:
//
//   - a tag that executes on insertion — script, iframe, object, svg, and the
//     handful of others browsers run without interaction;
//   - an event-handler attribute, which is how a harmless tag like img becomes
//     a payload;
//   - a scheme that executes — javascript:, vbscript:, data:text/html;
//   - breaking out of a quoted attribute to add either of the above;
//   - a CSS expression or binding, which older engines execute.
//
// Each is checked in *position*: an "onerror" in prose is a word, while an
// "onerror=" inside a tag is a handler. That distinction is the whole detector.
//
// # Contexts
//
// Injected values usually land inside an attribute, so the payload's first job
// is to escape it. As in detect/sqli, the value is analysed both as-is and as
// if it were interpolated inside a quoted attribute, and the strongest verdict
// wins. gwaf does not know which the origin will produce.
package xss

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Signal is one piece of structural evidence.
type Signal uint16

// Signals.
const (
	// SignalExecutingTag is a tag browsers run on insertion: script, iframe,
	// object, embed, svg, and similar. Ordinary user markup does not contain
	// these; ordinary user markup contains b, i, em, a, p.
	SignalExecutingTag Signal = 1 << iota

	// SignalEventHandler is an on*= attribute inside a tag. This is what turns
	// a harmless element into a payload — "<img src=x onerror=alert(1)>" — and
	// it is why detecting dangerous *tags* alone is not enough.
	SignalEventHandler

	// SignalScriptURI is a scheme that executes rather than fetches, occurring
	// anywhere in the value. Weak alone: "the javascript: scheme is blocked" is
	// a sentence someone writes.
	SignalScriptURI

	// SignalSchemeInAttribute is an executing scheme in the value position of a
	// URI attribute — href, src, formaction. That is not a mention of a scheme,
	// it is a link that runs code, and it is unambiguous.
	SignalSchemeInAttribute

	// SignalAttributeBreakout is a quote followed by what looks like a new
	// attribute: the shape of escaping attr="..." to add a handler.
	SignalAttributeBreakout

	// SignalStyleExpression is CSS that executes — expression(), -moz-binding,
	// behavior:url(). Legacy, still present in the wild.
	SignalStyleExpression

	// SignalTagBreakout is closing one element to open another, which escapes
	// raw-text contexts like <textarea> and <title>.
	SignalTagBreakout

	// SignalSinkCall is a JavaScript sink invoked with arguments. Weak on its
	// own — developers discuss eval() — and corroborating alongside anything
	// else.
	SignalSinkCall

	// SignalCommentBreakout is "-->" escaping an HTML comment.
	SignalCommentBreakout
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
	if s&SignalExecutingTag != 0 {
		add("executing_tag")
	}
	if s&SignalEventHandler != 0 {
		add("event_handler")
	}
	if s&SignalScriptURI != 0 {
		add("script_uri")
	}
	if s&SignalSchemeInAttribute != 0 {
		add("scheme_in_attribute")
	}
	if s&SignalAttributeBreakout != 0 {
		add("attribute_breakout")
	}
	if s&SignalStyleExpression != 0 {
		add("style_expression")
	}
	if s&SignalTagBreakout != 0 {
		add("tag_breakout")
	}
	if s&SignalSinkCall != 0 {
		add("sink_call")
	}
	if s&SignalCommentBreakout != 0 {
		add("comment_breakout")
	}
	if len(out) == 0 {
		return "none"
	}
	return string(out)
}

// weightOf prices each signal by what it means alone.
//
// Threshold is 5, so anything weighted 5 is sufficient by itself. The weak
// signals are weak deliberately: a lone "-->" or a mention of eval() appears in
// real text, and pricing those to fire alone is how a detector starts blocking
// bug reports about XSS.
func weightOf(s Signal) int {
	switch s {
	case SignalExecutingTag, SignalEventHandler, SignalStyleExpression,
		SignalSchemeInAttribute:
		return 5
	case SignalScriptURI:
		return 3
	case SignalAttributeBreakout, SignalTagBreakout:
		return 3
	case SignalSinkCall:
		return 2
	case SignalCommentBreakout:
		return 2
	default:
		return 0
	}
}

// Threshold is the score at or above which a value is reported.
const Threshold = 5

// executingTags run without any user interaction once inserted.
//
// Deliberately excludes the tags people actually write in comment fields — b,
// i, em, strong, p, a, code, pre, ul, li. An <a> becomes dangerous through its
// href scheme, which SignalScriptURI covers, not through being an <a>.
var executingTags = map[string]bool{
	"script": true, "iframe": true, "object": true, "embed": true,
	"applet": true, "svg": true, "math": true, "base": true,
	"meta": true, "link": true, "style": true, "frame": true,
	"frameset": true, "isindex": true, "portal": true,
	"animate": true, "set": true, "handler": true,
}

// rawTextTags hold unparsed text, so closing one escapes into markup context.
var rawTextTags = map[string]bool{
	"textarea": true, "title": true, "script": true, "style": true,
	"xmp": true, "iframe": true, "noembed": true, "noframes": true,
	"plaintext": true,
}

// sinks are JavaScript functions that turn a string into code.
var sinks = map[string]bool{
	"eval": true, "settimeout": true, "setinterval": true,
	"function": true, "atob": true, "unescape": true,
	"execscript": true, "createcontextualfragment": true,
}

// executingSchemes execute rather than fetch.
var executingSchemes = []string{
	"javascript:", "vbscript:", "livescript:", "mocha:",
	"data:text/html", "data:application/javascript", "data:text/javascript",
}

// Verdict is the result of analysing one value.
type Verdict struct {
	Signals Signal
	Score   int
	Span    types.Span
}

// Detected reports whether the evidence reached the threshold.
func (v Verdict) Detected() bool { return v.Score >= Threshold }

// Detector analyses values for cross-site scripting.
//
// A Detector is immutable and safe for concurrent use.
type Detector struct{}

// New returns a Detector.
func New() *Detector { return &Detector{} }

// Name implements the operator contract.
func (*Detector) Name() string { return "detect_xss" }

// maxScan bounds how much of a value is analysed.
//
// Every signal is local — a tag and its attributes, a scheme, a quote and what
// follows it — so a payload that needs more than this to express itself does
// not exist. The bound keeps a large body from driving unbounded work.
const maxScan = 64 << 10

// Analyze scores value and returns the verdict.
func (d *Detector) Analyze(value []byte) Verdict {
	if len(value) == 0 {
		return Verdict{}
	}
	src := value
	if len(src) > maxScan {
		src = src[:maxScan]
	}

	sigs := scanMarkup(src)

	// Attribute breakout: the value closes a quoted attribute and starts what
	// looks like a new one. Checked separately because it is about the boundary
	// with markup the value did not contain, so there is no tag to anchor to.
	sigs |= scanBreakout(src)

	total := 0
	for bit := Signal(1); bit != 0; bit <<= 1 {
		if sigs&bit != 0 {
			total += weightOf(bit)
		}
	}
	return Verdict{Signals: sigs, Score: total, Span: types.SpanOf(0, len(value))}
}

// scanMarkup walks the value looking for tag, scheme, and sink structure.
func scanMarkup(src []byte) Signal {
	var sigs Signal

	for i := 0; i < len(src); i++ {
		switch src[i] {
		case '<':
			// A '<' is only a tag if a name follows immediately. "if (a < b)"
			// has a space and is arithmetic; "</textarea>" and "<svg/onload"
			// are markup. This single check is what keeps prose out.
			j := i + 1
			closing := false
			if j < len(src) && src[j] == '/' {
				closing = true
				j++
			}
			if j >= len(src) || !isAlpha(src[j]) {
				continue
			}

			nameStart := j
			for j < len(src) && isNameByte(src[j]) {
				j++
			}
			name := lowerWord(src[nameStart:j])

			if closing {
				// Closing a raw-text element escapes into markup context, but
				// only if something follows it to exploit that.
				if rawTextTags[name] && hasMarkupAfter(src, j) {
					sigs |= SignalTagBreakout
				}
				continue
			}

			// A tag name alone is not a tag. To be markup the element must be
			// either *completed* by a '>' or *elaborated* by attributes; text
			// that merely names a tag is neither.
			//
			// This distinction was found by calibration, not by reasoning: the
			// benign corpus contains gateon's own SecLang WAF rules, whose
			// regexes legitimately contain "<script" inside a quoted string
			// with no '>' anywhere after it. A firewall that blocks an operator
			// from saving a rule mentioning <script is the classic failure
			// where the WAF blocks the security team.
			//
			// The narrow cost is an executing tag left unclosed and carrying no
			// name=value attribute, relying on surrounding markup to complete
			// it. Such a payload still needs an attribute or a handler to do
			// anything, and both are detected independently.
			completed, attrSigs := scanTag(src, j)
			if executingTags[name] && completed {
				sigs |= SignalExecutingTag
			}
			sigs |= attrSigs
			i = j - 1

		case 'j', 'J', 'v', 'V', 'l', 'L', 'm', 'M', 'd', 'D':
			// Lead bytes of the executing schemes, checked here so the common
			// case is one comparison rather than a substring search per scheme.
			if matchesScheme(src, i) {
				sigs |= SignalScriptURI
			}

		case 'e', 'E':
			// expression( in a style context.
			if hasFoldedPrefix(src[i:], "expression") && callFollows(src, i+len("expression")) {
				sigs |= SignalStyleExpression
			}

		case '-':
			if hasFoldedPrefix(src[i:], "-moz-binding") {
				sigs |= SignalStyleExpression
			}
			// "-->" escapes an HTML comment.
			if i+2 < len(src) && src[i+1] == '-' && src[i+2] == '>' {
				sigs |= SignalCommentBreakout
			}

		case 'b', 'B':
			if hasFoldedPrefix(src[i:], "behavior:") {
				sigs |= SignalStyleExpression
			}
		}

		// Sink calls anywhere: eval(...), setTimeout(...), atob(...).
		if isAlpha(src[i]) && (i == 0 || !isNameByte(src[i-1])) {
			j := i
			for j < len(src) && isNameByte(src[j]) {
				j++
			}
			if sinks[lowerWord(src[i:j])] && callFollows(src, j) {
				sigs |= SignalSinkCall
			}
		}
	}
	return sigs
}

// scanTag walks attributes from just after a tag name to the closing bracket.
//
// Position is what matters. "onerror" as a word in prose is nothing; "onerror="
// between a tag name and its '>' is a handler the browser will run.
//
// The first result reports whether this is markup at all: a tag is markup when
// it is completed by '>' or carries at least one attribute. A bare name
// followed by a quote, with no '>' after it, is text about a tag.
func scanTag(src []byte, i int) (completed bool, sigs Signal) {
	sawAttr := false

	for i < len(src) && src[i] != '>' {
		// Attribute names may be separated by whitespace or, in browsers, by
		// '/' — which is why "<svg/onload=alert(1)" works.
		if isSpace(src[i]) || src[i] == '/' {
			i++
			continue
		}
		if !isAlpha(src[i]) {
			i++
			continue
		}

		nameStart := i
		for i < len(src) && isNameByte(src[i]) {
			i++
		}
		attr := lowerWord(src[nameStart:i])

		// Skip to the value, if any.
		j := i
		for j < len(src) && isSpace(src[j]) {
			j++
		}
		if j < len(src) && src[j] == '=' {
			// A real attribute is name=value. A bare word is not: the text
			// following an unclosed tag name is full of words, and counting
			// those as attributes is what let a SecLang directive
			// ("...msg:'possible xss'...") read as markup.
			sawAttr = true
			j++
			for j < len(src) && isSpace(src[j]) {
				j++
			}

			// An event handler with a value is executable code.
			if isEventHandler(attr) {
				sigs |= SignalEventHandler
			}
			if isURIAttr(attr) && matchesScheme(src, j) {
				sigs |= SignalSchemeInAttribute
			}
			if attr == "style" && hasFoldedSub(src[j:], "expression") {
				sigs |= SignalStyleExpression
			}

			// Step over the value so its contents are not read as attributes.
			i = skipAttrValue(src, j)
			continue
		}

		// A bare handler attribute with no value cannot execute, so it is not
		// reported: "<div onerror>" does nothing.
		i = j
	}
	return i < len(src) || sawAttr, sigs
}

// scanBreakout looks for a quote that closes an attribute followed by what
// looks like a new attribute, which is the shape of escaping attr="...".
func scanBreakout(src []byte) Signal {
	for i := 0; i < len(src); i++ {
		if src[i] != '"' && src[i] != '\'' {
			continue
		}
		j := i + 1
		spaced := false
		for j < len(src) && (isSpace(src[j]) || src[j] == '/') {
			j++
			spaced = true
		}
		// A quote must be followed by separation and then a name, or it is just
		// a quotation mark in text.
		if !spaced || j >= len(src) || !isAlpha(src[j]) {
			continue
		}

		nameStart := j
		for j < len(src) && isNameByte(src[j]) {
			j++
		}
		attr := lowerWord(src[nameStart:j])
		for j < len(src) && isSpace(src[j]) {
			j++
		}
		if j < len(src) && src[j] == '=' {
			switch {
			case isEventHandler(attr):
				// Escaping a quoted attribute to add a handler is not merely a
				// breakout, it *is* handler injection: the browser will run it
				// exactly as if the tag had been written that way.
				return SignalAttributeBreakout | SignalEventHandler
			case isURIAttr(attr) && matchesScheme(src, j+1):
				return SignalAttributeBreakout | SignalSchemeInAttribute
			case isURIAttr(attr):
				return SignalAttributeBreakout
			}
		}
	}
	return 0
}

// isEventHandler reports whether an attribute name is an event handler.
//
// The "on" prefix plus at least two more letters. Checking the shape rather
// than enumerating handlers matters: browsers keep adding them, and a list
// would be permanently one event behind.
func isEventHandler(attr string) bool {
	if len(attr) < 4 || attr[0] != 'o' || attr[1] != 'n' {
		return false
	}
	for i := 2; i < len(attr); i++ {
		if attr[i] < 'a' || attr[i] > 'z' {
			return false
		}
	}
	return true
}

// isURIAttr reports whether an attribute takes a URI, so its scheme matters.
func isURIAttr(attr string) bool {
	switch attr {
	case "href", "src", "action", "formaction", "data", "poster",
		"background", "codebase", "cite", "longdesc", "usemap", "xlink:href":
		return true
	}
	return false
}

// matchesScheme reports whether an executing scheme starts at i, tolerating the
// whitespace and control bytes browsers strip before parsing one.
func matchesScheme(src []byte, i int) bool {
	// A quote may precede the scheme when it opens an attribute value.
	if i < len(src) && (src[i] == '"' || src[i] == '\'') {
		i++
	}
	for _, s := range executingSchemes {
		if matchesSchemeFolded(src, i, s) {
			return true
		}
	}
	return false
}

// matchesSchemeFolded compares case-insensitively while skipping the bytes
// browsers ignore inside a scheme — whitespace, NUL, and other controls. This
// is why "java\tscript:" and "java\x00script:" execute.
func matchesSchemeFolded(src []byte, i int, want string) bool {
	w := 0
	for i < len(src) && w < len(want) {
		c := src[i]
		if c < 0x21 && c != 0 {
			i++
			continue
		}
		if c == 0 {
			i++
			continue
		}
		if fold(c) != want[w] {
			return false
		}
		i++
		w++
	}
	return w == len(want)
}

// skipAttrValue advances past a quoted or bare attribute value.
func skipAttrValue(src []byte, i int) int {
	if i >= len(src) {
		return i
	}
	if q := src[i]; q == '"' || q == '\'' {
		i++
		for i < len(src) && src[i] != q {
			i++
		}
		if i < len(src) {
			i++
		}
		return i
	}
	for i < len(src) && !isSpace(src[i]) && src[i] != '>' {
		i++
	}
	return i
}

// hasMarkupAfter reports whether a tag opens after position i, which is what
// makes closing a raw-text element useful to an attacker.
func hasMarkupAfter(src []byte, i int) bool {
	for ; i < len(src); i++ {
		if src[i] == '<' && i+1 < len(src) && (isAlpha(src[i+1]) || src[i+1] == '/') {
			return true
		}
	}
	return false
}

// callFollows reports whether a '(' follows at i, past whitespace.
func callFollows(src []byte, i int) bool {
	for i < len(src) && isSpace(src[i]) {
		i++
	}
	return i < len(src) && src[i] == '('
}

func hasFoldedPrefix(src []byte, want string) bool {
	if len(src) < len(want) {
		return false
	}
	for i := 0; i < len(want); i++ {
		if fold(src[i]) != want[i] {
			return false
		}
	}
	return true
}

func hasFoldedSub(src []byte, want string) bool {
	for i := 0; i+len(want) <= len(src); i++ {
		if hasFoldedPrefix(src[i:], want) {
			return true
		}
	}
	return false
}

func fold(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNameByte(c byte) bool {
	return isAlpha(c) || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == ':'
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

const maxWordLen = 32

// lowerWord returns an ASCII-lowercased copy of a short name. Longer names
// cannot be a tag, attribute, or sink, so they fold to the empty string.
func lowerWord(w []byte) string {
	if len(w) > maxWordLen {
		return ""
	}
	var buf [maxWordLen]byte
	for i := range w {
		buf[i] = fold(w[i])
	}
	return string(buf[:len(w)])
}

// Operator adapts the detector to the rule engine, so it is prefiltered,
// metered, and reported like every other rule.
func Operator() rules.Operator { return &operator{d: New()} }

type operator struct{ d *Detector }

func (o *operator) Name() string { return "detect_xss" }

func (o *operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	v := o.d.Analyze(value)
	if !v.Detected() {
		return rules.Match{}, false
	}
	return rules.Match{Span: v.Span}, true
}

// Literals are the byte sequences without which no signal can fire.
//
// Derived from the signals rather than guessed: a tag needs '<', a handler
// needs "on" adjacent to '=', a scheme needs its own name, a breakout needs a
// quote, a CSS execution needs its keyword. The prefilter relies on this being
// exhaustive, and TestOperatorLiteralsCoverEveryAttack checks that it is.
func (o *operator) Literals() ([]string, bool) {
	return []string{
		"<",
		"javascript:", "vbscript:", "livescript:", "mocha:", "data:",
		"expression", "-moz-binding", "behavior:",
		"eval", "settimeout", "setinterval", "atob", "unescape", "function",
		"\"", "'",
		"-->",
	}, true
}

// Cost prices one analysis: a single pass with local lookahead.
func (o *operator) Cost() types.Fuel { return types.CostLiteralMatch * 4 }
