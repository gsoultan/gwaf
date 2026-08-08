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

	// SignalHandlerAssignment is an event-handler name assigned a call, standing
	// on its own rather than inside a tag or after a quote that closed one.
	//
	// Weak by design and never enough alone: "onclick=alert(1)" as a whole
	// parameter value is not an attack until something places it inside a tag,
	// and blocking it outright would block every article that quotes it. It
	// corroborates — with a javascript: scheme in the same value it is the
	// Ostrowski XSS polyglot, whose separators are comments and parentheses
	// rather than spaces, so no breakout or tag scan anchors on it.
	SignalHandlerAssignment
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
	if s&SignalHandlerAssignment != 0 {
		add("handler_assignment")
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
	case SignalHandlerAssignment:
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
	sigs |= scanHandlerAssignment(src)

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

// scanHandlerAssignment finds an event-handler name assigned a function call,
// anywhere in the value.
//
// It exists for payloads that carry a handler without giving the tag or breakout
// scanners anything to anchor on. The Ostrowski XSS polyglot is the case: it
// separates its tokens with comments and parentheses rather than whitespace, so
// "oNcliCk=alert()" sits in the middle of "/* */(...)" and neither scan reaches
// it. On its own that is a weak reading and stays below the threshold; with the
// javascript: scheme the same value carries, it is the polyglot.
//
// Two conditions keep ordinary JavaScript out. The name must not be a property
// access — "el.onclick = fn" is code someone is discussing, and the leading dot
// says so. And the value must start a call, so "onclick=null" and "the onclick
// handler" contribute nothing.
func scanHandlerAssignment(src []byte) Signal {
	for i := 0; i < len(src); i++ {
		if !isAlpha(src[i]) {
			continue
		}
		// Must start a token: a preceding dot makes it a property access, and a
		// preceding name byte makes it the tail of a longer word.
		if i > 0 && (src[i-1] == '.' || isNameByte(src[i-1])) {
			for i < len(src) && isNameByte(src[i]) {
				i++
			}
			continue
		}

		start := i
		for i < len(src) && isNameByte(src[i]) {
			i++
		}
		if !isEventHandler(lowerWord(src[start:i])) {
			i--
			continue
		}

		j := i
		for j < len(src) && isSpace(src[j]) {
			j++
		}
		if j >= len(src) || src[j] != '=' {
			i--
			continue
		}
		j++
		for j < len(src) && isSpace(src[j]) {
			j++
		}
		// The assigned value has to start a call: a name followed by '('.
		nameStart := j
		for j < len(src) && isNameByte(src[j]) {
			j++
		}
		if j > nameStart && j < len(src) && src[j] == '(' {
			return SignalHandlerAssignment
		}
		i--
	}
	return 0
}

// scanBreakout looks for a quote that closes an attribute followed by what
// looks like a new attribute, which is the shape of escaping attr="...".
func scanBreakout(src []byte) Signal {
	for i := 0; i < len(src); i++ {
		if src[i] != '"' && src[i] != '\'' {
			continue
		}
		// Skip whatever separates the closing quote from the next attribute
		// name. Whitespace and '/' are the obvious ones; '*' is accepted once a
		// '/' has been seen, because "/**/" between attributes separates them
		// exactly as a space does -- a browser inside a tag reads the first '/'
		// as a separator, "**" as an attribute name and the second '/' as
		// another separator. That is why the Ostrowski XSS polyglot is written
		// with comments instead of spaces, and it walked through here until the
		// polyglot phase found it. A bare "*onclick" is one attribute name to a
		// browser and executes nothing, so the '/' is required first.
		j := i + 1
		spaced, slashed := false, false
		for j < len(src) && (isSpace(src[j]) || src[j] == '/' || (src[j] == '*' && slashed)) {
			if src[j] == '/' {
				slashed = true
			}
			j++
			spaced = true
		}
		// A quote must be followed by separation and then a name, or it is just
		// a quotation mark in text.
		//
		// The separator is not actually required by a browser: `class="a"style=b`
		// is a parse error that every engine recovers from by starting a new
		// attribute, and payloads use that to drop the space. Allowing it
		// unconditionally would read `set "FOO=bar"` in prose as a tag, so the
		// unseparated form is accepted only when the name that follows is one
		// HTML actually defines -- a closed set no sentence wanders into.
		if j >= len(src) || !isAlpha(src[j]) {
			continue
		}
		if !spaced && !startsKnownAttr(src, j) {
			continue
		}

		// Walk the attributes that follow the closing quote, the way a browser
		// parses an attribute list. Inspecting only the first would miss every
		// payload that pads the handler behind something harmless --
		// `" autofocus onfocus=alert(1)` behind a valueless boolean attribute,
		// `" style=position:fixed onmouseover=alert(1)` behind a value-bearing
		// one. Both shapes are real WordPress plugin CVEs, and to the browser
		// that will run them the padding is not there at all.
		//
		// Two things keep this from reading prose as a tag. A word that is
		// neither a known boolean attribute nor followed by '=' ends the walk
		// immediately, which is what ordinary text looks like after a quote. And
		// an unquoted value ends at whitespace exactly as HTML says it does, so
		// the walk cannot slide across a sentence. The step count is bounded
		// because everything on this path takes attacker input.
		for steps := 0; steps < maxBreakoutAttrs; steps++ {
			nameStart := j
			for j < len(src) && isNameByte(src[j]) {
				j++
			}
			attr := lowerWord(src[nameStart:j])
			// Skip the separators after the name; the next thing is either '='
			// (a value-bearing attribute) or the start of the next attribute.
			k := j
			for k < len(src) && (isSpace(src[k]) || src[k] == '/') {
				k++
			}
			if k < len(src) && src[k] == '=' {
				switch {
				case isEventHandler(attr):
					// Escaping a quoted attribute to add a handler is not merely a
					// breakout, it *is* handler injection: the browser will run it
					// exactly as if the tag had been written that way.
					return SignalAttributeBreakout | SignalEventHandler
				case isURIAttr(attr) && matchesScheme(src, k+1):
					return SignalAttributeBreakout | SignalSchemeInAttribute
				case isURIAttr(attr):
					return SignalAttributeBreakout
				}
				// A value-bearing attribute that is neither a handler nor a URI
				// attr is padding -- `style=...` is the common one. Skip its
				// value the way HTML delimits one and keep walking: a quoted
				// value ends at its matching quote, an unquoted value ends at
				// whitespace.
				j = k + 1
				if j < len(src) && (src[j] == '"' || src[j] == '\'') {
					q := src[j]
					j++
					for j < len(src) && src[j] != q {
						j++
					}
					if j >= len(src) {
						break
					}
					j++ // past the closing quote
				} else {
					for j < len(src) && !isSpace(src[j]) {
						j++
					}
				}
				if !skipAttrSep(src, &j) {
					break
				}
				continue
			}
			if !isBooleanAttr(attr) {
				break
			}
			// Valueless boolean attribute (autofocus, hidden, ...): a browser
			// reads it as padding and moves to the next attribute, so we do too.
			// k already sits on the next attribute name; anything that is not one
			// -- a '>' closing the tag, punctuation, end of input -- ends the walk.
			if k >= len(src) || !isAlpha(src[k]) {
				break
			}
			j = k
		}
	}
	return 0
}

// startsKnownAttr reports whether the name at src[i:] is an HTML attribute
// name followed by '='. It gates the unseparated `..."style=...` breakout form,
// where there is no whitespace to distinguish a tag from a quoted string.
func startsKnownAttr(src []byte, i int) bool {
	j := i
	for j < len(src) && isNameByte(src[j]) {
		j++
	}
	if j >= len(src) || src[j] != '=' {
		return false
	}
	attr := lowerWord(src[i:j])
	if isEventHandler(attr) || isURIAttr(attr) || isBooleanAttr(attr) {
		return true
	}
	switch attr {
	case "style", "class", "id", "type", "name", "value", "title", "alt", "width", "height":
		return true
	}
	return false
}

// maxBreakoutAttrs bounds how many attributes scanBreakout walks after a
// quote-break. A real tag's attribute list is short; the bound is here because
// this loop reads attacker-controlled bytes and everything on that path gets a
// ceiling (CLAUDE.md invariant 2).
const maxBreakoutAttrs = 16

// skipAttrSep advances *i past the whitespace separating two attributes and
// reports whether an attribute name follows. Separators are required: without
// one, `x="a"onclick=` is a single attribute name to the tokenizer.
func skipAttrSep(src []byte, i *int) bool {
	j := *i
	spaced := false
	for j < len(src) && (isSpace(src[j]) || src[j] == '/') {
		j++
		spaced = true
	}
	if !spaced || j >= len(src) || !isAlpha(src[j]) {
		return false
	}
	*i = j
	return true
}

// isBooleanAttr reports whether attr is one of HTML's valueless boolean
// attributes. Unlike event handlers -- an open shape that browsers keep
// extending, so isEventHandler matches structurally -- the boolean attributes
// are a closed, slow-moving set, and enumerating them keeps scanBreakout from
// walking past arbitrary prose words to reach a distant handler. autofocus is
// the load-bearing entry: it auto-fires onfocus/onblur with no interaction.
func isBooleanAttr(attr string) bool {
	switch attr {
	case "autofocus", "autoplay", "checked", "controls", "default", "defer",
		"disabled", "formnovalidate", "hidden", "ismap", "loop", "multiple",
		"muted", "nomodule", "novalidate", "open", "playsinline", "readonly",
		"required", "reversed", "selected":
		return true
	}
	return false
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
		// A raw control or whitespace byte is ignored by the URL parser, so
		// "java\tscript:" reaches the interpreter and has to match here.
		if c < 0x21 && c != 0 {
			i++
			continue
		}
		if c == 0 {
			i++
			continue
		}
		// An HTML character reference is decoded by the browser before it parses
		// the scheme, so "java&Tab;script:" and "javascript&colon;alert(1)" both
		// execute. Decode it and treat the result the same as a raw byte: a
		// control/space code point is skipped, and any other is folded and
		// matched. Without this the entity broke the scan and the payload passed.
		if c == '&' {
			if r, next, ok := decodeCharRef(src, i); ok {
				if r < 0x21 {
					i = next
					continue
				}
				if r < 0x80 && fold(byte(r)) == want[w] {
					i = next
					w++
					continue
				}
				return false
			}
			return false
		}
		if fold(c) != want[w] {
			return false
		}
		i++
		w++
	}
	return w == len(want)
}

// decodeCharRef decodes the HTML character reference at src[i], which must be
// '&'. It returns the code point, the index just past the reference, and whether
// one was found. A literal ampersand that is not a reference reports ok=false,
// so it is treated as an ordinary byte.
//
// Numeric references (&#58; and &#x3a;) are decoded in full. Named references
// are limited to the handful that obfuscate a scheme -- tab, newline, colon,
// slash -- because a full HTML entity table does not belong on this path and
// those are the ones an attacker reaches for. The trailing semicolon is optional
// because browsers accept it missing.
func decodeCharRef(src []byte, i int) (rune, int, bool) {
	j := i + 1 // past '&'
	if j < len(src) && src[j] == '#' {
		j++
		hex := false
		if j < len(src) && (src[j] == 'x' || src[j] == 'X') {
			hex = true
			j++
		}
		start := j
		var v rune
		for j < len(src) {
			c := src[j]
			var d rune
			switch {
			case c >= '0' && c <= '9':
				d = rune(c - '0')
			case hex && c >= 'a' && c <= 'f':
				d = rune(c-'a') + 10
			case hex && c >= 'A' && c <= 'F':
				d = rune(c-'A') + 10
			default:
				c = 0 // sentinel: stop
			}
			if c == 0 {
				break
			}
			base := rune(10)
			if hex {
				base = 16
			}
			v = v*base + d
			if v > 0x10FFFF {
				return 0, 0, false
			}
			j++
		}
		if j == start {
			return 0, 0, false
		}
		if j < len(src) && src[j] == ';' {
			j++
		}
		return v, j, true
	}
	for _, ref := range schemeNamedRefs {
		if hasFoldedPrefixAt(src, j, ref.name) {
			k := j + len(ref.name)
			if k < len(src) && src[k] == ';' {
				k++
			}
			return ref.cp, k, true
		}
	}
	return 0, 0, false
}

// schemeNamedRefs are the named character references that obfuscate a scheme.
var schemeNamedRefs = []struct {
	name string
	cp   rune
}{
	{"newline", '\n'}, // longest first, so "newline" is tried before "new"
	{"tab", '\t'},
	{"colon", ':'},
	{"sol", '/'},
}

// hasFoldedPrefixAt reports whether src[i:] begins with want, case-insensitively.
func hasFoldedPrefixAt(src []byte, i int, want string) bool {
	if i+len(want) > len(src) {
		return false
	}
	for k := 0; k < len(want); k++ {
		if fold(src[i+k]) != want[k] {
			return false
		}
	}
	return true
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

func (o *operator) Name() string { return "detect_xss" }

func (o *operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	v := o.d.Analyze(value)
	if v.Score < o.threshold {
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
