// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
)

// jsContextInjection reports a payload reflected into JavaScript rather than
// into HTML.
//
// # Why detect/xss cannot see these
//
// It reads HTML structure — a tag, an attribute, a scheme in a URI attribute —
// and these payloads contain no HTML at all. Dumping the corpus's 45 XSS misses
// made the shape obvious: the value is reflected *inside a script*, so the
// attacker does not need a tag. They need to end the statement they landed in
// and start their own:
//
//	min=1026553;alert(document.domain)//772      break out of a numeric literal
//	x=};alert(1)//                               close a block
//	p=";alert(document.domain);"                 close a string
//	itemid=1); alert(document.domain);/*x        close a call
//	loginMode=alert(document.domain)             land in an expression already
//
// That is the same shape as rule 4021 and the reason it exists: a payload that
// stays inside one language the detectors do not read is outside all of them.
// detect/xss reads HTML, detect/shelli reads shell, detect/ssti reads templates.
// Nothing read JavaScript.
//
// # Why a call alone is not the signal
//
// "alert(" appears in every tutorial, every bug report about XSS, and every
// article explaining this attack. Matching it would put a rule in the core set
// that blocks the people fixing the bug — the failure IDScriptURI is narrowed to
// avoid, and the one already accepted as a false positive elsewhere in the
// corpus ("a security blog post quoting a payload").
//
// So a call has to arrive with evidence of *injection* beside it, and there are
// exactly three shapes that carry it:
//
//   - a handler assignment: "onerror=alert(", "onfocus=confirm(". The attribute
//     name is only meaningful to a browser, and assigning a call to it is not
//     something prose does.
//   - a breakout into a call: ";alert(", "};alert(", "');alert(", ");alert(".
//     Prose does not terminate a statement and then invoke.
//   - a call on the document identity: "alert(document.domain)",
//     "confirm(document.cookie)". These are what a proof-of-concept reads,
//     because they prove origin access, and there is no benign reason to send
//     one in a parameter.
//
// Measured against the 10,480-request benign corpus, none of "alert(",
// "confirm(", "prompt(", "onerror", "onfocus", "onmouseover", "document.domain"
// or "document.cookie" appears even once — so the narrowing above is headroom
// on top of an already-quiet vocabulary rather than the thing keeping it quiet.
// The corpus comes from one adopter (boundaries.md), which is why the rule is
// High rather than Certain.
func jsContextInjection() rules.Operator {
	// Calls that prove execution. Deliberately short: these are what a scanner
	// and a proof-of-concept use, not what an application sends.
	sinks := []string{"alert(", "confirm(", "prompt("}

	// What a proof-of-concept asks for once it runs.
	identity := []string{"document.domain", "document.cookie"}

	// Statement, block and call terminators, checked immediately before a call.
	//
	// Only these three. Quotes were in this set and had to come out: a bare
	// quote before a call is a string *opening*, not a breakout, so
	// "&quot;alert(1)&quot; is the classic payload" -- prose about XSS, read
	// under the HTML-entity interpretation as "alert(1)" -- matched. A real
	// breakout closes the quote and then terminates, which reaches this set at
	// the ';' rather than at the quote. '{', ',' and '+' came out for the same
	// reason: each is ordinary punctuation next to a call in a code snippet,
	// and none was needed for any payload the corpus actually carries.
	breakouts := []byte{';', '}', ')'}

	// Self-evidencing JavaScript, found by a language-specific red-team round.
	// None needs a breakout beside it because none has an ordinary reading in a
	// request parameter.
	selfEvident := []string{
		// A dynamic import of a data URL is a module built from the request.
		"import('data:", `import("data:`, "import(`data:",
		// Tagged-template invocation: alert`1` calls alert with no parentheses,
		// which is how a payload survives a filter that looks for "alert(".
		"alert`", "confirm`", "prompt`", "eval`",
	}
	// Reading the cookie is ordinary in a page and never in a request
	// parameter, and paired with a way off the machine it is exfiltration
	// rather than a mention.
	exfilSources := []string{"document.cookie", "localstorage.", "sessionstorage."}
	exfilSinks := []string{"fetch(", "xmlhttprequest", "sendbeacon(", "new image", ".src=", "location="}

	return op.Func("js_context_injection", func(v []byte) bool {
		for _, s := range selfEvident {
			if indexOfFold(v, s) >= 0 {
				return true
			}
		}
		for _, src := range exfilSources {
			if indexOfFold(v, src) < 0 {
				continue
			}
			for _, snk := range exfilSinks {
				if indexOfFold(v, snk) >= 0 {
					return true
				}
			}
		}
		for _, s := range sinks {
			i := 0
			for {
				k := indexOfFold(v[i:], s)
				if k < 0 {
					break
				}
				at := i + k
				i = at + 1

				// A call on the document's identity is self-evidencing.
				rest := v[at+len(s):]
				for _, id := range identity {
					if j := indexOfFold(rest, id); j >= 0 && j <= 2 {
						return true
					}
				}

				// Otherwise the call needs a breakout immediately before it.
				// Whitespace is skipped because "; alert(" is the same attack
				// as ";alert(".
				j := at - 1
				for j >= 0 && (v[j] == ' ' || v[j] == '\t' || v[j] == '\n' || v[j] == '\r') {
					j--
				}
				if j >= 0 {
					for _, b := range breakouts {
						// A ';' that closes an HTML character reference is not a
						// statement terminator. "&lt;script&gt;alert(1)" put one
						// directly before the call and matched here, which is the
						// right verdict reached by the wrong reading: the payload
						// is an entity-encoded script tag, and saying so is what
						// Decision.Interpretation is for. It also mattered for
						// precision -- HTML-escaped prose quoting JavaScript,
						// "&quot;alert(", carries the same shape and is not an
						// attack.
						if v[j] == b && !(b == ';' && closesCharReference(v, j)) {
							return true
						}
					}
					// A handler assignment: "on<word>=" ending right here.
					if v[j] == '=' && endsWithEventHandler(v[:j]) {
						return true
					}
				}
			}
		}
		return false
	}).WithLiterals(
		// Honest: every branch requires one of these as a substring. The call
		// forms cover the breakout, handler and identity branches; the rest
		// cover the self-evidencing and exfiltration ones.
		"alert(", "confirm(", "prompt(",
		"import('data:", `import("data:`, "import(`data:",
		"alert`", "confirm`", "prompt`", "eval`",
		"document.cookie", "localstorage.", "sessionstorage.",
	)
}

// endsWithEventHandler reports whether s ends in an event-handler attribute
// name — "on" followed by at least two letters, at a word boundary.
//
// The length floor keeps "on=" and "one=" out, and the boundary check is what
// stops "button=" and "reason=" from reading as handlers. It is a name test
// rather than a list because the handler vocabulary grows with every browser
// release: "oncontentvisibilityautostatechange" is in the corpus, and a list
// written today would not have it.
func endsWithEventHandler(s []byte) bool {
	end := len(s)
	i := end
	for i > 0 && isHandlerNameByte(s[i-1]) {
		i--
	}
	name := s[i:end]
	if len(name) < 4 || len(name) > 40 {
		return false
	}
	if !(name[0] == 'o' || name[0] == 'O') || !(name[1] == 'n' || name[1] == 'N') {
		return false
	}
	// The remainder has to be letters: "on123=" is not a handler.
	for _, c := range name[2:] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	// A boundary before "on", or the value starts there. Without this,
	// "button=" would end in "on" plus letters and read as a handler.
	if i == 0 {
		return true
	}
	switch s[i-1] {
	case ' ', '\t', '\n', '\r', '"', '\'', '/', ';', '<', '(', '&':
		return true
	}
	return false
}

// isHandlerNameByte reports whether c can appear in an attribute name.
func isHandlerNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// closesCharReference reports whether the ';' at i terminates an HTML character
// reference — "&lt;", "&#60;", "&#x3c;".
//
// The window is bounded at the longest entity name HTML defines
// (CounterClockwiseContourIntegral, 31 characters) plus its delimiters, so a
// stray '&' far earlier in the value cannot make an unrelated ';' look like an
// entity.
func closesCharReference(v []byte, i int) bool {
	if i <= 0 || v[i] != ';' {
		return false
	}
	const maxRef = 34
	lo := i - maxRef
	if lo < 0 {
		lo = 0
	}
	for j := i - 1; j >= lo; j-- {
		if v[j] == '&' {
			body := v[j+1 : i]
			if len(body) == 0 {
				return false
			}
			if body[0] == '#' {
				digits := body[1:]
				if len(digits) > 1 && (digits[0] == 'x' || digits[0] == 'X') {
					digits = digits[1:]
					for _, c := range digits {
						if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
							return false
						}
					}
					return len(digits) > 0
				}
				for _, c := range digits {
					if c < '0' || c > '9' {
						return false
					}
				}
				return len(digits) > 0
			}
			for _, c := range body {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
					return false
				}
			}
			return true
		}
		// An entity cannot contain these, so the search stops rather than
		// running to the window bound.
		if v[j] == ';' || v[j] == ' ' || v[j] == '<' || v[j] == '>' {
			return false
		}
	}
	return false
}
