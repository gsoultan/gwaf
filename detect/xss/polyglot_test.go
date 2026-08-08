// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package xss

import "testing"

// ostrowski is the XSS polyglot that is the standard test string for this class.
// It is written to survive attribute, script and URL contexts at once, and it
// separates its tokens with comments and parentheses rather than whitespace --
// which is exactly what made it walk past a scanner keyed on spaces.
const ostrowski = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//"

// TestPolyglotIsDetected covers the two independent holes the polyglot phase
// found: a comment run between attributes, and a handler assignment with nothing
// for the tag or breakout scans to anchor on.
func TestPolyglotIsDetected(t *testing.T) {
	d := New()
	for _, attack := range []string{
		ostrowski,
		// The breakout half on its own: "/**/" separates attributes exactly as a
		// space does once a browser is inside a tag.
		`'/*"/**/oNcliCk=alert()//`,
		`" /**/onmouseover=alert(1) x="`,
	} {
		if v := d.Analyze([]byte(attack)); !v.Detected() {
			t.Errorf("missed %q (score %d, signals %v)", attack, v.Score, v.Signals)
		}
	}
}

// TestHandlerAssignmentStaysWeak is the other half, and the reason the signal is
// worth 2 rather than 5.
//
// A handler assignment is only an attack once something places it inside a tag.
// As a whole parameter value it is a string people write about, and blocking it
// would block every article, bug report and tutorial that quotes one. It has to
// corroborate — with the javascript: scheme in the polyglot's case — before it
// means anything.
func TestHandlerAssignmentStaysWeak(t *testing.T) {
	d := New()
	for _, benign := range []string{
		"onclick=alert(1)",
		"el.onclick = function(){ save() }",
		"button.onmouseover = highlight(this)",
		"the onclick handler fires when clicked",
		"set onclick=null to remove it",
		"read about onerror handlers in the docs",
		"onclick equals alert in the example",
		"we bind onsubmit = validate(form) at startup",
	} {
		if v := d.Analyze([]byte(benign)); v.Detected() {
			t.Errorf("false positive on %q (score %d, signals %v)", benign, v.Score, v.Signals)
		}
	}
}
