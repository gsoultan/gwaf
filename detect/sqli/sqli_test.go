// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package sqli

import (
	"strings"
	"testing"
)

// attacks are payloads a signature engine would need a separate rule for each
// of. The point of a structural detector is that one implementation covers the
// whole family, so the list is deliberately full of variants.
var attacks = []struct {
	name    string
	payload string
}{
	// ---- tautologies -------------------------------------------------------
	{"classic quote break", "1' OR 1=1--"},
	{"double quote break", `1" OR 1=1--`},
	{"no space", "1'OR'1'='1"},
	{"string tautology", "' OR 'a'='a"},
	{"string tautology closed", "admin' OR 'x'='x'--"},
	{"mixed case", "1' oR 1=1--"},
	{"alternating case", "1' oR 1=1 -- "},
	{"comment split", "1'/**/OR/**/1=1--"},
	{"versioned comment", "1'/*!50000OR*/1=1--"},
	{"tab separated", "1'\tOR\t1=1--"},
	{"newline separated", "1'\nOR\n1=1--"},
	{"multiple spaces", "1'   OR   1=1  --"},
	{"greater than", "1' OR 2>1--"},
	{"not equal", "1' OR 1<>2--"},
	{"like tautology", "1' OR 'a' LIKE 'a'--"},
	{"and tautology", "1' AND 1=1--"},
	{"xor tautology", "1' XOR 1=1--"},
	{"pipe operator", "1' || '1'='1"},
	{"hash comment", "1' OR 1=1#"},
	{"null comparison", "1' OR NULL=NULL--"},

	// ---- auth-bypass tail --------------------------------------------------
	// Closing the literal and commenting away the rest of the statement, with
	// no condition of its own. Against "WHERE user='$u'" that is the whole
	// attack: the closing quote the application appends lands inside the
	// comment. Quote-break and comment-terminator each score below threshold,
	// so without the adjacency signal none of these are caught.
	{"numeric auth bypass tail", "1'--"},
	{"identifier auth bypass tail", "admin'--"},
	{"hash auth bypass tail", "admin'#"},
	{"double quote auth bypass tail", `admin"--`},
	{"auth bypass tail trailing space", "admin'-- "},

	// ---- union ------------------------------------------------------------
	{"union select", "1 UNION SELECT password FROM users"},
	{"union all select", "1 UNION ALL SELECT NULL,NULL"},
	{"union distinct", "1 UNION DISTINCT SELECT 1"},
	{"union mixed case", "1 UnIoN SeLeCt pw"},
	{"union comment split", "1 UNION/**/SELECT pw"},
	{"union many comments", "1/**/UNION/**/ALL/**/SELECT/**/pw"},
	{"union newline", "1 UNION\nSELECT pw"},
	{"union quoted", "1' UNION SELECT password FROM users--"},
	{"union tab", "1\tUNION\tSELECT\tpw"},

	// MySQL executable comments: /*!...*/ runs in every version, /*!NNNNN...*/
	// runs from version NNNNN. The keyword lives *inside* the comment, so a
	// tokenizer that treats /*...*/ as opaque never sees UNION SELECT. sqlmap's
	// versionedmorekeywords / modsecurityversioned tampers emit exactly this.
	{"versioned union split", "1/*!50000UNION*/ /*!50000SELECT*/ pw"},
	{"versioned union no version", "1/*!UNION*//*!SELECT*/pw"},
	{"versioned union one comment", "1/*!50000UNION SELECT*/pw"},
	{"versioned keywords", "1/*!50000UNION*//*!ALL*//*!SELECT*/pw"},

	// ---- stacked queries ---------------------------------------------------
	{"stacked drop", "1; DROP TABLE users"},
	{"stacked drop quoted", "1'; DROP TABLE users--"},
	{"stacked delete", "1; DELETE FROM users"},
	{"stacked update", "1; UPDATE users SET admin=1"},
	{"stacked insert", "1; INSERT INTO users VALUES(1)"},
	{"stacked truncate", "x'; TRUNCATE TABLE logs--"},
	{"stacked exec", "1; EXEC xp_cmdshell"},

	// ---- time-based and out-of-band ----------------------------------------
	{"sleep", "1' AND SLEEP(5)--"},
	{"sleep bare", "1 OR sleep(5)"},
	{"benchmark", "1' AND BENCHMARK(1000000,MD5(1))--"},
	{"pg_sleep", "1'; SELECT pg_sleep(10)--"},
	{"waitfor delay", "1'; WAITFOR DELAY '0:0:5'--"},
	{"load_file", "1' UNION SELECT load_file('/etc/passwd')--"},
	{"extractvalue", "1' AND extractvalue(1,concat(0x7e,version()))--"},
	{"updatexml", "1' AND updatexml(1,concat(0x7e,user()),1)--"},
	{"xp_cmdshell", "1'; EXEC master..xp_cmdshell('dir')--"},

	// ---- combined ----------------------------------------------------------
	{"tautology then union", "1' OR 1=1 UNION SELECT pw--"},
	{"backtick identifier", "1` OR 1=1--"},
	{"long payload", "admin' OR 1=1 /*comment*/ UNION ALL SELECT NULL,password,NULL FROM users--"},
}

// benign is the counterweight. Every entry is text a real user could send, and
// several deliberately contain SQL keywords: a detector that blocks these gets
// switched off, which is a worse outcome than the attack it stopped.
var benign = []struct {
	name  string
	value string
}{
	// ---- text that breaks a quote near a comment marker --------------------
	// The adjacency signal for the auth-bypass tail must not fire on these.
	// Each contains both halves — an apostrophe and a comment marker that runs
	// to the end of the value — but with content in between, which is what
	// separates prose and code from a truncation.
	{"jquery id selector", "$('#main').addClass('active')"},
	{"jquery attr selector", "$('#nav a[href^=\"/docs\"]').show()"},
	{"css fragment in value", "a.btn{color:#fff}"},
	{"apostrophe then dashes then words", "don't -- see the note below"},
	{"hashtag after apostrophe", "it's #trending today"},
	{"anchor link with apostrophe", "/faq#what's-new"},
	{"markdown em dash aside", "the plan's cost -- roughly $40 -- is fixed"},

	// ---- prose containing SQL keywords -------------------------------------
	{"select in prose", "please select a delivery option"},
	{"union in prose", "credit union membership application"},
	{"union selected", "the union selected a new representative"},
	{"union select adjacent-ish", "our union selects officers annually"},
	{"drop in prose", "drop off location near the station"},
	{"insert in prose", "insert the card and wait for the tone"},
	{"update in prose", "please update my mailing address"},
	{"delete in prose", "delete my account permanently"},
	{"order by in prose", "we order by phone every Tuesday"},
	{"group in prose", "the group has a table booked"},
	{"table in prose", "the table was set for six"},
	{"where in prose", "where is my order"},
	{"from in prose", "shipped from the Berlin warehouse"},
	{"all keywords", "select the union table and update the group order"},

	// ---- apostrophes -------------------------------------------------------
	{"contraction", "it's urgent"},
	{"possessive", "the user's account settings"},
	{"quoted speech", `he said "that's the one" and left`},
	{"irish name", "O'Brien"},
	{"french", "l'hôtel est complet"},
	{"multiple contractions", "it's fine, don't worry, we'll handle it"},

	// ---- comparisons in prose ----------------------------------------------
	{"math", "1 + 1 = 2"},
	{"price comparison", "price < 100 and rating > 4"},
	{"equals in text", "the total = 42 dollars"},
	{"ratio", "the ratio is 3:1 or 4:1"},

	// ---- code and markup users legitimately send ---------------------------
	{"code snippet", "if (a < b) { return a; }"},
	{"json", `{"name":"Alice","qty":3,"note":"deliver before 5pm"}`},
	{"json nested", `{"user":{"id":1,"prefs":{"theme":"dark"}}}`},
	{"markdown", "# Title\n\nSome *emphasis* and a [link](/x)."},
	{"css", "body { color: #fff; margin: 0 }"},
	{"url with query", "https://example.com/search?q=widgets&page=2"},
	{"regex in text", "^[a-z0-9_-]{3,16}$"},
	{"date range", "2026-01-01 -- 2026-12-31"},
	{"comment marker in prose", "see note -- it explains the change"},

	// ---- identifiers and encodings -----------------------------------------
	{"uuid", "550e8400-e29b-41d4-a716-446655440000"},
	{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123"},
	{"base64", "SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0Lg=="},
	{"semver", "1.2.3-beta.4+build.567"},
	{"file path", "/var/log/app/2026-08-05.log"},
	{"windows path", `C:\Users\alice\Documents`},
	{"email", "first.last+tag@example.co.uk"},
	{"hex color", "#ff00aa"},
	{"query string", "a=1&b=2&c=3"},
	{"csv row", "alice,30,engineer"},

	// ---- international -----------------------------------------------------
	{"cjk", "日本語のテキスト"},
	{"cyrillic", "Привет мир"},
	{"emoji", "great product 👍🎉"},
	{"accented", "café résumé naïve"},

	// ---- edge cases --------------------------------------------------------
	{"empty", ""},
	{"single char", "a"},
	{"single quote", "'"},
	{"single equals", "="},
	{"just digits", "12345"},
	{"whitespace", "   "},
}

// TestDoubledQuotesAreNotInjection records a deliberate non-detection.
//
// "1” OR ”1”=”1" looks like a payload but is not one under standard SQL:
// a doubled quote is an *escaped* quote, so interpolating it into '...' yields
// a single string literal ("1' OR '1'='1") that is compared, not executed. The
// tokenizer treats ” as an escape for exactly this reason.
//
// Flagging it would mean assuming a non-standard parser, and the cost of that
// assumption is false positives on every value containing a doubled quote —
// which includes any correctly-escaped user input. If a dialect is found that
// really does execute this, the fix is a fourth tokenization context, not a
// weakening of the escape rule.
func TestDoubledQuotesAreNotInjection(t *testing.T) {
	d := New()
	if v := d.Analyze([]byte(`1'' OR ''1''=''1`)); v.Detected() {
		t.Errorf("doubled-quote escaping was flagged: signals=%s", v.Signals)
	}
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
				t.Errorf("FALSE POSITIVE: %q\n  signals=%s score=%d context=%s",
					b.value, v.Signals, v.Score, v.Context)
			}
		})
	}
	t.Logf("false positives: %d/%d", fp, len(benign))
}

// TestStructureNotKeywords is the thesis stated as a test. The same words in
// prose order must not match, while the same words in query order must. A
// signature engine cannot distinguish these; that is the whole point.
func TestStructureNotKeywords(t *testing.T) {
	d := New()

	pairs := []struct {
		attack, prose string
	}{
		{"1 UNION SELECT pw", "the union selected a representative"},
		{"1; DROP TABLE users", "drop the table off at the warehouse"},
		{"1' OR 1=1--", "one or two -- either works"},
		{"1' AND SLEEP(5)--", "sleep(8h) is the recommendation"},
		{"1'; DROP TABLE t", "drop table service available"},
	}

	for _, p := range pairs {
		t.Run(p.attack, func(t *testing.T) {
			if v := d.Analyze([]byte(p.attack)); !v.Detected() {
				t.Errorf("attack %q not detected (score %d)", p.attack, v.Score)
			}
			if v := d.Analyze([]byte(p.prose)); v.Detected() {
				t.Errorf("prose %q flagged: signals=%s score=%d",
					p.prose, v.Signals, v.Score)
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
		{"1 UNION SELECT pw", SignalUnionSelect},
		{"1; DROP TABLE users", SignalStackedQuery},
		{"1' AND SLEEP(5)--", SignalDangerFunction},
		{"1' OR 1=1--", SignalBooleanInjection},
		{"1 UNION/**/SELECT pw", SignalCommentSplit},
	}

	for _, tt := range tests {
		t.Run(tt.payload, func(t *testing.T) {
			v := d.Analyze([]byte(tt.payload))
			if v.Signals&tt.want == 0 {
				t.Errorf("signals = %s, want it to include %s", v.Signals, tt.want)
			}
			// A decision has to be explainable; an unnamed signal is not.
			if v.Signals.String() == "none" {
				t.Error("signals stringify to none despite a detection")
			}
		})
	}
}

// TestBoundedOnPathologicalInput checks that adversarial shapes cannot drive
// unbounded work. The token cap is the bound; these inputs try to exceed it.
func TestBoundedOnPathologicalInput(t *testing.T) {
	d := New()

	inputs := []struct{ name, value string }{
		{"many quotes", strings.Repeat("'", 10000)},
		{"many comments", strings.Repeat("/*x*/", 5000)},
		{"unterminated comment", "/*" + strings.Repeat("x", 50000)},
		{"many operators", strings.Repeat("=", 10000)},
		{"many parens", strings.Repeat("(", 10000)},
		{"nested quotes", strings.Repeat("'\"", 5000)},
		{"long identifier", strings.Repeat("a", 100000)},
		{"many semicolons", strings.Repeat(";", 10000)},
		{"unions", strings.Repeat("UNION SELECT ", 2000)},
		{"null bytes", strings.Repeat("\x00", 10000)},
		{"high bytes", strings.Repeat("\xff\xfe", 5000)},
	}

	for _, in := range inputs {
		t.Run(in.name, func(t *testing.T) {
			// The assertion is that this returns at all, and quickly.
			_ = d.Analyze([]byte(in.value))
		})
	}
}

func TestAnalyzeIsDeterministic(t *testing.T) {
	d := New()
	for _, a := range attacks {
		first := d.Analyze([]byte(a.payload))
		for range 10 {
			if got := d.Analyze([]byte(a.payload)); got != first {
				t.Fatalf("%q: non-deterministic verdict", a.payload)
			}
		}
	}
}

// TestOperatorLiteralsCoverEveryAttack is the soundness check for prefiltering.
// The operator asserts that no signal can fire without one of its literals
// present. If an attack contains none of them, the prefilter would skip the
// rule and the detection would silently never happen.
func TestOperatorLiteralsCoverEveryAttack(t *testing.T) {
	op := Operator()
	lits, required := op.Literals()
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
			t.Errorf("payload %q contains none of the declared literals — "+
				"the prefilter would skip this rule and the detection would "+
				"silently never happen", a.payload)
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
		_, matched := op.Eval(nil, []byte(b.value))
		if matched {
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
	f.Add("")
	f.Add("'")
	f.Add("/*")
	f.Add("\x00\xff")

	d := New()
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 65536 {
			t.Skip()
		}

		v := d.Analyze([]byte(value))

		// Never panics, and the score always agrees with the signals it claims.
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
			t.Fatalf("Detected() disagrees with the threshold")
		}

		// Determinism: the engine memoises nothing here, but a verdict that
		// varied would make decisions order-dependent.
		if v2 := d.Analyze([]byte(value)); v2 != v {
			t.Fatalf("non-deterministic verdict for %q", value)
		}
	})
}

func BenchmarkAnalyzeBenign(b *testing.B) {
	d := New()
	v := []byte("an ordinary search query with no attack content whatsoever")
	b.ReportAllocs()
	b.SetBytes(int64(len(v)))
	for b.Loop() {
		d.Analyze(v)
	}
}

func BenchmarkAnalyzeAttack(b *testing.B) {
	d := New()
	v := []byte("1' OR 1=1 UNION ALL SELECT NULL,password FROM users--")
	b.ReportAllocs()
	b.SetBytes(int64(len(v)))
	for b.Loop() {
		d.Analyze(v)
	}
}

func BenchmarkAnalyzeJSON(b *testing.B) {
	d := New()
	v := []byte(`{"name":"Alice","qty":3,"note":"please deliver before 5pm"}`)
	b.ReportAllocs()
	b.SetBytes(int64(len(v)))
	for b.Loop() {
		d.Analyze(v)
	}
}
