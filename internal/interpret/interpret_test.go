// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package interpret

import (
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want Class
	}{
		{"empty", "", 0},
		{"plain", "ordinary text with no markers", 0},
		{"plain with digits", "order 12345 confirmed", 0},

		{"double encoded lower", "%252e%252e", ClassDoubleEncoded},
		{"double encoded in path", "..%252f..%252f", ClassDoubleEncoded},
		{"single encoded only", "%2e%2e%2f", 0},

		{"backslash", `a\b`, ClassSeparator},
		{"windows path", `..\..\windows`, ClassSeparator},

		{"encoded null", "file%00.jpg", ClassNullTruncate},
		{"literal null", "file\x00.jpg", ClassNullTruncate},

		{"overlong 2byte encoded", "%c0%ae", ClassOverlongUTF8},
		{"overlong c1", "%c1%9c", ClassOverlongUTF8},
		{"overlong 3byte", "%e0%80%ae", ClassOverlongUTF8},
		{"overlong raw", "\xc0\xae", ClassOverlongUTF8},

		{"utf7 shift", "+ADw-", ClassUTF7},
		{"utf7 in text", "text +AD4- more", ClassUTF7},
		// Detection requires the explicit '-' terminator so that '+' used as an
		// encoded space does not cost an extra reading on every query string.
		{"plus as space is not utf7", "a+b", 0},
		{"plus separated words", "hello+world+again", 0},
		{"trailing plus", "abc+", 0},
		{"literal plus escape", "a+-b", 0},

		{"entity named", "&lt;", ClassHTMLEntity},
		{"entity numeric", "&#60;", ClassHTMLEntity},
		{"bare ampersand", "a & b", 0},
		{"query separator", "a=1&b=2", ClassHTMLEntity}, // 'b' is alpha; over-detection is the safe direction

		{"combined", "%252e\\x%00+ADw-&lt;",
			ClassDoubleEncoded | ClassSeparator | ClassNullTruncate | ClassUTF7 | ClassHTMLEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Detect([]byte(tt.src)); got != tt.want {
				t.Errorf("Detect(%q) = %v (%s), want %v (%s)",
					tt.src, got, got, tt.want, tt.want)
			}
		})
	}
}

// TestDetectOverApproximates records the deliberate bias. A false positive here
// costs one extra reading; a false negative is a missed interpretation and
// therefore a bypass.
func TestDetectOverApproximates(t *testing.T) {
	// These are legitimate inputs that Detect flags anyway.
	for _, s := range []string{"a=1&b=2", "AT&T", "50%25 off"} {
		if !Detect([]byte(s)).Any() {
			t.Logf("Detect(%q) found no ambiguity — acceptable, but verify", s)
		}
	}
	// These must never be missed.
	mustDetect := map[string]Class{
		"%252f":  ClassDoubleEncoded,
		`\`:      ClassSeparator,
		"%00":    ClassNullTruncate,
		"%c0%ae": ClassOverlongUTF8,
		"+ADw-":  ClassUTF7,
		"&#60;":  ClassHTMLEntity,
	}
	for s, want := range mustDetect {
		if got := Detect([]byte(s)); !got.Has(want) {
			t.Errorf("Detect(%q) = %s, missing %s", s, got, want)
		}
	}
}

func readings(src string) []Reading {
	var s Set
	b := []byte(src)
	s.Build(b, Detect(b))
	return s.All()
}

// readingFor returns the reading resolving class, if present.
func readingFor(src string, class Class) (string, bool) {
	for _, r := range readings(src) {
		if r.Class == class {
			return string(r.Bytes), true
		}
	}
	return "", false
}

func TestVerbatimReadingIsAlwaysFirst(t *testing.T) {
	for _, src := range []string{"", "plain", "%252e", "+ADw-", `a\b`} {
		rs := readings(src)
		if len(rs) == 0 {
			t.Fatalf("Build(%q) produced no readings", src)
		}
		if string(rs[0].Bytes) != src {
			t.Errorf("Build(%q): first reading = %q, want the input verbatim",
				src, rs[0].Bytes)
		}
		if rs[0].Class != 0 {
			t.Errorf("Build(%q): verbatim reading claims class %s", src, rs[0].Class)
		}
	}
}

// TestUnambiguousValueHasOneReading is the cost guarantee. Traffic with no
// ambiguity must not pay for alternatives, or multi-interpretation would have
// been bought with the performance thesis.
func TestUnambiguousValueHasOneReading(t *testing.T) {
	for _, src := range []string{
		"", "plain text", "/api/v1/orders/12345", "hello world",
		"550e8400-e29b-41d4-a716-446655440000", "2026-08-05T07:38:00Z",
	} {
		if n := len(readings(src)); n != 1 {
			t.Errorf("Build(%q) produced %d readings, want 1", src, n)
		}
	}
}

func TestDoubleDecodedReading(t *testing.T) {
	tests := []struct{ src, want string }{
		{"%252e%252e%252f", "%2e%2e%2f"},
		{"..%252f..%252f", "..%2f..%2f"},
		{"%253Cscript%253E", "%3Cscript%3E"},
	}
	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			got, ok := readingFor(tt.src, ClassDoubleEncoded)
			if !ok {
				t.Fatalf("no double-decoded reading for %q", tt.src)
			}
			if got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSeparatorReading(t *testing.T) {
	got, ok := readingFor(`..\..\windows\system32`, ClassSeparator)
	if !ok {
		t.Fatal("no separator reading")
	}
	if want := "../../windows/system32"; got != want {
		t.Errorf("= %q, want %q", got, want)
	}
}

func TestNullTruncateReading(t *testing.T) {
	tests := []struct{ src, want string }{
		{"/etc/passwd%00.jpg", "/etc/passwd"},
		{"file\x00suffix", "file"},
		{"%00leading", ""},
	}
	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			got, ok := readingFor(tt.src, ClassNullTruncate)
			if !ok {
				t.Fatalf("no truncated reading for %q", tt.src)
			}
			if got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOverlongUTF8Reading(t *testing.T) {
	tests := []struct {
		name, src, want string
	}{
		{"dot 2byte", "%c0%ae%c0%ae", ".."},
		{"slash 2byte", "%c0%af", "/"},
		{"lt 2byte", "%c0%bc", "<"},
		{"gt 2byte", "%c0%be", ">"},
		{"3byte dot", "%e0%80%ae", "."},
		{"traversal", "%c0%ae%c0%ae%c0%afetc%c0%afpasswd", "../etc/passwd"},
		{"raw bytes", "\xc0\xae\xc0\xae", ".."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := readingFor(tt.src, ClassOverlongUTF8)
			if !ok {
				t.Fatalf("no overlong reading for %q", tt.src)
			}
			if got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}

// TestUTF7Reading covers the CVE-2026-21876 vector directly.
func TestUTF7Reading(t *testing.T) {
	tests := []struct {
		name, src, want string
	}{
		{"lt", "+ADw-", "<"},
		{"gt", "+AD4-", ">"},
		{"script tag", "+ADw-script+AD4-", "<script>"},
		{"full payload", "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
			"<script>alert(1)</script>"},
		// "+-" is UTF-7's literal plus, but a value containing only that has no
		// shift sequence, so Detect reports no ambiguity and no reading exists.
		{"plus not followed by base64", "a+ b", "a+ b"},
		{"text around", "x+ADw-y", "x<y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := readingFor(tt.src, ClassUTF7)
			if !ok {
				// Inputs that Detect does not flag as UTF-7 have no such
				// reading, which is correct for "a+ b".
				if tt.src == tt.want {
					return
				}
				t.Fatalf("no UTF-7 reading for %q", tt.src)
			}
			if got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHTMLEntityReading(t *testing.T) {
	tests := []struct {
		name, src, want string
	}{
		{"named lt gt", "&lt;script&gt;", "<script>"},
		{"amp", "AT&amp;T", "AT&T"},
		{"quot", "&quot;x&quot;", `"x"`},
		{"decimal", "&#60;script&#62;", "<script>"},
		{"hex lower", "&#x3c;script&#x3e;", "<script>"},
		{"hex upper", "&#X3C;", "<"},
		{"no semicolon", "&#60script", "<script"},
		{"unknown entity kept", "&nosuchentity;", "&nosuchentity;"},
		{"bare ampersand kept", "a & b", "a & b"},
		{"apos", "&apos;", "'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := readingFor(tt.src, ClassHTMLEntity)
			if !ok {
				if tt.src == tt.want {
					return
				}
				t.Fatalf("no entity reading for %q", tt.src)
			}
			if got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDuplicateReadingsDropped keeps the enumeration honest: an alternative
// that says nothing new is pure cost.
func TestDuplicateReadingsDropped(t *testing.T) {
	// A lone backslash-free, entity-free value whose alternative decodings all
	// collapse back to the original.
	src := "a=1&b=2"
	rs := readings(src)
	seen := map[string]bool{}
	for _, r := range rs {
		if seen[string(r.Bytes)] {
			t.Errorf("duplicate reading %q", r.Bytes)
		}
		seen[string(r.Bytes)] = true
	}
}

func TestReadingsAreBounded(t *testing.T) {
	// Every class at once, repeated, must still respect the cap.
	src := strings.Repeat("%252e\\x%00+ADw-&lt;", 20)
	rs := readings(src)
	if len(rs) > MaxReadings {
		t.Errorf("produced %d readings, cap is %d", len(rs), MaxReadings)
	}
}

func TestSetIsReusable(t *testing.T) {
	var s Set

	// Reuse across values must not leak state: a later value's readings must
	// not include an earlier value's bytes.
	for _, src := range []string{"%252e", "plain", "+ADw-", "", `a\b`} {
		b := []byte(src)
		s.Build(b, Detect(b))

		if string(s.At(0).Bytes) != src {
			t.Fatalf("verbatim reading = %q, want %q", s.At(0).Bytes, src)
		}
		for i := range s.Len() {
			if s.At(i).Bytes == nil && s.At(i).Class != 0 {
				t.Errorf("reading %d has a class but no bytes", i)
			}
		}
	}
}

func TestClassString(t *testing.T) {
	if got := Class(0).String(); got != "none" {
		t.Errorf("Class(0).String() = %q, want \"none\"", got)
	}
	if got := ClassUTF7.String(); got != "utf7" {
		t.Errorf("= %q, want \"utf7\"", got)
	}
	both := (ClassUTF7 | ClassHTMLEntity).String()
	if !strings.Contains(both, "utf7") || !strings.Contains(both, "html_entity") {
		t.Errorf("= %q, want both names", both)
	}
}

// FuzzBuild asserts the invariants that make multi-interpretation safe on
// arbitrary attacker input: it never panics, always yields the verbatim reading
// first, stays within the cap, and is deterministic.
func FuzzBuild(f *testing.F) {
	seeds := []string{
		"", "a", "%252e", `a\b`, "%00", "%c0%ae", "+ADw-", "&lt;",
		"%252e\\x%00+ADw-&lt;", "%", "%c0", "+", "&", "&#", "&#x",
		"+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-",
		"\x00\xff\xc0\xc1\xe0", strings.Repeat("%25", 100),
		strings.Repeat("+ADw-", 50), strings.Repeat("&lt;", 50),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 32768 {
			t.Skip()
		}
		b := []byte(src)

		var s Set
		classes := Detect(b)
		s.Build(b, classes)

		if s.Len() < 1 {
			t.Fatal("no readings produced")
		}
		if s.Len() > MaxReadings {
			t.Fatalf("produced %d readings, cap is %d", s.Len(), MaxReadings)
		}
		if string(s.At(0).Bytes) != src {
			t.Fatalf("first reading = %q, want the input verbatim", s.At(0).Bytes)
		}

		// Every alternative must resolve a class that was actually detected;
		// inventing readings for absent ambiguity would be wasted work and a
		// misleading audit record.
		for i := 1; i < s.Len(); i++ {
			r := s.At(i)
			if r.Class == 0 {
				t.Fatalf("reading %d has no class", i)
			}
			if !classes.Has(r.Class) {
				t.Fatalf("reading %d resolves %s, which Detect did not report", i, r.Class)
			}
		}

		// Determinism: readings are cached per transaction and compared, so a
		// non-deterministic build would make decisions order-dependent.
		var s2 Set
		s2.Build(b, classes)
		if s2.Len() != s.Len() {
			t.Fatalf("non-deterministic reading count: %d vs %d", s.Len(), s2.Len())
		}
		for i := range s.Len() {
			if string(s.At(i).Bytes) != string(s2.At(i).Bytes) {
				t.Fatalf("reading %d differs between runs", i)
			}
		}
	})
}

func BenchmarkDetectClean(b *testing.B) {
	src := []byte("an ordinary search query with no encoding markers present")
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		Detect(src)
	}
}

func BenchmarkBuildClean(b *testing.B) {
	src := []byte("an ordinary search query with no encoding markers present")
	classes := Detect(src)
	var s Set
	b.ReportAllocs()
	for b.Loop() {
		s.Build(src, classes)
	}
}

func BenchmarkBuildAmbiguous(b *testing.B) {
	src := []byte("%252e%252e%252f+ADw-script+AD4-&lt;x&gt;\\path%00")
	classes := Detect(src)
	var s Set
	b.ReportAllocs()
	for b.Loop() {
		s.Build(src, classes)
	}
}
