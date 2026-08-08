// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package interpret

import "testing"

// TestEveryClassSurvivesPercentEncoding is the standing guard against the worst
// bug this package has had, which it had three times.
//
// Readings are enumerated *before* the transform chain runs, so a value that
// arrived over a query string is still wearing its percent-escapes. Any class
// keyed on a literal character is therefore blind to the only spelling a real
// request carries — and blind in a way no unit test notices, because a test
// hands the raw bytes straight to Detect.
//
// It cost three classes before the pattern was seen:
//
//   - ClassHTMLEntity looked for '&', which on the wire is "%26". No entity
//     payload a browser can send was ever detected.
//   - ClassUTF7 looked for '+', which on the wire *must* be "%2B" because a bare
//     '+' in a query string means space. The reading named for CVE-2026-21876 was
//     inert against the vector it exists for.
//   - ClassBestFit shipped with the same hole and was caught by this test.
//
// A new class belongs in this table. If it detects the raw spelling and not the
// encoded one, it does not work.
func TestEveryClassSurvivesPercentEncoding(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw, wire string
		class     Class
	}{
		{"separator", `..\..\windows`, "..%5C..%5Cwindows", ClassSeparator},
		{"utf7", "+ADw-script+AD4-", "%2BADw-script%2BAD4-", ClassUTF7},
		{"null_truncate", "/etc/passwd\x00.jpg", "/etc/passwd%00.jpg", ClassNullTruncate},
		{"overlong_utf8", "\xc0\xae\xc0\xaf", "%c0%ae%c0%af", ClassOverlongUTF8},
		{"html_entity", "&#60;script&#62;", "%26%2360%3Bscript%26%2362%3B", ClassHTMLEntity},
		{"best_fit", "＜script＞", "%EF%BC%9Cscript%EF%BC%9E", ClassBestFit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !Detect([]byte(tc.raw)).Has(tc.class) {
				t.Fatalf("class not detected even raw: %q", tc.raw)
			}
			if !Detect([]byte(tc.wire)).Has(tc.class) {
				t.Errorf("blind on the wire: %q is detected, %q is not — "+
					"this class cannot fire on a real request", tc.raw, tc.wire)
			}
		})
	}
}

// TestUTF7DecodesFromTheWireForm pins the decoding as well as the detection: a
// class can be claimed and still yield the wrong bytes.
func TestUTF7DecodesFromTheWireForm(t *testing.T) {
	for _, tt := range []struct{ src, want string }{
		{"+ADw-script+AD4-", "<script>"},
		{"%2BADw-script%2BAD4-", "<script>"},
		// Fully encoded, as a client must send it. A raw '+' mixed in would be
		// a space to the server too, so it is not a payload anyone can use.
		{"%2BADw-img%2BACA-src%2BAD0-x%2BAD4-", "<img src=x>"},
	} {
		t.Run(tt.src, func(t *testing.T) {
			got, ok := readingFor(tt.src, ClassUTF7)
			if !ok {
				t.Fatalf("no utf7 reading for %q", tt.src)
			}
			if got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSeparatorDecodesFromTheWireForm is the same for the backslash reading.
func TestSeparatorDecodesFromTheWireForm(t *testing.T) {
	for _, tt := range []struct{ src, want string }{
		{`..\..\windows`, "../../windows"},
		{"..%5C..%5Cwindows", "../../windows"},
	} {
		got, ok := readingFor(tt.src, ClassSeparator)
		if !ok {
			t.Fatalf("no separator reading for %q", tt.src)
		}
		if got != tt.want {
			t.Errorf("%q = %q, want %q", tt.src, got, tt.want)
		}
	}
}
