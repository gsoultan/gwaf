// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzEncodedWidthIsWhatJSONWrites is the harness behind bound: it claims to
// know how many bytes encoding/json writes for a string, and the ceiling on a
// record is derived from that claim. If encoding/json ever escapes differently,
// this fails before the ceiling does.
func FuzzEncodedWidthIsWhatJSONWrites(f *testing.F) {
	f.Add("plain")
	f.Add("<script>alert(1)</script>")
	f.Add("\xa3\xa3\xa3")
	f.Add("\x00\x01\x1f\n\r\t\"\\")
	f.Add("  �")
	f.Add("é漢字")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := encodedWidth(s), len(b)-2; got != want {
			t.Errorf("encodedWidth(%q) = %d, encoding/json writes %d", s, got, want)
		}
	})
}

// TestBoundCutsWhatIsWrittenNotWhatArrived: the bound is on the encoded form.
// A string of '<' is six bytes a character on the wire, so the bound keeps a
// sixth of it, and never splits a multibyte character.
func TestBoundCutsWhatIsWrittenNotWhatArrived(t *testing.T) {
	cases := []struct {
		name string
		in   string
		n    int
	}{
		{"angle brackets", strings.Repeat("<", 4096), 256},
		{"invalid utf-8", strings.Repeat("\xa3", 4096), 256},
		{"control characters", strings.Repeat("\x01", 4096), 256},
		{"multibyte", strings.Repeat("漢", 4096), 256},
		{"mixed", strings.Repeat("a<\xa3é", 1024), 300},
		{"fits", "short", 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := bound(tc.in, tc.n)
			kept := strings.TrimSuffix(out, "…(truncated)")
			if len(tc.in) > tc.n && kept == out && encodedWidth(tc.in) > tc.n {
				t.Fatalf("not truncated")
			}
			if !utf8.ValidString(kept) && utf8.ValidString(tc.in) {
				t.Errorf("the cut split a character: %q", kept)
			}
			b, _ := json.Marshal(kept)
			if w := len(b) - 2; w > tc.n {
				t.Errorf("the kept part is %d bytes on the wire, over the bound of %d", w, tc.n)
			}
			if !strings.HasPrefix(tc.in, kept) {
				t.Errorf("the kept part is not a prefix of the input")
			}
		})
	}
}
