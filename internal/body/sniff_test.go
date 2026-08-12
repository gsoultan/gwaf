// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package body

import (
	"bytes"
	"strings"
	"testing"
)

func TestSniffMultipart(t *testing.T) {
	const part = "Content-Disposition: form-data; name=\"cmd\"\r\n\r\nvalue\r\n"

	for _, tc := range []struct {
		name string
		src  string
		want string // "" means it must not sniff
	}{
		// ---- the shapes it must recognise ----------------------------------
		{name: "webkit boundary", src: "--WebKitFormBoundaryAbc123\r\n" + part,
			want: "WebKitFormBoundaryAbc123"},
		{name: "dashes in boundary", src: "--------------------------abc\r\n" + part,
			want: "------------------------abc"},
		{name: "bare LF line ending", src: "--BOUND\n" + part, want: "BOUND"},
		{name: "trailing space is stripped", src: "--BOUND \r\n" + part, want: "BOUND"},
		{name: "boundary at 70 chars", src: "--" + strings.Repeat("a", 70) + "\r\n" + part,
			want: strings.Repeat("a", 70)},
		{name: "header in mixed case", src: "--B\r\nCONTENT-DISPOSITION: form-data\r\n\r\nx",
			want: "B"},

		// ---- shapes that merely start with "--" ----------------------------
		//
		// Every one of these is ordinary content. A sniff that fires here costs
		// a re-parse under a reading nobody will use, and can only invent
		// findings.
		{name: "unified diff", src: "--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n"},
		{name: "pgp block", src: "-----BEGIN PGP SIGNATURE-----\nabc\n"},
		{name: "cli flags", src: "--verbose --output=file.txt"},
		{name: "yaml marker", src: "---\nname: test\n"},
		{name: "sql comment", src: "-- a comment\nSELECT 1"},
		{name: "no part header", src: "--BOUND\r\njust some text\r\n--BOUND--\r\n"},

		// ---- malformed boundaries ------------------------------------------
		{name: "empty", src: ""},
		{name: "just dashes", src: "--"},
		{name: "dashes and newline", src: "--\r\n" + part},
		{name: "boundary over 70 chars", src: "--" + strings.Repeat("a", 71) + "\r\n" + part},
		{name: "illegal byte in boundary", src: "--BO UND\r\n" + part},
		{name: "illegal byte, tab", src: "--BO\tUND\r\n" + part},
		{name: "no line ending at all", src: "--BOUNDARYWITHNOEOL"},
		{name: "does not start with dashes", src: "x--BOUND\r\n" + part},
		{name: "part header past the cap", src: "--B\r\n" + strings.Repeat("x", 8192) + part},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SniffMultipart([]byte(tc.src))
			if tc.want == "" {
				if ok {
					t.Errorf("sniffed %q, want no sniff", got)
				}
				return
			}
			if !ok {
				t.Fatalf("did not sniff, want boundary %q", tc.want)
			}
			if string(got) != tc.want {
				t.Errorf("boundary = %q, want %q", got, tc.want)
			}
		})
	}
}

// FuzzSniffMultipart holds the properties the caller relies on.
//
// This function reads attacker-controlled bytes and hands what it finds to the
// multipart parser as a boundary, which makes it a parser taking hostile input
// and therefore non-negotiably fuzzed (CLAUDE.md §4). The three properties are
// the ones a caller cannot check for itself:
//
//   - it returns, and does not panic, on any input;
//   - a sniffed boundary is a slice *of the input*, so it cannot smuggle bytes
//     from elsewhere in memory into the parser;
//   - a sniffed boundary is one ParseMultipart accepts without panicking, since
//     that is precisely what transaction.go does with it.
func FuzzSniffMultipart(f *testing.F) {
	f.Add("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--B--\r\n")
	f.Add("--- a/x.go\n+++ b/x.go\n")
	f.Add("--\r\n")
	f.Add("--" + strings.Repeat("a", 70) + "\r\nContent-Disposition: x\r\n")
	f.Add("")
	f.Add("--B\nContent-Disposition:\n")

	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 1<<16 {
			t.Skip()
		}
		b := []byte(src)
		boundary, ok := SniffMultipart(b)
		if !ok {
			if boundary != nil {
				t.Fatal("returned a boundary alongside ok=false")
			}
			return
		}

		if len(boundary) == 0 || len(boundary) > 70 {
			t.Fatalf("boundary length %d outside RFC 2046 bounds", len(boundary))
		}
		// A slice of the input, not a fresh allocation carrying who-knows-what.
		if !isSliceOf(b, boundary) {
			t.Fatal("boundary does not alias the input")
		}
		for _, c := range boundary {
			if !isBoundaryByte(c) {
				t.Fatalf("boundary contains %q, which is not a bchar", c)
			}
		}

		// The contract the caller depends on: whatever this returns is safe to
		// parse with.
		var p Parser
		p.Reset(Limits{})
		_ = p.ParseMultipart(b, boundary,
			func(PartInfo) bool { return true },
			func(name, value []byte, _ Kind) bool {
				if len(name) > 65536 || len(value) > 1<<20 {
					t.Fatal("buffer exceeded its ceiling")
				}
				return true
			})
	})
}

// isSliceOf reports whether inner points into outer.
func isSliceOf(outer, inner []byte) bool {
	if len(inner) == 0 {
		return true
	}
	i := bytes.Index(outer, inner)
	return i >= 0
}
