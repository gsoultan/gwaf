// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package transform

import (
	"strings"
	"testing"

	"github.com/gsoultan/gwaf/rules"
)

// apply runs a transform with a generously sized scratch buffer and returns the
// result as a string plus whether anything changed.
func apply(t rules.Transform, src string) (string, bool) {
	dst := make([]byte, 0, t.MaxOutputLen(len(src)))
	out, changed := t.Apply(dst, []byte(src))
	return string(out), changed
}

func TestLowercase(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		changed bool
	}{
		{"", "", false},
		{"already lower", "already lower", false},
		{"UPPER", "upper", true},
		{"MiXeD", "mixed", true},
		{"digits 123 !@#", "digits 123 !@#", false},
		// Non-ASCII must pass through: Unicode folding can change byte length,
		// which would invalidate match spans.
		{"\xc3\x89T\xc3\x89", "\xc3\x89t\xc3\x89", true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, changed := apply(Lowercase, tt.in)
			if got != tt.want || changed != tt.changed {
				t.Errorf("Apply(%q) = (%q, %v), want (%q, %v)",
					tt.in, got, changed, tt.want, tt.changed)
			}
		})
	}
}

func TestRemoveWhitespace(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		changed bool
	}{
		{"", "", false},
		{"nospace", "nospace", false},
		{"a b", "ab", true},
		{"UNI ON SEL ECT", "UNIONSELECT", true},
		{"\ta\nb\r\vc\f", "abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, changed := apply(RemoveWhitespace, tt.in)
			if got != tt.want || changed != tt.changed {
				t.Errorf("Apply(%q) = (%q, %v), want (%q, %v)",
					tt.in, got, changed, tt.want, tt.changed)
			}
		})
	}
}

func TestCompressWhitespace(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		changed bool
	}{
		{"", "", false},
		{"a b c", "a b c", false},
		{"a  b", "a b", true},
		{"a\t\tb", "a b", true},
		{"a\n b", "a b", true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, changed := apply(CompressWhitespace, tt.in)
			if got != tt.want || changed != tt.changed {
				t.Errorf("Apply(%q) = (%q, %v), want (%q, %v)",
					tt.in, got, changed, tt.want, tt.changed)
			}
		})
	}
}

func TestURLDecode(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		changed bool
	}{
		{"nothing to decode", "plain", "plain", false},
		{"simple", "a%20b", "a b", true},
		{"plus is space", "a+b", "a b", true},
		{"uppercase hex", "%2F", "/", true},
		{"lowercase hex", "%2f", "/", true},
		{"traversal", "..%2f..%2fetc", "../../etc", true},
		{"script tag", "%3Cscript%3E", "<script>", true},
		{"null byte", "a%00b", "a\x00b", true},

		// Malformed escapes are preserved verbatim rather than dropped or
		// guessed. Guessing is how a WAF and an origin come to disagree about
		// what a request says, which is the CVE-2026-21876 failure class.
		{"truncated at end", "abc%", "abc%", true},
		{"one hex digit", "abc%4", "abc%4", true},
		{"non-hex digits", "%zz", "%zz", true},
		{"partial hex", "%4z", "%4z", true},

		// Single decoding pass only: %2525 must not become %. Recursive
		// decoding invents an interpretation the origin may not share.
		{"no recursive decode", "%2525", "%25", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := apply(URLDecode, tt.in)
			if got != tt.want || changed != tt.changed {
				t.Errorf("Apply(%q) = (%q, %v), want (%q, %v)",
					tt.in, got, changed, tt.want, tt.changed)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"simple", "/a/b/c", "/a/b/c"},
		{"dot segment", "/a/./b", "/a/b"},
		{"parent segment", "/a/b/../c", "/a/c"},
		{"double slash", "/a//b", "/a/b"},
		{"backslash separator", `\a\b`, "/a/b"},
		{"mixed separators", `/a\b/c`, "/a/b/c"},
		{"trailing slash kept", "/a/b/", "/a/b/"},
		{"root", "/", "/"},

		// An absolute path cannot escape its root; a relative one can, and that
		// traversal is meaningful so it must be preserved.
		{"cannot escape root", "/a/../../b", "/b"},
		{"relative traversal preserved", "../../etc/passwd", "../../etc/passwd"},
		{"relative single", "../etc", "../etc"},

		{"traversal to file", "/var/www/../../etc/passwd", "/etc/passwd"},
		{"windows traversal", `..\..\windows\system32`, "../../windows/system32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := apply(NormalizePath, tt.in)
			if got != tt.want {
				t.Errorf("Apply(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizePathIdempotent asserts that normalizing a normalized path is a
// no-op. A transform that keeps changing its own output would let an attacker
// pick which pass the origin agrees with.
func TestNormalizePathIdempotent(t *testing.T) {
	inputs := []string{
		"/a/b/c", "/a/./b", "/a/b/../c", `..\..\x`, "../../etc/passwd",
		"/", "//", "/a//b/", `\`, "a/b/../../..",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			once, _ := apply(NormalizePath, in)
			twice, _ := apply(NormalizePath, once)
			if once != twice {
				t.Errorf("not idempotent: %q -> %q -> %q", in, once, twice)
			}
		})
	}
}

// TestUnchangedReturnsInput verifies the no-change fast path returns the
// original slice rather than a copy. This is what keeps benign traffic free of
// allocations, so it is a behavioural guarantee, not an implementation detail.
func TestUnchangedReturnsInput(t *testing.T) {
	all := []rules.Transform{
		Lowercase, RemoveWhitespace, CompressWhitespace, URLDecode, NormalizePath,
	}
	src := []byte("plainlowercasetext")

	for _, tr := range all {
		t.Run(tr.Name(), func(t *testing.T) {
			dst := make([]byte, 0, tr.MaxOutputLen(len(src)))
			out, changed := tr.Apply(dst, src)
			if changed {
				t.Skip("transform reports a change for this input")
			}
			if len(out) != len(src) || (len(out) > 0 && &out[0] != &src[0]) {
				t.Error("unchanged transform must return the input slice, not a copy")
			}
		})
	}
}

// TestMaxOutputLenRespected asserts no transform exceeds its own declared
// bound. The engine sizes scratch from that bound, so exceeding it means
// growing the engine's buffer — an allocation on every request.
//
// Checking the final length is not enough: a transform can transiently exceed
// the bound and trim back, which grows the buffer without leaving evidence in
// the result. The capacity check below is what catches that, and it is how the
// NormalizePath trailing-separator overflow was found.
func TestMaxOutputLenRespected(t *testing.T) {
	all := []rules.Transform{
		Lowercase, RemoveWhitespace, CompressWhitespace, URLDecode, NormalizePath,
	}
	inputs := []string{
		"", "a", "/a/b", "/a/b/c", "a/b/c", "../..", "/x/y/z/w",
		strings.Repeat("%20", 100), strings.Repeat("../", 100),
		strings.Repeat("A B\t", 50), `\\\\a\\\\b`, "%%%%", "+++",
		strings.Repeat("/seg", 200),
	}

	for _, tr := range all {
		for _, in := range inputs {
			bound := tr.MaxOutputLen(len(in))

			// Give Apply exactly the capacity it asked for. If it needs more,
			// append reallocates and cap(out) exceeds the bound.
			dst := make([]byte, 0, bound)
			out, changed := tr.Apply(dst, []byte(in))

			if len(out) > bound {
				t.Errorf("%s(%q): output %d bytes exceeds MaxOutputLen %d",
					tr.Name(), in, len(out), bound)
			}
			// Only meaningful when the transform wrote into dst. On the
			// unchanged path it returns the input slice, whose capacity comes
			// from the caller's allocation and says nothing about the bound.
			if changed && cap(out) > bound {
				t.Errorf("%s(%q): grew the buffer to cap %d, exceeding MaxOutputLen %d "+
					"(this allocates on every request)", tr.Name(), in, cap(out), bound)
			}
		}
	}
}

func TestNamesAreStable(t *testing.T) {
	want := map[rules.Transform]string{
		Lowercase:          "lowercase",
		RemoveWhitespace:   "remove_whitespace",
		CompressWhitespace: "compress_whitespace",
		URLDecode:          "url_decode",
		NormalizePath:      "normalize_path",
	}
	for tr, name := range want {
		if got := tr.Name(); got != name {
			t.Errorf("Name() = %q, want %q", got, name)
		}
	}
}

func FuzzTransforms(f *testing.F) {
	seeds := []string{
		"", "a", "%20", "%2f%2e%2e", "../../etc/passwd", `..\..\x`,
		"A B\tC", "%", "%4", "%zz", "+++", "///", "\x00\xff",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	all := []rules.Transform{
		Lowercase, RemoveWhitespace, CompressWhitespace, URLDecode, NormalizePath,
	}

	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 65536 {
			t.Skip()
		}
		for _, tr := range all {
			bound := tr.MaxOutputLen(len(src))

			dst := make([]byte, 0, bound)
			out, changed := tr.Apply(dst, []byte(src))

			if len(out) > bound {
				t.Fatalf("%s(%q): %d bytes exceeds bound %d",
					tr.Name(), src, len(out), bound)
			}
			// Only meaningful when the transform wrote into dst; see
			// TestMaxOutputLenRespected.
			if changed && cap(out) > bound {
				t.Fatalf("%s(%q): grew the buffer to cap %d, exceeding bound %d",
					tr.Name(), src, cap(out), bound)
			}
			if !changed && string(out) != src {
				t.Fatalf("%s(%q): reported no change but returned %q",
					tr.Name(), src, out)
			}

			// Transforms are memoised per transaction, so an impure transform
			// would make a decision depend on evaluation order.
			dst2 := make([]byte, 0, bound)
			out2, changed2 := tr.Apply(dst2, []byte(src))
			if changed != changed2 || string(out) != string(out2) {
				t.Fatalf("%s(%q): not deterministic", tr.Name(), src)
			}
		}
	})
}
