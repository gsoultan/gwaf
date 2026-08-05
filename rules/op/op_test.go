// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package op

import (
	"slices"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf/rules"
)

func eval(o rules.Operator, value string) (rules.Match, bool) {
	return o.Eval(&rules.EvalContext{}, []byte(value))
}

func TestContains(t *testing.T) {
	o := Contains("select")

	tests := []struct {
		value string
		want  bool
	}{
		{"select", true},
		{"SELECT", true},
		{"SeLeCt", true},
		{"xxselectyy", true},
		{"insert", false},
		{"selec", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if _, got := eval(o, tt.value); got != tt.want {
				t.Errorf("Eval(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestContainsReportsSpan(t *testing.T) {
	o := Contains("select")
	m, ok := eval(o, "aaaSELECTbbb")
	if !ok {
		t.Fatal("no match")
	}
	if m.Span.Off != 3 || m.Span.Len != 6 {
		t.Errorf("span = {%d,%d}, want {3,6}", m.Span.Off, m.Span.Len)
	}
}

func TestContainsAny(t *testing.T) {
	o := ContainsAny("union", "select", "drop")

	for _, v := range []string{"UNION", "select", "xdropx"} {
		if _, ok := eval(o, v); !ok {
			t.Errorf("Eval(%q) = false, want true", v)
		}
	}
	if _, ok := eval(o, "nothing here"); ok {
		t.Error("Eval matched unrelated input")
	}
}

// TestOperatorMatchesEverythingItsLiteralsAdmit is the invariant that keeps
// prefiltering sound. The prefilter folds ASCII case; if an operator were
// stricter than the literals it declares, the prefilter would nominate it as a
// candidate and the operator would then reject input it should have matched —
// a silent miss with no way to observe it.
func TestOperatorMatchesEverythingItsLiteralsAdmit(t *testing.T) {
	ops := []rules.Operator{
		Contains("SeLeCt"),
		ContainsAny("UNION", "Drop"),
		HasPrefix("/Admin"),
		Equals("Exact"),
	}

	for _, o := range ops {
		lits, required := o.Literals()
		if !required {
			continue
		}
		for _, lit := range lits {
			for _, variant := range []string{lit, strings.ToUpper(lit), strings.ToLower(lit)} {
				if o.Name() == "equals" && variant != lit {
					// Equals is case-sensitive by contract, so it declares its
					// literal only as a necessary condition, not a sufficient
					// one. Its literal is still a superset of what it matches,
					// which is the direction that keeps prefiltering sound.
					continue
				}
				if _, ok := eval(o, variant); !ok {
					t.Errorf("%s: declared literal %q but did not match %q",
						o.Name(), lit, variant)
				}
			}
		}
	}
}

func TestEquals(t *testing.T) {
	o := Equals("exact")

	if _, ok := eval(o, "exact"); !ok {
		t.Error("exact match failed")
	}
	// Equals is case-sensitive: header and token comparisons where case
	// matters would otherwise be silently loosened.
	if _, ok := eval(o, "EXACT"); ok {
		t.Error("Equals matched a different case")
	}
	if _, ok := eval(o, "exactly"); ok {
		t.Error("Equals matched a superstring")
	}
}

func TestHasPrefix(t *testing.T) {
	o := HasPrefix("..")

	for _, v := range []string{"..", "../etc", "..\\windows"} {
		if _, ok := eval(o, v); !ok {
			t.Errorf("Eval(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", ".", "x..", "a/../b"} {
		if _, ok := eval(o, v); ok {
			t.Errorf("Eval(%q) = true, want false", v)
		}
	}
}

func TestFuncIsUnconditionalWithoutHint(t *testing.T) {
	o := Func("test", func([]byte) bool { return true })

	if _, required := o.Literals(); required {
		t.Error("Func without a hint reported required literals")
	}
}

func TestFuncWithLiterals(t *testing.T) {
	o := Func("test", func(v []byte) bool {
		return strings.Contains(string(v), "__schema")
	}).(LiteralHinter).WithLiterals("__schema")

	lits, required := o.Literals()
	if !required {
		t.Fatal("hinted Func did not report required literals")
	}
	if !slices.Equal(lits, []string{"__schema"}) {
		t.Errorf("Literals() = %v, want [__schema]", lits)
	}
}

// TestWithLiteralsDoesNotMutateOriginal guards against a shared-operator bug:
// hinting one rule's operator must not silently change another's.
func TestWithLiteralsDoesNotMutateOriginal(t *testing.T) {
	base := Func("test", func([]byte) bool { return true })
	hinted := base.(LiteralHinter).WithLiterals("x")

	if _, required := base.Literals(); required {
		t.Error("WithLiterals mutated the original operator")
	}
	if _, required := hinted.Literals(); !required {
		t.Error("hinted copy lost its literals")
	}
}

func TestEmptyLiteralsAreNotRequired(t *testing.T) {
	// An operator with nothing to match on must report itself unconditional
	// rather than claim an empty required set, which would prefilter it away
	// entirely.
	if _, required := ContainsAny().Literals(); required {
		t.Error("ContainsAny() with no needles claimed required literals")
	}
	if _, required := Equals("").Literals(); required {
		t.Error("Equals(\"\") claimed a required literal")
	}
}

func TestIndexFold(t *testing.T) {
	tests := []struct {
		haystack string
		needle   string
		want     int
	}{
		{"hello", "hello", 0},
		{"xxhello", "hello", 2},
		{"HELLO", "hello", 0},
		{"xxHeLLoyy", "hello", 2},
		{"hello", "world", -1},
		{"", "x", -1},
		{"x", "", 0},
		{"hell", "hello", -1},
		// A near miss before the real match: the scan must resume rather than
		// give up at the first candidate first-byte.
		{"heXlohello", "hello", 5},
		{"aaab", "ab", 2},
		{"AAAB", "ab", 2},
	}

	for _, tt := range tests {
		t.Run(tt.haystack+"/"+tt.needle, func(t *testing.T) {
			got := indexFold([]byte(tt.haystack), []byte(toLower(tt.needle)))
			if got != tt.want {
				t.Errorf("indexFold(%q, %q) = %d, want %d",
					tt.haystack, tt.needle, got, tt.want)
			}
		})
	}
}

func TestToLower(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"abc", "abc"},
		{"ABC", "abc"},
		{"AbC123!", "abc123!"},
		// Non-ASCII passes through: folding it could change byte length and
		// invalidate the span offsets a match reports.
		{"\xc3\x89", "\xc3\x89"},
	}
	for _, tt := range tests {
		if got := toLower(tt.in); got != tt.want {
			t.Errorf("toLower(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCostsAreNonZero(t *testing.T) {
	// A zero-cost operator would be invisible to fuel metering, which would
	// leave a hole in the DoS bound.
	ops := []rules.Operator{
		Contains("x"), ContainsAny("x"), Equals("x"), HasPrefix("x"),
		Func("f", func([]byte) bool { return false }),
	}
	for _, o := range ops {
		if o.Cost() <= 0 {
			t.Errorf("%s: Cost() = %d, want > 0", o.Name(), o.Cost())
		}
	}
}

// FuzzIndexFold checks the case-insensitive search against the standard
// library. A disagreement is either a missed detection or a false positive.
func FuzzIndexFold(f *testing.F) {
	f.Add("hello world", "world")
	f.Add("HELLO", "hello")
	f.Add("aaab", "ab")
	f.Add("", "")
	f.Add("\x00\xff", "\xff")

	f.Fuzz(func(t *testing.T, haystack, needle string) {
		if len(haystack) > 4096 || len(needle) > 256 {
			t.Skip()
		}
		// strings.ToLower is Unicode-aware and can change byte length, which
		// this deliberately does not do, so only compare on ASCII input.
		if !isASCII(haystack) || !isASCII(needle) {
			t.Skip()
		}

		got := indexFold([]byte(haystack), []byte(toLower(needle)))
		want := strings.Index(strings.ToLower(haystack), strings.ToLower(needle))

		if got != want {
			t.Fatalf("indexFold(%q, %q) = %d, want %d", haystack, needle, got, want)
		}
	})
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
