// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package prefilter

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf/internal/bitset"
)

// scan is a test helper returning the matched rule indices as a sorted slice.
func scan(t *testing.T, a *Automaton, input string) []int {
	t.Helper()
	set := bitset.New(1024)
	a.Scan([]byte(input), set)
	var got []int
	set.All(func(v int) bool {
		got = append(got, v)
		return true
	})
	return got
}

func build(pairs ...any) *Automaton {
	b := NewBuilder()
	for i := 0; i+1 < len(pairs); i += 2 {
		b.Add(pairs[i].(string), uint32(pairs[i+1].(int)))
	}
	return b.Build()
}

func TestScanSinglePattern(t *testing.T) {
	a := build("select", 0)

	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{"exact", "select", []int{0}},
		{"embedded", "xxselectyy", []int{0}},
		{"uppercase", "SELECT", []int{0}},
		{"mixed case", "SeLeCt", []int{0}},
		{"at end", "abcselect", []int{0}},
		{"absent", "insert", nil},
		{"partial", "selec", nil},
		{"empty input", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scan(t, a, tt.input)
			if !equalInts(got, tt.want) {
				t.Errorf("Scan(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestScanMultiplePatterns(t *testing.T) {
	a := build("union", 0, "select", 1, "drop", 2)

	tests := []struct {
		input string
		want  []int
	}{
		{"union select", []int{0, 1}},
		{"UNION SELECT", []int{0, 1}},
		{"drop table", []int{2}},
		{"union", []int{0}},
		{"nothing here", nil},
		{"uniondropselect", []int{0, 1, 2}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := scan(t, a, tt.input)
			if !equalInts(got, tt.want) {
				t.Errorf("Scan(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestScanOverlappingPatterns exercises the failure and dictionary links. A
// naive trie without them misses patterns that are suffixes of others, which is
// exactly the class of miss an attacker would rely on.
func TestScanOverlappingPatterns(t *testing.T) {
	a := build("he", 0, "she", 1, "his", 2, "hers", 3)

	tests := []struct {
		input string
		want  []int
	}{
		{"she", []int{0, 1}},  // "she" contains "he"
		{"hers", []int{0, 3}}, // "hers" contains "he"
		{"his", []int{2}},
		{"ushers", []int{0, 1, 3}}, // contains she, he, hers
		{"nothing", nil},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := scan(t, a, tt.input)
			if !equalInts(got, tt.want) {
				t.Errorf("Scan(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestScanFailureLinkRestart covers a partial match that fails and must restart
// mid-pattern rather than from the root. Getting this wrong silently drops
// matches that begin inside a failed prefix.
func TestScanFailureLinkRestart(t *testing.T) {
	a := build("abcd", 0, "bcx", 1)

	// "abcx" fails "abcd" at the last byte and must still find "bcx".
	got := scan(t, a, "abcx")
	if !equalInts(got, []int{1}) {
		t.Errorf("Scan(%q) = %v, want [1]", "abcx", got)
	}
}

func TestScanSharedLiteralMultipleRules(t *testing.T) {
	b := NewBuilder()
	b.Add("script", 0)
	b.Add("script", 1)
	b.Add("script", 2)
	a := b.Build()

	got := scan(t, a, "<script>")
	if !equalInts(got, []int{0, 1, 2}) {
		t.Errorf("got %v, want [0 1 2]", got)
	}
	if a.Patterns() != 1 {
		t.Errorf("Patterns() = %d, want 1 (distinct literals)", a.Patterns())
	}
}

func TestBuilderIgnoresEmptyLiteral(t *testing.T) {
	b := NewBuilder()
	b.Add("", 0)
	a := b.Build()

	if a.Patterns() != 0 {
		t.Errorf("Patterns() = %d, want 0", a.Patterns())
	}
	// An empty literal must not make every input a match: that would look like
	// a constraint while imposing none.
	if got := scan(t, a, "anything at all"); got != nil {
		t.Errorf("empty literal matched %v, want no matches", got)
	}
}

func TestBuilderDeduplicatesRuleIndex(t *testing.T) {
	b := NewBuilder()
	b.Add("aa", 7)
	b.Add("aa", 7)
	a := b.Build()

	set := bitset.New(64)
	a.Scan([]byte("aa"), set)
	if set.Len() != 1 {
		t.Errorf("Len() = %d, want 1", set.Len())
	}
}

func TestEmptyAutomaton(t *testing.T) {
	a := NewBuilder().Build()

	if !a.Empty() {
		t.Error("Empty() = false, want true")
	}
	if got := scan(t, a, "anything"); got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if a.MatchAny([]byte("anything")) {
		t.Error("MatchAny() = true, want false")
	}
	// Scan must still report bytes consumed so fuel accounting stays correct.
	if n := a.Scan([]byte("abcd"), bitset.New(8)); n != 4 {
		t.Errorf("Scan returned %d, want 4", n)
	}
}

func TestNilAutomatonIsSafe(t *testing.T) {
	var a *Automaton
	if !a.Empty() {
		t.Error("nil automaton should report Empty")
	}
}

func TestMatchAny(t *testing.T) {
	a := build("union", 0, "he", 1)

	tests := []struct {
		input string
		want  bool
	}{
		{"union select", true},
		{"UNION", true},
		{"she", true}, // via dictionary link
		{"nothing", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := a.MatchAny([]byte(tt.input)); got != tt.want {
				t.Errorf("MatchAny(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestScanReturnsBytesScanned(t *testing.T) {
	a := build("x", 0)
	input := "hello world"
	if n := a.Scan([]byte(input), bitset.New(8)); n != len(input) {
		t.Errorf("Scan returned %d, want %d", n, len(input))
	}
}

// TestScanAccumulatesAcrossValues verifies a caller may scan several values into
// one candidate set, which is how the engine handles multi-value targets.
func TestScanAccumulatesAcrossValues(t *testing.T) {
	a := build("aaa", 0, "bbb", 1)

	set := bitset.New(64)
	a.Scan([]byte("aaa"), set)
	a.Scan([]byte("bbb"), set)

	if !set.Has(0) || !set.Has(1) {
		t.Errorf("expected both rules present, got Len=%d", set.Len())
	}
}

func TestScanNonASCIIPassthrough(t *testing.T) {
	// Non-ASCII bytes must pass through folding unchanged; folding them could
	// change byte length and invalidate span arithmetic.
	a := build("\xc3\xa9t\xc3\xa9", 0)
	if got := scan(t, a, "l'\xc3\xa9t\xc3\xa9"); !equalInts(got, []int{0}) {
		t.Errorf("got %v, want [0]", got)
	}
}

func TestLongPatternAndInput(t *testing.T) {
	pattern := strings.Repeat("ab", 200)
	a := build(pattern, 0)

	input := strings.Repeat("a", 500) + pattern + strings.Repeat("b", 500)
	if got := scan(t, a, input); !equalInts(got, []int{0}) {
		t.Errorf("got %v, want [0]", got)
	}
}

// TestManyPatterns checks the automaton stays correct at a scale closer to a
// real ruleset, where failure links matter most.
func TestManyPatterns(t *testing.T) {
	const n = 2000
	b := NewBuilder()
	for i := range n {
		b.Add(fmt.Sprintf("pattern_%04d_x", i), uint32(i))
	}
	a := b.Build()

	if a.Patterns() != n {
		t.Fatalf("Patterns() = %d, want %d", a.Patterns(), n)
	}

	set := bitset.New(n)
	for _, i := range []int{0, 1, 999, n - 1} {
		set.Reset()
		a.Scan([]byte(fmt.Sprintf("junk pattern_%04d_x junk", i)), set)
		if !set.Has(i) {
			t.Errorf("pattern %d not found", i)
		}
		if set.Len() != 1 {
			t.Errorf("pattern %d: matched %d rules, want 1", i, set.Len())
		}
	}
}

func FuzzScan(f *testing.F) {
	f.Add("select", "union select from")
	f.Add("he", "ushers")
	f.Add("", "")
	f.Add("\x00\xff", "\x00\xff\x00")
	f.Add("aaaa", strings.Repeat("a", 100))

	f.Fuzz(func(t *testing.T, pattern, input string) {
		if len(pattern) > 4096 || len(input) > 65536 {
			t.Skip()
		}
		a := build(pattern, 0)

		set := bitset.New(64)
		n := a.Scan([]byte(input), set)
		if n != len(input) {
			t.Fatalf("Scan returned %d, want %d", n, len(input))
		}

		// The automaton must agree with a straightforward case-insensitive
		// substring search. Any disagreement is either a missed detection or a
		// false positive, and both are bugs.
		want := pattern != "" &&
			strings.Contains(strings.ToLower(input), strings.ToLower(pattern))
		got := set.Has(0)

		// ToLower is Unicode-aware and can change byte length, which the
		// automaton deliberately does not do. Only compare when folding is
		// byte-stable, i.e. pure ASCII.
		if isASCII(pattern) && isASCII(input) && got != want {
			t.Fatalf("pattern=%q input=%q: automaton=%v, substring=%v",
				pattern, input, got, want)
		}

		if any := a.MatchAny([]byte(input)); any != got {
			t.Fatalf("MatchAny=%v disagrees with Scan=%v", any, got)
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

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
