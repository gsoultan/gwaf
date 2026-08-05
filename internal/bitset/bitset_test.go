// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package bitset

import (
	"slices"
	"testing"
)

func collect(s *Set) []int {
	var got []int
	s.All(func(v int) bool {
		got = append(got, v)
		return true
	})
	return got
}

// TestZeroValueIsUsable guards the invariant that tripped an earlier bug: a
// Set{} has loWord == hiWord == 0, which does not satisfy the empty invariant,
// so every read path has to guard on the backing slice.
func TestZeroValueIsUsable(t *testing.T) {
	var s Set

	if !s.Empty() {
		t.Error("zero value reports non-empty")
	}
	if got := s.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
	if s.Has(0) {
		t.Error("Has(0) = true on the zero value")
	}
	if got := collect(&s); got != nil {
		t.Errorf("All yielded %v on the zero value", got)
	}
	s.Reset() // must not panic
	s.Add(5)  // out of capacity, must not panic
}

func TestAddAndHas(t *testing.T) {
	s := New(256)
	for _, v := range []int{0, 1, 63, 64, 65, 200, 255} {
		s.Add(v)
	}

	for _, v := range []int{0, 1, 63, 64, 65, 200, 255} {
		if !s.Has(v) {
			t.Errorf("Has(%d) = false after Add", v)
		}
	}
	for _, v := range []int{2, 62, 66, 199, 254} {
		if s.Has(v) {
			t.Errorf("Has(%d) = true without Add", v)
		}
	}
	if got := s.Len(); got != 7 {
		t.Errorf("Len() = %d, want 7", got)
	}
}

func TestAllIsAscending(t *testing.T) {
	s := New(512)
	want := []int{3, 64, 65, 127, 128, 400}
	for _, v := range want {
		s.Add(v)
	}
	got := collect(s)
	if !slices.Equal(got, want) {
		t.Errorf("All() = %v, want %v", got, want)
	}
}

func TestAllEarlyExit(t *testing.T) {
	s := New(128)
	for _, v := range []int{1, 2, 3, 4, 5} {
		s.Add(v)
	}

	seen := 0
	s.All(func(int) bool {
		seen++
		return seen < 3
	})
	if seen != 3 {
		t.Errorf("visited %d values, want 3", seen)
	}
}

func TestReset(t *testing.T) {
	s := New(1024)
	for _, v := range []int{0, 500, 1023} {
		s.Add(v)
	}
	s.Reset()

	if !s.Empty() {
		t.Error("Empty() = false after Reset")
	}
	if got := s.Len(); got != 0 {
		t.Errorf("Len() = %d after Reset", got)
	}
	if got := collect(s); got != nil {
		t.Errorf("All yielded %v after Reset", got)
	}

	// The set must remain usable after Reset; this is the per-request path.
	s.Add(7)
	if !s.Has(7) {
		t.Error("Add after Reset did not take effect")
	}
	if got := s.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1", got)
	}
}

// TestOutOfRangeIsIgnored covers the deliberate choice not to panic. The
// prefilter is a fast path and a stale automaton must degrade to a missed
// optimisation, never a crash on the request path.
func TestOutOfRangeIsIgnored(t *testing.T) {
	s := New(64)

	s.Add(-1)
	s.Add(64)
	s.Add(1 << 20)

	if !s.Empty() {
		t.Error("out-of-range values were stored")
	}
	if s.Has(64) || s.Has(-1) {
		t.Error("Has reported an out-of-range value")
	}
}

func TestGrowPreservesContents(t *testing.T) {
	s := New(64)
	s.Add(1)
	s.Add(63)

	s.Grow(1024)
	if !s.Has(1) || !s.Has(63) {
		t.Error("Grow lost existing values")
	}

	s.Add(1000)
	if !s.Has(1000) {
		t.Error("value in the grown range not stored")
	}
	if got := s.Len(); got != 3 {
		t.Errorf("Len() = %d, want 3", got)
	}
}

func TestGrowNeverShrinks(t *testing.T) {
	s := New(1024)
	before := s.Cap()
	s.Grow(64)
	if s.Cap() < before {
		t.Errorf("Cap shrank from %d to %d", before, s.Cap())
	}
}

// BenchmarkResetSparse is why Reset tracks touched words: a large ruleset with
// a tiny candidate set must not pay to clear the whole backing slice on every
// request.
func BenchmarkResetSparse(b *testing.B) {
	s := New(10000)
	b.ReportAllocs()
	for b.Loop() {
		s.Add(5000)
		s.Reset()
	}
}
