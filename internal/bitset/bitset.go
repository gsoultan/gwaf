// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package bitset provides a fixed-capacity bitset used to carry candidate rule
// sets from the prefilter to the evaluator.
//
// The prefilter produces a set of rule indices per request. That set is almost
// always empty and, when it is not, almost always tiny — so the representation
// is optimised for cheap Reset and cheap iteration over few set bits, not for
// dense set algebra.
package bitset

import "math/bits"

const wordBits = 64

// Set is a fixed-capacity set of non-negative integers.
//
// The zero value is an empty set with zero capacity. A Set is not safe for
// concurrent use; each transaction owns its own.
type Set struct {
	words []uint64
	// loWord/hiWord bound the words actually touched since the last Reset, so
	// Reset clears only that range rather than the whole backing slice.
	// Rulesets can be large while candidate sets stay tiny, and clearing 10k
	// rules' worth of words per request would dominate the benign path.
	//
	// The empty-set invariant is hiWord < loWord. The zero value does not
	// satisfy it, so every read path also guards on len(words); see Empty.
	loWord int
	hiWord int
}

// New returns a Set able to hold values in [0, capacity).
func New(capacity int) *Set {
	s := &Set{}
	s.Grow(capacity)
	return s
}

// Grow ensures s can hold values in [0, capacity). It never shrinks, and it
// preserves any values already present.
func (s *Set) Grow(capacity int) {
	if capacity <= 0 {
		return
	}
	need := (capacity + wordBits - 1) / wordBits
	if need <= len(s.words) {
		return
	}

	// Whether the set is empty must be decided before the backing slice is
	// replaced, because Empty consults it. Growing does not change which words
	// hold values, so a non-empty set keeps its bounds: resetting them here
	// would leave the bits set but make them invisible to Len and All, so a
	// candidate rule found before a grow would silently never be evaluated.
	wasEmpty := s.Empty()

	words := make([]uint64, need)
	copy(words, s.words)
	s.words = words

	if wasEmpty {
		s.resetBounds()
	}
}

// Cap returns the exclusive upper bound on values s can hold.
func (s *Set) Cap() int { return len(s.words) * wordBits }

// resetBounds restores the empty-set invariant for the touched-word range.
func (s *Set) resetBounds() {
	s.loWord = len(s.words)
	s.hiWord = -1
}

// Add inserts v. Values outside the set's capacity are ignored: the prefilter
// is a fast path and must not panic on a stale automaton, and a dropped
// candidate can only cause a missed optimisation, never a missed rule — the
// evaluator treats an out-of-range index as absent and falls back to evaluating
// the rule directly.
func (s *Set) Add(v int) {
	w := v / wordBits
	if v < 0 || w >= len(s.words) {
		return
	}
	s.words[w] |= 1 << (uint(v) % wordBits)
	if w < s.loWord {
		s.loWord = w
	}
	if w > s.hiWord {
		s.hiWord = w
	}
}

// Union adds every element of other to s.
func (s *Set) Union(other []uint64) {
	n := min(len(other), len(s.words))
	for w := range n {
		v := other[w]
		if v == 0 {
			continue
		}
		s.words[w] |= v
		if w < s.loWord {
			s.loWord = w
		}
		if w > s.hiWord {
			s.hiWord = w
		}
	}
}

// Has reports whether v is present.
func (s *Set) Has(v int) bool {
	w := v / wordBits
	if v < 0 || w >= len(s.words) {
		return false
	}
	return s.words[w]&(1<<(uint(v)%wordBits)) != 0
}

// Empty reports whether s holds no values.
//
// The len check keeps the zero value usable: a Set{} has loWord == hiWord == 0,
// which does not satisfy the empty invariant, and without this guard All and
// Len would index an empty backing slice.
func (s *Set) Empty() bool { return len(s.words) == 0 || s.hiWord < s.loWord }

// Len returns the number of values in s.
func (s *Set) Len() int {
	if s.Empty() {
		return 0
	}
	n := 0
	for w := s.loWord; w <= s.hiWord; w++ {
		n += bits.OnesCount64(s.words[w])
	}
	return n
}

// Reset empties s, clearing only the words that were actually touched.
func (s *Set) Reset() {
	if s.Empty() {
		return
	}
	clear(s.words[s.loWord : s.hiWord+1])
	s.resetBounds()
}

// All calls fn for each value in ascending order. It stops early if fn returns
// false.
func (s *Set) All(fn func(v int) bool) {
	if s.Empty() {
		return
	}
	for w := s.loWord; w <= s.hiWord; w++ {
		word := s.words[w]
		for word != 0 {
			b := bits.TrailingZeros64(word)
			if !fn(w*wordBits + b) {
				return
			}
			word &= word - 1
		}
	}
}
