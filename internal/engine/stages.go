// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package engine

import (
	"github.com/gsoultan/gwaf/internal/budget"
	"github.com/gsoultan/gwaf/rules"
)

// stages applies transform chains to one value, reusing the shared prefix
// between consecutive chains.
//
// # Why this exists
//
// Chain grouping already applies a chain once per group rather than once per
// rule. The remaining redundancy is *between* groups: the core ruleset's chains
// are [lowercase], [url_decode], [url_decode lowercase normalize_path], and
// [url_decode lowercase remove_whitespace], so url_decode ran three times over
// the same bytes and lowercase twice. Eight applications per value where five
// suffice, and it was 32% of the time on a benign 1 KiB JSON body.
//
// Groups arrive sorted by chain (see rules.sortGroupsByChain), so a chain that
// extends the previous one is adjacent to it. Each depth keeps its own buffer,
// so the intermediate result at every step survives long enough for the next
// chain to resume from it — which is exactly what ping-ponging two buffers
// cannot do.
//
// The saving grows with the ruleset rather than being a fixed win: a rule added
// with a chain that extends an existing family costs only its own last step.
//
// # What must stay true
//
// A transform reporting no change returns the input slice unchanged, so val[i]
// aliases val[i-1] and no copy happens. Buffers are per depth and never alias
// each other, so a transform always reads from a different array than it
// writes to.
type stages struct {
	src []byte

	// prev is the chain applied last, against which the next chain's shared
	// prefix is measured.
	prev []rules.Transform

	// buf[i] backs the value after i+1 transforms.
	buf []([]byte)

	// step[i] is the state after i+1 transforms: the value, which may alias
	// step[i-1].val when the transform changed nothing, and whether anything up
	// to and including i altered it.
	//
	// One slice of structs rather than two parallel slices. Both fields are
	// written on every transform step of every chain -- the profile put the two
	// stores at 180ms of apply's 780ms flat, more than the transforms
	// themselves cost -- and as parallel arrays each store lands on a different
	// cache line. Adjacent in one struct they share one, which is also what
	// Green Tea's locality-sensitive collector prefers (CLAUDE.md 4).
	step []stageState
}

// stageState is the result of one transform depth.
type stageState struct {
	val     []byte
	changed bool
}

// grow sizes the staging arrays for the longest chain in a phase.
func (s *stages) grow(depth int) {
	for len(s.buf) < depth {
		s.buf = append(s.buf, nil)
		s.step = append(s.step, stageState{})
	}
}

// reset begins a new value. The previous chain is forgotten, so the first group
// applies its chain in full.
func (s *stages) reset(src []byte) {
	s.src = src
	s.prev = nil
}

// apply runs chain over the current value and returns the result, whether any
// transform altered it, and whether the fuel budget held.
func (s *stages) apply(chain []rules.Transform, meter *budget.Meter) ([]byte, bool, bool) {
	if len(chain) == 0 {
		return s.src, false, true
	}
	s.grow(len(chain))

	// How much of this chain the previous one already computed.
	reuse := 0
	for reuse < len(chain) && reuse < len(s.prev) &&
		chain[reuse] == s.prev[reuse] {
		reuse++
	}

	cur := s.src
	transformed := false
	if reuse > 0 {
		st := s.step[reuse-1]
		cur, transformed = st.val, st.changed
	}

	for i := reuse; i < len(chain); i++ {
		t := chain[i]
		need := t.MaxOutputLen(len(cur))
		s.buf[i] = growTo(s.buf[i], need)

		next, changed := t.Apply(s.buf[i][:0], cur)
		if changed {
			if !meter.Spend(budget.Fuel(len(next)) * budget.CostPerByteTransformed) {
				return nil, false, false
			}
			cur = next
			transformed = true
		}
		// Recorded whether or not it changed: a later chain resuming at this
		// depth needs the value as of this step either way, and when nothing
		// changed that value is simply the previous one, with no copy.
		s.step[i] = stageState{val: cur, changed: transformed}
	}

	s.prev = chain
	return cur, transformed, true
}
