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

	// buf[i] backs the value after i+1 transforms; val[i] is that value, which
	// may alias val[i-1] when the transform changed nothing.
	buf []([]byte)
	val []([]byte)

	// changed[i] reports whether any transform up to and including i altered
	// the value, which is what the caller reports as "transformed".
	changed []bool
}

// grow sizes the staging arrays for the longest chain in a phase.
func (s *stages) grow(depth int) {
	for len(s.buf) < depth {
		s.buf = append(s.buf, nil)
		s.val = append(s.val, nil)
		s.changed = append(s.changed, false)
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
		cur = s.val[reuse-1]
		transformed = s.changed[reuse-1]
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
		s.val[i] = cur
		s.changed[i] = transformed
	}

	s.prev = chain
	return cur, transformed, true
}
