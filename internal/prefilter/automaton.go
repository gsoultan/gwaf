// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package prefilter implements the multi-pattern automaton that decides which
// rules are worth evaluating for a given input.
//
// This is the mechanism the performance thesis rests on. A conventional WAF
// evaluates every rule against every target value, which is O(rules × values)
// transform-and-match operations per request. gwaf instead compiles the
// required literals of every rule into one Aho-Corasick automaton, scans each
// value once, and evaluates only the rules whose literals actually appeared.
// On benign traffic the candidate set is empty and no operator runs at all.
// See docs/CONCEPT.md §1 and docs/PERFORMANCE.md §1.1.
//
// The automaton is built once at compile time, is immutable, and is safe for
// concurrent use by any number of transactions.
//
// # Representation
//
// Transitions are stored sparsely rather than as a dense 256-entry table per
// state. A dense table is faster per byte but costs 1 KiB per state, which for
// a CRS-scale ruleset (tens of thousands of states) would be tens of megabytes
// and would blow the resident-ruleset budget in CLAUDE.md §2. The root state,
// which is by far the most frequently visited, does get a dense table: that
// captures most of the speed benefit for 1 KiB total.
package prefilter

import (
	"sort"

	"github.com/gsoultan/gwaf/internal/bitset"
)

// fold maps ASCII upper case to lower case and leaves every other byte alone.
//
// Matching is case-insensitive because attack literals appear in arbitrary case
// and requiring rule authors to enumerate cases is exactly the kind of manual
// step that produces bypasses. Only ASCII is folded: WAF literals are ASCII in
// practice, and case folding arbitrary UTF-8 here would change byte lengths and
// break the offset arithmetic that the rest of the engine depends on.
func fold(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// node is one automaton state. Fields are int32 offsets into the flat side
// arrays rather than pointers, keeping the automaton compact and free of
// pointers for the collector to trace.
type node struct {
	childStart int32 // index into childBytes/childNext
	childCount int32
	fail       int32 // longest proper suffix that is also a prefix of some pattern
	dictLink   int32 // nearest fail-ancestor carrying outputs; 0 for none
	outStart   int32 // index into outputs
	outCount   int32
}

// Automaton is an immutable multi-pattern matcher mapping literal occurrences
// to candidate rule indices.
type Automaton struct {
	nodes      []node
	childBytes []byte  // transition labels, sorted ascending within each node
	childNext  []int32 // transition targets, parallel to childBytes
	outputs    []uint32

	// rootNext is a dense transition table for state 0. The root is visited on
	// most input bytes, so making its lookup a single indexed load rather than
	// a scan is worth the fixed 1 KiB.
	rootNext [256]int32

	patterns int
}

// Patterns returns the number of distinct literals compiled into a.
func (a *Automaton) Patterns() int { return a.patterns }

// States returns the number of automaton states, for diagnostics and tests.
func (a *Automaton) States() int { return len(a.nodes) }

// Empty reports whether a has no patterns, in which case Scan is a no-op.
func (a *Automaton) Empty() bool { return a == nil || a.patterns == 0 }

// child returns the transition from state on byte c.
//
// Labels are sorted ascending within a node, so the scan stops as soon as it
// passes c. Nodes have few children in practice, which makes a short linear
// scan over contiguous bytes faster and more cache-friendly than a binary
// search or a map.
func (a *Automaton) child(state int32, c byte) (int32, bool) {
	nd := &a.nodes[state]
	start := nd.childStart
	end := start + nd.childCount
	for i := start; i < end; i++ {
		b := a.childBytes[i]
		if b == c {
			return a.childNext[i], true
		}
		if b > c {
			break
		}
	}
	return 0, false
}

// Scan feeds input through the automaton and adds every matching rule index to
// dst. It returns the number of bytes scanned so the caller can charge fuel.
//
// dst is only ever added to, so a caller may scan several values into one
// candidate set. Scanning is linear in len(input) plus the number of matches.
func (a *Automaton) Scan(input []byte, dst *bitset.Set) int {
	if a.Empty() || len(input) == 0 {
		return len(input)
	}

	state := int32(0)
	for _, raw := range input {
		c := fold(raw)

		if state == 0 {
			state = a.rootNext[c]
		} else {
			for {
				if next, ok := a.child(state, c); ok {
					state = next
					break
				}
				state = a.nodes[state].fail
				if state == 0 {
					// Falling back to the root: take its dense transition
					// directly rather than looping again on a state that
					// cannot fail any further.
					state = a.rootNext[c]
					break
				}
			}
		}

		if state == 0 {
			continue
		}

		// Emit this state's outputs, then walk the dictionary-suffix chain to
		// pick up shorter patterns that also end here.
		for s := state; s > 0; {
			nd := &a.nodes[s]
			for i := nd.outStart; i < nd.outStart+nd.outCount; i++ {
				dst.Add(int(a.outputs[i]))
			}
			s = nd.dictLink
		}
	}
	return len(input)
}

// MatchAny reports whether any pattern occurs in input. It stops at the first
// match, which makes it cheaper than Scan when the caller only needs a yes or
// no answer.
func (a *Automaton) MatchAny(input []byte) bool {
	if a.Empty() || len(input) == 0 {
		return false
	}

	state := int32(0)
	for _, raw := range input {
		c := fold(raw)

		if state == 0 {
			state = a.rootNext[c]
		} else {
			for {
				if next, ok := a.child(state, c); ok {
					state = next
					break
				}
				state = a.nodes[state].fail
				if state == 0 {
					state = a.rootNext[c]
					break
				}
			}
		}

		if state == 0 {
			continue
		}
		if a.nodes[state].outCount > 0 || a.nodes[state].dictLink > 0 {
			return true
		}
	}
	return false
}

// Builder accumulates literals before compiling them into an Automaton.
//
// A Builder uses maps for clarity during construction; the compiled Automaton
// is a flat, pointer-free structure. Build time is not on the hot path.
type Builder struct {
	children []map[byte]int32
	outputs  [][]uint32
	patterns map[string]struct{}
}

// NewBuilder returns an empty Builder.
func NewBuilder() *Builder {
	b := &Builder{
		patterns: make(map[string]struct{}),
	}
	b.newNode() // state 0 is the root
	return b
}

func (b *Builder) newNode() int32 {
	b.children = append(b.children, nil)
	b.outputs = append(b.outputs, nil)
	return int32(len(b.children) - 1)
}

// Add registers that the presence of literal implies ruleIdx is a candidate.
//
// Empty literals are ignored: a rule that requires the empty string requires
// nothing, and admitting it would make every request a candidate for that rule
// while looking like a real constraint. Callers that genuinely cannot supply a
// literal must declare the rule unconditional instead, which is visible in the
// compile report.
//
// The same literal may be added for several rules, and a rule may register
// several literals. Multiple literals for one rule are treated as alternatives:
// any one of them makes the rule a candidate. That is the safe direction — an
// over-approximation costs a wasted evaluation, whereas requiring all literals
// would drop rules that should have run.
func (b *Builder) Add(literal string, ruleIdx uint32) {
	if literal == "" {
		return
	}
	b.patterns[literal] = struct{}{}

	state := int32(0)
	for i := range len(literal) {
		c := fold(literal[i])
		next, ok := b.children[state][c]
		if !ok {
			next = b.newNode()
			if b.children[state] == nil {
				b.children[state] = make(map[byte]int32, 4)
			}
			b.children[state][c] = next
		}
		state = next
	}

	// Deduplicate: the same rule can reach a state through several equivalent
	// literals, and a duplicated output would be re-added to the candidate set
	// on every match for no benefit.
	for _, existing := range b.outputs[state] {
		if existing == ruleIdx {
			return
		}
	}
	b.outputs[state] = append(b.outputs[state], ruleIdx)
}

// Build compiles the accumulated literals into an immutable Automaton.
func (b *Builder) Build() *Automaton {
	a := &Automaton{
		nodes:    make([]node, len(b.children)),
		patterns: len(b.patterns),
	}

	// Flatten transitions. Sorting labels lets child() stop scanning early.
	for state := range b.children {
		kids := b.children[state]
		nd := &a.nodes[state]
		nd.childStart = int32(len(a.childBytes))
		nd.childCount = int32(len(kids))
		if len(kids) == 0 {
			continue
		}
		labels := make([]byte, 0, len(kids))
		for c := range kids {
			labels = append(labels, c)
		}
		sort.Slice(labels, func(i, j int) bool { return labels[i] < labels[j] })
		for _, c := range labels {
			a.childBytes = append(a.childBytes, c)
			a.childNext = append(a.childNext, kids[c])
		}
	}

	// Flatten outputs.
	for state := range b.outputs {
		outs := b.outputs[state]
		nd := &a.nodes[state]
		nd.outStart = int32(len(a.outputs))
		nd.outCount = int32(len(outs))
		a.outputs = append(a.outputs, outs...)
	}

	a.buildLinks(b)
	return a
}

// buildLinks computes failure and dictionary-suffix links by breadth-first
// traversal. BFS order guarantees that when a state is processed its failure
// target has already been finalised, which is what makes the single pass valid.
func (a *Automaton) buildLinks(b *Builder) {
	queue := make([]int32, 0, len(a.nodes))

	// Depth 1: every root child fails back to the root.
	for c, next := range b.children[0] {
		a.nodes[next].fail = 0
		a.rootNext[c] = next
		queue = append(queue, next)
	}

	for head := 0; head < len(queue); head++ {
		u := queue[head]
		for c, v := range b.children[u] {
			// Walk u's failure chain for a state that can consume c.
			f := a.nodes[u].fail
			for {
				if next, ok := a.child(f, c); ok && next != v {
					a.nodes[v].fail = next
					break
				}
				if f == 0 {
					a.nodes[v].fail = 0
					break
				}
				f = a.nodes[f].fail
			}

			// A state's dictionary link is its nearest failure ancestor that
			// carries outputs, so Scan can enumerate every pattern ending at a
			// position without walking the whole failure chain.
			fv := a.nodes[v].fail
			if a.nodes[fv].outCount > 0 {
				a.nodes[v].dictLink = fv
			} else {
				a.nodes[v].dictLink = a.nodes[fv].dictLink
			}

			queue = append(queue, v)
		}
	}
}
