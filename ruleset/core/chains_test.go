// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"sort"
	"strings"
	"testing"
)

// The transform-chain inventory, pinned.
//
// # Why this is a test and not a comment
//
// Chains are the expensive axis. Each distinct chain is materialised once per
// value per phase, and .serena/memories/decisions.md records the measurement
// that makes this the number to watch: going from ten chains to twelve cost
// more than ninety extra literals did. Two rules in this cycle had to be moved
// off decodeChain onto a narrower one because RemoveWhitespace destroyed the
// word boundary they read, and each move is only free because the chain it
// moved to already existed.
//
// A rule author adding a novel chain pays that cost for every value in the
// phase, and nothing told them. This test does: adding a seventh chain fails
// the build until someone writes down why it has to exist.
//
// # The inventory, and why each one is load-bearing
//
// An audit of all six asked whether any could be merged. None can:
//
//   - (none) — the raw-byte rules. A CR in a header value and a NUL in a file
//     name are findings precisely because they arrived undecoded; decoding
//     first would invent them.
//   - lowercase — the *pre-decode* rules. 1001 matches "%2e%2e" and 1005
//     matches "%00", and URL-decoding first turns both into the thing they are
//     looking for and makes them unable to see it. 1005's own comment says
//     "matched before percent-decoding, on purpose". The response-leak rules
//     share this chain because decoding a response body is meaningless.
//   - url_decode+lowercase — the word-boundary rules. 3012 reads "on<word>="
//     and 2011 reads a statement verb followed by a boundary; RemoveWhitespace
//     welds "xss onfocus=" into "xssonfocus=" and "DROP TABLE" into
//     "droptableusers", which is the whole signal.
//   - url_decode+escape_decode — values carrying language-level escapes.
//   - url_decode+lowercase+remove_whitespace — decodeChain, the bulk.
//   - url_decode+hex_escape_decode+lowercase+normalize_path — pathChain, which
//     resolves traversal rather than looking for it.
//
// The prefix reuse in internal/engine.stages is what makes six affordable:
// sorted by chain, four of them resume from a url_decode already computed, and
// decodeChain resumes from url_decode+lowercase. Eight transform applications
// per value rather than twelve.
func TestTransformChainInventory(t *testing.T) {
	// Chain -> the rules that use it, across all phases.
	chains := map[string]int{}
	for _, r := range Default() {
		var names []string
		for _, tr := range r.Transforms {
			names = append(names, tr.Name())
		}
		key := strings.Join(names, "+")
		if key == "" {
			key = "(none)"
		}
		chains[key]++
	}

	want := map[string]bool{
		"(none)":                                 true,
		"lowercase":                              true,
		"url_decode+lowercase":                   true,
		"url_decode+escape_decode":               true,
		"url_decode+lowercase+remove_whitespace": true,
		"url_decode+hex_escape_decode+lowercase+normalize_path": true,
	}

	var got []string
	for k := range chains {
		got = append(got, k)
	}
	sort.Strings(got)

	for _, k := range got {
		if !want[k] {
			t.Errorf("new transform chain %q (%d rules).\n"+
				"  Each distinct chain is materialised once per value per phase, and going\n"+
				"  from ten chains to twelve once cost more than ninety extra literals.\n"+
				"  Before adding one: can the rule use an existing chain? If it genuinely\n"+
				"  cannot, add it here with the reason, the way the six above carry theirs.",
				k, chains[k])
		}
	}
	for k := range want {
		if chains[k] == 0 {
			t.Errorf("chain %q is documented in the inventory but no rule uses it; "+
				"remove it from `want` so the list stays honest", k)
		}
	}
	t.Logf("%d chains: %s", len(chains), strings.Join(got, ", "))
}
