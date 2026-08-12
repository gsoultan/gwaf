// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import (
	"testing"

	"github.com/gsoultan/gwaf/calibrate"
)

// TestAgreedOnRefusesToWiden is the property that matters.
//
// A suggestion is a hole in a firewall, and the tempting bug is to produce a
// tidy one by dropping whatever the samples disagree about. Widening
// "/a and /b" to "everywhere" turns a scoped exception into a disabled rule
// while still reading like tuning, which is the exact failure this command
// exists to prevent.
func TestAgreedOnRefusesToWiden(t *testing.T) {
	path := func(s calibrate.Sample) string { return s.Path }

	for _, tc := range []struct {
		name    string
		samples []calibrate.Sample
		want    string
		wantOK  bool
	}{
		{
			name:    "unanimous",
			samples: []calibrate.Sample{{Path: "/a"}, {Path: "/a"}},
			want:    "/a", wantOK: true,
		},
		{
			name:    "disagreement yields nothing",
			samples: []calibrate.Sample{{Path: "/a"}, {Path: "/b"}},
			wantOK:  false,
		},
		{
			name:    "one dissenter is still disagreement",
			samples: []calibrate.Sample{{Path: "/a"}, {Path: "/a"}, {Path: "/b"}},
			wantOK:  false,
		},
		{
			name:    "empty value is not a scope",
			samples: []calibrate.Sample{{Path: ""}, {Path: ""}},
			wantOK:  false,
		},
		{name: "no samples", samples: nil, wantOK: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := agreedOn(tc.samples, path)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTargetConstIsTypedOrAbsent checks that the emitted Go stays
// compile-checked. A target the tool does not recognise must be left off the
// suggestion rather than guessed at: a wrong Target silently widens the
// exception to collections it was never measured against.
func TestTargetConstIsTypedOrAbsent(t *testing.T) {
	for _, name := range []string{"ARGS", "args", "ARGS_NAMES", "REQUEST_HEADERS", "REQUEST_BODY"} {
		if targetConst(name) == "" {
			t.Errorf("targetConst(%q) = \"\", want a typed constant", name)
		}
	}
	for _, name := range []string{"", "SOMETHING_NEW", "TX", "GEO"} {
		if got := targetConst(name); got != "" {
			t.Errorf("targetConst(%q) = %q, want \"\" so the field is omitted", name, got)
		}
	}
}

// TestNoteNamesTheEvidence: an exception with no rationale is indistinguishable
// from a mistake six months later, which rules.Exception's own documentation
// says. The note must therefore carry the corpus entries, deduplicated.
func TestNoteNamesTheEvidence(t *testing.T) {
	r := calibrate.RuleResult{
		Hits: 3,
		Samples: []calibrate.Sample{
			{Name: "search with apostrophe"},
			{Name: "search with apostrophe"},
			{Name: "product filter"},
		},
	}
	got := note(r)
	for _, want := range []string{"search with apostrophe", "product filter"} {
		if !contains(got, want) {
			t.Errorf("note = %q, missing %q", got, want)
		}
	}
	if n := countOccurrences(got, "search with apostrophe"); n != 1 {
		t.Errorf("duplicate sample named %d times, want 1: %q", n, got)
	}

	// No names at all still has to say something an operator can act on.
	if got := note(calibrate.RuleResult{Hits: 7}); !contains(got, "7") {
		t.Errorf("note without samples = %q, want the hit count", got)
	}
}

func contains(s, sub string) bool { return countOccurrences(s, sub) > 0 }

func countOccurrences(s, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			n++
		}
	}
	return n
}
