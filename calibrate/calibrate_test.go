// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package calibrate_test

import (
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/calibrate"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
)

// corpus is a small benign set used by the unit tests. The committed corpus in
// testdata is what the real gate measures against.
var corpus = []calibrate.Request{
	{Name: "search", Target: "/search", Args: map[string]string{"q": "golang framework"}},
	{Name: "order", Target: "/api/orders/12345"},
	{Name: "apostrophe", Args: map[string]string{"q": "it's urgent"}},
	{Name: "prose", Args: map[string]string{"q": "the union selected a leader"}},
	{Name: "json", Method: "POST", Body: `{"name":"Alice"}`,
		Headers: map[string]string{"Content-Type": "application/json"}},
	{Name: "ua", Headers: map[string]string{"User-Agent": "Mozilla/5.0"}},
	{Name: "markup", Args: map[string]string{"q": "use the <b>bold</b> tag"}},
	{Name: "math", Args: map[string]string{"q": "1 + 1 = 2"}},
	{Name: "path", Args: map[string]string{"q": "/var/log/app.log"}},
	{Name: "uuid", Args: map[string]string{"id": "550e8400-e29b-41d4-a716-446655440000"}},
}

// noisyRule matches something every benign request in the corpus contains, so
// its measured rate is 100%.
func noisyRule(conf types.Confidence) rules.Rule {
	return rules.Rule{
		ID:         types.UserMin + 1,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetRequestMethod}},
		Op:         op.Contains("GET"),
		Actions:    []rules.Action{rules.Score},
		Severity:   types.SeverityNotice,
		Confidence: conf,
		Msg:        "matches every GET",
	}
}

// TestCatchesAnOverclaimingRule is the whole point of the tool: a rule that
// claims more precision than it has must fail the build.
func TestCatchesAnOverclaimingRule(t *testing.T) {
	waf, err := calibrate.NewWAF(
		gwaf.WithoutCoreRuleset(),
		gwaf.WithRuleset(rules.Set{noisyRule(types.Certain)}),
	)
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	rep, err := calibrate.Run(waf, corpus)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if rep.Passed() {
		t.Fatal("a rule matching every benign request passed calibration")
	}
	if rep.Failed != 1 {
		t.Errorf("Failed = %d, want 1", rep.Failed)
	}

	r := rep.Rules[0]
	if r.Measured <= r.Ceiling {
		t.Errorf("measured %.4f is within ceiling %.4f", r.Measured, r.Ceiling)
	}
	// A failure has to be reproducible, or it is a number somebody adjusts the
	// threshold to satisfy.
	if len(r.Samples) == 0 {
		t.Error("failure reported no samples")
	}
	if r.Suggested() != types.Heuristic {
		t.Errorf("Suggested() = %v, want heuristic for a rule matching everything",
			r.Suggested())
	}
}

// TestHonestTierPasses is the other direction: the same rule declaring the tier
// its measurement actually supports is not a failure.
func TestHonestTierPasses(t *testing.T) {
	waf, err := calibrate.NewWAF(
		gwaf.WithoutCoreRuleset(),
		gwaf.WithRuleset(rules.Set{noisyRule(types.Heuristic)}),
	)
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	rep, err := calibrate.Run(waf, corpus)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.Passed() {
		t.Errorf("a rule declaring the tier it earns was failed: %+v", rep.Rules[0])
	}
}

// TestCoreRulesetIsClean measures the shipped ruleset. A regression here means
// a rule started matching real traffic.
func TestCoreRulesetIsClean(t *testing.T) {
	waf, err := calibrate.NewWAF()
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	loaded, err := calibrate.LoadCorpusFile("../testdata/corpus/benign.jsonl")
	if err != nil {
		t.Fatalf("LoadCorpusFile: %v", err)
	}

	rep, err := calibrate.Run(waf, loaded)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, r := range rep.Rules {
		if !r.Passed() {
			t.Errorf("rule %s (%s) measured %.4f%%, ceiling %.4f%%: %+v",
				r.ID, r.Declared, r.Measured*100, r.Ceiling*100, r.Samples)
		}
	}
	t.Logf("%d rules against %d benign requests; %d matched nothing",
		len(rep.Rules), rep.Requests, rep.Clean)
}

// TestReportsItsOwnLimits guards the honesty of a passing result. A clean run
// against a small corpus is weak evidence, and the tool has to say so or it
// becomes a rubber stamp.
func TestReportsItsOwnLimits(t *testing.T) {
	waf, err := calibrate.NewWAF()
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	rep, err := calibrate.Run(waf, corpus)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := rep.MinDetectableRate(); got != 1.0/float64(len(corpus)) {
		t.Errorf("MinDetectableRate() = %v, want %v", got, 1.0/float64(len(corpus)))
	}

	// With ten requests, nothing stricter than Low can be measured at all.
	unvalidated := rep.UnvalidatedTiers()
	if len(unvalidated) == 0 {
		t.Fatal("a ten-request corpus claimed to validate every tier")
	}
	for _, want := range []types.Confidence{types.Certain, types.High, types.Medium} {
		found := false
		for _, c := range unvalidated {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s should be unvalidatable by a %d-request corpus",
				want, len(corpus))
		}
	}
}

func TestRequestsNeededFor(t *testing.T) {
	for _, tt := range []struct {
		c    types.Confidence
		want int
	}{
		{types.Certain, 10001},
		{types.High, 1001},
		{types.Medium, 101},
	} {
		if got := calibrate.RequestsNeededFor(tt.c); got != tt.want {
			t.Errorf("RequestsNeededFor(%s) = %d, want %d", tt.c, got, tt.want)
		}
	}
}

func TestEmptyCorpusIsAnError(t *testing.T) {
	waf, err := calibrate.NewWAF()
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}
	// Measuring against nothing would report every rule as clean, which is the
	// most dangerous possible output.
	if _, err := calibrate.Run(waf, nil); err == nil {
		t.Error("Run accepted an empty corpus")
	}
}

func TestLoadCorpus(t *testing.T) {
	const src = `# a comment
{"name":"first","target":"/a"}

{"name":"second","method":"POST","body":"x","headers":{"Content-Type":"text/plain"}}
{"target":"/unnamed"}
`
	got, err := calibrate.LoadCorpus(strings.NewReader(src))
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("loaded %d entries, want 3", len(got))
	}
	if got[0].Name != "first" || got[1].Method != "POST" {
		t.Errorf("parsed wrongly: %+v", got)
	}
	// An unnamed entry still needs an identifier, or a failure report cannot
	// point at it.
	if got[2].Name == "" {
		t.Error("unnamed entry got no fallback name")
	}
}

// TestMalformedCorpusIsAnError covers the one failure mode that would make a
// report lie: silently skipping entries inflates every denominator.
func TestMalformedCorpusIsAnError(t *testing.T) {
	if _, err := calibrate.LoadCorpus(strings.NewReader("{not json}\n")); err == nil {
		t.Error("LoadCorpus accepted a malformed line")
	}
}

// TestRuleCountedOncePerRequest checks the counting unit. A rule matching three
// arguments of one request is one false positive to whoever has to deal with
// it, not three.
func TestRuleCountedOncePerRequest(t *testing.T) {
	waf, err := calibrate.NewWAF(
		gwaf.WithoutCoreRuleset(),
		gwaf.WithRuleset(rules.Set{{
			ID:         types.UserMin + 2,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetArgs}},
			Op:         op.Contains("x"),
			Actions:    []rules.Action{rules.Score},
			Severity:   types.SeverityNotice,
			Confidence: types.Heuristic,
			Msg:        "matches x",
		}}),
	)
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	rep, err := calibrate.Run(waf, []calibrate.Request{{
		Name: "many args",
		Args: map[string]string{"a": "x", "b": "x", "c": "x", "d": "x"},
	}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := rep.Rules[0].Hits; got != 1 {
		t.Errorf("Hits = %d, want 1 — four matching arguments in one request is "+
			"one false positive, not four", got)
	}
}
