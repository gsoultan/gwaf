// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package conformance_test

import (
	"os"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/test/conformance"
)

// TestBundledSuite runs the FTW-format tests that ship with the repository.
//
// They exist so the runner is verifiable without downloading anything: a
// harness nobody can execute is a harness nobody trusts. They are explicitly not
// the conformance claim — they were written by the same people who wrote the
// rules, which is the bias the external corpus exists to remove.
func TestBundledSuite(t *testing.T) {
	files, err := conformance.LoadTests("testdata/gwaf")
	if err != nil {
		t.Fatalf("load bundled tests: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no bundled tests found")
	}

	waf, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	rep := conformance.Run(waf, files, conformance.ModeDetection)
	t.Log(rep)

	for _, f := range rep.Failures() {
		t.Errorf("%s / %s (stage %d): %s", f.File, f.Test, f.Stage, f.Reason)
	}
	if rep.Passed+rep.Failed == 0 {
		t.Error("every stage was skipped; the runner executed nothing")
	}
}

// TestCRSSuite runs the real OWASP CRS test corpus, when it is present.
//
// It is opt-in by environment because the corpus is thousands of files this
// repository does not vendor, and a test that silently passes when its input is
// missing is worse than one that is absent. Point it at a checkout:
//
//	CRS_TESTS=~/src/coreruleset/tests/regression/tests go test ./test/conformance/
//
// With CRS_RULES also set, the run switches to exact rule-ID comparison through
// the seclang bridge, which is the stricter claim:
//
//	CRS_TESTS=... CRS_RULES=~/src/coreruleset/rules go test ./test/conformance/
func TestCRSSuite(t *testing.T) {
	testDir := os.Getenv("CRS_TESTS")
	if testDir == "" {
		t.Skip("CRS_TESTS not set; skipping the external corpus " +
			"(see the doc comment — this is the run that produces a real number)")
	}

	files, err := conformance.LoadTests(testDir)
	if err != nil {
		t.Fatalf("load CRS tests from %s: %v", testDir, err)
	}
	t.Logf("loaded %d CRS test files", len(files))

	mode := conformance.ModeDetection
	opts := []gwaf.Option{}

	if rulesDir := os.Getenv("CRS_RULES"); rulesDir != "" {
		set, reports, err := conformance.LoadCRS(rulesDir)
		if err != nil {
			t.Fatalf("load CRS rules from %s: %v", rulesDir, err)
		}
		cov := conformance.Summarise(reports)
		// Printed beside the pass rate, always. "98% of tests pass" means
		// something different when the bridge translated half the rules.
		t.Log(cov)
		opts = append(opts, gwaf.WithRuleset(set))
		mode = conformance.ModeRuleID
	}

	waf, err := gwaf.New(opts...)
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	rep := conformance.Run(waf, files, mode)
	t.Log(rep)

	// Failures are logged rather than failing the build on the first run: the
	// external corpus tests rules gwaf never implemented, so a non-zero failure
	// count is expected and is the measurement, not a regression. Gate it with a
	// threshold once a baseline exists.
	for i, f := range rep.Failures() {
		if i >= 50 {
			t.Logf("... and %d more failures", len(rep.Failures())-50)
			break
		}
		t.Logf("FAIL %s / %s (stage %d): %s", f.File, f.Test, f.Stage, f.Reason)
	}
}

// TestSkippedStagesAreNotCountedAsPasses is the honesty guard on the runner
// itself. A suite that skips what it cannot run and reports 100% is lying, so
// the rate must exclude skips from its denominator entirely.
func TestSkippedStagesAreNotCountedAsPasses(t *testing.T) {
	files := map[string]conformance.File{
		"synthetic.yaml": {
			Tests: []conformance.Test{{
				TestTitle: "needs-a-socket",
				Stages: []conformance.Stage{{
					// raw_request cannot be honoured in-process.
					Input:  conformance.Input{RawRequest: "R0VUIC8gSFRUUC8xLjENCg0K"},
					Output: conformance.Output{Status: 403},
				}},
			}},
		},
	}

	waf, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	rep := conformance.Run(waf, files, conformance.ModeDetection)

	if rep.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", rep.Skipped)
	}
	if rep.Passed != 0 {
		t.Errorf("a skipped stage was counted as passed: %+v", rep)
	}
	if rep.Rate() != 0 {
		t.Errorf("rate = %v with nothing executed, want 0", rep.Rate())
	}
}

// TestFalsePositiveControlsFail proves the benign half actually asserts
// something: a WAF that blocked everything must fail these, or they are decoration.
func TestFalsePositiveControlsFail(t *testing.T) {
	files, err := conformance.LoadTests("testdata/gwaf")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// A ruleset that blocks every request: the pathological "100% detection"
	// WAF. It must pass the attack cases and fail every benign one.
	waf, err := gwaf.New(gwaf.WithThreshold(0))
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	rep := conformance.Run(waf, files, conformance.ModeDetection)

	if rep.Failed == 0 {
		t.Error("a block-everything configuration passed the whole suite; " +
			"the benign controls are not asserting anything")
	}
}
