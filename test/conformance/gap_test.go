// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package conformance_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/test/conformance"
)

// TestCRSGapReport turns the CRS corpus from a pass rate into a roadmap.
//
// The bare rate is close to useless on its own: the corpus is CRS's home turf and
// a large part of it asserts behaviour gwaf deliberately does not have — protocol
// enforcement, scanner detection by User-Agent, anomaly scoring. A single
// percentage mixes "gwaf misses a real attack" with "gwaf declines to do
// something it never claimed", and those need opposite responses.
//
// So this groups every failure by the CRS rule family that owns it and prints the
// families in order. A family at the top of that list is either a detector gwaf
// should grow or a scope decision gwaf should write down, and reading the list is
// how you tell which.
//
// Two numbers matter more than the rate and are printed separately:
//
//   - a *false positive* here means gwaf blocked a request CRS's own suite says
//     is clean, and that is a defect however the rate looks;
//   - a miss means gwaf allowed something CRS blocks, which is a gap only if the
//     thing is in scope at all.
//
//	CRS_TESTS=/tmp/crs/tests/regression/tests go test -run TestCRSGapReport -v ./test/conformance/
func TestCRSGapReport(t *testing.T) {
	testDir := os.Getenv("CRS_TESTS")
	if testDir == "" {
		t.Skip("CRS_TESTS not set; skipping the external corpus")
	}

	files, err := conformance.LoadTests(testDir)
	if err != nil {
		t.Fatalf("load %s: %v", testDir, err)
	}

	waf, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}
	rep := conformance.Run(waf, files, conformance.ModeDetection)
	t.Logf("corpus: %d files, %s", len(files), rep)

	type family struct {
		name                        string
		missed, falsePos, ambiguous int
	}
	byFamily := map[string]*family{}
	total := map[string]int{}

	for _, res := range rep.Results {
		fam := familyOf(res.File)
		if res.Skipped {
			continue
		}
		total[fam]++
		if res.Passed {
			continue
		}
		f := byFamily[fam]
		if f == nil {
			f = &family{name: fam}
			byFamily[fam] = f
		}
		switch {
		case strings.Contains(res.Reason, "expected a detection"):
			f.missed++
		case strings.Contains(res.Reason, "ambiguous without CRS IDs"):
			// Not a false positive. A CRS "rule-scoped negative" says one
			// specific rule must not fire; the input is frequently still an
			// attack, and gwaf blocking it with a different rule is right. It
			// cannot be judged without CRS rule IDs, which means ModeRuleID
			// against a seclang-converted ruleset. Counting it as a false
			// positive would be the harness claiming a defect it has not shown.
			f.ambiguous++
		default:
			f.falsePos++
		}
	}

	fams := make([]*family, 0, len(byFamily))
	for _, f := range byFamily {
		fams = append(fams, f)
	}
	sort.Slice(fams, func(i, j int) bool {
		if fams[i].missed != fams[j].missed {
			return fams[i].missed > fams[j].missed
		}
		return fams[i].name < fams[j].name
	})

	var falsePositives, ambiguous int
	t.Log("gaps by CRS rule family (missed / false-positive / rule-scoped-ambiguous / run):")
	for _, f := range fams {
		falsePositives += f.falsePos
		ambiguous += f.ambiguous
		t.Logf("  %-46s missed %-5d fp %-4d amb %-4d of %d",
			f.name, f.missed, f.falsePos, f.ambiguous, total[f.name])
	}
	t.Logf("totals: %d false positives, %d rule-scoped ambiguous "+
		"(judgeable only in ModeRuleID with CRS_RULES set)", falsePositives, ambiguous)

	// A false positive against CRS's own clean cases is a defect regardless of
	// what the headline rate says, so it is listed in full rather than counted.
	if falsePositives > 0 {
		t.Log("false positives in full (CRS says clean, gwaf blocked):")
		for _, res := range rep.Results {
			if res.Skipped || res.Passed ||
				strings.Contains(res.Reason, "expected a detection") ||
				strings.Contains(res.Reason, "ambiguous without CRS IDs") {
				continue
			}
			t.Logf("  FP %s / %s (stage %d): %s", res.File, res.Test, res.Stage, res.Reason)
		}
	}
}

// familyOf reduces "REQUEST-942-APPLICATION-ATTACK-SQLI/942490.yaml" to the
// directory, which is the CRS rule family.
func familyOf(file string) string {
	if d := filepath.Dir(file); d != "." && d != "" {
		return d
	}
	return file
}
