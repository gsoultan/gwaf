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
	"github.com/gsoultan/gwaf/types"
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
//
//   - a miss means gwaf allowed something CRS blocks, which is a gap only if the
//     thing is in scope at all.
//
//     CRS_TESTS=/tmp/crs/tests/regression/tests go test -run TestCRSGapReport -v ./test/conformance/
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

// TestConfidenceTiersWiden measures what the Medium tier actually buys.
//
// The tier is off by default: gwaf.New() runs Certain and High only. That is the
// safety property and the first half of this test protects it — the default must
// not move because an opt-in tier exists.
//
// The second half is the reason the tier exists at all. "Confidence tiers are
// strictly more expressive than paranoia levels" (CLAUDE.md §1) was a claim with
// an empty tier behind it: WithMinConfidence was wired up with nothing to
// select, so an operator who wanted a wider net had no dial to turn. A number
// here is what turns that back into a claim somebody can check.
func TestConfidenceTiersWiden(t *testing.T) {
	testDir := os.Getenv("CRS_TESTS")
	if testDir == "" {
		t.Skip("CRS_TESTS not set; skipping the external corpus")
	}
	files, err := conformance.LoadTests(testDir)
	if err != nil {
		t.Fatalf("load %s: %v", testDir, err)
	}

	def, err := gwaf.New()
	if err != nil {
		t.Fatal(err)
	}
	med, err := gwaf.New(gwaf.WithMinConfidence(types.Medium))
	if err != nil {
		t.Fatal(err)
	}

	dRep := conformance.Run(def, files, conformance.ModeDetection)
	mRep := conformance.Run(med, files, conformance.ModeDetection)

	t.Logf("default (Certain+High): %s", dRep)
	t.Logf("medium  (+Medium):      %s", mRep)
	t.Logf("delta: %+d stages detected", mRep.Passed-dRep.Passed)

	if mRep.Passed <= dRep.Passed {
		t.Errorf("the Medium tier detected nothing extra (%d vs %d) — "+
			"an opt-in tier that changes no verdict is not a tier",
			mRep.Passed, dRep.Passed)
	}
}

// TestCRSBridgeFidelity separates the two reasons a converted CRS rule can fail
// its own test, because only one of them is a bug in the converter.
//
// A rule that seclang never imported cannot fire, and that is a coverage number
// the report already carries. A rule that *was* imported and stays silent on the
// payload CRS wrote for it is a translation defect: the rule is present, it is
// wrong, and no coverage percentage will show that.
//
// Run with both variables set, so the ruleset is the converted CRS and the
// comparison is by exact rule ID:
//
//	CRS_TESTS=/tmp/crs/tests/regression/tests CRS_RULES=/tmp/crs/rules \
//	  go test -run TestCRSBridgeFidelity -v ./test/conformance/
func TestCRSBridgeFidelity(t *testing.T) {
	testDir, rulesDir := os.Getenv("CRS_TESTS"), os.Getenv("CRS_RULES")
	if testDir == "" || rulesDir == "" {
		t.Skip("CRS_TESTS and CRS_RULES not both set")
	}

	files, err := conformance.LoadTests(testDir)
	if err != nil {
		t.Fatalf("load tests: %v", err)
	}
	set, reports, err := conformance.LoadCRS(rulesDir)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	t.Logf("bridge: %s", conformance.Summarise(reports))

	imported := make(map[uint32]bool, len(set))
	for _, r := range set {
		imported[uint32(r.ID)] = true
	}

	waf, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatal(err)
	}
	rep := conformance.Run(waf, files, conformance.ModeRuleID)
	t.Logf("%s", rep)

	silent := map[uint32]int{} // imported, did not fire
	absent := map[uint32]int{} // never imported
	for _, res := range rep.Results {
		if res.Passed || res.Skipped {
			continue
		}
		for _, id := range ruleIDsIn(res.Reason) {
			if imported[id] {
				silent[id]++
			} else {
				absent[id]++
			}
		}
	}

	t.Logf("rules imported but silent on their own test: %d distinct", len(silent))
	for _, e := range topN(silent, 25) {
		t.Logf("  SILENT %d (%d stages) — imported, did not fire", e.id, e.n)
	}
	t.Logf("rules never imported: %d distinct (a coverage gap, not a defect)", len(absent))
}

type idCount struct {
	id uint32
	n  int
}

func topN(m map[uint32]int, n int) []idCount {
	out := make([]idCount, 0, len(m))
	for id, c := range m {
		out = append(out, idCount{id, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].id < out[j].id
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ruleIDsIn pulls the CRS rule IDs out of a failure reason such as
// "rules did not fire: 942340, 942350".
func ruleIDsIn(reason string) []uint32 {
	var out []uint32
	for _, f := range strings.FieldsFunc(reason, func(r rune) bool {
		return r < '0' || r > '9'
	}) {
		if len(f) < 5 || len(f) > 7 { // CRS IDs are six digits
			continue
		}
		var v uint32
		for _, c := range f {
			v = v*10 + uint32(c-'0')
		}
		out = append(out, v)
	}
	return out
}

// familyOf reduces "REQUEST-942-APPLICATION-ATTACK-SQLI/942490.yaml" to the
// directory, which is the CRS rule family.
func familyOf(file string) string {
	if d := filepath.Dir(file); d != "." && d != "" {
		return d
	}
	return file
}
