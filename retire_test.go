// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"os"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
	"github.com/gsoultan/gwaf/types"
)

// TestRetirementCandidates reports which literal rules the structural detectors
// have made redundant, by removing each one and seeing what the corpus loses.
//
// `detect/javaser` and `detect/phpi` shipped as *additions* rather than
// replacements, deliberately: the literal rules around them each carry payloads
// the detectors had not been measured against, and retiring one on the strength
// of "it looks covered" is how coverage disappears quietly. This is the
// measurement that was owed.
//
// It is a report rather than an assertion. Removing a rule and losing nothing
// says the corpus cannot tell them apart, which is evidence for retirement and
// not proof of it — the corpus is the cases somebody thought of. The decision
// stays human; this only supplies the number.
//
//	GWAF_RETIREMENT_REPORT=1 go test -run TestRetirementCandidates -v .
func TestRetirementCandidates(t *testing.T) {
	if os.Getenv("GWAF_RETIREMENT_REPORT") == "" {
		t.Skip("set GWAF_RETIREMENT_REPORT=1 to run the retirement analysis")
	}

	// The literal rules the two structural detectors plausibly supersede. Each
	// predates its detector and answers the same attack with a name list or a
	// fixed pattern.
	candidates := []types.RuleID{
		core.IDLFIPHPWrapper,       // 4003 php:// and friends
		core.IDPHPCodeUpload,       // 4004 <?php in an upload
		core.IDLog4ShellLookup,     // 4006 ${jndi:
		core.IDPHPObjectInjection,  // 4007 O:4:"..."
		core.IDJavaDeserialization, // 4008 0xACED / rO0AB
		core.IDSpring4Shell,        // 4009 class.module.classLoader
		core.IDExpressionLanguage,  // 4011 ${T(...)}
		core.IDJavaGadgetClass,     // 4012 known gadget names
		core.IDPHPDynamicEval,      // 4013 eval/assert
		core.IDPHPPregReplaceEval,  // 4016 preg_replace /e
	}

	full := newWAF(t)
	baseline := caughtSet(t, full)
	t.Logf("baseline: %d/%d corpus cases caught by the full ruleset",
		len(baseline), len(evasions))

	for _, id := range candidates {
		reduced, err := gwaf.New(
			gwaf.WithoutCoreRuleset(),
			gwaf.WithRuleset(without(core.Default(), id)),
		)
		if err != nil {
			t.Fatalf("build without rule %d: %v", id, err)
		}

		var lost []string
		got := caughtSet(t, reduced)
		for name := range baseline {
			if !got[name] {
				lost = append(lost, name)
			}
		}

		if len(lost) == 0 {
			t.Logf("  RETIRABLE  rule %d — removing it loses no corpus case", id)
			continue
		}
		t.Logf("  KEEP       rule %d — removing it loses %d case(s):", id, len(lost))
		for _, n := range lost {
			t.Logf("               %s", n)
		}
	}
}

// caughtSet runs the whole corpus and returns the names that were blocked.
//
// The opt-in cases are skipped: they are covered by rules that ship outside the
// default set, so a WAF built here would miss them for a reason that has nothing
// to do with the rule under test.
func caughtSet(t *testing.T, w *gwaf.WAF) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, e := range evasions {
		if e.optIn {
			continue
		}
		if runEvasion(t, w, e).Blocked() {
			out[e.name] = true
		}
	}
	return out
}

// without returns the set with one rule removed, including its body-phase mirror.
//
// The mirror matters: a rule and its generated counterpart are one decision, and
// removing only the request-phase half would measure something nobody would ever
// ship.
func without(set rules.Set, id types.RuleID) rules.Set {
	out := make(rules.Set, 0, len(set))
	for _, r := range set {
		if r.ID == id || r.ID == id+900 {
			continue
		}
		out = append(out, r)
	}
	return out
}
