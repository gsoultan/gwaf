// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"testing"

	"github.com/gsoultan/gwaf/types"
)

// TestMirrorIDsStayInBand enforces the ID allocation documented at the top of
// this package, rather than trusting anyone to remember it.
//
// A body-phase counterpart is its original's ID plus 900, so an authored ID
// ending at 100 or above mirrors out of its own band. IDNoSQLiEval was first
// allocated 2,501, which mirrored to 3,401 — an ID an operator paging at 3 a.m.
// would reasonably look up as cross-site scripting. Nothing failed; the rule
// worked. It was simply mislabelled in every audit log it would ever appear in.
func TestMirrorIDsStayInBand(t *testing.T) {
	for _, r := range requestRules() {
		band := r.ID / 1000
		if within := r.ID % 1000; within >= 1000-bodyPhaseOffset {
			t.Errorf("rule %d: mirrors to %d, leaving band %d,000-%d,999; "+
				"authored IDs must end below %d within their band",
				r.ID, r.ID+bodyPhaseOffset, band, band, 1000-bodyPhaseOffset)
		}
	}
}

// TestNoDuplicateIDs covers the same generation scheme from the other side: a
// mirror must not land on a rule someone authored by hand.
func TestNoDuplicateIDs(t *testing.T) {
	seen := map[types.RuleID]string{}
	for _, r := range Default() {
		if prev, dup := seen[r.ID]; dup {
			t.Errorf("rule %d is used twice: %q and %q", r.ID, prev, r.Msg)
		}
		seen[r.ID] = r.Msg
	}
}

// TestEveryRuleIsCertainOrHigh is the package doc as a test. Blocking by
// default is only defensible while it holds.
func TestEveryRuleIsCertainOrHigh(t *testing.T) {
	for _, r := range Default() {
		if r.Confidence != types.Certain && r.Confidence != types.High {
			t.Errorf("rule %d (%q) is %v; the core ruleset blocks by default "+
				"and may only carry Certain or High", r.ID, r.Msg, r.Confidence)
		}
	}
}

// TestBodyMirrorsNeverWidenTargets is the invariant that a generated rule
// inspects the body-phase equivalent of its original and nothing more.
//
// mirrorToBody used to assign a fixed target list, which silently widened every
// mirror to read argument values, argument names, and the raw body regardless
// of what the original was scoped to. That is invisible while every rule reads
// everything, and wrong the moment one does not: the NoSQL rules read parameter
// names only, and widening them blocked {"note":"use $ne to negate"}.
func TestBodyMirrorsNeverWidenTargets(t *testing.T) {
	authored := map[types.RuleID][]types.Target{}
	for _, r := range requestRules() {
		authored[r.ID] = r.Targets
	}

	for _, m := range Default() {
		if m.Phase != types.PhaseRequestBody {
			continue
		}
		src, ok := authored[m.ID-bodyPhaseOffset]
		if !ok {
			continue
		}

		var srcValues, srcNames bool
		for _, t := range src {
			switch t.Kind {
			case types.TargetArgs:
				srcValues = srcValues || t.Name == ""
			case types.TargetArgNames:
				srcNames = true
			}
		}

		for _, tg := range m.Targets {
			switch tg.Kind {
			case types.TargetArgs, types.TargetRequestBody:
				if !srcValues {
					t.Errorf("rule %d reads %v, but its original %d never read "+
						"argument values", m.ID, tg.Kind, m.ID-bodyPhaseOffset)
				}
			case types.TargetArgNames:
				if !srcNames {
					t.Errorf("rule %d reads ARGS_NAMES, but its original %d "+
						"never did", m.ID, m.ID-bodyPhaseOffset)
				}
			}
		}
	}
}
