// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/detect/shelli"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// CommandSinkRule reports a command line in a parameter whose name says the
// application hands it to a shell.
//
// # What was actually broken
//
// Nothing in the detector. detect/shelli scores "id" at exactly its threshold
// when told the parameter is a command sink, and has done since that mode was
// added. The value never reached it: the prefilter nominates the shell rule by
// scanning *values* for separators and interpreter paths, and "cmd=id" contains
// neither, so the rule was never a candidate. Four corpus exploits walked
// through a detector that would have caught all of them —
//
//	/data/manage/cmd.php?cmd=id
//	/AdminPage/conf/runCmd?cmd=id
//	?todo=syscmd&cmd=echo%20abc123
//	?x=shell_exec&y=echo%20-n%20X|md5sum
//
// This is the "key-anchored rule" problem recorded in decisions.md, and the
// engine already had the answer. The rule targets ARGS_NAMES and declares the
// sink names as its literals, so the automaton nominates it by matching the
// *name*; shelli.SinkOperator then reads the sibling value and scores that.
//
// # Why opt-in
//
// A parameter named "cmd" is not always a shell. Admin UIs use it for a verb —
// "cmd=list", "cmd=save" — and shelli scores those zero, which is why this is
// narrow rather than reckless. But "cmd=id" is indistinguishable from an
// identifier field in an application that has one, and only the embedder knows
// whether this application shells out. That is the Ownership test, and it is
// the same reason SSRFParamRule, SQLSinkRule and PathSinkRule ship exported.
//
//	waf, err := gwaf.New(gwaf.WithRuleset(
//	    rules.Set{core.CommandSinkRule(4022)},
//	))
//
// No WithBodyPhase here: the operator reads siblings from the argument
// collection, which the body phase populates for JSON and form fields alike, so
// the ARGS_NAMES target already covers both.
func CommandSinkRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:    id,
		Phase: types.PhaseRequestHeaders,
		// Names, not values. The name is the evidence the prefilter can key on.
		Targets: []types.Target{{Kind: types.TargetArgNames}},
		// Names arrive already decoded and are compared case-insensitively by
		// the operator, so no chain is needed. Adding one would materialise
		// every argument name again for nothing.
		Op:         shelli.SinkOperator(),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.High,
		Msg:        "Command line in a shell parameter",
		Tags:       []string{"rce", "shelli", "owasp-a03", "opt-in"},
	}
}
