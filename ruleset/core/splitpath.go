// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// SplitPathRule reports a sensitive file assembled from two parameters.
//
// "path=/etc/&target=passwd" is a real WordPress plugin CVE. The application
// joins them and opens /etc/passwd, and every rule here is right to pass each
// half: "/etc/" is a directory a file manager legitimately browses and "passwd"
// is a word. The payload exists only in the concatenation, which is why this is
// the one rule that reads EvalContext.Siblings.
//
// It is deliberately narrow. It fires when a value is a *sensitive directory
// prefix* and some other argument of the same request completes it into a file
// this ruleset already blocks whole — so it inherits sensitiveFileOp's judgement
// rather than inventing a second, looser one, and adds no new opinion about
// which files matter.
func SplitPathRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:    id,
		Phase: types.PhaseRequestHeaders,
		// Arguments only: the rule is about the relationship between two of
		// them.
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Transforms: pathChain,
		Op:         splitPathOp{},
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "Sensitive file assembled from separate parameters",
		Tags:       []string{"lfi", "traversal", "owasp-a01"},
	}
}

// sensitiveDirs are directory prefixes worth completing.
//
// Short, and every entry is the head of something sensitiveFileOp already
// matches whole. A prefix not on this list cannot produce a finding here, which
// is what bounds the sibling scan to the values that could matter.
var sensitiveDirs = []string{"etc/", "proc/self/", "windows/system32/", "root/.ssh/", "/.ssh/", "/.aws/"}

type splitPathOp struct{}

func (splitPathOp) Name() string { return "split_path" }

func (splitPathOp) Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool) {
	if ctx == nil || ctx.Target.Kind == types.TargetArgNames || len(ctx.Siblings.Names) < 2 {
		return rules.Match{}, false
	}
	if !endsWithSensitiveDir(value) {
		return rules.Match{}, false
	}

	// Join this prefix with each other argument and ask the rule that already
	// decides what a sensitive file is. Bounded by the argument count, and only
	// reached for a value that is already a sensitive directory.
	//
	// buf escapes -- it is handed to an interface method the compiler cannot
	// prove does not retain it -- so this costs one allocation. It is declared
	// after the guards above on purpose: ordinary traffic returns before
	// reaching it and allocates nothing, which is where the SLO applies.
	// Measured at 0 allocs benign, 1 alloc on a value already shaped like a
	// sensitive directory, by BenchmarkSplitPathEval and its benign twin.
	var buf [maxJoinLen]byte
	for i, name := range ctx.Siblings.Names {
		if i >= len(ctx.Siblings.Values) || string(name) == ctx.Key {
			continue
		}
		other := ctx.Siblings.Values[i]
		if len(other) == 0 || len(value)+len(other)+1 > maxJoinLen {
			continue
		}
		n := copy(buf[:], value)
		if buf[n-1] != '/' {
			buf[n] = '/'
			n++
		}
		n += copy(buf[n:], other)
		// An empty context rather than nil: sensitiveFileOp ignores it today,
		// and a nil here would turn any future key-aware implementation into a
		// panic on the request path rather than a compile error.
		if _, ok := sensitiveFileOp().Eval(&emptyCtx, buf[:n]); ok {
			return rules.WholeValue(value), true
		}
	}
	return rules.Match{}, false
}

// Literals is honest: every sensitive directory prefix contains a slash, and a
// value with no slash cannot be one.
func (splitPathOp) Literals() ([]string, bool) { return []string{"/"}, true }

func (splitPathOp) Cost() types.Fuel { return types.CostLiteralMatch * 4 }

// emptyCtx is handed to the nested operator call above. It is a package-level
// value rather than a literal so the call site allocates nothing.
var emptyCtx rules.EvalContext

// maxJoinLen bounds the join. Both halves are attacker-supplied.
const maxJoinLen = 512

// endsWithSensitiveDir reports whether v is a directory worth completing.
func endsWithSensitiveDir(v []byte) bool {
	if len(v) == 0 || len(v) > maxJoinLen {
		return false
	}
	for _, d := range sensitiveDirs {
		if len(v) < len(d) {
			continue
		}
		if string(v[len(v)-len(d):]) == d {
			return true
		}
		// "/etc" with no trailing slash is the same directory.
		if d[len(d)-1] == '/' && string(v[len(v)-len(d)+1:]) == d[:len(d)-1] {
			return true
		}
	}
	return false
}
