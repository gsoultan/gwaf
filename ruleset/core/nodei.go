// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
)

// nodeCodeInjection reports a JavaScript payload that reaches the process.
//
// # Why this exists as its own rule
//
// It was found by reading misses rather than by imagining attacks. The nuclei
// corpus's RCE class was gwaf's largest gap against CRS, and dumping the missed
// requests made the shape obvious: nine of them were Node.js, and none of the
// other detectors could have caught any of them. CVE-2025-1302 alone is seven,
// a JSONPath filter carrying
//
//	require('child_process').execSync('curl …')
//
// and CVE-2024-53900 is the same idea through a Mongo $where:
//
//	global.process.mainModule.constructor._load('child_process').exec(…)
//
// detect/shelli reads *shell* grammar and there is none here -- no separator, no
// command in command position, just a JavaScript method call whose argument
// happens to be a shell string. detect/ssti reads template syntax; phpi reads
// PHP. A JavaScript payload that never leaves JavaScript syntax was outside all
// of them.
//
// # Why the module name alone is not the signal
//
// "child_process" is ordinary content on a site that discusses Node: a tutorial,
// an issue tracker, a paste bin, a code-review tool. Matching the word would put
// a rule in the core set that blocks people writing about the thing it defends
// against, which is the failure mode IDScriptURI is narrowed to avoid --
// "javascript:" alone appears in every article about XSS.
//
// So the finding requires the module *and* an execution sink: the value has to
// both name the capability and use it. "we run child_process here" is prose;
// "child_process').execSync(" is an attack, and no benign reading survives the
// pairing.
//
// The loader walk is treated as self-evidencing and needs no second half.
// "constructor._load" and "process.binding" exist to reach a module from inside
// a sandbox; a request value containing either has already lost.
func nodeCodeInjection() rules.Operator {
	// Self-evidencing: sandbox escapes whose only purpose is to reach a module
	// the sandbox withheld.
	escapes := []string{
		"constructor._load", "process.binding(", "mainmodule.require",
		"constructor.constructor(", "process.mainmodule",
	}
	// The capability. On its own this is a word people write.
	modules := []string{"child_process", "node:child_process"}
	// The sink. On its own "exec(" is far too common -- it is a method name in
	// every language -- so it is only read together with a module above.
	sinks := []string{
		"execsync(", "exec(", "spawnsync(", "spawn(", "execfile(", "fork(",
	}

	return op.Func("node_code_injection", func(v []byte) bool {
		for _, e := range escapes {
			if indexOfFold(v, e) >= 0 {
				return true
			}
		}
		hasModule := false
		for _, m := range modules {
			if indexOfFold(v, m) >= 0 {
				hasModule = true
				break
			}
		}
		if !hasModule {
			return false
		}
		for _, s := range sinks {
			if indexOfFold(v, s) >= 0 {
				return true
			}
		}
		return false
	}).WithLiterals(
		// Honest: every branch above requires one of these as a substring. The
		// module names cover the paired branch, and each escape covers itself.
		// None is a prefix of ordinary English, so the automaton stays quiet on
		// benign traffic -- which is the property that makes this affordable.
		"child_process",
		"constructor._load", "process.binding(", "mainmodule.require",
		"constructor.constructor(", "process.mainmodule",
	)
}
