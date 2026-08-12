// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
)

// stringToCode reports a value that turns a string into running code.
//
// # The gap this closes
//
// A red-team round of language-specific evasions -- the ones a PHP or JavaScript
// specialist reaches for once the generic payloads fail -- got 17 of 24 through.
// The JavaScript half was one idea spelled ten ways:
//
//	Function('alert(1)')()
//	[]['constructor']['constructor']('alert(1)')()
//	globalThis['eval']('alert(1)')
//	setTimeout('alert(1)',0)
//	eval(atob('YWxlcnQoMSk='))
//	window['ale'+'rt'](1)
//
// None carries HTML, so detect/xss has nothing to read. None carries a handler,
// a statement terminator or document.domain, so rule 3012 declines. None names
// child_process, so rule 4021 declines. Each is correct about the question it
// asks, and the question none of them asks is the one these payloads answer:
// **is this value turning a string into code?**
//
// The PHP half is the same idea with different spelling -- a function invoked by
// name rather than written:
//
//	call_user_func('system','id')
//	array_map('system',['id'])
//
// rule 4023 looks for "system(" and these never write it; the name travels as a
// string and something else applies the parentheses.
//
// # Why each signal has no benign reading
//
// The constructor walk and globalThis subscript exist to reach a capability the
// surrounding scope withheld. A request parameter containing
// "['constructor']['constructor']" has already lost, whatever it decodes to.
//
// The string forms of Function, setTimeout and setInterval are the *code*
// overloads: setTimeout(fn, 0) is ordinary and setTimeout('...', 0) compiles its
// first argument. Requiring the quote is what separates them, and it is the same
// narrowing rule 4023 applies to "system(".
//
// eval paired with a decoder -- atob, unescape, decodeURIComponent, fromCharCode
// -- is decode-then-execute, which is a technique rather than a coincidence.
//
// For PHP, a quoted spawn name is not enough on its own: {"type":"system"} is
// ordinary JSON. It is paired with a callable-invoking API in the same value,
// which is what makes it an invocation rather than a word.
//
// Measured against the 10,480-request benign corpus, every token here appears
// zero times. High rather than Certain because that corpus is one adopter's
// traffic (boundaries.md).
func stringToCode() rules.Operator {
	// Self-evidencing: reaching a capability the scope withheld.
	escapes := []string{
		"constructor.constructor", "['constructor']", `["constructor"]`,
		"globalthis[", "globalthis.eval", "self['eval']", "window['eval']",
	}
	// The code overloads: a compiler entry point handed a string literal.
	compilers := []string{
		"function('", `function("`, "function(`",
		"settimeout('", `settimeout("`, "setinterval('", `setinterval("`,
		"setimmediate('", "execscript(",
	}
	// Decode-then-execute.
	decodeEval := []string{
		"eval(atob", "eval(unescape", "eval(decodeuri", "eval(atob(",
		"eval(string.fromcharcode", "eval(base64", "eval(window.atob",
	}
	// PHP: a function invoked by name. Each needs a quoted spawn name beside it.
	invokers := []string{
		"call_user_func", "call_user_func_array", "array_map(", "usort(",
		"array_filter(", "preg_replace_callback(", "register_shutdown_function(",
		"array_walk(", "forward_static_call",
	}
	spawnNames := []string{
		"'system'", `"system"`, "'passthru'", `"passthru"`,
		"'shell_exec'", `"shell_exec"`, "'exec'", `"exec"`,
		"'popen'", `"popen"`, "'proc_open'", `"proc_open"`,
		"'assert'", `"assert"`, "'eval'", `"eval"`,
	}

	return op.Func("string_to_code", func(v []byte) bool {
		for _, s := range escapes {
			if indexOfFold(v, s) >= 0 {
				return true
			}
		}
		for _, s := range compilers {
			if indexOfFold(v, s) >= 0 {
				return true
			}
		}
		for _, s := range decodeEval {
			if indexOfFold(v, s) >= 0 {
				return true
			}
		}
		// The PHP pairing: an invoker and a quoted name it can apply.
		hasInvoker := false
		for _, s := range invokers {
			if indexOfFold(v, s) >= 0 {
				hasInvoker = true
				break
			}
		}
		if !hasInvoker {
			return false
		}
		for _, s := range spawnNames {
			if indexOfFold(v, s) >= 0 {
				return true
			}
		}
		return false
	}).WithLiterals(
		// Honest: every branch requires one of these as a substring. The PHP
		// branch needs an invoker *and* a name, so listing the invokers alone
		// would already be sufficient -- the names are listed too because the
		// prefilter only has to nominate, and a value carrying neither cannot
		// match.
		"constructor.constructor", "['constructor']", `["constructor"]`,
		"globalthis[", "globalthis.eval", "self['eval']", "window['eval']",
		"function('", `function("`, "function(`",
		"settimeout('", `settimeout("`, "setinterval('", `setinterval("`,
		"setimmediate('", "execscript(",
		"eval(atob", "eval(unescape", "eval(decodeuri",
		"eval(string.fromcharcode", "eval(base64", "eval(window.atob",
		"call_user_func", "call_user_func_array", "array_map(", "usort(",
		"array_filter(", "preg_replace_callback(", "register_shutdown_function(",
		"array_walk(", "forward_static_call",
	)
}
