// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package phpi detects PHP injection by reading language structure rather than
// by listing function names.
//
// # Why not a function list
//
// The Core Rule Set splits PHP functions across three rules by risk — high,
// medium and low value — and the low tier alone is several hundred names. That
// is why they sit behind paranoia levels: "array_diff", "filemtime" and
// "date_add" are words a support ticket, a code review or a documentation search
// contains all day, and a name on its own says nothing about intent.
//
// The list is also the wrong shape for the attack. A payload does not need a
// dangerous function name at all — "$_GET[0]($_GET[1])" calls whatever the
// request asks for and contains no function name whatsoever, which is precisely
// how variable-function attacks work.
//
// # What is actually invariant
//
// PHP injection is *PHP syntax arriving in a value*. The syntax is fixed even
// though the vocabulary is not:
//
//   - an open tag, "<?php" or "<?=", is the language boundary itself;
//   - a stream wrapper, "php://input" or "expect://id", names an interpreter or
//     a process where a path was expected;
//   - a variable function, "$f(" or "$$x", is a call whose target is data;
//   - a superglobal, "$_GET" or "$GLOBALS", is the request reading itself.
//
// So a function name scores here only in *call position* and only alongside PHP
// structure. "we should replace array_diff with a set" has a name and no syntax,
// and is not an attack.
package phpi

import (
	"github.com/gsoultan/gwaf/internal/scan"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Signal is one piece of structural evidence.
type Signal uint16

// Signals.
const (
	// SignalOpenTag is a PHP open tag — "<?php", "<?=", or a bare "<?" followed
	// by whitespace. The language boundary arriving inside a value is not
	// something an application asks for.
	SignalOpenTag Signal = 1 << iota

	// SignalStreamWrapper is a wrapper scheme where a path belongs:
	// "php://input", "php://filter", "data://", "expect://", "zip://",
	// "phar://". Each turns a file read into something else — filter chains
	// disclose source, expect runs a command, phar triggers deserialization.
	SignalStreamWrapper

	// Serialized-object headers are deliberately *not* a signal here. Core rule
	// 4007 already reads them, and it solves the prefilter problem this package
	// could not: `O:4:"Evil"` contains no literal selective enough to key an
	// automaton on, so 4007 keys on the member separators instead — ";s:",
	// "{i:", ":{s:". Adding a second, weaker reading of the same attack would
	// cost a rule and buy nothing.

	// SignalVariableFunction is a call whose target is data rather than a name —
	// "$f(", "${'x'}(", "$$var". This is the attack that no function list can
	// ever cover, because the payload never names a function.
	SignalVariableFunction

	// SignalSuperglobal is a request superglobal — $_GET, $_POST, $_REQUEST,
	// $_COOKIE, $_FILES, $_SERVER, $GLOBALS. A value that reads the request it
	// arrived in is code, not data.
	SignalSuperglobal

	// SignalDangerCall is a function that executes, in call position: system(,
	// exec(, passthru(, shell_exec(, popen(, proc_open(, eval(, assert(,
	// create_function(, preg_replace( with /e. Call position is what makes it
	// evidence — the name alone is documentation.
	SignalDangerCall

	// SignalConfigDirective is a php.ini directive being set through the value —
	// "allow_url_include", "auto_prepend_file", "open_basedir". Reaching
	// configuration from a request parameter has no legitimate reading.
	SignalConfigDirective

	// SignalCloseTag is "?>". Weak alone: it appears in documentation and in XML
	// processing instructions. Corroborating.
	SignalCloseTag

	// SignalDangerStatement is a danger call written as a complete statement —
	// a non-empty argument list and a ';' terminator, as in "system('X');".
	// SignalDangerCall stays corroborating because "never eval() untrusted
	// input" is a sentence a security blog writes; this is the form prose does
	// not produce, so it stands alone.
	SignalDangerStatement

	// SignalShellExec is PHP's backtick operator executing a command. It is only
	// raised inside a PHP context, because a bare `id` is a markdown code span.
	SignalShellExec
)

// String implements fmt.Stringer so a decision can say what it saw.
func (s Signal) String() string {
	var out []byte
	add := func(n string) {
		if len(out) > 0 {
			out = append(out, '+')
		}
		out = append(out, n...)
	}
	if s&SignalOpenTag != 0 {
		add("open_tag")
	}
	if s&SignalStreamWrapper != 0 {
		add("stream_wrapper")
	}
	if s&SignalVariableFunction != 0 {
		add("variable_function")
	}
	if s&SignalSuperglobal != 0 {
		add("superglobal")
	}
	if s&SignalDangerCall != 0 {
		add("danger_call")
	}
	if s&SignalConfigDirective != 0 {
		add("config_directive")
	}
	if s&SignalCloseTag != 0 {
		add("close_tag")
	}
	if s&SignalDangerStatement != 0 {
		add("danger_statement")
	}
	if s&SignalShellExec != 0 {
		add("shell_exec")
	}
	if len(out) == 0 {
		return "none"
	}
	return string(out)
}

// weightOf prices each signal by what it means alone.
func weightOf(s Signal) int {
	switch s {
	case SignalStreamWrapper, SignalVariableFunction,
		SignalConfigDirective, SignalDangerStatement:
		return 5
	case SignalShellExec:
		return 4
	case SignalDangerCall:
		return 4
	// An open tag convicts alone, and it was measured rather than assumed.
	// Demoting it to corroborating did fix the one false positive a WordPress
	// replay produced -- "<?php echo $name; ?>" in a comment field is somebody
	// explaining PHP -- but it also dropped 32 real exploits from the same
	// replay: RCE fell from 84% to 43% and upload webshells from 100% to 40%,
	// because a PHP payload very often *is* just an open tag and a body. Two
	// false positives are not worth 32 webshells. A blogging platform that
	// carries PHP in its post bodies scopes an exception for those fields,
	// which is narrower than every other embedder paying for it.
	case SignalOpenTag:
		return 5
	case SignalSuperglobal:
		return 3
	case SignalCloseTag:
		return 1
	default:
		return 0
	}
}

// Threshold is the score at or above which a value is reported.
const Threshold = 5

// Verdict is the result of analysing one value.
type Verdict struct {
	Signals Signal
	Score   int
	Span    types.Span
}

// Detected reports whether the evidence reached the threshold.
func (v Verdict) Detected() bool { return v.Score >= Threshold }

// Detector analyses values for PHP injection.
//
// A Detector is immutable and safe for concurrent use.
type Detector struct{}

// New returns a Detector.
func New() *Detector { return &Detector{} }

// Name implements the operator contract.
func (*Detector) Name() string { return "detect_phpi" }

// maxScan bounds the structural scans; the engine's fuel meter owns the overall
// ceiling.
const maxScan = 8192

// Analyze scores value and returns the verdict.
func (d *Detector) Analyze(value []byte) Verdict {
	src := value
	if len(src) > maxScan {
		src = src[:maxScan]
	}

	var sigs Signal
	sigs |= scanTags(src)
	sigs |= scanWrappers(src)
	sigs |= scanVariables(src)
	sigs |= scanCalls(src)
	// Backticks are PHP's shell-execution operator: "<?= `id` ?>" runs id. They
	// are only read that way inside a PHP context, because a bare `id` is a
	// markdown code span and those arrive constantly in comments and issue
	// bodies.
	if sigs&SignalOpenTag != 0 && hasBacktickExec(src) {
		sigs |= SignalShellExec
	}

	total := 0
	for bit := Signal(1); bit != 0; bit <<= 1 {
		if sigs&bit != 0 {
			total += weightOf(bit)
		}
	}
	return Verdict{Signals: sigs, Score: total, Span: types.SpanOf(0, len(value))}
}

// scanTags finds the language boundary.
//
// Only "<?php" and "<?=" count. A bare "<?" followed by whitespace is the
// short-open-tag form, and accepting it was a false positive: "a <? b and c ?> d
// are comparisons" is arithmetic, and an XML processing instruction is not PHP
// either. short_open_tag has defaulted to Off since PHP 5.4, so the coverage
// given up is small and the sentence it stops blocking is not.
//
// A short-tag payload that does anything still scores: "<? system('id'); ?>"
// reaches the threshold on the call and the closing tag together.
func scanTags(v []byte) Signal {
	var sigs Signal
	for i := 0; i+1 < len(v); i++ {
		if v[i] != '<' || v[i+1] != '?' {
			continue
		}
		rest := v[i+2:]
		if hasPrefixFold(rest, "php") || hasPrefixFold(rest, "=") {
			sigs |= SignalOpenTag
		}
	}
	if indexFold(v, "?>") >= 0 {
		sigs |= SignalCloseTag
	}
	return sigs
}

// wrappers are schemes that turn a path into something executable or disclosing.
var wrappers = []string{
	"php://", "data://", "expect://", "zip://", "phar://", "glob://",
	"ogg://", "rar://", "compress.zlib://", "compress.bzip2://",
}

func scanWrappers(v []byte) Signal {
	for _, w := range wrappers {
		if indexFold(v, w) >= 0 {
			return SignalStreamWrapper
		}
	}
	return 0
}

// superglobals are the request arrays. A value that reads the request it
// arrived in is code.
var superglobals = []string{
	"$_get", "$_post", "$_request", "$_cookie", "$_files",
	"$_server", "$_env", "$_session", "$globals",
}

// scanVariables finds variable functions and superglobals.
//
// A variable function is the attack no function list can cover, because the
// payload never names a function: "$_GET[0]($_GET[1])" calls whatever the
// request asks for. The structure is a '$' whose expansion is immediately
// invoked.
func scanVariables(v []byte) Signal {
	var sigs Signal
	for _, g := range superglobals {
		if indexFold(v, g) >= 0 {
			sigs |= SignalSuperglobal
			break
		}
	}

	for i := 0; i < len(v); i++ {
		if v[i] != '$' {
			continue
		}
		// "$$var" — a variable variable.
		if i+1 < len(v) && v[i+1] == '$' {
			sigs |= SignalVariableFunction
			continue
		}
		// A call whose target is data, but only where the target is a
		// superglobal: "$_GET[0]($_GET[1])".
		//
		// A bare "$f(" was accepted here once and the literal it forced —
		// a lone "$" — made this rule a candidate for every price, every shell
		// variable and every template field on the internet. The prefilter is
		// where that is paid for, so the signal is narrowed to the form an
		// attacker can actually reach: the target has to come from the request,
		// and a local variable they cannot set is not an attack they can mount.
		if !hasPrefixFold(v[i:], "$_") && !hasPrefixFold(v[i:], "$globals") {
			continue
		}
		j := i + 1
		for j < len(v) && isNameByte(v[j]) {
			j++
		}
		if j == i+1 {
			continue
		}
		// Step over one subscript, so "$_GET[0](" is seen as a call.
		if j < len(v) && v[j] == '[' {
			for j < len(v) && v[j] != ']' {
				j++
			}
			if j < len(v) {
				j++
			}
		}
		if j < len(v) && v[j] == '(' {
			sigs |= SignalVariableFunction
		}
	}
	return sigs
}

// dangerCalls execute or evaluate. Only counted in call position.
var dangerCalls = []string{
	"system", "exec", "passthru", "shell_exec", "popen", "proc_open",
	"eval", "assert", "create_function", "preg_replace", "call_user_func",
	"call_user_func_array", "include", "include_once", "require", "require_once",
	"file_get_contents", "fpassthru", "readfile", "pcntl_exec",
}

// configDirectives reach php.ini from a request.
var configDirectives = []string{
	"allow_url_include", "allow_url_fopen", "auto_prepend_file",
	"auto_append_file", "open_basedir", "disable_functions", "safe_mode",
}

// scanCalls scores an executing function in call position, and configuration
// directives anywhere.
//
// Call position is the whole discriminator: "system" is a word, "system(" is an
// invocation. Requiring the parenthesis is what keeps "the payment system
// failed" out of the results while keeping "system('id')" in.
// isCallStatement reports whether the argument list opening at v[open] is a
// complete call statement: a non-empty argument list whose closing paren is
// followed by ';'.
//
// This is the line between a sentence naming a function and PHP being executed.
// "never eval() untrusted input in production" names one -- empty parens, no
// terminator. "system('X');" is code. Nesting is tracked so that
// "shell_exec(trim($x));" reads as one statement, and quotes are skipped so a
// ')' or ';' inside an argument string does not end it early.
func isCallStatement(v []byte, open int) bool {
	depth, i := 0, open
	for i < len(v) {
		switch v[i] {
		case '\'', '"':
			q := v[i]
			i++
			for i < len(v) && v[i] != q {
				if v[i] == '\\' {
					i++
				}
				i++
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				// Empty argument list is how prose names a function.
				if i == open+1 {
					return false
				}
				for j := i + 1; j < len(v); j++ {
					if isSpace(v[j]) {
						continue
					}
					return v[j] == ';'
				}
				return false
			}
		}
		i++
	}
	return false
}

// hasBacktickExec reports whether v contains a non-empty backtick pair on one
// line. The line bound matters: two backticks pages apart in prose are two
// separate code spans, not a command substitution.
func hasBacktickExec(v []byte) bool {
	for i := 0; i < len(v); i++ {
		if v[i] != '`' {
			continue
		}
		for j := i + 1; j < len(v); j++ {
			if v[j] == '\n' {
				break
			}
			if v[j] == '`' {
				return j > i+1
			}
		}
	}
	return false
}

func scanCalls(v []byte) Signal {
	var sigs Signal
	for _, c := range dangerCalls {
		i := 0
		for {
			j := indexFold(v[i:], c)
			if j < 0 {
				break
			}
			at := i + j
			i = at + 1
			// Must start a token.
			if at > 0 && isNameByte(v[at-1]) {
				continue
			}
			// Must be followed by "(" — optionally after whitespace, which PHP
			// permits between the name and the call.
			k := at + len(c)
			for k < len(v) && isSpace(v[k]) {
				k++
			}
			if k < len(v) && v[k] == '(' {
				sigs |= SignalDangerCall
				if isCallStatement(v, k) {
					sigs |= SignalDangerStatement
				}
				break
			}
		}
	}
	for _, c := range configDirectives {
		if indexFold(v, c) >= 0 {
			sigs |= SignalConfigDirective
			break
		}
	}
	return sigs
}

// ---- byte helpers -----------------------------------------------------------

func isNameByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_'
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

func fold(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func hasPrefixFold(v []byte, p string) bool {
	if len(v) < len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if fold(v[i]) != p[i] {
			return false
		}
	}
	return true
}

// indexFold finds a lowercase needle in v, folding v as it goes.
func indexFold(v []byte, needle string) int {
	if len(needle) == 0 || len(v) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(v); i++ {
		ok := true
		for j := 0; j < len(needle); j++ {
			if fold(v[i+j]) != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// ---- operator ---------------------------------------------------------------

// Operator adapts the detector to the rule engine.
func Operator() rules.Operator { return &operator{d: New(), threshold: Threshold} }

// OperatorAt returns an operator that reports at a caller-chosen score.
//
// This is how a rule earns a confidence tier below High out of the *same*
// evidence, rather than by writing a second, sloppier detector. Lower is more
// sensitive and less certain; a ruleset that lowers it is opting into false
// positives it has decided it can absorb, and that decision belongs to whoever
// runs the traffic.
func OperatorAt(threshold int) rules.Operator {
	return &operator{d: New(), threshold: threshold}
}

type operator struct {
	d         *Detector
	threshold int
}

func (o *operator) Name() string { return "detect_phpi" }

// Eval scores the value, covering all of it rather than its first maxScan bytes.
//
// The windowing is the fix for a padding bypass: the bound was applied by
// truncating, which reasons correctly about how long a payload is and not at all
// about where it sits. The same payload scored nothing when preceded by enough
// ordinary text. See internal/scan.
func (o *operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	var match rules.Match
	var found bool
	scan.Windows(value, maxScan, func(off int, w []byte) bool {
		v := o.d.Analyze(w)
		if v.Score < o.threshold {
			return true
		}
		// The span is relative to the window; callers want it relative to the
		// value they passed in.
		match = rules.Match{Span: types.SpanOf(off+int(v.Span.Off), int(v.Span.Len))}
		found = true
		return false
	})
	return match, found
}

// Literals are the byte sequences without which no scoring signal can fire.
//
// Every signal that can reach the threshold needs one: a tag opener, a wrapper
// scheme, a '$' for variable structure, or a name from the call and directive
// lists. FuzzLiteralsAreExhaustive enforces that this stays true.
func (o *operator) Literals() ([]string, bool) {
	// "$" alone is not here, deliberately. It was, and it made this rule a
	// candidate for "$19.99", "${total}" and every shell variable in a config
	// field — a measurable cost on traffic that can never match. The signals are
	// shaped so that the selective forms suffice.
	lits := []string{"<?", "$$", "$_", "$globals", "://"}
	lits = append(lits, dangerCalls...)
	lits = append(lits, configDirectives...)
	return lits, true
}

func (o *operator) Cost() types.Fuel { return types.CostLiteralMatch * 14 }
