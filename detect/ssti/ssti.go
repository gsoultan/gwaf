// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package ssti detects server-side template injection by reading what sits
// inside a template expression, never by the presence of one.
//
// # The delimiters are not the attack
//
// This is the whole design, and getting it wrong is how a template-injection
// detector becomes unusable. "{{ user.name }}" is Vue, Angular, Handlebars,
// Jinja, and Liquid. "${var.region}" is Terraform. "${{ matrix.os }}" is a
// GitHub Actions workflow. "#{name}" is Ruby string interpolation. "<%= x %>"
// is ERB. Every one of those appears in ordinary traffic: a CMS field, a
// documentation page, an issue tracker where somebody pasted a workflow file,
// an email-template editor, an i18n string.
//
// A detector that fires on "{{" blocks all of it. Since template *content* is
// exactly what template-editing applications accept, that detector would be
// most wrong precisely where it is most needed.
//
// So the delimiters only establish a context. The verdict comes from what is
// being *evaluated* inside them:
//
//   - Python object traversal — __class__, __mro__, __subclasses__, __globals__,
//     __builtins__, __import__. These reach the interpreter from a template and
//     have no meaning in a user-facing one.
//   - Framework internals — config, request, url_for, lipsum, cycler — followed
//     by attribute access. Reaching the app object is the first step of every
//     Jinja escape. The access is what counts: "{{ config }}" renders a value,
//     "{{ config.items() }}" walks into the interpreter.
//   - JVM class access — T(java.lang...), getRuntime, ProcessBuilder,
//     classLoader, forName, freemarker.template.utility.Execute. Spring EL and
//     FreeMarker both reach the class loader this way.
//   - Ruby execution — system(, IO.popen, Kernel, File.read, `backticks` inside
//     an interpolation.
//   - Velocity and Smarty directives that reach a runtime object.
//
// # Why this ships at High and not Certain
//
// Because the honest answer is that a determined false positive exists: an
// application whose users legitimately author Jinja templates will send
// "{{ config }}" on purpose. That application needs a scoped exception, and
// gwaf's job is to report the finding rather than to pretend the ambiguity is
// not there. Every other class in the core ruleset either has no such case or
// has one so rare it is not worth the recall.
//
// # Arithmetic probes are evidence, not proof
//
// "{{7*7}}" is how a tester confirms a template is evaluated, and it is the
// single most cited SSTI payload. It is also two digits and an operator, which
// is why it scores as corroboration rather than firing alone — "{{ 2*count }}"
// is a real thing to write in a template.
package ssti

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Signal is one piece of structural evidence.
type Signal uint16

// Signals.
const (
	// SignalPythonInternals is attribute access that reaches the interpreter:
	// __class__, __mro__, __subclasses__, __globals__, __builtins__, __import__.
	// A user-facing template has no reason to name any of them.
	SignalPythonInternals Signal = 1 << iota

	// SignalAppObject is a framework object — config, request, url_for, lipsum —
	// reached by attribute access or a call. "{{ config }}" renders a value and
	// scores nothing; "{{ config.items() }}" walks into the interpreter, and
	// that access is the first step of every Jinja escape.
	SignalAppObject

	// SignalJVMClassAccess is Spring EL or FreeMarker reaching the class loader:
	// T(java.lang...), getRuntime, ProcessBuilder, getClassLoader,
	// freemarker.template.utility.Execute.
	SignalJVMClassAccess

	// SignalRubyExecution is Ruby code that runs a command — system(, IO.popen,
	// Kernel., File.read, or a backtick command inside an interpolation.
	SignalRubyExecution

	// SignalDirectiveExecution is a Velocity or Smarty directive that reaches a
	// runtime object: #set with $rt, {php}, {system}.
	SignalDirectiveExecution

	// SignalArithmeticProbe is constant arithmetic inside a template expression
	// — the "{{7*7}}" that confirms evaluation. Deliberately weak: "{{ 2*n }}"
	// is a real template.
	SignalArithmeticProbe

	// SignalTemplateContext is a template delimiter. On its own it means only
	// that the value contains template syntax, which is true of a great deal of
	// legitimate content, so it carries no weight at all. It is tracked because
	// the other signals are only meaningful *inside* one.
	SignalTemplateContext
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
	if s&SignalPythonInternals != 0 {
		add("python_internals")
	}
	if s&SignalAppObject != 0 {
		add("app_object")
	}
	if s&SignalJVMClassAccess != 0 {
		add("jvm_class_access")
	}
	if s&SignalRubyExecution != 0 {
		add("ruby_execution")
	}
	if s&SignalDirectiveExecution != 0 {
		add("directive_execution")
	}
	if s&SignalArithmeticProbe != 0 {
		add("arithmetic_probe")
	}
	if s&SignalTemplateContext != 0 {
		add("template_context")
	}
	if len(out) == 0 {
		return "none"
	}
	return string(out)
}

// Threshold is the score at or above which a value is reported.
const Threshold = 5

// weightOf prices each signal by what it means alone.
//
// The strong signals reach the threshold by themselves because none of them has
// a benign reading inside a template: nothing legitimate asks a template for
// __subclasses__ or for java.lang.Runtime. The weak ones cannot fire alone, and
// SignalTemplateContext is worth nothing at all — that is the point of it.
func weightOf(s Signal) int {
	switch s {
	case SignalPythonInternals, SignalJVMClassAccess,
		SignalRubyExecution, SignalDirectiveExecution, SignalAppObject:
		return 5
	case SignalArithmeticProbe:
		return 2
	default:
		return 0
	}
}

// Verdict is the result of analysing one value.
type Verdict struct {
	Signals Signal
	Score   int
	Span    types.Span
}

// Detected reports whether the evidence reached the threshold.
func (v Verdict) Detected() bool { return v.Score >= Threshold }

// Detector analyses values for server-side template injection.
//
// A Detector is immutable and safe for concurrent use.
type Detector struct{}

// New returns a Detector.
func New() *Detector { return &Detector{} }

// Name implements the operator contract.
func (*Detector) Name() string { return "detect_ssti" }

// maxScan bounds how much of a value is analysed. Every signal is local to one
// expression, so a payload needing more than this does not exist.
const maxScan = 64 << 10

// Analyze scores value and returns the verdict.
func (d *Detector) Analyze(value []byte) Verdict {
	if len(value) == 0 {
		return Verdict{}
	}
	src := value
	if len(src) > maxScan {
		src = src[:maxScan]
	}

	sigs, span := scan(src)

	total := 0
	for bit := Signal(1); bit != 0; bit <<= 1 {
		if sigs&bit != 0 {
			total += weightOf(bit)
		}
	}
	return Verdict{Signals: sigs, Score: total, Span: span}
}

// scan walks the value, tracking whether it is inside a template expression and
// what that expression evaluates.
func scan(src []byte) (Signal, types.Span) {
	var sigs Signal
	var span types.Span
	found := false

	mark := func(s Signal, off, n int) {
		sigs |= s
		if !found && weightOf(s) > 0 {
			span = types.SpanOf(off, n)
			found = true
		}
	}

	for i := 0; i < len(src); i++ {
		// A template expression opens, and the region up to its close is what
		// gets read. Everything outside one is ordinary text.
		start, end, sig, ok := expressionAt(src, i)
		if !ok {
			continue
		}
		mark(SignalTemplateContext, i, 1)
		if sig != 0 {
			mark(sig, i, end-i)
		}

		expr := src[start:end]
		for _, s := range scanExpression(expr) {
			mark(s, start, end-start)
		}
		i = end - 1
	}
	return sigs, span
}

// delimiters are the template expression forms, as open/close byte pairs.
//
// "${{" is matched by "${" followed by "{", which is harmless: GitHub Actions
// expressions are read as expressions and then found to contain nothing
// dangerous, which is the correct outcome rather than a special case.
// A few carry a signal of their own, because the delimiter *is* the finding:
// Smarty's {php} executes PHP by definition, and no benign reading exists. The
// rest establish context only and are worth nothing on their own.
var delimiters = []struct {
	open, close string
	signal      Signal
}{
	{open: "{{", close: "}}"}, // Jinja, Twig, Handlebars, Vue, Angular, Liquid
	{open: "${", close: "}"},  // Spring EL, JSP EL, Thymeleaf, JS template literal
	{open: "#{", close: "}"},  // Ruby, Thymeleaf message, Slim
	{open: "<%", close: "%>"}, // ERB, JSP, ASP, EJS
	{open: "{%", close: "%}"}, // Jinja and Twig statements
	{open: "#set"},            // Velocity directive: reads to end of line
	{open: "{php}", signal: SignalDirectiveExecution},
	{open: "{system", signal: SignalDirectiveExecution},
	{open: "<#", close: ">"}, // FreeMarker directive
	{open: "@{", close: "}"}, // Razor
}

// expressionAt reports the bounds of a template expression opening at i.
//
// An unterminated expression still counts, reading to the end of the value: a
// payload does not have to be well formed to be evaluated, and requiring the
// close would be defeated by deleting it.
func expressionAt(src []byte, i int) (start, end int, sig Signal, ok bool) {
	for _, d := range delimiters {
		if !hasPrefix(src[i:], d.open) {
			continue
		}
		start = i + len(d.open)
		if d.close == "" {
			// A directive form: read to end of line.
			end = start
			for end < len(src) && src[end] != '\n' {
				end++
			}
			return start, end, d.signal, true
		}
		if j := indexFrom(src, start, d.close); j >= 0 {
			return start, j, d.signal, true
		}
		return start, len(src), d.signal, true
	}
	return 0, 0, 0, false
}

// pythonInternals reach the interpreter from a template.
var pythonInternals = []string{
	"__class__", "__mro__", "__subclasses__", "__globals__", "__builtins__",
	"__import__", "__init__", "__base__", "__bases__", "__code__",
	"__reduce__", "__dict__", "__getattribute__", "__loader__",
}

// appObjects are framework objects whose attributes lead to the interpreter.
//
// "self" is deliberately absent. "#{self.name}" is idiomatic Ruby and appears
// in ordinary prose about Ruby, while the Jinja payload that matters --
// self.__init__.__globals__ -- is caught by its dunder names regardless.
var appObjects = []string{
	"config", "request", "url_for", "get_flashed_messages",
	"lipsum", "cycler", "joiner", "namespace", "application",
}

// jvmAccess is Spring EL and FreeMarker reaching the class loader.
var jvmAccess = []string{
	"java.lang", "getruntime", "processbuilder", "classloader",
	"forname", "freemarker.template.utility", "javax.script",
	"scriptengine", "getdeclaredmethod", "loadclass", "getclass",
}

// rubyExecution is Ruby that runs a command.
var rubyExecution = []string{
	"io.popen", "kernel.", "file.read", "file.open", "%x(",
	"system(", "exec(", "spawn(", "open3.",
}

// directiveExecution reaches a runtime object from the template engine itself:
// a Velocity or Smarty directive, or a Twig internal.
//
// The Twig entries are the engine's own escape hatch. "_self" alone is
// legitimate and common -- "{% import _self as forms %}" is how every Twig
// macro file is written -- so it is deliberately absent. "_self.env" is not:
// it reaches the Environment object, and registerUndefinedFilterCallback then
// turns any function name into a filter, which is the two-step that makes
// "{{_self.env.registerUndefinedFilterCallback('system')}}" remote code
// execution. Naming the escape rather than the delimiter is the same rule the
// rest of this detector follows.
var directiveExecution = []string{
	"getruntime", "$rt.", "scriptutil", "{php}", "{system",
	"_self.env", "registerundefinedfiltercallback",
	"registerundefinedfunctioncallback", "getfilter(",
}

// scanExpression classifies the contents of one template expression.
func scanExpression(expr []byte) []Signal {
	var out []Signal

	if containsAnyFolded(expr, pythonInternals) {
		out = append(out, SignalPythonInternals)
	}
	if containsAnyFolded(expr, jvmAccess) || hasJVMTypeCall(expr) {
		out = append(out, SignalJVMClassAccess)
	}
	if containsAnyFolded(expr, rubyExecution) || hasBacktickCommand(expr) {
		out = append(out, SignalRubyExecution)
	}
	if containsAnyFolded(expr, directiveExecution) {
		out = append(out, SignalDirectiveExecution)
	}
	// An app object counts only when something is done with it. "{{ config }}"
	// renders a value; "{{ config.items() }}" walks into the interpreter, and
	// the difference is the access that follows the name.
	if hasAppObjectAccess(expr) {
		out = append(out, SignalAppObject)
	}
	if hasConstantArithmetic(expr) {
		out = append(out, SignalArithmeticProbe)
	}
	return out
}

// hasJVMTypeCall reports a Spring EL type reference: T(...).
func hasJVMTypeCall(expr []byte) bool {
	for i := 0; i+1 < len(expr); i++ {
		if (expr[i] == 'T' || expr[i] == 't') && expr[i+1] == '(' {
			// Preceded by an identifier byte it is part of a longer word.
			if i > 0 && isNameByte(expr[i-1]) {
				continue
			}
			return true
		}
	}
	return false
}

// hasBacktickCommand reports a backtick command substitution.
func hasBacktickCommand(expr []byte) bool {
	first := indexByte(expr, '`')
	return first >= 0 && indexByte(expr[first+1:], '`') >= 0
}

// hasAppObjectAccess reports a framework object followed by attribute access or
// a call, rather than merely named.
func hasAppObjectAccess(expr []byte) bool {
	for i := 0; i < len(expr); i++ {
		if i > 0 && isNameByte(expr[i-1]) {
			continue
		}
		for _, name := range appObjects {
			if !hasPrefixFolded(expr[i:], name) {
				continue
			}
			j := i + len(name)
			for j < len(expr) && isSpace(expr[j]) {
				j++
			}
			if j < len(expr) && (expr[j] == '.' || expr[j] == '[' || expr[j] == '(') {
				return true
			}
		}
	}
	return false
}

// hasConstantArithmetic reports arithmetic between two literal numbers, which
// is how a tester confirms a template is evaluated at all.
func hasConstantArithmetic(expr []byte) bool {
	for i := 0; i < len(expr); i++ {
		if !isDigit(expr[i]) {
			continue
		}
		if i > 0 && (isNameByte(expr[i-1]) || expr[i-1] == '.') {
			continue
		}
		j := i
		for j < len(expr) && isDigit(expr[j]) {
			j++
		}
		k := j
		for k < len(expr) && isSpace(expr[k]) {
			k++
		}
		if k >= len(expr) {
			return false
		}
		switch expr[k] {
		case '*', '+', '-', '/':
		default:
			i = j - 1
			continue
		}
		k++
		for k < len(expr) && isSpace(expr[k]) {
			k++
		}
		if k < len(expr) && isDigit(expr[k]) {
			return true
		}
		i = j - 1
	}
	return false
}

// ---- byte helpers -----------------------------------------------------------

func fold(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func isNameByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func hasPrefix(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	for i := range len(s) {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}

func hasPrefixFolded(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	for i := range len(s) {
		if fold(b[i]) != s[i] {
			return false
		}
	}
	return true
}

func containsAnyFolded(b []byte, subs []string) bool {
	for _, s := range subs {
		for i := 0; i+len(s) <= len(b); i++ {
			if hasPrefixFolded(b[i:], s) {
				return true
			}
		}
	}
	return false
}

func indexFrom(b []byte, from int, s string) int {
	for i := from; i+len(s) <= len(b); i++ {
		if hasPrefix(b[i:], s) {
			return i
		}
	}
	return -1
}

// ---- operator ---------------------------------------------------------------

// Operator adapts the detector to the rule engine, so it is prefiltered,
// metered, and reported like every other rule.
func Operator() rules.Operator { return &operator{d: New()} }

type operator struct{ d *Detector }

func (o *operator) Name() string { return "detect_ssti" }

func (o *operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	v := o.d.Analyze(value)
	if !v.Detected() {
		return rules.Match{}, false
	}
	return rules.Match{Span: v.Span}, true
}

// Literals are the byte sequences without which no scoring signal can fire.
//
// Every signal needs a template delimiter to be inside one, so the delimiters
// alone are sufficient and are far more selective than the payload vocabulary.
// FuzzLiteralsAreExhaustive enforces that this remains true.
func (o *operator) Literals() ([]string, bool) {
	out := make([]string, 0, len(delimiters))
	for _, d := range delimiters {
		out = append(out, d.open)
	}
	return out, true
}

// Cost prices one analysis: a scan with per-expression substring checks.
func (o *operator) Cost() types.Fuel { return types.CostLiteralMatch * 6 }
