// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package sqli detects SQL injection by parsing structure rather than matching
// strings.
//
// # Why not signatures
//
// A signature engine asks "does this input contain UNION SELECT?". That
// question has two failure modes and an attacker gets to pick either.
//
// It misses variants, because the payload space is unbounded while the
// signature list is not: "UNION/**/SELECT", "UnIoN SeLeCt", "UNION%0aSELECT",
// "/*!50000UNION*/SELECT". Each evasion needs a new signature, and the list
// only ever grows.
//
// It fires on prose, because English contains SQL keywords. "The union
// selected a new representative" contains "union select" once whitespace is
// normalized, and a signature cannot tell that apart from an attack. That false
// positive is worse than the miss: it gets the firewall switched off.
//
// # What this does instead
//
// The value is tokenized as SQL and scored on *grammar*. A payload is not
// recognised by the words it uses but by the shape it makes: a boolean
// connector joined to a comparison between two constants, a statement separator
// followed by a data-modifying keyword, a comment that truncates whatever
// follows. Prose containing the same words makes none of those shapes.
//
// # Quote breaking
//
// Injected input usually lands inside a quoted literal, so the payload's first
// job is to close it. Read literally, "1' OR 1=1--" is a number followed by an
// unterminated string — odd, not obviously hostile. Read as if interpolated
// inside '...', the quote *closes* the literal and the rest is a tautology plus
// a comment that discards the rest of the query.
//
// gwaf does not know which reading the origin will produce, so every value is
// tokenized under all three contexts and the strongest verdict wins. This is
// the same reasoning as the multi-interpretation decoding in
// internal/interpret, one layer up: never guess when you can evaluate.
package sqli

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Signal is one piece of structural evidence.
type Signal uint16

// Signals, roughly ordered by how much they mean on their own.
const (
	// SignalTautology is a comparison between two literals — "1=1", "'a'='a'".
	// Real queries do not compare two constants; there is no reason to write it
	// except to force a WHERE clause true.
	SignalTautology Signal = 1 << iota

	// SignalBooleanInjection is a boolean connector immediately joined to a
	// tautology: the shape that attaches an always-true condition to an
	// existing WHERE clause.
	SignalBooleanInjection

	// SignalUnionSelect is UNION followed by SELECT, optionally through ALL or
	// DISTINCT — the shape of appending a second result set. Crucially this
	// requires *adjacency in the token stream*, which is what "the union
	// selected a leader" does not have.
	SignalUnionSelect

	// SignalStackedQuery is a statement separator followed by a data-modifying
	// keyword.
	SignalStackedQuery

	// SignalDangerFunction is a call to a function whose only purpose in
	// injected input is to prove execution or exfiltrate.
	SignalDangerFunction

	// SignalCommentTerminator is a trailing comment, used to discard the rest
	// of the original query. Weak alone — inline comments appear in real text —
	// and strong corroboration alongside anything else.
	SignalCommentTerminator

	// SignalQuoteBreak means the value only parses as SQL when read as escaping
	// a quoted literal. Weak alone, since ordinary text contains apostrophes.
	SignalQuoteBreak

	// SignalCommentSplit is an inline comment between two keywords —
	// "UNION/**/SELECT" — which exists only to defeat string matching.
	SignalCommentSplit

	// SignalTerminatedQuoteBreak is the auth-bypass tail: a value that escapes
	// its quoted literal and then comments away everything the origin query
	// would have appended, with nothing in between — "1'--", "admin'--", "x'#".
	//
	// Quote-break and comment-terminator are each weak alone for good reason:
	// apostrophes and trailing dashes both occur in prose. Their *adjacency*,
	// with the comment running to the end of the value, is not prose. "don't
	// -- see below" has words between the two and does not qualify; "1'--" has
	// nothing between them, and closing a literal only to discard the rest of
	// the statement has no meaning except against a query.
	SignalTerminatedQuoteBreak
)

// String implements fmt.Stringer, so a decision can say what it saw.
func (s Signal) String() string {
	var out []byte
	add := func(n string) {
		if len(out) > 0 {
			out = append(out, '+')
		}
		out = append(out, n...)
	}
	if s&SignalTautology != 0 {
		add("tautology")
	}
	if s&SignalBooleanInjection != 0 {
		add("boolean_injection")
	}
	if s&SignalUnionSelect != 0 {
		add("union_select")
	}
	if s&SignalStackedQuery != 0 {
		add("stacked_query")
	}
	if s&SignalDangerFunction != 0 {
		add("danger_function")
	}
	if s&SignalCommentTerminator != 0 {
		add("comment_terminator")
	}
	if s&SignalQuoteBreak != 0 {
		add("quote_break")
	}
	if s&SignalCommentSplit != 0 {
		add("comment_split")
	}
	if s&SignalTerminatedQuoteBreak != 0 {
		add("terminated_quote_break")
	}
	if len(out) == 0 {
		return "none"
	}
	return string(out)
}

// weights price each signal by how much it means on its own.
//
// The threshold is 5, so any signal weighted 5 is sufficient alone and anything
// less needs corroboration. The weak signals are weak on purpose: a trailing
// comment or an apostrophe is ordinary in real text, and pricing them to fire
// alone is how a detector starts blocking bug reports.
func weightOf(s Signal) int {
	switch s {
	case SignalUnionSelect, SignalStackedQuery, SignalDangerFunction,
		SignalBooleanInjection, SignalTerminatedQuoteBreak:
		return 5
	case SignalCommentSplit:
		return 4
	case SignalTautology:
		return 3
	case SignalCommentTerminator:
		return 2
	case SignalQuoteBreak:
		return 1
	default:
		return 0
	}
}

// commentBodyEmpty reports whether a comment token carries nothing after its
// marker but whitespace.
//
// The tokenizer gives a line comment everything from the marker to the end of
// input, so the body is what distinguishes a truncation ("--") from an
// expression that merely contains a '#' ("#main').addClass('active')").
func commentBodyEmpty(text []byte) bool {
	body := text
	switch {
	case len(body) >= 2 && body[0] == '-' && body[1] == '-':
		body = body[2:]
	case len(body) >= 1 && body[0] == '#':
		body = body[1:]
	case len(body) >= 2 && body[0] == '/' && body[1] == '*':
		body = body[2:]
		// An unterminated /* consumed the rest; a terminated one ends in */.
		if n := len(body); n >= 2 && body[n-2] == '*' && body[n-1] == '/' {
			body = body[:n-2]
		}
	default:
		return false
	}
	for _, c := range body {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}

// Threshold is the score at or above which a value is reported as injection.
const Threshold = 5

// Verdict is the result of analysing one value.
type Verdict struct {
	Signals Signal
	Score   int
	Context string
	Span    types.Span
}

// Detected reports whether the evidence reached the threshold.
func (v Verdict) Detected() bool { return v.Score >= Threshold }

// Detector analyses values for SQL injection.
//
// A Detector is immutable and safe for concurrent use; the token buffer lives
// on the stack of each Analyze call, so there is no shared scratch to race on.
type Detector struct{}

// New returns a Detector.
func New() *Detector { return &Detector{} }

// Name implements the operator contract.
func (*Detector) Name() string { return "detect_sqli" }

// Analyze scores value under every interpolation context and returns the
// strongest verdict.
func (d *Detector) Analyze(value []byte) Verdict {
	if len(value) == 0 {
		return Verdict{}
	}

	// The token buffer is a local array so Analyze allocates nothing and needs
	// no shared state, which is what keeps the Detector concurrency-safe.
	var buf [maxTokens]token

	// A quoted context can only apply if the corresponding quote is present:
	// there is nothing to break out of otherwise. Checking first turns the
	// common case -- a value with no quotes, or a JSON body with only double
	// quotes -- from four tokenization passes into one or two. The scan is one
	// pass over the value and saves up to three.
	var single, double, backtick bool
	for _, c := range value {
		switch c {
		case '\'':
			single = true
		case '"':
			double = true
		case '`':
			backtick = true
		}
	}

	var best Verdict
	for ctx := context(0); ctx < contextCount; ctx++ {
		switch ctx {
		case ctxSingle:
			if !single {
				continue
			}
		case ctxDouble:
			if !double {
				continue
			}
		case ctxBacktick:
			if !backtick {
				continue
			}
		}

		toks := tokenize(buf[:0], value, ctx)
		if len(toks) == 0 {
			continue
		}
		v := score(toks, ctx, len(value))
		if v.Score > best.Score {
			best = v
		}
	}
	return best
}

// score walks a token stream and accumulates structural evidence.
func score(toks []token, ctx context, valueLen int) Verdict {
	var sigs Signal

	// Breaking out of a quoted literal is only meaningful under a quoted
	// context, and only when something followed the quote.
	if ctx != ctxNone && len(toks) > 0 {
		sigs |= SignalQuoteBreak
	}

	for i := 0; i < len(toks); i++ {
		t := toks[i]

		switch t.kind {
		case tkKeyword:
			w := lowerWord(t.text)

			// UNION [ALL|DISTINCT] SELECT, skipping comments — an inline
			// comment between the two is itself evidence, since its only
			// purpose there is to break up the pair for a string matcher.
			if w == "union" {
				j, split := skipNoise(toks, i+1)
				if j < len(toks) && toks[j].kind == tkKeyword {
					kw := lowerWord(toks[j].text)
					if kw == "all" || kw == "distinct" {
						j2, s2 := skipNoise(toks, j+1)
						j, split = j2, split || s2
					}
				}
				if j < len(toks) && toks[j].kind == tkKeyword &&
					lowerWord(toks[j].text) == "select" {
					sigs |= SignalUnionSelect
					if split {
						sigs |= SignalCommentSplit
					}
				}
			}

			// A function call to something that proves execution, but only
			// when it is attached to surrounding SQL. An isolated call is a
			// code snippet someone pasted into a text field; one joined to a
			// boolean connector, a keyword, or a statement separator is a
			// payload. Requiring attachment is what keeps "sleep(8h) is the
			// recommendation" out of the results.
			if (i+1 < len(toks) && toks[i+1].kind == tkLParen &&
				isDangerCall(w, toks, i)) || isPackagedDangerCall(toks, i) {
				sigs |= SignalDangerFunction
			}
			// WAITFOR DELAY has no parentheses.
			if w == "waitfor" {
				if j, _ := skipNoise(toks, i+1); j < len(toks) &&
					toks[j].kind == tkKeyword && lowerWord(toks[j].text) == "delay" {
					sigs |= SignalDangerFunction
				}
			}
			_ = w

		case tkIdent:
			// Danger functions are not all keywords; a bare identifier
			// immediately followed by "(" is a call.
			if (i+1 < len(toks) && toks[i+1].kind == tkLParen &&
				isDangerCall(lowerWord(t.text), toks, i)) || isPackagedDangerCall(toks, i) {
				sigs |= SignalDangerFunction
			}

		case tkSemi:
			// A statement separator followed by something that modifies data.
			if j, _ := skipNoise(toks, i+1); j < len(toks) &&
				toks[j].kind == tkKeyword && dmlKeywords[lowerWord(toks[j].text)] {
				sigs |= SignalStackedQuery
			}

		case tkComment:
			// A comment that runs to the end of the value truncates whatever
			// the origin would have appended.
			if t.off+len(t.text) >= valueLen {
				sigs |= SignalCommentTerminator

				// The auth-bypass tail. Under a quoted context the value has
				// already escaped its literal; if the terminating comment is
				// the first token after that break *and carries no body*, the
				// whole payload is "close the string, discard the rest" and
				// nothing else.
				//
				// The empty-body requirement is what separates this from real
				// text. A jQuery selector like $('#main').addClass('active')
				// also breaks a quote and also runs a '#' comment to the end of
				// the value — but that comment has a body, because the rest of
				// the expression is inside it. An attacker appending "--" to
				// truncate a query has nothing left to say.
				if ctx != ctxNone && i == 0 && commentBodyEmpty(t.text) {
					sigs |= SignalTerminatedQuoteBreak
				}
			}

		case tkLogic:
			// The characteristic shape: a boolean connector joined to a
			// comparison between two constants.
			if j, split := skipNoise(toks, i+1); isTautology(toks, j) {
				sigs |= SignalBooleanInjection | SignalTautology
				if split {
					sigs |= SignalCommentSplit
				}
			}
		}

		// A bare tautology anywhere, even without a connector.
		if isTautology(toks, i) {
			sigs |= SignalTautology
		}
	}

	total := 0
	for bit := Signal(1); bit != 0; bit <<= 1 {
		if sigs&bit != 0 {
			total += weightOf(bit)
		}
	}

	return Verdict{
		Signals: sigs,
		Score:   total,
		Context: contextName(ctx),
		Span:    types.SpanOf(0, valueLen),
	}
}

// isTautology reports whether the tokens at i form a comparison between two
// literals.
//
// Comparing two constants is meaningless in a real query — the value is known
// at parse time — so the construct exists only to force a condition. Requiring
// *both* sides to be literals is what keeps this off ordinary input: "price =
// 100" compares a column to a constant and does not match.
func isTautology(toks []token, i int) bool {
	l, j := literalAt(toks, i)
	if !l {
		return false
	}
	j, _ = skipNoise(toks, j)
	if j >= len(toks) || !isComparison(toks[j]) {
		return false
	}
	j, _ = skipNoise(toks, j+1)
	r, _ := literalAt(toks, j)
	return r
}

// literalAt reports whether a literal starts at i, and where it ends.
func literalAt(toks []token, i int) (bool, int) {
	if i >= len(toks) {
		return false, i
	}
	switch toks[i].kind {
	case tkNumber, tkString:
		return true, i + 1
	case tkUnterminated:
		// A quote the value never closes is still a literal operand: the
		// origin's parser closes it with the trailing quote of the query the
		// payload was injected into. That is precisely the shape of
		// "' OR 'a'='a" -- the final literal is only unterminated from gwaf's
		// point of view, not from the database's.
		return true, i + 1
	case tkKeyword:
		// NULL is a literal for comparison purposes.
		if lowerWord(toks[i].text) == "null" {
			return true, i + 1
		}
	}
	return false, i
}

// isComparison reports whether a token is a comparison operator, or LIKE.
func isComparison(t token) bool {
	if t.kind == tkKeyword && lowerWord(t.text) == "like" {
		return true
	}
	if t.kind != tkOperator {
		return false
	}
	switch string(t.text) {
	case "=", "==", "<", ">", "<=", ">=", "<>", "!=", "<=>":
		return true
	}
	return false
}

// attachedToSQL reports whether the token at i is joined to surrounding SQL
// rather than standing alone.
//
// A function call on its own is ordinary text — a code sample, a config line, a
// sentence about sleep. The same call preceded by a boolean connector, a
// keyword, or a statement separator is part of an expression someone is
// building, which is the difference between a paste and a payload.
func attachedToSQL(toks []token, i int) bool {
	for j := i - 1; j >= 0; j-- {
		switch toks[j].kind {
		case tkComment:
			continue // whitespace to a parser; keep looking
		case tkOperator:
			// An "=" that assigns a query-string parameter is not SQL context.
			//
			// The detector reads REQUEST_URI as well as the decoded arguments,
			// and in a URI every value is preceded by "name=" — so "?q=sleep(8h)
			// is the recommendation" looked attached to an operator and scored,
			// while the identical text as an argument value did not. A pentest
			// benign control caught it; the corpus had never carried the shape.
			//
			// A parameter assignment is recognised by what precedes the name: the
			// "?" that opens a query string or the "&" that separates one.
			if isQueryAssignment(toks, j) {
				return false
			}
			return true
		case tkLogic, tkKeyword, tkSemi, tkComma, tkLParen:
			return true
		default:
			return false
		}
	}
	return false
}

// isQueryAssignment reports whether the operator at toks[j] is the "=" of a
// query-string parameter rather than a SQL operator.
//
// The shape is "?name=" or "&name=": an "=", an identifier before it, and a
// query separator before that. Requiring all three is what keeps a real
// comparison — "id=1 AND sleep(5)" — attached, because there the "=" is
// followed by SQL rather than opening the value.
func isQueryAssignment(toks []token, j int) bool {
	if len(toks[j].text) != 1 || toks[j].text[0] != '=' {
		return false
	}
	if j == 0 {
		return false
	}
	name := j - 1
	if toks[name].kind != tkIdent && toks[name].kind != tkKeyword {
		return false
	}
	if name == 0 {
		// "name=value" with nothing before it: the whole value is a parameter
		// assignment, which is how a form body arrives.
		return true
	}
	sep := toks[name-1]
	if sep.kind == tkOperator && len(sep.text) == 1 &&
		(sep.text[0] == '&' || sep.text[0] == '?') {
		return true
	}
	// "?" may not be an operator token; accept any single-byte separator.
	return len(sep.text) == 1 && (sep.text[0] == '?' || sep.text[0] == '&')
}

// skipNoise advances past comment tokens, reporting whether any were skipped.
//
// A comment between two keywords is whitespace to a SQL parser, which is
// precisely why it is used to split them for a string matcher. Skipping them
// makes the grammar visible again; reporting that they were there records the
// evasion attempt.
func skipNoise(toks []token, i int) (int, bool) {
	skipped := false
	for i < len(toks) && toks[i].kind == tkComment {
		skipped = true
		i++
	}
	return i, skipped
}

func contextName(c context) string {
	switch c {
	case ctxSingle:
		return "single_quote"
	case ctxDouble:
		return "double_quote"
	default:
		return "bare"
	}
}

// Operator adapts the detector to the rule engine.
//
// A semantic detector is an operator, not a separate evaluation tier. That
// keeps it inside the machinery that already exists: it is prefiltered by its
// required literals, metered by the same fuel budget, and reported by the same
// compile report as every other rule.
func Operator() rules.Operator { return &operator{d: New()} }

type operator struct{ d *Detector }

func (o *operator) Name() string { return "detect_sqli" }

func (o *operator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	v := o.d.Analyze(value)
	if !v.Detected() {
		return rules.Match{}, false
	}
	return rules.Match{Span: v.Span}, true
}

// Literals are the byte sequences without which no signal can fire.
//
// This is an assertion the prefilter relies on, so it is derived from the
// signals rather than guessed. Every signal needs at least one of these
// present:
//
//   - tautology and boolean injection need a comparison operator or LIKE
//   - union/select and stacked queries need those keywords or a separator
//   - danger functions need their own name
//   - comment signals need a comment marker
//   - quote breaking needs a quote
//
// Deliberately absent: "or" and "and". They appear in most English prose, so
// including them would make nearly every text value a candidate for no gain —
// a boolean injection also requires a comparison operator, which is listed.
func (o *operator) Literals() ([]string, bool) {
	return []string{
		"=", "<", ">", "like",
		"'", "\"", "`",
		"--", "#", "/*",
		";",
		"union", "select", "insert", "update", "delete", "drop",
		"sleep", "benchmark", "load_file", "pg_sleep", "waitfor",
		"extractvalue", "updatexml", "xp_cmdshell",
		"||",
	}, true
}

// Cost prices one analysis. Tokenization runs three times over the value, so
// this is higher than a literal match and lower than a regex.
func (o *operator) Cost() types.Fuel { return types.CostLiteralMatch * 6 }

// isDangerCall reports whether a call to name at toks[i] is a danger function.
//
// Two tiers, and the difference between them is the whole point.
//
// A name in osAccessFuncs reaches outside the database — the filesystem, a
// command, the network, the engine's build configuration — and fires wherever it
// appears. It needs no attachment to surrounding SQL because the attacker often
// supplies no surrounding SQL: when the whole parameter value is
// "lo_import('/etc'||'/pass'||'wd')", the query around it belongs to the origin,
// and there is no boolean connector to attach to. Nothing legitimate sends
// "pg_read_file(" as a parameter, so the name alone carries the verdict.
//
// A name in dangerFuncs is dangerous only in context. "substring", "char", and
// "sleep" are ordinary words and ordinary functions in other languages, so those
// still require attachment — which is what keeps "use substring(0,5)" and
// "sleep(8h) is the recommendation" out of the results.
func isDangerCall(name string, toks []token, i int) bool {
	if osAccessFuncs[name] {
		return true
	}
	return dangerFuncs[name] && attachedToSQL(toks, i)
}

// isPackagedDangerCall reports an Oracle-style "package.function(" call.
//
// Oracle's dangerous built-ins are packages, not bare functions:
// "utl_http.request(...)", "dbms_lock.sleep(...)", "utl_file.fopen(...)". The
// tokenizer sees the package name, a dot, and the member, so the package is
// never the token immediately before "(" and the plain check misses it. The
// package name alone carries the verdict for the same reason the bare names do:
// nothing legitimate sends "utl_http." in a parameter.
func isPackagedDangerCall(toks []token, i int) bool {
	if i+3 >= len(toks) {
		return false
	}
	if !osAccessFuncs[lowerWord(toks[i].text)] {
		return false
	}
	// package . member (
	return toks[i+1].kind == tkDot &&
		(toks[i+2].kind == tkIdent || toks[i+2].kind == tkKeyword) &&
		toks[i+3].kind == tkLParen
}
