// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

// SQLSinkRule reports a whole SQL statement arriving in a parameter the
// application hands to a database.
//
// # Why the semantic detector does not catch these
//
// It looks for *injection* — a value that starts as data and becomes SQL
// partway through, by breaking a quote or attaching a connector. A parameter
// whose entire value is a valid statement never breaks anything:
//
//	sql=select 547653*865674 as id
//	{"sql":"SELECT * FROM users"}
//	<string>select user()</string>
//
// There is nothing to attach to and no quote to escape, so every grammar signal
// the detector reads is legitimately absent. That is the same distinction
// detect/shelli draws when it declines to read a value that is a command line
// from its first byte: a stored command is not an injected one, and treating
// them alike blocks every CI configuration in existence.
//
// # Why this is opt-in
//
// Because the request cannot tell the two apart, and the corpus proves it. The
// benign set carries
//
//	{"name":"Q1","query":"select revenue where region = 'EU'"}
//
// described as "a report DSL" — an application whose entire purpose is to
// accept a query someone wrote. Reporting tools, BI dashboards, database
// consoles and admin panels all do this by design, and for them a statement in
// a parameter is the product working.
//
// Whether *this* application hands user-supplied SQL to a database is something
// the embedder knows and gwaf cannot learn from one request. That is the
// Ownership test in CLAUDE.md §1, and it is the same reason SSRFParamRule ships
// exported rather than enabled.
//
// Enable it on an application that does not:
//
//	waf, err := gwaf.New(gwaf.WithRuleset(
//	    WithBodyPhase(rules.Set{core.SQLSinkRule(2011)}),
//	))
//
// WithBodyPhase because an opt-in rule gets no request-body counterpart of its
// own, and a JSON body is where this parameter usually arrives.
//
// # Why "query" is not in the list
//
// It is the name the benign case above uses, and it is the name a search box
// uses. The list is only the names that say "this is SQL" rather than "this is
// what the user asked for" — a distinction that costs a little coverage and
// buys the rule its false-positive rate.
func SQLSinkRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:    id,
		Phase: types.PhaseRequestHeaders,
		// Arguments only: the parameter name is half the evidence, so an
		// unkeyed collection can never match and evaluating it there is cost
		// with no possible finding.
		Targets: []types.Target{{Kind: types.TargetArgs}},
		// Deliberately not decodeChain. RemoveWhitespace welds "DROP TABLE
		// users" into "droptableusers", which destroys the word boundary this
		// rule depends on -- "select" followed by a letter is "selection", and
		// with the spaces gone every statement looks like one long identifier.
		// This chain is a prefix of decodeChain and already materialised for
		// rules 1013 and 3012 on this same target, so it costs nothing.
		Transforms: []rules.Transform{transform.URLDecode, transform.Lowercase},
		Op:         sqlSinkStatement(),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.High,
		Msg:        "SQL statement in a database parameter",
		Tags:       []string{"sqli", "owasp-a03", "opt-in"},
	}
}

// sqlSinkParams are parameter names whose value reaches a database as SQL.
//
// Deliberately short. Every name here says "this value is SQL"; none of them is
// a word an ordinary form uses for something else. "query", "q", "search",
// "filter" and "where" are all absent for that reason — each is what a search
// box is called, and three of them appear in the benign corpus.
var sqlSinkParams = setOf(
	"sql", "sqlquery", "sql_query", "rawsql", "raw_sql", "sqlstring",
	"stmt", "statement", "sqlstatement", "sql_statement", "querysql",
)

// sqlStatementKeywords are the verbs a statement can begin with.
//
// Anchored at the start of the value rather than searched for, because the
// finding is "this value *is* a statement". A value that merely mentions a verb
// is prose, and a value that reaches one partway through is injection — which
// is detect/sqli's job and is already covered.
//
// The boundary after the verb is required and is why this rule keeps its
// whitespace: "selection" and "withdrawal" begin with a verb and are not
// statements, and the only thing separating them from "select *" and "with x"
// is the byte that follows.
var sqlStatementKeywords = []string{
	"select", "insert", "update", "delete", "drop", "create",
	"alter", "truncate", "copy", "with", "merge", "grant", "exec",
}

func sqlSinkStatement() rules.Operator { return sqlSinkOp{} }

type sqlSinkOp struct{}

func (sqlSinkOp) Name() string { return "sql_sink_statement" }

func (sqlSinkOp) Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool) {
	// Argument names are themselves a target, and a name is not a statement.
	if ctx == nil || ctx.Target.Kind == types.TargetArgNames {
		return rules.Match{}, false
	}
	if !matchesParam(ctx.Key, sqlSinkParams) {
		return rules.Match{}, false
	}
	// Leading whitespace and an opening parenthesis are skipped: "(select …"
	// is how a subquery-shaped value arrives and it is the same finding.
	i := 0
	for i < len(value) && (isSpaceByte(value[i]) || value[i] == '(') {
		i++
	}
	rest := value[i:]
	for _, kw := range sqlStatementKeywords {
		if len(rest) < len(kw) || !equalFoldASCII(rest[:len(kw)], kw) {
			continue
		}
		// A word boundary after the verb. Without it "selection" and
		// "withdrawal" are statements.
		if len(rest) > len(kw) && isWordish(rest[len(kw)]) {
			continue
		}
		return rules.WholeValue(value), true
	}
	return rules.Match{}, false
}

// Literals is an honest assertion: the value has to begin with one of the
// statement verbs, so a value containing none of them cannot match. The
// trailing separator is dropped here because the prefilter matches substrings
// and the verb alone is what has to be present.
func (sqlSinkOp) Literals() ([]string, bool) {
	return []string{
		"select", "insert", "update", "delete", "drop", "create",
		"alter", "truncate", "copy", "with", "merge", "grant", "exec",
	}, true
}

func (sqlSinkOp) Cost() types.Fuel { return types.CostLiteralMatch }

// equalFoldASCII compares two byte slices case-insensitively for ASCII.
func equalFoldASCII(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		c := a[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != b[i] {
			return false
		}
	}
	return true
}

// isWordish reports whether c continues an identifier, so a verb followed by
// one is part of a longer word rather than a statement.
func isWordish(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '_'
}
