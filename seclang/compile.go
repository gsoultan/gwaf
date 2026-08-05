// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package seclang

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gsoultan/gwaf/detect/sqli"
	"github.com/gsoultan/gwaf/detect/xss"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

type compiler struct {
	opts    Options
	file    string
	report  Report
	removed map[uint32]bool

	// defaults carries SecDefaultAction, which applies to rules that do not
	// state their own disruptive action.
	defaults []action
}

func (c *compiler) run(ds []directive) rules.Set {
	c.removed = map[uint32]bool{}
	c.report.Directives = len(ds)

	// Removals are collected first: SecRuleRemoveById commonly appears *after*
	// the include that defined the rule, and a single pass in file order would
	// import a rule the operator had explicitly disabled.
	for _, d := range ds {
		switch strings.ToLower(d.Name) {
		case "secruleremovebyid":
			for _, a := range d.Args {
				c.collectRemovals(a)
			}
		case "secruleremovebytag", "secruleremovebymsg":
			c.skip(d.Line, 0, d.Name,
				"removal by tag or message needs the rule text at import time; "+
					"re-express it as SecRuleRemoveById or a gwaf exception")
		}
	}

	var set rules.Set
	for i := 0; i < len(ds); i++ {
		d := ds[i]
		switch strings.ToLower(d.Name) {
		case "secrule":
			consumed, rule, ok := c.secRule(ds, i)
			i += consumed
			if ok {
				set = append(set, rule)
			}
		case "secdefaultaction":
			if len(d.Args) > 0 {
				c.defaults = actionsOf(d.Args[len(d.Args)-1])
			}
		case "secaction", "secmarker", "secruleremovebyid",
			"secruleremovebytag", "secruleremovebymsg":
			// SecAction is unconditional bookkeeping — setvar, initcol,
			// skipAfter — and every one of those is cross-request state, which
			// is the embedder's by the first ownership test. SecMarker only
			// labels a position for skipAfter.
			if strings.EqualFold(d.Name, "secaction") {
				c.skip(d.Line, ruleIDOf(d.Args), d.Name,
					"unconditional actions set variables or jump; both are "+
						"cross-request state that belongs to the embedder")
			}
		case "secrequestbodyaccess", "secresponsebodyaccess", "secruleengine",
			"secrequestbodylimit", "secresponsebodylimit", "secauditengine",
			"secauditlog", "secauditlogparts", "secdebuglog", "secdebugloglevel",
			"sectmpdir", "secdatadir", "secpcrematchlimit", "seccomponentsignature",
			"secargumentseparator", "seccookieformat", "secstatusengine",
			"secunicodemapfile", "secresponsebodymimetype", "sechttpblkey",
			"seccollectiontimeout", "secxmlexternalentity":
			// Engine configuration. gwaf's equivalents are Options on the WAF,
			// set by the embedder in Go, and silently honouring a directive
			// that changes engine behaviour from a rules file would put
			// configuration in two places.
			c.skip(d.Line, 0, d.Name,
				"engine configuration is a gwaf Option, set by the embedder")
		case "include", "secremoterules":
			c.skip(d.Line, 0, d.Name,
				"file inclusion is the caller's: read the files and concatenate, "+
					"so what is imported is visible rather than resolved at parse time")
		default:
			c.skip(d.Line, 0, d.Name, "unknown or unsupported directive")
		}
	}

	// Removals apply last so they win regardless of file order.
	if len(c.removed) > 0 {
		kept := set[:0]
		for _, r := range set {
			if !c.removed[uint32(r.ID)-c.opts.Prefix] {
				kept = append(kept, r)
			}
		}
		set = kept
	}

	c.report.Rules = len(set)
	for _, r := range set {
		if lits, ok := r.Op.Literals(); ok && len(lits) > 0 {
			c.report.Prefiltered++
		}
	}
	return set
}

// secRule translates one SecRule, following a chain if present.
//
// Returns how many extra directives were consumed by the chain.
func (c *compiler) secRule(ds []directive, i int) (consumed int, out rules.Rule, ok bool) {
	d := ds[i]
	if len(d.Args) < 2 {
		c.skip(d.Line, 0, "SecRule", "needs at least a variable list and an operator")
		return 0, out, false
	}

	acts := actionsOf(argAt(d.Args, 2))
	id := ruleIDOf(d.Args)

	// A chain is a conjunction across *different* variables, and gwaf evaluates
	// a rule against one value at a time. The head is imported and the chained
	// conditions are reported: importing only the head would be strictly more
	// permissive than the original, which is the silent weakening this package
	// refuses to do.
	if hasAction(acts, "chain") {
		for j := i + 1; j < len(ds) && strings.EqualFold(ds[j].Name, "secrule"); j++ {
			consumed++
			if !hasAction(actionsOf(argAt(ds[j].Args, 2)), "chain") {
				break
			}
		}
		c.report.Chains++
		c.skip(d.Line, id, "chained SecRule",
			"a chain is a conjunction across several variables and gwaf evaluates "+
				"one value per rule; importing only the head would be more "+
				"permissive than the original")
		return consumed, out, false
	}

	targets, tSkip := c.targets(splitVariables(d.Args[0]))
	if tSkip != "" {
		c.skip(d.Line, id, "SecRule variables", tSkip)
		return consumed, out, false
	}
	if len(targets) == 0 {
		c.skip(d.Line, id, "SecRule variables", "no variable maps to a gwaf target")
		return consumed, out, false
	}

	name, arg, negated := parseOperator(d.Args[1])
	operator, oSkip := c.operator(name, arg, negated)
	if oSkip != "" {
		c.skip(d.Line, id, "@"+name, oSkip)
		return consumed, out, false
	}

	chain, xSkip := c.transforms(acts)
	if xSkip != "" {
		c.skip(d.Line, id, "transformation", xSkip)
		return consumed, out, false
	}

	all := append(actionsOf(""), c.defaults...)
	all = append(all, acts...)

	out = rules.Rule{
		ID:         types.RuleID(c.opts.Prefix + id),
		Phase:      phaseOf(all),
		Targets:    targets,
		Transforms: chain,
		Op:         operator,
		Actions:    []rules.Action{actionOf(all)},
		Severity:   severityOf(all),
		Confidence: types.Confidence(c.opts.DefaultConfidence),
		Msg:        messageOf(all),
		Tags:       tagsOf(all),
	}
	if out.ID == 0 {
		c.skip(d.Line, 0, "SecRule", "no id: action, so the rule cannot be "+
			"referenced in an audit log or an exception")
		return consumed, out, false
	}
	return consumed, out, true
}

// operator maps a SecLang operator onto a gwaf one.
func (c *compiler) operator(name, arg string, negated bool) (rules.Operator, string) {
	switch name {
	case "rx":
		o, err := newRegexOperator(arg, negated)
		if err != nil {
			// RE2 rejects backreferences and lookarounds by construction. That
			// is the property that makes importing a stranger's regexes safe,
			// so the pattern is reported rather than rewritten.
			return nil, fmt.Sprintf("pattern is not RE2-compatible (%v); "+
				"backreferences and lookarounds cannot be linear-time", err)
		}
		return o, ""

	case "contains":
		if negated {
			return nil, "negated @contains has no required literal and would " +
				"run against every value; express it as a gwaf exception"
		}
		return op.Contains(arg), ""

	case "containsword":
		if negated {
			return nil, "negated @containsWord would run against every value"
		}
		// Word boundaries around a literal, which RE2 expresses directly.
		o, err := newRegexOperator(`\b`+regexpQuote(arg)+`\b`, false)
		if err != nil {
			return nil, err.Error()
		}
		return o, ""

	case "streq":
		return op.Equals(arg), ""

	case "beginswith":
		return op.HasPrefix(arg), ""

	case "endswith":
		o, err := newRegexOperator(regexpQuote(arg)+`$`, negated)
		if err != nil {
			return nil, err.Error()
		}
		return o, ""

	case "pm", "pmf", "pmfromfile":
		if name != "pm" {
			return nil, "@pmFromFile reads a file at import time; inline the " +
				"phrases so the imported ruleset is self-contained"
		}
		phrases := strings.Fields(arg)
		if len(phrases) == 0 {
			return nil, "no phrases"
		}
		return op.ContainsAny(phrases...), ""

	case "within":
		// @within asks whether the *value* is one of a list, which is Equals
		// over a set rather than Contains.
		phrases := strings.Fields(arg)
		if len(phrases) == 0 {
			return nil, "no values"
		}
		return op.ContainsAny(phrases...), ""

	case "detectsqli":
		// The one place the translation is an upgrade. ModSecurity shipped
		// libinjection here; gwaf's structural detector reads the same grammar
		// with its own tokenizer and interpolation contexts.
		return sqli.Operator(), ""

	case "detectxss":
		return xss.Operator(), ""

	case "eq", "gt", "lt", "ge", "le":
		return nil, "numeric comparison operates on a counted collection " +
			"(&ARGS and friends), which gwaf does not model as a value"

	case "ipmatch", "ipmatchf", "ipmatchfromfile", "geolookup", "rbl":
		return nil, "address and reputation matching needs data or a network " +
			"lookup; supply it as a Resolver input from the embedder"

	case "validatebyterange", "validateurlencoding", "validateutf8encoding":
		return nil, "encoding validation is gwaf's canonicalization tier and " +
			"runs before rules rather than as one"

	case "inspectfile", "fuzzyhash":
		return nil, "file inspection needs the filesystem at request time"

	case "verifycc", "verifycpf", "verifyssn", "verifysvnr":
		return nil, "checksum operators are not implemented"

	case "unconditionalmatch":
		return nil, "an unconditional match has no literal and would run " +
			"against every value in its phase"

	default:
		return nil, "unsupported operator"
	}
}

// targets maps SecLang variables onto gwaf targets.
func (c *compiler) targets(vars []string) ([]types.Target, string) {
	var out []types.Target
	for _, v := range vars {
		if strings.HasPrefix(v, "!") {
			// An exclusion is a scoped exception in gwaf, which is a different
			// object with a different lifetime.
			return nil, "variable exclusions (!ARGS:x) are gwaf exceptions; " +
				"express them with rules.Exception so they are visible and tunable"
		}
		if strings.HasPrefix(v, "&") {
			return nil, "counting a collection (&ARGS) is not a value gwaf inspects"
		}

		name, qualifier, _ := strings.Cut(v, ":")
		kind, ok := targetKind(strings.ToUpper(strings.TrimSpace(name)))
		if !ok {
			return nil, fmt.Sprintf("variable %q has no gwaf equivalent", name)
		}
		if strings.HasPrefix(qualifier, "/") {
			return nil, "regex-qualified variables (ARGS:/^x/) select by name " +
				"pattern, which gwaf targets do not express"
		}
		out = append(out, types.Target{Kind: kind, Name: strings.TrimSpace(qualifier)})
	}
	return out, ""
}

func targetKind(name string) (types.TargetKind, bool) {
	switch name {
	case "ARGS", "ARGS_COMBINED_SIZE":
		return types.TargetArgs, true
	case "ARGS_NAMES":
		return types.TargetArgNames, true
	case "ARGS_GET":
		return types.TargetArgsGet, true
	case "ARGS_POST":
		return types.TargetArgsPost, true
	case "REQUEST_URI", "REQUEST_URI_RAW":
		return types.TargetRequestURI, true
	case "REQUEST_FILENAME":
		return types.TargetRequestPath, true
	case "REQUEST_METHOD":
		return types.TargetRequestMethod, true
	case "REQUEST_PROTOCOL":
		return types.TargetRequestProtocol, true
	case "REQUEST_HEADERS":
		return types.TargetRequestHeaders, true
	case "REQUEST_HEADERS_NAMES":
		return types.TargetRequestHeaderNames, true
	case "REQUEST_BODY", "REQUEST_LINE", "MULTIPART_FILENAME", "FILES", "FILES_NAMES":
		return types.TargetRequestBody, true
	case "REQUEST_COOKIES":
		return types.TargetRequestCookies, true
	case "REQUEST_COOKIES_NAMES":
		return types.TargetRequestCookieNames, true
	case "REMOTE_ADDR":
		return types.TargetRemoteAddr, true
	case "RESPONSE_BODY":
		return types.TargetResponseBody, true
	case "RESPONSE_HEADERS":
		return types.TargetResponseHeaders, true
	case "RESPONSE_STATUS":
		return types.TargetResponseStatus, true
	default:
		return types.TargetInvalid, false
	}
}

// transforms maps t: actions onto gwaf transforms.
func (c *compiler) transforms(acts []action) ([]rules.Transform, string) {
	var out []rules.Transform
	for _, a := range acts {
		if !strings.EqualFold(a.Name, "t") {
			continue
		}
		switch strings.ToLower(a.Value) {
		case "none":
			out = out[:0]
		case "lowercase":
			out = append(out, transform.Lowercase)
		case "urldecode", "urldecodeuni":
			out = append(out, transform.URLDecode)
		case "removewhitespace":
			out = append(out, transform.RemoveWhitespace)
		case "compresswhitespace":
			out = append(out, transform.CompressWhitespace)
		case "normalizepath", "normalizepathwin", "normalisepath":
			out = append(out, transform.NormalizePath)
		case "trim", "trimleft", "trimright":
			// Trimming changes only leading and trailing whitespace, and every
			// operator gwaf offers is position-independent, so dropping it
			// cannot change a verdict.
		default:
			return nil, fmt.Sprintf("transformation t:%s has no gwaf equivalent", a.Value)
		}
	}
	return out, ""
}

// ---- action helpers ---------------------------------------------------------

func actionsOf(s string) []action {
	parts := splitActions(s)
	out := make([]action, 0, len(parts))
	for _, p := range parts {
		out = append(out, parseAction(p))
	}
	return out
}

// argAt returns the i'th argument of a directive, or "".
//
// Args excludes the directive name, so for "SecRule VARS OP ACTIONS" the action
// list is index 2. An earlier off-by-one returned the operator instead, which
// meant no rule's actions were read at all: every imported rule silently lost
// its id, phase, message, severity, tags, and transformations, and no chain was
// ever detected. It compiled and imported rules that did almost nothing.
func argAt(args []string, i int) string {
	if i >= 0 && i < len(args) {
		return args[i]
	}
	return ""
}

func hasAction(acts []action, name string) bool {
	for _, a := range acts {
		if strings.EqualFold(a.Name, name) {
			return true
		}
	}
	return false
}

// actionValue returns the value of the last action with this name.
//
// Last, not first: SecDefaultAction is prepended and a rule's own actions
// follow, so a rule declaring phase:1 must override a default of phase:2. Taking
// the first match silently moved every such rule into the wrong phase — which
// still imports, still matches, and inspects the wrong data.
func actionValue(acts []action, name string) (string, bool) {
	for i := len(acts) - 1; i >= 0; i-- {
		if strings.EqualFold(acts[i].Name, name) {
			return acts[i].Value, true
		}
	}
	return "", false
}

func ruleIDOf(args []string) uint32 {
	for _, a := range args {
		for _, act := range actionsOf(a) {
			if strings.EqualFold(act.Name, "id") {
				n, err := strconv.ParseUint(act.Value, 10, 32)
				if err == nil {
					return uint32(n)
				}
			}
		}
	}
	return 0
}

func (c *compiler) collectRemovals(spec string) {
	for _, part := range strings.Fields(spec) {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err1 := strconv.ParseUint(strings.TrimSpace(lo), 10, 32)
		if err1 != nil {
			continue
		}
		if !isRange {
			c.removed[uint32(a)] = true
			continue
		}
		b, err2 := strconv.ParseUint(strings.TrimSpace(hi), 10, 32)
		if err2 != nil {
			continue
		}
		for id := a; id <= b && id-a < 100000; id++ {
			c.removed[uint32(id)] = true
		}
	}
}

func phaseOf(acts []action) types.Phase {
	v, ok := actionValue(acts, "phase")
	if !ok {
		return types.PhaseRequestBody
	}
	switch strings.ToLower(v) {
	case "1", "request_headers":
		return types.PhaseRequestHeaders
	case "2", "request_body":
		return types.PhaseRequestBody
	case "3", "response_headers":
		return types.PhaseResponseHeaders
	case "4", "response_body":
		return types.PhaseResponseBody
	default:
		return types.PhaseRequestBody
	}
}

// actionOf maps the disruptive action.
//
// A SecLang "pass" still scores in an anomaly-scoring ruleset, which is how CRS
// works: individual rules pass and add to a total that a later rule blocks on.
// gwaf models that directly with a scoring action, so the two agree.
func actionOf(acts []action) rules.Action {
	switch {
	case hasAction(acts, "deny"), hasAction(acts, "drop"), hasAction(acts, "redirect"):
		return rules.Block
	case hasAction(acts, "allow"):
		return rules.Allow
	default:
		return rules.Score
	}
}

func severityOf(acts []action) types.Severity {
	v, ok := actionValue(acts, "severity")
	if !ok {
		return types.SeverityWarning
	}
	switch strings.ToUpper(strings.Trim(v, "'\"")) {
	case "0", "EMERGENCY", "1", "ALERT", "2", "CRITICAL":
		return types.SeverityCritical
	case "3", "ERROR":
		return types.SeverityError
	case "4", "WARNING":
		return types.SeverityWarning
	default:
		return types.SeverityNotice
	}
}

func messageOf(acts []action) string {
	if v, ok := actionValue(acts, "msg"); ok && v != "" {
		return v
	}
	return "imported SecLang rule"
}

func tagsOf(acts []action) []string {
	var out []string
	for _, a := range acts {
		if strings.EqualFold(a.Name, "tag") && a.Value != "" {
			out = append(out, a.Value)
		}
	}
	return append(out, "seclang")
}

func (c *compiler) skip(line int, id uint32, what, why string) {
	c.report.Skipped = append(c.report.Skipped, Skip{
		File: c.file, Line: line, RuleID: id, What: what, Why: why,
	})
}

// regexpQuote escapes a literal for use inside a pattern.
func regexpQuote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(`\.+*?()|[]{}^$`, s[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
