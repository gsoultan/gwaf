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

	// paranoia is the level the rules currently being read belong to, and
	// endMarker is the SecMarker that closes that block.
	//
	// CRS expresses paranoia as *runtime control flow*: a rule tests
	// TX:DETECTION_PARANOIA_LEVEL and jumps past a block of rules when the
	// level is too low. gwaf expresses the same idea as a compile-time
	// confidence tier, so the gate is interpreted rather than translated —
	// reading it here is what lets an imported rule arrive at the tier CRS
	// intended instead of all of them arriving at one flat default.
	//
	// Two hundred of CRS's directives are these gates. Reporting them as
	// untranslatable was accurate and useless: they are not detection, and
	// gwaf already implements what they do.
	paranoia  int
	endMarker string
}

// paranoiaGate reports the level a TX:DETECTION_PARANOIA_LEVEL gate guards, and
// the marker it jumps to, for a directive of the shape
//
//	SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:942013,...,skipAfter:END-X"
//
// The "@lt N" form means "skip the block unless the level is at least N", so the
// rules that follow belong to paranoia level N.
func paranoiaGate(d directive) (level int, marker string, ok bool) {
	if len(d.Args) < 3 {
		return 0, "", false
	}
	v := strings.ToUpper(d.Args[0])
	if !strings.Contains(v, "TX:DETECTION_PARANOIA_LEVEL") &&
		!strings.Contains(v, "TX:BLOCKING_PARANOIA_LEVEL") {
		return 0, "", false
	}
	op := strings.TrimSpace(d.Args[1])
	if !strings.HasPrefix(strings.ToLower(op), "@lt ") {
		return 0, "", false
	}
	n, err := strconv.Atoi(strings.TrimSpace(op[4:]))
	if err != nil || n < 1 || n > 4 {
		return 0, "", false
	}
	for _, a := range d.Args[2:] {
		for _, part := range strings.Split(a, ",") {
			part = strings.TrimSpace(part)
			if rest, found := strings.CutPrefix(part, "skipAfter:"); found {
				return n, strings.Trim(rest, "'\""), true
			}
		}
	}
	return 0, "", false
}

func (c *compiler) run(ds []directive) rules.Set {
	c.removed = map[uint32]bool{}
	c.report.Directives = len(ds)

	// Removals are collected first: SecRuleRemoveById commonly appears *after*
	// the include that defined the rule, and a single pass in file order would
	// import a rule the operator had explicitly disabled.
	for _, d := range ds {
		c.file = d.File
		switch strings.ToLower(d.Name) {
		case "secruleremovebyid":
			for _, a := range d.Args {
				c.collectRemovals(a)
			}
		case "secruleremovebytag", "secruleremovebymsg":
			c.skip(d.Line, 0, d.Name,
				"removal by tag or message needs the rule text at import time; "+
					"re-express it as SecRuleRemoveById or a gwaf exception")

		case "secruleupdatetargetbyid":
			// Collected in the same pass as removals and for the same reason:
			// CRS puts these in REQUEST-999-COMMON-EXCEPTIONS-AFTER, which is
			// included last, so a single in-order pass sees them after the rules
			// they tune.
			//
			// All 55 in CRS 4.25 live in that file and all but one exclude a
			// cookie -- _ga, __gads, the analytics and ad cookies that are the
			// classic CRS false-positive source. Dropping them imported CRS's
			// detection without CRS's tuning.
			c.updateTarget(d.Line, d.Name, d.Args)
		}
	}

	var set rules.Set
	for i := 0; i < len(ds); i++ {
		d := ds[i]
		// Skips report the file the directive came from, not the whole input
		// list; the compiler walks directives in order so tracking it here is
		// enough to reach every c.skip below.
		c.file = d.File
		switch strings.ToLower(d.Name) {
		case "secrule":
			if lvl, marker, ok := paranoiaGate(ds[i]); ok {
				// Consumed as metadata, not translated. Everything up to the
				// marker belongs to this paranoia level.
				// Not counted again: report.Directives is the file's total,
				// set once before the loop.
				c.paranoia, c.endMarker = lvl, marker
				continue
			}
			consumed, rule, ok := c.secRule(ds, i)
			i += consumed
			if ok {
				set = append(set, rule)
			}
		case "secdefaultaction":
			if len(d.Args) > 0 {
				c.defaults = actionsOf(d.Args[len(d.Args)-1])
			}
		case "secmarker":
			// Closing the block a paranoia gate opened returns to PL1.
			if len(d.Args) > 0 && c.endMarker != "" &&
				strings.EqualFold(strings.Trim(d.Args[0], "'\""), c.endMarker) {
				c.paranoia, c.endMarker = 0, ""
			}
		case "secaction", "secruleremovebyid",
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

	targets, excl, tSkip := c.targets(splitVariables(d.Args[0]))
	if tSkip != "" {
		c.skip(d.Line, id, "SecRule variables", tSkip)
		return consumed, out, false
	}
	// Attached only once the rule is known to import. An exception for a rule
	// that was skipped suppresses nothing and reads, to whoever audits the
	// list later, as a hole somebody opened on purpose.
	for _, e := range excl {
		c.addException(rules.Exception{
			RuleID: types.RuleID(id),
			Target: e.Kind,
			Key:    e.Key,
			Note:   "SecLang !" + e.Key + " exclusion on rule " + strconv.FormatUint(uint64(id), 10),
		})
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
		Transforms: withArgDecoding(targets, chain),
		Op:         operator,
		Actions:    []rules.Action{actionOf(all)},
		Severity:   severityOf(all),
		Confidence: c.confidence(),
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

// withArgDecoding prepends URLDecode for the collections ModSecurity hands to a
// rule already decoded.
//
// This is the largest single fidelity defect the CRS regression suite found, and
// it is a difference in where decoding happens rather than whether it does.
// ModSecurity decodes the query string and the form body while *populating*
// ARGS, so by the time a rule runs "t:none" means "apply no further transforms"
// — the value is already decoded. gwaf keeps values raw and decodes per rule,
// which is what makes the transform chain a compile-time input rather than a
// fixed pipeline.
//
// Imported rules were therefore reading percent-encoded bytes their author never
// expected. CRS 932140 matched "for %variable in (set) do command" perfectly and
// never fired once, because what reached it was
// "for%20%25variable%20in%20%28set%29%20do%20command". 187 imported rules were
// silent on their own regression tests, and this is the common cause.
//
// Only the collections ModSecurity actually decodes get it. REQUEST_HEADERS and
// REQUEST_URI are raw there too, so decoding them here would invent a reading
// the original rule never had — and a rule looking for "%00" in a header would
// stop finding it.
func withArgDecoding(targets []types.Target, chain []rules.Transform) []rules.Transform {
	if !anyDecodedCollection(targets) {
		return chain
	}
	// A chain that already starts by decoding needs nothing: "t:urlDecode" on a
	// rule is the author asking for a *second* decode, and that is the
	// double-decoding reading, not this one.
	if len(chain) > 0 && chain[0].Name() == transform.URLDecode.Name() {
		return chain
	}
	return append([]rules.Transform{transform.URLDecode}, chain...)
}

// anyDecodedCollection reports whether a rule reads a collection ModSecurity
// populates with decoded values.
func anyDecodedCollection(targets []types.Target) bool {
	for _, t := range targets {
		switch t.Kind {
		case types.TargetArgs, types.TargetArgsGet, types.TargetArgsPost,
			types.TargetArgNames, types.TargetArgsJoined,
			types.TargetRequestCookies, types.TargetRequestCookieNames,
			types.TargetRequestBody, types.TargetFileNames:
			return true
		}
	}
	return false
}

// operator maps a SecLang operator onto a gwaf one.
func (c *compiler) operator(name, arg string, negated bool) (rules.Operator, string) {
	// A pattern bounded before it is compiled.
	//
	// Compiling a regex amplifies: a 1 MiB @rx argument built a program costing
	// 264 MiB, against the 55 MiB a whole Core Rule Set costs. RE2 already
	// refuses the classic program-size bombs -- "(a{1000}){1000}" and a
	// two-thousand-deep alternation are both rejected -- so what is left is
	// bulk, and bulk needs a ceiling rather than a cleverer engine.
	//
	// The bound is on the argument because that is what drives the cost. A
	// limit on total source misses this entirely: one megabyte of input is
	// nothing, and one megabyte in a single pattern is a quarter of a gigabyte.
	//
	// Sized against the largest pattern in the largest real ruleset: CRS's
	// longest operator argument is 8,504 bytes, and the default here is 64 KiB.
	if limit := c.opts.patternLimit(); limit >= 0 && len(arg) > limit {
		return nil, fmt.Sprintf("@%s argument is %d bytes, over the %d byte limit; "+
			"set Options.MaxPatternBytes to raise it, or a negative value for none",
			name, len(arg), limit)
	}
	// A macro that survives into the operator argument would be matched as
	// literal text, and "%{tx.allowed_methods}" appears in no request ever sent.
	// That is not a weakened rule, it is a dead one, and the operator would be
	// told method enforcement is in place while nothing enforces it. CRS 911100
	// and 920430 are both this shape.
	//
	// Reported rather than expanded: the values live in crs-setup.conf as
	// cross-rule TX state, which gwaf does not model, and both rules are policy
	// the embedder configures directly (docs/RULES.md §4).
	if m, ok := unexpandedMacro(arg); ok {
		return nil, fmt.Sprintf("operator argument contains the unexpanded macro %s, "+
			"which would be matched as literal text and could never fire; "+
			"configure this as policy instead", m)
	}

	// Operators below that build a positive match from their argument have no
	// way to carry a "!", and dropping it does not weaken the rule, it inverts
	// it. CRS uses !@within, !@streq, !@pm, !@pmFromFile and !@beginsWith, and
	// each one imported without its negation matches precisely the traffic the
	// original allowed. Reported instead, like anything else that cannot be
	// translated faithfully.
	//
	// @rx and @endsWith are absent from this list because they express negation
	// directly; @contains and @containsWord reject it below with their own
	// reasons.
	if negated {
		switch name {
		case "streq", "beginswith", "pm", "pmf", "pmfromfile", "within",
			"detectsqli", "detectxss":
			return nil, fmt.Sprintf("negated @%s cannot be expressed as a gwaf "+
				"operator, and importing it without the negation would "+
				"invert the rule", name)
		}
	}

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
		phrases := strings.Fields(arg)
		if name != "pm" {
			// The phrases are inlined at conversion time, so the generated
			// ruleset stays self-contained and needs no file at request time.
			// Options.DataFiles decides what the name resolves to; the converter
			// does not open anything itself.
			if c.opts.DataFiles == nil {
				return nil, "@" + name + " needs a phrase list; set " +
					"Options.DataFiles to resolve " + strconv.Quote(arg)
			}
			data, err := c.opts.DataFiles(arg)
			if err != nil {
				return nil, fmt.Sprintf("@%s could not read %s: %v", name, arg, err)
			}
			phrases = phraseList(data)
		}
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
func (c *compiler) targets(vars []string) ([]types.Target, []exclusion, string) {
	var out []types.Target
	var excl []exclusion
	for _, v := range vars {
		if strings.HasPrefix(v, "!") {
			// An exclusion is a scoped exception in gwaf -- a different object
			// with a different lifetime, which is why it is returned separately
			// rather than folded into the target list.
			//
			// This used to drop the whole rule. That is safe and expensive: a
			// SecRule carrying "!ARGS:foo" was not imported at all, so CRS's
			// detection went with its tuning. Importing the rule and attaching
			// the exception is equivalent to what CRS does and strictly better
			// than importing neither.
			e, why := parseExclusion(strings.TrimPrefix(v, "!"))
			if why != "" {
				return nil, nil, why
			}
			excl = append(excl, e)
			continue
		}
		if strings.HasPrefix(v, "&") {
			return nil, nil, "counting a collection (&ARGS) is not a value gwaf inspects"
		}

		name, qualifier, _ := strings.Cut(v, ":")

		// XML is addressed by XPath in SecLang and by nothing in gwaf, but the
		// two expressions CRS actually uses are not general XPath: "XML:/*" is
		// every element's text and "XML://@*" is every attribute's value.
		// Between them they cover 145 of CRS's directives and essentially all
		// of its XML usage.
		//
		// Both are substrings of the request body, which gwaf already inspects
		// for an XML content type -- verified: SQL injection inside an element
		// blocks on the body-phase rule. So they map to REQUEST_BODY, a
		// superset that can widen a match but never miss one.
		//
		// The imprecision is real and worth stating: the body also contains tag
		// names and markup, so an imported rule may match text an XPath would
		// have excluded. For rules that are calibrated after import that is the
		// right trade against dropping them, and the alternative -- a real
		// XPath engine over a DOM -- is a parser and an allocation model that
		// the hot path does not want.
		if strings.EqualFold(strings.TrimSpace(name), "XML") {
			q := strings.TrimSpace(qualifier)
			if q == "" || q == "/*" || q == "//@*" || q == "/*|//@*" {
				out = append(out, types.Target{Kind: types.TargetRequestBody})
				continue
			}
			return nil, nil, fmt.Sprintf("XML XPath %q is not one of the whole-document "+
				"forms gwaf can map to the request body", q)
		}

		kind, ok := targetKind(strings.ToUpper(strings.TrimSpace(name)))
		if !ok {
			return nil, nil, fmt.Sprintf("variable %q has no gwaf equivalent", name)
		}
		if strings.HasPrefix(qualifier, "/") {
			return nil, nil, "regex-qualified variables (ARGS:/^x/) select by name " +
				"pattern, which gwaf targets do not express"
		}
		out = append(out, types.Target{Kind: kind, Name: strings.TrimSpace(qualifier)})
	}
	return out, excl, ""
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
	case "REQUEST_FILENAME", "REQUEST_BASENAME":
		// REQUEST_BASENAME is the last path segment. gwaf has no separate
		// target for it, and the path is a superset — matching a basename
		// pattern against the whole path can only widen, never miss, which is
		// the safe direction for an import.
		return types.TargetRequestPath, true
	case "QUERY_STRING":
		// The query string is part of the request URI, which is what gwaf
		// records. Same reasoning: a superset never misses.
		return types.TargetRequestURI, true
	case "ARGS_GET_NAMES":
		return types.TargetArgNames, true
	case "REQUEST_METHOD":
		return types.TargetRequestMethod, true
	case "REQUEST_PROTOCOL":
		return types.TargetRequestProtocol, true
	case "REQUEST_HEADERS":
		return types.TargetRequestHeaders, true
	case "REQUEST_HEADERS_NAMES":
		return types.TargetRequestHeaderNames, true
	case "REQUEST_LINE":
		// The request line is "GET /path HTTP/1.1" — available in phase 1 and
		// nothing to do with the body.
		//
		// It was mapped to REQUEST_BODY, which is wrong twice over: it read the
		// wrong bytes, and it put a phase-1 rule in the body phase, so the
		// compiler rejected the whole ruleset with "REQUEST_BODY is not
		// available until phase request_body". CRS 920100 and 932170 are both
		// REQUEST_LINE rules at phase:1, so importing CRS failed outright — the
		// bridge could not load the ruleset it exists to load.
		//
		// Found by running the CRS corpus through the bridge rather than by
		// reading it: no in-tree test imported a REQUEST_LINE rule.
		//
		// That fix was half of one. Pointing it at REQUEST_URI made the ruleset
		// load, but still handed the rule the wrong bytes, and CRS 920100 is a
		// *negated* match against the full "METHOD URI PROTOCOL" form — so a URI
		// never matched it, the negation fired, and every single request through
		// the bridge scored 3 for "Invalid HTTP Request Line". Found on a real
		// request an adopter sent in, which is also why the head-to-head
		// false-positive figure for gwaf+CRS was overstated.
		return types.TargetRequestLine, true
	case "REQUEST_BODY", "MULTIPART_FILENAME", "FILES", "FILES_NAMES":
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
		// The mapping lives in transform.go, next to the exported names
		// Generate needs, so the compiler cannot accept a transform the
		// generator has no way to render.
		token := strings.ToLower(a.Value)
		switch {
		case token == "none":
			out = out[:0]
		case isDroppedTransform(token):
			// Faithfully translates to nothing; see droppedTransforms.
		default:
			tf, ok := transformFor(token)
			if !ok {
				return nil, fmt.Sprintf("transformation t:%s has no gwaf equivalent", a.Value)
			}
			out = append(out, tf)
		}
	}
	return out, ""
}

// unexpandedMacro finds a "%{...}" reference left in an operator argument and
// returns it. ModSecurity substitutes these from collections at request time;
// gwaf has no collections, so anything still present here is dead text.
func unexpandedMacro(arg string) (string, bool) {
	start := strings.Index(arg, "%{")
	if start < 0 {
		return "", false
	}
	end := strings.Index(arg[start:], "}")
	if end < 0 {
		return "", false
	}
	return arg[start : start+end+1], true
}

// phraseList reads a ModSecurity .data file: one phrase per line, '#' comments,
// blank lines ignored.
//
// A phrase is the whole line rather than whitespace-separated words, which is
// the difference between @pmFromFile and @pm. CRS relies on it —
// windows-powershell-commands.data and unix-shell.data both contain entries with
// spaces, and splitting them would turn one precise phrase into several
// dangerously generic ones.
func phraseList(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
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

// confidence returns the tier an imported rule should carry.
//
// Inside a paranoia-gated block it comes from the level CRS assigned, mapped by
// types.ConfidenceFromParanoiaLevel — PL1 is High, PL2 Medium, PL3 Low, PL4
// Heuristic. That is the honest translation: CRS's own authors placed the rule
// behind a level, and the level is a statement about how much false-positive
// risk it carries.
//
// Outside a gated block the caller's DefaultConfidence applies, because nothing
// in the file said otherwise.
func (c *compiler) confidence() types.Confidence {
	if c.paranoia > 0 {
		return types.ConfidenceFromParanoiaLevel(c.paranoia)
	}
	return types.Confidence(c.opts.DefaultConfidence)
}

// exclusion is a SecLang "!VAR:key" the compiler turns into a gwaf exception.
type exclusion struct {
	Kind types.TargetKind
	Key  string
}

// parseExclusion maps "REQUEST_COOKIES:__gads" onto a target and a key.
//
// A regex-qualified key -- CRS writes !REQUEST_COOKIES:/^_ga(?:_\w+)?$/ -- is
// refused rather than approximated. rules.Exception matches a key exactly, and
// the nearest prefix reading of that pattern also covers "_gabbage": broader
// than CRS wrote. An exception that is too broad is a wider hole in the
// firewall, which is the one direction it must not be wrong in, and it is the
// same reason `gwaf tune` prints exceptions for a human instead of applying
// them.
func parseExclusion(v string) (exclusion, string) {
	name, key, _ := strings.Cut(strings.TrimSpace(v), ":")
	kind, ok := targetKind(strings.TrimSpace(name))
	if !ok {
		return exclusion{}, fmt.Sprintf("exclusion names variable %q, which has "+
			"no gwaf equivalent", name)
	}
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "/") && strings.HasSuffix(key, "/") && len(key) > 1 {
		return exclusion{}, fmt.Sprintf("exclusion key %s is a regex; "+
			"rules.Exception matches a key exactly and widening it to a prefix "+
			"would suppress more than the ruleset asked for -- write the "+
			"exception by hand", key)
	}
	return exclusion{Kind: kind, Key: key}, ""
}

// addException records a translated exclusion, ignoring duplicates.
//
// CRS repeats the same exclusion across files -- five identical _ga cookie
// entries in COMMON-EXCEPTIONS-AFTER alone -- and a list that carries each one
// five times makes the report harder to audit without changing what it does.
func (c *compiler) addException(e rules.Exception) {
	for _, have := range c.report.Exceptions {
		if have.RuleID == e.RuleID && have.Target == e.Target && have.Key == e.Key {
			return
		}
	}
	c.report.Exceptions = append(c.report.Exceptions, e)
}

// updateTarget translates SecRuleUpdateTargetById into an exception.
//
//	SecRuleUpdateTargetById 932240 "!REQUEST_COOKIES:__gads"
//
// The positive form -- adding a target to an existing rule -- is refused. It
// widens what a rule inspects, and a rule that has already been imported and
// calibrated should not silently start reading a collection the operator did
// not see it read.
func (c *compiler) updateTarget(line int, name string, args []string) {
	if len(args) < 2 {
		c.skip(line, 0, name, "expected a rule ID and a variable list")
		return
	}
	id64, err := strconv.ParseUint(strings.TrimSpace(args[0]), 10, 32)
	if err != nil {
		c.skip(line, 0, name, "rule ID "+strconv.Quote(args[0])+" is not a number")
		return
	}
	id := uint32(id64)

	for _, v := range splitVariables(args[1]) {
		v = strings.TrimSpace(v)
		if !strings.HasPrefix(v, "!") {
			c.skip(line, id, name, "adding a target to an imported rule widens "+
				"what it inspects; only exclusions (!VAR:key) are translated")
			continue
		}
		e, why := parseExclusion(strings.TrimPrefix(v, "!"))
		if why != "" {
			c.skip(line, id, name, why)
			continue
		}
		c.addException(rules.Exception{
			RuleID: types.RuleID(id),
			Target: e.Kind,
			Key:    e.Key,
			Note:   "SecRuleUpdateTargetById " + strconv.FormatUint(id64, 10),
		})
	}
}
