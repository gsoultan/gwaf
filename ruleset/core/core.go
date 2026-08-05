// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package core provides the first-party ruleset loaded by gwaf.New.
//
// Every rule here is Certain or High confidence. That constraint is what makes
// blocking by default defensible: a WAF that ships in detection-only mode
// protects nothing while telling the operator they are covered, and a WAF that
// blocks on imprecise rules gets disabled within a week. The way out is not a
// safer default mode, it is a ruleset precise enough to enforce.
//
// Rules that need tuning belong in an optional bundle, not here.
//
// Confidence is a measured property, not an authored one: `gwaf calibrate`
// checks each rule's false-positive rate against the benign corpus and fails
// the build when it exceeds the declared tier's ceiling. See docs/CONCEPT.md §8.
package core

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

// ID allocation within the core range (1..99,999):
//
//	1,000–1,999  path traversal
//	2,000–2,999  SQL injection
//	3,000–3,999  cross-site scripting
//	4,000–4,999  command injection and local file inclusion
//	5,000–5,999  scanners and known-hostile clients
const (
	IDTraversalEncoded  types.RuleID = 1001
	IDTraversalRaw      types.RuleID = 1002
	IDSensitiveFile     types.RuleID = 1003
	IDSQLiTautology     types.RuleID = 2001
	IDSQLiUnionSelect   types.RuleID = 2002
	IDSQLiComment       types.RuleID = 2003
	IDSQLiStacked       types.RuleID = 2004
	IDXSSScriptTag      types.RuleID = 3001
	IDXSSEventHandler   types.RuleID = 3002
	IDXSSJavaScriptURI  types.RuleID = 3003
	IDRCEShellMetachars types.RuleID = 4001
	IDRCECommonBinaries types.RuleID = 4002
	IDLFIPHPWrapper     types.RuleID = 4003
	IDScannerUserAgent  types.RuleID = 5001
)

// argTargets are the request values an injection rule inspects. Header values
// are included because injection through headers is routine and a rule that
// only inspected arguments would miss it.
var argTargets = []types.Target{
	{Kind: types.TargetArgs},
	{Kind: types.TargetRequestURI},
	{Kind: types.TargetRequestHeaders},
}

// bodyTargets extend argTargets to the parsed body, for phase-2 rules.
var bodyTargets = []types.Target{
	{Kind: types.TargetArgs},
	{Kind: types.TargetRequestBody},
}

// decodeChain is the normalization applied before injection matching. Order
// matters: percent-decode first so that encoded payloads are seen, then fold
// case, then strip whitespace inserted to break up keywords.
var decodeChain = []rules.Transform{
	transform.URLDecode,
	transform.Lowercase,
	transform.RemoveWhitespace,
}

// pathChain normalizes a path before traversal matching.
var pathChain = []rules.Transform{
	transform.URLDecode,
	transform.Lowercase,
	transform.NormalizePath,
}

// Default is the ruleset gwaf.New loads when the embedder supplies none.
func Default() rules.Set {
	return rules.Set{
		// ---- Path traversal -------------------------------------------------
		{
			ID:    IDTraversalEncoded,
			Phase: types.PhaseRequestHeaders,
			Targets: []types.Target{
				{Kind: types.TargetRequestURI},
				{Kind: types.TargetArgs},
			},
			// Matched before normalization: an encoded traversal sequence in a
			// URI has no legitimate use, whereas the decoded form does appear
			// in ordinary relative links.
			Transforms: []rules.Transform{transform.Lowercase},
			Op:         op.ContainsAny("%2e%2e%2f", "%2e%2e/", "..%2f", "%2e%2e%5c", "..%5c"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Encoded path traversal sequence",
			Tags:       []string{"traversal", "owasp-a01"},
		},
		{
			ID:         IDTraversalRaw,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetRequestPath}},
			Transforms: pathChain,
			// After normalization a leading ".." means the path resolved above
			// its root, which a legitimate request target never does.
			Op:         op.HasPrefix(".."),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Path traversal above document root",
			Tags:       []string{"traversal", "owasp-a01"},
		},
		{
			ID:         IDSensitiveFile,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetRequestURI}, {Kind: types.TargetArgs}},
			Transforms: pathChain,
			Op: op.ContainsAny(
				"/etc/passwd", "/etc/shadow", "/proc/self/environ",
				"/windows/system32/config", ".ssh/id_rsa", ".aws/credentials",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Access to sensitive system file",
			Tags:       []string{"lfi", "owasp-a01"},
		},

		// ---- SQL injection --------------------------------------------------
		{
			ID:         IDSQLiTautology,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// Whitespace is stripped by the chain, so "1=1" also covers
			// "1 = 1" and "1/**/=/**/1" style padding.
			Op:         op.ContainsAny("'or1=1", "\"or1=1", "or1=1--", "'or'1'='1", "or1=1#"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "SQL injection tautology",
			Tags:       []string{"sqli", "owasp-a03"},
		},
		{
			ID:         IDSQLiUnionSelect,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			Op:         op.ContainsAny("unionselect", "unionallselect"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "SQL injection UNION SELECT",
			Tags:       []string{"sqli", "owasp-a03"},
		},
		{
			ID:         IDSQLiComment,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// Scored rather than blocking: these sequences occur in legitimate
			// content often enough that blocking on one alone would produce
			// false positives. They are strong corroboration when combined.
			Op:         op.ContainsAny("';--", "\";--", "'#", "/*!"),
			Actions:    []rules.Action{rules.Score},
			Severity:   types.SeverityError,
			Confidence: types.High,
			Msg:        "SQL comment sequence in input",
			Tags:       []string{"sqli", "owasp-a03"},
		},
		{
			ID:         IDSQLiStacked,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			Op:         op.ContainsAny(";drop table", ";droptable", ";truncatetable", ";deletefrom"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Stacked SQL statement",
			Tags:       []string{"sqli", "owasp-a03"},
		},

		// ---- Cross-site scripting ------------------------------------------
		{
			ID:         IDXSSScriptTag,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			Op:         op.ContainsAny("<script", "</script", "<svg/onload", "<iframesrc"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "XSS script tag injection",
			Tags:       []string{"xss", "owasp-a03"},
		},
		{
			ID:         IDXSSEventHandler,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			Op:         op.ContainsAny("onerror=", "onload=", "onmouseover=", "onfocus=", "onclick="),
			Actions:    []rules.Action{rules.Score},
			Severity:   types.SeverityError,
			Confidence: types.High,
			Msg:        "XSS event handler attribute",
			Tags:       []string{"xss", "owasp-a03"},
		},
		{
			ID:         IDXSSJavaScriptURI,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			Op:         op.ContainsAny("javascript:", "vbscript:", "data:text/html"),
			Actions:    []rules.Action{rules.Score},
			Severity:   types.SeverityError,
			Confidence: types.High,
			Msg:        "Script URI scheme in input",
			Tags:       []string{"xss", "owasp-a03"},
		},

		// ---- Command injection and inclusion --------------------------------
		{
			ID:         IDRCEShellMetachars,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			Op:         op.ContainsAny("$(", "`;", ";cat/", "|cat/", "&&cat/", ";wget", ";curl", "|nc-"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Shell command injection",
			Tags:       []string{"rce", "owasp-a03"},
		},
		{
			ID:         IDRCECommonBinaries,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			Op:         op.ContainsAny("/bin/sh", "/bin/bash", "cmd.exe", "powershell-e"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Shell binary referenced in input",
			Tags:       []string{"rce", "owasp-a03"},
		},
		{
			ID:         IDLFIPHPWrapper,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			Op:         op.ContainsAny("php://input", "php://filter", "expect://", "data://text"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "PHP stream wrapper in input",
			Tags:       []string{"lfi", "rce", "owasp-a03"},
		},

		// ---- Hostile clients -------------------------------------------------
		{
			ID:         IDScannerUserAgent,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetRequestHeaders, Name: "User-Agent"}},
			Transforms: []rules.Transform{transform.Lowercase},
			Op: op.ContainsAny(
				"sqlmap", "nikto", "acunetix", "nessus", "masscan",
				"nmap scripting engine", "dirbuster", "wpscan",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Known vulnerability scanner",
			Tags:       []string{"scanner", "reputation"},
		},

		// ---- Body phase ------------------------------------------------------
		{
			ID:         IDSQLiUnionSelect + 900, // 2902: body-phase counterpart
			Phase:      types.PhaseRequestBody,
			Targets:    bodyTargets,
			Transforms: decodeChain,
			Op:         op.ContainsAny("unionselect", "unionallselect"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "SQL injection UNION SELECT in body",
			Tags:       []string{"sqli", "owasp-a03"},
		},
		{
			ID:         IDXSSScriptTag + 900, // 3901: body-phase counterpart
			Phase:      types.PhaseRequestBody,
			Targets:    bodyTargets,
			Transforms: decodeChain,
			Op:         op.ContainsAny("<script", "</script", "<svg/onload"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "XSS script tag injection in body",
			Tags:       []string{"xss", "owasp-a03"},
		},
	}
}
