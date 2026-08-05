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
	"github.com/gsoultan/gwaf/detect/sqli"
	"github.com/gsoultan/gwaf/detect/xss"
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
	IDNullByteInjection types.RuleID = 1005
	IDTraversalRepeated types.RuleID = 1004
	// 2001-2004 were literal SQL injection rules: tautology, UNION SELECT,
	// comment sequences, and stacked statements. All four are superseded by
	// IDSQLiSemantic, which recognises the same constructs by grammar and
	// therefore also covers the variants a literal list has to enumerate.
	//
	// They were removed rather than kept alongside it because 2002 was an
	// active false positive: "the union selected a new representative"
	// collapses to "unionselected" once whitespace is stripped, which contains
	// "unionselect". The structural detector does not match it, because the
	// two keywords are not adjacent in the grammar.
	//
	// The IDs are retired, not reused. They appear in audit logs and any
	// exception someone already wrote, and silently rebinding them to different
	// behaviour would invalidate both.
	// 3001-3003 were literal XSS rules: script tags, event-handler attributes,
	// and script URI schemes. All three are superseded by IDXSSSemantic, which
	// recognises the same structures *in position* — an "onerror" inside a tag
	// rather than anywhere in the value — and therefore also covers the
	// variants a literal list cannot, such as "<svg/onload=" and
	// "java\tscript:".
	//
	// Retired, not reused: the IDs appear in audit logs and in any exception
	// already written against them.
	IDRCEShellMetachars types.RuleID = 4001
	IDRCECommonBinaries types.RuleID = 4002
	IDLFIPHPWrapper     types.RuleID = 4003
	IDPHPCodeUpload     types.RuleID = 4004
	IDXMLEntity         types.RuleID = 4005
	IDSQLiSemantic      types.RuleID = 2010
	IDXSSSemantic       types.RuleID = 3010
	IDScannerUserAgent  types.RuleID = 5001

	// 6,000-6,999: response-phase leak detection.
	IDLeakPrivateKey types.RuleID = 6001
	IDLeakStackTrace types.RuleID = 6002
	IDLeakSQLError   types.RuleID = 6003
)

// argTargets are the request values an injection rule inspects. Header values
// are included because injection through headers is routine and a rule that
// only inspected arguments would miss it.
var argTargets = []types.Target{
	{Kind: types.TargetArgs},
	// Parameter *names* are as attacker-controlled as their values, and a
	// payload placed in one would otherwise be invisible: nothing else inspects
	// them. This matters most for JSON object keys, which the body parser emits
	// here.
	{Kind: types.TargetArgNames},
	{Kind: types.TargetRequestURI},
	{Kind: types.TargetRequestHeaders},
}

// bodyTargets extend argTargets to the parsed body, for phase-2 rules.
var bodyTargets = []types.Target{
	{Kind: types.TargetArgs},
	{Kind: types.TargetArgNames},
	{Kind: types.TargetRequestBody},
}

// responseTargets are what a leak rule inspects. Header values matter as much
// as the body: a framework version or an internal hostname leaks just as
// effectively from a header.
// responseTargets is what a leak rule inspects at the response-headers phase.
// The body-phase counterpart is generated; see withResponsePhase.
var responseTargets = []types.Target{
	{Kind: types.TargetResponseHeaders},
}

// responseBodyTargets extends a leak rule to the body once it is available.
var responseBodyTargets = []types.Target{
	{Kind: types.TargetResponseHeaders},
	{Kind: types.TargetResponseBody},
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
//
// It is the request-phase rules plus a generated request-body counterpart for
// every rule that inspects attacker-supplied content, so a payload blocked in a
// query string is blocked identically in a JSON or form body.
func Default() rules.Set {
	return withResponsePhase(withBodyPhase(requestRules()))
}

// requestRules returns the rules authored for the request-headers phase.
func requestRules() rules.Set {
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
		{
			ID:         IDTraversalRepeated,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// A single "../" appears in legitimate relative references, but a
			// repeated segment does not: nothing a browser or client library
			// emits walks two levels up inside one parameter. Whitespace is
			// stripped by the chain, so padded variants are covered too.
			Op:         op.ContainsAny("../..", `..\..`, "..%2f..", `..%5c..`),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Repeated path traversal segment",
			Tags:       []string{"traversal", "owasp-a01"},
		},
		{
			ID:      IDNullByteInjection,
			Phase:   types.PhaseRequestHeaders,
			Targets: argTargets,
			// Matched *before* percent-decoding, on purpose. Decoded, a NUL is
			// indistinguishable from the NULs that fill ordinary binary upload
			// content; encoded, it is a deliberate act with no legitimate use.
			// No client, library, or browser emits "%00" in a parameter.
			//
			// This is the double-extension vector: "shell.php%00.jpg" passes a
			// suffix check that sees .jpg, and a C-backed handler truncates at
			// the NUL and saves shell.php. The payload is the disagreement
			// between the two readings, so the NUL itself is what to detect --
			// not the extension, which is legitimate on its own.
			Transforms: []rules.Transform{transform.Lowercase},
			Op:         op.ContainsAny("%00", "%u0000", "\\x00"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Encoded null byte in input",
			Tags:       []string{"traversal", "lfi", "owasp-a01"},
		},

		// ---- SQL injection --------------------------------------------------
		{
			ID:      IDSQLiSemantic,
			Phase:   types.PhaseRequestHeaders,
			Targets: argTargets,
			// Only percent-decoding and case folding: the tokenizer needs the
			// original whitespace and punctuation, because that structure is
			// exactly what it reads. Stripping whitespace here would destroy
			// the grammar the detector exists to see.
			Transforms: []rules.Transform{transform.URLDecode},
			// Structural detection rather than string matching. One rule covers
			// the whole variant family -- comment splitting, case alternation,
			// alternative operators, quote-context breaking -- that a signature
			// list has to enumerate one payload at a time. See detect/sqli.
			Op:         sqli.Operator(),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "SQL injection (structural)",
			Tags:       []string{"sqli", "owasp-a03", "semantic"},
		},

		// ---- Cross-site scripting ------------------------------------------

		// ---- Cross-site scripting -------------------------------------------
		{
			ID:      IDXSSSemantic,
			Phase:   types.PhaseRequestHeaders,
			Targets: argTargets,
			// Percent-decoding only. The detector reads markup structure, so
			// stripping whitespace or folding case here would destroy the very
			// positions it depends on: "onerror" adjacent to "=" inside a tag
			// is a handler, and the same bytes elsewhere are a word.
			Transforms: []rules.Transform{transform.URLDecode},
			Op:         xss.Operator(),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Cross-site scripting (structural)",
			Tags:       []string{"xss", "owasp-a03", "semantic"},
		},

		// ---- Command injection and inclusion --------------------------------
		{
			ID:         IDRCEShellMetachars,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// Every literal here names a *command*, not merely a metacharacter.
			//
			// "$(" alone was here and was wrong at Certain confidence. Two bytes
			// is not evidence: it is jQuery, it is a Makefile, it is a shell
			// snippet someone pasted into a bug report -- and in binary content
			// it appears by chance about once per hundred requests, which
			// calibration measured as a 1.2% false-positive rate on gRPC
			// traffic. Command substitution is dangerous when it substitutes a
			// command, so the literal must include one.
			Op: op.ContainsAny(
				";cat/", "|cat/", "&&cat/", ";wget", ";curl", "|nc-",
				";rm-rf", "&&rm-rf", ";chmod", "|sh-", ";bash-",
				"$(cat", "$(curl", "$(wget", "$(id", "$(whoami", "$(uname",
				"$(nc", "$(sh", "$(bash", "$(python", "$(perl",
				"`cat", "`curl", "`wget", "`id`", "`whoami", "`uname",
			),
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
		{
			ID:         IDPHPCodeUpload,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// A PHP open tag in a request value is code being delivered, not
			// data. This is the web-shell upload: the file is base64-encoded
			// inside a JSON field, decoded by the origin, written to disk, and
			// then requested.
			//
			// The tag alone is High rather than Certain because a narrow class
			// of applications legitimately carries PHP source in a request: a
			// code-sharing site, a CMS template editor, a paste bin. Those
			// deployments should scope an exception to the field that carries
			// it rather than lower the tier globally.
			Op:         op.ContainsAny("<?php", "<?=$", "<%php"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.High,
			Msg:        "PHP code in request value",
			Tags:       []string{"rce", "upload", "owasp-a03"},
		},
		{
			ID:         IDXMLEntity,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// An inline entity declaration in a request body is XML external
			// entity injection or an expansion bomb. There is no third thing it
			// is: a client sending data declares elements, never entities, and
			// a document that needs entities defines them in a schema the
			// server already has.
			//
			// This covers both shapes at once. "<!ENTITY x SYSTEM 'file:///etc/passwd'>"
			// reads a file the request had no business reading, and
			// "<!ENTITY lol '&lol;&lol;...'>" expands until the parser runs out
			// of memory. Whitespace is stripped by the chain, so the spacing
			// variants collapse together.
			Op:         op.ContainsAny("<!entity", "<!element", "%remote;", "<!attlist"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "XML entity declaration in request",
			Tags:       []string{"xxe", "dos", "owasp-a05"},
		},

		// ---- Response leaks --------------------------------------------------
		//
		// These are the reason a response phase exists. They detect what leaves
		// rather than what arrives, which is a different question: not "is this
		// an attack" but "did the origin just disclose something".
		//
		// All three are High rather than Certain. Each has a narrow class of
		// application for which the content is the product — a paste bin, an
		// error-tracking API, a database console — and those deployments should
		// scope an exception rather than have the tier lowered for everyone.
		{
			ID:         IDLeakPrivateKey,
			Phase:      types.PhaseResponseHeaders,
			Targets:    responseTargets,
			Transforms: []rules.Transform{transform.Lowercase},
			// A certificate is public and appears in responses legitimately; a
			// private key is the opposite of public and appears in one only by
			// mistake.
			Op: op.ContainsAny(
				"-----begin rsa private key", "-----begin dsa private key",
				"-----begin ec private key", "-----begin openssh private key",
				"-----begin pgp private key", "-----begin private key",
				"-----begin encrypted private key",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.High,
			Msg:        "Private key in response",
			Tags:       []string{"leak", "response", "owasp-a02"},
		},
		{
			ID:         IDLeakStackTrace,
			Phase:      types.PhaseResponseHeaders,
			Targets:    responseTargets,
			Transforms: []rules.Transform{transform.Lowercase},
			// A stack trace hands an attacker the framework, the version, the
			// filesystem layout, and often the query that failed. Each literal
			// pairs a marker with its context so the word alone does not match:
			// "panic:" is a word, "panic:" beside "goroutine" is Go leaking.
			Op: op.ContainsAny(
				"goroutine 1 [running]", "\npanic: runtime error",
				"traceback (most recent call last)",
				"at java.lang.", "at org.springframework.",
				"system.nullreferenceexception", "at system.web.",
				"fatal error: uncaught", "stack trace:\n#0",
				"activerecord::", "django.core.exceptions",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityError,
			Confidence: types.High,
			Msg:        "Stack trace in response",
			Tags:       []string{"leak", "response", "owasp-a05"},
		},
		{
			ID:         IDLeakSQLError,
			Phase:      types.PhaseResponseHeaders,
			Targets:    responseTargets,
			Transforms: []rules.Transform{transform.Lowercase},
			// A database error in a response is how an attacker confirms an
			// injection landed and then reads the schema back one message at a
			// time. It is the feedback channel that makes blind injection
			// unnecessary.
			Op: op.ContainsAny(
				"you have an error in your sql syntax",
				"warning: mysql_", "unclosed quotation mark after",
				"quoted string not properly terminated",
				"pg::syntaxerror", "sqlstate[", "ora-0", "ora-1",
				"microsoft ole db provider for sql server",
				"sqlite3::sqlexception", "psycopg2.errors",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.High,
			Msg:        "Database error in response",
			Tags:       []string{"leak", "response", "sqli", "owasp-a03"},
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
	}
}

// bodyPhaseOffset is added to a request-headers rule's ID to derive the ID of
// its request-body counterpart.
//
// The pairing is by construction rather than by hand. Hand-written duplicates
// drift: the first version of this ruleset mirrored two of the ten injection
// rules into the body phase, so a payload that was blocked in a query string
// sailed through in a JSON body. The evasion corpus caught it, and generating
// the pair removes the class of mistake rather than the instance.
const bodyPhaseOffset types.RuleID = 900

// mirrorToBody returns the request-body counterpart of a request-headers rule.
//
// Only the targets and phase change: an injection payload is the same payload
// whether it arrives in a query string or a JSON body, so the operator,
// transform chain, severity, and confidence are shared.
func mirrorToBody(r rules.Rule) rules.Rule {
	m := r
	m.ID = r.ID + bodyPhaseOffset
	m.Phase = types.PhaseRequestBody
	m.Targets = bodyTargets
	m.Msg = r.Msg + " (body)"
	return m
}

// withBodyPhase returns set plus a request-body counterpart for every rule that
// inspects attacker-supplied argument values.
//
// Selection is by what a rule *reads*, not by what it is tagged. An earlier
// version keyed off a list of tags, and that list is exactly the kind of thing
// that goes stale silently: the XXE rule was added with an "xxe" tag, no tag
// matched, no body counterpart was generated, and an entity declaration in a
// JSON or XML body went uninspected. Nothing failed — the rule simply was not
// there.
//
// Reading the targets removes the class of mistake rather than the instance,
// which is the same reason these rules are generated instead of hand-written.
// A rule that inspects the request path or one named header has no body
// equivalent and is left alone; mirroring it would produce a rule that can
// never match.
func withBodyPhase(set rules.Set) rules.Set {
	out := make(rules.Set, 0, len(set)*2)
	out = append(out, set...)

	for _, r := range set {
		if r.Phase != types.PhaseRequestHeaders {
			continue
		}
		if !readsArgs(r) {
			continue
		}
		out = append(out, mirrorToBody(r))
	}
	return out
}

// responsePhaseOffset derives a response-body rule's ID from its header-phase
// original, mirroring bodyPhaseOffset on the request side.
const responsePhaseOffset types.RuleID = 100

// withResponsePhase returns set plus a response-body counterpart for every
// response-headers rule.
//
// Symmetric with withBodyPhase, and for the same reason. A leak rule wants to
// read both the headers and the body, but the body does not exist yet at the
// header phase — so the header-phase rule reads headers, and a generated
// counterpart reads both once the body is available.
//
// The header-phase version is what lets an embedder stop a leaking response
// before any of it is written. The body-phase version is what catches the
// leak that was in the body all along.
func withResponsePhase(set rules.Set) rules.Set {
	out := make(rules.Set, 0, len(set)+8)
	out = append(out, set...)

	for _, r := range set {
		if r.Phase != types.PhaseResponseHeaders {
			continue
		}
		m := r
		m.ID = r.ID + responsePhaseOffset
		m.Phase = types.PhaseResponseBody
		m.Targets = responseBodyTargets
		m.Msg = r.Msg + " (body)"
		out = append(out, m)
	}
	return out
}

// readsArgs reports whether a rule inspects attacker-supplied argument values,
// which is what makes a body counterpart meaningful.
func readsArgs(r rules.Rule) bool {
	for _, t := range r.Targets {
		if t.Kind == types.TargetArgs && t.Name == "" {
			return true
		}
	}
	return false
}
