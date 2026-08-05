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
	"github.com/gsoultan/gwaf/detect/graphql"
	"github.com/gsoultan/gwaf/detect/ldapi"
	"github.com/gsoultan/gwaf/detect/nosqli"
	"github.com/gsoultan/gwaf/detect/shelli"
	"github.com/gsoultan/gwaf/detect/sqli"
	"github.com/gsoultan/gwaf/detect/ssti"
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
//	6,000–6,999  response-side disclosure
//	7,000–7,999  NoSQL injection
//	8,000–8,999  server-side template injection
//	9,000–9,999  LDAP injection
//	10,000–10,999 GraphQL abuse
//
// An authored ID must end below 100 within its band, because the generated
// body-phase counterpart is the ID plus 900 (see bodyPhaseOffset) and has to
// land in the same band. 2,501 would mirror to 3,401 — an ID an operator would
// reasonably look up as cross-site scripting. TestMirrorIDsStayInBand enforces
// this; it is not a convention anyone has to remember.
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
	// 4001 and 4002 were literal command injection rules: a list of command
	// names glued to separators, and a list of shell binary paths. Both are
	// superseded by IDShelliSemantic, which reads shell *structure* -- a name
	// in command position, after unquoting -- and therefore also covers the
	// forms no literal list can reach.
	//
	// Four payloads walked through them, each a technique in use for years:
	// glob obfuscation (/???/c?t), encode-and-pipe (echo …|base64 -d|sh),
	// fetch-and-pipe (curl …|sh), and substring expansion (${PATH:0:1}). None
	// contains the literal it would have to match.
	//
	// 4001 was also an active false positive: "`id`" was a literal, and that
	// is how everyone writes inline code in Markdown, so "use the `id` field"
	// was blocked. The structural detector does not report a bare backtick
	// substitution, for exactly that reason.
	//
	// Retired, not reused: the IDs appear in audit logs and in any exception
	// already written against them.
	IDLFIPHPWrapper    types.RuleID = 4003
	IDPHPCodeUpload    types.RuleID = 4004
	IDXMLEntity        types.RuleID = 4005
	IDShelliSemantic   types.RuleID = 4010
	IDSQLiSemantic     types.RuleID = 2010
	IDXSSSemantic      types.RuleID = 3010
	IDScannerUserAgent types.RuleID = 5001

	// 6,000-6,999: response-phase leak detection.
	IDLeakPrivateKey types.RuleID = 6001
	IDLeakStackTrace types.RuleID = 6002
	IDLeakSQLError   types.RuleID = 6003

	// 7,000-7,999: NoSQL injection.
	IDNoSQLiEval     types.RuleID = 7001
	IDNoSQLiOperator types.RuleID = 7002

	// 8,000-8,999: server-side template injection.
	IDSSTIExpression types.RuleID = 8001

	// 9,000-9,999: LDAP injection.
	IDLDAPiFilter types.RuleID = 9001

	// 10,000-10,999: GraphQL abuse. Not injection -- the document is valid and
	// the damage is done by its shape.
	IDGraphQLStructure types.RuleID = 10001

	// 10002 is graphql.IntrospectionRule and is deliberately NOT here.
	//
	// Introspection is how every GraphQL development tool works. Disabling it in
	// production is a defensible posture and blocking it by default would break
	// GraphiQL, Apollo Studio, and code generation on the day somebody adopted
	// gwaf -- which is the "gets switched off within a week" failure this
	// ruleset exists to avoid. A rule that needs tuning belongs in an optional
	// bundle (CLAUDE.md §1), so an embedder opts in:
	//
	//	gwaf.New(gwaf.WithRuleset(rules.Set{graphql.IntrospectionRule(10002)}))
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

// shellTargets are what a command-injection rule may read.
//
// REQUEST_URI is deliberately absent, and leaving it in was a category error
// that calibration measured at a 20% false-positive rate. A query string uses
// '&' as *its own* separator, so "?q=x&sort=price" reads as a command boundary
// followed by "sort" -- and sort, head, find, id, env, host, last, less, more,
// and w are all ordinary parameter names as well as commands. Every faceted
// search on the corpus was blocked.
//
// Individual argument values are what an application interpolates into a shell;
// the raw URI is a different language that merely shares punctuation.
var shellTargets = []types.Target{
	{Kind: types.TargetArgs},
	{Kind: types.TargetArgNames},
	{Kind: types.TargetRequestHeaders},
}

// graphqlTargets are the arguments that carry a GraphQL document.
//
// Scoped by name rather than left to a literal, because the only byte every
// abusive document must contain is "{" -- which is in every JSON body ever
// sent. The target check runs before the operator, so a rule scoped this way
// costs nothing on traffic that is not GraphQL.
//
// "query" is the field name in the GraphQL-over-HTTP specification, for both
// the POST body and the GET query string, so one name covers both.
var graphqlTargets = []types.Target{
	{Kind: types.TargetArgs, Name: "query"},
}

// nameTargets are parameter *names* alone.
//
// Scoped this narrowly on purpose: an operator token in a name is an injected
// query operator, while the same bytes in a value are somebody typing about
// MongoDB. Reading values here produced exactly that false positive against
// {"note":"use $ne to negate"}.
var nameTargets = []types.Target{
	{Kind: types.TargetArgNames},
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

		// ---- NoSQL injection ------------------------------------------------
		//
		// Two rules rather than one, because the evidence is not equally
		// certain and a rule carries a single confidence.
		//
		// Both read parameter *names*. That is the whole attack: in
		// {"password":{"$ne":null}} nothing dangerous appears in any value, so
		// a value-scanning detector finds nothing at all. See detect/nosqli.
		{
			ID:      IDNoSQLiEval,
			Phase:   types.PhaseRequestHeaders,
			Targets: nameTargets,
			// Percent-decoding only, and no case folding: MongoDB rejects
			// "$NE", so folding would widen the rule onto strings the database
			// would never honour.
			Transforms: []rules.Transform{transform.URLDecode},
			Op:         nosqli.Operator(nosqli.SignalEvalOperator),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "NoSQL injection: database code execution operator",
			Tags:       []string{"nosqli", "rce", "owasp-a03", "semantic"},
		},
		{
			ID:         IDNoSQLiOperator,
			Phase:      types.PhaseRequestHeaders,
			Targets:    nameTargets,
			Transforms: []rules.Transform{transform.URLDecode},
			Op: nosqli.Operator(nosqli.SignalQueryOperator |
				nosqli.SignalUpdateOperator | nosqli.SignalAmbiguousOperator),
			Actions:  []rules.Action{rules.Block},
			Severity: types.SeverityCritical,
			// High rather than Certain: a few frameworks expose MongoDB
			// operators as their published filter DSL, so "?price[$gt]=100" is
			// a documented feature somewhere. Such an application is a NoSQL
			// injection surface by design and reporting it is right — but that
			// is not the same as being certain it is an attack.
			Confidence: types.High,
			Msg:        "NoSQL injection: query operator in parameter name",
			Tags:       []string{"nosqli", "owasp-a03", "semantic"},
		},

		// ---- GraphQL abuse ---------------------------------------------------
		//
		// A different shape of attack from everything else here: the document is
		// valid, the field names are real, and the cost is in its structure. All
		// of it is computed from one request in isolation, which is why it sits
		// inside the scope line rather than outside it with rate limiting.
		{
			ID:      IDGraphQLStructure,
			Phase:   types.PhaseRequestBody,
			Targets: graphqlTargets,
			// Percent-decoding only. The GraphQL-over-HTTP specification defines
			// a GET form where the whole document rides in the query string, so
			// without this an encoded "%7B__schema%7D" is read as one long
			// identifier and every structural count comes back zero -- measured.
			//
			// Nothing else: folding case or stripping whitespace would destroy
			// the grammar the detector counts, which is the opposite problem.
			Transforms: []rules.Transform{transform.URLDecode},
			Op: graphql.Operator(graphql.Limits{},
				graphql.SignalExcessiveDepth|graphql.SignalExcessiveComplexity|
					graphql.SignalAliasAmplification|graphql.SignalFragmentCycle),
			Actions:  []rules.Action{rules.Block},
			Severity: types.SeverityCritical,
			// High rather than Certain: the limits are policy. A content model
			// that is genuinely fifteen levels deep exists, and the operator who
			// has one should raise the limit knowingly rather than discover it
			// as an outage.
			Confidence: types.High,
			Msg:        "GraphQL document exceeds its structural limits",
			Tags:       []string{"graphql", "dos", "owasp-a04"},
		},
		// ---- LDAP injection --------------------------------------------------
		{
			ID:      IDLDAPiFilter,
			Phase:   types.PhaseRequestHeaders,
			Targets: argTargets,
			// Percent-decoding only. The detector counts parentheses and reads
			// what follows them, so stripping whitespace or folding case would
			// leave the structure intact but is pointless work -- and the
			// filter grammar is case-insensitive in exactly the places this
			// does not look at.
			Transforms: []rules.Transform{transform.URLDecode},
			Op:         ldapi.Operator(),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "LDAP injection (structural)",
			Tags:       []string{"ldapi", "owasp-a03", "semantic"},
		},

		// ---- Server-side template injection ---------------------------------
		{
			ID:      IDSSTIExpression,
			Phase:   types.PhaseRequestHeaders,
			Targets: argTargets,
			// Percent-decoding only. The detector reads what sits inside a
			// template expression, so the delimiters, dots, and parentheses it
			// keys on must survive: folding case or stripping whitespace would
			// destroy the very structure being read.
			Transforms: []rules.Transform{transform.URLDecode},
			Op:         ssti.Operator(),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			// High, not Certain, and the reason is worth stating plainly: an
			// application whose users legitimately author Jinja or Liquid
			// templates will send "{{ config.x }}" on purpose. That application
			// needs a scoped exception. Reporting the finding is right;
			// claiming certainty about it would not be.
			Confidence: types.High,
			Msg:        "Server-side template injection",
			Tags:       []string{"ssti", "rce", "owasp-a03", "semantic"},
		},

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
			ID:      IDShelliSemantic,
			Phase:   types.PhaseRequestHeaders,
			Targets: shellTargets,
			// Percent-decoding only. The detector reads separators, quoting,
			// and expansion structure, so stripping whitespace or folding case
			// would destroy the positions it depends on: "cat" after a ';' is a
			// command, and the same three bytes elsewhere are a word.
			Transforms: []rules.Transform{transform.URLDecode},
			Op:         shelli.Operator(),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			// High rather than Certain, and calibration is what decided it.
			// CI/CD and automation platforms carry shell commands as *data* --
			// a pipeline API receives "cat VERSION | tr -d" in a `run` field
			// because running it is the product -- and gwaf cannot tell that
			// from injection using one request. Those applications need a
			// scoped exception on the field that carries commands; reporting
			// the finding is right, and certainty about it is not available.
			Confidence: types.High,
			Msg:        "Command injection (structural)",
			Tags:       []string{"rce", "shelli", "owasp-a03", "semantic"},
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
	m.DerivedFrom = r.ID
	m.Phase = types.PhaseRequestBody
	m.Targets = bodyTargetsFor(r.Targets)
	m.Msg = r.Msg + " (body)"
	return m
}

// bodyTargetsFor derives the body-phase targets from what the original rule
// actually read.
//
// This used to assign bodyTargets unconditionally, which silently *widened*
// every mirrored rule to inspect argument values, argument names, and the raw
// body — whatever the original had been scoped to. That is harmless while every
// rule reads everything, and wrong the moment one does not: the NoSQL rules read
// parameter names only, because "$ne" in a name is an injected query operator
// while the same bytes in a value are somebody typing about MongoDB. Widening
// them produced exactly that false positive.
//
// A mirror must inspect the body-phase equivalent of its original, never more.
func bodyTargetsFor(src []types.Target) []types.Target {
	var readsValues, readsNames bool
	for _, t := range src {
		switch t.Kind {
		case types.TargetArgs:
			if t.Name == "" {
				readsValues = true
			}
		case types.TargetArgNames:
			readsNames = true
		}
	}

	out := make([]types.Target, 0, len(bodyTargets))
	if readsValues {
		// ARGS at phase 2 carries query and body arguments merged; the raw body
		// covers formats the argument parsers do not decompose.
		out = append(out,
			types.Target{Kind: types.TargetArgs},
			types.Target{Kind: types.TargetRequestBody})
	}
	if readsNames {
		out = append(out, types.Target{Kind: types.TargetArgNames})
	}
	return out
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

// readsArgs reports whether a rule inspects attacker-supplied arguments —
// their values, their names, or both — which is what makes a body counterpart
// meaningful.
//
// Names count. A JSON object key arrives only at the body phase, so a rule that
// reads names and is not mirrored inspects query-string names and nothing else:
// it would catch "?password[$ne]=1" and miss {"password":{"$ne":null}}, which
// is the far more common form of the same attack.
func readsArgs(r rules.Rule) bool {
	for _, t := range r.Targets {
		switch t.Kind {
		case types.TargetArgs:
			if t.Name == "" {
				return true
			}
		case types.TargetArgNames:
			return true
		}
	}
	return false
}
