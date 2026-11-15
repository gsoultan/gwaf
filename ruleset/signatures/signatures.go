// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package signatures

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/op/rx"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

// Rule IDs. They sit in the first-party optional-bundle range (docs/RULES.md
// §7) and are stable: an embedder's exceptions and audit history refer to them.
const (
	IDScriptObfuscation   types.RuleID = 100001
	IDPHPKeyword          types.RuleID = 100002
	IDScriptInUserContent types.RuleID = 100003
	IDGoCode              types.RuleID = 100004
	IDJavaClass           types.RuleID = 100005
	IDNodeCode            types.RuleID = 100006
	IDSensitiveFileHeader types.RuleID = 100007
	IDShellshock          types.RuleID = 100008
	IDCommandSeparator    types.RuleID = 100009
	IDTraversalArgName    types.RuleID = 100010
	IDExpressionLanguage  types.RuleID = 100011
	IDGoAnywhere          types.RuleID = 100012
	IDText4Shell          types.RuleID = 100013
	IDFollina             types.RuleID = 100014
	IDShellBuiltin        types.RuleID = 100015
	IDShellshockBody      types.RuleID = 100016
	IDSQLTimeDelay        types.RuleID = 100017
	IDSQLSchemaEnum       types.RuleID = 100018
	IDSQLTautology        types.RuleID = 100019
	IDMOVEitHeader        types.RuleID = 100020
	IDXSSTagOrHandler     types.RuleID = 100021
	IDXSSObfuscated       types.RuleID = 100022
	IDNoSQLOperator       types.RuleID = 100023
	IDPrototypeChain      types.RuleID = 100024
	IDInternalAddress     types.RuleID = 100025
	IDUploadExecutableExt types.RuleID = 100026
	IDPDFJavaScript       types.RuleID = 100027
	IDRansomwareExt       types.RuleID = 100028
	IDWebShellName        types.RuleID = 100029
	IDRansomNote          types.RuleID = 100030
	IDRansomKeywords      types.RuleID = 100031
	IDCryptoMiner         types.RuleID = 100032
	IDWPPluginPHP         types.RuleID = 100033
	IDWPEnumeration       types.RuleID = 100034
	IDScannerUserAgent    types.RuleID = 100035
	IDScannerHeader       types.RuleID = 100036
	IDWebShellProbe       types.RuleID = 100037
	IDSensitiveFileProbe  types.RuleID = 100038
)

// spec is the compact form of a rule. A rules.Rule literal repeated across the
// whole set is mostly punctuation; a table lets a reviewer read the set at once.
type spec struct {
	id       types.RuleID
	phase    types.Phase
	targets  []types.Target
	xform    []rules.Transform
	op       rules.Operator
	severity types.Severity
	conf     types.Confidence
	msg      string
	tags     []string

	// action overrides the default of blocking. Nil blocks.
	action rules.Action
}

func (s spec) rule() rules.Rule {
	action := rules.Block
	if s.action != nil {
		action = s.action
	}
	return rules.Rule{
		ID:         s.id,
		Phase:      s.phase,
		Targets:    s.targets,
		Transforms: s.xform,
		Op:         s.op,
		Actions:    []rules.Action{action},
		Severity:   s.severity,
		Confidence: s.conf,
		Msg:        s.msg,
		Tags:       s.tags,
	}
}

func render(specs []spec) rules.Set {
	set := make(rules.Set, 0, len(specs))
	for _, s := range specs {
		set = append(set, s.rule())
	}
	return set
}

// Target groups.
var (
	tArgs     = []types.Target{{Kind: types.TargetArgs}}
	tArgNames = []types.Target{{Kind: types.TargetArgNames}}

	// The client-supplied name of an uploaded file. It is its own target rather
	// than an argument whose key happens to end in ".filename", so a rule about
	// executable uploads cannot also block "?page=index.php".
	tFileNames   = []types.Target{{Kind: types.TargetFileNames}}
	tURI         = []types.Target{{Kind: types.TargetRequestURI}}
	tPath        = []types.Target{{Kind: types.TargetRequestPath}}
	tHeaderNames = []types.Target{{Kind: types.TargetRequestHeaderNames}}

	tArgsHeadersURI = []types.Target{
		{Kind: types.TargetArgs},
		{Kind: types.TargetRequestHeaders},
		{Kind: types.TargetRequestURI},
	}

	// Parsed body arguments are merged into TargetArgs, so the raw body target
	// is added only for payloads that are not key/value structured.
	tArgsBody = []types.Target{
		{Kind: types.TargetArgs},
		{Kind: types.TargetRequestBody},
	}

	// Some payloads arrive as the parameter name rather than its value.
	tArgsNamesBody = []types.Target{
		{Kind: types.TargetArgs},
		{Kind: types.TargetArgNames},
		{Kind: types.TargetRequestBody},
	}

	// Transform chains. There are deliberately only two: a chain is
	// materialized once per value, so the cost that matters is the number of
	// distinct chains, not the number of rules using them. Every rule states its
	// decode, because without one each is bypassable by percent-encoding a
	// single character.
	norm    = []rules.Transform{transform.URLDecode, transform.Lowercase}
	decoded = []rules.Transform{transform.URLDecode}
)

func header(name string) []types.Target {
	return []types.Target{{Kind: types.TargetRequestHeaders, Name: name}}
}

// present matches any value at all. It is meaningful only on a keyed target:
// the engine evaluates it once per value under that key, so an absent header
// produces no evaluation and no match.
type presentOp struct{ name string }

func present(name string) rules.Operator { return &presentOp{name: name} }

func (o *presentOp) Name() string { return "present:" + o.name }

func (o *presentOp) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	return rules.WholeValue(value), true
}

// Literals reports that presence cannot be prefiltered by content: there is no
// byte sequence the value must contain. The rule using it shows up in the
// compile report's Unconditional list, and must be narrowly keyed to stay cheap.
func (o *presentOp) Literals() ([]string, bool) { return nil, false }

func (o *presentOp) Cost() types.Fuel { return types.CostLiteralMatch }

// All returns every signature rule.
//
// Nothing here is part of core.Default: pass the set, or the part of it wanted,
// to gwaf.WithRuleset. Rules below the engine's minimum confidence are dropped
// at compile time as usual, so the Medium and Low entries cost nothing unless
// asked for.
//
// The returned set is the caller's to edit -- to filter by ID or tag, or to
// replace an action -- and a fresh one is built on every call.
func All() rules.Set { return render(specs) }

// specs is the set. Ordering is by family for readability; the compiler sorts
// by (phase, ID), so source order does not affect evaluation.
var specs = []spec{
	{
		id: IDScriptObfuscation, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform: norm,
		op: op.ContainsAny("string.fromcharcode", "unescape(", "%u00", "eval(atob(",
			"navigator.sendbeacon", "new websocket(", "document.write(",
			"document.createelement('script')"),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Malicious JavaScript detected",
		tags: []string{"javascript", "malware"},
	},
	{
		id: IDPHPKeyword, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform: norm,
		op: op.ContainsAny("<?php", "file_get_contents(", "shell_exec(", "passthru(",
			"base64_decode(", "$_get", "$_post", "$_request", "$_server",
			"$_cookie", "$_files"),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "PHP vulnerability exploit attempt",
		tags: []string{"php", "injection"},
	},
	{
		id: IDScriptInUserContent, phase: types.PhaseRequestBody, targets: tPath,
		xform: norm,
		// A script *inside a directory whose purpose is user-supplied content*.
		//
		// Both halves are required. The extension alone is not evidence of
		// anything: WordPress is PHP, Django serves .py-backed routes, and
		// plenty of estates still run .jsp and .cgi — a rule matching only the
		// suffix refuses every one of those applications at the front door,
		// which is an outage dressed as a security control. The upload
		// directory alone is equally ordinary, since every site serves images
		// out of one. Only together do they describe a file the site accepted
		// as data and is now being asked to execute.
		op: rx.MustNew(`/(uploads?|files?|media|attachments?|images?|img|avatars?|tmp|temp|user[-_]?content|wp-content/uploads)/` +
			`[^?#]*\.(php[345]?|phtml|asp[x]?|jsp[x]?|sh|py|pl|exe|cgi|htaccess)$`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Script execution from a user-content directory",
		tags: []string{"upload", "rce"},
	},

	// --------------------------------------------------------------------- rce
	{
		id: IDGoCode, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform:    decoded,
		op:       rx.MustNew(`(os/exec|net/http/httputil|reflect\.ValueOf|unsafe\.Pointer|go\s+func\()`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Potential Go code injection",
		tags: []string{"rce", "golang"},
	},
	{
		id: IDJavaClass, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform:    decoded,
		op:       rx.MustNew(`(runtime\.exec|java\.lang\.Runtime|java\.lang\.ProcessBuilder|javax\.crypto|javax\.script|ognl\.|java\.net\.URLClassLoader)`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Potential Java code injection",
		tags: []string{"rce", "java"},
	},
	{
		// Node.js RCE and sandbox escape. Sits beside the Go and Java injection
		// rules and, like them, matches only unambiguous constructs — never a
		// bare "process.env", which is a plain property access that appears in
		// documentation and config text. Every alternative here is a specific
		// dangerous shape: require of a shell/fs module, an invoked
		// child_process/exec primitive, the .constructor.constructor("...")()
		// escape out of a template or vm sandbox, and the mainModule.require
		// pivot from a leaked process object.
		id: IDNodeCode, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform:    decoded,
		op:       rx.MustNew(`(?i)(require\(\s*['"](child_process|fs)['"]\s*\)|child_process['"]?\s*\)?\s*\.\s*exec|\.constructor\.constructor\(|mainModule\.require|process\.mainModule|\bexecSync\(|\bspawnSync\()`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Potential Node.js code injection",
		tags: []string{"rce", "nodejs"},
	},
	{
		// Absolute paths to sensitive system files, in any request header.
		// gwaf's core rule 1003 already catches these in the URI and arguments;
		// this closes the header surface (Referer, X-Forwarded-For) the fast
		// path used to scan. The literals have no benign reading in a header, so
		// there is no false-positive cost to the added surface.
		id: IDSensitiveFileHeader, phase: types.PhaseRequestHeaders,
		targets: []types.Target{
			{Kind: types.TargetRequestHeaders}, {Kind: types.TargetRequestHeaderNames},
		},
		xform: norm,
		op: op.ContainsAny(
			"/etc/passwd", "/etc/shadow", "/proc/self/environ",
			"/windows/system32/config", ".ssh/id_rsa", ".aws/credentials",
		),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Access to sensitive system file via header",
		tags: []string{"lfi"},
	},
	{
		id: IDShellshock, phase: types.PhaseRequestHeaders,
		targets: []types.Target{
			{Kind: types.TargetRequestHeaders}, {Kind: types.TargetRequestHeaderNames},
			{Kind: types.TargetArgs}, {Kind: types.TargetArgNames},
		},
		xform:    decoded,
		op:       rx.MustNew(`\(\)\s*\{\s*[:;\s]*\}`),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Shellshock attempt (CVE-2014-6271)",
		tags: []string{"rce", "cve-2014-6271"},
	},
	{
		id: IDCommandSeparator, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    norm,
		op:       rx.MustNew(`(?:;|\||&|\$|\n|\r)\s*(?:cat|ls|id|whoami|pwd|uname|netcat|nc|curl|wget|bash|sh|zsh|powershell|cmd\.exe)\b`),
		severity: types.SeverityCritical, conf: types.Medium,
		msg:  "Generic command injection attempt",
		tags: []string{"rce"},
	},
	{
		id: IDTraversalArgName, phase: types.PhaseRequestBody, targets: tArgNames,
		xform:    decoded,
		op:       op.Contains("../"),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Path traversal in a parameter or file name (CVE-2023-50164)",
		tags: []string{"rce", "cve-2023-50164"},
	},
	{
		// Low, by measurement: the pattern is any "${...}" or "#{...}", which is
		// also how a CMS template, a shell snippet and a GraphQL variable are
		// written. It matched 1.5% of the benign calibration corpus, above the
		// 1% a Medium rule is allowed.
		id: IDExpressionLanguage, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    decoded,
		op:       rx.MustNew(`(?:#|\$)\{.*\}`),
		severity: types.SeverityCritical, conf: types.Low,
		msg:  "Expression-language injection attempt (CVE-2022-22947)",
		tags: []string{"rce", "cve-2022-22947"},
	},
	{
		id: IDGoAnywhere, phase: types.PhaseRequestHeaders, targets: tURI,
		xform:    norm,
		op:       op.Contains("/goanywhere/licensing/accept"),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Fortra GoAnywhere MFT RCE attempt (CVE-2023-0669)",
		tags: []string{"rce", "cve-2023-0669"},
	},
	{
		id: IDText4Shell, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    norm,
		op:       rx.MustNew(`\$\{(?:script|dns|url):`),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Text4Shell RCE attempt (CVE-2022-42889)",
		tags: []string{"rce", "cve-2022-42889"},
	},
	{
		id: IDFollina, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    norm,
		op:       rx.MustNew(`ms-msdt:/id\s+it_browseforfile`),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Follina RCE attempt (CVE-2022-30190)",
		tags: []string{"rce", "cve-2022-30190"},
	},
	{
		// Low, by measurement: a commit message or a README quoting "; make" or
		// "| python" is ordinary on a webhook. It matched 1.07% of the benign
		// calibration corpus, above the 1% a Medium rule is allowed.
		id: IDShellBuiltin, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    norm,
		op:       rx.MustNew("(?:;|\\||&|\\$|\n|\r|`)\\s*(?:env|set|export|eval|exec|system|passthru|shell_exec|base64|python|perl|ruby|php|gcc|make|apt-get|yum|dnf)\\b"),
		severity: types.SeverityCritical, conf: types.Low,
		msg:  "Advanced shell injection attempt",
		tags: []string{"rce"},
	},
	// The body half of IDShellshock. That rule runs at the header phase, where
	// no body has been read, so on its own it sees only the query string and a
	// CGI host is exploitable by POST while Shellshock reads as covered.
	//
	// It is unconditional, and that is its cost: the pattern is all
	// metacharacters, so rx extracts no literal to prefilter on -- `\(\)` yields
	// "()", below rx's three-character floor -- and the rule runs on every body
	// in its phase. Narrowing the pattern to earn a literal is worse than the
	// cost: "(){" and "() {" are extractable but "()  {" and "()\t{" are equally
	// valid Shellshock, so the rule would stop firing with nothing to say it
	// had. An embedder with no CGI behind it should leave this one out.
	{
		id: IDShellshockBody, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    decoded,
		op:       rx.MustNew(`\(\)\s*\{\s*[:;\s]*\}`),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Shellshock attempt (CVE-2014-6271) (body)",
		tags: []string{"rce", "cve-2014-6271"},
	},

	// -------------------------------------------------------------------- sqli
	{
		id: IDSQLTimeDelay, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform:    norm,
		op:       rx.MustNew(`(sleep\(|benchmark\(|pg_sleep\(|dbms_lock\.sleep\(|waitfor\s+delay)`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Time-based blind SQL injection attempt",
		tags: []string{"sqli"},
	},
	{
		id: IDSQLSchemaEnum, phase: types.PhaseRequestBody, targets: tArgs,
		xform:    norm,
		op:       rx.MustNew(`(information_schema\.|sys\.tables|sys\.objects|pg_catalog\.|mysql\.db|@@version)`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "SQL schema enumeration attempt",
		tags: []string{"sqli"},
	},
	{
		id: IDSQLTautology, phase: types.PhaseRequestBody, targets: tArgs,
		xform: norm,
		// Only the explicit tautology forms. Bare "--", "#" and "/*" appear in
		// ordinary text too often to match on, and the structural SQLi detector
		// in core covers the comment-terminator bypass without that cost.
		op:       rx.MustNew(`'?\s+or\s+('?1'?\s*=\s*'?1|true)`),
		severity: types.SeverityCritical, conf: types.Medium,
		msg:  "SQL injection authentication bypass attempt",
		tags: []string{"sqli"},
	},
	{
		id: IDMOVEitHeader, phase: types.PhaseRequestHeaders, targets: header("X-siis-session-id"),
		op:       present("moveit-session-header"),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "MOVEit Transfer SQLi attempt (CVE-2023-34362)",
		tags: []string{"sqli", "cve-2023-34362"},
	},

	// --------------------------------------------------------------------- xss
	{
		id: IDXSSTagOrHandler, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform:    norm,
		op:       rx.MustNew(`(<script|on(load|error|click|mouseover|focus|submit|keydown|change)\s*=)`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Cross-site scripting attempt",
		tags: []string{"xss"},
	},
	{
		id: IDXSSObfuscated, phase: types.PhaseRequestBody, targets: tArgs,
		xform:    norm,
		op:       rx.MustNew(`(string\.fromcharcode|eval\(.*atob\(|eval\(.*base64|document\.write\(|unescape\()`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Obfuscated cross-site scripting attempt",
		tags: []string{"xss"},
	},

	// --------------------------------------------------------------- injection
	{
		id: IDNoSQLOperator, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    decoded,
		op:       rx.MustNew(`(\$where|\$gt|\$ne|\$lt|\$in|\$nin|\$exists|\$regex)`),
		severity: types.SeverityCritical, conf: types.Medium,
		msg:  "NoSQL injection attempt",
		tags: []string{"attack-nosql"},
	},
	{
		id: IDPrototypeChain, phase: types.PhaseRequestBody, targets: tArgsNamesBody,
		xform:    decoded,
		op:       op.ContainsAny("constructor[prototype]", ".prototype."),
		severity: types.SeverityCritical, conf: types.Medium,
		msg:  "Advanced prototype pollution attempt",
		tags: []string{"generic"},
	},
	{
		id: IDInternalAddress, phase: types.PhaseRequestBody, targets: tArgs,
		xform: norm,
		op: op.ContainsAny("127.0.0.1", "localhost", "169.254.169.254",
			"metadata.google.internal", "kubernetes.default.svc"),
		severity: types.SeverityCritical, conf: types.Medium,
		msg:  "SSRF attempt against an internal target",
		tags: []string{"attack-ssrf"},
	},

	// ----------------------------------------------------------------- malware
	{
		id: IDUploadExecutableExt, phase: types.PhaseRequestBody, targets: tFileNames,
		xform:    norm,
		op:       rx.MustNew(`\.(exe|php|phtml|sh|py|pl|rb|jsp|asp|aspx)$`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Suspicious file upload extension",
		tags: []string{"malware", "upload"},
	},
	{
		id: IDPDFJavaScript, phase: types.PhaseRequestBody, targets: tArgs,
		op:       rx.MustNew(`%PDF-1\.[0-7].*obj.*<<.*/JS.*>>.*endobj`),
		severity: types.SeverityError, conf: types.High,
		msg:  "PDF containing JavaScript",
		tags: []string{"malware", "upload"},
	},
	{
		id: IDRansomwareExt, phase: types.PhaseRequestBody, targets: tFileNames,
		xform: norm,
		op: rx.MustNew(
			`\.(locky|crypt|wncry|cryptolocker|zepto|aesir|thor|lockbit|clop|conti|ryuk|cerber|gandcrab|pysa)$`),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Ransomware file extension",
		tags: []string{"ransomware"},
	},
	{
		id: IDWebShellName, phase: types.PhaseRequestHeaders, targets: tPath,
		xform:    norm,
		op:       rx.MustNew(`/(c99|r57|sh3ll|weevely|pas|cmd|shell|backdoor|tunnel|proxy)\.(php|asp|aspx|jsp|pl|py|sh|cgi)`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Web shell filename requested",
		tags: []string{"malware", "rce"},
	},
	{
		id: IDRansomNote, phase: types.PhaseRequestHeaders, targets: tPath,
		xform:    norm,
		op:       rx.MustNew(`(read_me|decrypt_files|your_files_are_encrypted|recover_files|readme_for_decrypt)\.(txt|html|htm|png)`),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Ransomware note filename requested",
		tags: []string{"ransomware"},
	},
	{
		id: IDRansomKeywords, phase: types.PhaseRequestBody, targets: tArgs,
		xform: norm,
		// Deliberately Low confidence. These are ordinary words on a news site
		// or a payments API, so the rule is here for an embedder who wants it
		// and is dropped at every minimum above Low.
		op:       op.ContainsAny("ransom", "bitcoin", ".onion", "cryptolocker"),
		severity: types.SeverityWarning, conf: types.Low,
		msg:  "Ransomware keywords in a file upload",
		tags: []string{"ransomware"},
	},
	{
		id: IDCryptoMiner, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform: norm,
		op: op.ContainsAny("coinhive.min.js", "authedmine.min.js", "cryptonight.wasm",
			"monerominer", "miner.start"),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Cryptocurrency miner script detected",
		tags: []string{"attack-malware"},
	},
	{
		id: IDWPPluginPHP, phase: types.PhaseRequestHeaders, targets: tPath,
		xform:    norm,
		op:       rx.MustNew(`/wp-content/plugins/.*\.php`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "WordPress plugin execution attempt",
		tags: []string{"wordpress"},
	},
	{
		id: IDWPEnumeration, phase: types.PhaseRequestHeaders, targets: tPath,
		xform:    norm,
		op:       rx.MustNew(`(wp-json/wp/v2/users|wp-links-opml\.php|wp-config-sample\.php|wp-content/debug\.log|readme\.html|license\.txt|wp-content/uploads/.*\.php)`),
		severity: types.SeverityError, conf: types.High,
		msg:  "WordPress enumeration or information leak attempt",
		tags: []string{"wordpress"},
	},

	// ----------------------------------------------------------------- scanner
	{
		id: IDScannerUserAgent, phase: types.PhaseRequestHeaders, targets: header("User-Agent"),
		xform: norm,
		op: op.ContainsAny("nikto", "sqlmap", "acunetix", "nessus", "openvas", "arachni",
			"w3af", "dirbuster", "gobuster", "rustscan", "masscan", "zgrab",
			"nmap", "netsparker", "qualys", "censys", "shodan"),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Vulnerability scanner user agent",
		tags: []string{"scanner", "recon"},
	},
	{
		id: IDScannerHeader, phase: types.PhaseRequestHeaders, targets: tHeaderNames,
		xform: norm,
		op: op.ContainsAny("x-scanner", "acunetix-product", "acunetix-scanning-agreement",
			"nessus-check", "qualys-scan-as", "netsparker-scan-id"),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Vulnerability scanner header",
		tags: []string{"scanner"},
	},
	{
		id: IDWebShellProbe, phase: types.PhaseRequestHeaders, targets: tPath,
		xform:    norm,
		op:       rx.MustNew(`\b(shell|cmd|sh|bash|zsh|powershell|nc|netcat|web-shell|backdoor)\.(php|asp|aspx|jsp|sh|py|pl)\b`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Search for a common web shell or backdoor",
		tags: []string{"scanner", "rce"},
	},
	{
		id: IDSensitiveFileProbe, phase: types.PhaseRequestHeaders, targets: tPath,
		xform: norm,
		op: op.ContainsAny("/.env", "/.git", "/.vscode", "/.idea",
			"/docker-compose.yml", "/config.php.bak"),
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Sensitive file discovery attempt",
		tags: []string{"scanner", "recon"},
	},
}
