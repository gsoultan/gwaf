// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package leaks

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/op/rx"
	"github.com/gsoultan/gwaf/types"
)

// Rule IDs. They sit in the first-party optional-bundle range (docs/RULES.md
// §7) and are stable: an embedder's exceptions and audit history refer to them.
const (
	// Credentials and regulated data in a response.
	IDCardNumber        types.RuleID = 110001
	IDUSSocialSecurity  types.RuleID = 110002
	IDAWSAccessKey      types.RuleID = 110003
	IDGoogleAPIKey      types.RuleID = 110004
	IDSlackWebhook      types.RuleID = 110005
	IDGitHubPAT         types.RuleID = 110006
	IDGoogleOAuthSecret types.RuleID = 110007
	IDStripeLiveKey     types.RuleID = 110008
	IDGitHubToken       types.RuleID = 110009
	IDGitHubFinePAT     types.RuleID = 110010
	IDOpenAIKey         types.RuleID = 110011
	IDAnthropicKey      types.RuleID = 110012
	IDSlackToken        types.RuleID = 110013
	IDSendGridKey       types.RuleID = 110014
	IDTwilioSID         types.RuleID = 110015
	IDNPMToken          types.RuleID = 110016
	IDPyPIToken         types.RuleID = 110017
	IDGCPServiceAccount types.RuleID = 110018
	IDAzureStorageKey   types.RuleID = 110019
	IDDatabaseURI       types.RuleID = 110020
	IDPuTTYKey          types.RuleID = 110021
	IDPrivateKey        types.RuleID = 110022

	// Structural disclosure in a response.
	IDGoPanic         types.RuleID = 110101
	IDPythonTraceback types.RuleID = 110102
	IDJavaStackTrace  types.RuleID = 110103
	IDPHPError        types.RuleID = 110104
	IDDotNetException types.RuleID = 110105
	IDRubyBacktrace   types.RuleID = 110106
	IDDatabaseError   types.RuleID = 110107

	// Credentials arriving in a request.
	IDInboundPrivateKeyPEM   types.RuleID = 111001
	IDInboundAWSAccessKey    types.RuleID = 111002
	IDInboundStripeLiveKey   types.RuleID = 111003
	IDInboundGitHubPAT       types.RuleID = 111004
	IDInboundGitHubToken     types.RuleID = 111005
	IDInboundGitHubFinePAT   types.RuleID = 111006
	IDInboundOpenAIKey       types.RuleID = 111007
	IDInboundAnthropicKey    types.RuleID = 111008
	IDInboundSlackToken      types.RuleID = 111009
	IDInboundSlackWebhook    types.RuleID = 111010
	IDInboundGoogleAPIKey    types.RuleID = 111011
	IDInboundGoogleOAuth     types.RuleID = 111012
	IDInboundGCPServiceAcct  types.RuleID = 111013
	IDInboundAzureStorageKey types.RuleID = 111014
	IDInboundSendGridKey     types.RuleID = 111015
	IDInboundNPMToken        types.RuleID = 111016
	IDInboundPyPIToken       types.RuleID = 111017
	IDInboundPuTTYKey        types.RuleID = 111018
	IDInboundDBURICreds      types.RuleID = 111019
)

// Credential detectors, named because both directions use them.
//
// A response leaking an AWS key and a request carrying one are the same string
// found in two places, and writing the pattern twice is how the two copies come
// to disagree — one gets a new prefix, the other does not, and the gap is
// invisible until something walks out through it. One operator, two rules.
//
// Operators are stateless and already shared across every transaction
// evaluating a rule; sharing one across two rules is the same property.
var (
	opPrivateKeyPEM   = rx.MustNew(`-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`)
	opAWSAccessKey    = rx.MustNew(`\bAKIA[0-9A-Z]{16}\b`)
	opGoogleAPIKey    = rx.MustNew(`AIza[0-9A-Za-z\-_]{35}`)
	opSlackWebhook    = op.Contains("https://hooks.slack.com/services/")
	opGitHubPAT       = rx.MustNew(`ghp_[a-zA-Z0-9]{36}`)
	opGoogleOAuth     = rx.MustNew(`GOCSPX-[a-zA-Z0-9\-_]{28}`)
	opStripeLiveKey   = rx.MustNew(`\b[sr]k_live_[0-9a-zA-Z]{24,}`)
	opGitHubToken     = rx.MustNew(`\bgh[ousr]_[A-Za-z0-9]{36}\b`)
	opGitHubFinePAT   = rx.MustNew(`\bgithub_pat_[A-Za-z0-9_]{82}\b`)
	opOpenAIKey       = rx.MustNew(`\bsk-[A-Za-z0-9_-]{10,}T3BlbkFJ[A-Za-z0-9_-]{10,}`)
	opAnthropicKey    = rx.MustNew(`\bsk-ant-[a-z0-9]{3,}-[A-Za-z0-9_-]{80,}`)
	opSlackToken      = rx.MustNew(`\bxox[baprse]-[0-9A-Za-z-]{10,}`)
	opSendGridKey     = rx.MustNew(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`)
	opNPMToken        = rx.MustNew(`\bnpm_[A-Za-z0-9]{36}\b`)
	opPyPIToken       = rx.MustNew(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`)
	opGCPServiceAcct  = rx.MustNew(`"type"\s*:\s*"service_account"`)
	opAzureStorageKey = rx.MustNew(`\bAccountKey=[A-Za-z0-9+/]{86}==`)
	opPuTTYKey        = op.Contains("PuTTY-User-Key-File-")
	opDBURICreds      = rx.MustNew(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|clickhouse)` +
		`://[^\s:@/]{1,64}:[^\s:@/]{1,128}@`)
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

var (
	tRespBody = []types.Target{{Kind: types.TargetResponseBody}}
	tArgsBody = []types.Target{
		{Kind: types.TargetArgs},
		{Kind: types.TargetRequestBody},
	}
)

// Credentials returns the rules that find a credential, a card number or a US
// social security number in a response body.
//
// Each credential is recognised by an issuer-assigned prefix rather than by
// entropy, so a match is the credential and not a string that resembles one.
// They are response-phase rules and see only what the embedder passes to
// WriteResponseBody: give the transaction nothing and they report nothing.
//
// core.Default carries a PEM private key rule of its own. IDPrivateKey repeats
// it so that an embedder acting on this set by ID, to redact a credential
// where it would otherwise refuse the response, has every credential in one
// place and does not have to know which of them core happened to cover.
func Credentials() rules.Set { return render(credentialSpecs) }

// Disclosure returns the rules that find a stack trace or a database error in
// a response body.
//
// All are Confidence Medium, so the default minimum drops them: a site whose
// job is to display stack traces -- an error tracker, a CI dashboard, a paste
// service -- serves them legitimately.
func Disclosure() rules.Set { return render(disclosureSpecs) }

// Inbound returns the credential rules pointed at the request.
//
// They log and do not block. Refusing a POST because it contains a secret
// throws away what the user typed and teaches them to route around the WAF.
// They carry no card or social security number rule: outbound a card number is
// a leak, inbound it is a customer paying for something.
func Inbound() rules.Set { return render(inboundSpecs) }

// All returns Credentials, Disclosure and Inbound together.
func All() rules.Set {
	return append(append(Credentials(), Disclosure()...), Inbound()...)
}

var credentialSpecs = []spec{
	{
		id: IDCardNumber, phase: types.PhaseResponseBody, targets: tRespBody,
		// Issuer prefix, permitted length and Luhn together, rather than a
		// Visa-shaped regex, which misses every other brand and blocks on any
		// sixteen digits starting with a 4. See CardNumber.
		op: CardNumber(),
		// Certain, because the check digit has to agree: a
		// sixteen-digit string that carries an assigned prefix and validates
		// under Luhn is a card number, not a number that resembles one.
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Card number in response",
		tags: []string{"leak", "compliance"},
	},
	{
		id: IDUSSocialSecurity, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`\b\d{3}-\d{2}-\d{4}\b`),
		severity: types.SeverityCritical, conf: types.High,
		msg:  "US social security number in response",
		tags: []string{"leak", "compliance"},
	},
	{
		id: IDAWSAccessKey, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opAWSAccessKey,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "AWS access key in response",
		tags: []string{"leak"},
	},
	{
		id: IDGoogleAPIKey, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGoogleAPIKey,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Google API key in response",
		tags: []string{"leak"},
	},
	{
		id: IDSlackWebhook, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opSlackWebhook,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Slack webhook URL in response",
		tags: []string{"leak"},
	},
	{
		id: IDGitHubPAT, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGitHubPAT,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "GitHub personal access token in response",
		tags: []string{"leak"},
	},
	{
		id: IDGoogleOAuthSecret, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGoogleOAuth,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Google OAuth client secret in response",
		tags: []string{"leak"},
	},

	// The rest of what actually ends up in a response body: a payment
	// processor's live key, a git forge token, a model provider's key, a mail or
	// telephony key, a package registry token, a cloud service account, and a
	// database URI with the password still in it.
	{
		id: IDStripeLiveKey, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opStripeLiveKey,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Stripe live API key in response",
		tags: []string{"leak", "compliance"},
	},
	{
		// ghp_ has its own rule above; this covers the OAuth, user-to-server,
		// server-to-server and refresh prefixes, which leak from the same places
		// and were simply never listed.
		id: IDGitHubToken, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGitHubToken,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "GitHub token in response",
		tags: []string{"leak"},
	},
	{
		id: IDGitHubFinePAT, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGitHubFinePAT,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "GitHub fine-grained personal access token in response",
		tags: []string{"leak"},
	},
	{
		// T3BlbkFJ is "OpenAI" in base64 and sits in the middle of every key the
		// provider issues, which is what makes this specific rather than a match
		// on any sk- prefixed string.
		id: IDOpenAIKey, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opOpenAIKey,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "OpenAI API key in response",
		tags: []string{"leak"},
	},
	{
		id: IDAnthropicKey, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opAnthropicKey,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Anthropic API key in response",
		tags: []string{"leak"},
	},
	{
		id: IDSlackToken, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opSlackToken,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Slack token in response",
		tags: []string{"leak"},
	},
	{
		id: IDSendGridKey, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opSendGridKey,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "SendGrid API key in response",
		tags: []string{"leak"},
	},
	{
		// Account SID and API key SID share a shape: two fixed letters and 32
		// hex. That is the weakest signal of any credential rule here — a hex
		// digest preceded by those letters matches, and the alternation leaves
		// the prefilter no literal to skip on, so the rule runs over every
		// inspected response body. Medium for both reasons: it is the one
		// detector in this group whose false positive is plausible, and a
		// default-confidence ruleset should not pay for a rule the prefilter
		// cannot skip.
		id: IDTwilioSID, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`\b(?:AC|SK)[0-9a-f]{32}\b`),
		severity: types.SeverityCritical, conf: types.Medium,
		msg:  "Twilio account or API key SID in response",
		tags: []string{"leak"},
	},
	{
		id: IDNPMToken, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opNPMToken,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "npm access token in response",
		tags: []string{"leak"},
	},
	{
		id: IDPyPIToken, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opPyPIToken,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "PyPI upload token in response",
		tags: []string{"leak"},
	},
	{
		// The private key inside a service-account file is caught by 1130002;
		// this catches the file itself, including the copies that have had the
		// key stripped but still carry the client id and project.
		id: IDGCPServiceAccount, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGCPServiceAcct,
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Google Cloud service account key in response",
		tags: []string{"leak"},
	},
	{
		id: IDAzureStorageKey, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opAzureStorageKey,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Azure storage account key in response",
		tags: []string{"leak"},
	},
	{
		// A connection string with the password still in it is the leak that
		// costs the most and looks the most ordinary — it arrives in a config
		// dump, a health endpoint or an error page, and reads as a URL.
		id: IDDatabaseURI, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opDBURICreds,
		severity: types.SeverityCritical, conf: types.High,
		msg:  "Database connection string with credentials in response",
		tags: []string{"leak"},
	},
	{
		// The PEM rule above covers OPENSSH and every other "BEGIN ... PRIVATE
		// KEY" banner. PuTTY's format does not use one.
		id: IDPuTTYKey, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opPuTTYKey,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "PuTTY private key in response",
		tags: []string{"leak"},
	},
	{
		id: IDPrivateKey, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opPrivateKeyPEM,
		severity: types.SeverityCritical, conf: types.Certain,
		msg:  "Private key in response",
		tags: []string{"leak"},
	},
}

var disclosureSpecs = []spec{
	// Structural disclosure: a stack trace or a database error page. These leak
	// far more often than a card number does and are what the CRS RESPONSE-950
	// family covers — file paths, framework versions, query fragments and the
	// shape of the schema, all of which are reconnaissance for the next request.
	//
	// Medium, unlike the credential rules, because the false positive is real
	// and specific: a site whose job is to display stack traces — an error
	// tracker, a CI dashboard, a paste service, documentation — is serving them
	// legitimately.
	{
		id: IDGoPanic, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`goroutine \d+ \[[a-z ]+\]:`),
		severity: types.SeverityError, conf: types.Medium,
		msg:  "Go panic stack trace in response",
		tags: []string{"leak", "disclosure"},
	},
	{
		id: IDPythonTraceback, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       op.Contains("Traceback (most recent call last):"),
		severity: types.SeverityError, conf: types.Medium,
		msg:  "Python traceback in response",
		tags: []string{"leak", "disclosure"},
	},
	{
		id: IDJavaStackTrace, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`\bat [a-zA-Z_$][\w$]*(?:\.[\w$]+)+\([\w$]+\.java:\d+\)`),
		severity: types.SeverityError, conf: types.Medium,
		msg:  "Java stack trace in response",
		tags: []string{"leak", "disclosure"},
	},
	{
		id: IDPHPError, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`(?:Fatal error|Parse error|Warning|Notice):[^\n]{0,200}? in [^\n]{0,200}? on line \d+`),
		severity: types.SeverityError, conf: types.Medium,
		msg:  "PHP error with source path in response",
		tags: []string{"leak", "disclosure", "php"},
	},
	{
		id: IDDotNetException, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`\bSystem\.[A-Za-z0-9.]+Exception\b[^\n]{0,200}?\bat [A-Za-z0-9_.<>]+\(`),
		severity: types.SeverityError, conf: types.Medium,
		msg:  ".NET exception trace in response",
		tags: []string{"leak", "disclosure"},
	},
	{
		id: IDRubyBacktrace, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`\.rb:\d+:in `),
		severity: types.SeverityError, conf: types.Medium,
		msg:  "Ruby backtrace in response",
		tags: []string{"leak", "disclosure"},
	},
	{
		// Literals rather than a pattern: each of these is a database engine
		// naming itself in an error it should never have shown a client, and a
		// literal set gives the compiler something to prefilter on.
		id: IDDatabaseError, phase: types.PhaseResponseBody, targets: tRespBody,
		op: op.ContainsAny(
			"You have an error in your SQL syntax",
			"Unclosed quotation mark after the character string",
			"SQLSTATE[",
			"SQLiteException",
			"psycopg2.",
			"Npgsql.",
			"org.postgresql.util.PSQLException",
			"com.mysql.jdbc.exceptions",
			"Microsoft OLE DB Provider for SQL Server",
			"Warning: mysql_",
			"supplied argument is not a valid MySQL",
		),
		severity: types.SeverityError, conf: types.Medium,
		msg:  "Database engine error text in response",
		tags: []string{"leak", "disclosure"},
	},
}

var inboundSpecs = []spec{
	// The same credential detectors, pointed the other way: an engineer pasting
	// an AWS key into a support ticket, a private key attached to an issue, a
	// connection string typed into a chat app — all landing in a database, a
	// backup and a search index.
	//
	// They log rather than block, and redaction would be worse still: silently
	// altering what someone wrote is not a security control, it is data loss.
	// They are Certain, and scanning every request body is still a cost, which
	// is why this set is separate from the response-phase one.
	{
		id: IDInboundPrivateKeyPEM, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opPrivateKeyPEM,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "Private key sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundAWSAccessKey, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opAWSAccessKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "AWS access key sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundStripeLiveKey, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opStripeLiveKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "Stripe live API key sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundGitHubPAT, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGitHubPAT,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "GitHub personal access token sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundGitHubToken, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGitHubToken,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "GitHub token sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundGitHubFinePAT, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGitHubFinePAT,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "GitHub fine-grained personal access token sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundOpenAIKey, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opOpenAIKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "OpenAI API key sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundAnthropicKey, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opAnthropicKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "Anthropic API key sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundSlackToken, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opSlackToken,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "Slack token sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundSlackWebhook, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opSlackWebhook,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "Slack webhook URL sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundGoogleAPIKey, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGoogleAPIKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "Google API key sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundGoogleOAuth, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGoogleOAuth,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "Google OAuth client secret sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		// Finds a key file pasted into a field. It does not find a request whose
		// whole body is the key file: that body is parsed as JSON, and the
		// pattern spans a key and its value, which the parse separates.
		id: IDInboundGCPServiceAcct, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGCPServiceAcct,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "Google Cloud service account key sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundAzureStorageKey, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opAzureStorageKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "Azure storage account key sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundSendGridKey, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opSendGridKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "SendGrid API key sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundNPMToken, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opNPMToken,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "npm access token sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundPyPIToken, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opPyPIToken,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "PyPI upload token sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundPuTTYKey, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opPuTTYKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "PuTTY private key sent in a request",
		tags: []string{"leak", "inbound"},
	},
	{
		id: IDInboundDBURICreds, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opDBURICreds,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain,
		msg:  "Database connection string with credentials sent in a request",
		tags: []string{"leak", "inbound"},
	},
}
