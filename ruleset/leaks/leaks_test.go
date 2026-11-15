// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package leaks_test

import (
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/leaks"
	"github.com/gsoultan/gwaf/types"
)

// Every credential below is syntactically valid and none has ever been issued:
// the provider's own documentation example where one exists, and filler in the
// provider's alphabet where it does not.
//
// Each is spelled as a prefix concatenated with its body. Go folds that back to
// one constant, so the corpus is unchanged, but no single literal matches a
// provider pattern — which matters because a secret scanner cannot tell a
// credential detector's own test corpus from a leak, and blocks the push.
// Keep new fixtures in this shape.
const (
	fakeGitHubApp = "gho_" + "16C7e42F292c6912E7710c838347Ae178B4a"
	fakeGitHubSvc = "ghs_" + "16C7e42F292c6912E7710c838347Ae178B4a"
	// Exactly 82 characters after the prefix — the width GitHub issues and the
	// width the rule requires, so a shorter lookalike does not match.
	fakePAT       = "github_pat_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRST"
	fakeOpenAI    = "sk-proj-" + "abcdefghij1234567890T3BlbkFJabcdefghij1234567890"
	fakeAnthropic = "sk-ant-api03-" + "abcdefghijklmnopqrstuvwxyz0123456789" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-abcdefghij"
	fakeSlack = "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
	// 22 then 43, the two field widths SendGrid issues.
	fakeSendGrid = "SG." + "ABCDEFGHIJKLMNOPQRSTUV" + "." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
	fakeTwilio   = "AC" + "0123456789abcdef0123456789abcdef"
	// The API key shares the SID's body; only the prefix distinguishes them,
	// which is the whole of what the rule keys on.
	fakeTwilioKey = "SK" + "0123456789abcdef0123456789abcdef"
	fakeNPM       = "npm_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	fakePyPI      = "pypi-AgEIcHlwaS5vcmc" +
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	fakeAzureKey = "AccountKey=" +
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
		"abcdefghijklmnopqrstuvwx=="

	// Stripe's published documentation key. All four variants share one body,
	// which is exactly what makes the live/test and secret/publishable
	// distinctions the rule draws worth asserting.
	stripeBody     = "4eC39HqLyjWDarjtT1zdp7dc"
	fakeStripeLive = "sk_live_" + stripeBody
	fakeStripeRK   = "rk_live_" + stripeBody
	fakeStripeTest = "sk_test_" + stripeBody
	fakeStripePub  = "pk_live_" + stripeBody
)

// only builds an engine holding the single rule id, so a hit is that rule's.
func only(t *testing.T, id types.RuleID) *gwaf.WAF {
	t.Helper()
	var set rules.Set
	for _, r := range leaks.All() {
		if r.ID == id {
			set = append(set, r)
		}
	}
	if len(set) != 1 {
		t.Fatalf("rule %d: found %d times in leaks.All()", id, len(set))
	}
	w, err := gwaf.New(
		gwaf.WithoutCoreRuleset(),
		gwaf.WithRuleset(set),
		gwaf.WithMode(gwaf.DetectionOnly),
		gwaf.WithMinConfidence(types.Low),
	)
	if err != nil {
		t.Fatalf("rule %d: %v", id, err)
	}
	return w
}

// inResponse reports whether rule id matches a response carrying body.
func inResponse(w *gwaf.WAF, id types.RuleID, body string) bool {
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/api/x", "HTTP/1.1")
	tx.AddRequestHeader("Host", "app.example.com")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()
	tx.SetResponseStatus(200)
	tx.AddResponseHeader("Content-Type", "application/json")
	tx.ProcessResponseHeaders()
	tx.WriteResponseBody([]byte(body))
	tx.ProcessResponseBody()
	for _, m := range tx.Matches() {
		if m.RuleID == id {
			return true
		}
	}
	return false
}

// inRequest reports whether rule id matches a request carrying body as text.
func inRequest(w *gwaf.WAF, id types.RuleID, body string) (matched, blocked bool) {
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", "/tickets", "HTTP/1.1")
	tx.AddRequestHeader("Host", "app.example.com")
	tx.AddRequestHeader("Content-Type", "text/plain")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(body))
	d := tx.ProcessRequestBody()
	for _, m := range tx.Matches() {
		if m.RuleID == id {
			matched = true
		}
	}
	return matched, d.Blocked()
}

var responseCases = []struct {
	id     types.RuleID
	name   string
	hits   []string
	misses []string
}{
	{
		id: leaks.IDCardNumber, name: "card",
		hits:   []string{`{"pan":"4111111111111111"}`, "Paid with 5555 5555 5555 4444."},
		misses: []string{`{"total":4111.11}`, `{"order":"4000000000000000"}`, "1755678901234567"},
	},
	{
		id: leaks.IDUSSocialSecurity, name: "ssn",
		hits:   []string{`{"ssn":"123-45-6789"}`},
		misses: []string{"123456789", "2026-01-01", "12-345-6789"},
	},
	{
		id: leaks.IDAWSAccessKey, name: "aws",
		hits:   []string{`{"key":"` + "AKIA" + `IOSFODNN7EXAMPLE"}`},
		misses: []string{"AKIAshort", "akiaiosfodnn7example", "XAKIA" + "IOSFODNN7EXAMPLE"},
	},
	{
		id: leaks.IDGoogleAPIKey, name: "google-api-key",
		hits:   []string{`{"k":"` + "AIza" + `SyA12345678901234567890123456789012"}`},
		misses: []string{"AIzaShort", "aiza" + "SyA12345678901234567890123456789012"},
	},
	{
		id: leaks.IDSlackWebhook, name: "slack-webhook",
		hits:   []string{"https://hooks.slack.com" + "/services/T1/B2/xyz"},
		misses: []string{"https://slack.com/services", "hooks.slack.com"},
	},
	{
		id: leaks.IDGitHubPAT, name: "github-pat",
		hits:   []string{"ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"},
		misses: []string{"ghp_short", "ghp-abcdefghijklmnopqrstuvwxyz0123456789"},
	},
	{
		id: leaks.IDGoogleOAuthSecret, name: "google-oauth-secret",
		hits:   []string{"GOCSPX-" + "abcdefghijklmnopqrstuvwxyz12"},
		misses: []string{"GOCSPX-short", "gocspx-abcdefghijklmnopqrstuvwxyz12"},
	},
	{
		id: leaks.IDStripeLiveKey, name: "stripe",
		hits: []string{
			`{"key":"` + fakeStripeLive + `"}`,
			fakeStripeRK,
		},
		misses: []string{
			fakeStripeTest, // test keys are not a leak
			"sk_live_short",
			fakeStripePub, // publishable, by design public
		},
	},
	{
		id: leaks.IDGitHubToken, name: "github-token",
		hits:   []string{fakeGitHubApp, fakeGitHubSvc},
		misses: []string{"gho_tooshort", "ghx_16C7e42F292c6912E7710c838347Ae178B4a"},
	},
	{
		id: leaks.IDGitHubFinePAT, name: "github-fine-grained-pat",
		hits:   []string{fakePAT},
		misses: []string{"github_pat_tooshort", "github_pat_"},
	},
	{
		id: leaks.IDOpenAIKey, name: "openai",
		hits: []string{fakeOpenAI},
		misses: []string{
			// No T3BlbkFJ marker: an sk- prefix alone is not an OpenAI key.
			"sk-abcdefghijklmnopqrstuvwxyz1234567890",
			"sk-ant-api03-notopenai",
		},
	},
	{
		id: leaks.IDAnthropicKey, name: "anthropic",
		hits:   []string{fakeAnthropic},
		misses: []string{"sk-ant-api03-short", "sk-ant-"},
	},
	{
		id: leaks.IDSlackToken, name: "slack",
		hits:   []string{fakeSlack, "xoxp-123456789012-abcdefghijkl"},
		misses: []string{"xoxb-short", "xoxz-123456789012-abcdefghijkl"},
	},
	{
		id: leaks.IDSendGridKey, name: "sendgrid",
		hits:   []string{fakeSendGrid},
		misses: []string{"SG.tooshort.tooshort", "SG."},
	},
	{
		id: leaks.IDTwilioSID, name: "twilio",
		hits:   []string{fakeTwilio, fakeTwilioKey},
		misses: []string{"0123456789abcdef0123456789abcdef", "ACnothex"},
	},
	{
		id: leaks.IDNPMToken, name: "npm",
		hits:   []string{fakeNPM},
		misses: []string{"npm_short", "npmrc_abcdefghijklmnopqrstuvwxyz0123456789"},
	},
	{
		id: leaks.IDPyPIToken, name: "pypi",
		hits:   []string{fakePyPI},
		misses: []string{"pypi-AgEIcHlwaS5vcmc", "pypi-short"},
	},
	{
		id: leaks.IDGCPServiceAccount, name: "gcp-service-account",
		hits: []string{
			`{"type": "service_account", "project_id": "prod"}`,
			`{"type":"service_account"}`,
		},
		misses: []string{`{"type": "user_account"}`, `{"type": "service"}`},
	},
	{
		id: leaks.IDAzureStorageKey, name: "azure-storage-key",
		hits:   []string{fakeAzureKey},
		misses: []string{"AccountKey=short==", "AccountName=devstoreaccount1"},
	},
	{
		id: leaks.IDDatabaseURI, name: "db-connection-string",
		hits: []string{
			"postgres://app:s3cr3t@db.internal:5432/prod",
			"mongodb+srv://svc:hunter2@cluster0.example.net/app",
			"redis://default:p4ss@cache:6379",
		},
		misses: []string{
			"postgres://db.internal:5432/prod", // no credentials to leak
			"https://user:pass@example.com",    // not a database URI
			"postgres://app@db.internal:5432/prod",
		},
	},
	{
		id: leaks.IDPuTTYKey, name: "putty-key",
		hits:   []string{"PuTTY-User-Key-File-3: ssh-ed25519"},
		misses: []string{"PuTTY user guide", "putty-user-key-file"},
	},
	{
		id: leaks.IDGoPanic, name: "go-panic",
		hits:   []string{"panic: runtime error\n\ngoroutine 1 [running]:\nmain.main()"},
		misses: []string{"goroutines are cheap", "goroutine leak detected"},
	},
	{
		id: leaks.IDPythonTraceback, name: "python-traceback",
		hits:   []string{"Traceback (most recent call last):\n  File \"app.py\", line 3"},
		misses: []string{"traceback module", "Traceback:"},
	},
	{
		id: leaks.IDJavaStackTrace, name: "java-stack-trace",
		hits:   []string{"\tat com.example.svc.Handler.handle(Handler.java:42)"},
		misses: []string{"at com.example.svc.Handler.handle", "at Handler.java"},
	},
	{
		id: leaks.IDPHPError, name: "php-error",
		hits: []string{
			"Fatal error: Uncaught Error: Call to undefined function " +
				"foo() in /var/www/html/index.php on line 12",
		},
		misses: []string{"Fatal error: something went wrong", "on line 12"},
	},
	{
		id: leaks.IDDotNetException, name: "dotnet-exception",
		hits: []string{
			"System.NullReferenceException: Object reference not set. " +
				"at MyApp.Controllers.Home.Index(",
		},
		// Naming the exception type is not disclosing a trace; an API that
		// returns a typed error code should not block.
		misses: []string{"System.NullReferenceException", "catch (System.Exception)"},
	},
	{
		id: leaks.IDRubyBacktrace, name: "ruby-backtrace",
		hits:   []string{"app/controllers/users_controller.rb:12:in `index'"},
		misses: []string{"users_controller.rb", "config.rb:12"},
	},
	{
		id: leaks.IDDatabaseError, name: "sql-error-text",
		hits: []string{
			"You have an error in your SQL syntax; check the manual",
			"SQLSTATE[42S02]: Base table or view not found",
			"org.postgresql.util.PSQLException: ERROR: relation does not exist",
		},
		misses: []string{"SQL syntax highlighting", "SQLSTATE"},
	},
}

// TestResponseRulesDetectWhatTheyName runs each response rule alone, through a
// compiled engine, against a body it must catch and bodies it must not. Through
// the engine and not the operator directly, because a wrong literal hint leaves
// the operator correct and the rule dead.
func TestResponseRulesDetectWhatTheyName(t *testing.T) {
	t.Parallel()
	for _, tc := range responseCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := only(t, tc.id)
			for _, hit := range tc.hits {
				if !inResponse(w, tc.id, hit) {
					t.Errorf("rule %d missed %q", tc.id, truncate(hit))
				}
			}
			for _, miss := range tc.misses {
				if inResponse(w, tc.id, miss) {
					t.Errorf("rule %d fired on the benign %q", tc.id, truncate(miss))
				}
			}
		})
	}
}

func truncate(s string) string {
	if len(s) <= 60 {
		return s
	}
	return s[:57] + "..."
}

// TestEveryResponseRuleHasACase fails when a rule is added without payloads.
func TestEveryResponseRuleHasACase(t *testing.T) {
	covered := map[types.RuleID]bool{}
	for _, tc := range responseCases {
		covered[tc.id] = true
	}
	for _, r := range append(leaks.Credentials(), leaks.Disclosure()...) {
		if !covered[r.ID] {
			t.Errorf("rule %d (%s) has no test case", r.ID, r.Msg)
		}
		if r.Phase != types.PhaseResponseBody {
			t.Errorf("rule %d does not run at the response-body phase", r.ID)
		}
	}
}

// TestDisclosureIsBelowTheDefaultConfidence pins the gradient: a credential
// prefix is unambiguous, while a stack trace is something an error tracker or a
// CI dashboard serves for a living, so gwaf.New() with the whole package loaded
// must not block one.
func TestDisclosureIsBelowTheDefaultConfidence(t *testing.T) {
	for _, r := range leaks.Disclosure() {
		if r.Confidence >= types.High {
			t.Errorf("disclosure rule %d is %v; it would block at the default minimum", r.ID, r.Confidence)
		}
	}
	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(leaks.All()))
	if err != nil {
		t.Fatal(err)
	}
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/builds/42/log", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()
	tx.SetResponseStatus(200)
	tx.ProcessResponseHeaders()
	tx.WriteResponseBody([]byte("Traceback (most recent call last):\n  File \"app.py\", line 3"))
	if d := tx.ProcessResponseBody(); d.Blocked() {
		t.Errorf("a traceback in a response was blocked at the default confidence: %v", d)
	}
}

// TestInboundFindsSecretsAndNeverBlocks checks the request direction works and
// that it only records: refusing the POST throws away what the user typed.
func TestInboundFindsSecretsAndNeverBlocks(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		id      types.RuleID
		payload string
	}{
		{leaks.IDInboundPrivateKeyPEM, "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."},
		{leaks.IDInboundAWSAccessKey, "here is the key " + "AKIA" + "IOSFODNN7EXAMPLE, please try it"},
		{leaks.IDInboundStripeLiveKey, fakeStripeLive},
		{leaks.IDInboundGitHubPAT, "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"},
		{leaks.IDInboundGitHubToken, fakeGitHubApp},
		{leaks.IDInboundGitHubFinePAT, fakePAT},
		{leaks.IDInboundOpenAIKey, fakeOpenAI},
		{leaks.IDInboundAnthropicKey, fakeAnthropic},
		{leaks.IDInboundSlackToken, fakeSlack},
		{leaks.IDInboundSlackWebhook, "https://hooks.slack.com" + "/services/T00/B00/XXXX"},
		{leaks.IDInboundGoogleAPIKey, "AIza" + "SyA12345678901234567890123456789012"},
		{leaks.IDInboundGoogleOAuth, "GOCSPX-" + "abcdefghijklmnopqrstuvwxyz12"},
		// Pasted into a text field, which is how one arrives in a ticket. A
		// request whose whole body is the key file is parsed as JSON, and the
		// pattern spans a key and its value, so that form is not seen.
		{leaks.IDInboundGCPServiceAcct, `my key file: {"type": "service_account", "project_id": "prod"}`},
		{leaks.IDInboundAzureStorageKey, fakeAzureKey},
		{leaks.IDInboundSendGridKey, fakeSendGrid},
		{leaks.IDInboundNPMToken, fakeNPM},
		{leaks.IDInboundPyPIToken, fakePyPI},
		{leaks.IDInboundPuTTYKey, "PuTTY-User-Key-File-3: ssh-ed25519"},
		{leaks.IDInboundDBURICreds, "postgres://app:s3cr3t@db.internal:5432/prod"},
	} {
		w := only(t, tc.id)
		matched, _ := inRequest(w, tc.id, tc.payload)
		if !matched {
			t.Errorf("rule %d missed %q", tc.id, truncate(tc.payload))
		}
		if matched, _ := inRequest(w, tc.id, "please reset my password, my order is 4000123400001234"); matched {
			t.Errorf("rule %d fired on ordinary prose", tc.id)
		}
	}

	// The whole inbound set in a blocking engine still lets the request through.
	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(leaks.Inbound()))
	if err != nil {
		t.Fatal(err)
	}
	if _, blocked := inRequest(w, 0, "the key is "+"AKIA"+"IOSFODNN7EXAMPLE"); blocked {
		t.Error("an inbound secret blocked the request; these rules record and do not refuse")
	}
	if len(leaks.Inbound()) != 19 {
		t.Errorf("inbound set has %d rules; the table above covers 19", len(leaks.Inbound()))
	}
}

// TestNoInboundCardOrSocialSecurityRule pins the asymmetry: outbound a card
// number is a leak, inbound it is a customer paying for something.
func TestNoInboundCardOrSocialSecurityRule(t *testing.T) {
	w, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(leaks.Inbound()),
		gwaf.WithMode(gwaf.DetectionOnly))
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"card":"4111111111111111","cvv":"123"}`, `{"ssn":"123-45-6789"}`} {
		tx := w.NewTransaction()
		tx.SetRequestLine("POST", "/checkout", "HTTP/1.1")
		tx.AddRequestHeader("Content-Type", "application/json")
		tx.ProcessRequestHeaders()
		tx.SetRequestBody([]byte(body))
		tx.ProcessRequestBody()
		if n := len(tx.Matches()); n != 0 {
			t.Errorf("an inbound rule fired on %s", body)
		}
		tx.Close()
	}
}

// TestIDsAreInTheBundleRange checks every rule sits where docs/RULES.md says a
// first-party optional bundle does, with a message and a tag.
func TestIDsAreInTheBundleRange(t *testing.T) {
	seen := map[types.RuleID]bool{}
	for _, r := range leaks.All() {
		if seen[r.ID] {
			t.Errorf("rule %d appears twice", r.ID)
		}
		seen[r.ID] = true
		if r.ID.Namespace() != types.NamespaceBundle {
			t.Errorf("rule %d is in the %s range, want the optional-bundle range", r.ID, r.ID.Namespace())
		}
		if strings.TrimSpace(r.Msg) == "" || len(r.Tags) == 0 {
			t.Errorf("rule %d: needs a message and at least one tag", r.ID)
		}
	}
}

// TestSetsAreFresh pins that editing a returned set cannot change it for the
// next caller, which is what lets an embedder swap an action in place.
func TestSetsAreFresh(t *testing.T) {
	a := leaks.Inbound()
	a[0].Actions[0] = rules.Block
	a[0].Msg = "edited"
	if b := leaks.Inbound(); b[0].Msg == "edited" || b[0].Actions[0] == rules.Action(rules.Block) {
		t.Error("Inbound() returned shared state")
	}
}
