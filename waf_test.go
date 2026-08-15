// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"fmt"
	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
	"sync"
	"sync/atomic"
)

// newWAF builds a WAF for tests, failing fast on a compile error.
func newWAF(t *testing.T, opts ...gwaf.Option) *gwaf.WAF {
	t.Helper()
	w, err := gwaf.New(opts...)
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	return w
}

// req describes a request for the table tests.
type req struct {
	method  string
	target  string
	headers map[string]string
	args    map[string]string
	body    string
}

// run drives a full request through a transaction and returns the decision.
func run(t *testing.T, w *gwaf.WAF, r req) gwaf.Decision {
	t.Helper()

	tx := w.NewTransaction()
	defer tx.Close()

	method := r.method
	if method == "" {
		method = "GET"
	}
	target := r.target
	if target == "" {
		target = "/"
	}

	tx.SetRequestLine(method, target, "HTTP/1.1")
	tx.SetRemoteAddr("192.0.2.1")
	for k, v := range r.headers {
		tx.AddRequestHeader(k, v)
	}
	for k, v := range r.args {
		tx.AddArgument(k, v)
	}

	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return d
	}
	if r.body != "" {
		tx.SetRequestBody([]byte(r.body))
	}
	return tx.ProcessRequestBody()
}

// TestZeroConfigBlocksAttacks is the contract from CLAUDE.md §2b: gwaf.New()
// with no arguments must be a working, blocking firewall. A library that needs
// configuration before it protects anything ships inert.
func TestZeroConfigBlocksAttacks(t *testing.T) {
	w := newWAF(t)

	attacks := []struct {
		name string
		req  req
	}{
		{"sqli union in arg", req{args: map[string]string{"id": "1 UNION SELECT password FROM users"}}},
		{"sqli tautology", req{args: map[string]string{"id": "1' OR 1=1--"}}},
		{"sqli stacked drop", req{args: map[string]string{"q": "x'; DROP TABLE users"}}},
		{"xss script tag", req{args: map[string]string{"q": "<script>alert(1)</script>"}}},
		{"traversal encoded", req{target: "/files?path=..%2f..%2fetc%2fpasswd"}},
		{"traversal in path", req{target: "/static/../../etc/passwd"}},
		{"sensitive file", req{args: map[string]string{"f": "/etc/passwd"}}},
		{"shell injection", req{args: map[string]string{"host": "127.0.0.1; cat /etc/hosts"}}},
		{"php wrapper", req{args: map[string]string{"page": "php://filter/read=convert.base64-encode"}}},
		{"scanner ua", req{headers: map[string]string{"User-Agent": "sqlmap/1.7.2#stable"}}},
		{"sqli in body", req{method: "POST", body: "q=1 UNION ALL SELECT NULL"}},
		{"xss in body", req{method: "POST", body: `{"c":"<script>x</script>"}`}},
	}

	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			d := run(t, w, tt.req)
			if !d.Blocked() {
				t.Errorf("attack not blocked: verdict=%v score=%d rule=%d",
					d.Verdict(), d.Score(), d.RuleID())
			}
			// Every block must be explainable, or it is a block that gets
			// disabled the first time someone has to debug it.
			if d.RuleID() == 0 {
				t.Error("blocked without attributing a rule")
			}
			if d.Message() == "" {
				t.Error("blocked without a message")
			}
		})
	}
}

// TestCLIOptionInjectionEndToEnd drives the CLI argument-injection payloads
// through a zero-config WAF, proving the whole path — prefilter nomination on
// the "name=" literal, operator scan, and a block at the default confidence —
// not just the detector in isolation. A backend that splices an attacker value
// in as a separate argv element of git, ssh, tar or rsync runs each of these.
func TestCLIOptionInjectionEndToEnd(t *testing.T) {
	w := newWAF(t)

	blocked := []struct {
		name string
		arg  string
	}{
		{"git core.sshCommand", "-c core.sshCommand=id"},
		{"git upload-pack", "--upload-pack=id"},
		{"ssh ProxyCommand spaced", "-o ProxyCommand=id"},
		{"ssh ProxyCommand glued", "-oProxyCommand=id;"},
		{"tar checkpoint-action", "--checkpoint=1 --checkpoint-action=exec=sh x.sh"},
		{"info-zip unzip-command", "--unzip-command=id"},
		// Percent-encoded spaces, the shape CVE-2023-45878 used: the rule's
		// transform chain decodes before the detector reads, so the "name=" is
		// still seen. Value is one arg the application would hand to a shell.
		{"encoded proxycommand", "-o%20ProxyCommand=id"},
	}
	for _, tt := range blocked {
		t.Run("blocks/"+tt.name, func(t *testing.T) {
			d := run(t, w, req{args: map[string]string{"repo": tt.arg}})
			if !d.Blocked() {
				t.Errorf("not blocked: verdict=%v score=%d rule=%d arg=%q",
					d.Verdict(), d.Score(), d.RuleID(), tt.arg)
			}
			if d.RuleID() == 0 || d.Message() == "" {
				t.Errorf("blocked without attribution: rule=%d msg=%q", d.RuleID(), d.Message())
			}
		})
	}

	// Benign traffic that carries option-shaped values, prose with the option
	// words, and fields that merely end in the same bytes. Not one may block:
	// a single new false positive switches the whole firewall off.
	pass := []struct {
		name string
		req  req
	}{
		{"plain flags", req{args: map[string]string{"q": "--verbose -o output.txt"}}},
		{"git commit line", req{args: map[string]string{"cmd_help": `git commit -m "fix the bug"`}}},
		{"webpack config flag", req{args: map[string]string{"build": "--config webpack.config.js"}}},
		{"sort param", req{args: map[string]string{"sort": "-created_at"}}},
		{"array param", req{target: "/list?page%5Bsize%5D=20"}},
		{"filter param", req{args: map[string]string{"filter": "active"}}},
		{"equation", req{args: map[string]string{"formula": "e=mc2"}}},
		{"negative number", req{args: map[string]string{"delta": "-42"}}},
		{"iso date", req{args: map[string]string{"since": "2026-08-05T07:38:00Z"}}},
		{"uuid", req{args: map[string]string{"id": "550e8400-e29b-41d4-a716-446655440000"}}},
		{"base64 padded", req{args: map[string]string{"token": "YWRtaW46cGFzc3dvcmQ="}}},
		{"jwt with dashes", req{args: map[string]string{"t": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.a-b_c"}}},
		{"git editor config", req{args: map[string]string{"opt": "core.editor=vim"}}},
		{"field ends in Command", req{args: map[string]string{"getProxyCommand": "1"}}},
		{"utm params", req{args: map[string]string{"utm_source": "google", "utm_medium": "cpc"}}},
		{"checkpoint prose", req{args: map[string]string{"note": "we reached a checkpoint in the deploy"}}},
		{"proxy prose", req{args: map[string]string{"msg": "upload your proxy settings first"}}},
		{"receive-pack prose", req{args: map[string]string{"doc": "the receive-pack docs are unclear"}}},
		{"filename with dashes", req{args: map[string]string{"file": "my-report-2026-final.pdf"}}},
		{"docker run", req{args: map[string]string{"run": "docker run -e NODE_ENV=production -p 8080:80 app"}}},
		{"makefile line", req{method: "POST", body: `{"line":"CFLAGS = -O2 -Wall"}`}},
		{"json config body", req{method: "POST", body: `{"editor":"core.editor=nano","theme":"dark"}`}},
		{"semver", req{args: map[string]string{"v": "1.2.3-beta.4+build.567"}}},
		{"hex hash", req{args: map[string]string{"etag": "d41d8cd98f00b204e9800998ecf8427e"}}},
		{"proxy field name", req{args: map[string]string{"proxycommand": "enabled"}}}, // name w/o "=" value
	}
	for _, tt := range pass {
		t.Run("passes/"+tt.name, func(t *testing.T) {
			d := run(t, w, tt.req)
			if d.Blocked() {
				t.Errorf("FALSE POSITIVE: rule=%d msg=%q verdict=%v",
					d.RuleID(), d.Message(), d.Verdict())
			}
		})
	}
}

// TestBenignTrafficPasses is the other half of the contract. A detector that
// blocks everything passes any recall-only test, so false positives are checked
// with the same weight as detection.
func TestBenignTrafficPasses(t *testing.T) {
	w := newWAF(t)

	benign := []struct {
		name string
		req  req
	}{
		{"root", req{}},
		{"api path", req{target: "/api/v1/orders/12345"}},
		{"query args", req{target: "/search?q=golang+web+framework", args: map[string]string{"q": "golang web framework"}}},
		{"normal ua", req{headers: map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}}},
		{"json body", req{method: "POST", body: `{"name":"Alice","qty":3,"note":"please deliver before 5pm"}`}},
		{"form body", req{method: "POST", body: "email=user%40example.com&subject=Hello+there"}},
		{"relative link arg", req{args: map[string]string{"next": "/dashboard/settings"}}},
		{"uuid arg", req{args: map[string]string{"id": "550e8400-e29b-41d4-a716-446655440000"}}},
		{"iso timestamp", req{args: map[string]string{"since": "2026-08-05T07:38:00Z"}}},
		{"base64 arg", req{args: map[string]string{"t": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"}}},
		{"prose with apostrophe", req{method: "POST", body: `{"c":"it's a great product, I'd buy again"}`}},
		{"sql word in prose", req{method: "POST", body: `{"c":"we should select a new union representative"}`}},
		{"path with dots in filename", req{target: "/assets/app.min.v2.js"}},
		{"encoded space", req{args: map[string]string{"q": "hello%20world"}}},
		{"accept header", req{headers: map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9"}}},
	}

	for _, tt := range benign {
		t.Run(tt.name, func(t *testing.T) {
			d := run(t, w, tt.req)
			if d.Blocked() {
				t.Errorf("false positive: rule=%d msg=%q score=%d",
					d.RuleID(), d.Message(), d.Score())
			}
		})
	}
}

// TestBenignTrafficEvaluatesZeroRules is the performance thesis as a test. If
// the prefilter works, benign traffic reaches no operator at all; a drift above
// zero here is the leading indicator that latency is about to regress.
func TestBenignTrafficEvaluatesZeroRules(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/api/v1/orders/12345", "HTTP/1.1")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
	tx.AddRequestHeader("Accept", "application/json")
	tx.AddArgument("page", "2")

	d := tx.ProcessRequestHeaders()
	if d.Blocked() {
		t.Fatalf("benign request blocked: %v", d.Message())
	}
	if got := tx.RulesEvaluated(); got != 0 {
		t.Errorf("RulesEvaluated() = %d, want 0: the prefilter is not filtering", got)
	}
}

func TestDetectionOnlyDoesNotBlock(t *testing.T) {
	w := newWAF(t, gwaf.WithMode(gwaf.DetectionOnly))

	d := run(t, w, req{args: map[string]string{"id": "1 UNION SELECT x"}})
	if d.Blocked() {
		t.Error("detection-only mode blocked a request")
	}
	// The detection itself must still be reported, or the mode is useless for
	// the rollout it exists to support.
	if d.RuleID() == 0 {
		t.Error("detection-only mode lost the rule attribution")
	}
}

func TestPhaseShortCircuit(t *testing.T) {
	w := newWAF(t)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/?x=1", "HTTP/1.1")
	tx.AddRequestHeader("User-Agent", "sqlmap/1.7")

	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		t.Fatal("scanner user-agent not blocked at header phase")
	}
	// Blocking at the header phase is what lets a caller skip reading the body
	// off the socket entirely.
	if d.Reason() != gwaf.ReasonRule {
		t.Errorf("Reason() = %v, want ReasonRule", d.Reason())
	}
}

func TestCustomRule(t *testing.T) {
	custom := rules.Set{{
		ID:         1_000_001,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetRequestHeaders, Name: "X-Api-Key"}},
		Op:         op.Equals("forbidden-key"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "Revoked API key",
	}}

	w := newWAF(t, gwaf.WithRuleset(custom))

	d := run(t, w, req{headers: map[string]string{"X-Api-Key": "forbidden-key"}})
	if !d.Blocked() {
		t.Fatal("custom rule did not block")
	}
	if d.RuleID() != 1_000_001 {
		t.Errorf("RuleID() = %d, want 1000001", d.RuleID())
	}

	if d := run(t, w, req{headers: map[string]string{"X-Api-Key": "valid-key"}}); d.Blocked() {
		t.Error("custom rule blocked a valid key")
	}
}

func TestAnomalyThreshold(t *testing.T) {
	// Two scoring rules, each below the threshold alone but blocking together.
	set := rules.Set{
		{
			ID:         1_000_010,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetArgs}},
			Op:         op.Contains("alpha"),
			Actions:    []rules.Action{rules.ScoreBy(3)},
			Severity:   types.SeverityWarning,
			Confidence: types.Certain,
			Msg:        "alpha",
		},
		{
			ID:         1_000_011,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetArgs}},
			Op:         op.Contains("beta"),
			Actions:    []rules.Action{rules.ScoreBy(3)},
			Severity:   types.SeverityWarning,
			Confidence: types.Certain,
			Msg:        "beta",
		},
	}

	w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set), gwaf.WithThreshold(5))

	if d := run(t, w, req{args: map[string]string{"q": "alpha"}}); d.Blocked() {
		t.Errorf("single hit (score 3) blocked below threshold 5")
	}
	d := run(t, w, req{args: map[string]string{"q": "alpha and beta"}})
	if !d.Blocked() {
		t.Errorf("two hits (score 6) did not reach threshold 5, score=%d", d.Score())
	}
	if d.Reason() != gwaf.ReasonThreshold {
		t.Errorf("Reason() = %v, want ReasonThreshold", d.Reason())
	}
}

func TestConfidenceSelection(t *testing.T) {
	set := rules.Set{{
		ID:         1_000_020,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         op.Contains("maybe-bad"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityError,
		Confidence: types.Low,
		Msg:        "low confidence heuristic",
	}}

	// A Low-confidence rule must not run under the default High policy.
	strict := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if d := run(t, strict, req{args: map[string]string{"q": "maybe-bad"}}); d.Blocked() {
		t.Error("Low confidence rule ran under the default High minimum")
	}

	// Lowering the minimum admits it.
	loose := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set),
		gwaf.WithMinConfidence(types.Low))
	if d := run(t, loose, req{args: map[string]string{"q": "maybe-bad"}}); !d.Blocked() {
		t.Error("Low confidence rule did not run at MinConfidence(Low)")
	}
}

// TestParanoiaLevelCompat checks the CRS compatibility mapping, which is what
// lets an existing deployment's paranoia setting carry over.
func TestParanoiaLevelCompat(t *testing.T) {
	set := rules.Set{{
		ID:         1_000_030,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         op.Contains("pl3-only"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityError,
		Confidence: types.Low, // PL3 tier
		Msg:        "pl3 rule",
	}}

	pl1 := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set), gwaf.WithParanoiaLevel(1))
	if d := run(t, pl1, req{args: map[string]string{"q": "pl3-only"}}); d.Blocked() {
		t.Error("PL3-tier rule ran at paranoia level 1")
	}

	pl3 := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set), gwaf.WithParanoiaLevel(3))
	if d := run(t, pl3, req{args: map[string]string{"q": "pl3-only"}}); !d.Blocked() {
		t.Error("PL3-tier rule did not run at paranoia level 3")
	}
}

func TestLimitsRejectOversizedBody(t *testing.T) {
	w := newWAF(t, gwaf.WithLimits(gwaf.Limits{MaxBodySize: 64}))

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/upload", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(strings.Repeat("a", 128)))

	d := tx.ProcessRequestBody()
	if !d.Blocked() {
		t.Error("oversized body not rejected under fail-closed")
	}
	if d.Reason() != gwaf.ReasonLimit {
		t.Errorf("Reason() = %v, want ReasonLimit", d.Reason())
	}
}

func TestFailOpenPermitsOnLimit(t *testing.T) {
	w := newWAF(t,
		gwaf.WithLimits(gwaf.Limits{MaxBodySize: 64}),
		gwaf.WithFailMode(gwaf.FailOpen),
	)

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("POST", "/upload", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte(strings.Repeat("a", 128)))

	d := tx.ProcessRequestBody()
	if d.Blocked() {
		t.Error("fail-open still blocked on a limit breach")
	}
	// Fail-open must stay loud: the reason distinguishes "analysed and clean"
	// from "could not analyse and chose to allow".
	if d.Reason() != gwaf.ReasonLimit {
		t.Errorf("Reason() = %v, want ReasonLimit", d.Reason())
	}
}

func TestFuelExhaustionIsDeterministic(t *testing.T) {
	// A tiny budget guarantees exhaustion, and fuel being deterministic means
	// this reproduces identically every run — which a wall-clock budget could
	// not do.
	w := newWAF(t, gwaf.WithFuelLimit(1))

	var first gwaf.Decision
	for i := range 20 {
		tx := w.NewTransaction()
		tx.SetRequestLine("GET", "/?q=test", "HTTP/1.1")
		tx.AddArgument("q", strings.Repeat("payload ", 100))
		d := tx.ProcessRequestHeaders()
		tx.Close()

		if i == 0 {
			first = d
			if d.Reason() != gwaf.ReasonBudget {
				t.Fatalf("Reason() = %v, want ReasonBudget", d.Reason())
			}
			if !d.Blocked() {
				t.Fatal("fail-closed did not block on budget exhaustion")
			}
			continue
		}
		if d.Reason() != first.Reason() || d.Verdict() != first.Verdict() {
			t.Fatalf("run %d diverged: got (%v,%v), want (%v,%v)",
				i, d.Verdict(), d.Reason(), first.Verdict(), first.Reason())
		}
	}
}

func TestOnDecisionCallback(t *testing.T) {
	var got []gwaf.Decision
	w := newWAF(t, gwaf.OnDecision(func(d gwaf.Decision) { got = append(got, d) }))

	run(t, w, req{args: map[string]string{"id": "1 UNION SELECT x"}})

	if len(got) != 1 {
		t.Fatalf("callback invoked %d times, want 1", len(got))
	}
	if !got[0].Blocked() {
		t.Error("callback received a non-blocking decision")
	}
}

func TestSwapRuleset(t *testing.T) {
	w := newWAF(t, gwaf.WithoutCoreRuleset())

	if d := run(t, w, req{args: map[string]string{"q": "trigger"}}); d.Blocked() {
		t.Fatal("empty ruleset blocked a request")
	}

	rs, err := w.Compile(rules.Set{{
		ID:         1_000_040,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         op.Contains("trigger"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "swapped in",
	}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	w.SwapRuleset(rs)

	if d := run(t, w, req{args: map[string]string{"q": "trigger"}}); !d.Blocked() {
		t.Error("swapped ruleset did not take effect")
	}
}

// TestNoGlobalState verifies that independent instances stay independent. This
// is what makes multi-tenant embedding and parallel tests work, and it cannot
// be retrofitted once violated.
func TestNoGlobalState(t *testing.T) {
	strict := newWAF(t)
	permissive := newWAF(t, gwaf.WithoutCoreRuleset())

	attack := req{args: map[string]string{"id": "1 UNION SELECT x"}}

	if d := run(t, strict, attack); !d.Blocked() {
		t.Error("strict instance did not block")
	}
	if d := run(t, permissive, attack); d.Blocked() {
		t.Error("permissive instance blocked; instances are sharing state")
	}
	if d := run(t, strict, attack); !d.Blocked() {
		t.Error("strict instance stopped blocking after the permissive one ran")
	}
}

func TestConcurrentTransactions(t *testing.T) {
	w := newWAF(t)

	const goroutines = 32
	const iterations = 100

	errs := make(chan string, goroutines)
	done := make(chan struct{})

	for g := range goroutines {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for range iterations {
				// Alternate attack and benign traffic so a shared-state bug
				// shows up as a wrong verdict rather than only as a race.
				if g%2 == 0 {
					d := run(t, w, req{args: map[string]string{"id": "1 UNION SELECT x"}})
					if !d.Blocked() {
						errs <- "attack allowed under concurrency"
						return
					}
				} else {
					d := run(t, w, req{args: map[string]string{"q": "ordinary search text"}})
					if d.Blocked() {
						errs <- "benign blocked under concurrency"
						return
					}
				}
			}
		}(g)
	}

	for range goroutines {
		<-done
	}
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

func TestCompileReport(t *testing.T) {
	w := newWAF(t)
	r := w.Report()

	if r.Rules == 0 {
		t.Fatal("report has no rules")
	}
	if r.Literals == 0 {
		t.Error("report has no literals; the prefilter would be empty")
	}
	// The core ruleset is written to be fully prefilterable. If that stops
	// being true, every request pays for it and the report is where it shows.
	if len(r.Unconditional) != 0 {
		t.Errorf("core ruleset has %d unconditional rules: %+v",
			len(r.Unconditional), r.Unconditional)
	}
	if r.Prefiltered != r.Rules {
		t.Errorf("Prefiltered = %d, want %d (all rules)", r.Prefiltered, r.Rules)
	}
}

func TestUnconditionalRuleIsReported(t *testing.T) {
	w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{{
		ID:         1_000_050,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         op.Func("always", func([]byte) bool { return false }),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityNotice,
		Confidence: types.Certain,
		Msg:        "unconditional",
	}}))

	r := w.Report()
	if len(r.Unconditional) != 1 {
		t.Fatalf("Unconditional = %d, want 1", len(r.Unconditional))
	}
	u := r.Unconditional[0]
	if u.ID != 1_000_050 {
		t.Errorf("ID = %d, want 1000050", u.ID)
	}
	// The report must say why, or "unconditional" is not actionable.
	if u.Reason == "" {
		t.Error("unconditional rule reported without a reason")
	}
}

// TestFuncWithLiteralsIsPrefiltered verifies the documented escape hatch: a
// predicate that can honestly declare its required literals gets prefiltered
// like any built-in operator.
func TestFuncWithLiteralsIsPrefiltered(t *testing.T) {
	hinted := op.Func("graphql-introspection", func(v []byte) bool {
		return strings.Contains(string(v), "__schema")
	}).WithLiterals("__schema")

	w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{{
		ID:         1_000_060,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         hinted,
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityWarning,
		Confidence: types.Certain,
		Msg:        "introspection query",
	}}))

	if r := w.Report(); len(r.Unconditional) != 0 {
		t.Errorf("hinted Func should be prefiltered, got %+v", r.Unconditional)
	}

	if d := run(t, w, req{args: map[string]string{"q": "{__schema{types{name}}}"}}); !d.Blocked() {
		t.Error("hinted Func rule did not match")
	}
	if d := run(t, w, req{args: map[string]string{"q": "{user{name}}"}}); d.Blocked() {
		t.Error("hinted Func rule matched unrelated input")
	}
}

func TestTransactionReuseIsClean(t *testing.T) {
	w := newWAF(t)

	// An attack followed by benign traffic on a pooled transaction: residue
	// from the first would show up as a false positive on the second.
	for range 50 {
		if d := run(t, w, req{args: map[string]string{"id": "1 UNION SELECT x"}}); !d.Blocked() {
			t.Fatal("attack not blocked")
		}
		if d := run(t, w, req{args: map[string]string{"q": "ordinary text"}}); d.Blocked() {
			t.Fatalf("pooled transaction leaked state: rule=%d score=%d",
				d.RuleID(), d.Score())
		}
	}
}

func TestDecisionCarriesMatchSpan(t *testing.T) {
	w := newWAF(t)

	d := run(t, w, req{args: map[string]string{"id": "1 UNION SELECT x"}})
	if !d.Blocked() {
		t.Fatal("not blocked")
	}
	span, ok := d.MatchedSpan()
	if !ok {
		t.Fatal("blocked decision carries no match span")
	}
	if span.Len == 0 {
		t.Error("match span is empty")
	}
	if d.Target().Kind == types.TargetInvalid {
		t.Error("decision does not identify the matched target")
	}
}

// TestMediumTierIsOptInAndReachable is the safety property behind the whole
// confidence axis, asserted through behaviour rather than through a rule count.
//
// ruleset/core may now carry Medium rules; the engine's minimum confidence is
// High, so they are dropped at compile time and gwaf.New() never blocks on one.
// That is what makes an opt-in tier safe to ship.
//
// Both halves matter. If the default starts blocking these, an embedder who
// wrote gwaf.New() and read "blocks safely by default" got a wider net than they
// asked for. If the Medium WAF does not block them, the tier is decoration and
// the dial does nothing.
func TestMediumTierIsOptInAndReachable(t *testing.T) {
	def := newWAF(t)
	wide := newWAF(t, gwaf.WithMinConfidence(types.Medium))

	// Each is real structure scoring below the default bar: a tautology with
	// nothing attached, a scheme with no handler behind it, an executing call
	// with no surrounding PHP. Each is also a shape ordinary data takes, which
	// is exactly why the default declines to block it.
	for _, value := range []string{
		"1=1",
		"javascript:foo",
		"system('id')",
	} {
		if blocked(t, def, value) {
			t.Errorf("gwaf.New() blocked %q; the default tier must not act on "+
				"Medium-confidence structure", value)
		}
		if !blocked(t, wide, value) {
			t.Errorf("WithMinConfidence(Medium) did not block %q; the tier is "+
				"unreachable and the dial does nothing", value)
		}
	}
}

// blocked runs one value through a WAF as a query argument.
func blocked(t *testing.T, w *gwaf.WAF, value string) bool {
	t.Helper()
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/", "HTTP/1.1")
	tx.AddArgument("q", value)
	return tx.ProcessRequestBody().Blocked()
}

// TestInertOriginRulesAreAnnounced covers the upgrade cliff created in v0.4.1.
//
// The off-origin rules report nothing when no origins are declared, which is the
// safe direction and the fix for a real bypass. The failure mode it creates is a
// user one: an embedder upgrading from v0.4.0 keeps a ruleset that compiles,
// passes its tests, and quietly stops covering a whole OWASP category.
//
// Losing coverage must never be quieter than gaining it.
func TestInertOriginRulesAreAnnounced(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if _, err := gwaf.New(gwaf.WithLogger(logger)); err != nil {
		t.Fatalf("New: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "WithOrigins") {
		t.Errorf("no warning naming the fix when origins are unset; got %q", got)
	}

	buf.Reset()
	if _, err := gwaf.New(gwaf.WithLogger(logger), gwaf.WithOrigins("shop.example.com")); err != nil {
		t.Fatalf("New(origins): %v", err)
	}
	if s := buf.String(); strings.Contains(s, "WithOrigins") {
		t.Errorf("warned despite configured origins: %q", s)
	}
}

// TestSwapRulesetUnderLoad is the hot-reload safety claim, asserted.
//
// waf.go states it plainly: "ruleset is swapped atomically so a reload never
// exposes a partially applied plan. In-flight transactions finish against the
// plan they started with, which keeps audit logs reconstructable."
//
// That was a documented invariant with no test. TestConcurrentTransactions
// hammers a *fixed* ruleset and TestSwapRuleset swaps a *quiet* one; nothing
// swapped while requests were in flight, which is the only situation hot reload
// exists for. Every other documented-but-unenforced invariant probed in this
// repository turned out to be broken, so this one is measured rather than
// believed.
//
// # What is actually asserted
//
// Two rulesets that disagree: A blocks "alpha" and ignores "beta", B the
// reverse. A request carrying one of them must come back with one of exactly
// two answers -- blocked by the rule that owns it, or not blocked at all --
// and never with the *other* ruleset's rule ID, which is what a torn read
// would produce.
//
// The rule IDs are what make a mixture visible. A verdict alone could not
// distinguish "swapped between phases" from "corrupt plan"; the ID says which
// plan answered.
//
// Run under -race, which `make check` does, so a torn pointer is caught even in
// the runs where the timing does not produce a wrong answer.
func TestSwapRulesetUnderLoad(t *testing.T) {
	const (
		idAlpha = 1_000_050
		idBeta  = 1_000_051
	)
	mk := func(id types.RuleID, literal, msg string) rules.Set {
		return rules.Set{{
			ID:         id,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetArgs}},
			Op:         op.Contains(literal),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        msg,
		}}
	}

	w := newWAF(t, gwaf.WithoutCoreRuleset())
	rsA, err := w.Compile(mk(idAlpha, "alpha", "blocks alpha"))
	if err != nil {
		t.Fatalf("Compile A: %v", err)
	}
	rsB, err := w.Compile(mk(idBeta, "beta", "blocks beta"))
	if err != nil {
		t.Fatalf("Compile B: %v", err)
	}
	w.SwapRuleset(rsA)

	// Which rule ID is legitimate for which payload. Anything else is a plan
	// that answered for a value it does not contain a rule for.
	owner := map[string]types.RuleID{"alpha": idAlpha, "beta": idBeta}

	const (
		workers    = 24
		iterations = 400
	)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	swapped := make(chan struct{})
	bad := make(chan string, workers*4)

	// The swapper runs for the whole test, alternating as fast as it can so a
	// transaction is overwhelmingly likely to straddle one. It is not in the
	// worker WaitGroup: it outlives them by design and is stopped afterwards.
	//
	// swaps is counted and asserted below. A concurrency test that finishes
	// before the thing it races with has started is a test that passes without
	// exercising anything, which is worse than no test at all.
	var swaps atomic.Int64
	go func() {
		defer close(swapped)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				w.SwapRuleset(rsA)
			} else {
				w.SwapRuleset(rsB)
			}
			swaps.Add(1)
		}
	}()

	for g := range workers {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			payload := "alpha"
			if g%2 == 1 {
				payload = "beta"
			}
			want := owner[payload]
			for range iterations {
				tx := w.NewTransaction()
				tx.SetRequestLine("GET", "/x", "HTTP/1.1")
				tx.SetRemoteAddr("192.0.2.1")
				tx.AddArgument("q", payload)
				d := tx.ProcessRequestHeaders()
				if d.Blocked() && d.RuleID() != want {
					bad <- fmt.Sprintf("payload %q blocked by rule %d, "+
						"which belongs to the other ruleset: the plan was read torn",
						payload, d.RuleID())
				}
				tx.Close()
			}
		}(g)
	}

	// Workers first, then stop the swapper and let it drain.
	wg.Wait()
	close(stop)
	<-swapped
	close(bad)

	for msg := range bad {
		t.Error(msg)
	}

	// The premise, checked rather than assumed: a concurrency test that finishes
	// before the thing it races with has started passes without exercising
	// anything.
	//
	// The floor is deliberately far below what a quiet machine produces
	// (hundreds of thousands) rather than tied to the transaction count. How
	// much CPU the swapper wins against twenty-four workers is a property of
	// the host, and an assertion that tracks it fails on a busy machine while
	// saying nothing about the code -- the same mistake bench-guard exists to
	// prevent for benchmarks.
	const minSwaps = 1000
	if n := swaps.Load(); n < minSwaps {
		t.Errorf("only %d swaps against %d transactions: the swapper barely ran, "+
			"so this did not test the overlap it claims to",
			n, workers*iterations)
	} else {
		t.Logf("%d swaps across %d transactions", n, workers*iterations)
	}
}
