// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
)

// verdictOf runs one GET through the request phases and names the outcome:
// "allow", or the ID of the rule that blocked it.
func verdictOf(t *testing.T, w *gwaf.WAF, target string) string {
	t.Helper()
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRemoteAddr("192.0.2.1")
	tx.SetRequestLine("GET", target, "HTTP/1.1")
	tx.AddRequestHeader("Host", "app.example")
	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		d = tx.ProcessRequestBody()
	}
	if !d.Blocked() {
		return "allow"
	}
	return d.RuleID().String()
}

// TestAbsoluteFormIsJudgedAsOriginForm is the regression for absolute-form
// request targets (RFC 9112 §3.2.2), which a server must accept. Recorded as
// written, "GET http://app.example/index.php" carried an absolute URL ending in
// ".php" in REQUEST_URI, the core RFI rule (4014) read it as an inclusion, and
// every script page on a site was blocked for a client that used absolute
// form. The same request in origin form passed.
//
// The table is differential on purpose: absolute form must reach exactly the
// verdict origin form does, so the attack rows prove nothing was blinded and
// the benign rows prove nothing was invented.
func TestAbsoluteFormIsJudgedAsOriginForm(t *testing.T) {
	w := newWAF(t)
	paths := []struct {
		path   string
		attack bool
	}{
		{"/", false},
		{"/index.php", false},
		{"/c99.php", false},
		{"/wp-content/plugins/x.php", false},
		{"/app/login.jsp?next=/home", false},
		{"/default.aspx?id=7", false},
		{"/cgi-bin/status.cgi", false},
		{"/?callback=https://partner.example/hook", false},
		// Real inclusions, in the query, must still block in both forms.
		{"/index.php?page=http://evil.example/shell.php", true},
		{"/index.php?page=http://evil.example/shell.php%3F", true},
		{"/?file=ftp://evil.example/x.inc%00", true},
		// And path-shaped attacks must survive the rewrite.
		{"/.env", true},
		{"/.git/config", true},
		{"/x.php.bak", true},
		{"/../../etc/passwd", true},
		{"/?q=1'%20OR%20'1'='1", true},
	}
	prefixes := []string{"http://app.example", "https://app.example:8443", "HTTP://APP.EXAMPLE", "http://user@app.example"}
	for _, p := range paths {
		origin := verdictOf(t, w, p.path)
		if got := origin != "allow"; got != p.attack {
			t.Fatalf("%s in origin form: verdict %s; the table expects attack=%v", p.path, origin, p.attack)
		}
		for _, pre := range prefixes {
			if abs := verdictOf(t, w, pre+p.path); abs != origin {
				t.Errorf("%s%s: verdict %s, origin form %s", pre, p.path, abs, origin)
			}
		}
	}
}

// TestAbsoluteFormEmptyPathIsRoot covers the two absolute targets with no
// path, which RFC 9110 §4.2.3 resolves to "/".
func TestAbsoluteFormEmptyPathIsRoot(t *testing.T) {
	const id types.RuleID = 9_100_101
	w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{
		{ID: id, Phase: types.PhaseRequestHeaders, Targets: []types.Target{{Kind: types.TargetRequestPath}},
			Op: op.Equals("/"), Actions: []rules.Action{rules.Block}, Severity: types.SeverityCritical,
			Confidence: types.Certain, Msg: "root path"},
	}))
	for target, want := range map[string]types.RuleID{"http://app.example": id, "http://app.example?q=1": id} {
		if got := verdictOf(t, w, target); got != want.String() {
			t.Errorf("%s: verdict %s, want rule %s", target, got, want)
		}
	}
	// The query rule sees "/?q=1": block it alone, with the path rule off.
	w = newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{
		{ID: id + 1, Phase: types.PhaseRequestHeaders, Targets: []types.Target{{Kind: types.TargetRequestURI}},
			Op: op.Equals("/?q=1"), Actions: []rules.Action{rules.Block}, Severity: types.SeverityCritical,
			Confidence: types.Certain, Msg: "root with query"},
	}))
	if got := verdictOf(t, w, "http://app.example?q=1"); got != (id + 1).String() {
		t.Errorf("REQUEST_URI of http://app.example?q=1 is not /?q=1: verdict %s", got)
	}
}

// TestAbsoluteFormKeepsTheWireFormInRequestLine proves the scheme and
// authority are moved, not dropped: REQUEST_LINE still holds them.
func TestAbsoluteFormKeepsTheWireFormInRequestLine(t *testing.T) {
	const id types.RuleID = 9_100_111
	w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{{
		ID: id, Phase: types.PhaseRequestHeaders, Targets: []types.Target{{Kind: types.TargetRequestLine}},
		Op: op.Equals("GET http://app.example/x.php HTTP/1.1"), Actions: []rules.Action{rules.Block},
		Severity: types.SeverityCritical, Confidence: types.Certain, Msg: "wire line",
	}}))
	if got := verdictOf(t, w, "http://app.example/x.php"); got != id.String() {
		t.Errorf("REQUEST_LINE lost the absolute target: verdict %s", got)
	}
}

// TestAbsoluteFormMatchesAClosedSchema: a path that began "http:" matched no
// declared operation, so a closed schema refused every absolute-form request.
func TestAbsoluteFormMatchesAClosedSchema(t *testing.T) {
	api := newShadowSchema(t)
	api.Closed()
	w := newWAF(t, gwaf.WithSchema(api))
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "http://app.example/api/v1/orders", "HTTP/1.1")
	if tx.UndeclaredRoute() {
		t.Error("an absolute-form request for a declared operation was reported undeclared")
	}
	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		t.Errorf("a closed schema blocked an absolute-form request for a declared operation: %v", d)
	}
}

// TestNonAbsoluteTargetsAreRecordedAsSent guards the other direction: only
// "scheme://" is rewritten. A target with no leading slash, or a network-path
// "//host/x", reaches path rules exactly as it arrived.
func TestNonAbsoluteTargetsAreRecordedAsSent(t *testing.T) {
	const id types.RuleID = 9_100_121
	for _, target := range []string{"../etc/passwd", "//evil.example/x.php", "*", "1http://x/y", "http:/x", "mailto:a@b"} {
		w := newWAF(t, gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{{
			ID: id, Phase: types.PhaseRequestHeaders, Targets: []types.Target{{Kind: types.TargetRequestPath}},
			Op: op.Equals(target), Actions: []rules.Action{rules.Block}, Severity: types.SeverityCritical,
			Confidence: types.Certain, Msg: "as sent",
		}}))
		if got := verdictOf(t, w, target); got != id.String() {
			t.Errorf("%q was not recorded as sent: verdict %s", target, got)
		}
	}
}
