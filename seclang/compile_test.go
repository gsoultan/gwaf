// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package seclang_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/seclang"
)

// TestRequestLineTargetGetsTheWholeLine pins the fix for a bridge bug that made
// every request through the CRS bridge score 3.
//
// CRS 920100 is a *negated* match against the full "METHOD URI PROTOCOL" form:
// it fires when the start line does not look like a request line. The bridge
// used to hand it REQUEST_URI, so the regex could never match, the negation
// always fired, and "Invalid HTTP Request Line" was reported for every request
// ever seen — including the legitimate one an adopter sent in that found this.
//
// Both halves are asserted, because pointing the rule at the right bytes and
// pointing it at nothing look identical from the passing side.
func TestRequestLineTargetGetsTheWholeLine(t *testing.T) {
	// CRS 920100 verbatim, including the (?i) — an earlier draft of this test
	// dropped it, required a lowercase method, and "fired" on every input,
	// which looked exactly like the bug it was meant to catch.
	const conf = `SecRule REQUEST_LINE "!@rx (?i)^(?:connect (?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}\.?(?::[0-9]+)?|[\--9A-Z_a-z]+:[0-9]+)|options \*|[a-z]{3,10}[\s\x0b]+(?:[0-9A-Z_a-z]{3,7}?://[\--9A-Z_a-z]*(?::[0-9]+)?)?/[^#\?]*(?:\?[^\s\x0b#]*)?(?:#[^\s\x0b]*)?)[\s\x0b]+[\.-9A-Z_a-z]+$" \
	"id:920100,phase:1,block,t:none,msg:'Invalid HTTP Request Line'"`

	set, _, err := seclang.Parse("test.conf", []byte(conf), seclang.Options{
		DefaultConfidence: seclang.High,
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	w, err := gwaf.New(gwaf.WithRuleset(set))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// Asserted on whether the rule *matched*, not on whether the request was
	// blocked. 920100 is a scoring rule and one match does not reach the anomaly
	// threshold on its own, so a Blocked() assertion passes for both a rule that
	// works and a rule that was silenced — which is the failure this test exists
	// to detect.
	check := func(method, target, proto string) bool {
		tx := w.NewTransaction()
		defer tx.Close()
		tx.SetRequestLine(method, target, proto)
		tx.SetRemoteAddr("192.0.2.1")
		tx.AddRequestHeader("Host", "api.example.com")
		tx.ProcessRequestHeaders()
		for _, m := range tx.Matches() {
			if m.RuleID == 920100 {
				return true
			}
		}
		return false
	}

	// Well-formed lines must not fire. The first is the adopter's request.
	for _, c := range [][3]string{
		{"GET", "/v1/employees/dcf182f8-8fb0-11f1-a210-063287ecf782", "HTTP/1.1"},
		{"POST", "/v1/employees/dcf182f8-8fb0-11f1-a210-063287ecf782", "HTTP/1.1"},
		{"PUT", "/api/v1/users", "HTTP/1.1"},
		{"GET", "/", "HTTP/1.0"},
	} {
		if check(c[0], c[1], c[2]) {
			t.Errorf("well-formed request line reported as invalid: %q %q %q", c[0], c[1], c[2])
		}
	}

	// And a malformed one must still fire, or the rule was merely silenced.
	for _, c := range [][3]string{
		{"GET", "not-a-path", "HTTP/1.1"},
		{"G", "/x", "HTTP/1.1"},
		{"GET", "/x", ""},
	} {
		if !check(c[0], c[1], c[2]) {
			t.Errorf("malformed request line not reported: %q %q %q", c[0], c[1], c[2])
		}
	}
}
