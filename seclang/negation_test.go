// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package seclang_test

import (
	"strings"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/seclang"
)

// TestNegatedRegexSurvivesGeneration is the regression for the worst defect this
// converter has had.
//
// generate.go rendered every *regexOperator as seclang.MustRegex(pattern),
// discarding Negated(). A "!@rx" rule therefore came back as its own opposite,
// and CRS 920600 -- "block unless the Accept header is well formed" -- became
// "block when the Accept header is well formed". A converted CRS answered 403 to
// every request, including GET /health with no arguments, which is the outage
// the WAF is supposed to prevent.
//
// The test goes through Generate deliberately. Parse alone was always correct,
// so a test that stopped at the rules.Set passed while the emitted source was
// inverted.
func TestNegatedRegexSurvivesGeneration(t *testing.T) {
	const src = `SecRule ARGS:mode "!@rx ^(?:read|write)$" "id:1,phase:2,deny,msg:'bad mode'"`

	set, rep, err := seclang.Parse("t.conf", []byte(src), seclang.Options{
		DefaultConfidence: seclang.High,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 {
		t.Fatalf("negated @rx did not translate: %s", rep)
	}

	out, err := seclang.Generate("x", set, rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "MustRegexNegated(") {
		t.Error("generated source dropped the negation; the rule now means its opposite")
	}

	// And the behaviour, not just the spelling: the rule must fire on a value
	// the pattern does NOT match, and stay silent on one it does.
	waf, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode      string
		wantBlock bool
	}{
		{"read", false},
		{"write", false},
		{"delete", true},
	} {
		tx := waf.NewTransaction()
		// No query string: a negated rule fires on any value in the target that
		// fails the pattern, so a stray second ARGS:mode would block regardless.
		tx.SetRequestLine("GET", "/", "HTTP/1.1")
		tx.AddArgument("mode", tc.mode)
		got := tx.ProcessRequestBody().Blocked()
		if got != tc.wantBlock {
			t.Errorf("mode=%q blocked=%v, want %v", tc.mode, got, tc.wantBlock)
		}
		tx.Close()
	}
}

// TestNegationIsNeverSilentlyDropped: the operators that build a positive match
// from their argument cannot carry a "!", and importing them without it inverts
// the rule. CRS uses every one of these forms.
func TestNegationIsNeverSilentlyDropped(t *testing.T) {
	for _, tc := range []struct{ name, rule string }{
		{"within", `SecRule REQUEST_METHOD "!@within GET POST" "id:1,phase:1,deny"`},
		{"streq", `SecRule ARGS:a "!@streq expected" "id:1,phase:2,deny"`},
		{"beginsWith", `SecRule REQUEST_URI "!@beginsWith /api" "id:1,phase:1,deny"`},
		{"pm", `SecRule ARGS:a "!@pm alpha beta" "id:1,phase:2,deny"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, rep, err := seclang.Parse("t.conf", []byte(tc.rule), seclang.Options{
				DefaultConfidence: seclang.High,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(set) != 0 {
				t.Fatalf("!@%s imported without its negation, inverting the rule", tc.name)
			}
			if len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0].Why, "invert") {
				t.Errorf("skip does not explain the inversion risk: %s", rep)
			}
		})
	}
}

// TestNegatedEndsWithStillMeansNot covers the other operator that reaches the
// regex engine with a negation, so it travels the same rendering path as @rx.
func TestNegatedEndsWithStillMeansNot(t *testing.T) {
	const src = `SecRule ARGS:file "!@endsWith .pdf" "id:1,phase:2,deny"`

	set, rep, err := seclang.Parse("t.conf", []byte(src), seclang.Options{
		DefaultConfidence: seclang.High,
	})
	if err != nil || len(set) != 1 {
		t.Fatalf("set=%d err=%v rep=%s", len(set), err, rep)
	}

	waf, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(set))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		file      string
		wantBlock bool
	}{
		{"report.pdf", false},
		{"shell.php", true},
	} {
		tx := waf.NewTransaction()
		tx.SetRequestLine("GET", "/", "HTTP/1.1")
		tx.AddArgument("file", tc.file)
		if got := tx.ProcessRequestBody().Blocked(); got != tc.wantBlock {
			t.Errorf("file=%q blocked=%v, want %v", tc.file, got, tc.wantBlock)
		}
		tx.Close()
	}
}
