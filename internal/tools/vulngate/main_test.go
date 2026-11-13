// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import (
	"strings"
	"testing"
)

const cfg = `{"config":{"scanner_name":"govulncheck"}}` + "\n"

func osv(id string) string { return `{"osv":{"id":"` + id + `","summary":"s"}}` + "\n" }

func calledFinding(id, fixed string) string {
	return `{"finding":{"osv":"` + id + `","fixed_version":"` + fixed +
		`","trace":[{"module":"m","version":"v1","function":"F"}]}}` + "\n"
}

func importedFinding(id string) string {
	return `{"finding":{"osv":"` + id + `","trace":[{"module":"m","version":"v1","package":"p"}]}}` + "\n"
}

func TestJudge(t *testing.T) {
	allowEcho := map[string]string{"GO-1": "unused middleware default, no fix"}
	cases := []struct {
		name     string
		input    string
		allow    map[string]string
		problems []string // substrings, in order
		wantErr  bool
	}{
		{"clean scan", cfg, nil, nil, false},
		{"called finding fails", cfg + osv("GO-9") + calledFinding("GO-9", "v2"), nil,
			[]string{"GO-9: s"}, false},
		{"imported-only finding passes, as govulncheck ./... does", cfg + importedFinding("GO-9"), nil, nil, false},
		{"excepted finding without a fix passes", cfg + calledFinding("GO-1", ""), allowEcho, nil, false},
		{"excepted finding with a fix fails", cfg + calledFinding("GO-1", "v4.17.0"), allowEcho,
			[]string{"GO-1: a fix now exists (v4.17.0)"}, false},
		{"stale exception fails", cfg, allowEcho, []string{"GO-1: excepted but no longer reported"}, false},
		{"exception does not cover another ID", cfg + calledFinding("GO-1", "") + calledFinding("GO-2", ""), allowEcho,
			[]string{"GO-2:"}, false},
		{"no output is an error, never a pass", "", nil, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := judge(strings.NewReader(c.input), c.allow)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if len(got) != len(c.problems) {
				t.Fatalf("problems = %q, want %d matching %q", got, len(c.problems), c.problems)
			}
			for i, want := range c.problems {
				if !strings.Contains(got[i], want) {
					t.Errorf("problem %d = %q, want it to contain %q", i, got[i], want)
				}
			}
		})
	}
}

func TestParseAllowRequiresAReason(t *testing.T) {
	if _, err := parseAllow(strings.NewReader("./adapters/echo GO-1\n"), "./adapters/echo"); err == nil {
		t.Fatal("an exception with no reason was accepted")
	}
	got, err := parseAllow(strings.NewReader("# c\n\n./adapters/echo GO-1 why\n./other GO-2 why\n"), "./adapters/echo")
	if err != nil || len(got) != 1 || got["GO-1"] != "why" {
		t.Fatalf("got %v, %v; want only GO-1 for the named module", got, err)
	}
}
