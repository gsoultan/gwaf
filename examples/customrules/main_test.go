// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestExampleBehavesAsDocumented runs the example and checks each row.
//
// An example that compiles proves the API is reachable; an example that *runs*
// proves it does what its comments say. Both bugs this file caught were found
// that way — a rule reading one value of a resolver never fired, and a token in
// the sample data was two bytes short of what its own predicate required.
//
// Neither would have shown up in a documentation snippet.
func TestExampleBehavesAsDocumented(t *testing.T) {
	out, err := exec.Command("go", "run", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go run: %v\n%s", err, out)
	}
	got := string(out)
	t.Log("\n" + got)

	// Each documented row: the request, and whether it should be blocked.
	rows := []struct {
		name    string
		blocked bool
	}{
		{"ordinary request", false},
		{"internal path", true},                 // built-in operator + transforms
		{"service token from outside", true},    // op.Func with a literal hint
		{"wrong tenant", true},                  // custom Operator
		{"wrong tenant, excepted route", false}, // rules.Exception
		{"legacy encoded secret", true},         // custom Transform
		{"hostile ASN", true},                   // Resolver + custom Action
		{"ordinary ASN", false},
		{"sql injection (core rule)", true}, // custom rules add to core, not replace
	}

	for _, r := range rows {
		line := findLine(got, r.name)
		if line == "" {
			t.Errorf("no output row for %q", r.name)
			continue
		}
		if blocked := strings.Contains(line, "BLOCK"); blocked != r.blocked {
			t.Errorf("%s: blocked = %v, want %v\n  %s", r.name, blocked, r.blocked, line)
		}
	}

	// The custom Action ran exactly once, for the one ASN finding.
	if !strings.Contains(got, "audit action fired 1 time(s)") {
		t.Error("the custom Action did not run exactly once")
	}
}

// findLine returns the output row beginning with name.
func findLine(out, name string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, name+" ") {
			return l
		}
	}
	return ""
}

func TestMain(m *testing.M) {
	// `go run .` needs the example's own directory, which is where the test
	// already runs.
	os.Exit(m.Run())
}
