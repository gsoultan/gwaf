// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestExampleOutput runs the example and asserts every documented row.
//
// The example is a claim about what positive security buys, and a claim in a
// comment rots. Running it here means a change that quietly stops blocking a
// negative stake fails the build rather than the next reader's expectations.
func TestExampleOutput(t *testing.T) {
	out, err := exec.Command("go", "run", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go run .: %v\n%s", err, out)
	}
	got := string(out)

	for _, want := range []string{
		// Legitimate traffic is untouched. If this ever fails, the schema is
		// too strict and every row below is worthless.
		"legitimate bet                   allow",
		"legitimate withdrawal            allow",

		// Business logic: valid bytes, wrong meaning.
		"negative stake                   BLOCK",
		"stake above table limit          BLOCK",
		"integer overflow payout          BLOCK",
		"sub-cent precision stake         BLOCK",
		"unsupported currency             BLOCK",
		"malformed event id               BLOCK",
		"undeclared field smuggled in     BLOCK",
		"missing required field           BLOCK",

		// Reconnaissance: valid paths, wrong API.
		"cPanel probe                     BLOCK",
		"phpMyAdmin probe                 BLOCK",
		"WordPress user enumeration       BLOCK",
		"F5 BIG-IP CVE-2022-1388          BLOCK",
		"Atlassian CVE-2023-22515         BLOCK",

		// The violation names the reason, not just the verdict. An operator who
		// cannot tell out_of_range from not_in_enum cannot fix the caller.
		"out_of_range: stake",
		"not_in_enum: currency",
		"format_mismatch: event_id",
		"undeclared_parameter: is_admin",
		"missing_required_parameter: event_id",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q\n---\n%s", want, got)
		}
	}
}
