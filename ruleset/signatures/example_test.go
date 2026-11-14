// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package signatures_test

import (
	"fmt"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/signatures"
)

func ExampleAll() {
	waf, err := gwaf.New(gwaf.WithRuleset(signatures.All()))
	if err != nil {
		panic(err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", "/goanywhere/licensing/accept", "HTTP/1.1")
	d := tx.ProcessRequestHeaders()
	fmt.Println(d.Blocked(), d.RuleID() == signatures.IDGoAnywhere)
	// Output:
	// true true
}

// The set is the caller's to edit. Here an embedder with no CGI behind it
// leaves out the one rule that runs on every request body.
func ExampleAll_subset() {
	var set rules.Set
	for _, r := range signatures.All() {
		if r.ID != signatures.IDShellshockBody {
			set = append(set, r)
		}
	}
	_, err := gwaf.New(gwaf.WithRuleset(set))
	fmt.Println(err, len(signatures.All())-len(set))
	// Output:
	// <nil> 1
}
