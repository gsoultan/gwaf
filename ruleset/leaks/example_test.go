// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package leaks_test

import (
	"fmt"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/leaks"
	"github.com/gsoultan/gwaf/types"
)

// respond runs one response body through w and returns the decision.
func respond(w *gwaf.WAF, body string) gwaf.Decision {
	tx := w.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("GET", "/api/invoice/7", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()
	tx.SetResponseStatus(200)
	tx.ProcessResponseHeaders()
	tx.WriteResponseBody([]byte(body))
	return tx.ProcessResponseBody()
}

func ExampleCredentials() {
	waf, err := gwaf.New(gwaf.WithRuleset(leaks.Credentials()))
	if err != nil {
		panic(err)
	}
	fmt.Println(respond(waf, `{"paid_with":"4111 1111 1111 1111"}`).Blocked())
	fmt.Println(respond(waf, `{"order":"4000000000000000"}`).Blocked())
	// Output:
	// true
	// false
}

func ExampleDisclosure() {
	// Disclosure is Confidence Medium, so it has to be asked for twice: once by
	// loading it and once by lowering the minimum.
	waf, err := gwaf.New(
		gwaf.WithRuleset(leaks.Disclosure()),
		gwaf.WithMinConfidence(types.Medium),
	)
	if err != nil {
		panic(err)
	}
	d := respond(waf, "Traceback (most recent call last):\n  File \"app.py\", line 3")
	fmt.Println(d.Blocked(), d.RuleID() == leaks.IDPythonTraceback)
	// Output:
	// true true
}

func ExampleInbound() {
	waf, err := gwaf.New(gwaf.WithRuleset(leaks.Inbound()))
	if err != nil {
		panic(err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", "/tickets", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "text/plain")
	tx.ProcessRequestHeaders()
	tx.SetRequestBody([]byte("it fails with postgres://app:s3cr3t@db.internal:5432/prod"))
	d := tx.ProcessRequestBody()

	// Recorded, not refused.
	fmt.Println(d.Blocked(), len(tx.Matches()))
	// Output:
	// false 1
}

func ExampleAll() {
	fmt.Println(len(leaks.All()) == len(leaks.Credentials())+len(leaks.Disclosure())+len(leaks.Inbound()))
	// Output:
	// true
}

func ExampleCardNumber() {
	// The operator behind IDCardNumber, pointed at a target of the embedder's
	// choosing: here, a card number arriving in a field that should never
	// hold one.
	rule := rules.Rule{
		ID:         1_000_001,
		Phase:      types.PhaseRequestBody,
		Targets:    []types.Target{{Kind: types.TargetArgs, Name: "comment"}},
		Op:         leaks.CardNumber(),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityError,
		Confidence: types.Certain,
		Msg:        "Card number in a comment",
	}
	waf, err := gwaf.New(gwaf.WithoutCoreRuleset(), gwaf.WithRuleset(rules.Set{rule}))
	if err != nil {
		panic(err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.SetRequestLine("POST", "/reviews?comment=my+card+is+5555555555554444", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	fmt.Println(tx.ProcessRequestBody().Blocked())
	// Output:
	// true
}
