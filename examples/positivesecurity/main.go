// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Command positivesecurity shows what a schema catches that no signature can.
//
// A signature answers "does this value look like an attack?". Some of the most
// expensive attacks do not look like anything: a stake of -5000 is a valid
// number, "BTC" is a valid currency string, and /phpmyadmin/index.php is a
// valid path. They are attacks because the *application* does not accept them,
// and only the application can say so.
//
// That is the difference between negative security (block what is known bad)
// and positive security (accept what is known good). gwaf does both, and this
// example is the half that a rule cannot express.
//
// Run:
//
//	go run ./positivesecurity
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/schema"
)

func main() {
	// A sports-betting API, described once. Everything below follows from it.
	api, err := schema.New(
		schema.Operation{
			Method: "POST",
			Path:   "/api/v1/bets",
			Strict: true,
			Body: []schema.Field{
				{Name: "event_id", Kind: schema.KindString,
					Format: schema.FormatUUID, Required: true},
				// The bounds are the point. Declaring "number" accepts -5000
				// and 9223372036854775807 alike, and both are house money.
				{Name: "stake", Kind: schema.KindNumber, Required: true,
					Min: schema.Bound(0.01), Max: schema.Bound(10_000)},
				{Name: "odds", Kind: schema.KindNumber, Required: true,
					Min: schema.Bound(1.01), Max: schema.Bound(1000)},
				{Name: "currency", Kind: schema.KindEnum,
					Enum: []string{"USD", "EUR", "GBP"}},
			},
		},
		schema.Operation{
			Method: "POST",
			Path:   "/api/v1/withdraw",
			Strict: true,
			Body: []schema.Field{
				{Name: "amount", Kind: schema.KindNumber, Required: true,
					Min: schema.Bound(1), Max: schema.Bound(50_000)},
				{Name: "currency", Kind: schema.KindEnum,
					Enum: []string{"USD", "EUR", "GBP"}},
				{Name: "account", Kind: schema.KindString, MaxLength: 64},
			},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	// Closed turns the description into the definition: anything that matches no
	// operation is rejected. Opt-in, because it is only correct once the schema
	// is complete.
	api.Closed()

	waf, err := gwaf.New(gwaf.WithSchema(api))
	if err != nil {
		log.Fatal(err)
	}

	type probe struct {
		what   string
		method string
		path   string
		body   string
	}

	probes := []probe{
		{"legitimate bet", "POST", "/api/v1/bets",
			`{"event_id":"c5cd9f6d-4b91-11ed-b8da-eb423273f75b","stake":25.00,"odds":1.9,"currency":"USD"}`},
		{"legitimate withdrawal", "POST", "/api/v1/withdraw",
			`{"amount":250.00,"currency":"USD","account":"acct-9"}`},

		// Business logic. None of these contains a payload; a signature engine
		// has nothing to match on, because there is nothing wrong with the
		// bytes -- only with what they mean to this application.
		{"negative stake", "POST", "/api/v1/bets",
			`{"event_id":"c5cd9f6d-4b91-11ed-b8da-eb423273f75b","stake":-5000,"odds":1.9}`},
		{"stake above table limit", "POST", "/api/v1/bets",
			`{"event_id":"c5cd9f6d-4b91-11ed-b8da-eb423273f75b","stake":250000,"odds":1.9}`},
		{"integer overflow payout", "POST", "/api/v1/bets",
			`{"event_id":"c5cd9f6d-4b91-11ed-b8da-eb423273f75b","stake":9223372036854775807,"odds":2.0}`},
		{"sub-cent precision stake", "POST", "/api/v1/bets",
			`{"event_id":"c5cd9f6d-4b91-11ed-b8da-eb423273f75b","stake":0.000000001,"odds":1.9}`},
		{"unsupported currency", "POST", "/api/v1/withdraw",
			`{"amount":100,"currency":"BTC","account":"acct-1"}`},
		{"malformed event id", "POST", "/api/v1/bets",
			`{"event_id":"' OR 1=1--","stake":10,"odds":1.9}`},
		{"undeclared field smuggled in", "POST", "/api/v1/bets",
			`{"event_id":"c5cd9f6d-4b91-11ed-b8da-eb423273f75b","stake":10,"odds":1.9,"is_admin":true}`},
		{"missing required field", "POST", "/api/v1/bets",
			`{"stake":10,"odds":1.9}`},

		// Reconnaissance. These are not payloads either; they are requests for
		// routes this API does not have. A ruleset would need to know every
		// product on the internet to block them. A schema needs to know one API.
		{"cPanel probe", "GET", "/cpanel", ""},
		{"phpMyAdmin probe", "GET", "/phpmyadmin/index.php", ""},
		{"WordPress user enumeration", "GET", "/wp-json/wp/v2/users", ""},
		{"F5 BIG-IP CVE-2022-1388", "GET", "/mgmt/tm/util/bash", ""},
		{"Atlassian CVE-2023-22515", "GET", "/setup/setupadministrator.action", ""},
	}

	fmt.Printf("%-32s %-7s %s\n", "request", "verdict", "why")
	fmt.Println(strings.Repeat("-", 92))

	for _, p := range probes {
		tx := waf.NewTransaction()
		tx.SetRequestLine(p.method, p.path, "HTTP/1.1")
		if p.body != "" {
			tx.AddRequestHeader("Content-Type", "application/json")
		}
		d := tx.ProcessRequestHeaders()
		if !d.Blocked() && p.body != "" {
			tx.SetRequestBody([]byte(p.body))
			d = tx.ProcessRequestBody()
		}
		if !d.Blocked() {
			d = tx.Decision()
		}

		verdict, why := "allow", "—"
		if d.Blocked() {
			verdict = "BLOCK"
			why = d.Message()
			if det := d.Detail(); det != "" {
				why += " (" + det + ")"
			}
		}
		fmt.Printf("%-32s %-7s %s\n", p.what, verdict, why)
		tx.Close()
	}

	fmt.Println()
	fmt.Println("Every block above came from the schema, not from a rule. No signature")
	fmt.Println("describes -5000, \"BTC\", or /cpanel, because none of them is malformed —")
	fmt.Println("they are simply not what this API accepts, and only this API can say so.")
	fmt.Println()
	fmt.Println("What is still the embedder's: a withdrawal race, a bonus code reused")
	fmt.Println("across accounts, and one player reading another's bet. Those need memory")
	fmt.Println("or identity, and gwaf analyses one request with neither.")
}
