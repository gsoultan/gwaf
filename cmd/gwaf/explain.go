// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/ruleset/core"
	"github.com/gsoultan/gwaf/types"
)

// runExplain answers two questions an operator has at three in the morning:
// "what is rule 7002?" and "why did this request get blocked?".
//
// Both print what the library returns. The CLI formats; it does not analyse.
// That separation is the tier boundary in CLAUDE.md §1 — a toolchain command is
// a driver over the library, never a second implementation of it — and it is
// also what keeps the promise in §2b honest: everything printed here is
// reachable through Decision.Explain(), so a control plane needs no scraping.
func runExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	target := fs.String("target", "/", "request target to replay")
	method := fs.String("method", "GET", "request method to replay")
	arg := fs.String("arg", "", "argument value to replay, as name=value")
	header := fs.String("header", "", "header to replay, as Name:value")
	body := fs.String("body", "", "request body to replay")
	ctype := fs.String("content-type", "application/json", "Content-Type for the body")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// With a rule ID, describe the rule. With request data, replay it.
	if rest := fs.Args(); len(rest) > 0 {
		id, err := strconv.ParseUint(rest[0], 10, 32)
		if err != nil {
			return fmt.Errorf("explain: %q is not a rule ID: %w", rest[0], err)
		}
		return describeRule(types.RuleID(id))
	}
	if *arg == "" && *header == "" && *body == "" && *target == "/" {
		return fmt.Errorf("explain: give a rule ID, or request data to replay " +
			"(-arg, -header, -body, -target)")
	}
	return replay(*method, *target, *arg, *header, *body, *ctype)
}

// describeRule prints the anatomy of one rule from the core ruleset.
func describeRule(id types.RuleID) error {
	for _, r := range core.Default() {
		if r.ID != id {
			continue
		}

		fmt.Printf("rule %d: %s\n", r.ID, r.Msg)
		fmt.Printf("  phase:      %s\n", r.Phase)
		fmt.Printf("  severity:   %s\n", r.Severity)
		fmt.Printf("  confidence: %s\n", r.Confidence)
		if len(r.Tags) > 0 {
			fmt.Printf("  tags:       %s\n", strings.Join(r.Tags, ", "))
		}

		names := make([]string, 0, len(r.Targets))
		for _, t := range r.Targets {
			names = append(names, t.String())
		}
		fmt.Printf("  targets:    %s\n", strings.Join(names, ", "))

		if len(r.Transforms) > 0 {
			chain := make([]string, 0, len(r.Transforms))
			for _, t := range r.Transforms {
				chain = append(chain, t.Name())
			}
			fmt.Printf("  transforms: %s\n", strings.Join(chain, " → "))
		}

		fmt.Printf("  operator:   %s\n", r.Op.Name())
		if lits, ok := r.Op.Literals(); ok {
			fmt.Printf("  literals:   %d (%s)\n", len(lits), preview(lits))
		} else {
			// Worth saying loudly: an unconditional rule runs against every
			// value in its phase, so its cost is paid by benign traffic too.
			fmt.Printf("  literals:   none — this rule cannot be prefiltered " +
				"and runs on every value\n")
		}
		fmt.Printf("  cost:       %d fuel per evaluation\n", r.Op.Cost())
		return nil
	}
	return fmt.Errorf("explain: no rule %d in the core ruleset", id)
}

// replay runs one request through a default WAF and explains the outcome.
func replay(method, target, arg, header, body, ctype string) error {
	w, err := gwaf.New()
	if err != nil {
		return err
	}

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine(method, target, "HTTP/1.1")
	if header != "" {
		name, value, _ := strings.Cut(header, ":")
		tx.AddRequestHeader(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	if arg != "" {
		name, value, _ := strings.Cut(arg, "=")
		tx.AddArgument(name, value)
	}
	if body != "" {
		tx.AddRequestHeader("Content-Type", ctype)
	}

	d := tx.ProcessRequestHeaders()
	if !d.Blocked() && body != "" {
		tx.SetRequestBody([]byte(body))
		d = tx.ProcessRequestBody()
	}

	e := d.Explain()
	if !d.Blocked() {
		fmt.Printf("allowed: %s\n  rules evaluated: %d\n  score: %d\n",
			e.Reason(), e.RulesEvaluated(), e.Score())
		// Rules that matched without deciding are still worth showing: a
		// scoring rule that fires on every request is a tuning problem long
		// before it is a blocking one.
		if m := tx.Matches(); len(m) > 0 {
			fmt.Println("  matched without blocking:")
			for _, x := range m {
				fmt.Printf("    rule %d: %s\n", x.RuleID, x.Msg)
			}
		}
		return nil
	}

	fmt.Println(e)
	fmt.Fprintf(os.Stderr, "\nblocked\n")
	return nil
}

// preview renders the first few literals, so a rule with fifty does not fill
// the terminal.
func preview(lits []string) string {
	const max = 6
	shown := lits
	if len(shown) > max {
		shown = shown[:max]
	}
	out := strings.Join(shown, " ")
	if len(lits) > max {
		out += fmt.Sprintf(" … +%d more", len(lits)-max)
	}
	return out
}
