// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Command gwaf is the build-time toolchain.
//
// It is tier 2 in the artifact taxonomy (CLAUDE.md §1): a driver over the
// library, never in the request path, and containing no detection logic of its
// own. A compiler is a library plus a driver, and this is the driver.
//
//	gwaf calibrate [-corpus FILE] [-v]   measure each rule's false-positive rate
//	gwaf lint                            report prefilter coverage and cost
//	gwaf tune [-corpus FILE]             suggest narrow exceptions for measured FPs
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gsoultan/gwaf/calibrate"
	"github.com/gsoultan/gwaf/types"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "calibrate":
		err = runCalibrate(os.Args[2:])
	case "lint":
		err = runLint(os.Args[2:])
	case "explain":
		err = runExplain(os.Args[2:])
	case "tune":
		err = runTune(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "gwaf: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "gwaf: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gwaf -- build-time toolchain

  calibrate   measure each rule's false-positive rate against a benign corpus
  lint        report prefilter coverage, unconditional rules, and -- given a
              corpus -- how much benign traffic each rule's literals admit
  explain     describe a rule, or replay a request and explain the outcome
  tune        suggest the narrowest exceptions for the false positives measured

    gwaf explain 7002
    gwaf explain -arg 'q=1'"'"' OR 1=1--'
    gwaf tune -corpus testdata/corpus/benign.jsonl
    gwaf lint -corpus testdata/corpus/benign.jsonl

A rule is *prefiltered* when its operator declares a required literal, and
*selective* only when that literal is absent from ordinary traffic. Those are
different properties: "101 rules, 101 prefiltered" is true of a ruleset whose
literals are a quote and an equals sign. lint -corpus measures the second one.

All four are compile-time tools. None runs on the request path, and none
contains detection logic -- they are drivers over the library.

tune prints Go for a human to read and paste; it never edits configuration.
An exception is a hole in a firewall, and one punched automatically during a
build is a hole nobody reviewed.
`)
}

// runCalibrate measures the ruleset against a corpus and fails the build when a
// rule's measured false-positive rate exceeds what its confidence tier allows.
func runCalibrate(args []string) error {
	fs := flag.NewFlagSet("calibrate", flag.ExitOnError)
	corpusPath := fs.String("corpus", "testdata/corpus/benign.jsonl",
		"JSON Lines file of benign requests")
	verbose := fs.Bool("v", false, "report every rule, not only failures")
	if err := fs.Parse(args); err != nil {
		return err
	}

	corpus, err := calibrate.LoadCorpusFile(*corpusPath)
	if err != nil {
		return err
	}

	waf, err := calibrate.NewWAF()
	if err != nil {
		return err
	}

	rep, err := calibrate.Run(waf, corpus)
	if err != nil {
		return err
	}

	fmt.Printf("corpus: %d benign requests\n", rep.Requests)
	fmt.Printf("rules:  %d measured, %d matched nothing\n",
		len(rep.Rules), rep.Clean)

	// A clean run is only as strong as the corpus is large. Saying so here is
	// the difference between a gate and a rubber stamp.
	fmt.Printf("power:  smallest observable rate is %.4f%% (1 in %d)\n",
		rep.MinDetectableRate()*100, rep.Requests)
	if unvalidated := rep.UnvalidatedTiers(); len(unvalidated) > 0 {
		fmt.Printf("\nwarning: this corpus cannot validate a claim at:\n")
		for _, c := range unvalidated {
			fmt.Printf("  %-10s needs ~%d benign requests to observe one violation\n",
				c, calibrate.RequestsNeededFor(c))
		}
		fmt.Printf("a rule at those tiers passing here means it did not match these\n")
		fmt.Printf("%d requests -- not that its rate is below the ceiling. Grow the\n", rep.Requests)
		fmt.Printf("corpus; never loosen the ceiling.\n")
	}
	fmt.Println()

	shown := 0
	for _, r := range rep.Rules {
		if r.Passed() && !*verbose {
			continue
		}
		shown++

		status := "ok  "
		if !r.Passed() {
			status = "FAIL"
		}
		fmt.Printf("%s  %-8s %-10s measured %.4f%%  ceiling %.4f%%  %s\n",
			status, r.ID, r.Declared, r.Measured*100, r.Ceiling*100, r.Msg)

		if !r.Passed() {
			// A failure has to be reproducible, or the report is just a number
			// somebody will lower the threshold to satisfy.
			fmt.Printf("      matched %d/%d benign requests:\n", r.Hits, r.Requests)
			for _, s := range r.Samples {
				fmt.Printf("        %-28s %s", s.Name, s.Target)
				if s.Key != "" {
					fmt.Printf(":%s", s.Key)
				}
				if s.Interpretation != "none" && s.Interpretation != "" {
					fmt.Printf("  (via %s)", s.Interpretation)
				}
				fmt.Println()
			}
			fmt.Printf("      the measurement supports %s; either lower the "+
				"declared tier or fix the rule\n", r.Suggested())
		} else if r.Hits > 0 {
			fmt.Printf("      matched %d benign requests, within tier\n", r.Hits)
		}
	}

	if shown == 0 && !*verbose {
		fmt.Println("every rule is within its declared confidence tier")
	}

	if !rep.Passed() {
		return fmt.Errorf("%d rule(s) exceed their declared confidence tier", rep.Failed)
	}
	return nil
}

// runLint reports what compilation produced: how much of the ruleset is
// prefiltered, and what the rest costs on every request.
func runLint(args []string) error {
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	maxUnconditional := fs.Int("max-unconditional", 0,
		"fail if more than this many rules cannot be prefiltered")
	corpusPath := fs.String("corpus", "",
		"benign corpus to measure literal selectivity against (JSON Lines)")
	maxSelectivity := fs.Float64("max-selectivity", 1.01,
		"fail if a rule is nominated on more than this fraction of the corpus")
	if err := fs.Parse(args); err != nil {
		return err
	}

	waf, err := calibrate.NewWAF()
	if err != nil {
		return err
	}
	r := waf.Report()

	fmt.Printf("ruleset: %d rules, %d prefiltered, %d unconditional\n",
		r.Rules, r.Prefiltered, len(r.Unconditional))
	fmt.Printf("prefilter: %d literals, %d automaton states, %d transform chains\n",
		r.Literals, r.AutomatonStates, r.ChainGroups)

	if len(r.Unconditional) > 0 {
		// An unconditional rule runs on every request in its phase. Some are
		// legitimate; the point is that the cost is visible here rather than
		// discovered in a latency graph. See docs/RULES.md §5.
		fmt.Println("\nrules evaluated on every request:")
		for _, u := range r.Unconditional {
			fmt.Printf("  %-8s %-20s %s (%s)\n", u.ID, u.Operator, u.Reason, u.Phase)
		}
	}

	// Rules that compiled and cannot decide anything.
	//
	// This is the same list (*gwaf.WAF).Diagnostics returns at construction, and
	// it belongs here for the reason the API exists at all: a rule that reports
	// nothing until the embedder supplies configuration is invisible from every
	// direction except this one. It compiles, it lints clean, `gwaf explain`
	// describes it correctly, and it never fires.
	//
	// Reported rather than failed. lint builds the default ruleset with no
	// embedder configuration, so the off-origin entry is *always* present here
	// and always will be — making it an error would be a gate that is red every
	// day, which is a gate nobody reads. What it is instead is the answer to
	// "which of these rules needs something from me before it does anything".
	if diags := waf.Diagnostics(); len(diags) > 0 {
		fmt.Println("\nrules that need configuration before they decide anything:")
		for _, d := range diags {
			fmt.Printf("  %-8d %s\n", d.ID, d.Msg)
			fmt.Printf("           %s\n", d.Reason)
			fmt.Printf("           fix: %s\n", d.Fix)
		}
	}

	byTier := map[types.Confidence]int{}
	for _, cr := range waf.Ruleset().All() {
		byTier[cr.Rule.Confidence]++
	}
	fmt.Println("\nconfidence tiers:")
	for _, c := range []types.Confidence{
		types.Certain, types.High, types.Medium, types.Low, types.Heuristic,
	} {
		if n := byTier[c]; n > 0 {
			fmt.Printf("  %-10s %d\n", c, n)
		}
	}

	// Measured selectivity, when a corpus is supplied.
	//
	// The line above -- "N rules, N prefiltered, 0 unconditional" -- is true and
	// is not the whole answer. A rule is prefiltered if its operator declares a
	// required literal; it is *selective* only if that literal is absent from
	// most traffic. `detect_xss` declares `"`, which is in every JSON body, so
	// those rules are prefiltered and evaluated on everything at once.
	//
	// Soundness had a fuzz harness and selectivity had nothing, so the only way
	// to discover this was a CPU profile -- which is not something a rule author
	// runs, and not something CI would ever fail on.
	var overSelectivity []calibrate.RuleSelectivity
	if *corpusPath != "" {
		corpus, err := calibrate.LoadCorpusFile(*corpusPath)
		if err != nil {
			return err
		}
		sel, err := calibrate.Selectivity(waf, corpus)
		if err != nil {
			return err
		}

		fmt.Printf("\nprefilter selectivity, measured against %d benign requests:\n",
			sel.Requests)
		fmt.Printf("  %-8s %6s  %-26s %s\n", "rule", "admits", "worst literal", "message")

		shown := 0
		for _, r := range sel.Rules {
			// Below a twentieth of the corpus a literal is doing its job, and
			// listing every rule buries the ones that are not.
			if r.Rate < 0.05 && !r.Unconditional {
				continue
			}
			shown++
			worst := "(unconditional)"
			if w, ok := r.Worst(); ok {
				worst = fmt.Sprintf("%q %.0f%%", w.Literal, w.Rate*100)
			}
			fmt.Printf("  %-8d %5.1f%%  %-26s %s\n", r.ID, r.Rate*100, worst, r.Msg)
		}
		if shown == 0 {
			fmt.Printf("  every rule is nominated on under 5%% of benign requests\n")
		}

		overSelectivity = sel.Above(*maxSelectivity)
		if len(overSelectivity) > 0 {
			fmt.Printf("\n%d rule(s) exceed the selectivity budget of %.0f%%:\n",
				len(overSelectivity), *maxSelectivity*100)
			for _, r := range overSelectivity {
				fmt.Printf("  %-8d %s\n", r.ID, r.Msg)
				if w, ok := r.Worst(); ok {
					fmt.Printf("           %q appears in %d of %d benign requests\n",
						w.Literal, w.Requests, r.Requests)
					fmt.Printf("           fix: make the literal specific enough to be absent "+
						"from ordinary traffic, or accept the cost knowingly\n")
				}
			}
		}
	}

	if len(r.Unconditional) > *maxUnconditional {
		return fmt.Errorf("%d unconditional rules exceeds the budget of %d",
			len(r.Unconditional), *maxUnconditional)
	}
	if len(overSelectivity) > 0 {
		return fmt.Errorf("%d rule(s) are nominated on more than %.0f%% of benign traffic",
			len(overSelectivity), *maxSelectivity*100)
	}
	return nil
}
