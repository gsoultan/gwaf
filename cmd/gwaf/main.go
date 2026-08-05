// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Command gwaf is the build-time toolchain.
//
// It is tier 2 in the artifact taxonomy (CLAUDE.md §1): a driver over the
// library, never in the request path, and containing no detection logic of its
// own. A compiler is a library plus a driver, and this is the driver.
//
//	gwaf calibrate [-corpus FILE] [-v]   measure each rule's false-positive rate
//	gwaf lint                            report prefilter coverage and cost
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
  lint        report prefilter coverage and the cost of unconditional rules

Both are compile-time tools. Neither runs on the request path.
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

	if len(r.Unconditional) > *maxUnconditional {
		return fmt.Errorf("%d unconditional rules exceeds the budget of %d",
			len(r.Unconditional), *maxUnconditional)
	}
	return nil
}
