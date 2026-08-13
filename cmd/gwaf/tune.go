// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/gsoultan/gwaf/calibrate"
)

// runTune turns measured false positives into the narrowest exceptions that
// would have prevented them.
//
// # Why this is a command and not advice
//
// Everyone tuning a WAF does this by hand, and doing it by hand is why tuning
// goes wrong. The path of least resistance from a blocked legitimate request is
// to disable the rule, because that is one line and always works, and a ruleset
// tuned that way ends up protecting nothing while reporting that it is on. The
// literature's answer is to generate narrow exclusions from observed benign
// traffic rather than to widen by hand; gwaf already has the narrow primitive --
// rules.Exception, and Explanation.NarrowestException to derive one -- so what
// was missing was the step that reads a corpus and writes them out.
//
// # Why the output is Go rather than applied automatically
//
// An exception is a hole in a firewall. Something that punched them silently
// during a build would be a supply chain for holes: a corpus entry an attacker
// influenced becomes a permanent exemption nobody reviewed. So this prints, and
// a human pastes. Every suggestion carries the sample that produced it in a
// Note, because an exception with no rationale is indistinguishable from a
// mistake six months later (rules.Exception's own documentation says so).
//
// # Why it refuses to widen
//
// A suggestion is only emitted when the samples agree on what to scope to. If a
// rule fired on four different paths, no single path-scoped exception is
// correct, and the honest output is to say that and let a person decide --
// widening to "everywhere" to produce a tidy answer is precisely the failure
// this exists to prevent.
func runTune(args []string) error {
	fs := flag.NewFlagSet("tune", flag.ExitOnError)
	corpusPath := fs.String("corpus", "testdata/corpus/benign.jsonl",
		"JSON Lines file of benign requests")
	force := fs.Bool("force", false,
		"emit suggestions even when the corpus looks like it contains attacks")
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

	// Refuse to tune against traffic that is attacking you.
	//
	// Every message this command prints says "benign", and until now nothing
	// checked. That is the shape of defect this project treats as a bug
	// everywhere else: a claim with no harness behind it. Here the consequence
	// is worse than usual, because the failure is silent and permanent -- a
	// corpus containing last week's SQL injection yields an exception
	// suppressing the rule that caught it, and the suggestion looks exactly
	// like a legitimate one.
	//
	// It matters now because the corpus is meant to come from real traffic:
	// calibrate.Request documents its shape as "deliberately close to what an
	// access log holds". An access log is not a benign corpus. Whoever exports
	// one has to filter it -- 2xx/3xx only, nothing another engine flagged, no
	// scanner agents -- and this is the check that tells them they did not.
	//
	// Refuses rather than warns because the output is meant to be pasted, and a
	// warning above text somebody is about to paste is a warning somebody
	// pastes past. -force is there because a maintainer deliberately tuning a
	// deliberately hostile corpus is a real thing to want.
	if rep.LooksLikeProductionTraffic() && !*force {
		fmt.Fprintf(os.Stderr,
			"gwaf tune: %d of %d requests (%.2f%%) matched a rule at High or "+
				"Certain confidence.\n\n"+
				"Those tiers are calibrated to at most one false positive in "+
				"1,000 and 10,000 requests, so a corpus this far above them is "+
				"not benign -- it is traffic with attacks in it. Every exception "+
				"derived from it would permanently suppress a real detection.\n\n"+
				"If this is an access-log export, filter it first: keep only "+
				"requests the origin answered 2xx or 3xx, drop anything another "+
				"engine already flagged, drop known scanner agents.\n\n"+
				"Run `gwaf calibrate -corpus %s -v` to see which rules fired, or "+
				"pass -force if the corpus is hostile on purpose.\n",
			rep.Blocking, rep.Requests, rep.BlockingRate()*100, *corpusPath)
		return fmt.Errorf("corpus does not look benign")
	}

	var fired []calibrate.RuleResult
	for _, r := range rep.Rules {
		if r.Hits > 0 {
			fired = append(fired, r)
		}
	}
	sort.Slice(fired, func(i, j int) bool { return fired[i].Hits > fired[j].Hits })

	fmt.Printf("// %d benign requests; %d rules matched at least one.\n",
		rep.Requests, len(fired))
	if len(fired) == 0 {
		fmt.Println("// Nothing to tune. Every rule left this corpus alone.")
		return nil
	}
	fmt.Println("//")
	fmt.Println("// Review each one before pasting. An exception is a hole in a firewall,")
	fmt.Println("// and the corpus only proves these requests are benign -- not that every")
	fmt.Println("// request matching the same scope will be.")
	fmt.Println()
	fmt.Println("gwaf.WithExceptions(")

	unscoped := 0
	for _, r := range fired {
		path, okPath := agreedOn(r.Samples, func(s calibrate.Sample) string { return s.Path })
		key, okKey := agreedOn(r.Samples, func(s calibrate.Sample) string { return s.Key })
		target, okTarget := agreedOn(r.Samples, func(s calibrate.Sample) string { return s.Target })

		// Nothing to scope to means nothing to suggest. Emitting a rule-wide
		// exception here would be indistinguishable from disabling the rule.
		if !okPath && !okKey {
			unscoped++
			fmt.Printf("\t// rule %d (%s): fired on %d requests with no common path or\n",
				r.ID, r.Declared, r.Hits)
			fmt.Printf("\t// argument -- too broad to except. Fix or retire the rule instead.\n")
			for _, s := range sampleNames(r.Samples) {
				fmt.Printf("\t//   %s\n", s)
			}
			continue
		}

		fmt.Printf("\trules.Exception{\n")
		fmt.Printf("\t\tRuleID: %d,\n", r.ID)
		if okPath {
			fmt.Printf("\t\tPath:   %q,\n", path)
		}
		if okTarget {
			if c := targetConst(target); c != "" {
				fmt.Printf("\t\tTarget: %s,\n", c)
			}
		}
		if okKey && key != "" {
			fmt.Printf("\t\tKey:    %q,\n", key)
		}
		fmt.Printf("\t\tNote:   %q,\n", note(r))
		fmt.Printf("\t},\n")
	}
	fmt.Println(")")

	if unscoped > 0 {
		fmt.Printf("\n// %d rule(s) had no narrow scope and were not suggested. That is a\n", unscoped)
		fmt.Printf("// finding about the rule, not about the corpus.\n")
	}
	return nil
}

// agreedOn returns the single value every sample shares, and whether they all
// share one. Disagreement is not averaged away: it means no single scope is
// correct, and saying so is the point.
func agreedOn(samples []calibrate.Sample, f func(calibrate.Sample) string) (string, bool) {
	if len(samples) == 0 {
		return "", false
	}
	first := f(samples[0])
	if first == "" {
		return "", false
	}
	for _, s := range samples[1:] {
		if f(s) != first {
			return "", false
		}
	}
	return first, true
}

// targetConst maps a target's printed name back to the typed constant, so the
// emitted Go is compile-checked rather than stringly-typed (CLAUDE.md §2b.5).
// An unrecognised name yields "", and the field is left off rather than guessed.
func targetConst(name string) string {
	switch strings.ToUpper(name) {
	case "ARGS":
		return "types.TargetArgs"
	case "ARGS_NAMES":
		return "types.TargetArgNames"
	case "REQUEST_HEADERS":
		return "types.TargetRequestHeaders"
	case "REQUEST_BODY":
		return "types.TargetRequestBody"
	case "REQUEST_URI":
		return "types.TargetRequestURI"
	case "REQUEST_PATH":
		return "types.TargetRequestPath"
	case "REQUEST_COOKIES":
		return "types.TargetRequestCookies"
	}
	return ""
}

// note records why the exception exists, naming the corpus entries that
// produced it so a reviewer can go and look at them.
func note(r calibrate.RuleResult) string {
	names := sampleNames(r.Samples)
	if len(names) == 0 {
		return fmt.Sprintf("matched %d benign requests", r.Hits)
	}
	return fmt.Sprintf("benign in this corpus: %s", strings.Join(names, "; "))
}

// sampleNames lists the distinct corpus entry names behind a rule's samples.
func sampleNames(samples []calibrate.Sample) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range samples {
		if s.Name == "" || seen[s.Name] {
			continue
		}
		seen[s.Name] = true
		out = append(out, s.Name)
	}
	return out
}
