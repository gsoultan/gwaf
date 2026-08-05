// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package calibrate measures what a rule's confidence claim is actually worth.
//
// # Why confidence cannot be self-reported
//
// Every rule declares a confidence tier, and that tier decides whether the rule
// runs under a given policy and how much a match is trusted. Letting the rule's
// *author* pick it is how every ruleset drifts: everyone believes their own
// rule is precise, nobody measures, and the first evidence anyone gets is a
// support ticket about legitimate traffic being blocked.
//
// So the corpus decides. Every rule is run against a body of benign requests
// and its false-positive rate is measured. A rule declaring Certain is allowed
// one match in ten thousand; a rule declaring High, one in a thousand. Exceed
// the ceiling and the build fails.
//
// This turns false-positive rate from something discovered in production into a
// build-time gate, which is the single highest-leverage accuracy decision in
// gwaf. See docs/CONCEPT.md §8.
//
// # What a measurement here does and does not mean
//
// A match on benign traffic is a false positive *for that corpus*. The
// measurement is therefore only as good as the corpus is representative, which
// is why the corpus is a committed, reviewable artifact rather than something
// generated. Growing it is how the guarantee gets stronger; a rule that passes
// against ten requests has been told very little.
package calibrate

import (
	"fmt"
	"sort"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/types"
)

// RuleResult is one rule's measurement.
type RuleResult struct {
	ID types.RuleID

	// Msg is the rule's description, so a failure report is readable without
	// cross-referencing the ruleset.
	Msg string

	// Declared is the confidence the rule claims.
	Declared types.Confidence

	// Hits is how many benign requests the rule matched.
	Hits int

	// Requests is how many benign requests were evaluated.
	Requests int

	// Samples are up to SampleLimit of the benign requests that matched, so a
	// failure can be reproduced rather than merely reported.
	Samples []Sample

	// Measured is the observed false-positive rate.
	Measured float64

	// Ceiling is the highest rate the declared tier permits.
	Ceiling float64
}

// Passed reports whether the measured rate is within the declared tier.
func (r RuleResult) Passed() bool { return r.Measured <= r.Ceiling }

// Suggested returns the highest confidence tier the measurement supports.
//
// A rule measuring better than it claims is not a failure, but it is worth
// knowing: promoting it lets a stricter policy use it.
func (r RuleResult) Suggested() types.Confidence {
	for _, c := range []types.Confidence{
		types.Certain, types.High, types.Medium, types.Low, types.Heuristic,
	} {
		if r.Measured <= c.MaxFPRate() {
			return c
		}
	}
	return types.Heuristic
}

// Sample is one benign request a rule matched.
type Sample struct {
	// Name identifies the corpus entry.
	Name string

	// Target and Key locate the value that matched.
	Target string
	Key    string

	// Interpretation names the decoding under which it matched, or "none".
	Interpretation string
}

// SampleLimit bounds how many examples are kept per rule. Enough to reproduce a
// failure, not so many that a broken rule produces an unreadable report.
const SampleLimit = 5

// Report is the outcome of a calibration run.
type Report struct {
	// Rules are the per-rule results, worst first.
	Rules []RuleResult

	// Requests is the corpus size.
	Requests int

	// Failed counts rules whose measurement exceeded their declared tier.
	Failed int

	// Clean counts rules that matched no benign request at all.
	Clean int
}

// MinDetectableRate is the smallest non-zero false-positive rate this corpus
// can observe: one match out of however many requests it holds.
//
// This is the honest limit on what a passing result means. A rule that matched
// nothing in 71 requests has not been shown to have a rate below 0.01%; it has
// been shown not to match those 71. Reporting the bound stops a clean run from
// being read as a stronger guarantee than it is.
func (r Report) MinDetectableRate() float64 {
	if r.Requests == 0 {
		return 1
	}
	return 1 / float64(r.Requests)
}

// UnvalidatedTiers returns the confidence tiers whose ceiling is below what the
// corpus can measure, so a claim at those tiers is currently unfalsifiable.
//
// The fix is always more corpus, never a looser ceiling. A tier that cannot be
// measured is a tier nobody is checking.
func (r Report) UnvalidatedTiers() []types.Confidence {
	var out []types.Confidence
	min := r.MinDetectableRate()
	for _, c := range []types.Confidence{
		types.Certain, types.High, types.Medium, types.Low,
	} {
		if c.MaxFPRate() < min {
			out = append(out, c)
		}
	}
	return out
}

// RequestsNeededFor returns the corpus size required to observe a violation of
// a tier's ceiling at all.
func RequestsNeededFor(c types.Confidence) int {
	rate := c.MaxFPRate()
	if rate <= 0 {
		return 0
	}
	return int(1/rate) + 1
}

// Passed reports whether every rule stayed within its declared tier.
func (r Report) Passed() bool { return r.Failed == 0 }

// Run measures every rule in a WAF against a benign corpus.
//
// The WAF must be built with detection-only mode and the lowest minimum
// confidence, so that every rule is evaluated rather than only those a
// production policy would run. NewWAF builds one correctly.
func Run(waf *gwaf.WAF, corpus []Request) (Report, error) {
	if len(corpus) == 0 {
		return Report{}, fmt.Errorf("calibrate: corpus is empty")
	}

	seen := make(map[types.RuleID]*ruleAcc)

	for i := range corpus {
		req := &corpus[i]

		// A rule is counted at most once per request. A rule matching three
		// arguments of one request is one false positive to the operator who
		// has to deal with it, not three.
		fired := make(map[types.RuleID]bool)

		tx := waf.NewTransaction()
		req.apply(tx)

		tx.ProcessRequestHeaders()
		collect(tx, req, seen, fired)

		if req.Body != "" {
			tx.SetRequestBody([]byte(req.Body))
			tx.ProcessRequestBody()
			collect(tx, req, seen, fired)
		}
		tx.Close()
	}

	rs := waf.Ruleset()
	rep := Report{Requests: len(corpus)}

	for _, cr := range rs.All() {
		id := cr.Rule.ID
		a := seen[id]
		hits := 0
		var samples []Sample
		if a != nil {
			hits, samples = a.hits, a.samples
		}

		res := RuleResult{
			ID:       id,
			Msg:      cr.Rule.Msg,
			Declared: cr.Rule.Confidence,
			Hits:     hits,
			Requests: len(corpus),
			Samples:  samples,
			Measured: float64(hits) / float64(len(corpus)),
			Ceiling:  cr.Rule.Confidence.MaxFPRate(),
		}
		if hits == 0 {
			rep.Clean++
		}
		if !res.Passed() {
			rep.Failed++
		}
		rep.Rules = append(rep.Rules, res)
	}

	// Worst first: a report is read top-down and the failures are what matter.
	sort.SliceStable(rep.Rules, func(i, j int) bool {
		if rep.Rules[i].Measured != rep.Rules[j].Measured {
			return rep.Rules[i].Measured > rep.Rules[j].Measured
		}
		return rep.Rules[i].ID < rep.Rules[j].ID
	})
	return rep, nil
}

// ruleAcc accumulates one rule's measurements across the corpus.
type ruleAcc struct {
	hits    int
	samples []Sample
}

// collect records the matches from the phase just evaluated.
func collect(tx *gwaf.Transaction, req *Request, seen map[types.RuleID]*ruleAcc, fired map[types.RuleID]bool) {
	for _, m := range tx.Matches() {
		if fired[m.RuleID] {
			continue
		}
		fired[m.RuleID] = true

		a := seen[m.RuleID]
		if a == nil {
			a = &ruleAcc{}
			seen[m.RuleID] = a
		}
		a.hits++
		if len(a.samples) < SampleLimit {
			a.samples = append(a.samples, Sample{
				Name:           req.Name,
				Target:         m.Target.String(),
				Key:            m.Key,
				Interpretation: m.Interpretation,
			})
		}
	}
}
