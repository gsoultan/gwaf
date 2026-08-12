// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package calibrate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/internal/bitset"
	"github.com/gsoultan/gwaf/internal/prefilter"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Selectivity measures how often each rule's literals appear in benign traffic.
//
// # Why this exists
//
// `Operator.Literals` returns an OR-set plus a soundness bool, and soundness is
// the only property anything checked. A literal that is genuinely required is
// sound; a literal that is also present in every request filters nothing. Those
// are different properties and the second one had no measurement at all.
//
// `detect_xss` declares `"`. Every JSON body contains a quote, so the XSS rules
// are evaluated on 100% of JSON traffic — while `gwaf lint` reports "101 rules,
// 101 prefiltered, 0 unconditional" and is telling the truth, because they are
// prefiltered. It took a CPU profile to find, and a profile is not something a
// rule author runs.
//
// The nomination ceiling in the evasion suite could not have found it either.
// It was raised four times — 6, 10, 12, 14 — each time for a real and
// legitimate cause, until it was rewritten as a fraction of the ruleset. A
// bound on the total says something is nominating too much. It cannot say which
// literal is responsible, and that is the only fact anybody can act on.
//
// # What is measured
//
// For each rule: the fraction of benign requests in which at least one of its
// literals appears, and the same fraction per literal. Matching uses the
// engine's own automaton rather than a substring search, so it folds ASCII case
// exactly the way the prefilter does and cannot quietly disagree with it.
//
// The values searched are those the corpus describes — argument names and
// values, header values, the target, and the body — each passed through the
// rule's own transform chain first, because that is the form the prefilter sees.
//
// # What is not measured
//
// Nomination through an alternative interpretation. A value carrying an HTML
// entity is re-read by `internal/interpret` and each reading nominates
// independently, so a rule's true nomination rate is at or above the number
// reported here. This measures the verbatim reading, which is the one a rule
// author can reason about; it is a floor, and a floor is enough to find a
// literal that already appears in every request.
func Selectivity(waf *gwaf.WAF, corpus []Request) (SelectivityReport, error) {
	if waf == nil {
		return SelectivityReport{}, fmt.Errorf("calibrate: nil WAF")
	}
	if len(corpus) == 0 {
		return SelectivityReport{}, fmt.Errorf("calibrate: corpus is empty")
	}

	// Values are independent of the rule; extract them once rather than once per
	// rule, or this is O(rules x requests) string building for no reason.
	values := make([]map[types.TargetKind][][]byte, len(corpus))
	for i := range corpus {
		values[i] = corpus[i].targetValues()
	}

	rep := SelectivityReport{Requests: len(corpus)}

	for _, cr := range waf.Ruleset().All() {
		lits, exact := cr.Rule.Op.Literals()

		res := RuleSelectivity{
			ID:       cr.Rule.ID,
			Msg:      cr.Rule.Msg,
			Requests: len(corpus),
		}

		// A rule that cannot be prefiltered runs on everything by definition.
		// Reported rather than skipped: "evaluated on every request" is the
		// answer to the same question, and `gwaf lint` already budgets these.
		if !exact || len(lits) == 0 {
			res.Unconditional = true
			res.Nominated = len(corpus)
			res.Rate = 1
			rep.Rules = append(rep.Rules, res)
			continue
		}

		// One automaton per rule, each literal its own index, so a single scan
		// attributes the hit to the literal that caused it.
		b := prefilter.NewBuilder()
		for i, l := range lits {
			b.Add(string(l), uint32(i))
		}
		auto := b.Build()

		perLit := make([]int, len(lits))
		hits := bitset.New(len(lits))
		var scratch []byte

		for i := range corpus {
			hits.Reset()

			for _, t := range cr.Rule.Targets {
				for _, v := range values[i][t.Kind] {
					scratch = applyChain(scratch[:0], v, cr.Rule.Transforms)
					// Scan returns bytes scanned, for fuel accounting -- not a match
					// count. Reading it as one reports every rule as nominated on
					// every request, which is a number so obviously wrong it was
					// caught on the first run; a subtler misreading would not have
					// been. Nomination is what landed in the set.
					auto.Scan(scratch, hits)
				}
			}
			if !hits.Empty() {
				res.Nominated++
			}
			// Counted once per request per literal: a literal appearing in four
			// arguments of one request is one request that could not be
			// filtered, not four.
			for j := range lits {
				if hits.Has(j) {
					perLit[j]++
				}
			}
		}

		res.Rate = float64(res.Nominated) / float64(len(corpus))
		for j, l := range lits {
			res.Literals = append(res.Literals, LiteralSelectivity{
				Literal:  string(l),
				Requests: perLit[j],
				Rate:     float64(perLit[j]) / float64(len(corpus)),
			})
		}
		sort.SliceStable(res.Literals, func(a, b int) bool {
			return res.Literals[a].Requests > res.Literals[b].Requests
		})

		rep.Rules = append(rep.Rules, res)
	}

	sort.SliceStable(rep.Rules, func(a, b int) bool {
		return rep.Rules[a].Rate > rep.Rules[b].Rate
	})
	return rep, nil
}

// applyChain runs a rule's transforms in order, returning the form the
// prefilter matches against.
//
// This mirrors what the engine does per chain group. It is deliberately the
// simple version — no interning, no prefix reuse — because it runs at build
// time over a fixed corpus and correctness is worth more here than speed.
func applyChain(dst, src []byte, chain []rules.Transform) []byte {
	cur := src
	for _, t := range chain {
		need := t.MaxOutputLen(len(cur))
		if cap(dst) < need {
			dst = make([]byte, 0, need)
		}
		out, changed := t.Apply(dst[:0], cur)
		if changed {
			cur = out
			// The next transform must not write into the buffer it is reading.
			dst = make([]byte, 0, need)
		}
	}
	return cur
}

// targetValues returns the byte strings a request contributes, grouped by the
// target kind that carries them.
//
// Grouping matters, and the first version of this did not do it. Scanning every
// value against every rule overstates nomination for any rule with a narrow
// target: a rule scoped to ARGS was being credited with hits from the request
// URI and from headers it never reads. The reported rate has to be the rate the
// engine would produce, or the first person to check one by hand stops trusting
// the tool -- and a diagnostic nobody trusts is worse than none, because it also
// costs a build step.
//
// Argument *names* are their own group because they are attacker-controlled and
// the engine inspects them separately (ARGS_NAMES); a rule keyed on a parameter
// name would otherwise report perfect selectivity while nominating constantly.
func (r *Request) targetValues() map[types.TargetKind][][]byte {
	out := make(map[types.TargetKind][][]byte, 8)
	add := func(k types.TargetKind, v string) {
		if v != "" {
			out[k] = append(out[k], []byte(v))
		}
	}

	add(types.TargetRequestURI, r.Target)
	add(types.TargetRequestPath, pathOf(r.Target))
	add(types.TargetRequestMethod, r.Method)
	add(types.TargetRequestLine, strings.TrimSpace(r.Method+" "+r.Target))

	for k, v := range r.Args {
		add(types.TargetArgs, v)
		add(types.TargetArgsGet, v)
		add(types.TargetArgsPost, v)
		add(types.TargetArgsJoined, v)
		add(types.TargetArgNames, k)
	}
	for k, v := range r.Headers {
		add(types.TargetRequestHeaders, v)
		add(types.TargetRequestHeaderNames, k)
	}
	add(types.TargetRequestBody, r.Body)
	return out
}

// pathOf strips the query from a request target.
func pathOf(target string) string {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i]
	}
	return target
}

// LiteralSelectivity is how often one literal appears in benign traffic.
type LiteralSelectivity struct {
	Literal string
	// Requests is the number of benign requests containing this literal, counted
	// once per request however many values carry it.
	Requests int
	Rate     float64
}

// RuleSelectivity is how often one rule's prefilter admits benign traffic.
type RuleSelectivity struct {
	ID  types.RuleID
	Msg string

	// Nominated is the number of benign requests in which at least one literal
	// appeared — that is, requests on which this rule is evaluated and rejects.
	Nominated int
	Requests  int
	Rate      float64

	// Unconditional is set when the operator declares no exact literal set, so
	// the rule runs on every request regardless of content.
	Unconditional bool

	// Literals is sorted worst-first: the literal admitting the most traffic
	// comes first, because it is the one to change.
	Literals []LiteralSelectivity
}

// Worst returns the literal admitting the most benign traffic.
func (r RuleSelectivity) Worst() (LiteralSelectivity, bool) {
	if len(r.Literals) == 0 {
		return LiteralSelectivity{}, false
	}
	return r.Literals[0], true
}

// SelectivityReport is the measurement for a whole ruleset.
type SelectivityReport struct {
	Requests int
	// Rules is sorted worst-first by nomination rate.
	Rules []RuleSelectivity
}

// Above returns the rules nominated on at least rate of the corpus.
//
// The threshold is the caller's, because what counts as too much depends on the
// rule: a rule keyed on "://" is expected to see every request carrying a URL,
// and a rule keyed on a SQL keyword is not.
func (rep SelectivityReport) Above(rate float64) []RuleSelectivity {
	var out []RuleSelectivity
	for _, r := range rep.Rules {
		if r.Rate >= rate {
			out = append(out, r)
		}
	}
	return out
}
