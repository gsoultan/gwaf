// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf

import (
	"strconv"
	"strings"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// Explanation is the full anatomy of one decision, as data.
//
// gwaf ships no UI and never will, but "no UI" is not a licence to withhold
// information (CLAUDE.md §2b). Everything a control plane would want to draw —
// what fired, which bytes matched, how the input was normalised to get there,
// and the narrowest exception that would have allowed it — has to be reachable
// programmatically, or the missing accessor is a tier-1 API gap.
//
// # Why this hangs off Decision rather than off WAF
//
// docs/INTEGRATION.md used to describe `waf.Explain(txID)`, and that API cannot
// exist: looking a transaction up by ID means the WAF remembers transactions,
// which is cross-request state and the first of the five ownership tests. gwaf
// analyses one request in isolation and keeps nothing. So the explanation
// travels with the decision the caller already holds.
//
// An Explanation borrows nothing from the transaction arena — MatchedBytes is
// copied — so it stays valid after the transaction is closed and can be handed
// to an audit sink or a queue.
type Explanation struct {
	ruleID     types.RuleID
	message    string
	severity   types.Severity
	confidence types.Confidence
	tags       []string

	target    types.Target
	key       string
	span      types.Span
	hasSpan   bool
	matched   []byte
	transform []string
	reading   string

	path        string
	derivedFrom types.RuleID
	verdict     Verdict
	reason      Reason
	score       int
	evaluated   int
}

// RuleID is the rule that produced the decision, or zero if none did.
func (e Explanation) RuleID() types.RuleID { return e.ruleID }

// Message is the rule's human-readable description.
func (e Explanation) Message() string { return e.message }

// Severity is the rule's declared severity.
func (e Explanation) Severity() types.Severity { return e.severity }

// Confidence is the rule's declared confidence tier.
func (e Explanation) Confidence() types.Confidence { return e.confidence }

// Tags are the rule's classification tags.
func (e Explanation) Tags() []string { return e.tags }

// Target is the collection the matched value came from.
func (e Explanation) Target() types.Target { return e.target }

// Key is the specific value's name — a header name, an argument name, a JSON
// field path — or empty for unkeyed collections.
func (e Explanation) Key() string { return e.key }

// MatchedSpan is the byte range within the transformed value that matched,
// and whether there was one.
func (e Explanation) MatchedSpan() (types.Span, bool) { return e.span, e.hasSpan }

// MatchedBytes is a copy of the bytes that matched.
//
// Copied rather than borrowed: the transaction arena is recycled on Close, and
// an explanation that dangles into a reused buffer is worse than no explanation
// at all — it reports a different request's data with total confidence.
func (e Explanation) MatchedBytes() []byte { return e.matched }

// TransformChain is the normalization applied before the operator ran, in
// order. This is the step operators most often need and most often cannot get:
// a payload that looks harmless on the wire matched because it was decoded, and
// without the chain the finding reads as a malfunction.
func (e Explanation) TransformChain() []string { return e.transform }

// Interpretation names the decoding under which the match was found, or "none"
// when the value matched as sent. A finding visible only under an alternative
// reading is the most confusing kind to meet in a log.
func (e Explanation) Interpretation() string { return e.reading }

// Verdict is what gwaf recommends.
func (e Explanation) Verdict() Verdict { return e.verdict }

// Reason is why.
func (e Explanation) Reason() Reason { return e.reason }

// Score is the accumulated anomaly score at the point of decision.
func (e Explanation) Score() int { return e.score }

// RulesEvaluated is how many rules actually ran.
func (e Explanation) RulesEvaluated() int { return e.evaluated }

// NarrowestException returns the tightest exception that would have allowed
// this request, and whether one exists.
//
// "Tightest" means every field the finding pins down is pinned down: the rule,
// the request path, the collection, and the specific key. Suppressing that
// exception silences this finding and nothing else — not the same rule on
// another route, not another argument on the same route.
//
// This is the whole point of computing it rather than leaving it to an
// operator. Under time pressure the exception a human writes is
// `{RuleID: 7002}`, because it is the one they can be sure will work, and it
// disables the rule everywhere. Handing back the narrow form makes the correct
// fix the cheap one.
//
// It is a suggestion, not an endorsement. CLAUDE.md §6 prefers deleting a rule
// over excepting it, and a rule needing exceptions on many routes is a rule
// that is wrong rather than a rule that needs tuning.
func (e Explanation) NarrowestException() (rules.Exception, bool) {
	if e.ruleID == 0 {
		return rules.Exception{}, false
	}
	// Scoped to the authored rule when this finding came from a generated
	// counterpart, so the exception covers the detection at every phase rather
	// than at the one that happened to fire first.
	id := e.ruleID
	if e.derivedFrom != 0 {
		id = e.derivedFrom
	}
	return rules.Exception{
		RuleID: id,
		Path:   e.path,
		Target: e.target.Kind,
		Key:    e.key,
		Note:   "suppresses " + e.message + " for this route and field only",
	}, true
}

// String renders the explanation as an operator would want to read it.
func (e Explanation) String() string {
	var b strings.Builder
	b.WriteString("rule ")
	b.WriteString(strconv.FormatUint(uint64(e.ruleID), 10))
	b.WriteString(": ")
	b.WriteString(e.message)
	b.WriteString("\n  severity:   ")
	b.WriteString(e.severity.String())
	b.WriteString("\n  confidence: ")
	b.WriteString(e.confidence.String())
	b.WriteString("\n  target:     ")
	b.WriteString(e.target.String())
	if e.key != "" {
		b.WriteString(" [")
		b.WriteString(e.key)
		b.WriteString("]")
	}
	if e.hasSpan {
		b.WriteString("\n  matched:    ")
		b.WriteString(strconv.Quote(string(e.matched)))
		b.WriteString(" at offset ")
		b.WriteString(strconv.Itoa(int(e.span.Off)))
	}
	if len(e.transform) > 0 {
		b.WriteString("\n  transforms: ")
		b.WriteString(strings.Join(e.transform, " → "))
	}
	if e.reading != "" && e.reading != "none" {
		b.WriteString("\n  found under: ")
		b.WriteString(e.reading)
	}
	if x, ok := e.NarrowestException(); ok {
		b.WriteString("\n  to suppress just this finding:\n    rules.Exception{RuleID: ")
		b.WriteString(strconv.FormatUint(uint64(x.RuleID), 10))
		if x.Path != "" {
			b.WriteString(", Path: ")
			b.WriteString(strconv.Quote(x.Path))
		}
		b.WriteString(", Target: types.")
		b.WriteString(x.Target.ConstName())
		if x.Key != "" {
			b.WriteString(", Key: ")
			b.WriteString(strconv.Quote(x.Key))
		}
		b.WriteString("}")
	}
	return b.String()
}

// Explain returns the full anatomy of this decision.
//
// Safe to call on any Decision, including one that allowed the request: the
// result then carries the verdict and the evaluation count with no rule.
func (d Decision) Explain() Explanation {
	e := Explanation{
		target:      d.target,
		key:         d.key,
		path:        d.path,
		verdict:     d.verdict,
		derivedFrom: d.derivedFrom,
		reason:      d.reason,
		score:       d.score,
		evaluated:   d.rulesEvaluated,
		reading:     d.reading.String(),
	}
	if d.rule == nil || d.rule.Rule == nil {
		return e
	}

	r := d.rule.Rule
	e.ruleID = r.ID
	e.message = r.Msg
	e.severity = r.Severity
	e.confidence = r.Confidence
	e.tags = r.Tags

	for _, t := range r.Transforms {
		e.transform = append(e.transform, t.Name())
	}
	if d.hit != nil && d.hit.Span.Len > 0 {
		e.span = d.hit.Span
		e.hasSpan = true
		e.matched = append([]byte(nil), d.matchedBytes...)
	}
	return e
}
