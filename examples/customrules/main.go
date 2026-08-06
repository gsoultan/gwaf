// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Command customrules shows how an application writes its own rules.
//
//	go run ./customrules
//
// It runs a table of requests through a WAF built from custom rules and prints
// what happened to each, so the whole thing is visible without a browser.
//
// # The order here is the order you should reach for things
//
// Most custom rules are a struct literal and a built-in operator, and that is
// where to stay. Everything below it costs more — in latency, in review, or in
// the chance of being subtly wrong — and the file is arranged so the cheap
// answers come first:
//
//  1. a rule from a struct literal with a built-in operator
//  2. op.Func, the escape hatch, and what it costs
//  3. op.Func with a literal hint, which buys the cost back
//  4. a custom Operator, when a predicate is not enough
//  5. a custom Transform
//  6. a custom Action, where metrics and audit get wired
//  7. a Resolver, for a signal gwaf deliberately does not compute
//  8. an Exception, for when one of your rules is wrong about one route
//
// Points 4 through 7 are the four extension interfaces (docs/RULES.md §4).
// Nothing here needs a fork, and nothing here needs internal/.
package main

import (
	"bytes"
	"fmt"
	"iter"
	"strings"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

// Rule IDs. Yours, in a band that cannot collide with gwaf's core ruleset,
// which uses 1..99,999. An ID is not decoration: it is what an audit log
// records, what `gwaf explain` looks up, and what an exception refers to, so it
// has to stay stable once anything has seen it.
const (
	ruleLegacyAdminPath types.RuleID = 1_000_001
	ruleInternalToken   types.RuleID = 1_000_002
	ruleTenantMismatch  types.RuleID = 1_000_003
	ruleReversedSecret  types.RuleID = 1_000_004
	ruleUntrustedASN    types.RuleID = 1_000_005
)

func main() {
	auditLog := &auditAction{}

	set := rules.Set{
		// ---- 1. A struct literal and a built-in operator --------------------
		//
		// This covers most of what an application needs. Rules are data: they
		// serialize, diff, and code-review, and a typo in a target name is a
		// build failure rather than a rule that silently never fires.
		{
			ID:      ruleLegacyAdminPath,
			Phase:   types.PhaseRequestHeaders,
			Targets: []types.Target{{Kind: types.TargetRequestPath}},
			// Normalisation runs before the operator, so "/ADMIN/../admin/tools"
			// and "/admin/tools" are matched by the same rule.
			Transforms: []rules.Transform{transform.Lowercase, transform.NormalizePath},
			Op:         op.HasPrefix("/internal/"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			// Certain because this is a fact about your own routing, not a
			// guess about intent: nothing outside your network should reach it.
			Confidence: types.Certain,
			Msg:        "internal-only path reached from outside",
			Tags:       []string{"policy", "internal"},
		},

		// ---- 2 and 3. The escape hatch, and buying back its cost ------------
		//
		// op.Func takes any predicate. The engine cannot read literals out of a
		// Go function, so a bare Func rule is *unconditional*: it runs against
		// every value in its phase, and `gwaf lint` reports it as a latency
		// cost rather than letting it hide.
		//
		// WithLiterals buys that back by asserting what the predicate requires.
		// It is the one place in the API where you can be wrong without being
		// told — if the predicate can match input containing none of these
		// bytes, the rule silently stops firing — so state what the code
		// actually looks for, not what you expect to see.
		{
			ID:         ruleInternalToken,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetRequestHeaders}},
			Transforms: []rules.Transform{transform.Lowercase},
			Op: op.Func("internal-service-token", func(v []byte) bool {
				// A token minted for service-to-service calls, arriving from a
				// client. Cheap to check, impossible to express as a literal
				// alone, which is what makes it a Func.
				return bytes.HasPrefix(v, []byte("svc_")) && len(v) == 34
			}).WithLiterals("svc_"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "internal service token presented by an external client",
			Tags:       []string{"policy", "credentials"},
		},

		// ---- 4. A custom Operator -------------------------------------------
		//
		// When a predicate is not enough: an Operator can report *where* it
		// matched, declare its own literals, and price itself in the same fuel
		// the engine meters. See tenantOperator below.
		{
			ID:         ruleTenantMismatch,
			Phase:      types.PhaseRequestBody,
			Targets:    []types.Target{{Kind: types.TargetArgs, Name: "tenant"}},
			Op:         &tenantOperator{allowed: "acme"},
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityCritical,
			Confidence: types.Certain,
			Msg:        "request names a tenant the caller does not belong to",
			Tags:       []string{"policy", "multi-tenancy"},
		},

		// ---- 5. A custom Transform ------------------------------------------
		//
		// Normalisation your application performs and gwaf does not know about.
		// This one reverses the value, standing in for a bespoke encoding a
		// legacy client uses; the rule then matches what the origin will see
		// rather than what arrived.
		{
			ID:         ruleReversedSecret,
			Phase:      types.PhaseRequestHeaders,
			Targets:    []types.Target{{Kind: types.TargetArgs, Name: "legacy"}},
			Transforms: []rules.Transform{reverseTransform{}},
			Op:         op.Contains("secret"),
			Actions:    []rules.Action{rules.Block},
			Severity:   types.SeverityError,
			Confidence: types.High,
			Msg:        "legacy-encoded value carries a secret marker",
			Tags:       []string{"policy", "legacy"},
		},

		// ---- 6 and 7. A custom Action, and a Resolver ------------------------
		//
		// The Resolver supplies a score gwaf deliberately does not compute:
		// reputation needs state across requests, which is the embedder's by
		// the scope line in CLAUDE.md §1. gwaf consumes it; it never maintains
		// one. The Action is where the finding turns into a metric.
		{
			ID:      ruleUntrustedASN,
			Phase:   types.PhaseRequestHeaders,
			Targets: []types.Target{{Kind: types.TargetResolved, Name: "reputation.asn"}},
			Op:      op.ContainsAny("AS64496", "AS64511"),
			Actions: []rules.Action{auditLog, rules.Block},
			// High rather than Certain: a shared hosting ASN carries real users
			// as well as scanners, and this is the kind of rule that earns its
			// tier from `gwaf calibrate` against your own traffic.
			Severity:   types.SeverityWarning,
			Confidence: types.High,
			Msg:        "request from an autonomous system on the block list",
			Tags:       []string{"policy", "reputation"},
		},
	}

	waf, err := gwaf.New(
		gwaf.WithRuleset(set),

		// ---- 8. An Exception -------------------------------------------------
		//
		// One of your own rules will eventually be wrong about one route. The
		// narrow form is the short one on purpose: every field set must match,
		// so this silences exactly one finding and nothing else — not the same
		// rule elsewhere, not another argument here.
		//
		// Decision.Explain().NarrowestException() computes this for a finding
		// that already happened, so it is a value to copy rather than derive.
		gwaf.WithException(rules.Exception{
			RuleID: ruleTenantMismatch,
			Path:   "/api/v1/admin/tenants",
			Target: types.TargetArgs,
			Key:    "tenant",
			Note:   "the tenant-admin endpoint legitimately names other tenants",
		}),
	)
	if err != nil {
		panic(err)
	}

	run(waf)
	fmt.Printf("\naudit action fired %d time(s)\n", auditLog.count)
}

// ---- 4. Operator ------------------------------------------------------------

// tenantOperator reports a tenant identifier that is not the caller's.
//
// One of the four extension interfaces. Note what it has to provide beyond a
// predicate: a matched span so the decision is explainable, the literals that
// let the prefilter skip it, and a cost in the units the engine meters.
type tenantOperator struct{ allowed string }

func (o *tenantOperator) Name() string { return "tenant_mismatch" }

func (o *tenantOperator) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	if len(value) == 0 || string(value) == o.allowed {
		return rules.Match{}, false
	}
	// The span is what makes a block explainable: Explain() reports these exact
	// bytes, and a rule that cannot produce one is not a rule.
	return rules.Match{Span: types.SpanOf(0, len(value))}, true
}

// Literals reports that nothing is required, because this operator matches on
// *absence* of the expected value and no byte sequence has to be present.
//
// Honest rather than convenient: claiming a literal here would make the rule
// silently stop firing. The cost of saying so is that the rule is
// unconditional, and `gwaf lint` reports it.
func (o *tenantOperator) Literals() ([]string, bool) { return nil, false }

// Cost prices one evaluation in the same units the engine meters, so a custom
// operator cannot escape the per-request fuel bound.
func (o *tenantOperator) Cost() types.Fuel { return types.CostLiteralMatch }

// ---- 5. Transform -----------------------------------------------------------

// reverseTransform stands in for a bespoke encoding an application undoes.
//
// A Transform must be pure, and it must be allocation-free when the value is
// already normal — returning the input slice unchanged is what lets benign
// traffic cost nothing.
type reverseTransform struct{}

func (reverseTransform) Name() string { return "custom_reverse" }

func (reverseTransform) Apply(dst, src []byte) ([]byte, bool) {
	if len(src) < 2 {
		return src, false // unchanged: no copy, no allocation
	}
	dst = dst[:0]
	for i := len(src) - 1; i >= 0; i-- {
		dst = append(dst, src[i])
	}
	return dst, true
}

// MaxOutputLen lets the engine size its scratch space once, up front.
func (reverseTransform) MaxOutputLen(n int) int { return n }

// ---- 6. Action --------------------------------------------------------------

// auditAction counts findings and then blocks.
//
// This is where an embedder wires metrics, audit, and alerting: gwaf produces
// findings, and what they mean is the application's decision.
type auditAction struct{ count int }

func (*auditAction) Name() string { return "audit_and_block" }

func (a *auditAction) Run(ctx *rules.EvalContext, m rules.Match) rules.Outcome {
	a.count++
	_ = ctx // ctx carries the target and key the match came from
	_ = m   // m carries the matched span
	return rules.Outcome{Kind: rules.ActionBlock}
}

// ---- 7. Resolver ------------------------------------------------------------

// reputationResolver supplies a signal gwaf deliberately does not compute.
//
// Registered per transaction because it closes over data specific to one
// request, and called only if a rule in the phase reads its name — a reputation
// lookup is expensive, which is the whole reason it is outside gwaf's scope.
type reputationResolver struct{ score, asn string }

func (reputationResolver) Name() string { return "reputation" }

func (r reputationResolver) Resolve() iter.Seq2[string, []byte] {
	return func(yield func(string, []byte) bool) {
		// In a real application this is where the lookup happens, and it happens
		// here rather than earlier precisely so it can be skipped.
		if !yield("score", []byte(r.score)) {
			return
		}
		yield("asn", []byte(r.asn))
	}
}

// ---- driving it -------------------------------------------------------------

type sample struct {
	name   string
	method string
	target string
	args   map[string]string
	header [2]string
	asn    string
}

func run(waf *gwaf.WAF) {
	samples := []sample{
		{name: "ordinary request", target: "/api/v1/orders?page=2"},
		{name: "internal path", target: "/api/../internal/metrics"},
		{name: "service token from outside", target: "/api/v1/orders",
			header: [2]string{"Authorization", "svc_0123456789abcdef0123456789abcd"}},
		{name: "wrong tenant", target: "/api/v1/reports",
			args: map[string]string{"tenant": "globex"}},
		{name: "wrong tenant, excepted route", target: "/api/v1/admin/tenants",
			args: map[string]string{"tenant": "globex"}},
		{name: "legacy encoded secret", target: "/api/v1/legacy",
			args: map[string]string{"legacy": "terces-eslaf"}},
		{name: "hostile ASN", target: "/api/v1/orders", asn: "AS64496"},
		{name: "ordinary ASN", target: "/api/v1/orders", asn: "AS15169"},
		// The core ruleset is still loaded underneath: custom rules add to it
		// rather than replacing it.
		{name: "sql injection (core rule)", target: "/api/v1/orders",
			args: map[string]string{"q": "1' OR 1=1--"}},
	}

	fmt.Printf("%-32s %-8s %-8s %s\n", "request", "verdict", "rule", "why")
	fmt.Println(strings.Repeat("-", 92))

	for _, s := range samples {
		tx := waf.NewTransaction()

		if s.asn != "" {
			tx.AddResolver(reputationResolver{score: "12", asn: s.asn})
		}
		method := s.method
		if method == "" {
			method = "GET"
		}
		tx.SetRequestLine(method, s.target, "HTTP/1.1")
		tx.SetRemoteAddr("192.0.2.1")
		if s.header[0] != "" {
			tx.AddRequestHeader(s.header[0], s.header[1])
		}
		for k, v := range s.args {
			tx.AddArgument(k, v)
		}

		d := tx.ProcessRequestHeaders()
		if !d.Blocked() {
			d = tx.ProcessRequestBody()
		}

		verdict, why := "allow", "—"
		if d.Blocked() {
			verdict = "BLOCK"
			// Explain carries everything a control plane would draw: the rule,
			// the matched bytes, the transform chain that produced them, and
			// the narrowest exception that would allow this one request.
			why = d.Explain().Message()
		}
		fmt.Printf("%-32s %-8s %-8d %s\n", s.name, verdict, d.RuleID(), why)

		tx.Close()
	}
}
