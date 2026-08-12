// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package gwaf

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gwaf/internal/engine"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
	"github.com/gsoultan/gwaf/schema"
	"github.com/gsoultan/gwaf/types"
)

// WAF is a compiled, ready-to-use firewall.
//
// A WAF is safe for concurrent use by any number of goroutines. A Transaction
// obtained from it is not: each is owned by exactly one goroutine for its
// lifetime. That distinction is the most common misuse of every WAF library, so
// it is stated on both types.
//
// A WAF holds no global state. Any number of independent instances may coexist
// in one process with different rulesets, which is what makes multi-tenant
// embedding and parallel tests work.
type WAF struct {
	cfg config

	// ruleset is swapped atomically so a reload never exposes a partially
	// applied plan. In-flight transactions finish against the plan they
	// started with, which keeps audit logs reconstructable.
	ruleset atomic.Pointer[rules.Ruleset]

	// diags is computed once at construction and read-only thereafter, so
	// Diagnostics needs no lock.
	diags []Diagnostic

	txPool sync.Pool
}

// New compiles a WAF from options.
//
// With no options it returns a working, blocking WAF: safe defaults, sensible
// limits, and no configuration files to find. Adding rules is additive.
func New(opts ...Option) (*WAF, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if cfg.err != nil {
		return nil, cfg.err
	}

	// With no ruleset supplied, load the core set. New() with zero arguments
	// must return a WAF that actually protects something: requiring
	// configuration before a library does its job is how integrations end up
	// shipping an inert firewall.
	set := cfg.ruleset
	if !cfg.coreDisabled {
		set = append(core.Default(), set...)
	}
	set = selectByConfidence(set, cfg.minConf)

	rs, err := rules.Compile(set, rules.Options{})
	if err != nil {
		return nil, fmt.Errorf("gwaf: compiling ruleset: %w", err)
	}

	w := &WAF{cfg: cfg, diags: diagnose(&cfg, set)}
	w.ruleset.Store(rs)
	w.txPool.New = func() any { return newTransaction(w) }
	return w, nil
}

// Diagnostic reports a rule that compiled cleanly and will still not detect
// what its presence in the ruleset suggests it does.
//
// This is not a compile error: every rule here is well-formed, and an embedder
// may have declined the missing capability on purpose. It is the gap between
// what a ruleset looks like it covers and what it covers, which is otherwise
// visible only by reading the engine.
//
// The two cases it reports today are both ones gwaf shipped and could not see:
// an off-origin rule with no origins to compare against, and an argument rule
// with no body-phase counterpart, which inspects the query string while the
// payload arrives in JSON.
type Diagnostic struct {
	// ID and Msg identify the rule as it appears in a Decision.
	ID  types.RuleID
	Msg string

	// Reason states what the rule cannot do, in one sentence.
	Reason string

	// Fix names the option or helper that closes it.
	Fix string
}

// Diagnostics returns the rules that compiled but cannot detect what they
// appear to, in ruleset order. An empty result is the healthy answer.
//
// New logs the first of these once. It is returned as data because a log line
// is not an API: a control plane building a coverage view has to be able to ask
// (CLAUDE.md 2b -- every datum a UI would need is reachable programmatically).
//
//	for _, d := range waf.Diagnostics() {
//	    log.Warn("coverage gap", "rule", d.ID, "reason", d.Reason, "fix", d.Fix)
//	}
//
// The result is computed once at construction from the ruleset New compiled.
// It does not follow SwapRuleset, which takes an already-compiled ruleset.
func (w *WAF) Diagnostics() []Diagnostic {
	if len(w.diags) == 0 {
		return nil
	}
	out := make([]Diagnostic, len(w.diags))
	copy(out, w.diags)
	return out
}

// diagnose finds rules that compiled and cannot decide what they look like they
// decide.
//
// Losing coverage must never be quieter than gaining it. Both cases here were
// live in this repository: the off-origin rules went inert across a version
// bump and the benchmark harness kept publishing their numbers, and the opt-in
// SSRF rule has never had a body counterpart, so the one-liner in its own
// godoc inspected the query string of endpoints that take JSON.
func diagnose(cfg *config, set rules.Set) []Diagnostic {
	var out []Diagnostic

	// Rules that need a "here" to call a destination foreign to.
	if len(cfg.origins) == 0 {
		for i := range set {
			switch set[i].Op.Name() {
			case "off_origin_navigation_url", "off_origin_fetch_url":
				out = append(out, Diagnostic{
					ID:  set[i].ID,
					Msg: set[i].Msg,
					Reason: "no origins declared, so no destination can be shown to be off-origin; " +
						"the request's own Host header is attacker-supplied and cannot stand in",
					Fix: `gwaf.WithOrigins("your.host")`,
				})
			}
		}
	}

	// Argument rules that will only ever see the query string.
	//
	// Checked by ID rather than by asking core, so it holds for a rule from any
	// source: a counterpart declares the rule it came from in DerivedFrom.
	mirrored := make(map[types.RuleID]bool, len(set))
	for i := range set {
		if set[i].DerivedFrom != 0 {
			mirrored[set[i].DerivedFrom] = true
		}
	}
	for i := range set {
		if set[i].Phase != types.PhaseRequestHeaders || mirrored[set[i].ID] {
			continue
		}
		if !readsArgValues(set[i].Targets) {
			continue
		}
		out = append(out, Diagnostic{
			ID:  set[i].ID,
			Msg: set[i].Msg,
			Reason: "inspects arguments at the header phase only, so it sees the query string " +
				"and not a form or JSON body",
			Fix: "core.WithBodyPhase(rules.Set{...}) when adding the rule",
		})
	}

	if cfg.logger != nil && len(out) > 0 {
		// Phrased as a capability that is off rather than a firewall that is
		// broken, and only the first is logged. Both readers see this line:
		// somebody who has lost coverage and needs to know, and somebody in
		// their first ten seconds with the library, who has not lost anything
		// and should not be alarmed on line one of the README.
		d := out[0]
		cfg.logger.Info(
			"gwaf: a rule cannot detect what it looks like it detects: "+d.Reason+". "+
				"Fix with "+d.Fix+". "+
				"Call (*gwaf.WAF).Diagnostics for the full list.",
			"rule", d.ID, "msg", d.Msg, "total", len(out))
	}
	return out
}

// readsArgValues reports whether targets inspect argument values as a
// collection, which is what makes a body-phase counterpart meaningful. A rule
// scoped to one named argument or to the request path has no body equivalent.
func readsArgValues(targets []types.Target) bool {
	for _, t := range targets {
		if t.Kind == types.TargetArgs && t.Name == "" {
			return true
		}
	}
	return false
}

// selectByConfidence drops rules below the configured minimum tier.
//
// Selection happens at compile time, not per request: a rule the policy will
// never run costs nothing at runtime because it was never compiled into the
// plan or the prefilter automaton.
func selectByConfidence(set rules.Set, min types.Confidence) rules.Set {
	out := make(rules.Set, 0, len(set))
	for i := range set {
		if set[i].Confidence.AtLeast(min) {
			out = append(out, set[i])
		}
	}
	return out
}

// Ruleset returns the active compiled ruleset.
func (w *WAF) Ruleset() *rules.Ruleset { return w.ruleset.Load() }

// Report returns the active ruleset's compile summary.
func (w *WAF) Report() rules.Report { return w.ruleset.Load().Report() }

// Schema returns the configured API description, or nil.
func (w *WAF) Schema() *schema.Schema { return w.cfg.schema }

// Mode returns the configured enforcement mode.
func (w *WAF) Mode() Mode { return w.cfg.mode }

// SwapRuleset atomically replaces the active plan.
//
// Compilation and swap are separate on purpose: a ruleset is validated off the
// request path and the swap itself cannot fail, so a bad ruleset never goes
// live. In-flight transactions complete against the plan they started with.
func (w *WAF) SwapRuleset(rs *rules.Ruleset) {
	if rs == nil {
		return
	}
	w.ruleset.Store(rs)
}

// Compile builds a ruleset using this WAF's confidence policy, for later use
// with SwapRuleset.
func (w *WAF) Compile(set rules.Set) (*rules.Ruleset, error) {
	return rules.Compile(selectByConfidence(set, w.cfg.minConf), rules.Options{})
}

// NewTransaction begins analysing one request.
//
// The returned Transaction is owned by the calling goroutine and must be closed
// with Close, which returns its buffers to the pool. Failing to close leaks
// nothing permanently but forfeits the pooling that keeps steady-state
// allocation at zero.
func (w *WAF) NewTransaction() *Transaction {
	tx := w.txPool.Get().(*Transaction)
	tx.reset(w.ruleset.Load())
	return tx
}

// newTransaction constructs a pooled Transaction.
func newTransaction(w *WAF) *Transaction {
	rs := w.ruleset.Load()
	return &Transaction{
		waf:  w,
		eval: engine.NewEvaluator(rs),
	}
}
