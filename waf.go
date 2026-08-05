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

	w := &WAF{cfg: cfg}
	w.ruleset.Store(rs)
	w.txPool.New = func() any { return newTransaction(w) }
	return w, nil
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
