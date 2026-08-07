// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package telemetry counts what a WAF operator needs to see.
//
// # Why gwaf ships counters but not an exporter
//
// A WAF that cannot be observed cannot be trusted: "it is blocking things" is
// not an operational statement, and the questions that matter — how much traffic
// is blocked, by which rules, at what latency, and how often the budget runs out
// — are all counters.
//
// What gwaf will not do is choose your metrics system. An OpenTelemetry or
// Prometheus exporter is a dependency the embedder did not pick, which is the
// fifth ownership test in CLAUDE.md §1. So this package keeps the counters with
// the standard library alone and hands them over through Snapshot; wiring them
// into OTel, Prometheus, statsd, or a log line is ten lines in the embedder and
// zero dependencies here.
//
// # What is counted, and what is not
//
// Counters are per-WAF and cumulative. There are no histograms of arbitrary
// dimension and no per-route cardinality, because unbounded label cardinality is
// how a metrics endpoint becomes the outage — and gwaf's first invariant is that
// the WAF must never be the outage. Per-rule counts are bounded by the ruleset,
// which is bounded at compile time.
//
// # Concurrency
//
// A Metrics is safe for concurrent use by any number of goroutines. Counters use
// atomics; the per-rule map is guarded and only written on a match, which on
// ordinary traffic is rare.
package telemetry

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/types"
)

// Metrics accumulates counters for one WAF.
//
// The zero value is ready to use.
type Metrics struct {
	requests  atomic.Uint64
	blocked   atomic.Uint64
	allowed   atomic.Uint64
	errors    atomic.Uint64
	exhausted atomic.Uint64
	undecl    atomic.Uint64

	nanos atomic.Uint64 // total inspection time, for a mean
	maxNs atomic.Uint64

	mu       sync.Mutex
	byRule   map[uint32]uint64
	bySevere map[string]uint64
}

// Observe records one decision.
//
// d is the outcome and elapsed is how long inspection took. Pass a zero duration
// if the caller does not measure it; the latency counters simply stay at zero
// rather than reporting a number nobody produced.
func (m *Metrics) Observe(d gwaf.Decision, elapsed time.Duration) {
	m.requests.Add(1)
	if d.Blocked() {
		m.blocked.Add(1)
	} else {
		m.allowed.Add(1)
	}

	switch d.Reason() {
	case gwaf.ReasonBudget:
		// Budget exhaustion is its own counter rather than an error, because it
		// is the signal that the deployment's fuel limit is too low for its
		// traffic — actionable, and invisible if folded into a generic error.
		m.exhausted.Add(1)
	case gwaf.ReasonLimit, gwaf.ReasonDesync, gwaf.ReasonUndecidable:
		// Requests gwaf could not fully analyse, for reasons that are not the
		// fuel budget: a ceiling was hit, the framing was ambiguous, or the body
		// could not be decoded. Grouped because the operator response is the
		// same — find out why analysis is incomplete — and separated from
		// Exhausted because that one is fixed by raising a number.
		m.errors.Add(1)
	}

	if elapsed > 0 {
		ns := uint64(elapsed.Nanoseconds())
		m.nanos.Add(ns)
		for {
			cur := m.maxNs.Load()
			if ns <= cur || m.maxNs.CompareAndSwap(cur, ns) {
				break
			}
		}
	}

	if d.RuleID() == 0 {
		return
	}
	// Taken only on a match, so the ordinary path never contends on this lock.
	m.mu.Lock()
	if m.byRule == nil {
		m.byRule = map[uint32]uint64{}
		m.bySevere = map[string]uint64{}
	}
	m.byRule[uint32(d.RuleID())]++
	m.bySevere[d.Severity().String()]++
	m.mu.Unlock()
}

// ObserveUndeclared records a request that matched no schema operation — a
// shadow endpoint. Counted separately because it is a coverage signal rather
// than a security one: it says the schema is incomplete, not that anyone
// attacked anything.
func (m *Metrics) ObserveUndeclared() { m.undecl.Add(1) }

// Snapshot is a consistent-enough read of the counters.
//
// "Consistent enough" is deliberate: the counters are read without a global
// lock, so a snapshot taken during traffic may catch requests and blocked one
// increment apart. Taking a lock across all of them would put a mutex on the
// request path to make a monitoring endpoint prettier, which is the wrong trade.
type Snapshot struct {
	Requests uint64
	Blocked  uint64
	Allowed  uint64
	// Errors counts requests that could not be fully analysed for a reason other
	// than fuel: a limit, a framing conflict, or an undecodable body.
	Errors    uint64
	Exhausted uint64

	// Undeclared counts requests matching no schema operation.
	Undeclared uint64

	// MeanLatency and MaxLatency are zero when the caller passed no durations.
	MeanLatency time.Duration
	MaxLatency  time.Duration

	// ByRule and BySeverity are copies, safe to keep and iterate.
	ByRule     map[uint32]uint64
	BySeverity map[string]uint64
}

// BlockRate returns the fraction of requests blocked, 0 when none were seen.
//
// This is the number an operator watches after a ruleset change: a rate that
// jumps is either an attack or a false positive, and which one it is comes from
// ByRule.
func (s Snapshot) BlockRate() float64 {
	if s.Requests == 0 {
		return 0
	}
	return float64(s.Blocked) / float64(s.Requests)
}

// Snapshot reads the current counters.
func (m *Metrics) Snapshot() Snapshot {
	reqs := m.requests.Load()
	s := Snapshot{
		Requests:   reqs,
		Blocked:    m.blocked.Load(),
		Allowed:    m.allowed.Load(),
		Errors:     m.errors.Load(),
		Exhausted:  m.exhausted.Load(),
		Undeclared: m.undecl.Load(),
		MaxLatency: time.Duration(m.maxNs.Load()),
	}
	if total := m.nanos.Load(); total > 0 && reqs > 0 {
		s.MeanLatency = time.Duration(total / reqs)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.byRule) > 0 {
		s.ByRule = make(map[uint32]uint64, len(m.byRule))
		for k, v := range m.byRule {
			s.ByRule[k] = v
		}
	}
	if len(m.bySevere) > 0 {
		s.BySeverity = make(map[string]uint64, len(m.bySevere))
		for k, v := range m.bySevere {
			s.BySeverity[k] = v
		}
	}
	return s
}

// Reset zeroes every counter. Intended for tests and for an operator resetting a
// window deliberately, not for scraping — a scrape that resets loses whatever
// happened between the read and the reset.
func (m *Metrics) Reset() {
	m.requests.Store(0)
	m.blocked.Store(0)
	m.allowed.Store(0)
	m.errors.Store(0)
	m.exhausted.Store(0)
	m.undecl.Store(0)
	m.nanos.Store(0)
	m.maxNs.Store(0)

	m.mu.Lock()
	m.byRule = nil
	m.bySevere = nil
	m.mu.Unlock()
}

// TopRules returns the n most-fired rule IDs, most frequent first.
//
// This is the tuning view: the rule at the top of this list after a deployment
// is either the one doing the most work or the one producing the most false
// positives, and Explain on any one of its decisions says which.
func (s Snapshot) TopRules(n int) []RuleCount {
	if len(s.ByRule) == 0 || n <= 0 {
		return nil
	}
	out := make([]RuleCount, 0, len(s.ByRule))
	for id, c := range s.ByRule {
		out = append(out, RuleCount{RuleID: types.RuleID(id), Count: c})
	}
	// Selection sort over the top n: the ruleset is bounded and n is small, so
	// this avoids pulling in sort for a handful of elements.
	if n > len(out) {
		n = len(out)
	}
	for i := 0; i < n; i++ {
		best := i
		for j := i + 1; j < len(out); j++ {
			if out[j].Count > out[best].Count ||
				(out[j].Count == out[best].Count && out[j].RuleID < out[best].RuleID) {
				best = j
			}
		}
		out[i], out[best] = out[best], out[i]
	}
	return out[:n]
}

// RuleCount is one rule and how often it fired.
type RuleCount struct {
	RuleID types.RuleID
	Count  uint64
}
