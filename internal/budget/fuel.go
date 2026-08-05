// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package budget meters the work a single transaction is allowed to perform.
//
// Work is counted in fuel rather than wall-clock time. Consulting the clock per
// rule costs more than many rules do, and a wall-clock budget is
// nondeterministic: the same request can pass on an idle machine and fail on a
// loaded one, which makes budget violations impossible to reproduce in a test.
//
// Fuel is a static per-operation cost decremented from a counter, which gives
// three properties a security control needs:
//
//   - Deterministic. The same input always consumes the same fuel.
//   - Reproducible. A budget violation reproduces in a unit test.
//   - Provably bounded. Maximum fuel per request bounds the work an attacker
//     can induce, independent of input.
//
// See docs/CONCEPT.md §2.
package budget

import "github.com/gsoultan/gwaf/types"

// Fuel, the cost constants, and the default ceiling live in types, because
// Operator.Cost is part of a public extension point and an interface method
// returning an unexported type cannot be implemented from outside the module.
// See types/fuel.go.
//
// Aliased rather than re-declared so that a third party's types.Fuel and the
// engine's budget.Fuel are the same type, not two that need converting.
type Fuel = types.Fuel

// Operation costs, re-exported so engine code reads in one vocabulary.
const (
	CostPerByteScanned     = types.CostPerByteScanned
	CostPerByteTransformed = types.CostPerByteTransformed
	CostRuleDispatch       = types.CostRuleDispatch
	CostTargetResolve      = types.CostTargetResolve
	CostLiteralMatch       = types.CostLiteralMatch
	CostRegexPerByte       = types.CostRegexPerByte
	CostCustomOperator     = types.CostCustomOperator
)

// DefaultLimit is the per-transaction ceiling applied when an embedder does not
// choose one. See types.DefaultFuelLimit for the derivation.
const DefaultLimit = types.DefaultFuelLimit

// Meter tracks fuel consumption for one transaction.
//
// A Meter is owned by exactly one goroutine, like the Transaction that holds
// it, and is reset and reused across transactions rather than reallocated.
type Meter struct {
	remaining Fuel
	limit     Fuel
	exhausted bool
}

// Reset prepares m for a new transaction with the given limit. A non-positive
// limit means unmetered, which is intended for offline tooling — calibration,
// corpus replay, rule linting — never for serving traffic.
func (m *Meter) Reset(limit Fuel) {
	m.limit = limit
	m.remaining = limit
	m.exhausted = false
}

// Unmetered reports whether m is running without a ceiling.
func (m *Meter) Unmetered() bool { return m.limit <= 0 }

// Spend deducts n fuel and reports whether the transaction may continue.
//
// Once exhausted, a Meter stays exhausted for the rest of the transaction even
// if a later caller spends zero: partial evaluation after a budget violation
// would produce a decision derived from an incomplete rule set, which is
// indistinguishable from a bypass.
func (m *Meter) Spend(n Fuel) bool {
	if m.exhausted {
		return false
	}
	if m.limit <= 0 {
		return true
	}
	m.remaining -= n
	if m.remaining < 0 {
		m.remaining = 0
		m.exhausted = true
		return false
	}
	return true
}

// Exhausted reports whether the budget has been spent.
func (m *Meter) Exhausted() bool { return m.exhausted }

// Remaining returns the fuel left. It reports the limit for an unmetered Meter.
func (m *Meter) Remaining() Fuel {
	if m.limit <= 0 {
		return m.limit
	}
	return m.remaining
}

// Spent returns the fuel consumed so far.
func (m *Meter) Spent() Fuel {
	if m.limit <= 0 {
		return 0
	}
	return m.limit - m.remaining
}

// Limit returns the ceiling this Meter was reset with.
func (m *Meter) Limit() Fuel { return m.limit }
