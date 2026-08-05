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

// Fuel is an abstract unit of work. Costs are calibrated so that one unit is
// roughly one byte scanned by the prefilter; see the Cost constants.
type Fuel int64

// Operation costs. These are calibrated against the benchmark suite rather than
// guessed: bench/ asserts that measured wall-clock stays correlated with fuel
// spent, so a drift between the two fails CI rather than silently making the
// budget meaningless.
const (
	// CostPerByteScanned is charged for each input byte the prefilter reads.
	CostPerByteScanned Fuel = 1

	// CostPerByteTransformed is charged per byte of materialised transform
	// output. Transforms allocate and copy, so they cost more than a scan.
	CostPerByteTransformed Fuel = 2

	// CostRuleDispatch is the fixed overhead of evaluating one candidate rule,
	// before its operator runs.
	CostRuleDispatch Fuel = 8

	// CostTargetResolve is the fixed overhead of resolving one target
	// collection for a transaction.
	CostTargetResolve Fuel = 16

	// CostLiteralMatch is a literal comparison against an already-scanned value.
	CostLiteralMatch Fuel = 4

	// CostRegexPerByte is charged per input byte for a regex evaluation. Regex
	// is the fallback tier and is priced to reflect that.
	CostRegexPerByte Fuel = 10

	// CostCustomOperator is the floor charged for a third-party operator, which
	// the engine cannot cost statically. Custom operators may charge more via
	// Meter.Spend.
	CostCustomOperator Fuel = 64
)

// DefaultLimit is the per-transaction fuel ceiling applied when an embedder
// does not choose one.
//
// It is derived from the default input limits rather than picked, because the
// two have to be coherent: a request that the input limits admit must not then
// be rejected for running out of fuel, or the deployment would reject traffic
// it was configured to accept.
//
// The derivation, with the defaults in gwaf.DefaultLimits:
//
//	inspected bytes   ≈ MaxBodySize (1 MiB) + arguments + headers ≈ 1.5 MiB
//	transform chains  ≈ 6 distinct chains across a realistic ruleset
//	cost per byte     = 1 (scan) + 2 (transform) = 3
//
//	1.5 MiB × 6 × 3 ≈ 28 M
//
// 32,000,000 leaves headroom above that while still bounding the work an
// attacker can induce to a fixed multiple of a legitimate maximum-size request.
// Deployments with tighter input limits should lower this in proportion; the
// bound is only as useful as it is tight.
const DefaultLimit Fuel = 32_000_000

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
